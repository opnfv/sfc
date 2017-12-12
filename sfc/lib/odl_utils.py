import ConfigParser
import os
import requests
import time
import json
import re
import logging
import functest.utils.functest_utils as ft_utils
import sfc.lib.openstack_tacker as os_tacker
import sfc.lib.openstack_utils as os_sfc_utils


logger = logging.getLogger(__name__)


def actual_rsps_in_compute(ovs_logger, compute_ssh):
    '''
    Example flows that match the regex (line wrapped because of flake8)
    table=101, n_packets=7, n_bytes=595, priority=500,tcp,in_port=2,tp_dst=80
    actions=push_nsh,load:0x1->NXM_NX_NSH_MDTYPE[],load:0x3->NXM_NX_NSH_NP[],
    load:0x27->NXM_NX_NSP[0..23],load:0xff->NXM_NX_NSI[],
    load:0xffffff->NXM_NX_NSH_C1[],load:0->NXM_NX_NSH_C2[],resubmit(,17)
    '''
    match_rsp = re.compile(
        r'.+tp_dst=([0-9]+).+load:(0x[0-9a-f]+)->NXM_NX_NSP\[0\.\.23\].+')
    # First line is OFPST_FLOW reply (OF1.3) (xid=0x2):
    # This is not a flow so ignore
    flows = (ovs_logger.ofctl_dump_flows(compute_ssh, 'br-int', '101')
             .strip().split('\n')[1:])
    matching_flows = [match_rsp.match(f) for f in flows]
    # group(1) = 22 (tp_dst value) | group(2) = 0xff (rsp value)
    rsps_in_compute = ['{0}_{1}'.format(mf.group(2), mf.group(1))
                       for mf in matching_flows if mf is not None]
    return rsps_in_compute


def get_active_rsps(odl_ip, odl_port):
    '''
    Queries operational datastore and returns the RSPs for which we have
    created a classifier (ACL). These are considered as active RSPs
    for which classification rules should exist in the compute nodes

    This function enhances the returned dictionary with the
    destination port of the ACL.
    '''

    acls = get_odl_acl_list(odl_ip, odl_port)
    rsps = []
    for acl in acls['access-lists']['acl']:
        try:
            # We get the first ace. ODL creates a new ACL
            # with one ace for each classifier
            ace = acl['access-list-entries']['ace'][0]
        except:
            logger.warn('ACL {0} does not have an ACE'.format(
                acl['acl-name']))
            continue

        if not ('netvirt-sfc-acl:rsp-name' in ace['actions']):
            continue

        rsp_name = ace['actions']['netvirt-sfc-acl:rsp-name']
        rsp = get_odl_resource_elem(odl_ip,
                                    odl_port,
                                    'rendered-service-path',
                                    rsp_name,
                                    datastore='operational')
        '''
        Rsps are returned in the format:
        {
           "rendered-service-path": [
               {
                   "name": "Path-red-Path-83",
                   "path-id": 83,
                    ...
                    "rendered-service-path-hop": [
                        {
                            ...
                            "service-function-name": "testVNF1",
                            "service-index": 255
               ...
           'rendered-service-path' Is returned as a list with one
           element (we select by name and the names are unique)
        '''
        rsp_port = rsp['rendered-service-path'][0]
        rsp_port['dst-port'] = (ace['matches']
                                ['destination-port-range']['lower-port'])
        rsps.append(rsp_port)
    return rsps


def promised_rsps_in_computes(odl_ip, odl_port):
    '''
    Return a list of rsp_port which represents the rsp id and the destination
    port configured in ODL
    '''
    rsps = get_active_rsps(odl_ip, odl_port)
    rsps_in_computes = ['{0}_{1}'.format(hex(rsp['path-id']), rsp['dst-port'])
                        for rsp in rsps]

    return rsps_in_computes


@ft_utils.timethis
def wait_for_classification_rules(ovs_logger, compute_nodes, odl_ip, odl_port,
                                  timeout=200):
    '''
    Check if the classification rules configured in ODL are implemented in OVS.
    We know by experience that this process might take a while
    '''
    try:
        # Find the compute where the client is
        compute_client = os_sfc_utils.get_compute_client()

        for compute_node in compute_nodes:
            if compute_node.name in compute_client:
                compute = compute_node
        try:
            compute
        except NameError:
            logger.debug("No compute where the client is was found")
            raise Exception("No compute where the client is was found")

        # Find the configured rsps in ODL. Its format is nsp_destPort
        promised_rsps = []
        timeout2 = 10
        while not promised_rsps:
            promised_rsps = promised_rsps_in_computes(odl_ip, odl_port)
            timeout2 -= 1
            if timeout2 == 0:
                os_tacker.get_tacker_items()
                get_odl_items(odl_ip, odl_port)
                raise Exception("RSPs not configured in ODL")
            time.sleep(3)

        while timeout > 0:
            logger.info("RSPs in ODL Operational DataStore:")
            logger.info("{0}".format(promised_rsps))

            # Fetch the rsps implemented in the compute
            compute_rsps = actual_rsps_in_compute(ovs_logger,
                                                  compute.ssh_client)

            logger.info("RSPs in compute nodes:")
            logger.info("{0}".format(compute_rsps))

            # We use sets to compare as we will not have the same value twice
            if not (set(promised_rsps) ^ set(compute_rsps)):
                # OVS state is consistent with ODL
                logger.info("Classification rules were updated")
                return

            timeout -= 1
            time.sleep(1)

        if timeout <= 0:
            logger.error("Timeout but classification rules are not updated")

    except Exception as e:
        logger.error('Error when waiting for classification rules: %s' % e)


def get_odl_ip_port(nodes):
    controller_node = next(n for n in nodes if n.is_controller())
    home_folder = controller_node.run_cmd('pwd')
    remote_ml2_conf_etc = '/etc/neutron/plugins/ml2/ml2_conf.ini'
    remote_ml2_conf_home = '{0}/ml2_conf.ini'.format(home_folder)
    local_ml2_conf_file = os.path.join(os.getcwd(), 'ml2_conf.ini')
    controller_node.run_cmd('sudo cp {0} {1}/'
                            .format(remote_ml2_conf_etc, home_folder))
    controller_node.run_cmd('sudo chmod 777 {0}'
                            .format(remote_ml2_conf_home))
    controller_node.get_file(remote_ml2_conf_home, local_ml2_conf_file)
    con_par = ConfigParser.RawConfigParser()
    con_par.read(local_ml2_conf_file)
    ip, port = re.search(r'[0-9]+(?:\.[0-9]+){3}\:[0-9]+',
                         con_par.get('ml2_odl', 'url')).group().split(':')
    return ip, port


def pluralize(s):
    return '{0}s'.format(s)


def format_odl_resource_list_url(odl_ip, odl_port, resource,
                                 datastore='config', odl_user='admin',
                                 odl_pwd='admin'):
    return ('http://{usr}:{pwd}@{ip}:{port}/restconf/{ds}/{rsrc}:{rsrcs}'
            .format(usr=odl_user, pwd=odl_pwd, ip=odl_ip, port=odl_port,
                    ds=datastore, rsrc=resource, rsrcs=pluralize(resource)))


def format_odl_resource_elem_url(odl_ip, odl_port, resource,
                                 elem_name, datastore='config'):
    list_url = format_odl_resource_list_url(
        odl_ip, odl_port, resource, datastore=datastore)
    return ('{0}/{1}/{2}'.format(list_url, resource, elem_name))


def odl_resource_list_names(resource, resource_json):
    if len(resource_json[pluralize(resource)].items()) == 0:
        return []
    return [r['name'] for r in resource_json[pluralize(resource)][resource]]


def get_odl_resource_list(odl_ip, odl_port, resource, datastore='config'):
    url = format_odl_resource_list_url(
        odl_ip, odl_port, resource, datastore=datastore)
    return requests.get(url).json()


def get_odl_resource_elem(odl_ip, odl_port, resource,
                          elem_name, datastore='config'):
    url = format_odl_resource_elem_url(
        odl_ip, odl_port, resource, elem_name, datastore=datastore)
    return requests.get(url).json()


def delete_odl_resource_elem(odl_ip, odl_port, resource, elem_name,
                             datastore='config'):
    url = format_odl_resource_elem_url(
        odl_ip, odl_port, resource, elem_name, datastore=datastore)
    requests.delete(url)


def odl_acl_types_names(acl_json):
    if len(acl_json['access-lists'].items()) == 0:
        return []
    return [(acl['acl-type'], acl['acl-name'])
            for acl in acl_json['access-lists']['acl']]


def format_odl_acl_list_url(odl_ip, odl_port,
                            odl_user='admin', odl_pwd='admin'):
    acl_list_url = ('http://{usr}:{pwd}@{ip}:{port}/restconf/config/'
                    'ietf-access-control-list:access-lists'
                    .format(usr=odl_user, pwd=odl_pwd,
                            ip=odl_ip, port=odl_port))
    return acl_list_url


def improve_json_layout(json_response):
    return json.dumps(json_response, indent=4, separators=(',', ': '))


def get_odl_items(odl_ip, odl_port):
    acl_list_url = format_odl_acl_list_url(odl_ip, odl_port)
    sf_list_url = format_odl_resource_list_url(odl_ip, odl_port,
                                               "service-function")
    sff_list_url = format_odl_resource_list_url(odl_ip, odl_port,
                                                "service-function-forwarder")
    sfc_list_url = format_odl_resource_list_url(odl_ip, odl_port,
                                                "service-function-chain")
    rsp_list_url = format_odl_resource_list_url(odl_ip, odl_port,
                                                "rendered-service-path",
                                                datastore="operational")
    r_acl = requests.get(acl_list_url).json()
    r_sf = requests.get(sf_list_url).json()
    r_sff = requests.get(sff_list_url).json()
    r_sfc = requests.get(sfc_list_url).json()
    r_rsp = requests.get(rsp_list_url).json()
    logger.debug("Configured ACLs in ODL: %s" % improve_json_layout(r_acl))
    logger.debug("Configured SFs in ODL: %s" % improve_json_layout(r_sf))
    logger.debug("Configured SFFs in ODL: %s" % improve_json_layout(r_sff))
    logger.debug("Configured SFCs in ODL: %s" % improve_json_layout(r_sfc))
    logger.debug("Configured RSPs in ODL: %s" % improve_json_layout(r_rsp))


def get_odl_acl_list(odl_ip, odl_port):
    acl_list_url = format_odl_acl_list_url(odl_ip, odl_port)
    r = requests.get(acl_list_url)
    return r.json()


def delete_odl_acl(odl_ip, odl_port, acl_type, acl_name):
    acl_list_url = format_odl_acl_list_url(odl_ip, odl_port)
    acl_url = '{0}/acl/{1}/{2}'.format(acl_list_url, acl_type, acl_name)
    requests.delete(acl_url)


def delete_acl(odl_ip, odl_port):
    # delete_sfc_classifier(tacker_client, sfc_clf_name=clf_name)
    delete_odl_acl(odl_ip,
                   odl_port,
                   'ietf-access-control-list:ipv4-acl',
                   clf_name)


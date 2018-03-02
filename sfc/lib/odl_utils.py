import ConfigParser
import os
import requests
import time
import json
import re
import logging
import functools
import sfc.lib.openstack_utils as os_sfc_utils


logger = logging.getLogger(__name__)


ODL_MODULE_EXCEPTIONS = {
    "service-function-path-state": "service-function-path"
}

ODL_PLURAL_EXCEPTIONS = {
    "service-function-path-state": "service-function-paths-state"
}


def actual_rsps_in_compute(ovs_logger, compute_ssh):
    '''
    Example flows that match the regex (line wrapped because of flake8)
    table=101, n_packets=7, n_bytes=595, priority=500,tcp,in_port=2,tp_dst=80
    actions=push_nsh,load:0x1->NXM_NX_NSH_MDTYPE[],load:0x3->NXM_NX_NSH_NP[],
    load:0x27->NXM_NX_NSP[0..23],load:0xff->NXM_NX_NSI[],
    load:0xffffff->NXM_NX_NSH_C1[],load:0->NXM_NX_NSH_C2[],resubmit(,17)
    '''
    match_rsp = re.compile(r'.+'
                           r'(tp_(?:src|dst)=[0-9]+)'
                           r'.+'
                           r'load:(0x[0-9a-f]+)->NXM_NX_NSP\[0\.\.23\]'
                           r'.+')
    # First line is OFPST_FLOW reply (OF1.3) (xid=0x2):
    # This is not a flow so ignore
    flows = (ovs_logger.ofctl_dump_flows(compute_ssh, 'br-int', '101')
             .strip().split('\n')[1:])
    matching_flows = [match_rsp.match(f) for f in flows]
    # group(1) = tsp_dst=22 | group(2) = 0xff (rsp value)
    rsps_in_compute = ['{0}|{1}'.format(mf.group(2), mf.group(1))
                       for mf in matching_flows if mf is not None]
    return rsps_in_compute


def get_active_rsps_on_port(odl_ip, odl_port, neutron_port):
    '''
    Queries operational datastore and returns the RSPs for which we have
    created a classifier (ACL) on a specific neutron port. These are
    considered as active RSPs on that port for which classification rules
    should exist in the compute node on which such port is located.

    This function enhances the returned dictionary with the
    openflow match on the tcp port of the ACL.
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

        # Depending on the port being a source or destination port,
        # we will be looking for forward or reverse RSPs
        matches = ace.get('matches', {})
        src_port = matches.get('netvirt-sfc-acl:source-port-uuid', None)
        dst_port = matches.get('netvirt-sfc-acl:destination-port-uuid', None)
        if src_port == neutron_port.id:
            reverse_path = False
        elif dst_port == neutron_port.id:
            reverse_path = True
        else:
            continue
        of_match_key = 'tp_src' if reverse_path else 'tp_dst'
        of_match_value = matches['destination-port-range']['lower-port']
        of_port_match = of_match_key + '=' + str(of_match_value)

        rsps_from_actions = get_rsps_from_netvirt_acl_actions(odl_ip, odl_port, ace['actions'])

        '''
        Rsps are returned in the format:
        {
           "rendered-service-path": [
               {
                   "name": "Path-red-Path-83",
                   "path-id": 83,
                   "reverse-path": true,
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
        rsps = []
        for rsp in rsps_from_actions:
            # Filter out RSPs that are not in the appropriate direction
            # for the specified port
            if rsp.get('reverse-path', None) != reverse_path:
                continue

            rsp['of-port-match'] = of_port_match
            rsps.append(rsp)

    return rsps


def get_rsps_from_netvirt_acl_actions(odl_ip, odl_port, netvirt_acl_actions):
    '''
    Return the list of RSPs referenced from the netvirt sfc redirect action
    '''
    rsp_names = []

    if 'netvirt-sfc-acl:rsp-name' in netvirt_acl_actions:
        rsp_names.append(netvirt_acl_actions['netvirt-sfc-acl:rsp-name'])

    if 'netvirt-sfc-acl:sfp-name' in netvirt_acl_actions:
        # If the acl redirect action is a sfp instead of rsp
        # we need to get the rsps associated to that sfp
        sfp_name = netvirt_acl_actions['netvirt-sfc-acl:sfp-name']
        sfp_state = get_odl_resource_elem(odl_ip,
                                          odl_port,
                                          'service-function-path-state',
                                          sfp_name,
                                          datastore='operational')
        sfp_rsps = sfp_state.get('sfp-rendered-service-path', [])
        sfp_rsp_names = [rsp['name'] for rsp in sfp_rsps if 'name' in rsp]
        rsp_names.extend(sfp_rsp_names)

    rsps = []
    for rsp_name in rsp_names:
        rsp = get_odl_resource_elem(odl_ip,
                                    odl_port,
                                    'rendered-service-path',
                                    rsp_name,
                                    datastore='operational')
        rsps.append(rsp)

    return rsps


def promised_rsps_in_computes(odl_ip, odl_port, neutron_port):
    '''
    Return a list of rsp_port which represents the rsp id and the destination
    port configured in ODL
    '''
    rsps = get_active_rsps_on_port(odl_ip, odl_port, neutron_port)
    rsps_in_computes = ['{0}|{1}'.format(
                            hex(rsp['path-id']), rsp['of-port-match'])
                        for rsp in rsps]

    return rsps_in_computes


def timethis(func):
    """Measure the time it takes for a function to complete"""
    @functools.wraps(func)
    def timed(*args, **kwargs):
        ts = time.time()
        result = func(*args, **kwargs)
        te = time.time()
        elapsed = '{0}'.format(te - ts)
        logger.info('{f}(*{a}, **{kw}) took: {t} sec'.format(
            f=func.__name__, a=args, kw=kwargs, t=elapsed))
        return result, elapsed
    return timed


@timethis
def wait_for_classification_rules(ovs_logger, compute_nodes, odl_ip, odl_port,
                                  compute_name, neutron_port, timeout=200):
    '''
    Check if the classification rules configured in ODL are implemented in OVS.
    We know by experience that this process might take a while
    '''
    try:
        compute = find_compute(compute_name, compute_nodes)

        # Find the configured rsps in ODL. Its format is nsp_destPort
        promised_rsps = []
        timeout2 = 10
        while not promised_rsps:
            promised_rsps = promised_rsps_in_computes(odl_ip, odl_port,
                                                      neutron_port)
            timeout2 -= 1
            if timeout2 == 0:
                os_sfc_utils.get_tacker_items()
                get_odl_items(odl_ip, odl_port)
                raise Exception("RSPs not configured in ODL")
            time.sleep(3)

        while timeout > 0:
            logger.info("RSPs in ODL Operational DataStore"
                        "for port '{}':".format(neutron_port.id))
            logger.info("{0}".format(promised_rsps))

            # Fetch the rsps implemented in the compute
            compute_rsps = actual_rsps_in_compute(ovs_logger,
                                                  compute.ssh_client)

            logger.info("RSPs in compute nodes:")
            logger.info("{0}".format(compute_rsps))

            # We use sets to compare as we will not have the same value twice
            if not (set(promised_rsps) - set(compute_rsps)):
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


def pluralize(resource):
    plural = ODL_PLURAL_EXCEPTIONS.get(resource, None)
    if not plural:
        plural = '{0}s'.format(resource)
    return plural


def get_module(resource):
    module = ODL_MODULE_EXCEPTIONS.get(resource, None)
    if not module:
        module = resource
    return module


def format_odl_resource_list_url(odl_ip, odl_port, resource,
                                 datastore='config', odl_user='admin',
                                 odl_pwd='admin'):
    return ('http://{usr}:{pwd}@{ip}:{port}/restconf/{ds}/{rsrc}:{rsrcs}'
            .format(usr=odl_user, pwd=odl_pwd, ip=odl_ip, port=odl_port,
                    ds=datastore, rsrc=get_module(resource),
                    rsrcs=pluralize(resource)))


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
    response = requests.get(url).json()
    # We get:
    # {'<resource>' : [element]}
    # Return just element
    return response.get(resource, [{}])[0]


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


def delete_acl(clf_name, odl_ip, odl_port):
    # delete_sfc_classifier(tacker_client, sfc_clf_name=clf_name)
    delete_odl_acl(odl_ip,
                   odl_port,
                   'ietf-access-control-list:ipv4-acl',
                   clf_name)


def find_compute(compute_client_name, compute_nodes):
    for compute_node in compute_nodes:
        if compute_node.name in compute_client_name:
            compute = compute_node
    try:
        compute
    except NameError:
        logger.debug("No compute, where the client is, was found")
        raise Exception("No compute, where the client is, was found")

    return compute


def check_vnffg_deletion(odl_ip, odl_port, ovs_logger, neutron_port,
                         compute_client_name, compute_nodes, retries=20):
    '''
    First, RSPs are checked in the operational datastore of ODL. Nothing
    should exist. As it might take a while for ODL to remove that, some
    retries are needed.

    Secondly, we check that the classification rules are removed too
    '''

    retries_counter = retries

    # Check RSPs
    while retries_counter > 0:
        if (get_active_rsps_on_port(odl_ip, odl_port, neutron_port)):
            retries_counter -= 1
            time.sleep(3)
        else:
            break

    if not retries_counter:
        logger.debug("RSPs are still active in the MD-SAL")
        return False

    # Get the compute where the client is running
    try:
        compute = find_compute(compute_client_name, compute_nodes)
    except Exception as e:
        logger.debug("There was an error getting the compute: e" % e)

    retries_counter = retries

    # Check classification flows
    while retries_counter > 0:
        if (actual_rsps_in_compute(ovs_logger, compute.ssh_client)):
            retries_counter -= 1
            time.sleep(3)
        else:
            break

    if not retries_counter:
        logger.debug("Classification flows still in the compute")
        return False

    return True


def create_chain(tacker_client, default_param_file, neutron_port,
                 COMMON_CONFIG, TESTCASE_CONFIG):

    tosca_file = os.path.join(COMMON_CONFIG.sfc_test_dir,
                              COMMON_CONFIG.vnffgd_dir,
                              TESTCASE_CONFIG.test_vnffgd_red)

    os_sfc_utils.create_vnffgd(tacker_client,
                               tosca_file=tosca_file,
                               vnffgd_name='red')

    os_sfc_utils.create_vnffg_with_param_file(tacker_client, 'red',
                                              'red_http',
                                              default_param_file,
                                              neutron_port.id)

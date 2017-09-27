#!/usr/bin/python
#
# Copyright (c) 2016 All rights reserved
# This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
import ConfigParser
import os
import re
import subprocess
import requests
import time
import json

import logging
from functest.utils.constants import CONST
import functest.utils.functest_utils as ft_utils
import functest.utils.openstack_utils as os_utils
import sfc.lib.openstack_tacker as os_tacker


logger = logging.getLogger(__name__)
SSH_OPTIONS = '-q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'
FUNCTEST_RESULTS_DIR = os.path.join("home", "opnfv",
                                    "functest", "results", "odl-sfc")


def run_cmd(cmd):
    """
    Run given command locally
    Return a tuple with the return code, stdout, and stderr of the command
    """
    pipe = subprocess.Popen(cmd,
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    stdout, stderr = [stream.strip() for stream in pipe.communicate()]
    output = ' - STDOUT: "%s"' % stdout if len(stdout) > 0 else ''
    error = ' - STDERR: "%s"' % stdout if len(stderr) > 0 else ''
    logger.debug("Running [{command}] returns: [{rc}]{output}{error}".format(
                 command=cmd,
                 rc=pipe.returncode,
                 output=output,
                 error=error))

    return pipe.returncode, stdout, stderr


def run_cmd_remote(ip, cmd, username="root", passwd="opnfv"):
    """run given command on Remote Machine, Can be VM"""
    ssh_opt_append = "%s -o ConnectTimeout=50 " % SSH_OPTIONS
    ssh_cmd = "sshpass -p %s ssh %s %s@%s %s" % (
        passwd, ssh_opt_append, username, ip, cmd)
    return run_cmd(ssh_cmd)


def download_image(url, image_path):
    image_filename = os.path.basename(image_path)
    image_url = "%s/%s" % (url, image_filename)
    image_dir = os.path.dirname(image_path)
    if not os.path.isfile(image_path):
        logger.info("Downloading image")
        ft_utils.download_url(image_url, image_dir)
    else:
        logger.info("Using old image")


def get_av_zones():
    '''
    Return the availability zone each host belongs to
    '''
    nova_client = os_utils.get_nova_client()
    hosts = os_utils.get_hypervisors(nova_client)
    return ['nova::{0}'.format(host) for host in hosts]


def get_compute_client():
    '''
    Return the compute where the client sits
    '''
    nova_client = os_utils.get_nova_client()
    hosts = os_utils.get_hypervisors(nova_client)
    for compute in hosts:
        vms = nova_client.servers.list(search_opts={'host': compute})
        for vm in vms:
            if "client" in vm.name:
                return compute
    return False


def create_vnf_in_av_zone(
                          tacker_client,
                          vnf_name,
                          vnfd_name,
                          vim_name,
                          default_param_file,
                          av_zone=None):
    param_file = default_param_file

    if av_zone is not None or av_zone != 'nova':
        param_file = os.path.join(
            '/tmp',
            'param_{0}.json'.format(av_zone.replace('::', '_')))
        data = {
               'zone': av_zone
               }
        with open(param_file, 'w+') as f:
            json.dump(data, f)
    os_tacker.create_vnf(tacker_client,
                         vnf_name,
                         vnfd_name=vnfd_name,
                         vim_name=vim_name,
                         param_file=param_file)


def create_vnffg_with_param_file(tacker_client, vnffgd_name, vnffg_name,
                                 default_param_file, neutron_port):
    param_file = default_param_file

    if neutron_port is not None:
        param_file = os.path.join(
            '/tmp',
            'param_{0}.json'.format(neutron_port))
        data = {
               'net_src_port_id': neutron_port
               }
        with open(param_file, 'w+') as f:
            json.dump(data, f)
    os_tacker.create_vnffg(tacker_client,
                           vnffgd_name=vnffgd_name,
                           vnffg_name=vnffg_name,
                           param_file=param_file)


def setup_neutron(neutron_client, net, subnet, router, subnet_cidr):
    n_dict = os_utils.create_network_full(neutron_client,
                                          net,
                                          subnet,
                                          router,
                                          subnet_cidr)
    if not n_dict:
        logger.error("failed to create neutron network")
        return False

    return n_dict["net_id"]


def create_secgroup_rule(neutron_client, sg_id, direction, protocol,
                         port_range_min=None, port_range_max=None):
    # We create a security group in 2 steps
    # 1 - we check the format and set the json body accordingly
    # 2 - we call neturon client to create the security group

    # Format check
    json_body = {'security_group_rule': {'direction': direction,
                                         'security_group_id': sg_id,
                                         'protocol': protocol}}
    # parameters may be
    # - both None => we do nothing
    # - both Not None => we add them to the json description
    # but one cannot be None is the other is not None
    if (port_range_min is not None and port_range_max is not None):
        # add port_range in json description
        json_body['security_group_rule']['port_range_min'] = port_range_min
        json_body['security_group_rule']['port_range_max'] = port_range_max
        logger.debug("Security_group format set (port range included)")
    else:
        # either both port range are set to None => do nothing
        # or one is set but not the other => log it and return False
        if port_range_min is None and port_range_max is None:
            logger.debug("Security_group format set (no port range mentioned)")
        else:
            logger.error("Bad security group format."
                         "One of the port range is not properly set:"
                         "range min: {},"
                         "range max: {}".format(port_range_min,
                                                port_range_max))
            return False

    # Create security group using neutron client
    try:
        neutron_client.create_security_group_rule(json_body)
        return True
    except:
        return False


def setup_ingress_egress_secgroup(neutron_client, protocol,
                                  min_port=None, max_port=None):
    secgroups = os_utils.get_security_groups(neutron_client)
    for sg in secgroups:
        # TODO: the version of the create_secgroup_rule function in
        # functest swallows the exception thrown when a secgroup rule
        # already exists and prints a ton of noise in the test output.
        # Instead of making changes in functest code this late in the
        # release cycle, we keep our own version without the exception
        # logging. We must find a way to properly cleanup sec group
        # rules using "functest openstack clean" or pretty printing the
        # specific exception in the next release
        create_secgroup_rule(neutron_client, sg['id'],
                             'ingress', protocol,
                             port_range_min=min_port,
                             port_range_max=max_port)
        create_secgroup_rule(neutron_client, sg['id'],
                             'egress', protocol,
                             port_range_min=min_port,
                             port_range_max=max_port)


def create_security_groups(neutron_client, secgroup_name, secgroup_descr):
    sg_id = os_utils.create_security_group_full(neutron_client,
                                                secgroup_name, secgroup_descr)
    setup_ingress_egress_secgroup(neutron_client, "icmp")
    setup_ingress_egress_secgroup(neutron_client, "tcp", 22, 22)
    setup_ingress_egress_secgroup(neutron_client, "tcp", 80, 80)
    setup_ingress_egress_secgroup(neutron_client, "udp", 67, 68)
    return sg_id


def create_instance(nova_client, name, flavor, image_id, network_id, sg_id,
                    secgroup_name=None, fixed_ip=None,
                    av_zone='', userdata=None, files=None):
    logger.info("Creating instance '%s'..." % name)
    logger.debug(
        "Configuration:\n name=%s \n flavor=%s \n image=%s \n"
        " network=%s\n secgroup=%s \n hypervisor=%s \n"
        " fixed_ip=%s\n files=%s\n userdata=\n%s\n"
        % (name, flavor, image_id, network_id, sg_id,
           av_zone, fixed_ip, files, userdata))
    instance = os_utils.create_instance_and_wait_for_active(
        flavor,
        image_id,
        network_id,
        name,
        config_drive=True,
        userdata=userdata,
        av_zone=av_zone,
        fixed_ip=fixed_ip,
        files=files)

    if instance is None:
        logger.error("Error while booting instance.")
        return None

    if secgroup_name:
        logger.debug("Adding '%s' to security group '%s'..."
                     % (name, secgroup_name))
    else:
        logger.debug("Adding '%s' to security group '%s'..."
                     % (name, sg_id))
    os_utils.add_secgroup_to_instance(nova_client, instance.id, sg_id)

    return instance


def ping(remote, retries=100, retry_timeout=1):
    cmd = 'ping -c1 -w{timeout} {remote}'.format(
          timeout=retry_timeout,
          remote=remote)

    while retries > 0:
        rc, _, _ = run_cmd(cmd)
        if rc == 0:
            return True

        retries -= 1

    return False


def assign_floating_ip(nova_client, neutron_client, instance_id):
    instance = nova_client.servers.get(instance_id)
    floating_ip = os_utils.create_floating_ip(neutron_client)['fip_addr']
    instance.add_floating_ip(floating_ip)
    logger.info("Assigned floating ip [%s] to instance [%s]"
                % (floating_ip, instance.name))

    return floating_ip


def start_http_server(ip, iterations_check=5):
    """
    Start http server on a given machine. Wait until the process exists
    and until the port is up
    """
    cmd = "\'python -m SimpleHTTPServer 80"
    cmd = cmd + " > /dev/null 2>&1 &\'"
    run_cmd_remote(ip, cmd)

    # Wait for the process to start before checking
    time.sleep(3)
    _, output, _ = run_cmd_remote(ip, "ps aux | grep SimpleHTTPServer")
    if not output:
        logger.error("Failed to start http server")
        return False
    logger.info(output)

    while iterations_check > 0:
        _, output, _ = run_cmd_remote(ip, "ss -na | grep *:80")
        if output:
            return True
        else:
            logger.debug("Port 80 is not up yet")
            iterations_check -= 1
            time.sleep(5)

    logger.error("Failed to start http server")
    return False


def start_vxlan_tool(remote_ip, interface="eth0", block=None):
    """
    Starts vxlan_tool on a remote host.
    vxlan_tool.py converts a regular Service Function into a NSH-aware SF
    when the "--do forward" option is used, it decrements the NSI appropiately.
    'block' parameters allows to specify a port where packets will be dropped.
    """
    command = "nohup python /root/vxlan_tool.py"
    options = "{do} {interface} {block_option}".format(
        do="--do forward",
        interface="--interface {}".format(interface),
        block_option="--block {}".format(block) if block is not None else "")
    output_redirection = "> /dev/null 2>&1"

    full_command = "{command} {options} {output_redirection} &".format(
        command=command,
        options=options,
        output_redirection=output_redirection)

    output_execution = run_cmd_remote(remote_ip, full_command)

    # Wait for the process to start before checking
    time.sleep(3)
    _, output, _ = run_cmd_remote(remote_ip, "ps aux | grep vxlan_tool")
    if not output:
        logger.error("Failed to start the vxlan tool")
        return False

    return output_execution


def stop_vxlan_tool(remote_ip):
    """ Stops vxlan_tool on a remote host"""
    command = "pkill -f vxlan_tool.py"
    return run_cmd_remote(remote_ip, command)


def netcat(source_ip, destination_ip, destination_port, source_port=None,
           timeout=5):
    """
    SSH into source_ip, and check the connectivity from there to destination_ip
    on the specified port, using the netcat command.
    Returns 0 on successful execution, != 0 on failure
    """
    source_port_option = '' if source_port is None else '-p %s' % source_port
    cmd = "nc -z {option} -w {timeout} {ip} {port}".format(
          option=source_port_option,
          timeout=timeout,
          ip=destination_ip,
          port=destination_port)
    rc, _, _ = run_cmd_remote(source_ip, cmd)
    logger.info("Running [%s] from [%s] returns [%s]" % (cmd, source_ip, rc))
    return rc


def is_ssh_blocked(source_ip, destination_ip, source_port=None):
    rc = netcat(
        source_ip,
        destination_ip,
        destination_port="22",
        source_port=source_port)
    return rc != 0


def is_http_blocked(source_ip, destination_ip, source_port=None):
    rc = netcat(
        source_ip,
        destination_ip,
        destination_port="80",
        source_port=source_port)
    return rc != 0


def capture_ovs_logs(ovs_logger, controller_clients, compute_clients, error):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    ovs_logger.dump_ovs_logs(controller_clients,
                             compute_clients,
                             related_error=error,
                             timestamp=timestamp)


def get_ssh_clients(nodes):
    return [n.ssh_client for n in nodes]


def check_ssh(ips, retries=100):
    """Check SSH connectivity to VNFs"""
    check = [False for ip in ips]
    logger.info("Checking SSH connectivity to the SFs with ips %s" % str(ips))
    while retries and not all(check):
        for index, ip in enumerate(ips):
            rc, _, _ = run_cmd_remote(ip, "exit")
            check[index] = True if rc == 0 else False

        if all(check):
            logger.info("SSH connectivity to the SFs established")
            return True

        time.sleep(3)
        retries -= 1

    return False


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
        compute_client = get_compute_client()

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


def get_nova_id(tacker_client, resource, vnf_id=None, vnf_name=None):
    vnf = os_tacker.get_vnf(tacker_client, vnf_id, vnf_name)
    try:
        if vnf is None:
            raise Exception("VNF not found")
        heat = os_utils.get_heat_client()
        resource = heat.resources.get(vnf['instance_id'], resource)
        return resource.attributes['id']
    except:
        logger.error("Cannot get nova ID for VNF (id='%s', name='%s')"
                     % (vnf_id, vnf_name))
        return None


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


def get_odl_acl_list(odl_ip, odl_port):
    acl_list_url = format_odl_acl_list_url(odl_ip, odl_port)
    r = requests.get(acl_list_url)
    return r.json()


def delete_odl_acl(odl_ip, odl_port, acl_type, acl_name):
    acl_list_url = format_odl_acl_list_url(odl_ip, odl_port)
    acl_url = '{0}/acl/{1}/{2}'.format(acl_list_url, acl_type, acl_name)
    requests.delete(acl_url)


def delete_classifier_and_acl(tacker_client, clf_name, odl_ip, odl_port):
    os_tacker.delete_sfc_classifier(tacker_client, sfc_clf_name=clf_name)
    delete_odl_acl(odl_ip,
                   odl_port,
                   'ietf-access-control-list:ipv4-acl',
                   clf_name)


def fill_installer_dict(installer_type):
        default_string = "defaults.installer.{}.".format(installer_type)
        installer_yaml_fields = {
                             "user": default_string+"user",
                             "password": default_string+"password",
                             "cluster": default_string+"cluster",
                             "pkey_file": default_string+"pkey_file"
                           }
        return installer_yaml_fields


def register_vim(tacker_client, vim_file=None):
    tmp_file = '/tmp/register-vim.json'
    if vim_file is not None:
        with open(vim_file) as f:
            json_dict = json.load(f)

        json_dict['vim']['auth_url'] = CONST.__getattribute__('OS_AUTH_URL')
        json_dict['vim']['auth_cred']['password'] = CONST.__getattribute__(
                                                        'OS_PASSWORD')

        json.dump(json_dict, open(tmp_file, 'w'))

    os_tacker.create_vim(tacker_client, vim_file=tmp_file)


def get_neutron_interfaces(vm):
    '''
    Get the interfaces of an instance
    '''
    nova_client = os_utils.get_nova_client()
    interfaces = nova_client.servers.interface_list(vm.id)
    return interfaces


def get_vm_port_id(vm):
    '''
    Get the neutron port id of the client
    '''
    interfaces = get_neutron_interfaces(vm)
    if len(interfaces) > 1:
        raise Exception("Client has more than one interface. Not expected!")
    return interfaces[0].id


# The following method should be part of os_utils in functest but that lib is
# being deprecated. I place it here until we know what to do for F release

def disable_sg_port(neutron_port):
    '''
    Disable the security groups in the provided neutron port
    '''

    json_body = {'port': {
             'security_groups': [],
             'port_security_enabled': 'False',
    }}
    neutron_client = os_utils.get_neutron_client()
    try:
        port_result = neutron_client.update_port(neutron_port, body=json_body)
    except Exception as e:
        logger.debug("Error while disabling sg in port %s" % e)

    return port_result

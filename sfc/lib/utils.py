#!/usr/bin/python
#
# Copyright (c) 2016 All rights reserved
# This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
#
# http://www.apache.org/licenses/LICENSE-2.0
#

import os
import re
import subprocess
import requests
import time
import xmltodict
import yaml

import logging as ft_logger
# import functest.utils.functest_logger as ft_logger
import functest.utils.functest_utils as ft_utils
import functest.utils.openstack_utils as os_utils
import functest.utils.openstack_tacker as os_tacker


logger = ft_logger.getLogger(__name__)
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


def configure_iptables(controller_nodes):
    """Configures IPTABLES on OpenStack Controller"""
    iptable_cmds = ["iptables -P INPUT ACCEPT",
                    "iptables -t nat -P INPUT ACCEPT",
                    "iptables -A INPUT -m state \
                    --state NEW,ESTABLISHED,RELATED -j ACCEPT"]

    for cmd in iptable_cmds:
        logger.info("Configuring %s on contoller" % cmd)
        for controller in controller_nodes:
            controller.run_cmd(cmd)


def download_image(url, image_path):
    image_filename = os.path.basename(image_path)
    image_url = "%s/%s" % (url, image_filename)
    image_dir = os.path.dirname(image_path)
    if not os.path.isfile(image_path):
        logger.info("Downloading image")
        ft_utils.download_url(image_url, image_dir)
    else:
        logger.info("Using old image")


def av_zone_from_compute_id(compute_id):
    return 'node-{0}.domain.tld'.format(compute_id)


def create_vnf_in_av_zone(
        tacker_client, vnf_name, vnfd_name, default_param_file, av_zone=None):
    param_file = default_param_file

    if av_zone is not None or av_zone != 'nova':
        param_file = os.path.join(
            '/tmp',
            'param_{0}.yaml'.format(av_zone.replace('::', '_')))
        data = {
            'vdus': {
                'vdu1': {
                    'param': {
                        'zone': av_zone
                    }
                }
            }
        }
        with open(param_file, 'w+') as f:
            yaml.dump(data, f, default_flow_style=False)

    os_tacker.create_vnf(tacker_client,
                         vnf_name,
                         vnfd_name=vnfd_name,
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


def get_floating_ips(nova_client, neutron_client):
    ips = []
    instances = nova_client.servers.list()
    for instance in instances:
        floatip_dic = os_utils.create_floating_ip(neutron_client)
        floatip = floatip_dic['fip_addr']
        instance.add_floating_ip(floatip)
        logger.info("Instance name and ip %s:%s " % (instance.name, floatip))
        logger.info("Waiting for instance %s:%s to come up" %
                    (instance.name, floatip))
        if not ping(floatip):
            logger.info("Instance %s:%s didn't come up" %
                        (instance.name, floatip))
            return None

        if instance.name == "server":
            logger.info("Server:%s is reachable" % floatip)
            server_ip = floatip
        elif instance.name == "client":
            logger.info("Client:%s is reachable" % floatip)
            client_ip = floatip
        else:
            logger.info("SF:%s is reachable" % floatip)
            ips.append(floatip)

    return server_ip, client_ip, ips[1], ips[0]


def start_http_server(ip):
    """Start http server on a given machine, Can be VM"""
    cmd = "\'python -m SimpleHTTPServer 80"
    cmd = cmd + " > /dev/null 2>&1 &\'"
    run_cmd_remote(ip, cmd)
    _, output, _ = run_cmd_remote(ip, "ps aux | grep SimpleHTTPServer")
    if not output:
        logger.error("Failed to start http server")
        return False

    logger.info(output)
    return True


def vxlan_firewall(sf, iface="eth0", port="22", block=True):
    """Set firewall using vxlan_tool.py on a given machine, Can be VM"""
    cmd = "python vxlan_tool.py -i %s -d forward -v off" % iface
    if block:
        cmd = "python vxlan_tool.py -i eth0 -d forward -v off -b %s" % port

    cmd = "sh -c 'cd /root;nohup " + cmd + " > /dev/null 2>&1 &'"
    run_cmd_remote(sf, cmd)
    time.sleep(7)


def vxlan_tool_stop(sf):
    cmd = "pkill -f vxlan_tool.py"
    run_cmd_remote(sf, cmd)


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
    match_rsp = re.compile(r'.+load:(0x[0-9a-f]+)->NXM_NX_NSP\[0\.\.23\].+')
    flows = (ovs_logger.ofctl_dump_flows(compute_ssh, 'br-int', '11')
             .strip().split('\n')[1:])
    matching_flows = [match_rsp.match(f) for f in flows]
    rsps_in_compute = [mf.group(1) for mf in matching_flows if mf is not None]
    return rsps_in_compute


def promised_rsps_in_computes(odl_ip, odl_port, topology):
    # Queries operational datastore and returns the RSPs and
    # the computes in which we should expect them
    rsps = get_odl_resource_list(odl_ip, odl_port, datastore='operational')
    rsps_in_computes = {}
    for rsp in rsps['rendered-service-paths']['rendered-service-path']:
        computes_with_rsp = [topology[hop['service-function-name']]
                             for hop
                             in rsp['rendered-service-path-hop']]
        rsps_in_computes[rsp['path-id']] = computes_with_rsp
    return rsps_in_computes


def wait_for_classification_rules2(ovs_logger, compute_nodes, odl_ip, odl_port,
                                   topology, timeout=200):
    try:
        while True:
            if timeout == 0:
                logger.error(
                        "Timeout but classification rules are not updated")
                return
            promised_rsps = promised_rsps_in_computes(
                odl_ip, odl_port, topology)

            actual_rsps_in_computes = {}
            for node in compute_nodes:
                av_zone = av_zone_from_compute_id(node.id)
                actual_rsps_in_computes[av_zone] = actual_rsps_in_compute(
                    ovs_logger, node.ssh_client)

            promises_fulfilled = []
            for rsp, computes in promised_rsps.items():
                computes_have_rsp = [rsp
                                     in actual_rsps_in_computes[compute]
                                     for compute in computes]
                promises_fulfilled.append(all(computes_have_rsp))

            if all(promises_fulfilled):
                return

            timeout -= 1
            time.sleep(1)
    except Exception, e:
        logger.error('Error when waiting for classification rules: %s' % e)


def ofctl_time_counter(ovs_logger, ssh_conn, max_duration=None):
    try:
        # We get the flows from table 11
        table = 11
        br = "br-int"
        output = ovs_logger.ofctl_dump_flows(ssh_conn, br, table)
        pattern = "NXM_NX_NSP"
        rsps = []
        lines = output.split(",")
        for line in lines:
            if max_duration is not None:
                pattern2 = "duration"
                is_there2 = re.findall(pattern2, line)
                if is_there2:
                    value = line.split("=")[1].split(".")[0]
                    value_int = int(value)
                    if value_int < max_duration:
                        # The RSP is new, no need to store the RSP in first_RSP
                        return rsps
                    else:
                        continue
            is_there = re.findall(pattern, line)
            if is_there:
                value = line.split(":")[1].split("-")[0]
                rsps.append(value)
        return rsps
    except Exception, e:
        logger.error('Error when countering %s' % e)
        return None


@ft_utils.timethis
def wait_for_classification_rules(ovs_logger, compute_clients,
                                  num_chains, timeout=200):
    # 10 sec. is the threshold to consider a flow from an old deployment
    for compute_client in compute_clients:
        max_duration = 10
        rsps = ofctl_time_counter(ovs_logger, compute_client, max_duration)
        # first_RSP saves a potential RSP from an old deployment.
        # ODL may take quite some time to implement the new flow
        # and an old flow may be there
        if compute_client == compute_clients[0]:
            first_RSP = rsps[0] if len(rsps) > 0 else ''
        else:
            first_RSP = ''
            rsps = ''
        logger.debug("This is the first_RSP: %s" % first_RSP)
        if num_chains == 1:
            while not ((len(rsps) == 1) and (first_RSP != rsps[0])):
                rsps = ofctl_time_counter(ovs_logger, compute_client)
                logger.debug("These are the rsps: %s" % rsps)
                timeout -= 1
                if timeout == 0:
                    logger.error(
                        "Timeout but classification rules are not updated")
                    return
                time.sleep(1)
        elif num_chains == 2:
            while not ((len(rsps) > 1) and (first_RSP != rsps[0]) and
                       (rsps[0] == rsps[1])):
                rsps = ofctl_time_counter(ovs_logger, compute_client)
                logger.info("This is the rsps: %s" % rsps)
                timeout -= 1
                if timeout == 0:
                    logger.error(
                        "Timeout but classification rules are not updated")
                    return
                time.sleep(1)
        logger.info("classification rules updated")


def setup_compute_node(cidr, compute_nodes):
    logger.info("bringing up br-int iface and flushing arp tables")
    grep_cidr_routes = ("ip route | grep -o {0} || true".format(cidr)).strip()
    add_cidr = "ip route add {0} dev br-int".format(cidr)
    for compute in compute_nodes:
        compute.run_cmd("ip -s -s neigh flush all")
        compute.run_cmd("ifconfig br-int up")
        if not compute.run_cmd(grep_cidr_routes):
            logger.info("adding route %s in %s" % (cidr, compute.ip))
            compute.run_cmd(add_cidr)
        else:
            logger.info("route %s already exists" % cidr)


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
    local_jetty = os.path.join(os.getcwd(), 'jetty.xml')
    odl_node = next(n for n in nodes if n.is_odl())
    odl_node.get_file('/opt/opendaylight/etc/jetty.xml', local_jetty)
    with open(local_jetty) as fd:
        parsed = xmltodict.parse(fd.read(), dict_constructor=dict)

    ip = (parsed['Configure']['Call'][0]['Arg']['New']
          ['Set'][0]['Property']['@default'])
    port = (parsed['Configure']['Call'][0]['Arg']['New']
            ['Set'][1]['Property']['@default'])
    return ip, port


def pluralize(s):
    return '{0}s'.format(s)


def format_odl_resource_list_url(odl_ip, odl_port, resource,
                                 datastore='config', odl_user='admin',
                                 odl_pwd='admin'):
    return ('http://{usr}:{pwd}@{ip}:{port}/restconf/{ds}/{rsrc}:{rsrcs}'
            .format(usr=odl_user, pwd=odl_pwd, ip=odl_ip, port=odl_port,
                    ds=datastore, rsrc=resource, rsrcs=pluralize(resource)))


def format_odl_resource_elem_url(odl_ip, odl_port, resource, elem_name):
    list_url = format_odl_resource_list_url(odl_ip, odl_port, resource)
    return ('{0}/{1}/{2}'.format(list_url, resource, elem_name))


def odl_resource_list_names(resource, resource_json):
    if len(resource_json[pluralize(resource)].items()) == 0:
        return []
    return [r['name'] for r in resource_json[pluralize(resource)][resource]]


def get_odl_resource_list(odl_ip, odl_port, resource, datastore='config'):
    url = format_odl_resource_list_url(odl_ip, odl_port, resource,
                                       datastore=datastore)
    return requests.get(url).json()


def delete_odl_resource_elem(odl_ip, odl_port, resource, elem_name):
    url = format_odl_resource_elem_url(odl_ip, odl_port, resource, elem_name)
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

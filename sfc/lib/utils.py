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
import time

import functest.utils.functest_logger as ft_logger
import functest.utils.functest_utils as ft_utils
import functest.utils.openstack_utils as os_utils


logger = ft_logger.Logger("sfc_test_utils").getLogger()
SSH_OPTIONS = '-q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'
FUNCTEST_RESULTS_DIR = os.path.join("home", "opnfv",
                                    "functest", "results", "odl-sfc")


def run_cmd(cmd):
    """run given command locally and return commands output if success"""
    pipe = subprocess.Popen(cmd, shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    (output, errors) = pipe.communicate()
    logger.debug("running [%s] returns: <%s> - %s "
                 "" % (cmd, pipe.returncode, output))
    if output:
        output = output.strip()
    if pipe.returncode != 0 or len(errors) > 0:
        logger.error('FAILED to execute {0}'.format(cmd))
        logger.error(errors)
        return None

    return output


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


def setup_ingress_egress_secgroup(neutron_client, protocol,
                                  min_port=None, max_port=None):
    secgroups = os_utils.get_security_groups(neutron_client)
    for sg in secgroups:
        os_utils.create_secgroup_rule(neutron_client, sg['id'],
                                      'ingress', protocol,
                                      port_range_min=min_port,
                                      port_range_max=max_port)
        os_utils.create_secgroup_rule(neutron_client, sg['id'],
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


def ping(remote, pkt_cnt=1, iface=None, retries=100, timeout=None):
    ping_cmd = 'ping'

    if timeout:
        ping_cmd = ping_cmd + ' -w %s' % timeout

    grep_cmd = "grep -e 'packet loss' -e rtt"

    if iface is not None:
        ping_cmd = ping_cmd + ' -I %s' % iface

    ping_cmd = ping_cmd + ' -i 0 -c %d %s' % (pkt_cnt, remote)
    cmd = ping_cmd + '|' + grep_cmd

    while retries > 0:
        output = run_cmd(cmd)
        if not output:
            return False

        match = re.search('(\d*)% packet loss', output)
        if not match:
            return False

        packet_loss = int(match.group(1))
        if packet_loss == 0:
            return True

        retries -= 1

    return False


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
    output = run_cmd_remote(ip, "ps aux|grep SimpleHTTPServer")
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


def vxlan_tool_stop(sf):
    cmd = "pkill -f vxlan_tool.py"
    run_cmd_remote(sf, cmd)


def netcat(s_ip, c_ip, port="80", timeout=5):
    """Run netcat on a give machine, Can be VM"""
    cmd = "nc -zv "
    cmd = cmd + " -w %s %s %s" % (timeout, s_ip, port)
    cmd = cmd + " 2>&1"
    output = run_cmd_remote(c_ip, cmd)
    logger.info("%s" % output)
    return output


def is_ssh_blocked(srv_prv_ip, client_ip):
    res = netcat(srv_prv_ip, client_ip, port="22")
    match = re.search("nc:.*timed out:.*", res, re.M)
    if match:
        return True

    return False


def is_http_blocked(srv_prv_ip, client_ip):
    res = netcat(srv_prv_ip, client_ip, port="80")
    match = re.search(".* 80 port.* succeeded!", res, re.M)
    if match:
        return False

    return True


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
    check = [False, False]
    logger.info("Checking SSH connectivity to the SFs with ips %s" % str(ips))
    while retries and not all(check):
        for index, ip in enumerate(ips):
            check[index] = run_cmd_remote(ip, "exit")

        if all(check):
            logger.info("SSH connectivity to the SFs established")
            return True

        time.sleep(3)
        retries -= 1

    return False


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
def wait_for_classification_rules(ovs_logger, compute_clients, timeout=200):
    # 10 sec. is the threshold to consider a flow from an old deployment
    max_duration = 10
    rsps = ofctl_time_counter(ovs_logger, compute_clients[0], max_duration)
    # first_RSP saves a potential RSP from an old deployment. ODL may take
    # quite some time to implement the new flow and an old flow may be there
    first_RSP = rsps[0] if len(rsps) > 0 else ''
    while not ((len(rsps) > 1) and
               (first_RSP != rsps[0]) and
               (rsps[0] == rsps[1])):
        rsps = ofctl_time_counter(ovs_logger, compute_clients[0])
        timeout -= 1
        if timeout == 0:
            logger.error(
                "Timeout but classification rules are not updated")
            return
        time.sleep(1)
    logger.info("classification rules updated")


def setup_compute_node(cidr, compute_nodes):
    logger.info("bringing up br-int iface")
    grep_cidr_routes = ("ip route|grep -o {0} || true".format(cidr)).strip()
    add_cidr = "ip route add {0} br-int".format(cidr)
    for compute in compute_nodes:
        compute.run_cmd("ifconfig br-int up")
        if not compute.run_cmd(grep_cidr_routes):
            logger.info("adding route %s in %s" % (cidr, compute.ip))
            compute.run_cmd(add_cidr)
        else:
            logger.info("route %s exists" % cidr)

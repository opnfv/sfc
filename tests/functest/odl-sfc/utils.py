import os
import subprocess
import time
import functest.utils.functest_logger as ft_logger
import functest.utils.functest_utils as ft_utils
import functest.utils.openstack_utils as os_utils
import re
import json
import SSHUtils as ssh_utils


logger = ft_logger.Logger("sfc_test_utils").getLogger()
SSH_OPTIONS = '-q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'
FUNCTEST_RESULTS_DIR = os.path.join("home", "opnfv",
                                    "functest", "results", "odl-sfc")


def run_cmd(cmd, wdir=None, ignore_stderr=False, ignore_no_output=True):
    """run given command locally and return commands output if success"""
    pipe = subprocess.Popen(cmd, shell=True,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, cwd=wdir)

    (output, errors) = pipe.communicate()
    if output:
        output = output.strip()
    if pipe.returncode < 0:
        logger.error(errors)
        return False
    if errors:
        logger.error(errors)
        return ignore_stderr

    if ignore_no_output and not output:
        return True

    return output


def run_cmd_on_controller(cmd):
    """run given command on OpenStack controller"""
    ip_controllers = get_openstack_node_ips("controller")
    if not ip_controllers:
        return None

    ssh_cmd = "ssh %s %s %s" % (SSH_OPTIONS, ip_controllers[0], cmd)
    return run_cmd_on_fm(ssh_cmd)


def run_cmd_on_compute(cmd):
    """run given command on OpenStack Compute node"""
    ip_computes = get_openstack_node_ips("compute")
    if not ip_computes:
        return None

    ssh_cmd = "ssh %s %s %s" % (SSH_OPTIONS, ip_computes[0], cmd)
    return run_cmd_on_fm(ssh_cmd)


def run_cmd_on_fm(cmd, username="root", passwd="r00tme"):
    """run given command on Fuel Master"""
    ip = os.environ.get("INSTALLER_IP")
    ssh_cmd = "sshpass -p %s ssh %s %s@%s %s" % (
        passwd, SSH_OPTIONS, username, ip, cmd)
    return run_cmd(ssh_cmd)


def run_cmd_remote(ip, cmd, username="root", passwd="opnfv"):
    """run given command on Remote Machine, Can be VM"""
    ssh_opt_append = "%s -o ConnectTimeout=50 " % SSH_OPTIONS
    ssh_cmd = "sshpass -p %s ssh %s %s@%s %s" % (
        passwd, ssh_opt_append, username, ip, cmd)
    return run_cmd(ssh_cmd)


def get_openstack_node_ips(role):
    """Get OpenStack Nodes IP Address"""
    fuel_env = os.environ.get("FUEL_ENV")
    if fuel_env is not None:
        cmd = "fuel2 node list -f json -e %s" % fuel_env
    else:
        cmd = "fuel2 node list -f json"

    nodes = run_cmd_on_fm(cmd)
    ips = []
    nodes = json.loads(nodes)
    for node in nodes:
        if role in node["roles"]:
            ips.append(node["ip"])

    return ips


def configure_iptables():
    """Configures IPTABLES on OpenStack Controller"""
    iptable_cmds = ["iptables -P INPUT ACCEPT",
                    "iptables -t nat -P INPUT ACCEPT",
                    "iptables -A INPUT -m state \
                    --state NEW,ESTABLISHED,RELATED -j ACCEPT"]

    for cmd in iptable_cmds:
        logger.info("Configuring %s on contoller" % cmd)
        run_cmd_on_controller(cmd)


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
                    compute_node='', userdata=None, files=None):
    logger.info("Creating instance '%s'..." % name)
    logger.debug(
        "Configuration:\n name=%s \n flavor=%s \n image=%s \n"
        " network=%s\n secgroup=%s \n hypervisor=%s \n"
        " fixed_ip=%s\n files=%s\n userdata=\n%s\n"
        % (name, flavor, image_id, network_id, sg_id,
           compute_node, fixed_ip, files, userdata))
    instance = os_utils.create_instance_and_wait_for_active(
        flavor,
        image_id,
        network_id,
        name,
        config_drive=True,
        userdata=userdata,
        av_zone=compute_node,
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
    instances = nova_client.servers.list(search_opts={'all_tenants': 1})
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


def capture_err_logs(ovs_logger, controller_clients, compute_clients, error):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    ovs_logger.dump_ovs_logs(controller_clients,
                             compute_clients,
                             related_error=error,
                             timestamp=timestamp)


def get_ssh_clients(role, proxy):
    clients = []
    for ip in get_openstack_node_ips(role):
        s_client = ssh_utils.get_ssh_client(ip, 'root', proxy=proxy)
        clients.append(s_client)

    return clients


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


def ofctl_time_counter(ovs_logger, ssh_conn):
    try:
        # We get the flows from table 11
        table = 11
        br = "br-int"
        output = ovs_logger.ofctl_dump_flows(ssh_conn, br, table)
        pattern = "NXM_NX_NSP"
        rsps = []
        lines = output.split(",")
        for line in lines:
            is_there = re.findall(pattern, line)
            if is_there:
                value = line.split(":")[1].split("-")[0]
                rsps.append(value)
        return rsps
    except Exception, e:
        logger.error('Error when countering %s' % e)
        return None


@ft_utils.timethis
def capture_time_log(ovs_logger, compute_clients, timeout=200):
    rsps = ofctl_time_counter(ovs_logger, compute_clients[0])
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


def get_compute_nodes(nova_client, required_node_number=2):
    """Get the compute nodes in the deployment"""
    compute_nodes = os_utils.get_hypervisors(nova_client)

    num_compute_nodes = len(compute_nodes)
    if num_compute_nodes < 2:
        logger.error("There are %s compute nodes in the deployment. "
                     "Minimum number of nodes to complete the test is 2."
                     % num_compute_nodes)
        return None

    logger.debug("Compute nodes: %s" % compute_nodes)
    return compute_nodes


def setup_compute_node(cidr):
    logger.info("bringing up br-int iface")
    run_cmd_on_compute("ifconfig br-int up")
    if not run_cmd_on_compute("ip route|grep -o %s" % cidr):
        logger.info("adding route %s" % cidr)
        return run_cmd_on_compute("ip route add %s" % cidr)
    else:
        logger.info("route %s exists" % cidr)

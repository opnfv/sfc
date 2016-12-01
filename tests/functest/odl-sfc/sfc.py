import argparse
import os
import sys
import functest.utils.functest_logger as ft_logger
import functest.utils.openstack_utils as os_utils
import functest.utils.openstack_tacker as os_tacker
from terminal_colors import TerminalColors as terminal
import threading
import ovs_utils
import utils as test_utils
import config as sfc_config
from results import Results


parser = argparse.ArgumentParser()

parser.add_argument("-r", "--report",
                    help="Create json result file",
                    action="store_true")

args = parser.parse_args()

""" logging configuration """
logger = ft_logger.Logger("ODL_SFC").getLogger()

CLIENT = "client"
SERVER = "server"
COMMON_CONFIG = sfc_config.CommonConfig()
# TestcaseConfig sfc name will be changed once
# we rename sfc.py with appropriate name
TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc')


def main():
    results = Results(COMMON_CONFIG.line_length)
    results.add_to_summary(0, "=")
    results.add_to_summary(2, "STATUS", "SUBTEST")
    results.add_to_summary(0, "=")

    installer_type = os.environ.get("INSTALLER_TYPE")
    if installer_type != "fuel":
        logger.error(
            terminal.foreground(
                'Currently supported only Fuel Installer type', 'light_red'))
        sys.exit(1)

    installer_ip = os.environ.get("INSTALLER_IP")
    if not installer_ip:
        logger.error(
            terminal.foreground('Installer ip is not set', 'light_red'))
        logger.error(
            terminal.foreground('export INSTALLER_IP=<ip>', 'light_red'))
        sys.exit(1)

    test_utils.setup_compute_node(TESTCASE_CONFIG.subnet_cidr)
    test_utils.configure_iptables()
    test_utils.download_image(COMMON_CONFIG.url,
                              COMMON_CONFIG.image_path)
    _, custom_flv_id = os_utils.get_or_create_flavor(
        COMMON_CONFIG.flavor, 1500, 10, 1, public=True)
    if not custom_flv_id:
        logger.error("Failed to create custom flavor")
        sys.exit(1)

    glance_client = os_utils.get_glance_client()
    neutron_client = os_utils.get_neutron_client()
    nova_client = os_utils.get_nova_client()
    tacker_client = os_tacker.get_tacker_client()

    controller_clients = test_utils.get_ssh_clients("controller",
                                                    COMMON_CONFIG.fuel_proxy)
    compute_clients = test_utils.get_ssh_clients("compute",
                                                 COMMON_CONFIG.fuel_proxy)

    ovs_logger = ovs_utils.OVSLogger(
        os.path.join(COMMON_CONFIG.sfc_test_dir, 'ovs-logs'),
        COMMON_CONFIG.functest_results_dir)

    image_id = os_utils.create_glance_image(glance_client,
                                            COMMON_CONFIG.image_name,
                                            COMMON_CONFIG.image_path,
                                            COMMON_CONFIG.image_format,
                                            public=True)

    network_id = test_utils.setup_neutron(neutron_client,
                                          TESTCASE_CONFIG.net_name,
                                          TESTCASE_CONFIG.subnet_name,
                                          TESTCASE_CONFIG.router_name,
                                          TESTCASE_CONFIG.subnet_cidr)

    sg_id = test_utils.create_security_groups(neutron_client,
                                              TESTCASE_CONFIG.secgroup_name,
                                              TESTCASE_CONFIG.secgroup_descr)

    test_utils.create_instance(
        nova_client, CLIENT, COMMON_CONFIG.flavor, image_id,
        network_id, sg_id)
    srv_instance = test_utils.create_instance(
        nova_client, SERVER, COMMON_CONFIG.flavor, image_id,
        network_id, sg_id)

    srv_prv_ip = srv_instance.networks.get(TESTCASE_CONFIG.net_name)[0]

    tosca_file = os.path.join(COMMON_CONFIG.sfc_test_dir,
                              COMMON_CONFIG.vnfd_dir,
                              TESTCASE_CONFIG.test_vnfd_red)
    os_tacker.create_vnfd(
        tacker_client,
        tosca_file=tosca_file)

    tosca_file = os.path.join(COMMON_CONFIG.sfc_test_dir,
                              COMMON_CONFIG.vnfd_dir,
                              TESTCASE_CONFIG.test_vnfd_blue)
    os_tacker.create_vnfd(
        tacker_client,
        tosca_file=tosca_file)

    os_tacker.create_vnf(
        tacker_client, 'testVNF1', vnfd_name='test-vnfd1')
    os_tacker.create_vnf(
        tacker_client, 'testVNF2', vnfd_name='test-vnfd2')

    try:
        os_tacker.wait_for_vnf(tacker_client, vnf_name='testVNF1')
        os_tacker.wait_for_vnf(tacker_client, vnf_name='testVNF2')
    except:
        logger.error('ERROR while booting vnfs')
        sys.exit(1)

    os_tacker.create_sfc(tacker_client, 'red', chain_vnf_names=['testVNF1'])
    os_tacker.create_sfc(tacker_client, 'blue', chain_vnf_names=['testVNF2'])

    os_tacker.create_sfc_classifier(
        tacker_client, 'red_http', sfc_name='red',
        match={
            'source_port': 0,
            'dest_port': 80,
            'protocol': 6
        })

    os_tacker.create_sfc_classifier(
        tacker_client, 'red_ssh', sfc_name='red',
        match={
            'source_port': 0,
            'dest_port': 22,
            'protocol': 6
        })

    logger.info(test_utils.run_cmd('tacker sfc-list'))
    logger.info(test_utils.run_cmd('tacker sfc-classifier-list'))

    # Start measuring the time it takes to implement the classification rules
    t1 = threading.Thread(target=test_utils.capture_time_log,
                          args=(ovs_logger, compute_clients,))
    try:
        t1.start()
    except Exception, e:
        logger.error("Unable to start the thread that counts time %s" % e)

    server_ip, client_ip, sf1, sf2 = test_utils.get_floating_ips(
        nova_client, neutron_client)

    if not test_utils.check_ssh([sf1, sf2]):
        logger.error("Cannot establish SSH connection to the SFs")
        sys.exit(1)

    logger.info("Starting HTTP server on %s" % server_ip)
    if not test_utils.start_http_server(server_ip):
        logger.error(
            terminal.foreground(
                'Failed to start HTTP server on %s' % server_ip,
                'light_red'))
        sys.exit(1)

    logger.info("Starting HTTP firewall on %s" % sf2)
    test_utils.vxlan_firewall(sf2, port="80")
    logger.info("Starting SSH firewall on %s" % sf1)
    test_utils.vxlan_firewall(sf1, port="22")

    logger.info("Wait for ODL to update the classification rules in OVS")
    t1.join()

    logger.info("Test SSH")
    if test_utils.is_ssh_blocked(srv_prv_ip, client_ip):
        results.add_to_summary(2, "PASS", "SSH Blocked")
    else:
        error = terminal.foreground(
            'TEST 1 [FAILED] ==> SSH NOT BLOCKED',
            'light_red')
        logger.error(error)
        test_utils.capture_err_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "SSH Blocked")

    logger.info("Test HTTP")
    if not test_utils.is_http_blocked(srv_prv_ip, client_ip):
        results.add_to_summary(2, "PASS", "HTTP works")
    else:
        error = terminal.foreground(
            'TEST 2 [FAILED] ==> HTTP BLOCKED',
            'light_red')
        logger.error(error)
        test_utils.capture_err_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP works")

    logger.info("Changing the classification")
    os_tacker.delete_sfc_classifier(tacker_client, sfc_clf_name='red_http')
    os_tacker.delete_sfc_classifier(tacker_client, sfc_clf_name='red_ssh')

    os_tacker.create_sfc_classifier(
        tacker_client, 'blue_http', sfc_name='blue',
        match={
            'source_port': 0,
            'dest_port': 80,
            'protocol': 6
        })

    os_tacker.create_sfc_classifier(
        tacker_client, 'blue_ssh', sfc_name='blue',
        match={
            'source_port': 0,
            'dest_port': 22,
            'protocol': 6
        })

    logger.info(test_utils.run_cmd('tacker sfc-classifier-list'))

    # Start measuring the time it takes to implement the classification rules
    t2 = threading.Thread(target=test_utils.capture_time_log,
                          args=(ovs_logger, compute_clients,))
    try:
        t2.start()
    except Exception, e:
        logger.error("Unable to start the thread that counts time %s" % e)

    logger.info("Wait for ODL to update the classification rules in OVS")
    t2.join()

    logger.info("Test HTTP")
    if test_utils.is_http_blocked(srv_prv_ip, client_ip):
        results.add_to_summary(2, "PASS", "HTTP Blocked")
    else:
        error = (terminal.foreground(
            'TEST 3 [FAILED] ==> HTTP WORKS',
            'light_red'))
        logger.error(error)
        test_utils.capture_err_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP Blocked")

    logger.info("Test SSH")
    if not test_utils.is_ssh_blocked(srv_prv_ip, client_ip):
        results.add_to_summary(2, "PASS", "SSH works")
    else:
        error = (terminal.foreground(
            'TEST 4 [FAILED] ==> SSH BLOCKED',
            'light_red'))
        logger.error(error)
        test_utils.capture_err_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "SSH works")

    return results.compile_summary()


if __name__ == '__main__':
    main()

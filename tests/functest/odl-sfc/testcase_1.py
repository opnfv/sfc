import argparse
import os
import subprocess
import sys
import functest.utils.functest_logger as ft_logger
import functest.utils.openstack_utils as os_utils
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
TESTCASE_CONFIG = sfc_config.TestcaseConfig('testcase_1')

SFC_TEST_DIR = os.path.join(COMMON_CONFIG.repo_path,
                            "tests", "functest", "odl-sfc")
TACKER_SCRIPT = os.path.join(SFC_TEST_DIR, "sfc_tacker.bash")
TACKER_CHANGECLASSI = os.path.join(SFC_TEST_DIR, "sfc_change_classi.bash")


def main():
    results = Results(COMMON_CONFIG.line_length)

    results.add_to_summary(0, "=")
    results.add_to_summary(2, "STATUS", "SUBTEST")
    results.add_to_summary(0, "=")

    installer_type = os.environ.get("INSTALLER_TYPE")
    if installer_type != "fuel":
        logger.error(
            '\033[91mCurrently support only Fuel Installer type\033[0m')
        sys.exit(1)

    installer_ip = os.environ.get("INSTALLER_IP")
    if not installer_ip:
        logger.error(
            '\033[91minstaller ip is not set\033[0m')
        logger.error(
            '\033[91mexport INSTALLER_IP=<ip>\033[0m')
        sys.exit(1)

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

    proxy = {
        'ip': COMMON_CONFIG.fuel_master_ip,
        'username': COMMON_CONFIG.fuel_master_uname,
        'password': COMMON_CONFIG.fuel_master_passwd
    }

    controller_clients = test_utils.get_ssh_clients("controller", proxy)
    compute_clients = test_utils.get_ssh_clients("compute", proxy)

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

    test_utils.boot_instance(
        nova_client, CLIENT, COMMON_CONFIG.flavor, image_id,
        network_id, sg_id, TESTCASE_CONFIG.net_name)
    srv_prv_ip = test_utils.boot_instance(
        nova_client, SERVER, COMMON_CONFIG.flavor, image_id,
        network_id, sg_id, TESTCASE_CONFIG.net_name)

    subprocess.call(TACKER_SCRIPT, shell=True)

    # Start measuring the time it takes to implement the classification rules
    try:
        t1 = test_utils.start_new_thread(test_utils.capture_time_log,
                                         compute_clients)
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
            '\033[91mFailed to start HTTP server on %s\033[0m' % server_ip)
        sys.exit(1)

    logger.info("Starting HTTP firewall on %s" % sf2)
    test_utils.vxlan_firewall(sf2, port="80")
    logger.info("Starting SSH firewall on %s" % sf1)
    test_utils.vxlan_firewall(sf1, port="22")

    logger.info("Wait for ODL to update the classification rules in OVS")
    t1.join()

    if test_utils.is_ssh_blocked(srv_prv_ip, client_ip):
        results.add_to_summary(2, "PASS", "SSH Blocked")
    else:
        error = ('\033[91mTEST 1 [FAILED] ==> SSH NOT BLOCKED\033[0m')
        logger.error(error)
        test_utils.capture_err_logs(controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "SSH Blocked")

    if not test_utils.is_http_blocked(srv_prv_ip, client_ip):
        results.add_to_summary(2, "PASS", "HTTP works")
    else:
        error = ('\033[91mTEST 2 [FAILED] ==> HTTP BLOCKED\033[0m')
        logger.error(error)
        test_utils.capture_err_logs(controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP works")

    logger.info("Changing the classification")
    subprocess.call(TACKER_CHANGECLASSI, shell=True)

    try:
        t2 = test_utils.start_new_thread(
            test_utils.capture_time_log, compute_clients)
    except Exception, e:
        logger.error("Unable to start the thread that counts time %s" % e)

    logger.info("Wait for ODL to update the classification rules in OVS")
    t2.join()
    if test_utils.is_http_blocked(srv_prv_ip, client_ip):
        results.add_to_summary(2, "PASS", "HTTP Blocked")
    else:
        error = ('\033[91mTEST 3 [FAILED] ==> HTTP WORKS\033[0m')
        logger.error(error)
        test_utils.capture_err_logs(controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP Blocked")

    if not test_utils.is_ssh_blocked(srv_prv_ip, client_ip):
        results.add_to_summary(2, "PASS", "SSH works")
    else:
        error = ('\033[91mTEST 4 [FAILED] ==> SSH BLOCKED\033[0m')
        logger.error(error)
        test_utils.capture_err_logs(controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "SSH works")

    return results.compile_summary(TESTCASE_CONFIG.success_criteria)


if __name__ == '__main__':
    main()

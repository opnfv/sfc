import argparse
import os
import sys
import time
import functest.utils.functest_logger as ft_logger
import functest.utils.functest_utils as ft_utils
import functest.utils.openstack_utils as os_utils
import functest.utils.openstack_tacker as os_tacker
import threading
import utils as test_utils
import config as sfc_config

parser = argparse.ArgumentParser()

parser.add_argument("-r", "--report",
                    help="Create json result file",
                    action="store_true")

args = parser.parse_args()

""" logging configuration """
logger = ft_logger.Logger("ODL_SFC").getLogger()

CLIENT = "client"
SERVER = "server"
json_results = {"tests": 4, "failures": 0}
COMMON_CONFIG = sfc_config.CommonConfig()
TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_two_chains_SSH_and_HTTP')


def update_json_results(name, result):
    json_results.update({name: result})
    if result is not "Passed":
        json_results["failures"] += 1

    return


def main():
    installer_type = os.environ.get("INSTALLER_TYPE")
    if installer_type != "fuel":
        logger.error(
            '\033[91mCurrently supported only Fuel Installer type\033[0m')
        sys.exit(1)

    installer_ip = os.environ.get("INSTALLER_IP")
    if not installer_ip:
        logger.error(
            '\033[91minstaller ip is not set\033[0m')
        logger.error(
            '\033[91mexport INSTALLER_IP=<ip>\033[0m')
        sys.exit(1)

    start_time = time.time()
    status = "PASS"
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

    test_utils.create_instance(
        nova_client, CLIENT, COMMON_CONFIG.flavor, image_id,
        network_id, sg_id)
    srv_instance = test_utils.create_instance(
        nova_client, SERVER, COMMON_CONFIG.flavor, image_id,
        network_id, sg_id)

    srv_prv_ip = srv_instance.networks.get(TESTCASE_CONFIG.net_name)[0]

    tosca_file = os.path.join(COMMON_CONFIG.vnfd_yaml_dir,
                              TESTCASE_CONFIG.test_vnfd_red)

    # creates testVNF1 and waits for it to come up
    test_utils.create_tacker_vnf_instance(tacker_client,
                                          tosca_file, 'testVNF1')

    tosca_file = os.path.join(COMMON_CONFIG.vnfd_yaml_dir,
                              TESTCASE_CONFIG.test_vnfd_blue)

    # creates testVNF2 and waits for it to come up
    test_utils.create_tacker_vnf_instance(tacker_client,
                                          tosca_file, 'testVNF2')

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
                          args=(compute_clients,))
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
            '\033[91mFailed to start HTTP server on %s\033[0m' % server_ip)
        sys.exit(1)

    logger.info("Starting HTTP firewall on %s" % sf2)
    test_utils.vxlan_firewall(sf2, port="80")
    logger.info("Starting SSH firewall on %s" % sf1)
    test_utils.vxlan_firewall(sf1, port="22")

    logger.info("Wait for ODL to update the classification rules in OVS")
    t1.join()

    logger.info("Test SSH")
    if test_utils.is_ssh_blocked(srv_prv_ip, client_ip):
        logger.info('\033[92mTEST 1 [PASSED] ==> SSH BLOCKED\033[0m')
        update_json_results("Test 1: SSH Blocked", "Passed")
    else:
        error = ('\033[91mTEST 1 [FAILED] ==> SSH NOT BLOCKED\033[0m')
        logger.error(error)
        test_utils.capture_err_logs(controller_clients, compute_clients, error)
        update_json_results("Test 1: SSH Blocked", "Failed")

    logger.info("Test HTTP")
    if not test_utils.is_http_blocked(srv_prv_ip, client_ip):
        logger.info('\033[92mTEST 2 [PASSED] ==> HTTP WORKS\033[0m')
        update_json_results("Test 2: HTTP works", "Passed")
    else:
        error = ('\033[91mTEST 2 [FAILED] ==> HTTP BLOCKED\033[0m')
        logger.error(error)
        test_utils.capture_err_logs(controller_clients, compute_clients, error)
        update_json_results("Test 2: HTTP works", "Failed")

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
                          args=(compute_clients,))
    try:
        t2.start()
    except Exception, e:
        logger.error("Unable to start the thread that counts time %s" % e)

    logger.info("Wait for ODL to update the classification rules in OVS")
    t2.join()

    logger.info("Test HTTP")
    if test_utils.is_http_blocked(srv_prv_ip, client_ip):
        logger.info('\033[92mTEST 3 [PASSED] ==> HTTP Blocked\033[0m')
        update_json_results("Test 3: HTTP Blocked", "Passed")
    else:
        error = ('\033[91mTEST 3 [FAILED] ==> HTTP WORKS\033[0m')
        logger.error(error)
        test_utils.capture_err_logs(controller_clients, compute_clients, error)
        update_json_results("Test 3: HTTP Blocked", "Failed")

    logger.info("Test SSH")
    if not test_utils.is_ssh_blocked(srv_prv_ip, client_ip):
        logger.info('\033[92mTEST 4 [PASSED] ==> SSH Works\033[0m')
        update_json_results("Test 4: SSH Works", "Passed")
    else:
        error = ('\033[91mTEST 4 [FAILED] ==> SSH BLOCKED\033[0m')
        logger.error(error)
        test_utils.capture_err_logs(controller_clients, compute_clients, error)
        update_json_results("Test 4: SSH Works", "Failed")

    if json_results["failures"]:
        status = "FAIL"
        logger.error('\033[91mSFC TESTS: %s :( FOUND %s FAIL \033[0m' % (
            status, json_results["failures"]))

    if args.report:
        stop_time = time.time()
        logger.debug("Promise Results json: " + str(json_results))
        ft_utils.push_results_to_db("sfc",
                                    "sfc_two_chains_SSH_and_HTTP",
                                    start_time,
                                    stop_time,
                                    status,
                                    json_results)

    if status == "PASS":
        logger.info('\033[92mSFC ALL TESTS: %s :)\033[0m' % status)
        sys.exit(0)

    sys.exit(1)


if __name__ == '__main__':
    main()

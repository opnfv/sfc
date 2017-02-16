#!/bin/python
#
# Copyright (c) 2015 All rights reserved
# This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
#
# http://www.apache.org/licenses/LICENSE-2.0
#

import argparse
import os
import sys
import time

import functest.utils.functest_logger as ft_logger
import functest.utils.functest_utils as ft_utils
import functest.utils.openstack_tacker as os_tacker
import functest.utils.openstack_utils as os_utils
import opnfv.utils.ovs_logger as ovs_log
import sfc.lib.config as sfc_config
import sfc.lib.utils as test_utils


parser = argparse.ArgumentParser()

parser.add_argument("-r", "--report",
                    help="Create json result file",
                    action="store_true")

args = parser.parse_args()

""" logging configuration """
logger = ft_logger.Logger("ODL_SFC").getLogger()

REPO_PATH = os.path.join(os.environ['REPOS_DIR'], 'sfc/')
SFC_TEST_DIR = os.path.join(REPO_PATH, "sfc/tests/functest")
TACKER_SCRIPT = os.path.join(SFC_TEST_DIR, "sfc_tacker_test2.bash")
TACKER_VNFD1 = os.path.join(SFC_TEST_DIR, "vnfd-templates", "test2-vnfd1.yaml")
TACKER_VNFD2 = os.path.join(SFC_TEST_DIR, "vnfd-templates", "test2-vnfd2.yaml")
CLIENT = "client"
SERVER = "server"
ssh_options = '-q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'
json_results = {"tests": 4, "failures": 0}
COMMON_CONFIG = sfc_config.CommonConfig()
TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_one_chain_two_service'
                                            '_functions_different_computes')

PROXY = {
    'ip': COMMON_CONFIG.fuel_master_ip,
    'username': COMMON_CONFIG.fuel_master_uname,
    'password': COMMON_CONFIG.fuel_master_passwd
}


def update_json_results(name, result):
    json_results.update({name: result})
    if result is not "Passed":
        json_results["failures"] += 1
    return


# JIRA: SFC-52 new function
def setup_availability_zones(nova_client):
    computes = os_utils.get_hypervisors(nova_client)
    az = ["nova::" + computes[0], "nova::" + computes[1]]
    logger.debug("These are the availability zones %s" % az)
    return az


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

    controller_clients = test_utils.get_ssh_clients("controller", PROXY)
    compute_clients = test_utils.get_ssh_clients("compute", PROXY)

    ovs_logger = ovs_log.OVSLogger(
        os.path.join(COMMON_CONFIG.sfc_test_dir, 'ovs-logs'),
        COMMON_CONFIG.functest_results_dir)

    image_id = os_utils.create_glance_image(glance_client,
                                            COMMON_CONFIG.image_name,
                                            COMMON_CONFIG.image_path,
                                            COMMON_CONFIG.image_format,
                                            public='public')

    network_id = test_utils.setup_neutron(neutron_client,
                                          TESTCASE_CONFIG.net_name,
                                          TESTCASE_CONFIG.subnet_name,
                                          TESTCASE_CONFIG.router_name,
                                          TESTCASE_CONFIG.subnet_cidr)

    sg_id = test_utils.create_security_groups(neutron_client,
                                              TESTCASE_CONFIG.secgroup_name,
                                              TESTCASE_CONFIG.secgroup_descr)

    availability_zones = setup_availability_zones(nova_client)

    test_utils.create_instance(
        nova_client, CLIENT, COMMON_CONFIG.flavor,
        image_id, network_id, sg_id)

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

    test_utils.create_vnf_in_av_zone(
        tacker_client,
        'testVNF1',
        'test-vnfd1',
        av_zone=availability_zones[0])
    test_utils.create_vnf_in_av_zone(
        tacker_client,
        'testVNF2',
        'test-vnfd2',
        av_zone=availability_zones[1])

    vnf1_id = os_tacker.wait_for_vnf(tacker_client, vnf_name='testVNF1')
    vnf2_id = os_tacker.wait_for_vnf(tacker_client, vnf_name='testVNF2')
    if vnf1_id is None or vnf2_id is None:
        logger.error('ERROR while booting vnfs')
        sys.exit(1)

    os_tacker.create_sfc(tacker_client, 'red',
                         chain_vnf_names=['testVNF1', 'testVNF2'])

    os_tacker.create_sfc_classifier(
        tacker_client, 'red_http', sfc_name='red',
        match={
            'source_port': 0,
            'dest_port': 80,
            'protocol': 6
        })

    logger.info(test_utils.run_cmd('tacker sfc-list')[1])
    logger.info(test_utils.run_cmd('tacker sfc-classifier-list')[1])

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

    logger.info("Starting vxlan_tool on %s" % sf2)
    test_utils.vxlan_firewall(sf2, block=False)
    logger.info("Starting vxlan_tool on %s" % sf1)
    test_utils.vxlan_firewall(sf1, block=False)

    logger.info("Wait for ODL to update the classification rules in OVS")
    time.sleep(100)

    logger.info("Test HTTP")
    if not test_utils.is_http_blocked(client_ip, srv_prv_ip):
        logger.info('\033[92mTEST 1 [PASSED] ==> HTTP WORKS\033[0m')
        update_json_results("Test 1: HTTP works", "Passed")
    else:
        error = ('\033[91mTEST 1 [FAILED] ==> HTTP BLOCKED\033[0m')
        logger.error(error)
        test_utils.capture_ovs_logs(
            ovs_logger, controller_clients, compute_clients, error)
        update_json_results("Test 1: HTTP works", "Failed")

    logger.info("Changing the vxlan_tool to block HTTP traffic")

    # Make SF1 block now http traffic
    test_utils.vxlan_tool_stop(sf1)
    test_utils.vxlan_firewall(sf1, port="80")

    logger.info("Test HTTP again")
    if test_utils.is_http_blocked(client_ip, srv_prv_ip):
        logger.info('\033[92mTEST 2 [PASSED] ==> HTTP Blocked\033[0m')
        update_json_results("Test 2: HTTP Blocked", "Passed")
    else:
        error = ('\033[91mTEST 2 [FAILED] ==> HTTP WORKS\033[0m')
        logger.error(error)
        test_utils.capture_ovs_logs(
            ovs_logger, controller_clients, compute_clients, error)
        update_json_results("Test 2: HTTP Blocked", "Failed")

    if json_results["failures"]:
        status = "FAIL"
        logger.error('\033[91mSFC TESTS: %s :( FOUND %s FAIL \033[0m' % (
            status, json_results["failures"]))

    if args.report:
        stop_time = time.time()
        logger.debug("Promise Results json: " + str(json_results))
        ft_utils.push_results_to_db("sfc",
                                    "sfc_one_chain_two_service_functions"
                                    "_different_computes",
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

#!/bin/python
#
# Copyright (c) 2015 All rights reserved
# This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
#
# http://www.apache.org/licenses/LICENSE-2.0
#

import os
import sys
import threading

import functest.utils.functest_logger as ft_logger
import functest.utils.openstack_tacker as os_tacker
import functest.utils.openstack_utils as os_utils
import opnfv.utils.ovs_logger as ovs_log

import sfc.lib.config as sfc_config
import sfc.lib.utils as test_utils
from sfc.lib.results import Results


logger = ft_logger.Logger("ODL_SFC").getLogger()

CLIENT = "client"
SERVER = "server"
COMMON_CONFIG = sfc_config.CommonConfig()
TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_symmetric_chain')


def assert_installer_type():
    if os.environ.get('INSTALLER_TYPE')  not in ('fuel', 'apex'):
        logger.error(
            '\033[91mCurrently supported only Fuel Installer type\033[0m')
        sys.exit(1)

def assert_installer_ip():
    if not os.environ.get("INSTALLER_IP"):
        logger.error('\033[91minstaller ip is not set\033[0m')
        logger.error('\033[91mexport INSTALLER_IP=<ip>\033[0m')
        sys.exit(1)


def main():
    assert_installer_type()
    assert_installer_ip()

    results = Results(COMMON_CONFIG.line_length)
    results.add_to_summary(0, "=")
    results.add_to_summary(2, "STATUS", "SUBTEST")
    results.add_to_summary(0, "=")

    test_utils.setup_compute_node(TESTCASE_CONFIG.subnet_cidr)
    test_utils.configure_iptables()
    test_utils.download_image(COMMON_CONFIG.url, COMMON_CONFIG.image_path)
    _, custom_flv_id = os_utils.get_or_create_flavor(
        COMMON_CONFIG.flavor,
        COMMON_CONFIG.ram_size_in_mb,
        COMMON_CONFIG.disk_size_in_gb,
        COMMON_CONFIG.vcpu_count,
        public=True)
    if not custom_flv_id:
        logger.error("Failed to create custom flavor")
        sys.exit(1)

    glance_client = os_utils.get_glance_client()
    neutron_client = os_utils.get_neutron_client()
    nova_client = os_utils.get_nova_client()
    tacker_client = os_tacker.get_tacker_client()

    controller_clients = test_utils.get_ssh_clients(
        "controller",
        COMMON_CONFIG.fuel_proxy)

    compute_clients = test_utils.get_ssh_clients(
        "compute",
        COMMON_CONFIG.fuel_proxy)

    ovs_logger = ovs_log.OVSLogger(
        os.path.join(COMMON_CONFIG.sfc_test_dir, 'ovs-logs'),
        COMMON_CONFIG.functest_results_dir)

    image_id = os_utils.create_glance_image(
        glance_client,
        COMMON_CONFIG.image_name,
        COMMON_CONFIG.image_path,
        COMMON_CONFIG.image_format,
        public='public')

    network_id = test_utils.setup_neutron(
        neutron_client,
        TESTCASE_CONFIG.net_name,
        TESTCASE_CONFIG.subnet_name,
        TESTCASE_CONFIG.router_name,
        TESTCASE_CONFIG.subnet_cidr)

    sg_id = test_utils.create_security_groups(
        neutron_client,
        TESTCASE_CONFIG.secgroup_name,
        TESTCASE_CONFIG.secgroup_descr)

    test_utils.create_instance(
        nova_client,
        CLIENT,
        COMMON_CONFIG.flavor,
        image_id,
        network_id,
        sg_id)

    srv_instance = test_utils.create_instance(
        nova_client,
        SERVER,
        COMMON_CONFIG.flavor,
        image_id,
        network_id,
        sg_id)

    srv_prv_ip = srv_instance.networks.get(TESTCASE_CONFIG.net_name)[0]

    tosca = os.path.join(
        COMMON_CONFIG.sfc_test_dir,
        COMMON_CONFIG.vnfd_dir,
        TESTCASE_CONFIG.test_vnfd)

    os_tacker.create_vnfd(tacker_client, tosca_file=tosca)
    os_tacker.create_vnf(tacker_client, 'testVNF1', vnfd_name='test-vnfd1')

    try:
        os_tacker.wait_for_vnf(tacker_client, vnf_name='testVNF1')
    except:
        logger.error('ERROR while booting VNF')
        sys.exit(1)

    # TODO: this chain should be symmetric
    os_tacker.create_sfc(tacker_client, 'red', chain_vnf_names=['testVNF1'])

    os_tacker.create_sfc_classifier(
        tacker_client, 'red_http', sfc_name='red',
        match={
            'source_port': 0,
            'dest_port': 80,
            'protocol': 6
        })

    logger.info(test_utils.run_cmd('tacker sfc-list'))
    logger.info(test_utils.run_cmd('tacker sfc-classifier-list'))

    # Start measuring the time it takes to implement the classification rules
    t1 = threading.Thread(target=test_utils.wait_for_classification_rules,
                          args=(ovs_logger, compute_clients,))
    try:
        t1.start()
    except Exception, e:
        logger.error("Unable to start the thread that counts time %s" % e)

    # TODO: Find a replacement for get_floating_ips()
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

    # TODO: Add port to configuration
    logger.info("Starting firewall on %s, blocking port %d" % (sf2, 23023))
    test_utils.vxlan_firewall(sf2, port="23023")

    logger.info("Wait for ODL to update the classification rules in OVS")
    t1.join()

    # TODO: Ensure src port is NOT 23023
    logger.info("Test HTTP")
    if not test_utils.is_http_blocked(srv_prv_ip, client_ip):
        results.add_to_summary(2, "PASS", "HTTP works")
    else:
        error = ('\033[91mTEST 2 [FAILED] ==> HTTP BLOCKED\033[0m')
        logger.error(error)
        test_utils.capture_ovs_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP works")


    # TODO: Ensure src port is 23023
    logger.info("Test HTTP")
    if test_utils.is_http_blocked(srv_prv_ip, client_ip):
        results.add_to_summary(2, "PASS", "HTTP Blocked")
    else:
        error = ('\033[91mTEST 3 [FAILED] ==> HTTP WORKS\033[0m')
        logger.error(error)
        test_utils.capture_ovs_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP Blocked")

    return results.compile_summary()


if __name__ == '__main__':
    main()

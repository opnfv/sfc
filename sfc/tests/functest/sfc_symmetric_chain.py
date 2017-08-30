#!/bin/python
#
# Copyright (c) 2017 Ericsson AB and others. All rights reserved
#
# This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
#
# http://www.apache.org/licenses/LICENSE-2.0
#

import os
import sys
import threading
import logging

import functest.utils.openstack_tacker as os_tacker
import functest.utils.openstack_utils as os_utils
import opnfv.utils.ovs_logger as ovs_log
from opnfv.deployment.factory import Factory as DeploymentFactory

import sfc.lib.config as sfc_config
import sfc.lib.utils as test_utils
from sfc.lib.results import Results
import sfc.lib.topology_shuffler as topo_shuffler


logger = logging.getLogger(__name__)

CLIENT = "client"
SERVER = "server"
COMMON_CONFIG = sfc_config.CommonConfig()
TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_symmetric_chain')


def main():
    deploymentHandler = DeploymentFactory.get_handler(
        COMMON_CONFIG.installer_type,
        COMMON_CONFIG.installer_ip,
        COMMON_CONFIG.installer_user,
        COMMON_CONFIG.installer_password,
        COMMON_CONFIG.installer_key_file)

    cluster = COMMON_CONFIG.installer_cluster
    all_nodes = (deploymentHandler.get_nodes({'cluster': cluster})
                 if cluster is not None
                 else deploymentHandler.get_nodes())

    controller_nodes = [node for node in all_nodes if node.is_controller()]
    compute_nodes = [node for node in all_nodes if node.is_compute()]

    odl_ip, odl_port = test_utils.get_odl_ip_port(all_nodes)

    results = Results(COMMON_CONFIG.line_length)
    results.add_to_summary(0, "=")
    results.add_to_summary(2, "STATUS", "SUBTEST")
    results.add_to_summary(0, "=")

    test_utils.setup_compute_node(TESTCASE_CONFIG.subnet_cidr, compute_nodes)
    test_utils.configure_iptables(controller_nodes)
    test_utils.download_image(COMMON_CONFIG.url, COMMON_CONFIG.image_path)

    neutron_client = os_utils.get_neutron_client()
    nova_client = os_utils.get_nova_client()
    tacker_client = os_tacker.get_tacker_client()

    _, custom_flavor_id = os_utils.get_or_create_flavor(
        COMMON_CONFIG.flavor,
        COMMON_CONFIG.ram_size_in_mb,
        COMMON_CONFIG.disk_size_in_gb,
        COMMON_CONFIG.vcpu_count,
        public=True)
    if custom_flavor_id is None:
        logger.error("Failed to create custom flavor")
        sys.exit(1)

    controller_clients = test_utils.get_ssh_clients(controller_nodes)
    compute_clients = test_utils.get_ssh_clients(compute_nodes)

    ovs_logger = ovs_log.OVSLogger(
        os.path.join(COMMON_CONFIG.sfc_test_dir, 'ovs-logs'),
        COMMON_CONFIG.functest_results_dir)

    image_id = os_utils.create_glance_image(
        os_utils.get_glance_client(),
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

    vnf_name = 'testVNF1'
    # Using seed=0 uses the baseline topology: everything in the same host
    testTopology = topo_shuffler.topology([vnf_name], seed=0)
    logger.info('This test is run with the topology {0}'
                .format(testTopology['id']))
    logger.info('Topology description: {0}'
                .format(testTopology['description']))

    client_instance = test_utils.create_instance(
        nova_client,
        CLIENT,
        COMMON_CONFIG.flavor,
        image_id,
        network_id,
        sg_id,
        av_zone=testTopology[CLIENT])

    server_instance = test_utils.create_instance(
        nova_client,
        SERVER,
        COMMON_CONFIG.flavor,
        image_id,
        network_id,
        sg_id,
        av_zone=testTopology[SERVER])

    server_ip = server_instance.networks.get(TESTCASE_CONFIG.net_name)[0]

    tosca_file = os.path.join(
        COMMON_CONFIG.sfc_test_dir,
        COMMON_CONFIG.vnfd_dir,
        TESTCASE_CONFIG.test_vnfd)

    default_param_file = os.path.join(
        COMMON_CONFIG.sfc_test_dir,
        COMMON_CONFIG.vnfd_dir,
        COMMON_CONFIG.vnfd_default_params_file)

    os_tacker.create_vnfd(tacker_client, tosca_file=tosca_file)
    test_utils.create_vnf_in_av_zone(
        tacker_client,
        vnf_name,
        'test-vnfd1',
        default_param_file,
        testTopology[vnf_name])

    vnf_id = os_tacker.wait_for_vnf(tacker_client, vnf_name=vnf_name)
    if vnf_id is None:
        logger.error('ERROR while booting VNF')
        sys.exit(1)

    vnf_instance_id = test_utils.get_nova_id(tacker_client, 'vdu1', vnf_id)
    os_utils.add_secgroup_to_instance(nova_client, vnf_instance_id, sg_id)

    os_tacker.create_sfc(
        tacker_client,
        sfc_name='red',
        chain_vnf_names=[vnf_name],
        symmetrical=True)

    os_tacker.create_sfc_classifier(
        tacker_client, 'red_http', sfc_name='red',
        match={
            'source_port': 0,
            'dest_port': 80,
            'protocol': 6
        })

    # FIXME: JIRA SFC-86
    # Tacker does not allow to specify the direction of the chain to be used,
    # only references the SFP (which for symmetric chains results in two RSPs)
    os_tacker.create_sfc_classifier(
        tacker_client, 'red_http_reverse', sfc_name='red',
        match={
            'source_port': 80,
            'dest_port': 0,
            'protocol': 6
        })

    logger.info(test_utils.run_cmd('tacker sfc-list'))
    logger.info(test_utils.run_cmd('tacker sfc-classifier-list'))

    # Start measuring the time it takes to implement the classification rules
    t1 = threading.Thread(target=test_utils.wait_for_classification_rules,
                          args=(ovs_logger, compute_nodes, odl_ip, odl_port,
                                testTopology,))

    try:
        t1.start()
    except Exception as e:
        logger.error("Unable to start the thread that counts time %s" % e)

    logger.info("Assigning floating IPs to instances")
    server_floating_ip = test_utils.assign_floating_ip(
        nova_client, neutron_client, server_instance.id)
    client_floating_ip = test_utils.assign_floating_ip(
        nova_client, neutron_client, client_instance.id)
    sf_floating_ip = test_utils.assign_floating_ip(
        nova_client, neutron_client, vnf_instance_id)

    for ip in (server_floating_ip, client_floating_ip, sf_floating_ip):
        logger.info("Checking connectivity towards floating IP [%s]" % ip)
        if not test_utils.ping(ip, retries=50, retry_timeout=1):
            logger.error("Cannot ping floating IP [%s]" % ip)
            sys.exit(1)
        logger.info("Successful ping to floating IP [%s]" % ip)

    if not test_utils.check_ssh([sf_floating_ip]):
        logger.error("Cannot establish SSH connection to the SFs")
        sys.exit(1)

    logger.info("Starting HTTP server on %s" % server_floating_ip)
    if not test_utils.start_http_server(server_floating_ip):
        logger.error('\033[91mFailed to start the HTTP server\033[0m')
        sys.exit(1)

    blocked_port = TESTCASE_CONFIG.blocked_source_port
    logger.info("Firewall started, blocking traffic port %d" % blocked_port)
    test_utils.start_vxlan_tool(sf_floating_ip, block=blocked_port)

    logger.info("Wait for ODL to update the classification rules in OVS")
    t1.join()

    allowed_port = TESTCASE_CONFIG.allowed_source_port
    logger.info("Test if HTTP from port %s works" % allowed_port)
    if not test_utils.is_http_blocked(
            client_floating_ip, server_ip, allowed_port):
        results.add_to_summary(2, "PASS", "HTTP works")
    else:
        error = ('\033[91mTEST 1 [FAILED] ==> HTTP BLOCKED\033[0m')
        logger.error(error)
        test_utils.capture_ovs_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP works")

    logger.info("Test if HTTP from port %s is blocked" % blocked_port)
    if test_utils.is_http_blocked(
            client_floating_ip, server_ip, blocked_port):
        results.add_to_summary(2, "PASS", "HTTP Blocked")
    else:
        error = ('\033[91mTEST 2 [FAILED] ==> HTTP WORKS\033[0m')
        logger.error(error)
        test_utils.capture_ovs_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP Blocked")

    return results.compile_summary()


if __name__ == '__main__':
    logging.config.fileConfig(COMMON_CONFIG.functest_logging_api)
    main()

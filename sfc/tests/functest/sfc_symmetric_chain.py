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

import sfc.lib.openstack_utils as os_sfc_utils
import sfc.lib.odl_utils as odl_utils
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

    odl_ip, odl_port = odl_utils.get_odl_ip_port(all_nodes)

    results = Results(COMMON_CONFIG.line_length)
    results.add_to_summary(0, "=")
    results.add_to_summary(2, "STATUS", "SUBTEST")
    results.add_to_summary(0, "=")

    openstack_sfc = os_sfc_utils.OpenStackSFC()

    tacker_client = os_sfc_utils.get_tacker_client()

    _, custom_flavor = openstack_sfc.get_or_create_flavor(
        COMMON_CONFIG.flavor,
        COMMON_CONFIG.ram_size_in_mb,
        COMMON_CONFIG.disk_size_in_gb,
        COMMON_CONFIG.vcpu_count)
    if custom_flavor is None:
        logger.error("Failed to create custom flavor")
        sys.exit(1)

    controller_clients = test_utils.get_ssh_clients(controller_nodes)
    compute_clients = test_utils.get_ssh_clients(compute_nodes)

    ovs_logger = ovs_log.OVSLogger(
        os.path.join(COMMON_CONFIG.sfc_test_dir, 'ovs-logs'),
        COMMON_CONFIG.functest_results_dir)

    image_creator = openstack_sfc.register_glance_image(
        COMMON_CONFIG.image_name,
        COMMON_CONFIG.image_url,
        COMMON_CONFIG.image_format,
        'public')

    network, router = openstack_sfc.create_network_infrastructure(
        TESTCASE_CONFIG.net_name,
        TESTCASE_CONFIG.subnet_name,
        TESTCASE_CONFIG.subnet_cidr,
        TESTCASE_CONFIG.router_name)

    sg = openstack_sfc.create_security_group(TESTCASE_CONFIG.secgroup_name)

    vnf_name = 'testVNF1'
    # Using seed=0 uses the baseline topology: everything in the same host
    testTopology = topo_shuffler.topology([vnf_name], openstack_sfc, seed=0)
    logger.info('This test is run with the topology {0}'
                .format(testTopology['id']))
    logger.info('Topology description: {0}'
                .format(testTopology['description']))

    client_instance, client_creator = openstack_sfc.create_instance(
        CLIENT, COMMON_CONFIG.flavor, image_creator, network, sg,
        av_zone=testTopology['client'])

    server_instance, server_creator = openstack_sfc.create_instance(
        SERVER, COMMON_CONFIG.flavor, image_creator, network, sg,
        av_zone=testTopology['server'])

    server_ip = server_instance.ports[0].ips[0]['ip_address']
    logger.info("Server instance received private ip [{}]".format(server_ip))

    tosca_file = os.path.join(
        COMMON_CONFIG.sfc_test_dir,
        COMMON_CONFIG.vnfd_dir,
        TESTCASE_CONFIG.test_vnfd)

    default_param_file = os.path.join(
        COMMON_CONFIG.sfc_test_dir,
        COMMON_CONFIG.vnfd_dir,
        COMMON_CONFIG.vnfd_default_params_file)

    os_sfc_utils.create_vnfd(tacker_client, tosca_file=tosca_file)
    test_utils.create_vnf_in_av_zone(
        tacker_client,
        vnf_name,
        'test-vnfd1',
        default_param_file,
        testTopology[vnf_name])

    vnf_id = os_sfc_utils.wait_for_vnf(tacker_client, vnf_name=vnf_name)
    if vnf_id is None:
        logger.error('ERROR while booting VNF')
        sys.exit(1)

    os_sfc_utils.create_sfc(
        tacker_client,
        sfc_name='red',
        chain_vnf_names=[vnf_name],
        symmetrical=True)

    os_sfc_utils.create_sfc_classifier(
        tacker_client, 'red_http', sfc_name='red',
        match={
            'source_port': 0,
            'dest_port': 80,
            'protocol': 6
        })

    # FIXME: JIRA SFC-86
    # Tacker does not allow to specify the direction of the chain to be used,
    # only references the SFP (which for symmetric chains results in two RSPs)
    os_sfc_utils.create_sfc_classifier(
        tacker_client, 'red_http_reverse', sfc_name='red',
        match={
            'source_port': 80,
            'dest_port': 0,
            'protocol': 6
        })

    logger.info(test_utils.run_cmd('tacker sfc-list'))
    logger.info(test_utils.run_cmd('tacker sfc-classifier-list'))

    # Start measuring the time it takes to implement the classification rules
    t1 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                          args=(ovs_logger, compute_nodes, odl_ip, odl_port,))

    try:
        t1.start()
    except Exception as e:
        logger.error("Unable to start the thread that counts time %s" % e)

    logger.info("Assigning floating IPs to instances")
    client_floating_ip = openstack_sfc.assign_floating_ip(router,
                                                          client_instance,
                                                          client_creator)
    server_floating_ip = openstack_sfc.assign_floating_ip(router,
                                                          server_instance,
                                                          server_creator)
    fips_sfs = openstack_sfc.assign_floating_ip_vnfs(router)
    sf_floating_ip = fips_sfs[0]

    fips = [client_floating_ip, server_floating_ip, fips_sfs[0]]

    for ip in fips:
        logger.info("Checking connectivity towards floating IP [%s]" % ip)
        if not test_utils.ping(ip, retries=50, retry_timeout=3):
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

    return results.compile_summary(), openstack_sfc.creators


if __name__ == '__main__':
    logging.config.fileConfig(COMMON_CONFIG.functest_logging_api)
    main()

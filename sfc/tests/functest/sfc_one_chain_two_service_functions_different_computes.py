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

import logging as ft_logger
# import functest.utils.functest_logger as ft_logger
import functest.utils.openstack_tacker as os_tacker
import functest.utils.openstack_utils as os_utils
import opnfv.utils.ovs_logger as ovs_log

import sfc.lib.config as sfc_config
import sfc.lib.utils as test_utils
from sfc.lib.results import Results
from opnfv.deployment.factory import Factory as DeploymentFactory
import sfc.lib.topology_shuffler as topo_shuffler

""" logging configuration """
logger = ft_logger.getLogger('SFC_one_chain_two_sfs')

CLIENT = "client"
SERVER = "server"
COMMON_CONFIG = sfc_config.CommonConfig()
TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_one_chain_two_service'
                                            '_functions_different_computes')


def main():
    deploymentHandler = DeploymentFactory.get_handler(
        COMMON_CONFIG.installer_type,
        COMMON_CONFIG.installer_ip,
        COMMON_CONFIG.installer_user,
        installer_pwd=COMMON_CONFIG.installer_password)

    cluster = COMMON_CONFIG.installer_cluster
    openstack_nodes = (deploymentHandler.get_nodes({'cluster': cluster})
                       if cluster is not None
                       else deploymentHandler.get_nodes())

    controller_nodes = [node for node in openstack_nodes
                        if node.is_controller()]
    compute_nodes = [node for node in openstack_nodes
                     if node.is_compute()]

    for compute in compute_nodes:
        logger.debug("This is a compute: %s" % compute.info)

    results = Results(COMMON_CONFIG.line_length)
    results.add_to_summary(0, "=")
    results.add_to_summary(2, "STATUS", "SUBTEST")
    results.add_to_summary(0, "=")

    test_utils.setup_compute_node(TESTCASE_CONFIG.subnet_cidr, compute_nodes)
    test_utils.configure_iptables(controller_nodes)

    test_utils.download_image(COMMON_CONFIG.url,
                              COMMON_CONFIG.image_path)
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

    controller_clients = test_utils.get_ssh_clients(controller_nodes)
    compute_clients = test_utils.get_ssh_clients(compute_nodes)

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

    vnfs = ['testVNF1', 'testVNF2']

    topo_seed = topo_shuffler.get_seed()
    testTopology = topo_shuffler.topology(vnfs, seed=topo_seed)

    logger.info('This test is run with the topology {0}'
                .format(testTopology['id']))
    logger.info('Topology description: {0}'
                .format(testTopology['description']))

    test_utils.create_instance(
        nova_client, CLIENT, COMMON_CONFIG.flavor,
        image_id, network_id, sg_id, av_zone=testTopology['client'])

    srv_instance = test_utils.create_instance(
        nova_client, SERVER, COMMON_CONFIG.flavor, image_id,
        network_id, sg_id, av_zone=testTopology['server'])

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

    default_param_file = os.path.join(
        COMMON_CONFIG.sfc_test_dir,
        COMMON_CONFIG.vnfd_dir,
        COMMON_CONFIG.vnfd_default_params_file)

    test_utils.create_vnf_in_av_zone(
        tacker_client, vnfs[0], 'test-vnfd1',
        default_param_file, testTopology[vnfs[0]])
    test_utils.create_vnf_in_av_zone(
        tacker_client, vnfs[1], 'test-vnfd2',
        default_param_file, testTopology[vnfs[1]])

    vnf1 = os_tacker.wait_for_vnf(tacker_client, vnf_name=vnfs[0])
    vnf2 = os_tacker.wait_for_vnf(tacker_client, vnf_name=vnfs[1])
    if vnf1 is None or vnf2 is None:
        logger.error('ERROR while booting vnfs')
        sys.exit(1)

    instances = os_utils.get_instances(nova_client)
    for instance in instances:
        if ('client' not in instance.name) and ('server' not in instance.name):
            os_utils.add_secgroup_to_instance(nova_client, instance.id, sg_id)

    os_tacker.create_sfc(tacker_client, 'red',
                         chain_vnf_names=[vnfs[0], vnfs[1]])

    os_tacker.create_sfc_classifier(
        tacker_client, 'red_http', sfc_name='red',
        match={
            'source_port': 0,
            'dest_port': 80,
            'protocol': 6
        })

    logger.info(test_utils.run_cmd('tacker sfc-list')[1])
    logger.info(test_utils.run_cmd('tacker sfc-classifier-list')[1])

    num_chains = 1

    # Start measuring the time it takes to implement the classification rules
    t1 = threading.Thread(target=test_utils.wait_for_classification_rules,
                          args=(ovs_logger, compute_clients, num_chains,))
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

    logger.info("Starting vxlan_tool on %s" % sf2)
    test_utils.vxlan_firewall(sf2, block=False)
    logger.info("Starting vxlan_tool on %s" % sf1)
    test_utils.vxlan_firewall(sf1, block=False)

    logger.info("Wait for ODL to update the classification rules in OVS")
    t1.join()

    logger.info("Test HTTP")
    if not test_utils.is_http_blocked(client_ip, srv_prv_ip):
        results.add_to_summary(2, "PASS", "HTTP works")
    else:
        error = ('\033[91mTEST 1 [FAILED] ==> HTTP BLOCKED\033[0m')
        logger.error(error)
        test_utils.capture_ovs_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP blocked")

    logger.info("Changing the vxlan_tool to block HTTP traffic")

    # Make SF1 block now http traffic
    test_utils.vxlan_tool_stop(sf1)
    test_utils.vxlan_firewall(sf1, port="80")

    logger.info("Test HTTP again")
    if test_utils.is_http_blocked(client_ip, srv_prv_ip):
        results.add_to_summary(2, "PASS", "HTTP Blocked")
    else:
        error = ('\033[91mTEST 2 [FAILED] ==> HTTP WORKS\033[0m')
        logger.error(error)
        test_utils.capture_ovs_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP not blocked")

    return results.compile_summary()


if __name__ == '__main__':
    main()

#!/usr/bin/env python
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
import sfc.lib.openstack_utils as os_sfc_utils
import sfc.lib.odl_utils as odl_utils
import opnfv.utils.ovs_logger as ovs_log
import sfc.lib.config as sfc_config
import sfc.lib.test_utils as test_utils
import sfc.lib.topology_shuffler as topo_shuffler

from opnfv.utils import opnfv_logger as logger
from sfc.lib.results import Results
from opnfv.deployment.factory import Factory as DeploymentFactory

""" logging configuration """
logger = logger.Logger(__name__).getLogger()

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

    custom_flavor = openstack_sfc.create_flavor(
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
    topo_seed = topo_shuffler.get_seed()
    testTopology = topo_shuffler.topology([vnf_name], openstack_sfc,
                                          seed=topo_seed)
    logger.info('This test is run with the topology {0}'
                .format(testTopology['id']))
    logger.info('Topology description: {0}'
                .format(testTopology['description']))

    client_instance, client_creator = openstack_sfc.create_instance(
        CLIENT, COMMON_CONFIG.flavor, image_creator, network, sg,
        av_zone=testTopology[CLIENT])

    server_instance, server_creator = openstack_sfc.create_instance(
        SERVER, COMMON_CONFIG.flavor, image_creator, network, sg,
        av_zone=testTopology[SERVER])

    server_ip = server_instance.ports[0].ips[0]['ip_address']
    logger.info("Server instance received private ip [{}]".format(server_ip))

    os_sfc_utils.register_vim(tacker_client, vim_file=COMMON_CONFIG.vim_file)

    tosca_file = os.path.join(
        COMMON_CONFIG.sfc_test_dir,
        COMMON_CONFIG.vnfd_dir,
        TESTCASE_CONFIG.test_vnfd)

    default_param_file = os.path.join(
        COMMON_CONFIG.sfc_test_dir,
        COMMON_CONFIG.vnfd_dir,
        COMMON_CONFIG.vnfd_default_params_file)

    os_sfc_utils.create_vnfd(
        tacker_client,
        tosca_file=tosca_file,
        vnfd_name='test-vnfd1')
    os_sfc_utils.create_vnf_in_av_zone(
        tacker_client,
        vnf_name,
        'test-vnfd1',
        'test-vim',
        default_param_file,
        testTopology[vnf_name])

    vnf_id = os_sfc_utils.wait_for_vnf(tacker_client, vnf_name=vnf_name)
    if vnf_id is None:
        logger.error('ERROR while booting VNF')
        sys.exit(1)

    tosca_file = os.path.join(
        COMMON_CONFIG.sfc_test_dir,
        COMMON_CONFIG.vnffgd_dir,
        TESTCASE_CONFIG.test_vnffgd)
    os_sfc_utils.create_vnffgd(
        tacker_client,
        tosca_file=tosca_file,
        vnffgd_name='test-vnffgd')

    client_port = openstack_sfc.get_client_port(
        client_instance,
        client_creator)
    server_port = openstack_sfc.get_client_port(
        server_instance,
        server_creator)

    server_ip_prefix = server_ip + '/32'

    os_sfc_utils.create_vnffg_with_param_file(
        tacker_client,
        'test-vnffgd',
        'test-vnffg',
        default_param_file,
        client_port.id,
        server_port.id,
        server_ip_prefix)

    # Start measuring the time it takes to implement the classification rules
    t1 = threading.Thread(
        target=wait_for_classification_rules,
        args=(ovs_logger, compute_nodes,
              openstack_sfc.get_compute_server(), server_port,
              openstack_sfc.get_compute_client(), client_port,
              odl_ip, odl_port,))

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

    vnf_ip = os_sfc_utils.get_vnf_ip(tacker_client, vnf_id=vnf_id)
    fips_sfs = openstack_sfc.assign_floating_ip_vnfs(router, [vnf_ip])
    sf_floating_ip = fips_sfs[0]

    fips = [client_floating_ip, server_floating_ip, sf_floating_ip]

    for ip in fips:
        logger.info("Checking connectivity towards floating IP [%s]" % ip)
        if not test_utils.ping(ip, retries=50, retry_timeout=3):
            logger.error("Cannot ping floating IP [%s]" % ip)
            os_sfc_utils.get_tacker_items()
            odl_utils.get_odl_items(odl_ip, odl_port)
            sys.exit(1)
        logger.info("Successful ping to floating IP [%s]" % ip)

    if not test_utils.check_ssh([sf_floating_ip]):
        logger.error("Cannot establish SSH connection to the SFs")
        sys.exit(1)

    logger.info("Starting HTTP server on %s" % server_floating_ip)
    if not test_utils.start_http_server(server_floating_ip):
        logger.error('\033[91mFailed to start the HTTP server\033[0m')
        sys.exit(1)

    logger.info("Starting vxlan_tool on %s" % sf_floating_ip)
    test_utils.start_vxlan_tool(sf_floating_ip, interface='eth0',
                                output='eth1')
    test_utils.start_vxlan_tool(sf_floating_ip, interface='eth1',
                                output='eth0')

    logger.info("Wait for ODL to update the classification rules in OVS")
    t1.join()

    logger.info("Test HTTP")
    if not test_utils.is_http_blocked(client_floating_ip,
                                      server_ip,
                                      TESTCASE_CONFIG.source_port):
        results.add_to_summary(2, "PASS", "HTTP works")
    else:
        error = ('\033[91mTEST 1 [FAILED] ==> HTTP BLOCKED\033[0m')
        logger.error(error)
        test_utils.capture_ovs_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP blocked")

    logger.info("Changing the vxlan_tool to block HTTP request traffic")

    # Make SF1 block http request traffic
    test_utils.stop_vxlan_tool(sf_floating_ip)
    logger.info("Starting HTTP firewall on %s" % sf_floating_ip)
    test_utils.start_vxlan_tool(sf_floating_ip, interface='eth0',
                                output='eth1', block="80")
    test_utils.start_vxlan_tool(sf_floating_ip, interface='eth1',
                                output='eth0')

    logger.info("Test HTTP again blocking request on SF1")
    if test_utils.is_http_blocked(client_floating_ip,
                                  server_ip,
                                  TESTCASE_CONFIG.source_port):
        results.add_to_summary(2, "PASS", "HTTP uplink blocked")
    else:
        error = ('\033[91mTEST 2 [FAILED] ==> HTTP WORKS\033[0m')
        logger.error(error)
        test_utils.capture_ovs_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP works")

    logger.info("Changing the vxlan_tool to block HTTP response traffic")

    # Make SF1 block response http traffic
    test_utils.stop_vxlan_tool(sf_floating_ip)
    logger.info("Starting HTTP firewall on %s" % sf_floating_ip)
    test_utils.start_vxlan_tool(sf_floating_ip, interface='eth0',
                                output='eth1')
    test_utils.start_vxlan_tool(sf_floating_ip, interface='eth1',
                                output='eth0',
                                block=TESTCASE_CONFIG.source_port)

    logger.info("Test HTTP again blocking response on SF1")
    if test_utils.is_http_blocked(client_floating_ip,
                                  server_ip,
                                  TESTCASE_CONFIG.source_port):
        results.add_to_summary(2, "PASS", "HTTP downlink blocked")
    else:
        error = ('\033[91mTEST 3 [FAILED] ==> HTTP WORKS\033[0m')
        logger.error(error)
        test_utils.capture_ovs_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP works")

    logger.info("Changing the vxlan_tool to allow HTTP traffic")

    # Make SF1 allow http traffic
    test_utils.stop_vxlan_tool(sf_floating_ip)
    logger.info("Starting HTTP firewall on %s" % sf_floating_ip)
    test_utils.start_vxlan_tool(sf_floating_ip, interface='eth0',
                                output='eth1')
    test_utils.start_vxlan_tool(sf_floating_ip, interface='eth1',
                                output='eth0')

    logger.info("Test HTTP")
    if not test_utils.is_http_blocked(client_floating_ip, server_ip):
        results.add_to_summary(2, "PASS", "HTTP restored")
    else:
        error = ('\033[91mTEST 4 [FAILED] ==> HTTP BLOCKED\033[0m')
        logger.error(error)
        test_utils.capture_ovs_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP blocked")

    return results.compile_summary(), openstack_sfc.creators


def wait_for_classification_rules(ovs_logger, compute_nodes,
                                  server_compute, server_port,
                                  client_compute, client_port,
                                  odl_ip, odl_port):
    if client_compute == server_compute:
        odl_utils.wait_for_classification_rules(
            ovs_logger,
            compute_nodes,
            odl_ip,
            odl_port,
            client_compute,
            [server_port, client_port])
    else:
        odl_utils.wait_for_classification_rules(
            ovs_logger,
            compute_nodes,
            odl_ip,
            odl_port,
            server_compute,
            server_port)
        odl_utils.wait_for_classification_rules(
            ovs_logger,
            compute_nodes,
            odl_ip,
            odl_port,
            client_compute,
            client_port)


if __name__ == '__main__':
    main()

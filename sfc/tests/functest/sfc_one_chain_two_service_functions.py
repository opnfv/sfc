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
import logging

import sfc.lib.openstack_tacker as os_tacker
import functest.utils.openstack_utils as os_utils
import opnfv.utils.ovs_logger as ovs_log

import sfc.lib.config as sfc_config
import sfc.lib.utils as test_utils
from sfc.lib.results import Results
from opnfv.deployment.factory import Factory as DeploymentFactory
import sfc.lib.topology_shuffler as topo_shuffler

from snaps.openstack.create_image import OpenStackImage
from snaps.config.image import ImageConfig

from snaps.config.network import NetworkConfig, SubnetConfig
from snaps.openstack.create_network import OpenStackNetwork

from snaps.config.flavor import FlavorConfig
from snaps.openstack.create_flavor import OpenStackFlavor

from snaps.config.router import RouterConfig
from snaps.openstack.create_router import OpenStackRouter

""" logging configuration """
logger = logging.getLogger(__name__)

CLIENT = "client"
SERVER = "server"
COMMON_CONFIG = sfc_config.CommonConfig()
TESTCASE_CONFIG = sfc_config.TestcaseConfig(
                                            'sfc_one_chain_two_service'
                                            '_functions')


def main():
    deploymentHandler = DeploymentFactory.get_handler(
        COMMON_CONFIG.installer_type,
        COMMON_CONFIG.installer_ip,
        COMMON_CONFIG.installer_user,
        COMMON_CONFIG.installer_password,
        COMMON_CONFIG.installer_key_file)

    installer_type = os.environ.get("INSTALLER_TYPE")

    supported_installers = ['fuel', 'apex', 'osa']

    if installer_type not in supported_installers:
        logger.error(
            '\033[91mYour installer is not supported yet\033[0m')
        sys.exit(1)

    installer_ip = os.environ.get("INSTALLER_IP")
    if not installer_ip:
        logger.error(
            '\033[91minstaller ip is not set\033[0m')
        logger.error(
            '\033[91mexport INSTALLER_IP=<ip>\033[0m')
        sys.exit(1)

    cluster = COMMON_CONFIG.installer_cluster

    openstack_nodes = (deploymentHandler.get_nodes({'cluster': cluster})
                       if cluster is not None
                       else deploymentHandler.get_nodes())

    controller_nodes = [node for node in openstack_nodes
                        if node.is_controller()]
    compute_nodes = [node for node in openstack_nodes
                     if node.is_compute()]

    odl_ip, odl_port = test_utils.get_odl_ip_port(openstack_nodes)

    for compute in compute_nodes:
        logger.info("This is a compute: %s" % compute.ip)

    results = Results(COMMON_CONFIG.line_length)
    results.add_to_summary(0, "=")
    results.add_to_summary(2, "STATUS", "SUBTEST")
    results.add_to_summary(0, "=")

    test_utils.download_image(COMMON_CONFIG.url,
                              COMMON_CONFIG.image_path)

    flavor_settings = FlavorConfig(
        name=COMMON_CONFIG.flavor,
        ram=COMMON_CONFIG.ram_size_in_mb,
        disk=COMMON_CONFIG.disk_size_in_gb,
        vcpus=COMMON_CONFIG.vcpu_count)
    flavor = OpenStackFlavor(os_creds, flavor_settings)
    flavor_id = flavor_creator.create()
    if flavor is None or flavor_id is None:
        logger.error("Failed to create custom flavor")
        sys.exit(1)

    neutron_client = os_utils.get_neutron_client()
    nova_client = os_utils.get_nova_client()
    tacker_client = os_tacker.get_tacker_client()

    controller_clients = test_utils.get_ssh_clients(controller_nodes)
    compute_clients = test_utils.get_ssh_clients(compute_nodes)

    ovs_logger = ovs_log.OVSLogger(
        os.path.join(COMMON_CONFIG.sfc_test_dir, 'ovs-logs'),
        COMMON_CONFIG.functest_results_dir)


    image_settings = ImageConfig(name=COMMON_CONFIG.image_name,
                                 img_format=COMMON_CONFIG.image_format,
                                 url=COMMON_CONFIG.image_path
                                 public=True)
    image = OpenStackImage(os_creds, image_settings)
    image_id = image.create()
    if image_id is None:
        logger.error("Failed to create the image")
        sys.exit(1)

    subnet_settings = SubnetConfig(name=TESTCASE_CONFIG.subnet_name,
                                   cidr=TESTCASE_CONFIG.subnet_cidr)
    network_settings = NetworkConfig(name=TESTCASE_CONFIG.net_name,
                                     subnet_settings=[subnet_settings])
    network = OpenStackNetwork(os_creds, network_settings)
    network_id = network.create()

   if network_id is None:
        logger.error("Failed to create the network")
        sys.exit(1)

    router_settings = RouterConfig(name=TESTCASE_CONFIG.router_name,
                                   external_gateway=...,
                                   internal_subnets=TESTCASE_CONFIG.subnet_name)
    router_creator = OpenStackRouter(os_creds, router_settings)
    router_id = router_creator.create()

    if router_id is None:
        logger.error("Failed to create the router")
        sys.exit(1)

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

    client_instance = test_utils.create_instance(
        nova_client, CLIENT, COMMON_CONFIG.flavor, image_id,
        network_id, sg_id, av_zone=testTopology['client'])

    server_instance = test_utils.create_instance(
        nova_client, SERVER, COMMON_CONFIG.flavor, image_id,
        network_id, sg_id, av_zone=testTopology['server'])

    client_ip = client_instance.networks.get(TESTCASE_CONFIG.net_name)[0]
    logger.info("Client instance received private ip [{}]".format(client_ip))
    server_ip = server_instance.networks.get(TESTCASE_CONFIG.net_name)[0]
    logger.info("Server instance received private ip [{}]".format(server_ip))

    test_utils.register_vim(tacker_client, vim_file=COMMON_CONFIG.vim_file)

    tosca_file = os.path.join(COMMON_CONFIG.sfc_test_dir,
                              COMMON_CONFIG.vnfd_dir,
                              TESTCASE_CONFIG.test_vnfd_red)

    os_tacker.create_vnfd(
        tacker_client,
        tosca_file=tosca_file, vnfd_name='test-vnfd1')

    tosca_file = os.path.join(COMMON_CONFIG.sfc_test_dir,
                              COMMON_CONFIG.vnfd_dir,
                              TESTCASE_CONFIG.test_vnfd_blue)
    os_tacker.create_vnfd(
        tacker_client,
        tosca_file=tosca_file, vnfd_name='test-vnfd2')

    default_param_file = os.path.join(
        COMMON_CONFIG.sfc_test_dir,
        COMMON_CONFIG.vnfd_dir,
        COMMON_CONFIG.vnfd_default_params_file)

    test_utils.create_vnf_in_av_zone(
        tacker_client, vnfs[0], 'test-vnfd1', 'test-vim',
        default_param_file, testTopology[vnfs[0]])
    test_utils.create_vnf_in_av_zone(
        tacker_client, vnfs[1], 'test-vnfd2', 'test-vim',
        default_param_file, testTopology[vnfs[1]])

    vnf1_id = os_tacker.wait_for_vnf(tacker_client, vnf_name=vnfs[0])
    vnf2_id = os_tacker.wait_for_vnf(tacker_client, vnf_name=vnfs[1])
    if vnf1_id is None or vnf2_id is None:
        logger.error('ERROR while booting vnfs')
        sys.exit(1)

    vnf1_instance_id = test_utils.get_nova_id(tacker_client, 'VDU1', vnf1_id)

    vnf2_instance_id = test_utils.get_nova_id(tacker_client, 'VDU1', vnf2_id)

    tosca_file = os.path.join(COMMON_CONFIG.sfc_test_dir,
                              COMMON_CONFIG.vnffgd_dir,
                              TESTCASE_CONFIG.test_vnffgd_red)

    os_tacker.create_vnffgd(tacker_client,
                            tosca_file=tosca_file,
                            vnffgd_name='red')

    neutron_port = test_utils.get_client_port_id(client_instance)
    test_utils.create_vnffg_with_param_file(tacker_client, 'red',
                                            'red_http',
                                            default_param_file,
                                            neutron_port)

    # Start measuring the time it takes to implement the classification rules
    t1 = threading.Thread(target=test_utils.wait_for_classification_rules,
                          args=(ovs_logger, compute_nodes, odl_ip, odl_port,))
    try:
        t1.start()
    except Exception as e:
        logger.error("Unable to start the thread that counts time %s" % e)

    logger.info("Assigning floating IPs to instances")
    server_floating_ip = test_utils.assign_floating_ip(
        nova_client, neutron_client, server_instance.id)
    client_floating_ip = test_utils.assign_floating_ip(
        nova_client, neutron_client, client_instance.id)
    sf1_floating_ip = test_utils.assign_floating_ip(
        nova_client, neutron_client, vnf1_instance_id)
    sf2_floating_ip = test_utils.assign_floating_ip(
        nova_client, neutron_client, vnf2_instance_id)

    for ip in (server_floating_ip,
               client_floating_ip,
               sf1_floating_ip,
               sf2_floating_ip):
        logger.info("Checking connectivity towards floating IP [%s]" % ip)
        if not test_utils.ping(ip, retries=50, retry_timeout=3):
            logger.error("Cannot ping floating IP [%s]" % ip)
            os_tacker.get_tacker_items()
            test_utils.get_odl_items(odl_ip, odl_port)
            sys.exit(1)
        logger.info("Successful ping to floating IP [%s]" % ip)

    if not test_utils.check_ssh([sf1_floating_ip, sf2_floating_ip]):
        logger.error("Cannot establish SSH connection to the SFs")
        sys.exit(1)

    logger.info("Starting HTTP server on %s" % server_floating_ip)
    if not test_utils.start_http_server(server_floating_ip):
        logger.error(
            'Failed to start HTTP server on %s' % server_floating_ip)
        sys.exit(1)

    for sf_floating_ip in (sf1_floating_ip, sf2_floating_ip):
        logger.info("Starting vxlan_tool on %s" % sf_floating_ip)
        test_utils.start_vxlan_tool(sf_floating_ip)

    logger.info("Wait for ODL to update the classification rules in OVS")
    t1.join()

    logger.info("Test HTTP")
    if not test_utils.is_http_blocked(client_floating_ip, server_ip):
        results.add_to_summary(2, "PASS", "HTTP works")
    else:
        error = ('\033[91mTEST 1 [FAILED] ==> HTTP BLOCKED\033[0m')
        logger.error(error)
        test_utils.capture_ovs_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP blocked")

    logger.info("Changing the vxlan_tool to block HTTP traffic")

    # Make SF1 block http traffic
    test_utils.stop_vxlan_tool(sf1_floating_ip)
    logger.info("Starting HTTP firewall on %s" % sf1_floating_ip)
    test_utils.start_vxlan_tool(sf1_floating_ip, block="80")

    logger.info("Test HTTP again blocking SF1")
    if test_utils.is_http_blocked(client_floating_ip, server_ip):
        results.add_to_summary(2, "PASS", "HTTP Blocked")
    else:
        error = ('\033[91mTEST 2 [FAILED] ==> HTTP WORKS\033[0m')
        logger.error(error)
        test_utils.capture_ovs_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP not blocked")

    # Make SF2 block http traffic
    test_utils.stop_vxlan_tool(sf2_floating_ip)
    logger.info("Starting HTTP firewall on %s" % sf2_floating_ip)
    test_utils.start_vxlan_tool(sf2_floating_ip, block="80")
    logger.info("Stopping HTTP firewall on %s" % sf1_floating_ip)
    test_utils.stop_vxlan_tool(sf1_floating_ip)

    logger.info("Test HTTP again blocking SF2")
    if test_utils.is_http_blocked(client_floating_ip, server_ip):
        results.add_to_summary(2, "PASS", "HTTP Blocked")
    else:
        error = ('\033[91mTEST 3 [FAILED] ==> HTTP WORKS\033[0m')
        logger.error(error)
        test_utils.capture_ovs_logs(
            ovs_logger, controller_clients, compute_clients, error)
        results.add_to_summary(2, "FAIL", "HTTP not blocked")

    return results.compile_summary()


if __name__ == '__main__':
    logging.config.fileConfig(COMMON_CONFIG.functest_logging_api)
    main()

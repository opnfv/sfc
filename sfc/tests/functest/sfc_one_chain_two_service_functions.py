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

    supported_installers = ['fuel', 'apex', 'osa', 'compass']

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

    odl_ip, odl_port = odl_utils.get_odl_ip_port(openstack_nodes)

    for compute in compute_nodes:
        logger.info("This is a compute: %s" % compute.ip)

    results = Results(COMMON_CONFIG.line_length)
    results.add_to_summary(0, "=")
    results.add_to_summary(2, "STATUS", "SUBTEST")
    results.add_to_summary(0, "=")

    openstack_sfc = os_sfc_utils.OpenStackSFC()

    custom_flv = openstack_sfc.create_flavor(
        COMMON_CONFIG.flavor,
        COMMON_CONFIG.ram_size_in_mb,
        COMMON_CONFIG.disk_size_in_gb,
        COMMON_CONFIG.vcpu_count)
    if not custom_flv:
        logger.error("Failed to create custom flavor")
        sys.exit(1)

    tacker_client = os_sfc_utils.get_tacker_client()

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

    vnfs = ['testVNF1', 'testVNF2']

    topo_seed = topo_shuffler.get_seed()
    testTopology = topo_shuffler.topology(vnfs, openstack_sfc, seed=topo_seed)

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

    os_sfc_utils.register_vim(tacker_client, vim_file=COMMON_CONFIG.vim_file)

    tosca_file = os.path.join(COMMON_CONFIG.sfc_test_dir,
                              COMMON_CONFIG.vnfd_dir,
                              TESTCASE_CONFIG.test_vnfd_red)

    os_sfc_utils.create_vnfd(
        tacker_client,
        tosca_file=tosca_file, vnfd_name='test-vnfd1')

    tosca_file = os.path.join(COMMON_CONFIG.sfc_test_dir,
                              COMMON_CONFIG.vnfd_dir,
                              TESTCASE_CONFIG.test_vnfd_blue)
    os_sfc_utils.create_vnfd(
        tacker_client,
        tosca_file=tosca_file, vnfd_name='test-vnfd2')

    default_param_file = os.path.join(
        COMMON_CONFIG.sfc_test_dir,
        COMMON_CONFIG.vnfd_dir,
        COMMON_CONFIG.vnfd_default_params_file)

    os_sfc_utils.create_vnf_in_av_zone(
        tacker_client, vnfs[0], 'test-vnfd1', 'test-vim',
        default_param_file, testTopology[vnfs[0]])
    os_sfc_utils.create_vnf_in_av_zone(
        tacker_client, vnfs[1], 'test-vnfd2', 'test-vim',
        default_param_file, testTopology[vnfs[1]])

    vnf1_id = os_sfc_utils.wait_for_vnf(tacker_client, vnf_name=vnfs[0])
    vnf2_id = os_sfc_utils.wait_for_vnf(tacker_client, vnf_name=vnfs[1])
    if vnf1_id is None or vnf2_id is None:
        logger.error('ERROR while booting vnfs')
        sys.exit(1)

    tosca_file = os.path.join(COMMON_CONFIG.sfc_test_dir,
                              COMMON_CONFIG.vnffgd_dir,
                              TESTCASE_CONFIG.test_vnffgd_red)

    os_sfc_utils.create_vnffgd(tacker_client,
                               tosca_file=tosca_file,
                               vnffgd_name='red')

    neutron_port = openstack_sfc.get_client_port(client_instance,
                                                 client_creator)
    os_sfc_utils.create_vnffg_with_param_file(tacker_client, 'red',
                                              'red_http',
                                              default_param_file,
                                              neutron_port.id)

    # Start measuring the time it takes to implement the classification rules
    t1 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                          args=(ovs_logger, compute_nodes, odl_ip,
                                odl_port, openstack_sfc.get_compute_client(),
                                [neutron_port],))
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
    sf1_floating_ip = fips_sfs[0]
    sf2_floating_ip = fips_sfs[1]

    fips = [client_floating_ip, server_floating_ip, sf1_floating_ip,
            sf2_floating_ip]

    for ip in fips:
        logger.info("Checking connectivity towards floating IP [%s]" % ip)
        if not test_utils.ping(ip, retries=50, retry_timeout=3):
            logger.error("Cannot ping floating IP [%s]" % ip)
            os_sfc_utils.get_tacker_items()
            odl_utils.get_odl_items(odl_ip, odl_port)
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

    return results.compile_summary(), openstack_sfc.creators


if __name__ == '__main__':
    logging.config.fileConfig(COMMON_CONFIG.functest_logging_api)
    main()

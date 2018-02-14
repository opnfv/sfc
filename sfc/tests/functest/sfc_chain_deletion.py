#!/usr/bin/env python
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

from sfc.tests.functest.sfc_parent_function import CommonTestCase as Common

import sfc.lib.config as sfc_config
import sfc.lib.test_utils as test_utils
from sfc.lib.results import Results
from opnfv.deployment.factory import Factory as DeploymentFactory
import sfc.lib.topology_shuffler as topo_shuffler


logger = logging.getLogger(__name__)
openstack_sfc = os_sfc_utils.OpenStackSFC()
CLIENT = "client"
SERVER = "server"
COMMON_CONFIG = sfc_config.CommonConfig()
TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_chain_deletion')


class SfcChainDeletion(Common):

    def run(self):
        vvfn = Common()
        supported_installers = ['fuel', 'apex', 'osa', 'compass']

        vvfn.initial_check_installer(supported_installers)

        ovs_logger, network, router, sg, image_creator = vvfn.preparation_openstack(COMMON_CONFIG, TESTCASE_CONFIG,
                                                                                    logger, supported_installers)
        compute_nodes, controller_nodes = vvfn.installer_deployment_nodes(COMMON_CONFIG)
        odl_ip, odl_port, deployment_handler = vvfn.installer_deployment(COMMON_CONFIG)

        for compute in compute_nodes:
            logger.info("This is a compute: %s" % compute.ip)

        results = Results(COMMON_CONFIG.line_length)
        results.add_to_summary(0, "=")
        results.add_to_summary(2, "STATUS", "SUBTEST")
        results.add_to_summary(0, "=")

        vnf_names = ['testVNF1', 'testVNF2']

        test_topology, topo_seed = vvfn.prepare_topology(vnf_names)

        logger.info('This test is run with the topology {0}'
                    .format(test_topology['id']))
        logger.info('Topology description: {0}'
                    .format(test_topology['description']))

        server_instance, server_creator, client_instance, client_creator = vvfn.prepare_server_client_elements(
            COMMON_CONFIG, SERVER, image_creator, vnf_names, topo_seed, network, sg)
        tacker_client = os_sfc_utils.get_tacker_client()

        os_sfc_utils.register_vim(tacker_client, vim_file=COMMON_CONFIG.vim_file)

        vvfn.create_custom_vnfd(COMMON_CONFIG, tacker_client, TESTCASE_CONFIG.test_vnfd_red, 'test-vnfd1')
        vvfn.create_custom_av(COMMON_CONFIG, tacker_client, vnf_names[0], 'test-vnfd1', 'test-vim', topo_seed)

        vvfn.create_chain(COMMON_CONFIG, TESTCASE_CONFIG, client_instance, client_creator)

        t1 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                              args=(ovs_logger, compute_nodes, odl_ip,
                                    odl_port, client_instance.compute_host,))

        try:
            t1.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        logger.info("Assigning floating IPs to instances")

        server_floating_ip, client_floating_ip = vvfn.custom_floating_ip(router, client_instance, client_creator,
                                                                         server_instance, server_creator)
        fips_sfs = openstack_sfc.assign_floating_ip_vnfs(router)
        # sf1_floating_ip = fips_sfs[0]

        fips = [client_floating_ip, server_floating_ip, sf1_floating_ip]
        vvfn.check_floating_ips(fips, fips_sfs[0], fips_sfs[0], server_floating_ip, odl_ip, odl_port)

        logger.info("Wait for ODL to update the classification rules in OVS")
        t1.join()

        vvfn.remove_vnff(tacker_client, 'red_http', 'red')
        vvfn.check_deletion(odl_ip, odl_port, ovs_logger, compute_nodes, openstack_sfc.get_compute_client)

        vvfn.create_chain(COMMON_CONFIG, TESTCASE_CONFIG, client_instance, client_creator)

        t2 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                              args=(ovs_logger, compute_nodes, odl_ip,
                                    odl_port, client_instance.compute_host,))
        try:
            t2.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        logger.info("Starting SSH firewall on %s" % sf1_floating_ip)
        test_utils.start_vxlan_tool(sf1_floating_ip)

        logger.info("Wait for ODL to update the classification rules in OVS")
        t2.join()

        logger.info("Test HTTP")
        results, verdict_allowed_http = vvfn.present_results_allowed_http(COMMON_CONFIG, client_floating_ip,
                                                                           server_instance, ovs_logger,
                                                                           deployment_handler, compute_nodes)

        logger.info("Stopping HTTP firewall on %s" % sf1_floating_ip)
        test_utils.stop_vxlan_tool(sf1_floating_ip)
        logger.info("Starting HTTP firewall on %s" % sf1_floating_ip)
        test_utils.start_vxlan_tool(sf1_floating_ip, block="80")

        logger.info("Test HTTP again")
        results, verdict = vvfn.present_results_http(COMMON_CONFIG, client_floating_ip, server_instance, ovs_logger,
                                                      deployment_handler, compute_nodes)

        if __name__ == '__main__':
            return results.compile_summary(), openstack_sfc.creators

        if __name__ == 'sfc.tests.functest.sfc_chain_deletion':
            return results.compile_summary(), openstack_sfc.creators

        total_verdict = (verdict_allowed_http and verdict_http)

        if total_verdict:
            return testcase.TestCase.EX_OK

        return testcase.TestCase.EX_RUN_ERROR


def main():
    logging.config.fileConfig(COMMON_CONFIG.functest_logging_api)
    run_main = SfcChainDeletion()
    results, creators = run_main.run()

    return results, creators


if __name__ == '__main__':
    logging.config.fileConfig(COMMON_CONFIG.functest_logging_api)
    test_run = SfcChainDeletion()
    test_run.run()

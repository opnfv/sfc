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

from sfc.tests.functest.sfc_parent_function import CommonTestCase as Common

import sfc.lib.openstack_utils as os_sfc_utils
import sfc.lib.odl_utils as odl_utils
import opnfv.utils.ovs_logger as ovs_log

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
TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_two_chains_SSH_and_HTTP')


class SfcTwoChainsSSHandHTTP(Common):

    def run(self):
        vvfn = Common()
        supported_installers = ['fuel', 'apex', 'osa', 'compass']

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

        server_ip = server_instance.ports[0].ips[0]['ip_address']
        logger.info("Server instance received private ip [{}]".format(server_ip))

        os_sfc_utils.register_vim(tacker_client, vim_file=COMMON_CONFIG.vim_file)

        vvfn.create_custom_vnfd(COMMON_CONFIG, tacker_client, TESTCASE_CONFIG.test_vnfd_red, 'test-vnfd1')
        vvfn.create_custom_vnfd(COMMON_CONFIG, tacker_client, TESTCASE_CONFIG.test_vnfd_blue, 'test-vnfd2')

        vvfn.create_custom_av(COMMON_CONFIG, tacker_client, vnf_names[0], 'test-vnfd1', 'test-vim', topo_seed)
        vvfn.create_custom_av(COMMON_CONFIG, tacker_client, vnf_names[1], 'test-vnfd2', 'test-vim', topo_seed)

        vvfn.path_join(COMMON_CONFIG, TESTCASE_CONFIG, tacker_client, client_instance, 'red', 'red_http')

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

        sf1_floating_ip, sf2_floating_ip = vvfn.custom_sf_floating_ip(router)
        fips = [client_floating_ip, server_floating_ip, sf1_floating_ip, sf2_floating_ip]

        vvfn.check_floating_ips(fips, sf1_floating_ip, sf2_floating_ip, server_floating_ip, odl_ip, odl_port)
        logger.info("Wait for ODL to update the classification rules in OVS")
        t1.join()

        results, verdict_ssh = vvfn.present_results_ssh(COMMON_CONFIG, server_instance, deployment_handler,
                                                        compute_nodes, client_floating_ip,
                                                        ovs_logger)
        results, verdict_http = vvfn.present_results_http(COMMON_CONFIG, client_floating_ip, server_instance,
                                                          ovs_logger, deployment_handler, compute_nodes)
        verdict_vvfn1 = (verdict_ssh and verdict_http)

        logger.info("Changing the classification")

        vvfn.remove_vnff(tacker_client, 'red_http_works', 'red')

        vvfn.path_join(COMMON_CONFIG, TESTCASE_CONFIG, tacker_client, client_instance, 'blue', 'blue_ssh')

        # Start measuring the time it takes to implement the classification rules
        t2 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                              args=(ovs_logger, compute_nodes, odl_ip, odl_port, client_instance.compute_host,))
        try:
            t2.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        logger.info("Wait for ODL to update the classification rules in OVS")
        t2.join()

        results, verdict_ssh = vvfn.present_results_ssh(COMMON_CONFIG, server_instance, deployment_handler,
                                                        compute_nodes, client_floating_ip,
                                                        ovs_logger)
        results, verdict_http = vvfn.present_results_http(COMMON_CONFIG, client_floating_ip, server_instance,
                                                          ovs_logger, deployment_handler, compute_nodes)
        verdict_vvfn2 = (verdict_ssh and verdict_http)

        if __name__ == '__main__':
            return results.compile_summary(), openstack_sfc.creators

        if __name__ == 'sfc.tests.functest.sfc_two_chains_SSH_and_HTTP':
            return results.compile_summary(), openstack_sfc.creators

        total_verdict = (verdict_vvfn1 and verdict_vvfn2)

        if total_verdict:
            return testcase.TestCase.EX_OK

        return testcase.TestCase.EX_RUN_ERROR


def main():
    logging.config.fileConfig(COMMON_CONFIG.functest_logging_api)
    run_main = SfcTwoChainsSSHandHTTP()
    results, creators = run_main.run()

    return results, creators


if __name__ == '__main__':
    logging.config.fileConfig(COMMON_CONFIG.functest_logging_api)
    test_run = SfcTwoChainsSSHandHTTP()
    test_run.run()

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

from sfc.tests.functest.sfc_parent_function import CommonTestCase as Common

import sfc.lib.openstack_utils as os_sfc_utils
import sfc.lib.odl_utils as odl_utils
import opnfv.utils.ovs_logger as ovs_log

import sfc.lib.config as sfc_config
import sfc.lib.test_utils as test_utils
from sfc.lib.results import Results
from opnfv.deployment.factory import Factory as DeploymentFactory
import sfc.lib.topology_shuffler as topo_shuffler

""" logging configuration """
logger = logging.getLogger(__name__)

CLIENT = "client"
SERVER = "server"
COMMON_CONFIG = sfc_config.CommonConfig()
TESTCASE_CONFIG = sfc_config.TestcaseConfig(
                                            'sfc_one_chain_two_service'
                                            '_functions')


class SfcOneChainTwoServiceTC(Common):

    def run(self):
        supported_installers = ['fuel', 'apex', 'osa']
        vvfn = Common()

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

        vnfs = ['testVNF1', 'testVNF2']

        test_topology, topo_seed = vvfn.prepare_topology(vnfs)
        compute_clients, controller_clients = vvfn.prepare_client_resources(COMMON_CONFIG, compute_nodes,
                                                                            controller_nodes)
        tacker_client = os_sfc_utils.get_tacker_client()

        server_instance, server_creator, client_instance, client_creator = vvfn.prepare_server_client_elements(
            COMMON_CONFIG, SERVER, image_creator, vnfs, topo_seed, network, sg)

        logger.info('This test is run with the topology {0}'.format(test_topology['id']))
        logger.info('Topology description: {0}'.format(test_topology['description']))

        server_ip = server_instance.ports[0].ips[0]['ip_address']
        logger.info("Server instance received private ip [{}]".format(server_ip))

        os_sfc_utils.register_vim(tacker_client, vim_file=COMMON_CONFIG.vim_file)

        vvfn1 = Common()
        vvfn2 = Common()

        vvfn1.create_custom_vnfd(COMMON_CONFIG, tacker_client, TESTCASE_CONFIG.test_vnfd_red, 'test-vnfd1')
        vvfn2.create_custom_vnfd(COMMON_CONFIG, tacker_client, TESTCASE_CONFIG.test_vnfd_blue, 'test-vnfd2')

        vnfs = ['testVNF1', 'testVNF2']
        vvfn1.create_custom_av(COMMON_CONFIG, tacker_client, vnfs[0], 'test-vnfd1', 'test-vim', topo_seed)
        vvfn2.create_custom_av(COMMON_CONFIG, tacker_client, vnfs[1], 'test-vnfd2', 'test-vim', topo_seed)

        vvfn1.path_join(COMMON_CONFIG, TESTCASE_CONFIG, tacker_client, client_instance, 'red', 'red_http')

    # Start measuring the time it takes to implement the classification rules
        t1 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                              args=(ovs_logger, compute_nodes, odl_ip, odl_port, openstack_sfc.get_compute_client(),))
        try:
            t1.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        server_floating_ip, client_floating_ip = \
            vvfn.custom_floating_ip(router, client_instance, client_creator, server_instance, server_creator)

        sf1_floating_ip, sf2_floating_ip = vvfn.custom_sf_floating_ip(router)
        fips = [client_floating_ip, server_floating_ip, sf1_floating_ip, sf2_floating_ip]

        vvfn.check_floating_ips(fips, sf1_floating_ip, sf2_floating_ip, server_floating_ip, odl_ip, odl_port)

        t1.join()

        results, verdict = vvfn.present_results_http(COMMON_CONFIG, client_floating_ip, server_instance, ovs_logger,
                                                     deployment_handler, compute_nodes)

        results, verdict_traffic = \
            vvfn.block_http_trafic(sf1_floating_ip, sf2_floating_ip, client_floating_ip, ovs_logger, controller_clients,
                                   server_ip, compute_nodes, results)
        total_verdict = (verdict and verdict_traffic)

        if __name__ == '__main__':
            return results.compile_summary(), openstack_sfc.creators

        if total_verdict:
            return testcase.TestCase.EX_OK

        return testcase.TestCase.EX_RUN_ERROR


if __name__ == '__main__':
    logging.config.fileConfig(COMMON_CONFIG.functest_logging_api)
    test_run = SfcOneChainTwoServiceTC()
    test_run.run()

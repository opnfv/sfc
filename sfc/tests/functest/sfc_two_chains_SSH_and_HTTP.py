#!/usr/bin/env python
#
# Copyright (c) 2015 All rights reserved
# This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
#
# http://www.apache.org/licenses/LICENSE-2.0
#

import threading
import logging
from sfc.tests.functest.sfc_parent_function import SFCCommonTestCase as Common
import sfc.lib.openstack_utils as os_sfc_utils
import sfc.lib.odl_utils as odl_utils
import sfc.lib.config as sfc_config
from sfc.lib.results import Results


logger = logging.getLogger(__name__)
openstack_sfc = os_sfc_utils.OpenStackSFC()
CLIENT = "client"
SERVER = "server"
COMMON_CONFIG = sfc_config.CommonConfig()
TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_two_chains_SSH_and_HTTP')


class SfcTwoChainsSSHandHTTP(Common):

    def run(self):

        supported_installers = ['fuel', 'apex', 'osa', 'compass']

        ovs_logger, network, router, sg, image_creator, creators =\
            self.preparation_openstack(TESTCASE_CONFIG, logger,
                                       supported_installers)
        compute_nodes, controller_nodes = self.get_installer_deployment_nodes()
        odl_ip, odl_port, deployment_handler = self.get_deployment_odl()

        for compute in compute_nodes:
            logger.info("This is a compute: %s" % compute.ip)

        results = Results(COMMON_CONFIG.line_length)
        results.add_to_summary(0, "=")
        results.add_to_summary(2, "STATUS", "SUBTEST")
        results.add_to_summary(0, "=")

        vnf_names = ['testVNF1', 'testVNF2']

        test_topology, topo_seed = self.prepare_topology(vnf_names)

        logger.info('This test is run with the topology {0}'
                    .format(test_topology['id']))
        logger.info('Topology description: {0}'
                    .format(test_topology['description']))

        server_instance, server_creator, client_instance, client_creator =\
            self.prepare_server_client_vm(image_creator, vnf_names, topo_seed,
                                          network, sg)
        tacker_client = os_sfc_utils.get_tacker_client()

        server_ip = server_instance.ports[0].ips[0]['ip_address']
        logger.info("Server instance received private ip [{}]".
                    format(server_ip))

        os_sfc_utils.register_vim(tacker_client,
                                  vim_file=COMMON_CONFIG.vim_file)

        self.create_custom_vnfd(tacker_client, TESTCASE_CONFIG.test_vnfd_red,
                                'test-vnfd1')
        self.create_custom_vnfd(tacker_client, TESTCASE_CONFIG.test_vnfd_blue,
                                'test-vnfd2')

        self.create_custom_av(tacker_client, vnf_names[0], 'test-vnfd1',
                              'test-vim', topo_seed)
        self.create_custom_av(tacker_client, vnf_names[1], 'test-vnfd2',
                              'test-vim', topo_seed)

        self.vnffg(TESTCASE_CONFIG, tacker_client, client_instance, 'red',
                   'red_http')

        t1 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                              args=(ovs_logger, compute_nodes, odl_ip,
                                    odl_port, client_instance.compute_host,))

        try:
            t1.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        logger.info("Assigning floating IPs to instances")
        server_floating_ip, client_floating_ip =\
            self.assign_floating_ip(router, client_instance, client_creator,
                                    server_instance, server_creator)

        sf1_floating_ip, sf2_floating_ip = self.custom_sf_floating_ip(router)
        fips = [client_floating_ip, server_floating_ip, sf1_floating_ip,
                sf2_floating_ip]

        self.check_floating_ips(fips, sf1_floating_ip, sf2_floating_ip,
                                odl_ip, odl_port)
        self.start_services_in_vm(server_floating_ip, sf1_floating_ip,
                                  sf2_floating_ip)
        logger.info("Wait for ODL to update the classification rules in OVS")
        t1.join()

        openstack_nodes = self.get_openstack_nodes(deployment_handler)

        results = self.present_results_ssh(server_instance, compute_nodes,
                                           client_floating_ip, ovs_logger,
                                           openstack_nodes)
        results = self.present_results_http(client_floating_ip,
                                            server_instance,
                                            ovs_logger, compute_nodes,
                                            openstack_nodes)

        logger.info("Changing the classification")

        self.remove_vnffg(tacker_client, 'red_http_works', 'red')

        self.create_vnffg(TESTCASE_CONFIG, tacker_client, client_instance,
                          client_creator, 'blue', 'blue_ssh')

        # Start measuring the time it takes to implement the classification
        #  rules
        t2 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                              args=(ovs_logger, compute_nodes, odl_ip,
                                    odl_port, client_instance.compute_host,))
        try:
            t2.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        logger.info("Wait for ODL to update the classification rules in OVS")
        t2.join()

        results = self.present_results_ssh(server_instance, compute_nodes,
                                           client_floating_ip, ovs_logger,
                                           openstack_nodes)
        results = self.present_results_http(client_floating_ip,
                                            server_instance,
                                            ovs_logger, compute_nodes,
                                            openstack_nodes)

        if __name__ == '__main__':
            return results.compile_summary(), creators

        if __name__ == 'sfc.tests.functest.sfc_two_chains_SSH_and_HTTP':
            return results.compile_summary(), creators


def main():
    logger.info("The test scenario %s is starting", __name__)
    run_main = SfcTwoChainsSSHandHTTP()
    results, creators = run_main.run()

    return results, creators


if __name__ == '__main__':
    logging.config.fileConfig(COMMON_CONFIG.functest_logging_api)
    test_run = SfcTwoChainsSSHandHTTP()
    test_run.run()
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
import sfc.lib.openstack_utils as os_sfc_utils
import sfc.lib.odl_utils as odl_utils
from sfc.tests.functest import sfc_parent_function
import sfc.lib.config as sfc_config
import sfc.lib.test_utils as test_utils
from sfc.lib.results import Results


logger = logging.getLogger(__name__)
openstack_sfc = os_sfc_utils.OpenStackSFC()
CLIENT = "client"
SERVER = "server"
COMMON_CONFIG = sfc_config.CommonConfig()
TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_chain_deletion')


class SfcChainDeletion(sfc_parent_function.SfcCommonTestCase):
    """We create one client and one server using nova.
       Then, a SF is created using tacker.
       A service chain routing the traffic
       throught this SF will be created as well.
       After that the chain is deleted and re-created.
       Finally, the vxlan tool is used in order to check a single
       HTTP traffic scenario.
       Input : system details as well as TC templates are used
       Output : results , creators
    """
    def run(self):

        supported_installers = ['fuel', 'apex', 'osa', 'compass']

        ovs_logger, network, router, sg, image_creator, creators =\
            self.prepare_env(TESTCASE_CONFIG, logger, supported_installers)
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

        os_sfc_utils.register_vim(tacker_client,
                                  vim_file=COMMON_CONFIG.vim_file)

        self.create_custom_vnfd(tacker_client, TESTCASE_CONFIG.test_vnfd_red,
                                'test-vnfd1')
        self.create_custom_av(tacker_client, vnf_names[0], 'test-vnfd1',
                              'test-vim', test_topology)

        neutron_port = self.create_chain(TESTCASE_CONFIG, client_instance,
                                         client_creator)

        t1 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                              args=(ovs_logger, compute_nodes, odl_ip,
                                    odl_port, client_instance.compute_host,
                                    neutron_port))

        try:
            t1.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        logger.info("Assigning floating IPs to instances")

        server_floating_ip, client_floating_ip =\
            self.assign_floating_ip(router, client_instance, client_creator,
                                    server_instance, server_creator)
        fips_sfs = openstack_sfc.assign_floating_ip_vnfs(router)
        sf1_floating_ip = fips_sfs[0]

        fips = [client_floating_ip, server_floating_ip, sf1_floating_ip]
        self.check_floating_ips(fips, fips_sfs[0], fips_sfs[0],
                                odl_ip, odl_port)

        self.start_services_in_vm(server_floating_ip, sf1_floating_ip,
                                  sf1_floating_ip)
        logger.info("Wait for ODL to update the classification rules in OVS")
        t1.join()

        self.remove_vnffg(tacker_client, 'red_http', 'red')
        self.check_deletion(odl_ip, odl_port, ovs_logger, compute_nodes,
                            openstack_sfc.get_compute_client)

        neutron_port = self.create_chain(TESTCASE_CONFIG, client_instance,
                                         client_creator)

        t2 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                              args=(ovs_logger, compute_nodes, odl_ip,
                                    odl_port, client_instance.compute_host,
                                    neutron_port))
        try:
            t2.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        logger.info("Starting SSH firewall on %s" % sf1_floating_ip)
        test_utils.start_vxlan_tool(sf1_floating_ip)

        logger.info("Wait for ODL to update the classification rules in OVS")
        t2.join()

        openstack_nodes = self.get_openstack_nodes(deployment_handler)

        logger.info("Test HTTP")
        results = self.present_results_allowed_http(client_floating_ip,
                                                    server_instance,
                                                    ovs_logger, compute_nodes,
                                                    openstack_nodes)

        self.vxlan_blocking_start(sf1_floating_ip, "80")

        logger.info("Test HTTP again")
        results = self.present_results_http(client_floating_ip,
                                            server_instance, ovs_logger,
                                            compute_nodes, openstack_nodes)

        if __name__ == '__main__':
            return results.compile_summary(), creators

        if __name__ == 'sfc.tests.functest.sfc_chain_deletion':
            return results.compile_summary(), creators


def main():
    logger.info("The test scenario %s is starting", __name__)
    run_main = SfcChainDeletion()
    results, creators = run_main.run()

    return results, creators


if __name__ == '__main__':
    logging.config.fileConfig(COMMON_CONFIG.functest_logging_api)
    test_run = SfcChainDeletion()
    test_run.run()

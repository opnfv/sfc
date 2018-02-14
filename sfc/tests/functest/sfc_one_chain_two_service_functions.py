#!/bin/python
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
from sfc.tests.functest import sfc_parent_function
import sfc.lib.openstack_utils as os_sfc_utils
import sfc.lib.odl_utils as odl_utils
import sfc.lib.config as sfc_config
from sfc.lib.results import Results

""" logging configuration """
logger = logging.getLogger(__name__)

openstack_sfc = os_sfc_utils.OpenStackSFC()
CLIENT = "client"
SERVER = "server"
COMMON_CONFIG = sfc_config.CommonConfig()
TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_one_chain_two_service'
                                            '_functions')


class SfcOneChainTwoServiceTC(sfc_parent_function.SfcCommonTestCase):
    """
    We create one client and one server using nova.
    Then, 2 SFs are created using tacker.
    A chain is created where both SFs are included.
    The vxlan tool is used on both SFs. The purpose is to
    check different HTTP traffic combinations.
    Input : system details as well as TC templates are used
    Output : results , creators
    """
    def run(self):
        supported_installers = ['fuel', 'apex', 'osa', 'compass']

        self.prepare_env(TESTCASE_CONFIG, supported_installers)

        results = Results(COMMON_CONFIG.line_length)
        results.add_to_summary(0, "=")
        results.add_to_summary(2, "STATUS", "SUBTEST")
        results.add_to_summary(0, "=")

        vnfs = ['testVNF1', 'testVNF2']

        self.prepare_topology(vnfs)
        self.prepare_client_resources()

        self.prepare_server_client_vm(vnfs)

        self.create_custom_vnfd(TESTCASE_CONFIG.test_vnfd_red,
                                'test-vnfd1')
        self.create_custom_vnfd(TESTCASE_CONFIG.test_vnfd_blue,
                                'test-vnfd2')

        self.create_custom_av(vnfs[0], 'test-vnfd1', 'test-vim')
        self.create_custom_av(vnfs[1], 'test-vnfd2', 'test-vim')

        self.create_vnffg(TESTCASE_CONFIG, 'red', 'red_http')
        # Start measuring the time it takes to implement the
        #  classification rules
        t1 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                              args=(self.ovs_logger, self.compute_nodes,
                                    self.odl_ip, self.odl_port,
                                    self.client_instance.compute_host,
                                    self.neutron_port))
        try:
            t1.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        self.assign_floating_ip()

        sf1_floating_ip, sf2_floating_ip = self.custom_sf_floating_ip()
        fips = [self.client_floating_ip, self.server_floating_ip,
                sf1_floating_ip, sf2_floating_ip]

        self.check_floating_ips(fips, sf1_floating_ip, sf2_floating_ip)
        self.start_services_in_vm(sf1_floating_ip, sf2_floating_ip)

        t1.join()

        logger.info("Allowed HTTP scenario")
        results = self.present_results_allowed_http()

        self.vxlan_blocking_start(sf1_floating_ip, "80")
        results = self.present_results_http()

        self.vxlan_blocking_start(sf2_floating_ip, "80")
        self.vxlan_blocking_stop(sf1_floating_ip)

        results = self.present_results_http()

        if __name__ == '__main__':
            return results.compile_summary(), self.creators

        if __name__ ==\
                'sfc.tests.functest.sfc_one_chain_two_service_functions':
            return results.compile_summary(), self.creators


def main():
    logger.info("The test scenario %s is starting", __name__)
    run_main = SfcOneChainTwoServiceTC()
    results, creators = run_main.run()

    return results, creators


if __name__ == '__main__':
    logging.config.fileConfig(COMMON_CONFIG.functest_logging_api)
    test_run = SfcOneChainTwoServiceTC()
    test_run.run()

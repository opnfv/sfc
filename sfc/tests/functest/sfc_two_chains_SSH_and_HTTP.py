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
import urllib3

import sfc.lib.odl_utils as odl_utils
import sfc.lib.config as sfc_config
from sfc.tests.functest import sfc_parent_function

""" logging configuration """
logger = logging.getLogger(__name__)


class SfcTwoChainsSSHandHTTP(sfc_parent_function.SfcCommonTestCase):
    """We create one client and one server using nova.
    Then, 2 SFs are created using tacker.
    Two chains are created, having one SF each.
    The vxlan tool is used on both SFs. The purpose is to
    check different HTTP and SSH traffic combinations.
    """

    def run(self):

        logger.info("The test scenario %s is starting", __name__)

        self.register_vnf_template(self.testcase_config.test_vnfd_red,
                                   'test-vnfd1')
        self.register_vnf_template(self.testcase_config.test_vnfd_blue,
                                   'test-vnfd2')

        self.create_vnf(self.vnfs[0], 'test-vnfd1', 'test-vim')
        self.create_vnf(self.vnfs[1], 'test-vnfd2', 'test-vim')

        self.create_vnffg(self.testcase_config.test_vnffgd_red, 'red',
                          'red_http', port=80, protocol='tcp', symmetric=False)

        t1 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                              args=(self.ovs_logger, self.compute_nodes,
                                    self.odl_ip, self.odl_port,
                                    self.client_instance.compute_host,
                                    [self.neutron_client_port],))

        try:
            t1.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        logger.info("Assigning floating IPs to instances")
        self.assign_floating_ip_client_server()

        self.assign_floating_ip_sfs()

        self.check_floating_ips()
        self.start_services_in_vm()
        self.vxlan_blocking_start(self.fips_sfs[0], "22")
        self.vxlan_blocking_start(self.fips_sfs[1], "80")

        logger.info("Wait for ODL to update the classification rules in OVS")
        t1.join()

        results = self.present_results_ssh()
        results = self.present_results_allowed_http()

        logger.info("Changing the classification")

        self.remove_vnffg('red_http', 'red')

        self.create_vnffg(self.testcase_config.test_vnffgd_blue, 'blue',
                          'blue_ssh')

        # Start measuring the time it takes to implement the classification
        #  rules
        t2 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                              args=(self.ovs_logger, self.compute_nodes,
                                    self.odl_ip, self.odl_port,
                                    self.client_instance.compute_host,
                                    self.neutron_client_port,))
        try:
            t2.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        logger.info("Wait for ODL to update the classification rules in OVS")
        t2.join()

        results = self.present_results_http()
        results = self.present_results_allowed_ssh()

        if __name__ == '__main__':
            return results.compile_summary(), self.creators

        if __name__ == 'sfc.tests.functest.sfc_two_chains_SSH_and_HTTP':
            return results.compile_summary(), self.creators

    def get_creators(self):
        """Return the creators info, specially in case the info is not
        returned due to an exception.

        :return: creators
        """
        return self.creators


if __name__ == '__main__':

    # Disable InsecureRequestWarning errors when executing the SFC tests in XCI
    urllib3.disable_warnings()

    TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_two_chains_SSH_and_HTTP')
    supported_installers = ['fuel', 'apex', 'osa', 'compass']
    vnf_names = ['testVNF1', 'testVNF2']

    test_run = SfcTwoChainsSSHandHTTP(TESTCASE_CONFIG, supported_installers,
                                      vnf_names)
    test_run.run()

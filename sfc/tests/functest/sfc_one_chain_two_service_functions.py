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
import urllib3

import sfc.lib.odl_utils as odl_utils
import sfc.lib.config as sfc_config
from sfc.tests.functest import sfc_parent_function

""" logging configuration """
logger = logging.getLogger(__name__)


class SfcOneChainTwoServiceTC(sfc_parent_function.SfcCommonTestCase):
    """We create one client and one server using nova.
    Then, 2 SFs are created using tacker.
    A chain is created where both SFs are included.
    The vxlan tool is used on both SFs. The purpose is to
    check different HTTP traffic combinations.
    """
    def run(self):

        logger.info("The test scenario %s is starting", __name__)
        self.create_custom_vnfd(self.testcase_config.test_vnfd_red,
                                'test-vnfd1')
        self.create_custom_vnfd(self.testcase_config.test_vnfd_blue,
                                'test-vnfd2')

        self.create_vnf(self.vnfs[0], 'test-vnfd1', 'test-vim')
        self.create_vnf(self.vnfs[1], 'test-vnfd2', 'test-vim')

        self.create_vnffg(self.testcase_config.test_vnffgd_red, 'red',
                          'red_http')
        # Start measuring the time it takes to implement the
        #  classification rules
        t1 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                              args=(self.ovs_logger, self.compute_nodes,
                                    self.odl_ip, self.odl_port,
                                    self.client_instance.compute_host,
                                    [self.neutron_port],))
        try:
            t1.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        self.assign_floating_ip_client_server()

        self.assign_floating_ip_sfs()

        self.check_floating_ips()
        self.start_services_in_vm()

        t1.join()

        logger.info("Allowed HTTP scenario")
        results = self.present_results_allowed_http()

        self.vxlan_blocking_start(self.fips_sfs[0], "80")
        results = self.present_results_http()

        self.vxlan_blocking_start(self.fips_sfs[1], "80")
        self.vxlan_blocking_stop(self.fips_sfs[0])

        results = self.present_results_http()

        if __name__ == '__main__':
            return results.compile_summary(), self.creators

        if __name__ == \
                'sfc.tests.functest.sfc_one_chain_two_service_functions':
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

    TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_one_chain_two_service'
                                                '_functions')
    supported_installers = ['fuel', 'apex', 'osa', 'compass']
    vnfs = ['testVNF1', 'testVNF2']

    test_run = SfcOneChainTwoServiceTC(TESTCASE_CONFIG, supported_installers,
                                       vnfs)
    test_run.run()

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
import sfc.lib.test_utils as test_utils
from sfc.tests.functest import sfc_parent_function

logger = logging.getLogger(__name__)


class SfcChainDeletion(sfc_parent_function.SfcCommonTestCase):
    """We create one client and one server using nova.
    Then, a SF is created using tacker.
    A service chain routing the traffic
    throught this SF will be created as well.
    After that the chain is deleted and re-created.
    Finally, the vxlan tool is used in order to check a single
    HTTP traffic scenario.
    """
    def run(self):

        logger.info("The test scenario %s is starting", __name__)
        self.register_vnf_template(self.testcase_config.test_vnfd_red,
                                   'test-vnfd1')
        self.create_vnf(self.vnfs[0], 'test-vnfd1', 'test-vim')

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
        logger.info("Wait for ODL to update the classification rules in OVS")
        t1.join()

        self.remove_vnffg('red_http', 'red')
        self.check_deletion()

        self.create_vnffg(self.testcase_config.test_vnffgd_red, 'blue',
                          'blue_http', port=80, protocol='tcp',
                          symmetric=False, only_chain=True)

        t2 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                              args=(self.ovs_logger, self.compute_nodes,
                                    self.odl_ip, self.odl_port,
                                    self.client_instance.compute_host,
                                    [self.neutron_client_port],))
        try:
            t2.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        logger.info("Starting SSH firewall on %s" % self.fips_sfs[0])
        test_utils.start_vxlan_tool(self.fips_sfs[0])

        logger.info("Wait for ODL to update the classification rules in OVS")
        t2.join()

        logger.info("Test HTTP")
        results = self.present_results_allowed_http()

        self.vxlan_blocking_start(self.fips_sfs[0], "80")

        logger.info("Test HTTP again")
        results = self.present_results_http()

        if __name__ == '__main__':
            return results.compile_summary(), self.creators

        if __name__ == 'sfc.tests.functest.sfc_chain_deletion':
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

    TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_chain_deletion')
    supported_installers = ['fuel', 'apex', 'osa', 'compass']
    vnf_names = ['testVNF1', 'testVNF2']

    test_run = SfcChainDeletion(TESTCASE_CONFIG, supported_installers,
                                vnf_names)
    test_run.run()

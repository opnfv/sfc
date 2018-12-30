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

import sfc.lib.odl_utils as odl_utils
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

        self.register_vnf_template(self.testcase_config, 'test_vnfd_red',
                                   'test-vnfd1')
        self.register_vnf_template(self.testcase_config, 'test_vnfd_blue',
                                   'test-vnfd2')

        self.register_ns_template(self.testcase_config, 'test_one_chain_nsd',
                                  'test-one-chain-nsd')

        self.create_vnf(self.vnfs[0], 'test-vnfd1', 'test-vim')
        self.create_vnf(self.vnfs[1], 'test-vnfd2', 'test-vim')

        self.create_ns(self.testcase_config, 'test-one-chain-nsd', 'test-vim')

        self.create_vnffg(self.testcase_config, "test_vnffgd_red", 'red',
                          'red_http', port=80, protocol='tcp', symmetric=False)

        # Start measuring the time it takes to implement the
        #  classification rules
        t1 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                              args=(self.ovs_logger, self.compute_nodes,
                                    self.odl_ip, self.odl_port,
                                    self.client_instance.hypervisor_hostname,
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

#!/usr/bin/env python
#
# Copyright (c) 2017 Ericsson AB and others. All rights reserved
#
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

logger = logging.getLogger(__name__)


class SfcSymmetricChain(sfc_parent_function.SfcCommonTestCase):
    """
    A symmetric service chain routing the traffic throught
    this SF will be created. The purpose is to
    check different HTTP traffic combinations using firewall.
    """

    def run(self):

        logger.info("The test scenario %s is starting", __name__)

        self.register_vnf_template(self.testcase_config, 'test_vnfd',
                                   'test-vnfd1')
        self.create_vnf(self.vnfs[0], 'test-vnfd1', 'test-vim', symmetric=True)

        self.create_vnffg(self.testcase_config, 'test_vnffgd', 'red-symmetric',
                          'red_http', port=80, protocol='tcp', symmetric=True)

        # Start measuring the time it takes to implement
        # the classification rules
        t1 = threading.Thread(target=symmetric_wait_for_classification_rules,
                              args=(self.ovs_logger, self.compute_nodes,
                                    self.server_instance.hypervisor_hostname,
                                    self.port_server,
                                    self.client_instance.hypervisor_hostname,
                                    self.port_client,
                                    self.odl_ip, self.odl_port,))
        try:
            t1.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        logger.info("Assigning floating IPs to instances")

        self.assign_floating_ip_client_server()

        self.assign_floating_ip_sfs()

        self.check_floating_ips()

        self.start_services_in_vm()

        self.vxlan_start_interface(self.fips_sfs[0], 'eth0', 'eth1', None)
        self.vxlan_start_interface(self.fips_sfs[0], 'eth1', 'eth0', None)

        logger.info("Wait for ODL to update the classification rules in OVS")
        t1.join()

        results = self.present_results_allowed_port_http(self.testcase_config)

        self.vxlan_blocking_stop(self.fips_sfs[0])
        self.vxlan_start_interface(self.fips_sfs[0], 'eth0', 'eth1', "80")
        self.vxlan_start_interface(self.fips_sfs[0], 'eth1', 'eth0', None)

        results = self.present_results_blocked_port_http(self.testcase_config,
                                                         'HTTP uplink')

        self.vxlan_blocking_stop(self.fips_sfs[0])
        self.vxlan_start_interface(self.fips_sfs[0], 'eth0', 'eth1', None)
        self.vxlan_start_interface(self.fips_sfs[0], 'eth1', 'eth0',
                                   self.testcase_config.source_port)

        results = self.present_results_blocked_port_http(self.testcase_config,
                                                         'HTTP downlink')

        self.vxlan_blocking_stop(self.fips_sfs[0])
        self.vxlan_start_interface(self.fips_sfs[0], 'eth0', 'eth1', None)
        self.vxlan_start_interface(self.fips_sfs[0], 'eth1', 'eth0', None)
        results = self.present_results_allowed_http()

        if __name__ == '__main__':
            return results.compile_summary(), self.creators

        if __name__ == 'sfc.tests.functest.sfc_symmetric_chain':
            return results.compile_summary(), self.creators

    def get_creators(self):
        """Return the creators info, specially in case the info is not
        returned due to an exception.

        :return: creators
        """
        return self.creators


def symmetric_wait_for_classification_rules(ovs_logger, compute_nodes,
                                            server_compute, server_port,
                                            client_compute, client_port,
                                            odl_ip, odl_port):
    if client_compute == server_compute:
        odl_utils.wait_for_classification_rules(
            ovs_logger,
            compute_nodes,
            odl_ip,
            odl_port,
            client_compute,
            [server_port, client_port])
    else:
        odl_utils.wait_for_classification_rules(
            ovs_logger,
            compute_nodes,
            odl_ip,
            odl_port,
            server_compute,
            server_port)
        odl_utils.wait_for_classification_rules(
            ovs_logger,
            compute_nodes,
            odl_ip,
            odl_port,
            client_compute,
            client_port)

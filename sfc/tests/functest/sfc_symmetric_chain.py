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
import os
import sys
import threading
import sfc.lib.openstack_utils as os_sfc_utils
import sfc.lib.odl_utils as odl_utils
import opnfv.utils.ovs_logger as ovs_log
import sfc.lib.config as sfc_config
import sfc.lib.test_utils as test_utils
import sfc.lib.topology_shuffler as topo_shuffler

from opnfv.utils import opnfv_logger as logger
from sfc.lib.results import Results
from opnfv.deployment.factory import Factory as DeploymentFactory

""" logging configuration """
logger = logger.Logger(__name__).getLogger()

from sfc.tests.functest import sfc_parent_function

openstack_sfc = os_sfc_utils.OpenStackSFC()
CLIENT = "client"
SERVER = "server"
COMMON_CONFIG = sfc_config.CommonConfig()
TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_symmetric_chain')
supported_installers = ['fuel', 'apex', 'osa', 'compass']
vnf_names = ['testVNF1']


class SfcSymmetricChain(sfc_parent_function.SfcCommonTestCase):
    """One client and one server are created using nova.
    The server will be running a web server on port 80.
    Then one Service Function (SF) is created using Tacker.
    This service function will be running a firewall that
    blocks the traffic in a specific port.
    A symmetric service chain routing the traffic throught
    this SF will be created as well.
    The purpose is to check different HTTP traffic
    combinations using firewall.
    """

    def run(self):

        logger.info("The test scenario %s is starting", __name__)
        self.create_custom_vnfd(TESTCASE_CONFIG.test_vnfd, 'test-vnfd1')
        self.create_custom_av(vnf_names[0], 'test-vnfd1', 'test-vim')

        if self.vnf_id is None:
            logger.error('ERROR while booting VNF')
            sys.exit(1)

        tosca_file = os.path.join(
            COMMON_CONFIG.sfc_test_dir,
            COMMON_CONFIG.vnffgd_dir,
            TESTCASE_CONFIG.test_vnffgd)
        os_sfc_utils.create_vnffgd(
            self.tacker_client,
            tosca_file=tosca_file,
            vnffgd_name='test-vnffgd')

        client_port = openstack_sfc.get_client_port(
            self.client_instance,
            self.client_creator)
        server_port = openstack_sfc.get_client_port(
            self.server_instance,
            self.server_creator)

        server_ip_prefix = self.server_ip + '/32'

        default_param_file = os.path.join(
            COMMON_CONFIG.sfc_test_dir,
            COMMON_CONFIG.vnfd_dir,
            COMMON_CONFIG.vnfd_default_params_file)

        os_sfc_utils.create_vnffg_with_param_file(
            self.tacker_client,
            'test-vnffgd',
            'test-vnffg',
            default_param_file,
            client_port.id,
            server_port.id,
            server_ip_prefix)
        # Start measuring the time it takes to implement the classification
        #  rules
        t1 = threading.Thread(target=wait_for_classification_rules,
                              args=(self.ovs_logger, self.compute_nodes,
                                    self.server_instance.compute_host,
                                    server_port,
                                    self.client_instance.compute_host,
                                    client_port, self.odl_ip,
                                    self.odl_port,))

        try:
            t1.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        logger.info("Assigning floating IPs to instances")
        self.assign_floating_ip_client_server()

        vnf_ip = os_sfc_utils.get_vnf_ip(self.tacker_client,
                                         vnf_id=self.vnf_id)
        self.assign_floating_ip_sfs(vnf_ip)

        self.check_floating_ips()

        self.start_services_in_vm()

        self.vxlan_start_interface(self.fips_sfs[0], 'eth0', 'eth1', None)
        self.vxlan_start_interface(self.fips_sfs[0], 'eth1', 'eth0', None)

        logger.info("Wait for ODL to update the classification rules in OVS")
        t1.join()

        results = self.present_results_allowed_port_http(TESTCASE_CONFIG)

        self.vxlan_blocking_stop(self.fips_sfs[0])
        self.vxlan_start_interface(self.fips_sfs[0], 'eth0', 'eth1', "80")
        self.vxlan_start_interface(self.fips_sfs[0], 'eth1', 'eth0', None)

        results = self.present_results_blocked_port_http(TESTCASE_CONFIG)

        self.vxlan_blocking_stop(self.fips_sfs[0])
        self.vxlan_start_interface(self.fips_sfs[0], 'eth0', 'eth1', None)
        self.vxlan_start_interface(self.fips_sfs[0], 'eth1', 'eth0',
                                   TESTCASE_CONFIG.source_port)

        results = self.present_results_blocked_port_http(TESTCASE_CONFIG)

        self.vxlan_blocking_stop(self.fips_sfs[0])
        self.vxlan_start_interface(self.fips_sfs[0], 'eth0', 'eth1', None)
        self.vxlan_start_interface(self.fips_sfs[0], 'eth1', 'eth0', None)
        results = self.present_results_allowed_http()

        if __name__ == '__main__':
            return results.compile_summary(), self.creators

        if __name__ == 'sfc.tests.functest.sfc_symmetric_chain':
            return results.compile_summary(), self.creators


def wait_for_classification_rules(ovs_logger, compute_nodes,
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


if __name__ == '__main__':
    test_run = SfcSymmetricChain(TESTCASE_CONFIG, supported_installers,
                                 vnf_names)
    test_run.run()

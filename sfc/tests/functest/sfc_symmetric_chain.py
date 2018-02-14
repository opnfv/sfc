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
import sfc.lib.openstack_utils as os_sfc_utils
import sfc.lib.odl_utils as odl_utils
from sfc.tests.functest.sfc_parent_function import CommonTestCase as Common
import sfc.lib.config as sfc_config
import sfc.lib.utils as test_utils
import sfc.lib.topology_shuffler as topo_shuffler


logger = logging.getLogger(__name__)
openstack_sfc = os_sfc_utils.OpenStackSFC()
CLIENT = "client"
SERVER = "server"
COMMON_CONFIG = sfc_config.CommonConfig()
TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_symmetric_chain')


class SfcSymmetricChain(Common):

    def run(self):
        supported_installers = ['fuel', 'apex', 'osa', 'compass']
        vvfn = Common()

        ovs_logger, network, router, sg, image_creator, creators =\
            vvfn.preparation_openstack(TESTCASE_CONFIG, logger,
                                       supported_installers)

        compute_nodes, controller_nodes = vvfn.installer_deployment_nodes()
        odl_ip, odl_port, deployment_handler = vvfn.installer_deployment()

        vnf_names = ['testVNF1']
        # Using seed=0 uses the baseline topology: everything in the same host
        test_topology = topo_shuffler.topology(vnf_names, openstack_sfc,
                                               seed=0)
        topo_seed = topo_shuffler.get_seed()
        logger.info('This test is run with the topology {0}'
                    .format(test_topology['id']))
        logger.info('Topology description: {0}'
                    .format(test_topology['description']))

        server_instance, server_creator, client_instance, client_creator = \
            vvfn.prepare_server_client_elements(image_creator, vnf_names,
                                                topo_seed, network, sg)
        server_ip = server_instance.ports[0].ips[0]['ip_address']
        logger.info("Server instance received private ip [{}]".
                    format(server_ip))
        tacker_client = os_sfc_utils.get_tacker_client()

        vvfn.create_custom_vnfd(tacker_client, TESTCASE_CONFIG.test_vnfd,
                                'test-vnfd1')
        vvfn.create_custom_av(tacker_client, vnf_names, 'test-vnfd1', '',
                              topo_seed)

        os_sfc_utils.create_sfc(
            tacker_client,
            sfc_name='red',
            chain_vnf_names=vnf_names[0],
            symmetrical=True)

        os_sfc_utils.create_sfc_classifier(
            tacker_client, 'red_http', sfc_name='red',
            match={
                'source_port': 0,
                'dest_port': 80,
                'protocol': 6
            })

        # FIXME: JIRA SFC-86
        # Tacker does not allow to specify the direction of the chain to be
        #  used,
        # only references the SFP (which for symmetric chains results in two
        #  RSPs)
        os_sfc_utils.create_sfc_classifier(
            tacker_client, 'red_http_reverse', sfc_name='red',
            match={
                'source_port': 80,
                'dest_port': 0,
                'protocol': 6
            })

        logger.info(test_utils.run_cmd('tacker sfc-list'))
        logger.info(test_utils.run_cmd('tacker sfc-classifier-list'))

        # Start measuring the time it takes to implement the classification
        #  rules
        t1 = threading.Thread(target=odl_utils.wait_for_classification_rules,
                              args=(ovs_logger, compute_nodes, odl_ip,
                                    odl_port,))

        try:
            t1.start()
        except Exception as e:
            logger.error("Unable to start the thread that counts time %s" % e)

        logger.info("Assigning floating IPs to instances")
        server_floating_ip, client_floating_ip =\
            vvfn.custom_floating_ip(router, client_instance, client_creator,
                                    server_instance, server_creator)

        fips_sfs = openstack_sfc.assign_floating_ip_vnfs(router)
        # sf_floating_ip = fips_sfs[0]

        fips = [client_floating_ip, server_floating_ip, fips_sfs[0]]

        vvfn.check_floating_ips(fips, fips_sfs[0], fips_sfs[0],
                                server_floating_ip, odl_ip, odl_port)

        logger.info("Wait for ODL to update the classification rules in OVS")
        t1.join()

        results = vvfn.present_results_allowedport_http(TESTCASE_CONFIG,
                                                        client_floating_ip,
                                                        server_instance,
                                                        ovs_logger,
                                                        deployment_handler,
                                                        compute_nodes)
        results = vvfn.present_results_http(client_floating_ip,
                                            server_instance,
                                            ovs_logger, deployment_handler,
                                            compute_nodes)

        if __name__ == '__main__':
            return results.compile_summary(), creators

        if __name__ == 'sfc.tests.functest.sfc_symmetric_chain':
            return results.compile_summary(), creators


def main():
    logger.info("The test scenario %s is starting", __name__)
    run_main = SfcSymmetricChain()
    results, creators = run_main.run()

    return results, creators


if __name__ == '__main__':
    logging.config.fileConfig(COMMON_CONFIG.functest_logging_api)
    test_run = SfcSymmetricChain()
    test_run.run()

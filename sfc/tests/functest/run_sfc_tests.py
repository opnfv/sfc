#!/bin/python
#
# Copyright (c) 2015 All rights reserved
# This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
#
# http://www.apache.org/licenses/LICENSE-2.0
#

import importlib
import os
import time
import sys
import yaml

from functest.core import testcase
from opnfv.utils import ovs_logger as ovs_log
from opnfv.deployment.factory import Factory as DeploymentFactory
from sfc.lib import cleanup as sfc_cleanup
from sfc.lib import config as sfc_config
from sfc.lib import utils as sfc_utils

from collections import OrderedDict
import logging

logger = logging.getLogger(__name__)
COMMON_CONFIG = sfc_config.CommonConfig()


class SfcFunctest(testcase.OSGCTestCase):

    def __disable_heat_resource_finder_cache_apex(self, controllers):
        remote_heat_conf_etc = '/etc/heat/heat.conf'
        remote_heat_conf_home = '/home/heat-admin/heat.conf'
        local_heat_conf = '/tmp/heat.conf'
        cmd_restart_heat = ("sudo"
                            " /bin/systemctl"
                            " restart"
                            " openstack-heat-engine.service"
                            )
        for controller in controllers:
            logger.info("Fetch {0} from controller {1}"
                        .format(remote_heat_conf_etc, controller.ip))
            controller.run_cmd('sudo cp {0} /home/heat-admin/'
                               .format(remote_heat_conf_etc))
            controller.run_cmd('sudo chmod 777 {0}'
                               .format(remote_heat_conf_home))
            controller.get_file(remote_heat_conf_home, local_heat_conf)
            with open(local_heat_conf, 'a') as cfg:
                cfg.write('\n[resource_finder_cache]\n')
                cfg.write('caching=False\n')
            logger.info("Replace {0} with {1} in controller {2}"
                        .format(remote_heat_conf_etc,
                                local_heat_conf,
                                controller.ip))
            controller.run_cmd('sudo rm -f {0}'.format(remote_heat_conf_home))
            controller.run_cmd('sudo rm -f {0}'.format(remote_heat_conf_etc))
            controller.put_file(local_heat_conf,
                                remote_heat_conf_home)
            controller.run_cmd('sudo cp {0} /etc/heat/'
                               .format(remote_heat_conf_home))
            logger.info("Restart heat-engine in {0}".format(controller.ip))
            controller.run_cmd(cmd_restart_heat)
            os.remove(local_heat_conf)
        logger.info("Waiting for heat-engine to restart in controllers")
        time.sleep(10)

    def __disable_heat_resource_finder_cache_fuel(self, controllers):
        remote_heat_conf = '/etc/heat/heat.conf'
        local_heat_conf = '/tmp/heat.conf'
        for controller in controllers:
            logger.info("Fetch {0} from controller {1}"
                        .format(remote_heat_conf, controller.ip))
            controller.get_file(remote_heat_conf, local_heat_conf)
            with open(local_heat_conf, 'a') as cfg:
                cfg.write('\n[resource_finder_cache]\n')
                cfg.write('caching=False\n')
            logger.info("Replace {0} with {1} in controller {2}"
                        .format(remote_heat_conf,
                                local_heat_conf,
                                controller.ip))
            controller.run_cmd('rm -f {0}'.format(remote_heat_conf))
            controller.put_file(local_heat_conf, remote_heat_conf)
            logger.info("Restart heat-engine in {0}".format(controller.ip))
            controller.run_cmd('service heat-engine restart')
            os.remove(local_heat_conf)
        logger.info("Waiting for heat-engine to restart in controllers")
        time.sleep(10)

    def __disable_heat_resource_finder_cache(self, nodes, installer_type):
        controllers = [node for node in nodes if node.is_controller()]

        if installer_type == 'apex':
            self.__disable_heat_resource_finder_cache_apex(controllers)
        elif installer_type == "fuel":
            self.__disable_heat_resource_finder_cache_fuel(controllers)
        else:
            raise Exception('Unsupported installer')

    def run(self):

        deploymentHandler = DeploymentFactory.get_handler(
            COMMON_CONFIG.installer_type,
            COMMON_CONFIG.installer_ip,
            COMMON_CONFIG.installer_user,
            COMMON_CONFIG.installer_password,
            COMMON_CONFIG.installer_key_file)

        cluster = COMMON_CONFIG.installer_cluster
        nodes = (deploymentHandler.get_nodes({'cluster': cluster})
                 if cluster is not None
                 else deploymentHandler.get_nodes())

        self.__disable_heat_resource_finder_cache(nodes,
                                                  COMMON_CONFIG.installer_type)

        odl_ip, odl_port = sfc_utils.get_odl_ip_port(
            nodes, COMMON_CONFIG.installer_type)

        ovs_logger = ovs_log.OVSLogger(
            os.path.join(COMMON_CONFIG.sfc_test_dir, 'ovs-logs'),
            COMMON_CONFIG.functest_results_dir)

        config_file = os.path.join(COMMON_CONFIG.config_file)
        with open(config_file) as f:
            config_yaml = yaml.safe_load(f)

        testcases = config_yaml.get("testcases")
        testcases_ordered = OrderedDict(sorted(testcases.items(),
                                               key=lambda x: x[1]['order']))
        overall_status = "NOT TESTED"
        self.start_time = time.time()
        for tc, test_cfg in testcases_ordered.items():
            if test_cfg['enabled']:
                test_name = tc
                test_descr = test_cfg['description']
                title = ("Running '%s - %s'" %
                         (test_name, test_descr))
                logger.info(title)
                logger.info("%s\n" % ("=" * len(title)))
                t = importlib.import_module(
                    "sfc.tests.functest.{0}".format(test_name),
                    package=None)
                start_time = time.time()
                try:
                    result = t.main()
                except Exception as e:
                    logger.error("Exception when executing: %s" % test_name)
                    logger.error(e)
                    result = {'status': 'FAILED'}
                end_time = time.time()
                duration = end_time - start_time
                logger.info("Results of test case '%s - %s':\n%s\n" %
                            (test_name, test_descr, result))
                if result['status'] == 'PASS':
                    status = 'PASS'
                    self.details.update({test_name: "worked"})
                    if overall_status != "FAIL":
                        overall_status = "PASS"
                else:
                    status = 'FAIL'
                    overall_status = "FAIL"
                    self.details.update({test_name: "execution error."})
                    ovs_logger.create_artifact_archive()

                dic = {"duration": duration, "status": status}
                self.details.update({test_name: dic})
                sfc_cleanup.cleanup(odl_ip=odl_ip, odl_port=odl_port)

        self.stop_time = time.time()

        if overall_status == "PASS":
            self.result = 100
            return testcase.TestCase.EX_OK

        return testcase.TestCase.EX_RUN_ERROR


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s'
                        '- %(levelname)s - %(message)s')
    SFC = SfcFunctest()
    sys.exit(SFC.run())

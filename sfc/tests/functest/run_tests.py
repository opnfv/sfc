#!/bin/python
#
# Copyright (c) 2015 All rights reserved
# This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
#
# http://www.apache.org/licenses/LICENSE-2.0
#

import argparse
import importlib
import os
import sys
import time
import yaml

import logging
import logging.config
import functest.utils.functest_utils as ft_utils
import functest.utils.openstack_utils as os_utils
import opnfv.utils.ovs_logger as ovs_log
import sfc.lib.cleanup as sfc_cleanup
import sfc.lib.config as sfc_config
import sfc.lib.utils as sfc_utils
from functest.utils.constants import CONST

from collections import OrderedDict
from opnfv.deployment.factory import Factory as DeploymentFactory


logger = logging.getLogger("odl-sfc")
COMMON_CONFIG = sfc_config.CommonConfig()


def push_results(testname, start_time, end_time, criteria, details):
    logger.info("Push testcase '%s' results into the DB...\n" % testname)
    ft_utils.push_results_to_db("sfc",
                                testname,
                                start_time,
                                end_time,
                                criteria,
                                details)


def fetch_tackerc_file(controller_node):
    rc_file = os.path.join(COMMON_CONFIG.sfc_test_dir, 'tackerc')
    if not os.path.exists(rc_file):
        logger.info("tackerc file not found, fetching it from controller")
        controller_node.get_file("/root/tackerc", rc_file)
    else:
        logger.info("found tackerc file")
    return rc_file


def disable_heat_resource_finder_cache(nodes):
    controllers = [node for node in nodes if node.is_controller()]
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
                    .format(remote_heat_conf, local_heat_conf, controller.ip))
        controller.run_cmd('rm -f {0}'.format(remote_heat_conf))
        controller.put_file(local_heat_conf, remote_heat_conf)
        logger.info("Restart heat-engine in {0}".format(controller.ip))
        controller.run_cmd('service heat-engine restart')
        os.remove(local_heat_conf)
    logger.info("Waiting for heat-engine to restart in controllers")
    time.sleep(10)


def main(report=False):
    deploymentHandler = DeploymentFactory.get_handler(
        COMMON_CONFIG.installer_type,
        COMMON_CONFIG.installer_ip,
        COMMON_CONFIG.installer_user,
        installer_pwd=COMMON_CONFIG.installer_password)

    cluster = COMMON_CONFIG.installer_cluster
    nodes = (deploymentHandler.get_nodes({'cluster': cluster})
             if cluster is not None
             else deploymentHandler.get_nodes())

    a_controller = [node for node in nodes
                    if node.is_controller()][0]

    disable_heat_resource_finder_cache(nodes)

    rc_file = fetch_tackerc_file(a_controller)
    os_utils.source_credentials(rc_file)

    logger.info("Updating env with {0}".format(rc_file))
    logger.info("OS credentials:")
    for var, value in os.environ.items():
        if var.startswith("OS_"):
            logger.info("\t{0}={1}".format(var, value))

    odl_ip, odl_port = sfc_utils.get_odl_ip_port(nodes)

    ovs_logger = ovs_log.OVSLogger(
        os.path.join(COMMON_CONFIG.sfc_test_dir, 'ovs-logs'),
        COMMON_CONFIG.functest_results_dir)

    config_file = os.path.join(COMMON_CONFIG.config_file)
    with open(config_file) as f:
        config_yaml = yaml.safe_load(f)

    testcases = config_yaml.get("testcases")
    testcases_ordered = OrderedDict(sorted(testcases.items(),
                                           key=lambda x: x[1]['order']))
    overall_details = {}
    overall_status = "NOT TESTED"
    overall_start_time = time.time()
    for testcase, test_cfg in testcases_ordered.items():
        if test_cfg['enabled']:
            test_name = testcase
            test_descr = test_cfg['description']
            test_name_db = test_cfg['testname_db']
            title = ("Running '%s - %s'" %
                     (test_name, test_descr))
            logger.info(title)
            logger.info("%s\n" % ("=" * len(title)))
            t = importlib.import_module(
                "sfc.tests.functest.{0}".format(testcase),
                package=None)
            start_time = time.time()
            try:
                result = t.main()
            except Exception, e:
                logger.error("Exception when executing: %s" % testcase)
                logger.error(e)
                result = {'status': 'FAILED'}
            end_time = time.time()
            duration = end_time - start_time
            logger.info("Results of test case '%s - %s':\n%s\n" %
                        (test_name, test_descr, result))
            if result['status'] == 'PASS':
                status = 'PASS'
                overall_details.update({test_name_db: "worked"})
                if overall_status != "FAIL":
                    overall_status = "PASS"
            else:
                status = 'FAIL'
                overall_status = "FAIL"
                overall_details.update({test_name_db: "execution error."})
                ovs_logger.create_artifact_archive()

            if report:
                details = result.get("details")
                push_results(
                    test_name_db, start_time, end_time, status, details)

            dic = {"duration": duration, "status": status}
            overall_details.update({test_name_db: dic})
            sfc_cleanup.cleanup(odl_ip=odl_ip, odl_port=odl_port)

    overall_end_time = time.time()
    if report:
        push_results(
            "odl-sfc", overall_start_time, overall_end_time,
            overall_status, overall_details)

    if overall_status == "FAIL":
        sys.exit(-1)

    sys.exit(0)


if __name__ == '__main__':
    logging.config.fileConfig(
        CONST.__getattribute__('dir_functest_logging_cfg'))
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--report",
                        help="Create json result file",
                        action="store_true")
    args = parser.parse_args()
    main(report=args.report)

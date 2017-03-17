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

import functest.utils.functest_logger as ft_logger
import functest.utils.functest_utils as ft_utils
import functest.utils.openstack_utils as os_utils
import opnfv.utils.ovs_logger as ovs_log
import sfc.lib.cleanup as sfc_cleanup
import sfc.lib.config as sfc_config
from opnfv.deployment.factory import Factory as DeploymentFactory


parser = argparse.ArgumentParser()
parser.add_argument("-r", "--report",
                    help="Create json result file",
                    action="store_true")
args = parser.parse_args()

logger = ft_logger.Logger(__name__).getLogger()
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


def main():
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
    rc_file = fetch_tackerc_file(a_controller)

    os_utils.source_credentials(rc_file)

    logger.info("Updating env with {0}".format(rc_file))
    logger.info("OS credentials:")
    for var, value in os.environ.items():
        if var.startswith("OS_"):
            logger.info("\t{0}={1}".format(var, value))

    ovs_logger = ovs_log.OVSLogger(
        os.path.join(COMMON_CONFIG.sfc_test_dir, 'ovs-logs'),
        COMMON_CONFIG.functest_results_dir)

    config_file = os.path.join(COMMON_CONFIG.config_file)
    with open(config_file) as f:
        config_yaml = yaml.safe_load(f)

    testcases = config_yaml.get("testcases")
    overall_details = {}
    overall_status = "FAIL"
    overall_start_time = time.time()
    for testcase in testcases:
        if testcases[testcase]['enabled']:
            test_name = testcase
            test_descr = testcases[testcase]['description']
            test_name_db = testcases[testcase]['testname_db']
            title = ("Running '%s - %s'" %
                     (test_name, test_descr))
            logger.info(title)
            logger.info("%s\n" % ("=" * len(title)))
            t = importlib.import_module(testcase, package=None)
            start_time = time.time()
            result = t.main()
            end_time = time.time()
            duration = end_time - start_time
            status = "FAIL"
            if result != 0:
                overall_details.update({test_name_db: "execution error."})
            else:
                status = result.get("status")
                if status == "FAIL":
                    overall_status = "FAIL"
                    ovs_logger.create_artifact_archive()

                logger.info("Results of test case '%s - %s':\n%s\n" %
                            (test_name, test_descr, result))

                dic = {"duration": duration, "status": overall_status}
                overall_details.update({test_name_db: dic})
            if args.report:
                details = result.get("details")
                push_results(
                    test_name_db, start_time, end_time, status, details)
            sfc_cleanup.cleanup()

    overall_end_time = time.time()
    if args.report:
        push_results(
            "odl-sfc", overall_start_time, overall_end_time,
            overall_status, overall_details)

    if overall_status == "FAIL":
        sys.exit(-1)

    sys.exit(0)


if __name__ == '__main__':
    main()

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
import config as sfc_config
import importlib
import os
import sys
import time
import yaml

import functest.utils.functest_logger as ft_logger
import functest.utils.functest_utils as ft_utils
import opnfv.utils.ovs_logger as ovs_log
import opnfv.utils.SSHUtils as ssh_utils
import sfc.lib.utils as utils


parser = argparse.ArgumentParser()
parser.add_argument("-r", "--report",
                    help="Create json result file",
                    action="store_true")
args = parser.parse_args()

logger = ft_logger.Logger("sfc-run-tests").getLogger()
COMMON_CONFIG = sfc_config.CommonConfig()


def push_results(testname, start_time, end_time, criteria, details):
    logger.info("Push testcase '%s' results into the DB...\n" % testname)
    ft_utils.push_results_to_db("sfc",
                                testname,
                                start_time,
                                end_time,
                                criteria,
                                details)


def get_tackerc_file():
    rc_file = os.path.join(COMMON_CONFIG.sfc_test_dir, 'tackerc')
    if not os.path.exists(rc_file):
        logger.info("tackerc file not found, getting it from controller")
        ip = utils.get_openstack_node_ips("controller")
        ssh_conn = ssh_utils.get_ssh_client(ip[0], 'root',
                                            proxy=COMMON_CONFIG.fuel_proxy)
        ssh_utils.get_file(ssh_conn, "tackerc", rc_file)
    else:
        logger.info("found tackerc file")

    return rc_file


def set_tacker_rc_file_env():
    rc_file = get_tackerc_file()
    with open(rc_file) as f:
        for line in f.readlines():
            if not (line.startswith('#') or len(line) == 1):
                filtered = line.strip().split(' ')
                kv = filtered[1].split('=')
                logger.info("Set shell env %s=%s" % (kv[0], kv[1]))
                os.environ[kv[0]] = kv[1].strip("'")


def main():
    set_tacker_rc_file_env()
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

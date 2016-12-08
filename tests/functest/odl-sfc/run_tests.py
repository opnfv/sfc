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
import ovs_utils
import functest.utils.functest_logger as ft_logger
import functest.utils.functest_utils as ft_utils
import yaml
import utils


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


def get_from_tackerc_file(env):
    cmd = "grep -o %s=.* tackerc|cut -d= -f2" % env
    value = utils.run_cmd_on_controller(cmd)
    if not value:
        logger.info("failed to get value for %s" % env)
        return None

    return eval(value)


def set_tacker_rc_file_env():
    os_password = get_from_tackerc_file("OS_PASSWORD")
    os_auth_url = get_from_tackerc_file("OS_AUTH_URL")
    os.environ['OS_NO_CACHE'] = 'true'
    os.environ['OS_TENANT_NAME'] = 'services'
    os.environ['OS_PROJECT_NAME'] = 'services'
    os.environ['OS_USERNAME'] = 'tacker'
    os.environ['OS_PASSWORD'] = os_password
    os.environ['OS_AUTH_URL'] = os_auth_url
    os.environ['OS_DEFAULT_DOMAIN'] = 'default'
    os.environ['OS_AUTH_STRATEGY'] = 'keystone'
    os.environ['OS_REGION_NAME'] = 'RegionOne'
    os.environ['TACKER_ENDPOINT_TYPE'] = 'internalURL'


def main():
    set_tacker_rc_file_env()
    ovs_logger = ovs_utils.OVSLogger(
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

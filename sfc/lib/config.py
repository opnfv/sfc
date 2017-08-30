#!/usr/bin/python
#
# Copyright (c) 2016 All rights reserved
# This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
#
# http://www.apache.org/licenses/LICENSE-2.0
#

import os
import yaml
import sfc
import functest

import sfc.lib.utils as test_utils
from functest.utils.constants import CONST
import logging
import functest.utils.functest_utils as ft_utils


logger = logging.getLogger(__name__)


class CommonConfig(object):
    """
    Common configuration parameters across testcases
    """

    def __init__(self):
        self.line_length = 30
        self.test_db = ft_utils.get_functest_config("results.test_db_url")
        self.functest_repo_path = os.path.dirname(functest.__file__)
        self.functest_logging_api = os.path.join(self.functest_repo_path,
                                                 "ci", "logging.ini")
        self.sfc_repo_path = os.path.dirname(sfc.__file__)
        self.sfc_test_dir = os.path.join(
            self.sfc_repo_path, "tests", "functest")
        self.vnfd_dir = os.path.join(self.sfc_test_dir, "vnfd-templates")
        self.vnfd_default_params_file = os.path.join(
            self.sfc_test_dir, "vnfd-default-params-file")
        self.functest_results_dir = os.path.join(
            CONST.dir_results, "odl-sfc")
        self.config_file = os.path.join(self.sfc_test_dir,  "config.yaml")

        self.installer_type = CONST.__getattribute__('INSTALLER_TYPE')

        self.installer_fields = test_utils.fill_installer_dict(
                self.installer_type)

        self.installer_ip = CONST.__getattribute__('INSTALLER_IP')

        self.installer_user = ft_utils.get_parameter_from_yaml(
            self.installer_fields['user'], self.config_file)

        try:
            self.installer_password = ft_utils.get_parameter_from_yaml(
                self.installer_fields['password'], self.config_file)
        except:
            self.installer_password = None

        try:
            self.installer_key_file = ft_utils.get_parameter_from_yaml(
                self.installer_fields['pkey_file'], self.config_file)
        except:
            self.installer_key_file = None

        try:
            self.installer_cluster = ft_utils.get_parameter_from_yaml(
                self.installer_fields['cluster'], self.config_file)
        except:
            self.installer_cluster = None

        self.flavor = ft_utils.get_parameter_from_yaml(
            "defaults.flavor", self.config_file)
        self.ram_size_in_mb = ft_utils.get_parameter_from_yaml(
            "defaults.ram_size_in_mb", self.config_file)
        self.disk_size_in_gb = ft_utils.get_parameter_from_yaml(
            "defaults.disk_size_in_gb", self.config_file)
        self.vcpu_count = ft_utils.get_parameter_from_yaml(
            "defaults.vcpu_count", self.config_file)
        self.image_name = ft_utils.get_parameter_from_yaml(
            "defaults.image_name", self.config_file)
        self.image_file_name = ft_utils.get_parameter_from_yaml(
            "defaults.image_file_name", self.config_file)
        self.image_format = ft_utils.get_parameter_from_yaml(
            "defaults.image_format", self.config_file)
        self.url = ft_utils.get_parameter_from_yaml(
            "defaults.url", self.config_file)
        self.dir_functest_data = ft_utils.get_functest_config(
            "general.dir.functest_data")
        self.image_path = os.path.join(
            self.dir_functest_data, self.image_file_name)


class TestcaseConfig(object):
    """
    Configuration for a testcase.
    Parse config.yaml into a dict and create an object out of it.
    """

    def __init__(self, testcase):
        common_config = CommonConfig()
        test_config = None
        with open(common_config.config_file) as f:
            testcases_yaml = yaml.safe_load(f)
            test_config = testcases_yaml['testcases'].get(testcase, None)
        if test_config is None:
            logger.error('Test {0} configuration is not present in {1}'
                         .format(testcase, common_config.config_file))
        # Update class fields with configuration variables dynamically
        self.__dict__.update(**test_config)

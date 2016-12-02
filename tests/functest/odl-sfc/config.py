import yaml
import os

import functest.utils.functest_logger as ft_logger
import functest.utils.functest_utils as ft_utils
import functest.utils.functest_constants as ft_constants

logger = ft_logger.Logger("sfc_test_config").getLogger()


class CommonConfig(object):
    """
    Common configuration parameters across testcases
    """

    def __init__(self):
        self.line_length = 30
        self.test_db = ft_utils.get_functest_config("results.test_db_url")
        self.repo_path = ft_constants.SFC_REPO_DIR
        self.sfc_test_dir = os.path.join(self.repo_path, "tests",
                                         "functest", "odl-sfc")
        self.functest_results_dir = os.path.join(
            ft_constants.FUNCTEST_RESULTS_DIR, "odl-sfc")
        self.config_file = os.path.join(self.sfc_test_dir,  "config.yaml")
        self.fuel_master_ip = ft_utils.get_parameter_from_yaml(
            "defaults.fuel_master_ip", self.config_file)
        self.fuel_master_uname = ft_utils.get_parameter_from_yaml(
            "defaults.fuel_master_uname", self.config_file)
        self.fuel_master_passwd = ft_utils.get_parameter_from_yaml(
            "defaults.fuel_master_passwd", self.config_file)
        self.flavor = ft_utils.get_parameter_from_yaml(
            "defaults.flavor", self.config_file)
        self.image_name = ft_utils.get_parameter_from_yaml(
            "defaults.image_name", self.config_file)
        self.image_file_name = ft_utils.get_parameter_from_yaml(
            "defaults.image_file_name", self.config_file)
        self.image_format = ft_utils.get_parameter_from_yaml(
            "defaults.image_format", self.config_file)
        self.url = ft_utils.get_parameter_from_yaml(
            "defaults.url", self.config_file)
        self.dir_functest_data = ft_utils.get_functest_config(
            "general.directories.dir_functest_data")
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

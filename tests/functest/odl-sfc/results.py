#!/usr/bin/python
#
# Copyright (c) 2016 All rights reserved
# This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
import time

import functest.utils.functest_logger as ft_logger

logger = ft_logger.Logger("sfc-results").getLogger()


class Results(object):

    def __init__(self, line_length):
        self.line_length = line_length
        self.test_result = "PASS"
        self.summary = ""
        self.details = []
        self.num_tests = 0
        self.num_tests_failed = 0

    def add_to_summary(self, num_cols, col1, col2=""):
        if num_cols == 0:
            self.summary += ("+%s+\n" % (col1 * (self.line_length - 2)))
        elif num_cols == 1:
            self.summary += ("| " + col1.ljust(self.line_length - 3) + "|\n")
        elif num_cols == 2:
            self.summary += ("| %s" % col1.ljust(7) + "| ")
            self.summary += (col2.ljust(self.line_length - 12) + "|\n")
            if col1 in ("FAIL", "PASS"):
                self.details.append({col2: col1})
                self.num_tests += 1
                if col1 == "FAIL":
                    self.num_tests_failed += 1

    def compile_summary(self, SUCCESS_CRITERIA):
        success_message = "All the subtests have passed."
        failure_message = "One or more subtests have failed."

        self.add_to_summary(0, "=")
        logger.info("\n%s" % self.summary)
        if self.test_result == "PASS":
            logger.info(success_message)
        else:
            logger.info(failure_message)

        status = "PASS"
        success = 100 - \
            (100 * int(self.num_tests_failed) / int(self.num_tests))
        if success < int(SUCCESS_CRITERIA):
            status = "FAILED"

        return {"status": status, "details": self.details}

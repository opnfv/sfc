# Copyright (c) 2016 All rights reserved
# This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
#
# http://www.apache.org/licenses/LICENSE-2.0

import functest.utils.functest_logger as ft_logger


class TerminalCodes():
    # List of codes: http://misc.flogisoft.com/bash/tip_colors_and_formatting
    LIGHT_RED = '\33[91m'
    LIGHT_GREEN = '\33[92m'
    RESET_ALL = '\33[0m'


class Logger(ft_logger.Logger):
    '''
    Logger that uses terminal color codes to write the output.
    It is meant to be used with test cases, so that the result of
    the test can be easily identified with the typical green/red colors
    '''

    def __init__(self, name):
        super(Logger, self).__init__(name)
        self.logger.fail = self.fail
        self.logger.success = self.success

    def getLogger(self):
        return self.logger

    def _colorize(self, message, color_code):
        return "{prefix_code}{message}{suffix_code}".format(
            prefix_code=color_code,
            message=message,
            suffix_code=TerminalCodes.RESET_ALL)

    def fail(self, message, *args, **kwargs):
        formatted_message = self._colorize(message, TerminalCodes.LIGHT_RED)
        self.logger.info(formatted_message, *args, **kwargs)

    def success(self, message, *args, **kwargs):
        formatted_message = self._colorize(message, TerminalCodes.LIGHT_GREEN)
        self.logger.info(formatted_message, *args, **kwargs)

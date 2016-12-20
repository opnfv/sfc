import functest.utils.functest_logger as ft_logger

class Logger(ft_logger.Logger):
    def __init__(self, name):
        super(Logger, self).__init__(name)

    def fail(self, message, *args, **kwargs):
        formatted_message = "{0}{1}{2}".format('\33[91m', message, '\33[0m')
        self.logger.error(formatted_message, *args, **kwargs)

    def success(self, message, *args, **kwargs):
        formatted_message = "{0}{1}{2}".format('\33[92m', message, '\33[0m')
        self.logger.info(formatted_message, *args, **kwargs)

class TerminalColor:
    """
    Utility class to change the color of a string that is going to be printed
    in a text terminal. It uses terminal color codes to wrap the original string.

    Color reference: http://misc.flogisoft.com/bash/tip_colors_and_formatting
    """

    FOREGROUNDS = {
        'light_red': '\33[91m',
        'light_green': '\33[92m',
    }

    RESET = '\33[0m'

    @classmethod
    def _embed(cls, original_str, color_code):
        return "{0}{1}{2}".format(color_code, original_str, cls.RESET)

    @classmethod
    def foreground(cls, original_str, color_name):
        return cls._embed(original_str, cls.FOREGROUNDS[color_name])

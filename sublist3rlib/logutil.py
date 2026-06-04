# coding: utf-8
"""Logging setup with optional ANSI colouring, replacing the old print() calls."""
import logging
import sys

logger = logging.getLogger('sublist3r')

# ANSI colours
G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # reset

_LEVEL_COLOR = {
    logging.DEBUG: R,      # per-source realtime hits
    logging.INFO: G,
    logging.WARNING: Y,
    logging.ERROR: R,
    logging.CRITICAL: R,
}

# Whether colour is active for this run; consulted by the banner. Set by setup_logging().
_USE_COLOR = True


def colors():
    """Return (G, Y, B, R, W), blanked to empty strings when colour is disabled."""
    if _USE_COLOR:
        return G, Y, B, R, W
    return '', '', '', '', ''


class ColorFormatter(logging.Formatter):
    def __init__(self, use_color=True):
        super().__init__('%(message)s')
        self.use_color = use_color

    def format(self, record):
        msg = super().format(record)
        if self.use_color:
            color = _LEVEL_COLOR.get(record.levelno, '')
            return "%s[-] %s%s" % (color, msg, W)
        return "[-] " + msg


def setup_logging(verbose=False, no_color=False, silent=False):
    global _USE_COLOR
    """Configure the 'sublist3r' logger for CLI use.

    - silent  -> only errors are shown
    - verbose -> DEBUG (realtime per-subdomain output)
    - else    -> INFO
    """
    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    if silent:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    use_color = not no_color
    if use_color and sys.platform.startswith('win'):
        try:
            import colorama
            colorama.init()
        except ImportError:
            use_color = False

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColorFormatter(use_color=use_color))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    _USE_COLOR = use_color
    return use_color

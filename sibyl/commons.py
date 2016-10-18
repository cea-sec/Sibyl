"""Common / shared elements"""
import logging

def init_logger(name):
    logger = logging.getLogger(name)

    console_handler = logging.StreamHandler()
    log_format = "%(levelname)-5s: %(message)s"
    console_handler.setFormatter(logging.Formatter(log_format))
    logger.addHandler(console_handler)

    logger.setLevel(logging.ERROR)
    return logger


class TimeoutException(Exception):
    """Exception to be called on timeouts"""
    pass


END_ADDR = 0x1337babe

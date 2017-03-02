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

def print_table(ligs, title=True, separator='|'):
    "Print nicely @ligs. If title, @ligs[0] is title ligne"
    # Calc max by col
    columns = [0] * len(ligs[0])
    for lig in ligs:
        for index, element in enumerate(lig):
            columns[index] = max(columns[index], len(element))

    fmt_l = ["{%d:^%d}" % (i, l + 2) for i, l in enumerate(columns)]
    fmt = separator.join(fmt_l)

    for i, lig in enumerate(ligs):
        if i == 1 and title:
            print "-" * len(fmt.format(*lig))
        print fmt.format(*lig)

from argparse import ArgumentParser
import os

from utils.log import log_info
from find import test_find
from learn import test_learn

AVAILABLE_TEST = [
    test_find,
    test_learn,
]


parser = ArgumentParser("Regression tester")
parser.add_argument("-f", "--func-heuristic", action="store_true",
                    help="Enable function addresses detection heuristics")
parser.add_argument("-a", "--arch-heuristic", action="store_true",
                    help="Enable architecture detection heuristics")
parser.add_argument("-p", "--pin-tracer", action="store_true",
                    help="Enable PIN tracer")
args = parser.parse_args()

def run_test(test_func, args):
    log_info("Start test: "+test_func.__module__)

    module_path = os.path.dirname(test_func.__module__.replace('.','/'))
    previous_cwd = os.getcwd()

    os.chdir(os.path.join(previous_cwd, module_path))
    ret = test_func(args)
    os.chdir(previous_cwd)
    return ret

fail = False
for test in AVAILABLE_TEST:
    fail |= run_test(test, args)

assert fail is False

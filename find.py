# This file is part of Sibyl.
# Copyright 2014 Camille MOUGEY <camille.mougey@cea.fr>
#
# Sibyl is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Sibyl is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Sibyl. If not, see <http://www.gnu.org/licenses/>.

import argparse
import logging
from multiprocessing import cpu_count, Queue, Process
from miasm2.analysis.machine import Machine
from sibyl.testlauncher import TestLauncher
from sibyl.test import AVAILABLE_TESTS
from sibyl.abi import ABIS

parser = argparse.ArgumentParser(description="Function guesser")
parser.add_argument("filename", help="File to load")
parser.add_argument("architecture", help="Architecture used. Available: " + \
                        ",".join(Machine.available_machine()))
parser.add_argument("abi", help="ABI to used. Available: " + \
                        ",".join([x.__name__ for x in ABIS]))
parser.add_argument("address", help="Address of the function under test",
                    nargs="+")
parser.add_argument("-t", "--tests", help="Tests to run. Available: all," + \
                        ",".join(AVAILABLE_TESTS.keys()),
                    nargs="*", default=["all"])
parser.add_argument("-v", "--verbose", help="Verbose mode", action="store_true")
parser.add_argument("-q", "--quiet", help="Display only results",
                    action="store_true")
parser.add_argument("-i", "--timeout", help="Test timeout (in seconds)",
                    default=2, type=int)
parser.add_argument("-m", "--mapping-base", help="Binary mapping address",
                    default="0")
parser.add_argument("-j", "--jitter", help="""Jitter engine.
Available: tcc (default), llvm, python""", default="tcc")
args = parser.parse_args()


# Functions
def do_test(filename, addr_queue, machine, abicls, tests_cls, map_addr, quiet,
            timeout, jitter, verbose):

    # Init components
    tl = TestLauncher(filename, machine, abicls, tests_cls, jitter, map_addr)
    if verbose:
        tl.logger.setLevel(logging.INFO)
    # Main loop
    while True:
        address = addr_queue.get()
        if address is None:
            break
        possible_funcs = tl.run(address, timeout_seconds=timeout)

        if possible_funcs:
            print "0x%08x : %s" % (address, ",".join(tl.possible_funcs))
        elif not quiet:
            print "No candidate found"


# Parse args
machine = Machine(args.architecture)
addresses = [int(addr, 0) for addr in args.address]
map_addr = int(args.mapping_base, 0)

for abicls in ABIS:
    if args.abi == abicls.__name__:
        break
else:
    raise ValueError("Unknown ABI name: %s" % args.abi)
tests = []
for tname, tcases in AVAILABLE_TESTS.items():
    if "all" in args.tests or tname in args.tests:
        tests += tcases

# Prepare multiprocess
cpu_c = cpu_count()
queue = Queue()
processes = []

for _ in xrange(cpu_c):
    p = Process(target=do_test, args=(args.filename, queue, machine,
                                      abicls, tests, map_addr,
                                      args.quiet, args.timeout, args.jitter,
                                      args.verbose))
    processes.append(p)
    p.start()

# Add tasks
for address in addresses:
    queue.put(address)

# Add poison pill
for _ in xrange(cpu_c):
    queue.put(None)

# Get results
queue.close()
queue.join_thread()
for p in processes:
    p.join()

if not queue.empty():
    print("An error occured: queue is not empty")

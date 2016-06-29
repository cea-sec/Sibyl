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
from miasm2.analysis.binary import Container
from sibyl.testlauncher import TestLauncher
from sibyl.test import AVAILABLE_TESTS
from sibyl.abi import ABIS
from sibyl.heuristics.arch import ArchHeuristic
from sibyl.heuristics.func import FuncHeuristic

parser = argparse.ArgumentParser(description="Function guesser")
parser.add_argument("filename", help="File to load")
parser.add_argument("abi", help="ABI to used. Available: " + \
                        ",".join([x.__name__ for x in ABIS]))
parser.add_argument("address", help="Address of the function under test",
                    nargs="*")
parser.add_argument("-a", "--architecture", help="Architecture used. Available: " + \
                    ",".join(Machine.available_machine()))
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
parser.add_argument("-p", "--monoproc", help="Launch tests in a single process",
                    action="store_true")
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
            print "No candidate found for 0x%08x" % address

# Fake Process
class FakeProcess(object):
    """Mock simulating Process API in monoprocess mode"""

    def __init__(self, target, args):
        self.target = target
        self.args = args

    def start(self, *args, **kwargs):
        self.target(*self.args)

    def join(self, *args, **kwargs):
        pass

# Parse args
architecture = False
if args.architecture:
    architecture = args.architecture
else:
    with open(args.filename) as fdesc:
        architecture = ArchHeuristic(fdesc).guess()
    if not architecture:
        raise ValueError("Unable to recognize the architecture, please specify it")
    if not args.quiet:
        print "Guessed architecture: %s" % architecture

machine = Machine(architecture)
if not args.address:
    if not args.quiet:
        print "No function address provided, start guessing"

    cont = Container.from_stream(open(args.filename))
    fh = FuncHeuristic(cont, machine)
    addresses = list(fh.guess())
    if not args.quiet:
        print "Found %d addresses" % len(addresses)
else:
    addresses = [int(addr, 0) for addr in args.address]
map_addr = int(args.mapping_base, 0)
if args.monoproc:
    cpu_count = lambda: 1
    Process = FakeProcess

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

# Add tasks
for address in addresses:
    queue.put(address)

# Add poison pill
for _ in xrange(cpu_c):
    queue.put(None)

for _ in xrange(cpu_c):
    p = Process(target=do_test, args=(args.filename, queue, machine,
                                      abicls, tests, map_addr,
                                      args.quiet, args.timeout, args.jitter,
                                      args.verbose))
    processes.append(p)
    p.start()

# Get results
queue.close()
queue.join_thread()
for p in processes:
    p.join()

if not queue.empty():
    raise RuntimeError("An error occured: queue is not empty")

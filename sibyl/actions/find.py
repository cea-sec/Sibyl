# This file is part of Sibyl.
# Copyright 2014 - 2017 Camille MOUGEY <camille.mougey@cea.fr>
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

import logging
from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container
from sibyl.testlauncher import TestLauncher
from sibyl.test import AVAILABLE_TESTS
from sibyl.abi import ABIS
from sibyl.heuristics.arch import ArchHeuristic
from sibyl.heuristics.func import FuncHeuristic

from sibyl.actions.action import Action


class FakeProcess(object):
    """Mock simulating Process API in monoprocess mode"""

    def __init__(self, target, args):
        self.target = target
        self.args = args

    def start(self, *args, **kwargs):
        self.target(*self.args)

    def join(self, *args, **kwargs):
        pass


class ActionFind(Action):
    """Action for actually launching function guessing"""

    _name_ = "find"
    _desc_ = "Function guesser"
    _args_ = [
        # Mandatory
        (["filename"], {"help": "File to load"}),
        (["abi"], {"help": "ABI to used. Available: " + \
                   # TODO: use available option of ArgumentParser
                 ",".join([x.__name__ for x in ABIS])}),
        (["address"], {"help": "Address of the function under test",
                     "nargs": "*"}),
        # Optional
        (["-a", "--architecture"], {"help": "Architecture used. Available: " + \
                                    ",".join(Machine.available_machine())}),
        (["-t", "--tests"], {"help": "Tests to run. Available: all," + \
                             ",".join(AVAILABLE_TESTS.keys()),
                             "nargs": "*",
                             "default": ["all"]}),
        (["-v", "--verbose"], {"help": "Verbose mode",
                               "action": "store_true"}),
        (["-q", "--quiet"], {"help": "Display only results",
                             "action": "store_true"}),
        (["-i", "--timeout"], {"help": "Test timeout (in seconds)",
                               "default": 2,
                               "type": int}),
        (["-m", "--mapping-base"], {"help": "Binary mapping address",
                                    "default": "0"}),
        (["-j", "--jitter"], {"help": """Jitter engine.
Available: gcc (default), tcc, llvm, python, qemu""",
                              "default": "gcc"}),
        (["-p", "--monoproc"], {"help": "Launch tests in a single process",
                                "action": "store_true"}),
    ]

    def do_test(self, addr_queue):
        """Multi-process worker for launching on functions"""

        # Init components
        tl = TestLauncher(self.args.filename, self.machine, self.abicls,
                          self.tests, self.args.jitter, self.map_addr)
        if self.args.verbose:
            tl.logger.setLevel(logging.INFO)
        # Main loop
        while True:
            address = addr_queue.get()
            if address is None:
                break
            possible_funcs = tl.run(address, timeout_seconds=self.args.timeout)

            if possible_funcs:
                print "0x%08x : %s" % (address, ",".join(tl.possible_funcs))
            elif not self.args.quiet:
                print "No candidate found for 0x%08x" % address

    def run(self):
        """Launch search"""

        # Import multiprocessing only when required
        from multiprocessing import cpu_count, Queue, Process

        # Parse args
        architecture = False
        if self.args.architecture:
            architecture = self.args.architecture
        else:
            with open(self.args.filename) as fdesc:
                architecture = ArchHeuristic(fdesc).guess()
            if not architecture:
                raise ValueError("Unable to recognize the architecture, please specify it")
            if not self.args.quiet:
                print "Guessed architecture: %s" % architecture

        self.machine = Machine(architecture)
        if not self.args.address:
            if not self.args.quiet:
                print "No function address provided, start guessing"

            cont = Container.from_stream(open(self.args.filename))
            fh = FuncHeuristic(cont, self.machine)
            addresses = list(fh.guess())
            if not self.args.quiet:
                print "Found %d addresses" % len(addresses)
        else:
            addresses = [int(addr, 0) for addr in self.args.address]
        self.map_addr = int(self.args.mapping_base, 0)
        if self.args.monoproc:
            cpu_count = lambda: 1
            Process = FakeProcess

        for abicls in ABIS:
            if self.args.abi == abicls.__name__:
                break
        else:
            raise ValueError("Unknown ABI name: %s" % self.args.abi)
        self.abicls = abicls

        self.tests = []
        for tname, tcases in AVAILABLE_TESTS.items():
            if "all" in self.args.tests or tname in self.args.tests:
                self.tests += tcases

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
            p = Process(target=self.do_test, args=(queue,))
            processes.append(p)
            p.start()

        # Get results
        queue.close()
        queue.join_thread()
        for p in processes:
            p.join()

        if not queue.empty():
            raise RuntimeError("An error occured: queue is not empty")

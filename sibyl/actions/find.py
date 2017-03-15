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
import json
import sys
from collections import namedtuple

from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container

from sibyl.config import config
from sibyl.testlauncher import TestLauncher
from sibyl.abi import ABIS
from sibyl.heuristics.arch import ArchHeuristic
from sibyl.commons import print_table
from sibyl.actions.action import Action

# Message exchanged with workers
MessageTaskDone = namedtuple("MessageTaskDone", ["address", "results"])


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
        (["address"], {"help": "Address of the function under test. Allowed" \
                       " formats are '112233', '0x11223344', '-' for stdin " \
                       "and 'filename' for a file containing addresses",
                       "nargs": "+"}),
        # Optional
        (["-a", "--architecture"], {"help": "Target architecture",
                                    "choices": Machine.available_machine()}),
        (["-b", "--abi"], {"help": "ABI to use",
                           "choices": [x.__name__ for x in ABIS]}),
        (["-t", "--tests"], {"help": "Tests to run (default is all)",
                             "choices": config.available_tests.keys(),
                             "default": [],
                             "action": "append"}),
        (["-v", "--verbose"], {"help": "Verbose mode (use multiple time to " \
                               "increase verbosity level)",
                               "action": "count",
                               "default": 0}),
        (["-i", "--timeout"], {"help": "Test timeout (in seconds)",
                               "default": 2,
                               "type": int}),
        (["-m", "--mapping-base"], {"help": "Binary mapping address",
                                    "default": "0"}),
        (["-j", "--jitter"], {"help": "Jitter engine (override default one)",
                              "choices": ["gcc", "tcc", "llvm", "python", "qemu"],
                              "default": config.jit_engine}),
        (["-p", "--monoproc"], {"help": "Launch tests in a single process " \
                                "(mainly for debug purpose)",
                                "action": "store_true"}),
        (["-o", "--output-format"], {"help": "Output format",
                                     "choices": ["JSON", "human"],
                                     "default": "human"}),
    ]

    def do_test(self, addr_queue, msg_queue):
        """Multi-process worker for launching on functions"""

        # Init components
        tl = TestLauncher(self.args.filename, self.machine, self.abicls,
                          self.tests, self.args.jitter, self.map_addr)

        # Activatate logging INFO on at least -vv
        if self.args.verbose > 1:
            tl.logger.setLevel(logging.INFO)

        # Main loop
        while True:
            address = addr_queue.get()
            if address is None:
                break
            possible_funcs = tl.run(address, timeout_seconds=self.args.timeout)
            msg_queue.put(MessageTaskDone(address, possible_funcs))

        # Signal to master the end
        msg_queue.put(None)

    def run(self):
        """Launch search"""

        # Import multiprocessing only when required
        from multiprocessing import cpu_count, Queue, Process

        # Parse args
        self.map_addr = int(self.args.mapping_base, 0)
        if self.args.monoproc:
            cpu_count = lambda: 1
            Process = FakeProcess

        # Architecture
        architecture = False
        if self.args.architecture:
            architecture = self.args.architecture
        else:
            with open(self.args.filename) as fdesc:
                architecture = ArchHeuristic(fdesc).guess()
            if not architecture:
                raise ValueError("Unable to recognize the architecture, please specify it")
            if self.args.verbose > 0:
                print "Guessed architecture: %s" % architecture

        self.machine = Machine(architecture)
        if not self.args.address:
            print "No function address provided. Use 'sibyl func' to discover addresses"
            exit(-1)
        addresses = []
        for address in self.args.address:
            if address == '-':
                # Use stdin
                addresses = [int(addr, 0) for addr in sys.stdin]
                continue
            try:
                addresses.append(int(address, 0))
            except ValueError:
                # File
                addresses = [int(addr, 0) for addr in open(address)]
        if self.args.verbose > 0:
            print "Found %d addresses" % len(addresses)


        # Select ABI
        if self.args.abi is None:
            candidates = set(abicls for abicls in ABIS
                             if architecture in abicls.arch)
            if not candidates:
                raise ValueError("No ABI for architecture %s" % architecture)
            if len(candidates) > 1:
                print "Please specify the ABI:"
                print "\t" + "\n\t".join(cand.__name__ for cand in candidates)
                exit(0)
            abicls = candidates.pop()
        else:
            for abicls in ABIS:
                if self.args.abi == abicls.__name__:
                    break
            else:
                raise ValueError("Unknown ABI name: %s" % self.args.abi)
        self.abicls = abicls

        # Select Test set
        self.tests = []
        for tname, tcases in config.available_tests.iteritems():
            if not self.args.tests or tname in self.args.tests:
                self.tests += tcases
        if self.args.verbose > 0:
            print "Found %d test cases" % len(self.tests)

        # Prepare multiprocess
        cpu_c = cpu_count()
        addr_queue = Queue()
        msg_queue = Queue()
        processes = []

        # Add tasks
        for address in addresses:
            addr_queue.put(address)

        # Add poison pill
        for _ in xrange(cpu_c):
            addr_queue.put(None)

        # Launch workers
        for _ in xrange(cpu_c):
            p = Process(target=self.do_test, args=(addr_queue, msg_queue))
            processes.append(p)
            p.start()
        addr_queue.close()

        # Get results
        nb_poison = 0
        results = {} # address -> possible functions
        while nb_poison < cpu_c:
            msg = msg_queue.get()
            # Poison pill
            if msg is None:
                nb_poison += 1
                continue

            # Save result
            results[msg.address] = msg.results

            # Display status if needed
            if self.args.verbose > 0:
                sys.stdout.write("\r%d / %d" % (len(results), len(addresses)))
                sys.stdout.flush()
            if msg.results and self.args.output_format == "human":
                prefix = ""
                if self.args.verbose > 0:
                    prefix = "\r"
                print prefix + "0x%08x : %s" % (msg.address, ",".join(msg.results))

        # Clean output if needed
        if self.args.verbose > 0:
            print ""

        # End connexions
        msg_queue.close()
        msg_queue.join_thread()

        addr_queue.join_thread()
        for p in processes:
            p.join()

        if not addr_queue.empty():
            raise RuntimeError("An error occured: queue is not empty")

        # Print final results
        if self.args.output_format == "JSON":
            # Expand results to always have the same key, and address as int
            print json.dumps({"information": {"total_count": len(addresses),
                                              "test_cases": len(self.tests)},
                              "results": [{"address": addr, "functions": result}
                                          for addr, result in results.iteritems()],
            })
        elif self.args.output_format == "human" and self.args.verbose > 0:
            # Summarize results
            title = ["Address", "Candidates"]
            ligs = [title]

            ligs += [["0x%08x" % addr, ",".join(result)]
                     for addr, result in sorted(results.iteritems(),
                                                key=lambda x: x[0])
                     if result]
            print_table(ligs, separator="| ")



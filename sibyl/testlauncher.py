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

"""This module provides a way to prepare and launch Sibyl tests on a binary"""


import time
import signal
import logging
from miasm2.analysis.binary import Container

from sibyl.commons import init_logger, TimeoutException, END_ADDR
from sibyl.engine import QEMUEngine, MiasmEngine

class TestLauncher(object):
    "Launch tests for a function and report matching candidates"

    def __init__(self, filename, machine, abicls, tests_cls, engine_name,
                 map_addr=0):

        # Logging facilities
        self.logger = init_logger("testlauncher")

        # Prepare JiT engine
        self.machine = machine
        self.init_engine(engine_name)

        # Init and snapshot VM
        self.load_vm(filename, map_addr)
        self.snapshot = self.engine.take_snapshot()

        # Init tests
        self.init_abi(abicls)
        self.initialize_tests(tests_cls)

    def initialize_tests(self, tests_cls):
        tests = []
        for testcls in tests_cls:
            tests.append(testcls(self.jitter, self.abi))
        self.tests = tests

    def load_vm(self, filename, map_addr):
        self.ctr = Container.from_stream(open(filename), vm=self.jitter.vm,
                                         addr=map_addr)
        self.jitter.cpu.init_regs()
        self.jitter.init_stack()

    def init_engine(self, engine_name):
        if engine_name == "qemu":
            self.engine = QEMUEngine(self.machine)
        else:
            self.engine = MiasmEngine(self.machine, engine_name)
        self.jitter = self.engine.jitter

    def init_abi(self, abicls):
        ira = self.machine.ira()
        self.abi = abicls(self.jitter, ira)

    def launch_tests(self, test, address, timeout_seconds=0):
        # Variables to remind between two "launch_test"
        self._temp_reset_mem = True

        # Reset between functions
        test.reset_full()

        # Callback to launch
        def launch_test(init, check):
            """Launch a test associated with @init, @check"""

            # Reset state
            self.engine.restore_snapshot(memory=self._temp_reset_mem)
            self.abi.reset()
            test.reset()

            # Prepare VM
            init(test)
            self.abi.prepare_call(ret_addr=END_ADDR)

            # Run code
            status = self.engine.run(address, timeout_seconds)
            if not status:
                # Early quit
                self._temp_reset_mem = True
                return False

            # Check result
            to_ret = check(test)

            # Update flags
            self._temp_reset_mem = test.reset_mem

            return to_ret

        # Launch subtests
        status = test.tests.execute(launch_test)
        if status:
            self._possible_funcs.append(test.func)

    def run(self, address, *args, **kwargs):
        self._possible_funcs = []

        nb_tests = len(self.tests)
        self.logger.info("Launch tests (%d available functions)" % (nb_tests))
        starttime = time.time()

        self.engine.prepare_run()
        for test in self.tests:
            self.launch_tests(test, address, *args, **kwargs)

        self.logger.info("Total time: %.4f seconds" % (time.time() - starttime))
        return self._possible_funcs

    def get_possible_funcs(self):
        return self._possible_funcs
    possible_funcs = property(get_possible_funcs)

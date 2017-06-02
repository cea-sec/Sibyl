'''
This module gives a tracer that uses pin (3.0-76991-gcc-linux) to run the program
'''

import tempfile
import os

import sibyl
from sibyl.learn.tracer.tracer import Tracer
from sibyl.learn.trace import Trace, Snapshot
from sibyl.config import config


class TracerPin(Tracer):

    '''Tracer that uses pin'''

    def do_trace(self):
        '''Run the pintool and construct the trace from the pintool output file'''

        tmpName = self.__run_pin_cmd()
        return self.__parse_pin_output_file(open(tmpName))

    def __run_pin_cmd(self):
        '''Run the pintool'''

        tmp = tempfile.NamedTemporaryFile(suffix=".trace", delete=False)
        tmpName = tmp.name
        tmp.close()

        pintool = config.pin_tracer
        if not pintool or not os.path.exists(pintool):
            raise RuntimeError("Unable to found the PIN-tool at '%s'. Please "\
                               "update the associated configuration" % pintool)

        cmd = [os.path.join(config.pin_root, "pin"), "-ifeellucky", "-t",
               pintool, "-a", "0x%x" % self.address, "-o", tmpName,
               "--", self.program]
        self._run_cmd(cmd)

        return tmpName

    def __parse_pin_output_file(self, traceFile):
        '''Parse the file created by the pintool in order to construct the trace'''

        trace = Trace()

        # Statefull elements
        started = False
        current_image_name = None

        # State machine for parsing
        for line in traceFile:
            infos = line.strip().split(' ')
            entry_type = infos[0]


            # Image loaded in memory
            # IMG <img_name>
            if entry_type == "IMG":
                img_name = infos[1]
                current_image_name = img_name
                continue

            # Symbol entry
            # S <symbol_addr> <symbol_name>
            elif entry_type == 'S':
                assert current_image_name is not None
                symbol_name = infos[2]
                symbol_addr = int(infos[1], 16)
                trace.add_symbol(current_image_name, symbol_name, symbol_addr)
                continue

            values = [int(v, 16) for v in infos[1:]]

            # Start of the learned function
            # Fields are registers value
            if entry_type == 'I':
                if not started:
                    started = True
                    current_snapshot = Snapshot(self.abicls, self.machine)

                for i, reg_name in enumerate(self.reg_list):
                    current_snapshot.add_input_register(reg_name, values[i])

            # Executed instructions address
            elif entry_type == '@':
                if started:
                    current_snapshot.add_executed_instruction(values[0])

            # Memory read access
            # Fields are read address, read size and read value
            elif entry_type == 'R':
                if started:
                    current_snapshot.add_memory_read(
                        values[0], values[1], values[2])

            # Memory write access
            # Fields are writen address, writen size and writen value
            elif entry_type == 'W':
                if started:
                    current_snapshot.add_memory_write(
                        values[0], values[1], values[2])

            # End of the learned function
            # Field are register value
            elif entry_type == 'O':
                if started:
                    for i, reg_name in enumerate(self.reg_list):
                        current_snapshot.add_output_register(
                            reg_name, values[i])

                    # The learned function execution is over
                    # Snapshot can be added to the trace
                    started = False
                    yield current_snapshot

            # Call to a function
            # CALL <caller_addr> <stack pointer>
            elif entry_type == "CALL":
                current_snapshot.add_call(values[0], values[1])

            # Return from a function
            # RET <ret_addr> <stack pointer after> <ret value>
            elif entry_type == "RET":
                current_snapshot.add_ret(values[0], values[1], values[2])

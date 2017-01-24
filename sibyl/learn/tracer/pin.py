'''
This module gives a tracer that uses pin (3.0-76991-gcc-linux) to run the program
'''

import tempfile
import os

import sibyl
from sibyl.learn.tracer.tracer import Tracer
from sibyl.learn.trace import Trace, Snapshot


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

        pin_root = os.environ.get("PIN_ROOT", "")

        cmd = [os.path.join(pin_root, "pin"), "-ifeellucky", "-t", os.path.dirname(sibyl.__path__[0]) + "/ext/pin_tracer/pin_tracer.so", "-a", "0x%x" % self.address, "-o", tmpName, "--", "./" + self.program]
        self._run_cmd(cmd)

        return tmpName

    def __parse_pin_output_file(self, traceFile):
        '''Parse the file created by the pintool in order to construct the trace'''

        # Read the begin of file until the first blank line
        # This correspond to the segment enumeration
        segments = []
        for line in traceFile:
            if line == "\n":
                break

            # Each line begins with the bound of the segment,
            # separated by a '-' and followed by a white space
            segments += [tuple([int(addr, 16)
                               for addr in line.split(' ')[0].split('-')])]

        trace = Trace()
        started = False
        for line in traceFile:
            infos = line.strip().split(' ')
            first_char = infos[0]
            values = [int(v, 16) for v in infos[1:]]

            # Start of the learned function
            # Fields are registers value
            if first_char == 'I':
                if not started:
                    started = True
                    current_snapshot = Snapshot(segments, self.abicls, self.machine)

                for i, reg_name in enumerate(self.reg_list):
                    current_snapshot.add_input_register(reg_name, values[i])

            # Executed instructions address
            elif first_char == '@':
                if started:
                    current_snapshot.add_executed_instruction(values[0])

            # Memory read access
            # Fields are read address, read size and read value
            elif first_char == 'R':
                if started:
                    current_snapshot.add_memory_read(
                        values[0], values[1], values[2])

            # Memory write access
            # Fields are writen address, writen size and writen value
            elif first_char == 'W':
                if started:
                    current_snapshot.add_memory_write(
                        values[0], values[1], values[2])

            # End of the learned function
            # Field are register value
            elif first_char == 'O':
                if started:
                    for i, reg_name in enumerate(self.reg_list):
                        current_snapshot.add_output_register(
                            reg_name, values[i])

                    # The learned function execution is over
                    # Snapshot can be added to the trace
                    started = False
                    trace.append(current_snapshot)

        return trace

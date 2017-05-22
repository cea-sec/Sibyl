from collections import namedtuple
import struct

from sibyl.learn.replay import Replay
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.core.graph import DiGraph
from miasm2.analysis.machine import Machine


class Trace(list):
    '''List of snapshot'''

    def __init__(self, *args, **kwargs):
        super(Trace, self).__init__(*args, **kwargs)
        # Image name -> symbol name -> in-memory address
        self.symbols = {}

    def add_symbol(self, image_name, symbol_name, symbol_addr):
        """Add the symbol:addr from the image image_name"""
        self.symbols.setdefault(image_name, dict())[symbol_name] = symbol_addr

    def symbol_to_address(self, symbol_name, image_name=None):
        """Get the corresponding in-memory address from a symbol, or None if not found
        If image_name is set, restrict to the given image only
        """
        if image_name is not None:
            return self.symbols[image_name].get(symbol_name, None)

        found = None
        for symbols in self.symbols.itervalues():
            if symbol_name in symbols:
                if found is not None:
                    raise ValueError("At least two symbols for this symbol")
                found = symbols[symbol_name]
        return found

    def clean(self):
        '''Try to remove all implementation dependant elements from the trace'''

        clean_trace = Trace()
        for snapshot in self:
            clean_trace.append(snapshot.clean())
        clean_trace.symbols = self.symbols.copy()
        return clean_trace


class MemoryAccess(object):
    '''Represent a memory block, read or write by the learned function'''

    def __init__(self, size, data, access):

        self.size = size
        self.data = data
        self.access = access

    def __str__(self):
        str_access = ""
        if self.access & PAGE_READ:
            str_access += "READ"
        if self.access & PAGE_WRITE:
            if str_access != "":
                str_access += " "
            str_access += "WRITE"

        return "size: " + str(self.size) + ", data: " + repr(self.data) + ", access: " + str_access

    def __repr__(self):
        return "<" + str(self) + ">"


class Snapshot(object):

    @classmethod
    def get_byte(cls, value, byte):
        '''Return the byte @byte of the value'''
        return struct.pack('@B', (value & (0xFF << (8 * byte))) >> (8 * byte))

    @classmethod
    def unpack_ptr(cls, value):
        return struct.unpack('@P', value)[0]

    def __init__(self, abicls, machine):
        self.abicls = abicls

        self.input_reg = {}
        self.output_reg = {}

        self._previous_addr = 0
        self._current_addr = 0
        self._instr_count = 0
        self._pending_call = []
        # Function addr -> list of information on calls
        self.function_calls = {}
        self.paths = DiGraph()

        self.in_memory = {}
        self.out_memory = {}

        self._ira = Machine(machine).ira()
        self._ptr_size = self._ira.sizeof_pointer()/8
        self.sp = self._ira.sp.name

    def add_input_register(self, reg_name, reg_value):
        self.input_reg[reg_name] = reg_value

    def add_output_register(self, reg_name, reg_value):
        self.output_reg[reg_name] = reg_value

    def add_memory_read(self, address, size, value):
        for i in xrange(size):
            self.out_memory[address + i] = MemoryAccess(1,
                                                        Snapshot.get_byte(value, i),
                                                        0,  # Output access never used
            )

            if address + i not in self.in_memory:
                self.in_memory[address + i] = MemoryAccess(1,
                                                           Snapshot.get_byte(value, i),
                                                           PAGE_READ,
                )

            else:
                self.in_memory[address + i].access |= PAGE_READ

    def add_memory_write(self, address, size, value):
        for i in xrange(size):
            self.out_memory[address + i] = MemoryAccess(1,
                                                        Snapshot.get_byte(value, i),
                                                        0,  # Output access never used
            )

            if address + i not in self.in_memory:
                self.in_memory[address + i] = MemoryAccess(1,
                                                           "\x00",
                                                           # The value is
                                                           # not used by the
                                                           # test
                                                           PAGE_WRITE,
                )

            else:
                self.in_memory[address + i].access |= PAGE_WRITE

    def add_executed_instruction(self, address):
        '''
        Function called to signal that the address has been executed
        This function has to be called in the order of their executed instruction
        Else paths can not be updated correctly
        '''
        self._previous_addr = self._current_addr
        self._current_addr = address
        self.paths.add_uniq_edge(self._previous_addr, self._current_addr)
        self._instr_count += 1

        # Resolve call destination
        if (self._pending_call and
            self._previous_addr == self._pending_call[-1]["caller_addr"]):
            info = self._pending_call[-1]
            info["dest"] = address
            info["beg"] = self._instr_count


    def add_call(self, caller_addr, stack_ptr):
        '''
        Function call, target is not determined yet
        called *before* instruction execution
        '''
        info = {"stack_ptr": stack_ptr,
                "caller_addr": caller_addr,
        }
        self._pending_call.append(info)

    def add_ret(self, ret_addr, stack_ptr, value):
        '''
        Function ret
        called *after* instruction execution
        '''
        # Find corresponding call
        assert self._pending_call
        assert self._pending_call[-1]["stack_ptr"] >= stack_ptr

        info = self._pending_call.pop()
        info["end"] = self._instr_count
        info["ret"] = value
        current_interval = self.function_calls.setdefault(info["dest"],
                                                          list()).append(info)

    def clean(self):
        """Clean the snapshot for further uses"""

        self.agglomerate_memory(self.in_memory)
        self.agglomerate_memory(self.out_memory)

    def agglomerate_memory(self, mem):
        '''
        Assuming @mem is only composed of non-overlapping block
        this function agglomerate contiguous blocks having the same access right
        '''
        for addr in sorted(mem.keys()):

            # if the addr is not already deleted
            if addr in mem:

                end_addr = addr + mem[addr].size
                while end_addr in mem:
                    cur_mem = mem[addr]
                    next_mem = mem[end_addr]

                    # If access change, do not agglomerate
                    if cur_mem.access != next_mem.access:
                        break

                    cur_mem.size += next_mem.size
                    cur_mem.data += next_mem.data
                    del mem[end_addr]
                    end_addr += next_mem.size

from collections import namedtuple
import struct

from sibyl.learn.replay import Replay
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.core.graph import DiGraph
from miasm2.analysis.machine import Machine

class Trace(list):
    '''List of snapshot'''

    def clean(self):
        '''Try to remove all implementation dependant elements from the trace'''

        clean_trace = Trace()

        for snapshot in self:

            clean_trace.append(snapshot.clean())

        return clean_trace


class MemoryAccess(object):
    '''Represent a memory bloc, read or write by the learned function'''

    def __init__(self, size, data, access, segment):

        self.size = size
        self.data = data
        self.access = access
        self.segment = segment

    def __str__(self):
        str_access = ""
        if self.access & PAGE_READ:
            str_access += "READ"
        if self.access & PAGE_WRITE:
            if str_access != "":
                str_access += " "
            str_access += "WRITE"

        return "size: " + str(self.size) + ", data: " + repr(self.data) + ", segment: " + str(self.segment) + ", access: " + str_access

    def __repr__(self):
        return "<" + str(self) + ">"


class Reference(object):
    '''Represent a reference by the in/out memory/register to memory'''

    def __init__(self, segment, size):

        self.in_reg = []
        self.out_reg = []
        self.in_mem = []
        self.out_mem = []

        self.segment = segment
        self.size = size

    def __str__(self):
        res = ""
        for k in ["size", "in_reg", "out_reg", "in_mem", "out_mem", "segment"]:
            if res != "":
                res += ", "
            res += k + ": " +str(getattr(self, k))
        return res

    def __repr__(self):
        return "<" + str(self) + ">"

    def add_ref(self, name, value_type):
        getattr(self, value_type).append(name)

    def addresses_to_segment_offset(self, segments):
        '''Convert the absolute addresses to segment base/offset addresses'''
        seg_idx = {}
        for addr in self.out_mem:
            for i, seg in enumerate(segments):
                if seg[0] < addr < seg[1]:
                    seg_idx[addr] = i
                    break
        for addr in self.in_mem:
            for i, seg in enumerate(segments):
                if seg[0] < addr < seg[1]:
                    seg_idx[addr] = i
                    break

        self.in_mem = [(addr - segments[seg_idx[addr]][0],  seg_idx[addr])
                       for addr in self.in_mem]
        self.out_mem = [(addr - segments[seg_idx[addr]][0], seg_idx[addr])
                        for addr in self.out_mem]


class Snapshot(object):

    clobbered_regs = ["RCX", "RDX", "RSI", "RDI", "RBP", "R8", "R9", "R10", "R11", "RBP"]

    @classmethod
    def get_byte(cls, value, byte):
        '''Return the byte @byte of the value'''
        return struct.pack('@B', (value & (0xFF << (8 * byte))) >> (8 * byte))

    @classmethod
    def unpack_ptr(cls, value):
        return struct.unpack('@P', value)[0]

    def __init__(self, segments, abicls, machine):
        self.segments = segments
        self.abicls = abicls

        self.input_reg = {}
        self.output_reg = {}

        self._previous_addr = 0
        self._current_addr = 0
        self.paths = DiGraph()

        self.in_memory = {}
        self.out_memory = {}

        self.refs = {}

        self._ira = Machine(machine).ira()
        self._ptr_size = self._ira.sizeof_pointer()/8
        self.sp = self._ira.sp.name

    def _get_segment_index_by_addr(self, addr):
        for i, seg in enumerate(self.segments):
            if seg[0] <= addr < seg[1]:
                return i
        raise ValueError("Segment not found for addr %x" % addr)

    def add_input_register(self, reg_name, reg_value):
        self.input_reg[reg_name] = reg_value

    def add_output_register(self, reg_name, reg_value):
        self.output_reg[reg_name] = reg_value

    def add_memory_read(self, address, size, value):
        for i in xrange(size):
            self.out_memory[address + i] = MemoryAccess(1,
                                                        Snapshot.get_byte(value, i),
                                                        0,  # Output access never used
                                                        self._get_segment_index_by_addr(address + i))
            
            if address + i not in self.in_memory:
                self.in_memory[address + i] = MemoryAccess(1,
                                                           Snapshot.get_byte(value, i),
                                                           PAGE_READ,
                                                           self._get_segment_index_by_addr(address + i))

            else:
                self.in_memory[address + i].access |= PAGE_READ

    def add_memory_write(self, address, size, value):
        for i in xrange(size):
            self.out_memory[address + i] = MemoryAccess(1,
                                                        Snapshot.get_byte(value, i),
                                                        0,  # Output access never used
                                                        self._get_segment_index_by_addr(address + i))

            if address + i not in self.in_memory:
                self.in_memory[address + i] = MemoryAccess(1,
                                                           "\x00",
                                                           # The value is
                                                           # not used by the
                                                           # test
                                                           PAGE_WRITE,
                                                           self._get_segment_index_by_addr(address + i))

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

    def clean(self):
        '''Try to remove all implementation dependant elements from the trace'''

        # do not record stack frame on output because the use of this
        # memory aera is implementation dependant
        self.remove_stack_frame()

        self.agglomerate_memory(self.in_memory)
        self.agglomerate_memory(self.out_memory)

        self.remove_clobbered_registers()

        self.find_references_to_input_memory()

        self.addresses_to_segment_offset()

        self.remap_segment()

    def remove_stack_frame(self):
        '''
        Remove stack frame from the memory.
        Memory is considered fragmented ie. composed of one bit sized blocks
        '''

        SP = self.input_reg[self.sp]
        
        stack_seg_idx = self._get_segment_index_by_addr(SP)
        top_stack = self.segments[stack_seg_idx][0]
        
        for mem in (self.out_memory, self.in_memory):
            for addr in mem.keys():
                if top_stack < addr < SP + self._ptr_size:
                    # addr in stack frame
                    del mem[addr]

    def agglomerate_memory(self, mem):
        '''
        Assuming @mem is only composed of 1 byte sized bloc,
        this function agglomerate contiguous blocs that are in the same segment and have the same access right
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

                    # If segment change, do not agglomerate
                    if cur_mem.segment != next_mem.segment:
                        break

                    cur_mem.size += next_mem.size
                    cur_mem.data += next_mem.data
                    del mem[end_addr]
                    end_addr += next_mem.size

    def remove_clobbered_registers(self):
        '''Remove clobbered registers from the output memory'''
        self.output_reg = {reg: v for reg, v in self.output_reg.iteritems() if reg not in self.clobbered_regs}

    def find_references_to_input_memory(self):
        '''
        Populate the refs attribut
        This attribut should contain all the references (pointers) present in memory and registers
        '''

        # The heuristic used to detect is: if a memory bloc or a
        # register hold a value that is an address used in the input
        # memory, then this bloc or register is a reference

        # To determine the size of the referenced memory, the strategy
        # is a greedy one. All the memory that follow the referenced
        # address is considered as part of the reference.

        for reg, value in self.input_reg.iteritems():
            if reg != self.sp:
                self.update_references(reg, value, "in_reg")
        for reg, value in self.output_reg.iteritems():
            if reg != self.sp:
                self.update_references(reg, value, "out_reg")

        ptr_size = self._ptr_size

        for addr, mem in self.in_memory.iteritems():
            data = mem.data
            for i in xrange(len(data) - ptr_size + 1):
                self.update_references(
                    addr + i, self.unpack_ptr(data[i:ptr_size + i]), "in_mem")

        for addr, mem in self.out_memory.iteritems():
            data = mem.data
            for i in xrange(len(data) - ptr_size + 1):
                self.update_references(
                    addr + i, self.unpack_ptr(data[i:ptr_size + i]), "out_mem")

        self.add_rsp_ref_to_stack()

        # If two references are contiguous, then the first reference
        # size will cover the second one. The following code remove
        # these kind of overlaps
        for ref in sorted(self.refs):
            for ref2 in self.refs:
                if ref < ref2 < ref + self.refs[ref].size:
                    self.refs[ref].size -= self.refs[ref2].size

    
                    
    def add_rsp_ref_to_stack(self):
        in_RSP = self.input_reg[self.sp]
        out_RSP = self.output_reg[self.sp]

        stack_seg_idx = self._get_segment_index_by_addr(in_RSP)

        if in_RSP not in self.refs:
            self.refs[in_RSP] = Reference(stack_seg_idx, self._ptr_size)
        self.refs[in_RSP].add_ref("RSP", "in_reg")
        if out_RSP not in self.refs:
            self.refs[out_RSP] = Reference(stack_seg_idx, self._ptr_size)
        self.refs[out_RSP].add_ref("RSP", "out_reg")

    def update_references(self, name, value, value_type):
        in_mem = self.in_memory
        for addr, mem in in_mem.iteritems():
            if addr <= value < addr + mem.size:

                if value not in self.refs:
                    size = mem.size - (value - addr)
                    while addr + size in in_mem:
                        size += in_mem[addr + size].size

                    self.refs[value] = Reference(mem.segment, size)

                self.refs[value].add_ref(name, value_type)

    def addresses_to_segment_offset(self):
        '''Convert the absolute addresses to segment base/offset addresses'''

        self._addresses_to_segment_offset(self.in_memory)
        self._addresses_to_segment_offset(self.out_memory)
        self._addresses_to_segment_offset(self.refs)

        for ref in self.refs.itervalues():
            ref.addresses_to_segment_offset(self.segments)

    def _addresses_to_segment_offset(self, mem):
        for addr in mem.keys():
            seg_idx = mem[addr].segment
            segment_base = self.segments[seg_idx][0]
            mem[(addr - segment_base, seg_idx)] = mem.pop(addr)

    def isRegInInputRef(self, reg):
        for addr, ref in self.refs.iteritems():
            if reg in ref.in_reg:
                return addr
        return None

    def isRegInOutputRef(self, reg):
        for addr, ref in self.refs.iteritems():
            if reg in ref.out_reg:
                return addr
        return None

    def isMemInRef(self, mem):
        for addr, ref in self.refs.iteritems():
            if mem in ref.in_mem:
                return addr
        return None

    def _updateSegmentInDict(self, dic, seg_mapping):
        '''
        Change the segment indexes used by dic according to the new segment mapping seg_mapping
        '''
        for (offset, seg) in dic.keys():
            new_seg_nb = seg_mapping[seg]
            dic[(offset, seg)].segment = new_seg_nb
            dic[(offset, new_seg_nb)] = dic.pop((offset, seg))

    def __update_mapping_struct(self, memory, seg_mapping, seg_borne):
        '''
        Add the segments used in mem to the segment mapping (seg_mapping) and update the bornes (seg_borne)
        Instance variable "__nb_seg" should be initialized to 0 before the fisrt call to this function
        '''

        for (offset, seg), mem in memory.iteritems():
            if seg in seg_mapping:
                (minAddr, maxAddr) = seg_borne[seg]
                seg_borne[seg] = (
                    min(minAddr, offset), max(maxAddr, offset + mem.size))
            else:
                seg_borne[seg] = (offset, offset + mem.size)
                seg_mapping[seg] = self.__nb_seg
                self.__nb_seg += 1
        return self.__nb_seg

    def remap_segment(self):
        '''
        Reduce the self.segment structure to be minimalist (only segments used by in and out memory)
        '''
        seg_mapping = {}
        seg_borne = {}

        
        # Get the new segment mapping and corresponding sizes
        self.__nb_seg = 0
        self.__update_mapping_struct(self.in_memory, seg_mapping, seg_borne)
        self.__update_mapping_struct(self.out_memory, seg_mapping, seg_borne)
        self.__update_mapping_struct(self.refs, seg_mapping, seg_borne)
        

        seg_size = [0] * len(seg_mapping)
        for no_seg, borne in seg_borne.iteritems():
            seg_size[seg_mapping[no_seg]] = borne[1] - borne[0]


        # Use the new mapping in snapshot's dictionaries
        self._updateSegmentInDict(self.in_memory, seg_mapping)
        self._updateSegmentInDict(self.out_memory, seg_mapping)
        self._updateSegmentInDict(self.refs, seg_mapping)

        # Use the new mapping inside reference structure
        for ref in self.refs.itervalues():
            ref.in_mem = [(offset, seg_mapping[seg]) for (offset, seg) in ref.in_mem]
            ref.out_mem = [(offset, seg_mapping[seg]) for (offset, seg) in ref.out_mem]

        # Update self.segment according to the new mapping
        new_segments = [None] * len(seg_mapping)

        for seg, mapping in seg_mapping.iteritems():
            new_segments[mapping] = self.segments[seg]
        self.segments = new_segments
        
    def removeRegFromRef(self, reg):
        for ref in self.refs.itervalues():
            if reg in ref.in_reg:
                ref.in_reg.remove(reg)


    def removeMemFromRef(self, mem):
        for ref in self.refs.itervalues():
            if mem in ref.in_mem:
                ref.in_mem.remove(mem)


    def getStackSegment(self):
        for addr, ref in self.refs.iteritems():
            if self.sp in ref.in_reg:
                return addr


    # True: arg changed
    # False: arg not present
    def changeArg(self, number, newValue):

        # If argument is pass in a register
        if number < 7:
            reg_list = self.abicls.regs_mapping

            self.removeRegFromRef(reg_list[number - 1])

            try:
                self.input_reg[reg_list[number - 1]] = newValue
                del self.output_reg[reg_list[number - 1]]
            except KeyError:
                pass

            return True

        # If argument is pass on the stack
        else:
            (stackOff, stackSeg) = self.getStackSegment()

            argAddr = stackOff + 8 * (number - 7) + 8

            self.removeMemFromRef((argAddr, stackSeg))

            argFoundInSnapshot = False

            memO = self.out_memory
            memI = self.in_memory

            # Search for the arg adresse in the input memory$
            # If it is found, change its value
            for (offset, seg), mem in memI.iteritems():
                if seg == stackSeg:
                    if offset <= argAddr < offset + mem.size:
                        argFoundInSnapshot = True
                        data = mem.data
                        mem.data = data[0:argAddr - offset] + struct.pack(
                            '@P', newValue) + data[self._ptr_size + argAddr - offset:]
                        mem.size = len(mem.data)

            # If the argument is found, we remove it from the input memory
            # Because it will be allocated as an argument by the test itself
            if argFoundInSnapshot:
                for (offset, seg) in memO.keys():
                    addr = (offset, seg)
                    if seg == stackSeg:
                        if offset <= argAddr < offset + memO[addr].size:

                            if argAddr + self._ptr_size < offset + memO[addr].size:
                                memaccess =  MemoryAccess(memO[addr].size - (argAddr + self._ptr_size - offset),
                                                          memO[addr].data[argAddr - offset:argAddr + self._ptr_size - offset],
                                                          memO[addr].access,
                                                          stackSeg)
                                memO[(argAddr + self._ptr_size, stackSeg)] = memaccess

                            if argAddr > offset:
                                memO[addr].size = argAddr - offset

                            else:
                                del memO[addr]

            return argFoundInSnapshot

import struct

from miasm2.jitter.loader.elf import vm_load_elf
from miasm2.analysis.machine import Machine
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE, EXCEPT_ACCESS_VIOL, EXCEPT_DIV_BY_ZERO, EXCEPT_PRIV_INSN


class Replay(object):
    '''
    Class used to run a snapshot and check that it recognize or not a given function code
    Potential replay errors are stored in self.learnexception
    '''

    segsize = 0x10000000

    def __init__(self, filename, learned_addr, replayed_snapshot, abicls, machine):
        '''
        @filename: program to be used
        @learned_addr: addresse of the function to be tested
        @replayed_snapshot: snapshot to be used
        @abicls: ABI used by the program
        @machine: machine used by the program
        '''
        self.isFuncFound = False
        self.filename = filename
        self.learned_addr = learned_addr
        self.snapshot = replayed_snapshot
        self.replayexception = []
        self.abicls = abicls
        self.machine = Machine(machine)
        self.ira = self.machine.ira()
        self.ptr_size = self.ira.sizeof_pointer()/8

    def segToAddr(self, seg):
        return (seg + 1) * self.segsize

    def use_snapshot(self, jitter):
        '''Initilize the VM with the snapshot informations'''
        for reg, value in self.snapshot.input_reg.iteritems():
            setattr(jitter.cpu, reg, value)

        for (offset, segIdx), ref in self.snapshot.refs.iteritems():
            newValue = offset + self.segToAddr(segIdx)
            for reg in ref.in_reg:
                setattr(jitter.cpu, reg, newValue)

        jitter.vm.add_memory_page(
            jitter.cpu.RSP - 0x10000, PAGE_READ | PAGE_WRITE, "".join("\x00" for _ in xrange(0x10008)), "Stack")

        memI = self.snapshot.in_memory
        for (offset, segIdx), mem in memI.iteritems():
            addr = self.segToAddr(segIdx) + offset
            if not jitter.vm.is_mapped(addr, mem.size):
                jitter.vm.add_memory_page(addr, mem.access, mem.data)
            else:
                if jitter.vm.get_mem_access(addr) & 0b11 == mem.access & 0b11:
                    jitter.vm.set_mem(addr, mem.data)
                else:
                    # TODO memory page is already set but have not the
                    # same access right. However delete page does not
                    # exist
                    jitter.vm.set_mem(addr, mem.data)

        for (offset, segIdxRef), ref in self.snapshot.refs.iteritems():
            newValue = offset + self.segToAddr(segIdxRef)
            for (memOff, segIdx) in ref.in_mem:
                jitter.vm.set_mem(
                    memOff + self.segToAddr(segIdx), struct.pack('@P', newValue))

    def compare_snapshot(self, jitter):
        '''Compare the expected result with the real one to determine if the function is recognize or not'''
        func_found = True

        # Update register output ref before comparison
        for (offset, segIdx), ref in self.snapshot.refs.iteritems():
            newValue = offset + self.segToAddr(segIdx)
            for reg in ref.out_reg:
                self.snapshot.output_reg[reg] = newValue

            for (offR, segR) in ref.out_mem:
                for (offM, segM), mem in self.snapshot.out_memory.iteritems():
                    if segR == segM and offM <= offR < offM + mem.size:
                        mem.data = mem.data[:offR-offM] + struct.pack('@P', newValue) + mem.data[offR-offM+self.ptr_size:]

        for reg, value in self.snapshot.output_reg.iteritems():
            if value != getattr(jitter.cpu, reg):
                self.replayexception += ["output register %s wrong : %i expected, %i found" % (reg, value, getattr(jitter.cpu, reg))]
                func_found = False

        for (offset, segIdx), mem in self.snapshot.out_memory.iteritems():
            addr = self.segToAddr(segIdx)
            if mem.data != jitter.vm.get_mem(addr + offset, mem.size):
                self.replayexception += ["output memory wrong at 0x%x: %s expected, %s found" % (addr + offset, repr(mem.data), repr(jitter.vm.get_mem(addr + offset, mem.size)))]
                func_found = False

        return func_found

    def end_func(self, jitter):
        if jitter.vm.is_mapped(getattr(jitter.cpu, self.ira.ret_reg.name), 1):
            self.replayexception += ["return value might be a pointer"]

        self.isFuncFound = self.compare_snapshot(jitter)

        jitter.run = False
        return False

    def run(self):
        '''Main function that is in charge of running the test and return the result:
        true if the snapshot has recognized the function, false else.'''

        # Retrieve miasm tools
        jitter = self.machine.jitter("gcc")

        vm_load_elf(jitter.vm, open(self.filename, "rb").read())

        # Init segment
        jitter.ir_arch.do_stk_segm = True
        jitter.ir_arch.do_ds_segm = True
        jitter.ir_arch.do_str_segm = True
        jitter.ir_arch.do_all_segm = True

        FS_0_ADDR = 0x7ff70000
        jitter.cpu.FS = 0x4
        jitter.cpu.set_segm_base(jitter.cpu.FS, FS_0_ADDR)
        jitter.vm.add_memory_page(
            FS_0_ADDR + 0x28, PAGE_READ, "\x42\x42\x42\x42\x42\x42\x42\x42", "Stack canary FS[0x28]")

        # Init the jitter with the snapshot
        self.use_snapshot(jitter)
        
        # Change the return address to our breakpoint
        jitter.vm.set_mem(jitter.cpu.RSP, struct.pack("P", 0x1337BEEF))
        # jitter.push_uint64_t(0x1337BEEF)
        jitter.add_breakpoint(0x1337BEEF, self.end_func)

        # Run the execution
        jitter.init_run(self.learned_addr)
        
        try:
            jitter.continue_run()
            assert jitter.run == False
        except AssertionError:
            if jitter.vm.get_exception() & EXCEPT_ACCESS_VIOL:
                self.replayexception += ["access violation"]
            elif jitter.vm.get_exception() & EXCEPT_DIV_BY_ZERO:
                self.replayexception += ["division by zero"]
            elif jitter.vm.get_exception() & EXCEPT_PRIV_INSN:
                self.replayexception += ["execution of private instruction"]
            else:
                self.replayexception += ["exception no %i" % (jitter.vm.get_exception())]
            self.isFuncFound = False
            
        return self.isFuncFound

import struct

from miasm2.jitter.loader.elf import vm_load_elf
from miasm2.analysis.machine import Machine
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE, EXCEPT_ACCESS_VIOL, EXCEPT_DIV_BY_ZERO, EXCEPT_PRIV_INSN

from sibyl.config import config


class Replay(object):
    '''
    Class used to run a snapshot and check that it recognize or not a given function code
    Potential replay errors are stored in self.learnexception
    '''

    def __init__(self, testcreator, replayed_snapshot):
        '''
        @testcreator: TestCreator instance with associated information
        @replayed_snapshot: snapshot to be used
        '''
        self.isFuncFound = False
        self.filename = testcreator.program
        self.learned_addr = testcreator.address
        self.snapshot = replayed_snapshot
        self.replayexception = []
        self.abicls = testcreator.abicls
        self.machine = Machine(testcreator.machine)
        self.trace = testcreator.trace
        self.logger = testcreator.logger
        self.ira = self.machine.ira()
        self.ptr_size = self.ira.sizeof_pointer()/8

    def use_snapshot(self, jitter):
        '''Initilize the VM with the snapshot informations'''
        for reg, value in self.snapshot.input_reg.iteritems():
            setattr(jitter.cpu, reg, value)

        # Set values for input memory
        for addr, mem in self.snapshot.in_memory.iteritems():
            assert mem.access != 0
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

    def compare_snapshot(self, jitter):
        '''Compare the expected result with the real one to determine if the function is recognize or not'''
        func_found = True

        for reg, value in self.snapshot.output_reg.iteritems():
            if value != getattr(jitter.cpu, reg):
                self.replayexception += ["output register %s wrong : %i expected, %i found" % (reg, value, getattr(jitter.cpu, reg))]
                func_found = False

        for addr, mem in self.snapshot.out_memory.iteritems():
            self.logger.debug("Check @%s, %s bytes: %r", hex(addr), hex(mem.size), mem.data[:0x10])
            if mem.data != jitter.vm.get_mem(addr, mem.size):
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
        jitter = self.machine.jitter(config.miasm_engine)

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

        # Get the return address for our breakpoint
        return_addr = struct.unpack("P", jitter.vm.get_mem(jitter.cpu.RSP,
                                                           0x8))[0]
        jitter.add_breakpoint(return_addr, self.end_func)

        # Run the execution
        jitter.init_run(self.learned_addr)

        try:
            jitter.continue_run()
            assert jitter.run == False
        except AssertionError:
            # set the replayexception to the correct error
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

import signal

from sibyl.engine.engine import Engine
from sibyl.commons import TimeoutException, END_ADDR


class MiasmEngine(Engine):
    """Engine based on Miasm"""

    def __init__(self, machine, jit_engine):
        jitter = machine.jitter(jit_engine)
        jitter.set_breakpoint(END_ADDR, MiasmEngine._code_sentinelle)
        self.jitter = jitter

        # Signal handling
        #
        # Due to Python signal handling implementation, signals aren't handled
        # nor passed to Jitted code in case of registration with signal API
        if jit_engine == "python":
            signal.signal(signal.SIGALRM, MiasmEngine._timeout)
        elif jit_engine in ["llvm", "tcc", "gcc"]:
            self.jitter.vm.set_alarm()
        else:
            raise ValueError("Unknown engine: %s" % jit_engine)

        super(MiasmEngine, self).__init__(machine)


    @staticmethod
    def _code_sentinelle(jitter):
        jitter.run = False
        jitter.pc = 0
        return True

    @staticmethod
    def _timeout(signum, frame):
        raise TimeoutException()

    def run(self, address, timeout_seconds):
        self.jitter.init_run(address)

        try:
            signal.alarm(timeout_seconds)
            self.jitter.continue_run()
        except (AssertionError, RuntimeError, ValueError,
                KeyError, IndexError, TimeoutException) as _:
            return False
        except Exception as error:
            self.logger.exception(error)
            return False
        finally:
            signal.alarm(0)

        return True

    def restore_snapshot(self, memory=True):
        # Restore memory
        if memory:
            self.jitter.vm.reset_memory_page_pool()
            self.jitter.vm.reset_code_bloc_pool()
            for addr, metadata in self.vm_mem.iteritems():
                self.jitter.vm.add_memory_page(addr,
                                               metadata["access"],
                                               metadata["data"])

        # Restore registers
        self.jitter.cpu.init_regs()
        self.jitter.cpu.set_gpreg(self.vm_regs)

        # Reset intern elements
        self.jitter.vm.set_exception(0)
        self.jitter.cpu.set_exception(0)
        self.jitter.bs._atomic_mode = False

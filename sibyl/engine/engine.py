from sibyl.commons import init_logger


class Engine(object):
    """Wrapper on execution engine"""

    def __init__(self, machine):
        """Instanciate an Engine
        @machine: miasm2.analysis.machine:Machine instance"""
        self.logger = init_logger(self.__class__.__name__)

    def take_snapshot(self):
        self.vm_mem = self.jitter.vm.get_all_memory()
        self.vm_regs = self.jitter.cpu.get_gpreg()

    def restore_snapshot(self, memory=True):
        raise NotImplementedError("Abstract method")

    def run(self, address, timeout_seconds):
        raise NotImplementedError("Abstract method")

    def prepare_run(self):
        pass

    def restore_snapshot(self, memory=True):
        raise NotImplementedError("Abstract method")

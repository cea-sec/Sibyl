from miasm2.core.utils import pck32
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
try:
    import unicorn
    from unicorn.x86_const import *
except ImportError:
    unicorn = None

from sibyl.engine.engine import Engine
from sibyl.commons import END_ADDR


class UnexpectedStopException(Exception):
    """Exception to be called on timeouts"""
    pass

class QEMUEngine(Engine):
    """Engine based on QEMU, using unicorn as a wrapper"""

    def __init__(self, machine):
        if unicorn is None:
            raise ImportError("QEMU engine unavailable: 'unicorn' import error")

        self.jitter = UcWrapJitter()
        super(QEMUEngine, self).__init__(machine)


    def run(self, address, timeout_seconds):
        try:
            self.jitter.run(address, timeout_seconds)
        except UnexpectedStopException as _:
            return False
        except Exception as error:
            self.logger.exception(error)
            return False

        return True

    def prepare_run(self):
        # XXX HACK: Avoid a slow down of unicorn (apparently to too many
        # threads...)
        self.jitter.renew()

    def restore_snapshot(self, memory=True):
        # Restore VM
        if memory:
            self.jitter.vm.restore_mem_state(self.vm_mem)

        # Restore registers
        self.jitter.cpu.set_gpreg(self.vm_regs)


class UcWrapJitter(object):

    def __init__(self):
        self.renew()

    def renew(self):
        self.mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.vm = UcWrapVM(self.mu)
        self.cpu = UcWrapCPU(self.mu)

    def init_stack(self):
        self.vm.add_memory_page(0x1230000, PAGE_WRITE | PAGE_READ, "\x00" * 0x10000, "Stack")
        self.cpu.ESP = 0x1230000 + 0x10000

    def push_uint32_t(self, value):
        self.cpu.ESP -= 32 / 8
        self.vm.set_mem(self.cpu.ESP, pck32(value))

    def run(self, pc, timeout_seconds=1):
        try:
            self.mu.emu_start(pc, END_ADDR,
                              timeout_seconds * unicorn.UC_SECOND_SCALE)
        except Exception as e:
            self.mu.emu_stop()
            if self.cpu.EIP != END_ADDR:
                raise UnexpectedStopException()

    def verbose_mode(self):
        self.mu.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED, self.hook_mem_invalid)
        self.mu.hook_add(unicorn.UC_HOOK_CODE, self.hook_code)

    @staticmethod
    def hook_code(uc, address, size, user_data):
        print(">>> Tracing instruction at 0x%x, instruction size = %u" %(address, size))
        return True

    @staticmethod
    def hook_mem_invalid(uc, access, address, size, value, user_data):
        self.logger.error("Invalid memory access at %s", hex(address))
        return False


class UcWrapVM(object):

    def __init__(self, mu):
        self.mem_page = []
        self.mu = mu

    def add_memory_page(self, addr, access, item_str, name=""):
        size = len(item_str)
        size = (size + 0xfff) & ~0xfff

        for page in self.mem_page:
            if page["addr"] <= addr < page["addr"] + page["size"]:
                self.set_mem(addr, item_str)
                return

        self.mem_page.append({"addr": addr,
                              "size": size,
                              "name": name,
                              "access": access,
        })

        self.mu.mem_map(addr, size)
        self.set_mem(addr, item_str)

    def get_mem(self, addr, size):
        return str(self.mu.mem_read(addr, size))

    def set_mem(self, addr, content):
        self.mu.mem_write(addr, str(content))

    def get_all_memory(self):
        dico = {}
        for page in self.mem_page:
            data = self.get_mem(page["addr"], page["size"])
            dico[page["addr"]] = {"access": page["access"],
                                  "size": len(data),
                                  "data": data}

        return dico

    def restore_mem_state(self, mem_state):
        """Restore the memory state according to mem_state
        Optimisation: only consider memory unwrittable"""
        new_mem_page = []
        addrs = set()

        for page in self.mem_page:
            if page["addr"] not in mem_state:
                # Remove additionnal pages
                self.mu.mem_unmap(page["addr"], page["size"])
            else:
                # Rewrite pages content
                if page["access"] & PAGE_WRITE:
                    self.set_mem(page["addr"], mem_state[page["addr"]]["data"])
                new_mem_page.append(page)
                addrs.add(page["addr"])

        for addr, page in mem_state.iteritems():
            # Add missing pages
            if addr not in addrs:
                self.mu.mem_map(addr, page["size"])
                self.set_mem(addr, page["data"])
                new_mem_page.append({"addr": addr,
                                     "size": page["size"],
                                     "name": "",
                                     "access": page["access"]})
        self.mem_page = new_mem_page


class UcWrapCPU(object):

    regs = [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
            UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP]
    def __init__(self, mu):
        self.mu = mu

    def init_regs(self):
        for reg in self.regs:
            self.mu.reg_write(reg, 0)

    def __setattr__(self, name, value):
        if name in ["mu"]:
            super(UcWrapCPU, self).__setattr__(name, value)
        elif name == "ESP":
            self.mu.reg_write(UC_X86_REG_ESP, value)
        elif name == "EIP":
            self.mu.reg_write(UC_X86_REG_EIP, value)
        else:
            fds

    def __getattr__(self, name):
        if name == "ESP":
            return self.mu.reg_read(UC_X86_REG_ESP)
        if name == "EIP":
            return self.mu.reg_read(UC_X86_REG_EIP)
        if name == "EAX":
            return self.mu.reg_read(UC_X86_REG_EAX)
        else:
            print name
            super(UcWrapCPU, self).__getattr__(name)

    def get_gpreg(self):
        return {i: self.mu.reg_read(v) for i, v in enumerate(self.regs)}

    def set_gpreg(self, values):
        for i, v in enumerate(self.regs):
            self.mu.reg_write(v, values[i])

    def set_exception(self, value):
        pass


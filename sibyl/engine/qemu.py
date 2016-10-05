from miasm2.core.utils import pck32
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
try:
    import unicorn
    from unicorn.x86_const import *
    from unicorn.arm_const import *
except ImportError:
    unicorn = None

from sibyl.engine.engine import Engine
from sibyl.commons import END_ADDR, init_logger


class UnexpectedStopException(Exception):
    """Exception to be called on timeouts"""
    pass

class QEMUEngine(Engine):
    """Engine based on QEMU, using unicorn as a wrapper"""

    def __init__(self, machine):
        if unicorn is None:
            raise ImportError("QEMU engine unavailable: 'unicorn' import error")

        self.jitter = UcWrapJitter(machine)
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

    def __init__(self, machine):
        self.ira = machine.ira()
        self.renew()

    def renew(self):
        ask_arch, ask_attrib = self.ira.arch.name, self.ira.attrib
        cpucls = UcWrapCPU.available_cpus.get((ask_arch, ask_attrib), None)
        if not cpucls:
            raise ValueError("Unimplemented architecture (%s, %s)" % (ask_arch,
                                                                      ask_attrib))
        arch, mode = cpucls.uc_arch, cpucls.uc_mode

        self.mu = unicorn.Uc(arch, mode)
        self.vm = UcWrapVM(self.mu)
        self.cpu = cpucls(self.mu)

    def init_stack(self):
        self.vm.add_memory_page(0x1230000, PAGE_WRITE | PAGE_READ,
                                "\x00" * 0x10000, "Stack")
        setattr(self.cpu, self.ira.sp.name, 0x1230000 + 0x10000)

    def push_uint32_t(self, value):
        setattr(self.cpu, self.ira.sp.name,
                getattr(self.cpu, self.ira.sp.name) - self.ira.sp.size / 8)
        self.vm.set_mem(getattr(self.cpu, self.ira.sp.name), pck32(value))

    def run(self, pc, timeout_seconds=1):
        try:
            self.mu.emu_start(pc, END_ADDR,
                              timeout_seconds * unicorn.UC_SECOND_SCALE)
        except unicorn.UcError as e:
            if getattr(self.cpu, self.ira.pc.name) != END_ADDR:
                raise UnexpectedStopException()
        finally:
            self.mu.emu_stop()

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

    # name -> Uc value
    regs = None
    # PC registers, name and Uc value
    pc_reg_name = None
    pc_reg_value = None

    # (arch, attrib) -> CPU class
    available_cpus = {}
    # Uc architecture and mode
    uc_arch = None
    uc_mode = None

    def __init__(self, mu):
        self.mu = mu
        self.logger = init_logger("UcWrapCPU")

    def init_regs(self):
        for reg in self.regs.itervalues():
            self.mu.reg_write(reg, 0)

    def __setattr__(self, name, value):
        if name in ["mu", "logger"]:
            super(UcWrapCPU, self).__setattr__(name, value)
        elif name in self.regs:
            self.mu.reg_write(self.regs[name], value)
        elif name == self.pc_reg_name:
            self.mu.reg_write(self.pc_reg_value, value)
        else:
            self.logger.warning("Unknown attribute %s set to %s", name, value)
            raise AttributeError()

    def __getattr__(self, name):
        if name in self.regs:
            return self.mu.reg_read(self.regs[name])
        elif name == self.pc_reg_name:
            return self.mu.reg_read(self.pc_reg_value)
        else:
            raise AttributeError

    def get_gpreg(self):
        return {k: self.mu.reg_read(v) for k, v in self.regs.iteritems()}

    def set_gpreg(self, values):
        for k, v in values.iteritems():
            self.mu.reg_write(self.regs[k], v)

    @classmethod
    def register(cls, arch, attrib):
        super(cls, cls).available_cpus[(arch, attrib)] = cls


class UcWrapCPU_x86_32(UcWrapCPU):

    uc_arch = unicorn.UC_ARCH_X86
    uc_mode = unicorn.UC_MODE_32
    regs = {"EAX": UC_X86_REG_EAX, "EBX": UC_X86_REG_EBX, "ECX": UC_X86_REG_ECX,
            "EDX": UC_X86_REG_EDX, "ESI": UC_X86_REG_ESI, "EDI": UC_X86_REG_EDI,
            "EBP": UC_X86_REG_EBP, "ESP": UC_X86_REG_ESP,
    }
    pc_reg_name = "EIP"
    pc_reg_value = UC_X86_REG_EIP


class UcWrapCPU_arml(UcWrapCPU):

    uc_arch = unicorn.UC_ARCH_ARM
    uc_mode = unicorn.UC_MODE_ARM + unicorn.UC_MODE_LITTLE_ENDIAN
    regs = {'CPSR': UC_ARM_REG_CPSR, 'SPSR': UC_ARM_REG_SPSR,
            'R4': UC_ARM_REG_R4, 'R5': UC_ARM_REG_R5, 'R6': UC_ARM_REG_R6,
            'R7': UC_ARM_REG_R7, 'R0': UC_ARM_REG_R0, 'R1': UC_ARM_REG_R1,
            'R2': UC_ARM_REG_R2, 'R3': UC_ARM_REG_R3, 'R8': UC_ARM_REG_R8,
            'R9': UC_ARM_REG_R9, 'R14': UC_ARM_REG_R14, 'R15': UC_ARM_REG_R15,
            'R12': UC_ARM_REG_R12, 'R13': UC_ARM_REG_R13, 'R10': UC_ARM_REG_R10,
            'R11': UC_ARM_REG_R11, 'SP': UC_ARM_REG_SP, 'SL': UC_ARM_REG_SL,
            'SB': UC_ARM_REG_SB, 'LR': UC_ARM_REG_LR,
    }
    pc_reg_name = "PC"
    pc_reg_value = UC_ARM_REG_PC


class UcWrapCPU_armb(UcWrapCPU_arml):

    uc_mode = unicorn.UC_MODE_ARM + unicorn.UC_MODE_BIG_ENDIAN


UcWrapCPU_x86_32.register("x86", 32)
UcWrapCPU_arml.register("arm", "l")
UcWrapCPU_armb.register("arm", "b")

from miasm2.core.utils import pck32, pck64
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
try:
    import unicorn
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

    def push_uint64_t(self, value):
        setattr(self.cpu, self.ira.sp.name,
                getattr(self.cpu, self.ira.sp.name) - self.ira.sp.size / 8)
        self.vm.set_mem(getattr(self.cpu, self.ira.sp.name), pck64(value))

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

    def is_mapped(self, address, size):
        for addr in xrange(address, address + size):
            for page in self.mem_page:
                if page["addr"] <= addr < page["addr"] + page["size"]:
                    break
            else:
                return False
        return True

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
    # Registers mask (int -> uint)
    reg_mask = None

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
        if name in ["mu", "logger", "regs", "pc_reg_name", "pc_reg_value"]:
            super(UcWrapCPU, self).__setattr__(name, value)
        elif name in self.regs:
            self.mu.reg_write(self.regs[name], value)
        elif name == self.pc_reg_name:
            self.mu.reg_write(self.pc_reg_value, value)
        else:
            raise AttributeError("Unknown attribute %s set to %s", name, value)

    def __getattr__(self, name):
        if name in self.regs:
            return self.mu.reg_read(self.regs[name]) & self.reg_mask
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

    reg_mask = 0xFFFFFFFF

    if unicorn:
        uc_arch = unicorn.UC_ARCH_X86
        uc_mode = unicorn.UC_MODE_32

    def __init__(self, *args, **kwargs):
        import unicorn.x86_const as csts
        self.regs = {
            "EAX": csts.UC_X86_REG_EAX, "EBX": csts.UC_X86_REG_EBX,
            "ECX": csts.UC_X86_REG_ECX, "EDI": csts.UC_X86_REG_EDI,
            "EDX": csts.UC_X86_REG_EDX, "ESI": csts.UC_X86_REG_ESI,
            "EBP": csts.UC_X86_REG_EBP, "ESP": csts.UC_X86_REG_ESP,
        }
        self.pc_reg_name = "EIP"
        self.pc_reg_value = csts.UC_X86_REG_EIP
        super(self.__class__, self).__init__(*args, **kwargs)


class UcWrapCPU_x86_64(UcWrapCPU):

    reg_mask = 0xFFFFFFFFFFFFFFFF

    if unicorn:
        uc_arch = unicorn.UC_ARCH_X86
        uc_mode = unicorn.UC_MODE_64

    def __init__(self, *args, **kwargs):
        import unicorn.x86_const as csts
        self.regs = {
            "RAX": csts.UC_X86_REG_RAX, "RBX": csts.UC_X86_REG_RBX,
            "RCX": csts.UC_X86_REG_RCX, "RDI": csts.UC_X86_REG_RDI,
            "RDX": csts.UC_X86_REG_RDX, "RSI": csts.UC_X86_REG_RSI,
            "RBP": csts.UC_X86_REG_RBP, "RSP": csts.UC_X86_REG_RSP,
             "R8": csts.UC_X86_REG_R8, "R11": csts.UC_X86_REG_R11,
            "R9": csts.UC_X86_REG_R9, "R10": csts.UC_X86_REG_R10,
            "R12": csts.UC_X86_REG_R12, "R13": csts.UC_X86_REG_R13,
            "R14": csts.UC_X86_REG_R14, "R15": csts.UC_X86_REG_R15,
        }
        self.pc_reg_name = "RIP"
        self.pc_reg_value = csts.UC_X86_REG_RIP
        super(self.__class__, self).__init__(*args, **kwargs)


class UcWrapCPU_arml(UcWrapCPU):

    reg_mask = 0xFFFFFFFF

    if unicorn:
        uc_arch = unicorn.UC_ARCH_ARM
        uc_mode = unicorn.UC_MODE_ARM + unicorn.UC_MODE_LITTLE_ENDIAN

    def __init__(self, *args, **kwargs):
        import unicorn.arm_const as csts
        self.regs = {
            'CPSR': csts.UC_ARM_REG_CPSR, 'SPSR': csts.UC_ARM_REG_SPSR,
            'R4': csts.UC_ARM_REG_R4, 'R5': csts.UC_ARM_REG_R5,
            'R6': csts.UC_ARM_REG_R6, 'R1': csts.UC_ARM_REG_R1,
            'R7': csts.UC_ARM_REG_R7, 'R0': csts.UC_ARM_REG_R0,
            'R2': csts.UC_ARM_REG_R2, 'R3': csts.UC_ARM_REG_R3,
            'R8': csts.UC_ARM_REG_R8, 'R15': csts.UC_ARM_REG_R15,
            'R9': csts.UC_ARM_REG_R9, 'R14': csts.UC_ARM_REG_R14,
            'R12': csts.UC_ARM_REG_R12, 'R13': csts.UC_ARM_REG_R13,
            'R10': csts.UC_ARM_REG_R10, 'SL': csts.UC_ARM_REG_SL,
            'R11': csts.UC_ARM_REG_R11, 'SP': csts.UC_ARM_REG_SP,
            'SB': csts.UC_ARM_REG_SB, 'LR': csts.UC_ARM_REG_LR,
        }
        self.pc_reg_name = "PC"
        self.pc_reg_value = csts.UC_ARM_REG_PC
        super(self.__class__, self).__init__(*args, **kwargs)


class UcWrapCPU_armb(UcWrapCPU_arml):

    if unicorn:
        uc_mode = unicorn.UC_MODE_ARM + unicorn.UC_MODE_BIG_ENDIAN


class UcWrapCPU_mips32l(UcWrapCPU):

    reg_mask = 0xFFFFFFFF

    if unicorn:
        uc_arch = unicorn.UC_ARCH_MIPS
        uc_mode = unicorn.UC_MODE_MIPS32 + unicorn.UC_MODE_LITTLE_ENDIAN

    def __init__(self, *args, **kwargs):
        import unicorn.mips_const as csts
        self.regs = {
            'CPR0_0': csts.UC_MIPS_REG_0, 'CPR0_1': csts.UC_MIPS_REG_1,
            'CPR0_10': csts.UC_MIPS_REG_10, 'CPR0_11': csts.UC_MIPS_REG_11,
            'CPR0_12': csts.UC_MIPS_REG_12, 'CPR0_13': csts.UC_MIPS_REG_13,
            'CPR0_14': csts.UC_MIPS_REG_14, 'CPR0_15': csts.UC_MIPS_REG_15,
            'CPR0_16': csts.UC_MIPS_REG_16, 'CPR0_17': csts.UC_MIPS_REG_17,
            'CPR0_18': csts.UC_MIPS_REG_18, 'CPR0_19': csts.UC_MIPS_REG_19,
            'CPR0_2': csts.UC_MIPS_REG_2, 'CPR0_20': csts.UC_MIPS_REG_20,
            'CPR0_21': csts.UC_MIPS_REG_21, 'CPR0_22': csts.UC_MIPS_REG_22,
            'CPR0_23': csts.UC_MIPS_REG_23, 'CPR0_24': csts.UC_MIPS_REG_24,
            'CPR0_25': csts.UC_MIPS_REG_25, 'CPR0_26': csts.UC_MIPS_REG_26,
            'CPR0_27': csts.UC_MIPS_REG_27, 'CPR0_28': csts.UC_MIPS_REG_28,
            'CPR0_29': csts.UC_MIPS_REG_29, 'CPR0_3': csts.UC_MIPS_REG_3,
            'CPR0_30': csts.UC_MIPS_REG_30, 'CPR0_31': csts.UC_MIPS_REG_31,
            'CPR0_4': csts.UC_MIPS_REG_4, 'CPR0_5': csts.UC_MIPS_REG_5,
            'CPR0_6': csts.UC_MIPS_REG_6, 'CPR0_7': csts.UC_MIPS_REG_7,
            'CPR0_8': csts.UC_MIPS_REG_8, 'CPR0_9': csts.UC_MIPS_REG_9,
            'A0': csts.UC_MIPS_REG_A0, 'A1': csts.UC_MIPS_REG_A1,
            'A2': csts.UC_MIPS_REG_A2, 'CC1': csts.UC_MIPS_REG_CC1,
            'A3': csts.UC_MIPS_REG_A3, 'CC0': csts.UC_MIPS_REG_CC0,
            'CC2': csts.UC_MIPS_REG_CC2, 'CC3': csts.UC_MIPS_REG_CC3,
            'CC4': csts.UC_MIPS_REG_CC4, 'CC5': csts.UC_MIPS_REG_CC5,
            'CC6': csts.UC_MIPS_REG_CC6, 'CC7': csts.UC_MIPS_REG_CC7,
            'F0': csts.UC_MIPS_REG_F0, 'F1': csts.UC_MIPS_REG_F1,
            'F10': csts.UC_MIPS_REG_F10, 'F5': csts.UC_MIPS_REG_F5,
            'F11': csts.UC_MIPS_REG_F11, 'F12': csts.UC_MIPS_REG_F12,
            'F13': csts.UC_MIPS_REG_F13, 'F14': csts.UC_MIPS_REG_F14,
            'F15': csts.UC_MIPS_REG_F15, 'F16': csts.UC_MIPS_REG_F16,
            'F17': csts.UC_MIPS_REG_F17, 'F18': csts.UC_MIPS_REG_F18,
            'F19': csts.UC_MIPS_REG_F19, 'F2': csts.UC_MIPS_REG_F2,
            'F20': csts.UC_MIPS_REG_F20, 'F21': csts.UC_MIPS_REG_F21,
            'F22': csts.UC_MIPS_REG_F22, 'F23': csts.UC_MIPS_REG_F23,
            'F24': csts.UC_MIPS_REG_F24, 'F25': csts.UC_MIPS_REG_F25,
            'F26': csts.UC_MIPS_REG_F26, 'F27': csts.UC_MIPS_REG_F27,
            'F28': csts.UC_MIPS_REG_F28, 'F29': csts.UC_MIPS_REG_F29,
            'F3': csts.UC_MIPS_REG_F3, 'F30': csts.UC_MIPS_REG_F30,
            'F31': csts.UC_MIPS_REG_F31, 'F4': csts.UC_MIPS_REG_F4,
            'F6': csts.UC_MIPS_REG_F6, 'F7': csts.UC_MIPS_REG_F7,
            'F8': csts.UC_MIPS_REG_F8,
            'F9': csts.UC_MIPS_REG_F9, 'FCC0': csts.UC_MIPS_REG_FCC0,
            'FCC1': csts.UC_MIPS_REG_FCC1, 'FCC2': csts.UC_MIPS_REG_FCC2,
            'FCC3': csts.UC_MIPS_REG_FCC3, 'FCC4': csts.UC_MIPS_REG_FCC4,
            'FCC5': csts.UC_MIPS_REG_FCC5, 'FCC6': csts.UC_MIPS_REG_FCC6,
            'FCC7': csts.UC_MIPS_REG_FCC7, 'FP': csts.UC_MIPS_REG_FP,
            'GP': csts.UC_MIPS_REG_GP, 'R_HI': csts.UC_MIPS_REG_HI,
            'K0': csts.UC_MIPS_REG_K0, 'RA': csts.UC_MIPS_REG_RA,
            'K1': csts.UC_MIPS_REG_K1, 'R_LO': csts.UC_MIPS_REG_LO,
            'S0': csts.UC_MIPS_REG_S0, 'S1': csts.UC_MIPS_REG_S1,
            'S2': csts.UC_MIPS_REG_S2, 'S3': csts.UC_MIPS_REG_S3,
            'S4': csts.UC_MIPS_REG_S4, 'S5': csts.UC_MIPS_REG_S5,
            'S6': csts.UC_MIPS_REG_S6, 'S7': csts.UC_MIPS_REG_S7,
            'S8': csts.UC_MIPS_REG_S8, 'SP': csts.UC_MIPS_REG_SP,
            'T0': csts.UC_MIPS_REG_T0, 'T1': csts.UC_MIPS_REG_T1,
            'T2': csts.UC_MIPS_REG_T2, 'T3': csts.UC_MIPS_REG_T3,
            'T4': csts.UC_MIPS_REG_T4, 'T5': csts.UC_MIPS_REG_T5,
            'T6': csts.UC_MIPS_REG_T6, 'T7': csts.UC_MIPS_REG_T7,
            'T8': csts.UC_MIPS_REG_T8, 'T9': csts.UC_MIPS_REG_T9,
            'V0': csts.UC_MIPS_REG_V0, 'V1': csts.UC_MIPS_REG_V1,
            'W0': csts.UC_MIPS_REG_W0, 'W1': csts.UC_MIPS_REG_W1,
            'W10': csts.UC_MIPS_REG_W10, 'W11': csts.UC_MIPS_REG_W11,
            'W12': csts.UC_MIPS_REG_W12, 'W13': csts.UC_MIPS_REG_W13,
            'W14': csts.UC_MIPS_REG_W14, 'W15': csts.UC_MIPS_REG_W15,
            'W16': csts.UC_MIPS_REG_W16, 'W17': csts.UC_MIPS_REG_W17,
            'W18': csts.UC_MIPS_REG_W18, 'W19': csts.UC_MIPS_REG_W19,
            'W2': csts.UC_MIPS_REG_W2, 'W20': csts.UC_MIPS_REG_W20,
            'W21': csts.UC_MIPS_REG_W21, 'W22': csts.UC_MIPS_REG_W22,
            'W23': csts.UC_MIPS_REG_W23, 'W24': csts.UC_MIPS_REG_W24,
            'W25': csts.UC_MIPS_REG_W25, 'W26': csts.UC_MIPS_REG_W26,
            'W27': csts.UC_MIPS_REG_W27, 'W28': csts.UC_MIPS_REG_W28,
            'W29': csts.UC_MIPS_REG_W29, 'W3': csts.UC_MIPS_REG_W3,
            'W30': csts.UC_MIPS_REG_W30, 'W31': csts.UC_MIPS_REG_W31,
            'W4': csts.UC_MIPS_REG_W4, 'W5': csts.UC_MIPS_REG_W5,
            'W6': csts.UC_MIPS_REG_W6, 'W7': csts.UC_MIPS_REG_W7,
            'W8': csts.UC_MIPS_REG_W8, 'W9': csts.UC_MIPS_REG_W9,
        }
        self.pc_reg_name = "PC"
        self.pc_reg_value = csts.UC_MIPS_REG_PC
        super(self.__class__, self).__init__(*args, **kwargs)


class UcWrapCPU_mips32b(UcWrapCPU):

    if unicorn:
        uc_mode = unicorn.UC_MODE_MIPS32 + unicorn.UC_MODE_BIG_ENDIAN


UcWrapCPU_x86_32.register("x86", 32)
UcWrapCPU_x86_64.register("x86", 64)
UcWrapCPU_arml.register("arm", "l")
UcWrapCPU_armb.register("arm", "b")
UcWrapCPU_mips32l.register("mips32", "l")
UcWrapCPU_mips32b.register("mips32", "b")

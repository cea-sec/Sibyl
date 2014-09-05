from sibyl.abi import abi


class ABIRegsStack_x86(abi.ABIRegsStack):

    def set_ret(self, ret_addr):
        self.vm_push(ret_addr)


class ABIStdCall_x86_32(ABIRegsStack_x86):

    regs_mapping = [] # Stack only
    RTL = True

    def vm_push(self, element):
        self.jitter.vm_push_uint32_t(element)


class ABIFastCall_x86_32(ABIRegsStack_x86):

    regs_mapping = ["ECX", "EDX"] # Stack only

    def vm_push(self, element):
        self.jitter.vm_push_uint32_t(element)


class ABI_AMD64(ABIRegsStack_x86):

    regs_mapping = ["RDI", "RSI", "RDX", "RCX", "R8", "R9"]

    def vm_push(self, element):
        self.jitter.vm_push_uint64_t(element)


ABIS = [ABIStdCall_x86_32, ABIFastCall_x86_32, ABI_AMD64]

from sibyl.abi import abi


class ABI_MIPS_O32(abi.ABIRegsStack):

    regs_mapping = ["A0", "A1", "A2", "A3"]

    def set_ret(self, ret_addr):
        self.jitter.cpu.RA = ret_addr

    def vm_push(self, element):
        self.jitter.vm_push_uint32_t(element)


ABIS = [ABI_MIPS_O32]

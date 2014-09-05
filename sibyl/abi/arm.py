from sibyl.abi import abi


class ABI_ARM(abi.ABIRegsStack):

    regs_mapping = ["R0", "R1", "R2", "R3"]

    def set_ret(self, ret_addr):
        self.jitter.cpu.LR = ret_addr

    def vm_push(self, element):
        self.jitter.vm_push_uint32_t(element)


ABIS = [ABI_ARM]

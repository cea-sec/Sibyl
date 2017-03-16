Adding an ABI
-------------

### Overview

The ABI descriptions in Sibyl are quite simple for now.
Their are located in `sibyl/abi`, and all inherits from `sibyl.abi.abi:ABI`.

The convention is to regroup them by relative architecture.

### Add an ABI

Here is a commented fake ABI, where arguments are first passed by registers, and
then by stack:

```Python
class ABI_CUSTOM(abi.ABIRegsStack):

	# Map argument number -> register name
    regs_mapping = ["A0", "A1", "A2", "A3"]
	# Associate this ABI to a given architecture, to be used when this
	# achitecture is recognized
    arch = ["mips32b", "mips32l"]

	# Indicate how the return address has to be set (stack, specific register,
	# ...)
    def set_ret(self, ret_addr):
        self.jitter.cpu.RA = ret_addr

	# Indicate how an element is push on the stack, for stack based arguments
    def vm_push(self, element):
        self.jitter.push_uint32_t(element)
```

Finally, the class just has to be added to the `sibyl.abi:ABIS` list to be
considered.

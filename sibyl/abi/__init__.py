from sibyl.abi.x86 import ABIS as ABIS_X86
from sibyl.abi.arm import ABIS as ABIS_ARM
from sibyl.abi.mips import ABIS as ABIS_MIPS
ABIS = ABIS_X86 + ABIS_ARM + ABIS_MIPS
__all__ = ["ABIS"]

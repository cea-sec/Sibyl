# This file is part of Sibyl.
# Copyright 2014 Camille MOUGEY <camille.mougey@cea.fr>
#
# Sibyl is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Sibyl is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Sibyl. If not, see <http://www.gnu.org/licenses/>.


from sibyl.abi import abi


class ABIRegsStack_x86(abi.ABIRegsStack):

    def set_ret(self, ret_addr):
        self.vm_push(ret_addr)


class ABIStdCall_x86_32(ABIRegsStack_x86):

    regs_mapping = [] # Stack only
    RTL = True

    def vm_push(self, element):
        self.jitter.push_uint32_t(element)


class ABIFastCall_x86_32(ABIRegsStack_x86):

    regs_mapping = ["ECX", "EDX"] # Stack only

    def vm_push(self, element):
        self.jitter.push_uint32_t(element)


class ABI_AMD64(ABIRegsStack_x86):

    regs_mapping = ["RDI", "RSI", "RDX", "RCX", "R8", "R9"]

    def vm_push(self, element):
        self.jitter.push_uint64_t(element)


ABIS = [ABIStdCall_x86_32, ABIFastCall_x86_32, ABI_AMD64]

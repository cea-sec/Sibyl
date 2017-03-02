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


class ABI_MIPS_O32(abi.ABIRegsStack):

    regs_mapping = ["A0", "A1", "A2", "A3"]
    arch = ["mips32b", "mips32l"]

    def set_ret(self, ret_addr):
        self.jitter.cpu.RA = ret_addr

    def vm_push(self, element):
        self.jitter.push_uint32_t(element)


ABIS = [ABI_MIPS_O32]

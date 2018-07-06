# This file is part of Sibyl.
# Copyright 2018 Camille MOUGEY <camille.mougey@cea.fr>
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
#
# Author: Guillaume VALADON <guillaume@valadon.net>


from sibyl.abi import abi


class ABI_MEP(abi.ABIRegsStack):

    regs_mapping = ["R1", "R2", "R3", "R4"]
    arch = ["mepl", "mepb"]

    def set_ret(self, ret_addr):
        self.jitter.cpu.LP = ret_addr

    def vm_push(self, element):
        self.jitter.push_uint32_t(element)


ABIS = [ABI_MEP]

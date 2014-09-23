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

from sibyl.abi.x86 import ABIS as ABIS_X86
from sibyl.abi.arm import ABIS as ABIS_ARM
from sibyl.abi.mips import ABIS as ABIS_MIPS
ABIS = ABIS_X86 + ABIS_ARM + ABIS_MIPS
__all__ = ["ABIS"]

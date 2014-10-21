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


import random
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.expression.modint import mod_size2int


class Test(object):
    "Main class for tests"

    # Elements to override

    func = ""   # Possible function if test passes
    tests = [] # List of tests (init, check) to pass
    reset_mem = True # Reset memory between tests

    def init(self):
        "Called for setting up the test case"
        pass

    def check(self):
        """Called to check test result
        Return True if all checks are passed"""
        return True

    def reset_full(self):
        """Reset the test case between two functions"""
        self.alloc_pool = 0x20000000

    def reset(self):
        """Reset the test case between two subtests"""
        self.reset_full()

    # Utils

    def __init__(self, jitter, abi):
        self.jitter = jitter
        self.alloc_pool = 0x20000000
        self.abi = abi

    def __alloc_mem(self, mem, read=True, write=False):
        right = 0
        if read:
            right |= PAGE_READ
        if write:
            right |= PAGE_WRITE

        # Memory alignement
        mem += "".join([chr(random.randint(0, 255)) \
                            for _ in xrange((16 - len(mem) % 16))])

        self.jitter.vm.add_memory_page(self.alloc_pool, right, mem)
        to_ret = self.alloc_pool
        self.alloc_pool += len(mem) + 1

        return to_ret

    def _alloc_mem(self, size, read=True, write=False):
        mem = "".join([chr(random.randint(0, 255)) for _ in xrange(size)])
        return self.__alloc_mem(mem, read=read, write=write)

    def _alloc_string(self, string, read=True, write=False):
        return self.__alloc_mem(string + "\x00", read=read, write=write)

    def _alloc_pointer(self, pointer, read=True, write=False):
        pointer_size = self.abi.ira.sizeof_pointer()
        return self.__alloc_mem(Test.pack(pointer, pointer_size),
                                read=read,
                                write=write)

    def _write_mem(self, addr, element):
        self.jitter.vm.set_mem(addr, element)

    def _write_string(self, addr, element):
        self._write_mem(addr, element + "\x00")

    def _add_arg(self, number, element):
        self.abi.add_arg(number, element)

    def _get_result(self):
        return self.abi.get_result()

    def _ensure_mem(self, addr, element):
        try:
            return self.jitter.vm.get_mem(addr, len(element)) == element
        except RuntimeError:
            return False

    def _as_int(self, element):
        int_size = self.abi.ira.sizeof_int()
        max_val = 2**int_size
        return (element + max_val) % max_val

    def _to_int(self, element):
        int_size = self.abi.ira.sizeof_int()
        return mod_size2int[int_size](element)

    def _memread_pointer(self, addr):
        pointer_size = self.abi.ira.sizeof_pointer() / 8
        try:
            element = self.jitter.vm.get_mem(addr, pointer_size)
        except RuntimeError:
            return False
        return Test.unpack(element)

    @staticmethod
    def pack(element, size):
        out = ""
        while element != 0:
            out += chr(element % 0x100)
            element >>= 8
        if len(out) > size / 8:
            raise ValueError("To big to be packed")
        out = "\x00" * ((size / 8) - len(out)) + out
        return out

    @staticmethod
    def unpack(element):
        return int(element[::-1].encode("hex"), 16)

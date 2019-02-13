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
from miasm2.expression.simplifications import expr_simp
try:
    import pycparser
except ImportError:
    pycparser = None
else:
    from miasm2.core.objc import CTypesManagerNotPacked, CHandler
    from miasm2.core.ctypesmngr import CAstTypes
    from miasm2.arch.x86.ctype import CTypeAMD64_unk

from sibyl.commons import HeaderFile


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

    def _reserv_mem(self, size, read=True, write=False):
        right = 0
        if read:
            right |= PAGE_READ
        if write:
            right |= PAGE_WRITE

        # Memory alignement
        size += 16 - size % 16

        to_ret = self.alloc_pool
        self.alloc_pool += size + 1

        return to_ret

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

    def _ensure_mem_sparse(self, addr, element, offsets):
        """@offsets: offsets to ignore"""
        for i, sub_element in enumerate(element):
            if i in offsets:
                continue
            if not self._ensure_mem(addr + i, sub_element):
                return False
        return True

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
        out = out + "\x00" * ((size / 8) - len(out))
        return out

    @staticmethod
    def unpack(element):
        return int(element[::-1].encode("hex"), 16)


class TestSet(object):
    """Stand for a set of test to run, potentially associated to a logic form

    The logic form is represented as a tree, in which nodes are TestSet children
    instance
    """

    def __and__(self, ts):
        return TestSetAnd(self, ts)

    def __or__(self, ts):
        return TestSetOr(self, ts)

    def execute(self, callback):
        """Successive execution of test set (like a visitor on the aossicated tree)
        through @callback
        @callback: bool func(init, check)
        """
        return NotImplementedError("Asbtract method")


class TestSetAnd(TestSet):
    """Logic form : TestSet1 & TestSet2

    Lazy evaluation: if TestSet1 fail, TestSet2 is not launched
    """

    def __init__(self, ts1, ts2):
        super(TestSetAnd, self).__init__()
        assert isinstance(ts1, TestSet)
        assert isinstance(ts2, TestSet)
        self._ts1 = ts1
        self._ts2 = ts2

    def __repr__(self):
        return "%r TS_AND %r" % (self._ts1, self._ts2)

    def execute(self, callback):
        if not self._ts1.execute(callback):
            # Early quit
            return False
        else:
            # First test is valid
            return self._ts2.execute(callback)


class TestSetOr(TestSet):
    """Logic form : TestSet1 | TestSet2

    Lazy evaluation: if TestSet1 success, TestSet2 is not launched
    """

    def __init__(self, ts1, ts2):
        super(TestSetOr, self).__init__()
        assert isinstance(ts1, TestSet)
        assert isinstance(ts2, TestSet)
        self._ts1 = ts1
        self._ts2 = ts2

    def __repr__(self):
        return "%r TS_OR %r" % (self._ts1, self._ts2)

    def execute(self, callback):
        if self._ts1.execute(callback):
            # Early quit
            return True
        else:
            return self._ts2.execute(callback)


class TestSetTest(TestSet):
    """Terminal node of TestSet

    Stand for a check in a test case

    init: initialization function, called before launching the target address
    check: checking function, verifying the final state
    """

    def __init__(self, init, check):
        super(TestSetTest, self).__init__()
        self._init = init
        self._check = check

    def __repr__(self):
        return "<TST %r,%r>" % (self._init, self._check)

    def execute(self, callback):
        return callback(self._init, self._check)


class TestSetGenerator(TestSet):
    """TestSet based using a generator to retrieve tests"""

    def __init__(self, generator):
        self._generator = generator

    def execute(self, callback):
        for (init, check) in self._generator:
            if not callback(init, check):
                return False
        return True


class TestHeader(Test):
    """Test extension with support for header parsing, and handling of struct
    offset, size, ...
    """

    header = None

    def __init__(self, *args, **kwargs):
        super(TestHeader, self).__init__(*args, **kwargs)
        # Requirement check
        if pycparser is None:
            raise ImportError("pycparser module is needed to launch tests based"
                              "on header files")

        ctype_manager = CTypesManagerNotPacked(CAstTypes(), CTypeAMD64_unk())

        hdr = HeaderFile(self.header, ctype_manager)
        proto = hdr.functions[self.func]
        self.c_handler = CHandler(
            hdr.ctype_manager,
            {'arg%d_%s' % (i, name): set([proto.args[name]])
             for i, name in enumerate(proto.args_order)}
        )
        self.expr_types_from_C = {'arg%d_%s' % (i, name): proto.args[name]
                                  for i, name in enumerate(proto.args_order)}
        self.cache_sizeof = {}
        self.cache_trad = {}
        self.cache_field_addr = {}

    def sizeof(self, Clike):
        ret = self.cache_sizeof.get(Clike, None)
        if ret is None:
            ret = self.c_handler.c_to_type(
                Clike,
                self.expr_types_from_C
            ).size * 8
            self.cache_sizeof[Clike] = ret
        return ret

    def trad(self, Clike):
        ret = self.cache_trad.get(Clike, None)
        if ret is None:
            ret = self.c_handler.c_to_expr(Clike, self.expr_types_from_C)
            self.cache_trad[Clike] = ret
        return ret

    def field_addr(self, base, Clike, is_ptr=False):
        key = (base, Clike, is_ptr)
        ret = self.cache_field_addr.get(key, None)
        if ret is None:
            base_expr = self.trad(base)
            if is_ptr:
                access_expr = self.trad(Clike)
            else:
                access_expr = self.trad("&(%s)" % Clike)
            offset = int(expr_simp(access_expr - base_expr))
            ret = offset
            self.cache_field_addr[key] = ret
        return ret

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


from sibyl.test.test import Test, TestSetTest


class TestAbs(Test):

    value = 42

    # Test1
    def init1(self):
        self._add_arg(0, self.value + 1)

    def check1(self):
        result = self._get_result()
        return result == (self.value + 1)

    # Test2
    def init2(self):
        self._add_arg(0, self._as_int(-1 * self.value))

    def check2(self):
        result = self._get_result()
        return result == self.value

    # Properties
    func = "abs"
    tests = TestSetTest(init1, check1) & TestSetTest(init2, check2)


class TestA64l(Test):

    my_string = "v/"
    value = 123

    # Test
    def init(self):
        self.my_addr = self._alloc_string(self.my_string)
        self._add_arg(0, self.my_addr)

    def check(self):
        result = self._get_result()
        return all([result == self.value,
                    self._ensure_mem(self.my_addr, self.my_string)])

    # Properties
    func = "a64l"
    tests = TestSetTest(init, check)


class TestAtoi(Test):

    my_string = "44"
    my_string2 = "127.0.0.1"

    # Test
    def my_init(self, string):
        self.my_addr = self._alloc_string(string)
        self._add_arg(0, self.my_addr)

    def my_check(self, string):
        result = self._get_result()
        return all([result == int(string.split(".")[0]),
                    self._ensure_mem(self.my_addr, string)])

    # Test1
    def init1(self):
        return self.my_init(self.my_string)

    def check1(self):
        return self.my_check(self.my_string)

    # Test1
    def init2(self):
        return self.my_init(self.my_string2)

    def check2(self):
        return self.my_check(self.my_string2)


    # Properties
    func = "atoi"
    tests = TestSetTest(init1, check1) & TestSetTest(init2, check2)


TESTS = [TestAbs, TestA64l, TestAtoi]

from sibyl.test import test


class TestAbs(test.Test):

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
    tests = [(init1, check1), (init2, check2)]


class TestA64l(test.Test):

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
    tests = [(init, check)]


class TestAtoi(test.Test):

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
    tests = [(init1, check1), (init2, check2)]



TESTS = [TestAbs, TestA64l, TestAtoi]

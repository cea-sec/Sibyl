TODO: update

### Adding a test case
Available test cases are in the directory _sibyl/test/_.
A test has to extend the class _sibyl.test.test.Test_ and provide at least:

* _func_: the name of the function to test
* _tests_: a list of (_init_, _check_) methods respectively called to initialize the VM and check the resulting state

Here is a commented case:
```Python
class TestA64l(test.Test):

    my_string = "v/"
    value = 123

    # Test
    def init(self):
        # Alloc a string thanks to a common API, in read only
        self.my_addr = self._alloc_string(self.my_string)
        # Set the first argument independently of ABI
        self._add_arg(0, self.my_addr)

    def check(self):
        # Get the result independently of ABI
        result = self._get_result()
        # Check the expected result, and verify memory
        return all([result == self.value,
                    self._ensure_mem(self.my_addr, self.my_string)])

    # Properties
    func = "a64l"
    tests = [(init, check)]
```

A more elaborated test can be found in _sibyl/test/ctype.py_.


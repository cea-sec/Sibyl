Adding a test case
------------------

### Overview

Available test cases are in the directory _sibyl/test/_.
A test has to extend the class _sibyl.test.test.Test_ and provide at least:

* _func_: the name of the function to test
* _tests_: a `TestSetTest` instance, composed of (_init_, _check_) methods
  respectively called to initialize the VM and check the resulting state

Finally, the class has to be "announced", by beeing in the `TESTS` (list)
variable of the module.

### Example

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
    tests = TestSetTest(init, check)
```

A more elaborated test can be found in _sibyl/test/ctype.py_.

### TestSetTest

In order to avoid false positive, it is recommended to use multiple tests. For
instance, testing a `strlen` with at least two strings (different in size) will
avoid finding function returning always the same number.

To do so, `TestSetTest` instance can be combined through `&` and `|` operator,
respectively imposing the success of both tests, or the success of one of them.

For instance (`TestStrlen`):
```Python
    tests = TestSetTest(init, check) & TestSetTest(init2, check2)
```

Tests to run can also be choosen on the fly, depending on previous test results.
In fact, `Test.tests` act as a generator. It is asked to produce a `(init,
check)` couple only after the previous check. The `func` attribute is read only
on success, so it can be changed in the same time than test strategy if needed.

For instance, `TestIsCharset` in `ctype.py` implements a test strategy based on
a decision tree.

### Subscribing custom tests

To avoid modifying the sibyl package for each new test, one can add them in the
configuration file.

In the section `tests`, one just have to add:
```
[tests]
name = path/to/source.py
```

Where `source.py` offers a `TESTS` variable.

Here is two example of organisation:
* A file with custom tests implementation, offering `TESTS` at its end
* A directory with several tests implemenration, and a single file merging them
  in its `TESTS` variable

For more detail on configuration, please consult the relative documentation.

Once the configuration done, the new tests should appear in the `Tests
availables` section of `sibyl config`, and in the help of `--tests` options of
`sibyl find` under name `name`.

Without specifying tests (ie. all tests) or with `-t name`, these tests
will be used in the identification.


### Debugging its tests

A few trick can be used to debug the tests.

The Python `pdb` module is a good start to obtain and inspect the context in
`init` or `check` methods.

As error are masked, because they are considered as a recognition fail, one
would probably want to avoid this exception catching. To do this, remove error
catching code in `sibyl/engine/miasm.py::MiasmEngine.run` (if you're using one
of the Miasm jitter).

Adding jitter log could also help, for instance by adding in this same method:
```Python
self.jitter.jit.log_mn = True
self.jitter.jit.log_regs = True
```

Please refer to Miasm for more information on this.

Finally, it is often easier to:
* deactivate multiprocessing (`find -p`)
* use only your function, on one test (`find -t name addr1`)
* deactivate timeout (`find -t 0`)

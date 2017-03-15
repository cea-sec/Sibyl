Testing
-------

### Integrated regression tests

Sibyl is provided with a few regression tests.

To test a Sibyl installation:

```
$ cd c_tests && python run_ctests.py
...
```

Heuristics can be tested by using `-f` and `-a` options, respectively for
functions and architecture guessing.

One should have at least a few functions detected. Depending on your system, the
package `libc6-dev-i386` may be required to build the tests.

Depending on the current Sibyl state, some functions can be misdetected or
absent.

### External regression tests

Sibyl commits go through a CI process, which includes tests on real programs.
These tests are available
on [Sibyl-tests](https://github.com/commial/Sibyl-tests) repository.


### Learning tests

As Learning documentation, this part will completely change soon.

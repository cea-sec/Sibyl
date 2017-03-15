TODO

Testing
-------

Sibyl is provided with a few regression tests.

To test a Sibyl installation:

```
$ cd c_tests && python run_ctests.py
...
```

One should have at least a few functions detected. Depending on your system, the
package `libc6-dev-i386` may be required to build the tests.

Depending on the current Sibyl state, some functions can be misdetected or
absent.

TODO: Sibyl-tests


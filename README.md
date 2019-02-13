This file is part of Sibyl.

Copyright 2014 - 2019 [Camille MOUGEY](mailto:camille.mougey@cea.fr)


Sibyl
=====

A _Miasm2_ based function divination.

Idea
----

In reverse engineer work, stripped binaries are common (malwares, firmwares, ...). Often, they carry usual libraries, such as _libc_ or _openssl_. Identifying such libraries and their functions can be an interesting starting point.
But it is a time consuming task. Moreover, this task is made more difficult due to optimizations, architectures and compilers diversity, custom implementations, obfuscation, ...

Tools have been developed to automate this task. Some are based on CFG (Control Flow Graph) signature (_Bindiff_), others on magic constants (_FindCrypt_) or enhanced pattern matching (_FLIRT_).

_Sibyl_ is one of these tools, dynamic analysis oriented and **based on _Miasm2_** (https://github.com/cea-sec/miasm).
The idea is to identify functions from their side effects. That way, identification is independent of the used implementation.

Identifications are done thanks to these steps:

1. Initialize a minimalist VM for the targeted architecture, with only needed elements
2. Prepare the function call using the correct ABI and API
3. Run the target function code inside the VM
4. If the function crashes (null derefencement, not enough stack arguments, ...), switch to the next test case
4b. If the function ends correctly, compare the final VM state with the expected one. If they match, consider the test case as a candidate

For instance, if one want to identify a _strlen_, the test will be as follow:

1. Allocate a string containing _"Hello %sworld!"_ in a read-only memory page
2. Call the function with a pointer on the string as first argument
3. Compare the result with _14_
4. Execute the same test with a different string to avoid false positives (detecting a function which always returns _14_)

_Sibyl_ test cases are written **architecture and ABI independant**.

Basically, _Sibyl_ suffers from false positives (identifying a non _strlen_ as a _strlen_ one) and false negatives
(misidentifying or skipping a real _strlen_).
Given the hypothesis that the ABI is exactly the one used by the function, Sibyl becomes complete (no more false negatives).

As a sideline, _Sibyl_ can be used to bruteforce a program ABI.

**Long story short, this is an enhanced API bruteforcing tool**.

Basic usage
-----------

_Sibyl_ comes with a CLI, named `sibyl`, and an _IDA_ (https://www.hex-rays.com)
stub.

### CLI

The `sibyl` tool is a wrapper on several sub-actions.

```
$ sibyl
Usage: /usr/local/bin/sibyl [action]

Actions:
	config   Configuration management
	find     Function guesser
	func     Function discovering
	learn    Learn a new function
```

The main usage of Sibyl, function recognition, is done through the `find`
action. This action comes with several options, to specify ABI, architecture,
test cases, ...

To launch function recognition on the ARMv6 binary `busybox-amv6l`(busybox
1.21.1 http://www.busybox.net/downloads/binaries/1.21.1/), targetting address
`0x8230` and `0x8550` and using included test cases:
```
$ sibyl find binaries/busybox-armv6l 0x00008550 0x00008230
0x00008230 : strlen
0x00008550 : memmove
```

### IDA stub

The IDA stub is located in `ext/ida/find.py`. If `sibyl` is installed on the
system, no other action is needed to have it running (see section Installation
for more details)

Once the script has been loaded by _IDA_, the user is asked to launch Sibyl
either on the current function, or on all function detected by IDA.

The architecture and ABI are provided by IDA. Optionnaly, the set of test to use
can be modified.

On _busybox-i486_:
![IDA stub](doc/img/ida_screen.png?raw=true)

And the associated result:
```
Python>
Launch identification on 3085 function(s)
Found memcpy at 0x8057120
Found memmove at 0x805714c
Found memset at 0x8057174
Found strcat at 0x80571a8
Found strchr at 0x80571cc
Found strcmp at 0x8057208
Found strcpy at 0x8057228
Found strlen at 0x8057244
Found strncmp at 0x8057258
Found strncpy at 0x8057280
Found strnlen at 0x80572a8
Found strrchr at 0x80572c0
Found memcmp at 0x80572ff
Found strsep at 0x80576ac
Found strspn at 0x8057704
Found stricmp at 0x805799c
Found strpbrk at 0x8057ab8
Found strtok at 0x8057b30
Found strcmp at 0x8057b48
Found atoi at 0x805df1c
Current: 64.83% (sub_0x80b4ab3)| Estimated time remaining: 14.45s
Found atoi at 0x80f1cf3
Current: 100.00% (sub_0x80f7a93)| Estimated time remaining: 0.00s
Finished ! Found 21 candidates in 42.70s
Results are also available in 'sibyl_res'
```

The corresponding function get an additionnal comment like `[Sibyl] memmove?`

Additionnaly, a method `launch_on_funcs` is provided for scripting purposes, and
the result of the last run, in addition to the human output on console, is
available in `sibyl_res` variable.

### Binary Ninja stub

An external stub for Binary Ninja is
available [here](https://github.com/kenoph/binja_sibyl), maintained
by [@kenoph](https://github.com/kenoph).

Documentation
-------------

A more detailed documentation is available in `doc`:

* [Advanced usage](doc/ADVANCED_USE.md)
* [Configuration](doc/CONFIG.md)
* [Testing](doc/TESTING.md)
* [Learning](doc/LEARNING.md)
* [Adding a new signature](doc/ADD_TEST.md)
* [Adding a new ABI](doc/ADD_ABI.md)

Current version is v0.2. See [changelog](doc/CHANGELOG.md) for more details.

Installation
------------

### Standard

_Sibyl_ requires at least _Miasm2_ version `v0.1.1` and the corresponding version of _Elfesteem_.
For the `qemu` engine, the `unicorn` python package must be installed (refer to the documentation of Unicorn for more detail).

_Sibyl_ comes as a Python module, and the installation follow the standard procedure:
```
$ python setup.py build
# Add the resulting build directory in your PYTHONPATH, or:
$ python setup.py install
```

In addition of the `sibyl` Python module, a CLI tool is provided, named
`sibyl`. See the usage documentation for more information.

If needed, consult [testing documentation](doc/TESTING.md) to check your Sibyl
installation.

### IDA

The IDA stub is located in `ext/ida`. To benefit from multiprocessing, Sibyl is
invoke through the CLI as a subprocess. Then, there is no need to have the
`sibyl` module in IDA Python namespace.

Long story short, it should work out of the box once `sibyl` CLI is available.

### Docker

_Sibyl_ is also available through _Docker automated build_. Use:

```
$ docker run -i -t commial/sibyl
Usage: /usr/local/bin/sibyl [action]

Actions:
	config   Configuration management
	find     Function guesser
	func     Function discovering
	learn    Learn a new function
```

Support
-------

### Test cases

Sibyl comes with several test cases, located in `sibyl/test`. These tests are
based on function from _string.h_, _stdlib.h_ and _ctype.h_.

One can add its custom test cases, and reference it through the configuration
file. Have a look at [Configuration](doc/CONFIG.md)
and [Adding a new signature](doc/ADD_TEST.md) for more information.


### Architectures by engine

Sibyl comes with the support of multiple architecture, and multiple engine.

| arch/jit | python             | tcc                       | gcc                       | llvm               | qemu                              |
|----------|--------------------|---------------------------|---------------------------|--------------------|-----------------------------------|
| arml     | :heavy_check_mark: | :heavy_check_mark:        | :heavy_check_mark:        | :heavy_check_mark: | :heavy_check_mark:                |
| armb     | :heavy_check_mark: | :heavy_check_mark:        | :heavy_check_mark:        | :heavy_check_mark: | :heavy_check_mark:                |
| armtl    | :x:                | :x:                       | :x:                       | :x:                | :warning: use `arml` with +1 offset |
| armtb    | :x:                | :x:                       | :x:                       | :x:                | :warning: use `armb` with +1 offset |
| sh4      | :x:                | :x:                       | :x:                       | :x:                | :x:                               |
| x86_16   | :heavy_check_mark: | :heavy_check_mark:        | :heavy_check_mark:        | :heavy_check_mark: | :heavy_check_mark:                |
| x86_32   | :heavy_check_mark: | :heavy_check_mark:        | :heavy_check_mark:        | :heavy_check_mark: | :heavy_check_mark:                |
| x86_64   | :heavy_check_mark: | :warning: bad SSE support | :warning: bad SSE support | :heavy_check_mark: | :heavy_check_mark:                |
| msp430   | :heavy_check_mark: | :heavy_check_mark:        | :heavy_check_mark:        | :heavy_check_mark: | :heavy_check_mark:                |
| mips32b  | :heavy_check_mark: | :heavy_check_mark:        | :heavy_check_mark:        | :heavy_check_mark: | :heavy_check_mark:                |
| mips32l  | :heavy_check_mark: | :heavy_check_mark:        | :heavy_check_mark:        | :heavy_check_mark: | :heavy_check_mark:                |
| aarch64l | :heavy_check_mark: | :heavy_check_mark:        | :heavy_check_mark:        | :heavy_check_mark: | :heavy_check_mark:                |
| aarch64b | :heavy_check_mark: | :heavy_check_mark:        | :heavy_check_mark:        | :heavy_check_mark: | :heavy_check_mark:                |


FAQ
---

Do not hesitate to consult and open an issue if precisions are still needed.

### How infinite loops are managed?

Behaviors close to infinite loop happen quite often, especially when the arguments are not formatted as expected by the function (trying another test case).
To avoid these behaviors, there is a timeout on each sub-test. The _-i/--timeout_ argument adjusts this parameter (2 by default, 0 to disable timeout).

### How to run the tool on a custom architecture?

Once the architecture and corresponding semantic is implemented in Miasm2, one just needs to implement the wanted ABI in _sibyl/abi/_.
If writing the jitter engine part is an issue, one can directly use the _python_ jitter option with _-j/--jitter_ argument.
If the semantic is not complete enough, one can add the corresponding bridge with _qemu_ in `sibyl/engine/qemu.py`, if available.

### Is my `sibyl func` freezed?

Sibyl may take time due to the number of function to consider and the test set
size (Sibyl time complexity is approximately in O(number function * test set
size)).

In addition, library are often present in the same binary zone, giving the
impression that Sibyl got result by burst.

A convenient way to observe its progress is the use of the `-v` option.

### How many coffees could I take while Sibyl is running?

| binary         | architecture | test set size | addresses to check | number of function found | elapsed time |
|----------------|--------------|---------------|--------------------|--------------------------|--------------|
| busybox-i486   | x86_32       |            26 |               3085 |                       21 | 36.0s        |
| busybox-armv6l | arml         |            26 |               3063 |                       48 | 1m16.5s      |
| busybox-mipsel | mips32l      |            26 |               3065 |                       16 | 44.0s        |

These tests have been done on a standard, 4 i7 CPU laptop, using the default
configuration (ie. `qemu` jitter) and addresses provided by IDA.

Please note that, by design, Sibyl is _embarrassingly parallel_.

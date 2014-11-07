This file is part of Sibyl.

Copyright 2014 [Camille MOUGEY](mailto:camille.mougey@cea.fr)


Sibyl
=====

A _Miasm2_ based function divination.

Idea
----

In reverse engineer work, stripped binaries are common (malwares, firmwares, ...). Often, they carry usual libraries, such as _libc_ or _openssl_. Identifying such libraries and their functions can be an interesting starting point.
But it is a time consuming task. Moreover, this task is made more difficult due to optimizations, architectures and compilers diversity, custom implementations, ...

Tools have been developed to automate this task. Some are based on CFG (Control Flow Graph) signature (_Bindiff_), others on magic constants (_FindCrypt_) or enhanced pattern matching (_FLIRT_).

_Sibyl_ is one of these tools, dynamic analysis oriented and **based on _Miasm2_** (http://code.google.com/p/miasm/).
The idea is to identify the side effects of functions. That way, identification is independent of the used implementation.

Identifications are done thanks to these steps:

1. Initialize the state of a _Miasm2_ VM with only needed elements
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

Usage
-----

_Sibyl_ comes with several test cases, implementing a part of _string.h_, _stdlib.h_ and _ctype.h_.

Interfaces are **find.py** and corresponding _IDA_ (https://www.hex-rays.com) stub **find_ida.py**.

### Basic
```
$ python find.py -h

positional arguments:
  filename              File to load
  architecture          Architecture used. Available: arml,armb,armtl,armtb,sh
                        4,x86_16,x86_32,x86_64,msp430,mips32b,mips32l
  abi                   ABI to used. Available: ABIStdCall_x86_32,ABIFastCall_
                        x86_32,ABI_AMD64,ABI_ARM,ABI_MIPS_O32
  address               Address of the function under test

optional arguments:
  -h, --help            show this help message and exit
  -t [TESTS [TESTS ...]], --tests [TESTS [TESTS ...]]
                        Tests to run. Available: all,ctype,string,stdlib
  -v, --verbose         Verbose mode
  -q, --quiet           Display only results
  -i TIMEOUT, --timeout TIMEOUT
                        Test timeout (in seconds)
  -m MAPPING_BASE, --mapping-base MAPPING_BASE
                        Binary mapping address
  -j JITTER, --jitter JITTER
                        Jitter engine. Available: tcc (default), llvm, python
```
An example of included tests (_stderr_ is redirected to null to avoid Miasm2 memory error warnings):

```
$ time python find.py c_tests/test_ctype x86_32 ABIStdCall_x86_32 0x8048e59 2>/dev/null
0x08048e59 : isalpha

real    0m1.311s
user    0m1.849s
sys     0m0.308s
```

### IDA stub

In order to use the _find_ida.py_ script, one needs to edit it to assign _identify_binary_ to the correct path of _find.py_.
Once the script has been loaded by _IDA_, these functions are provided:

* _identify_help()_: print help
* _identify_me(architecture, abi, options)_: candidates for current
function
* _identify_all(architecture, abi, options)_: candidates for all
functions recognized by _IDA_

An example on _busybox-i486_ (busybox 1.21.1 http://www.busybox.net/downloads/binaries/1.21.1/):

```
Python> identify_me("x86_32", "ABIStdCall_x86_32")
Launch identification on 1 function(s)
Current: 100.00% (sub_0x80572a8)| Estimated time remaining: 0.00s
0x080572a8 : strnlen
Finished ! Found 1 candidates in 1.06s
```

### Multi-ABI, multi-architecture

On **x86 32 bits**, standard ABI (_busybox-i486_ v1.21.1):
```
Python>identify_all("x86_32", "ABIStdCall_x86_32")
Launch identification on 3056 function(s)
Current: 65.45% (sub_0x80b6d8c)| Estimated time remaining: 49.80s
0x08057258 : strncmp
0x080576ac : strsep
0x08057b48 : strcmp,strncmp
0x080571cc : strchr
0x08057244 : strlen
0x08057704 : strspn
0x08057b30 : strtok
0x08057280 : strncpy
0x080571a8 : strcat
0x08057228 : strcpy
0x080572c0 : strrchr
0x0805799c : stricmp
0x08057208 : strcmp,strncmp
0x080572a8 : strnlen
0x080572ff : memcmp
0x08057ab8 : strpbrk
0x0805df1c : atoi
Current: 100.00% (sub_0x80f7a93)| Estimated time remaining: 0.00s
0x080f1cf3 : atoi
Finished ! Found 18 candidates in 145.24s

```
On **arm v6**, ARM ABI(_busybox-armv6l_ v1.21.1):
```
Python>identify_all("arml", "ABI_ARM")
Launch identification on 3063 function(s)
Current: 65.30% (sub_0xab228)| Estimated time remaining: 54.93s
0x0000a21c : strcpy
0x00020390 : strlen
0x000befd0 : strlen
0x000d9714 : strncpy
0x000d98ec : strsep
0x000d9d24 : stricmp
0x00008170 : memset
0x00051d40 : strcmp
0x000d9398 : strcat
0x000d93c0 : strchr
0x000d959c : strcpy
0x000d9604 : strncmp
Current: 100.00% (sub_0xf0354)| Estimated time remaining: 0.00s
0x000d9fe0 : strtok
0x000b7240 : isspace
0x000b7828 : ispunct
0x00008120 : memcmp
0x00008210 : strcmp
0x00008230 : strlen
0x00073c44 : bzero
0x0008c01c : bzero
0x0008d86c : isdigit
0x000d989c : strrchr
0x000d9978 : strspn
0x000d9ef8 : strpbrk
0x000da010 : strcmp
Finished ! Found 20 candidates in 195.31s

```
On **mips 32 bits LSB**, O32 ABI(_busybox-mipsel_ v1.21.1):
```
Python>identify_all("mips32l", "ABI_MIPS_O32")
Launch identification on 3065 function(s)
Current: 65.25% (sub_0x4d929c)| Estimated time remaining: 39.63s
0x0041b230 : strncmp
0x0041b630 : strspn
0x004ac138 : strcmp,strncmp
0x0041a66c : memcmp
0x0041b3c0 : strnlen
0x0041ae80 : strchr
0x0041ae40 : strcat
0x0041b0b0 : strcpy
0x0041b300 : strncpy
0x0045ec94 : strlen
0x0041b080 : strcmp,strncmp
0x0041b170 : strlen
0x0041bd50 : strpbrk
Current: 100.00% (sub_0x556a1c)| Estimated time remaining: 0.00s
0x005057c0 : isdigit
Finished ! Found 14 candidates in 113.38s

```
On **x86 64 bits**, AMD ABI(_busybox-x86_64_ v1.21.1) with some options:
```
Python>identify_all("x86_64", "ABI_AMD64", jitter="python", test_set=["ctype"])
Launch identification on 3096 function(s)
Current: 64.60% (sub_0x478459)| Estimated time remaining: 32.05s
Current: 100.00% (sub_0x4be192)| Estimated time remaining: 0.00s
0x0047cd8e : iscntrl
0x00492713 : isdigit
0x004b6032 : ispunct
0x004b5ba0 : isspace
Finished ! Found 4 candidates in 66.11s
```

Tests were run on a standard 4 cores CPU (_Sibyl_ support multiprocessing).

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


Installation
------------
_Sibyl_ requires the last version of _Miasm2_ and the corresponding version of _Elfesteem_.
_Sibyl_ comes as a package, without _setup.py_ utility for now.
One just needs to add the _Sibyl_ root directory to its _PYTHONPATH_ environment variable.

_Sibyl_ is also available through _Docker automated build_. Use:

```
$ docker run -i -t commial/sibyl
usage: find.py [-h] [-t [TESTS [TESTS ...]]] [-v] [-q] [-i TIMEOUT]
               [-m MAPPING_BASE] [-j JITTER]
               filename architecture abi address [address ...]

Function guesser

positional arguments:
  filename              File to load
  architecture          Architecture used. Available: arml,armb,armtl,armtb,sh
                        4,x86_16,x86_32,x86_64,msp430,mips32b,mips32l
  abi                   ABI to used. Available: ABIStdCall_x86_32,ABIFastCall_
                        x86_32,ABI_AMD64,ABI_ARM,ABI_MIPS_O32
  address               Address of the function under test

optional arguments:
  -h, --help            show this help message and exit
  -t [TESTS [TESTS ...]], --tests [TESTS [TESTS ...]]
                        Tests to run. Available: all,ctype,string,stdlib
  -v, --verbose         Verbose mode
  -q, --quiet           Display only results
  -i TIMEOUT, --timeout TIMEOUT
                        Test timeout (in seconds)
  -m MAPPING_BASE, --mapping-base MAPPING_BASE
                        Binary mapping address
  -j JITTER, --jitter JITTER
                        Jitter engine. Available: tcc (default), llvm, python

```

FAQ
---

### How infinite loops are managed ?

Behaviors close to infinite loop happen quite often, especially when the arguments are not formatted as expected by the function (trying another test case).
To avoid these behaviors, there is a timeout on each sub-test. The _-i/--timeout_ argument adjusts this parameter (2 by default, 0 to disable timeout).

### How to run the tool on a custom architecture ?

Once the architecture and corresponding semantic is implemented in Miasm2, one just needs to implement the wanted ABI in _sibyl/abi/_.
If writing the jitter engine part is an issue, one can directly use the _python_ jitter option with _-j/--jitter_ argument.

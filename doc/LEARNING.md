Learning
--------

### Overview

The learning module can be used to automatically create a new test from an
existing binary.  It requires:

* A binary implementing the targeted function
* At least one call to this function with working arguments
* The targeted function prototype, including involved structures

With these information, the module will run an instrumented version of the
function, and collect *semantic side effects*.

Then, these side effects are abstracted in an architecture agnostic form, close
to the C language.

During the recognition phase, this form is derived according to the expected
memory layout: structure padding, `int` size, etc.

If there are multiple calls to the function, Sibyl will apply a pruning policy
to keep the only relevant ones, according to the associated configuration.

:warning: Depending on the target binary, a few precaution should be taken;
indeed, depending on the used *tracer*, the binary might be run in an
unsandboxed environment.

### Example

Let's
use
[SoftFp, 2016/12/20 release](https://bellard.org/softfp/softfp-2016-12-20.tar.gz),
a software floating point library, as an example.

We will target a few arithmetic functions, and use the regression test
`softfptest` to retrieve calls to these functions.

#### Setup

`softfptest` is slightly modified before being used. Indeed, we only need a few
run of the main loop to obtain a fairly amount of calls to the targeted
functions. As a result, the learning process will be faster.

Function prototypes are also needed:

```C
typedef unsigned long int uint64_t;
typedef unsigned int uint32_t;

typedef uint64_t sfloat64;

typedef enum {
    RM_RNE,
    RM_RTZ,
    RM_RDN,
    RM_RUP,
    RM_RMM,
} RoundingModeEnum;


sfloat64 add_sf64(sfloat64 a, sfloat64 b, RoundingModeEnum rm, uint32_t *pfflags);
sfloat64 mul_sf64(sfloat64 a, sfloat64 b, RoundingModeEnum rm, uint32_t *pfflags);
sfloat64 div_sf64(sfloat64 a, sfloat64 b, RoundingModeEnum rm, uint32_t *pfflags);
sfloat64 sqrt_sf64(sfloat64 a, RoundingModeEnum rm, uint32_t *pfflags);
sfloat64 fma_sf64(sfloat64 a, sfloat64 b, sfloat64 c, RoundingModeEnum rm, uint32_t *pfflags);
sfloat64 min_sf64(sfloat64 a, sfloat64 b, uint32_t *pfflags);
sfloat64 max_sf64(sfloat64 a, sfloat64 b, uint32_t *pfflags);
```

Also, the *PIN tracer* has to be compiled:

```
$ cd ext/pin_tracer
$ PIN_ROOT=/opt/... make
...
```

And the configuration set accordingly (see [the associated documentation](CONFIG.md) for more detail).

#### Options

The target action is `learn`.

In this example, the *tracer* used is *PIN*, for performance reasons and because
the target binary is available on a supported architecture. In other cases, the
*Miasm* tracer is still available.

A lot of calls returns zero (due to the architecture of the regression test). To
ignore them (there are mostly irrelevant and pollute the resulting tests),
`--avoid-null` (`-z`) is used.

The result is dumped in a Python file: `-o float_{NAME}.py`.

#### Learning

The complete command line is:
```
$ sibyl learn -v -z {FUNC_NAME} softfptest soft.h -o float_{NAME}.py
```

One may notice that a few warning are displayed:
```
WARNING: argument pfflags not used?!
```

Indeed, Sibyl has detected that the `pfflags` argument seems to not be used in
any of the calls keep. This could indicate a lack of call example, a too
restrictive implementation, or a useless argument.

#### Obtained test

The resulting test looks like:
```Python
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE

from sibyl.test.test import TestHeader, TestSetTest

class Testmax_sf64(TestHeader):
    '''This is an auto-generated class, using the Sibyl learn module'''

    func = "max_sf64"
    header = '''
typedef unsigned long int uint64_t;
...
'''

    def init1(self):

        self._add_arg(0, 0) # arg0_a
        self._add_arg(1, 9218868437227405312) # arg1_b

    def check1(self):
        return all((
            # Check output value
            self._get_result() == 0x7ff0000000000000,
        ))

...
tests =  TestSetTest(init1, check1) & TestSetTest(init2, check2) & TestSetTest(init3, check3) & TestSetTest(init4, check4) & TestSetTest(init5, check5)

TESTS = [Testmax_sf64]
```

When type understanding is needed, the tests are a bit more complicated (from `mul_sf64`):
```Python
   def init2(self):
        # arg3_pfflags
        base0_ptr_size = self.field_addr("arg3_pfflags", "*(arg3_pfflags)") + self.sizeof("*(arg3_pfflags)")
        base0_ptr = self._alloc_mem(base0_ptr_size, read=True, write=True)

        self._add_arg(0, 0) # arg0_a
        self._add_arg(1, 9218868437227405312) # arg1_b
        self._add_arg(2, 0) # arg2_rm
        self._add_arg(3, base0_ptr) # arg3_pfflags

        # *(arg3_pfflags) = 0x0
        self._write_mem(base0_ptr, self.pack(0x0, self.sizeof("*(arg3_pfflags)")))

        self.base0_ptr = base0_ptr

    def check2(self):
        return all((
            # Check output value
            self._get_result() == 0x7ff8000000000000,
            # *(arg3_pfflags) == 0x10
            self._ensure_mem(self.base0_ptr, self.pack(0x10, self.sizeof("*(arg3_pfflags)"))),
        ))

```

#### Replay

Outputs are directly usable as Sibyl test. To regroup them in a common test set, one can create a Python script merging `TESTS` list from the different scripts, as:

```Python
out = []
for f in ["add", "mul", "div", "sqrt", "fma", "min", "max"]:
    execfile("float_%s_sf64.py" % f)
    out += TESTS

TESTS = out
```

To inform Sibyl about this new test set, a line is added in the configuration
(see [the associated documentation](CONFIG.md) for more detail):

```Python
[tests]
sfloat = /path/to/float.py
```

The tests are now detected by Sibyl, as stated by this command line:
```
$ sibyl config
...
	sfloat (7)
		add_sf64, mul_sf64, div_sf64, sqrt_sf64, fma_sf64, min_sf64, max_sf64
```

At this stage, they are replayable on new binaries, for instance on an obfuscated version of `softfptest`:
```
$ sibyl func softfptest.obfu | sibyl find -v -t sfloat -b ABI_AMD64_SYSTEMV softfptest.obfu -
Guessed architecture: x86_64
Found 405 addresses
Found 7 test cases
0x004330d0 : max_sf64
0x0042a9a0 : mul_sf64
0x00431e30 : min_sf64
0x0042bc90 : fma_sf64
0x00430c70 : sqrt_sf64
0x00429270 : add_sf64
0x0042ee70 : div_sf64
```

### Known limitations

The learning module has known limitations.

As mentioned in the previous section, it is necessary to have a working binary,
which call the function with valid arguments.

In addition, this binary must be *traceable*, which could not be the case,
depending on the architecture.

The limitation of Sibyl are also applied to this module; for instance and for
now, there is no support of floating argument, or ABI specificity such as
structure in-lining in arguments.

For now Sibyl does not track, and then does not support, functions using an
allocator for their semantic use (for example, a function allocating a new
structure through `malloc`).

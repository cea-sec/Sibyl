Avanced use
-----------

### Architecture selection

The architecture might be automatically recognized from the binary (for
instance, using ELF or PE information).

If not, the architecture can be specified / forced using the `--architecture`
argument of `find`.

### Mapping shift

It may happens that the file format is not correctly recognized (for instance,
in firmware), and that having the binary mapped at a specific address modify the
function behavior (ie. they use absolute address).

For these cases, the option `--mapping-base` can be used to specify a base
address for the binary mapping.

### Emulation engine
A few emulation engine are supported. Through the `--jitter` option, one can
specified:

* `python`: use a full Python emulation
* `tcc` or `gcc`: use a C compiler to JiT code (thanks to Miasm)
* `LLVM`: use LLVM JiT capabilities (thanks to Miasm)
* `qemu`: use the Unicorn (http://www.unicorn-engine.org/) QEMU binding

Empirically, the `qemu` jitter happens to be the fastest, but requires an
additionnal dependency. In addition, it may not support a custom architecture
added to Miasm.

The second fastest jitter is `gcc`, because of the repeated call to the same
function (and its cache). In addition, it requires a very common dependency.

### Function heuristic

The `sibyl func` action provides a way to find possible function addresses.  It
uses heuristics, which can be individually activated or de-activated using `-e`
and `-d` options.

For instance, the `recursive_call` heuristics may take a long time to ends,
where the `pattern_matching` one is very fast but innacurate.

The full list can be obtain in the `--help` description.

As a side note, a common, dirty, way to obtain function addresses is to use the
following one-liner in IDA console:
```Python
open("/tmp/addrs", "w").write("\n".join(hex(x).replace("L", "") for x in Functions()))
```

### Addresses specification

The targeted addresses can be specified in three ways:
* using the addresses, such as `sibyl find my_binary 0x11223344 0x22334455 12345`
* using a file, such as `sibyl find my_binary /tmp/addrs`
* using stdin, such as `sibyl func my_binary | sibyl find my_binary -`

### ABI selection

The ABI can be specified or overwritten thanks to the `--abi` option of `sibyl
find`.

If only one ABI is available for the target architecture, it will be selected
automatically. Otherwise, the command line will ask for more precision.

The choosen ABI is indicated if the verbosity level is high enough.

### Linking with other tools

Sibyl output is intended to be human readable.

But, depending on the usage, some options are provided for an easier linking:
* `sibyl find` can deliver results in JSON format (`-o JSON`)
* `sibyl config` can be requested for direct value, or possible value of a
  configuration element (`-V element`)
* the `sibyl` module can be used as an API

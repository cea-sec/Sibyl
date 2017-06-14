Configuration
-------------

### Configuration files

The default Sibyl configuration can be overwritten with configuration file.

These files are taken in account if they are located in any of the location (and
in the same order) returned by `sibyl config` when no configuration are
available:
```
$ sibyl config
No configuration file found. Supported paths:
	/etc/sibyl.conf
	/etc/sibyl/sibyl.conf
	/usr/local/etc/sibyl.conf
	/usr/local/etc/sibyl/sibyl.conf
	/home/user/sibyl.conf
	/home/user/.sibyl.conf
...
```

The resulting configuration file can be obtain through `sibyl config -d`.

### Default configuration

The default configuration is equivalent to:

```Python
[find]
jit_engine = qemu,miasm
stubs = $MIASM/os_dep/win_api_x86_32.py,$MIASM/os_dep/linux_stdlib.py

[tests]
ctype = $SIBYL/test/ctype.py
string = $SIBYL/test/string.py
stdlib = $SIBYL/test/stdlib.py

[miasm]
jit_engine = gcc,llvm,tcc,python

[pin]
root = $PIN_ROOT
tracer = $SIBYL/ext/pin_tracer/pin_tracer.so

[learn]
prune_strategy = branch
prune_keep = 1
prune_keep_max = 5

[ida]
idaq64 =
```

### Section 'find'

This section is relative to the `find` action.

The `jit_engine` parameter is a list, separated by ',', of jitter engine
preference.
If the first engine is not available, then the second is used, and so on.
The keyword `miasm` can be used to stand for the Miasm elected engine.

To known the jitter engine elected, use `sibyl config -V jit_engine`.

The `stubs` parameter is a list, separated by ',' of Python file path. These
files can implement stubs (as Python function with the correct name). These
stubs will be used to emulate external APIs, on supported jitter engines, during
the `find` action.

### Section 'tests'

This section links to available test sets. By default, only Sibyl ones are
present.

The syntax is: `name = path/to/file.py`.

The list of registered tests can be obtain withe
`sibyl config -V available_tests_keys`.

For more information on tests, please refer to the corresponding documentation.

### Section 'miasm'

This section highlights options relative to Miasm use.

The `miasm_engine` parameter is a list, separated by ',', of jitter engine
preference when Miasm is used.
If the first engine is not available, then the second is used, and so on.

To known the jitter engine elected, use `sibyl config -V miasm_engine`.

### Section 'pin'

This section contains options relative to PIN use.

The `root` parameter is the root path of the Intel Pin installation (the one
containing the `pin` binary).
By default, the environment variable `$PIN_ROOT` is used (if it exists).
If `pin` is already in the user's path, this parameter can be ignored.

The `tracer` parameter is the path of the compiled version of the tracer
`ext/pin_tracer/pin_tracer.cpp`, which will probably looks like
`/path/to/sibyl/ext/pin_tracer/pin_tracer.so`.

### Section 'learn'

This section contains options relative to the `learn` action.

The `prune_strategy` parameter indicates which strategy should be used to prune
the obtained snapshots. Current supported values are `branch`, `keep`, `keepall`.

The `prune_keep` value specifies the number of snapshot to keep per prunning.

The `prune_keep_map` value specifies the overall maximum number of snapshot to
keep. `0` means no limit.

Please refer to the related documentation for more information.

### Section 'ida'

This section contains options relative to IDA use.

The `idaq64` parameter is the path of the `idaq64` binary. It will be used to
find the executable if it is not in the `$PATH`.

### Configuration overview

Using `sibyl config` without option, one can obtain:
* the configuration file used, if any
* available configuration file paths
* elected jit engine
* loaded Tests, associated to their names

### API

Sibyl configuration is available from `sibyl.config:config`.

This `Config` instance provides:
* `jit_engine`: Name of engine to use for jit
* `available_tests`: dictionnary mapping test group name to corresponding classes

### Path handling

This rules are applied for path:
* the token `$SIBYL` can be used to point to Sibyl installation dir;
* the token `$MIASM` can be used to point to Miasm2 installation dir;
* `~` or `~user` are replaced with the `user` home directory;
* Environment variables are expanded;


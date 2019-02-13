Changelog
---------

### Version 0.2

* Land the new learning module (initial version from [@graux-pierre](https://github.com/graux-pierre))
* Add documentation on how-to-learn a function, associated principle and limits
* Mine function address from IDA in sibyl func
* Support multiple strategy for trace pruning
* Add support for API stubbing
* Radare2 find script from [@m-1-k-3](https://github.com/m-1-k-3)
* Toshiba MeP support from [@guedou](https://github.com/guedou)

Minors :

* Various fixes from [@serpilliere](https://github.com/serpilliere)
* Reflect API changes for Miasm v0.1.1
* Add configuration associated with PIN (PIN_ROOT + tracer path)
* Add regression tests for the learning module
* Support expanduser in config
* Restrict `bzero` implementation to avoid false positive
* Adds support for function returning a non-allocated pointer

### Version 0.1

This is the initial release, including:

* Sibyl as a Python module
* CLI `sibyl`
* IDA stub
* Configuration management
* Support for Miasm, QEMU engine
* Support for a few ABI
* Support for a few functions of _string.h_, _ctype.h_ and _stdlib.h_
* Regression tests
* PoC of a learning module
* Documentation

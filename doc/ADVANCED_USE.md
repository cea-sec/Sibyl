TODO:
- architecture selection
- mapping shift
- abi selection
- func heuristic
- emulation engine
- address input



### Emulation engine
A few emulation engine are supported. Through the `--jitter` option, one can
specified:

* `python`: use a full Python emulation
* `tcc` or `gcc`: use a C compiler to JiT code (thanks to Miasm)
* `LLVM` TODO
* `qemu`: use the Unicorn (http://www.unicorn-engine.org/) QEMU binding


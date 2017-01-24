ifneq ("$(PIN_ROOT)", "")
	CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
	include $(CONFIG_ROOT)/makefile.config
	include $(TOOLS_ROOT)/Config/makefile.default.rules
endif

all: intel64

intel64:
ifeq ("$(PIN_ROOT)", "")
 # PIN_ROOT has to point the root directory of pin-3.0-76991-gcc-linux
	$(error PIN_ROOT variable is not set)
endif
	$(MAKE) TARGET=intel64 obj-intel64/pin_tracer.so
	mv obj-intel64/pin_tracer.so .

clean:
	rm -rf obj-intel64 pin_tracer.so

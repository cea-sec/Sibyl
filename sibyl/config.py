# This file is part of Sibyl.
# Copyright 2014 - 2017 Camille MOUGEY <camille.mougey@cea.fr>
#
# Sibyl is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Sibyl is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Sibyl. If not, see <http://www.gnu.org/licenses/>.
"""Configuration handling"""

import os
import ConfigParser

default_config = {
    "jit_engine": ["qemu", "miasm"],
    "miasm_engine": ["gcc", "llvm", "tcc", "python"],
    "tests": {"string": "$SIBYL/test/string.py",
              "stdlib": "$SIBYL/test/stdlib.py",
              "ctype": "$SIBYL/test/ctype.py",
    },
    "pin_root": os.environ.get("PIN_ROOT", ""),
}

config_paths = [os.path.join(path, 'sibyl.conf')
                for path in ['/etc', '/etc/sibyl', '/usr/local/etc',
                             '/usr/local/etc/sibyl']]
if os.getenv("HOME"):
    config_paths += [os.path.join(os.getenv("HOME"), 'sibyl.conf'),
                     os.path.join(os.getenv("HOME"), '.sibyl.conf')]

class Config(object):
    """Configuration wrapper"""

    def __init__(self, default_config, files):
        """Init the configuration wrapper
        @default_config: dict
        @files: list of files
        """
        self.config = dict(default_config)

        # Update from files
        self.parse_files(files)

        # Init caches
        self._jit_engine = None
        self._miasm_engine = None
        self._available_tests = None

    def parse_files(self, files):
        """Load configuration from @files (which could not exist)"""
        cparser = ConfigParser.SafeConfigParser()
        cparser.read(files)

        config = {}
        # Find
        if cparser.has_section("find"):

            # jit_engine = qemu,llvm,gcc
            if cparser.has_option("find", "jit_engine"):
                self.config["jit_engine"] = cparser.get("find", "jit_engine").split(",")

        # Tests
        #
        # [tests]
        # name = path/to/source.py
        if cparser.has_section("tests"):
            for name in cparser.options("tests"):
                self.config["tests"][name] = cparser.get("tests", name)

        # Miasm
        #
        # [miasm]
        if cparser.has_section("miasm"):
            # jit_engine = llvm,gcc
            if cparser.has_option("miasm", "jit_engine"):
                self.config["miasm_engine"] = cparser.get("miasm", "jit_engine").split(",")

        # PIN
        #
        # [pin]
        if cparser.has_section("pin"):
            # root = /path
            if cparser.has_option("pin", "root"):
                self.config["pin_root"] = cparser.get("pin", "root")

    def dump(self):
        """Dump the current configuration as a config file"""
        out = []

        # Find
        out.append("[find]")
        out.append("jit_engine = %s" % ",".join(self.config["jit_engine"]))

        # Tests
        out.append("")
        out.append("[tests]")
        for name, path in self.config["tests"].iteritems():
            out.append("%s = %s" % (name, path))

        # Miasm
        out.append("")
        out.append("[miasm]")
        out.append("jit_engine = %s" % ",".join(self.config["miasm_engine"]))

        # Pin
        out.append("")
        out.append("[pin]")
        out.append("root = %s" % self.config["pin_root"])

        return out

    @property
    def jit_engine(self):
        """Name of engine to use for jit"""
        # Cache
        if self._jit_engine is not None:
            return self._jit_engine

        # Try to resolve jitter by preference order
        for engine in self.config["jit_engine"]:
            if engine == "qemu":
                # Do not include from 'sibyl.engine.qemu' to avoid include loops
                try:
                    import unicorn
                except ImportError:
                    continue
            elif engine == "miasm":
                try:
                    engine = self.miasm_engine
                except RuntimeError:
                    continue
            break
        else:
            raise RuntimeError("Cannot found a supported jitter")

        self._jit_engine = engine
        return engine

    @property
    def available_tests(self):
        """Return a dictionnary mapping test group name to corresponding
        classes"""
        # Cache
        if self._available_tests is not None:
            return self._available_tests

        available_tests = {}
        # Fetch tests from files
        import sibyl
        sibyl_base = sibyl.__path__[0]

        for name, fpath in self.config["tests"].iteritems():
            # Keyword
            fpath = fpath.replace("$SIBYL", sibyl_base)

            # Get TESTS
            context = {}
            execfile(fpath, context)
            available_tests[name] = context["TESTS"]

        self._available_tests = available_tests
        return self._available_tests

    @property
    def miasm_engine(self):
        """Name of engine to use for Miasm relative tasks"""
        # Cache
        if self._miasm_engine is not None:
            return self._miasm_engine

        # Try to resolve jitter by preference order
        for engine in self.config["miasm_engine"]:
            if engine == "llvm":
                try:
                    import llvmlite
                except ImportError:
                    continue
            break
        else:
            raise RuntimeError("Cannot found a support jitter")

        self._miasm_engine = engine
        return engine

    @property
    def pin_root(self):
        """Base path of Intel PIN install"""
        return self.config["pin_root"]


config = Config(default_config, config_paths)

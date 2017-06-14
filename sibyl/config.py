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
    "pin_root": "$PIN_ROOT",
    "pin_tracer": "$SIBYL/ext/pin_tracer/pin_tracer.so",
    "prune_strategy": "branch",
    "prune_keep": 1,
    "prune_keep_max": 5,
    "stubs": ["$MIASM/os_dep/win_api_x86_32.py",
              "$MIASM/os_dep/linux_stdlib.py",
    ],
    "idaq64_path": "",
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

    @staticmethod
    def expandpath(path):
        """Expand @path with following rules:
        - $SIBYL is replaced by the installation path of Sibyl
        - $MIASM is replaced by the installation path of miasm2
        - path are expanded ('~' -> '/home/user', ...)
        """
        if "$SIBYL" in path:
            import sibyl
            sibyl_base = sibyl.__path__[0]
            path = path.replace("$SIBYL", sibyl_base)

        if "$MIASM" in path:
            import miasm2
            miasm2_base = miasm2.__path__[0]
            path = path.replace("$MIASM", miasm2_base)

        path = os.path.expandvars(path)
        path = os.path.expanduser(path)

        return path

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

            # stubs = $MIASM/file.py,$MIASM/file2.py
            if cparser.has_option("find", "stubs"):
                self.config["stubs"] = cparser.get("find", "stubs").split(",")

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
            # tracer = /path/to/lib.so
            if cparser.has_option("pin", "tracer"):
                self.config["pin_tracer"] = cparser.get("pin", "tracer")

        # Learning
        #
        # [learn]
        if cparser.has_section("learn"):
            # prune_strategy = branch
            if cparser.has_option("learn", "prune_strategy"):
                self.config["prune_strategy"] = cparser.get("learn",
                                                            "prune_strategy")
            # prune_keep = 1
            if cparser.has_option("learn", "prune_keep"):
                self.config["prune_keep"] = cparser.getint("learn",
                                                           "prune_keep")
            # prune_keep_max = 5
            if cparser.has_option("learn", "prune_keep_max"):
                self.config["prune_keep"] = cparser.getint("learn",
                                                           "prune_keep_max")

        # IDA
        #
        # [ida]
        if cparser.has_section("ida"):
            # idaq64 = /path/to/idaq64
            if cparser.has_option("ida", "idaq64"):
                self.config["idaq64_path"] = cparser.get("ida", "idaq64")


    def dump(self):
        """Dump the current configuration as a config file"""
        out = []

        # Find
        out.append("[find]")
        out.append("jit_engine = %s" % ",".join(self.config["jit_engine"]))
        out.append("stubs = %s" % ",".join(self.config["stubs"]))

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
        out.append("tracer = %s" % self.config["pin_tracer"])

        # Learn
        out.append("")
        out.append("[learn]")
        out.append("prune_strategy = %s" % self.config["prune_strategy"])
        out.append("prune_keep = %d" % self.config["prune_keep"])
        out.append("prune_keep_max = %d" % self.config["prune_keep_max"])

        # IDA
        out.append("")
        out.append("[ida]")
        out.append("idaq64 = %s" % self.config["idaq64_path"])

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

        # Fetch tests from files
        available_tests = {}
        for name, fpath in self.config["tests"].iteritems():
            fpath = self.expandpath(fpath)

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
        path = self.expandpath(self.config["pin_root"])
        return path if path != "$PIN_ROOT" else ""

    @property
    def pin_tracer(self):
        """PIN-tool to use for tracing
        It should be the compiled version of ext/pin_tracer/pin_tracer.cpp
        """
        return self.expandpath(self.config["pin_tracer"])

    @property
    def prune_strategy(self):
        """Strategy used to prune while learning"""
        strategy = self.config["prune_strategy"]
        if strategy not in [
                "branch",
                "keepall",
                "keep",
        ]:
            raise ValueError("Unknown strategy type: %s" % strategy)
        return strategy

    @property
    def prune_keep(self):
        """Number of elements to keep for each pruning possibility"""
        return self.config["prune_keep"]

    @property
    def prune_keep_max(self):
        """Maximum number of snapshot to keep while pruning"""
        return self.config["prune_keep_max"]

    @property
    def stubs(self):
        """List of paths to Python files implementing API stubs"""
        return [path
                for path in (self.expandpath(path)
                             for path in self.config["stubs"])
                if os.path.exists(path)]

    @property
    def idaq64_path(self):
        """Path of idaq64 binary, from config or PATH"""
        # Use custom value first
        if self.config["idaq64_path"]:
            path = self.expandpath(self.config["idaq64"])
            if os.path.exists(path):
                return path

        # Try to find in $PATH
        for path in os.environ["PATH"].split(os.pathsep):
            path = os.path.join(path.strip('"'), "idaq64")
            if os.path.exists(path):
                return path

        return None

config = Config(default_config, config_paths)

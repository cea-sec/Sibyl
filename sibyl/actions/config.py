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

import os

from sibyl.config import config, config_paths
from sibyl.actions.action import Action


class ActionConfig(Action):
    """Configuration management"""

    _name_ = "config"
    _desc_ = "Configuration management"
    _args_ = [
        (("-V", "--value"), {"help": "Return the value of a specific option"}),
        (("-d", "--dump"), {"help": "Dump the current configuration",
                            "action": "store_true"}),
    ]

    def run(self):
        if self.args.dump:
            print "\n".join(config.dump())
        elif self.args.value:
            if self.args.value.endswith("_keys") and hasattr(config,
                                                             self.args.value[:-5]):
                val = getattr(config, self.args.value[:-5]).keys()
            elif hasattr(config, self.args.value):
                val = getattr(config, self.args.value)
            else:
                val = "ERROR"
            print val
        else:
            self.show()

    def show(self):
        # Configuration files
        files = [fpath for fpath in config_paths if os.path.isfile(fpath)]
        if not files:
            print "No configuration file found. Supported paths:"
            print "\t" + "\n\t".join(config_paths)
        else:
            print "Configuration loaded from %s" % ", ".join(files)

        # Jitter engine
        engines = config.config["jit_engine"]
        if "miasm" in engines:
            idx = engines.index("miasm")
            engines[idx:idx + 1] = config.config["miasm_engine"]
        print "Jitter engine (preference order): %s" % ", ".join(engines)
        print "Elected jitter engine: %s" % config.jit_engine

        # Stubbing
        stubs = config.stubs
        if stubs:
            print "API stubbing activated on supported jitter, from %d files" % len(stubs)
        else:
            print "API stubbing is deactivated"

        # PIN
        if (config.pin_root and
            os.path.exists(os.path.join(config.pin_root, "pin"))):
            print "PIN root path found at: %s" % config.pin_root
        else:
            print "PIN root path not found"
        if (config.pin_tracer and
            os.path.exists(config.pin_tracer)):
            print "PIN tracer found at: %s" % config.pin_tracer
        else:
            print "PIN tracer not found"

        # Learn
        print "Learn's pruning strategy: %s/%d/%d" % (config.prune_strategy,
                                                      config.prune_keep,
                                                      config.prune_keep_max)

        # IDA
        idaq64_path = config.idaq64_path
        if idaq64_path:
            "IDA has been found at: %s" % idaq64_path
        else:
            print "IDA has been not found"

        # Tests
        print "Tests availables:"
        for name, tests in config.available_tests.iteritems():
            print "\t%s (%d)" % (name, len(tests))
            print "\t\t" + ", ".join(test.func for test in tests)

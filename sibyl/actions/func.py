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

from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container

from sibyl.config import config, config_paths
from sibyl.actions.action import Action
from sibyl.heuristics.func import FuncHeuristic, ida_funcs
from sibyl.heuristics.arch import ArchHeuristic


heur_names = FuncHeuristic(None, None, "").heuristic_names

class ActionFunc(Action):
    """Function discovering"""

    _name_ = "func"
    _desc_ = "Function discovering"
    _args_ = [
        # Mandatory
        (["filename"], {"help": "File to load"}),
        # Optional
        (["-a", "--architecture"], {"help": "Target architecture",
                                    "choices": Machine.available_machine()}),
        (["-v", "--verbose"], {"help": "Verbose mode",
                               "action": "store_true"}),
        (["-d", "--disable-heuristic"], {"help": "Disable an heuristic",
                                         "action": "append",
                                         "choices": heur_names,
                                         "default": []}),
        (["-e", "--enable-heuristic"], {"help": "Enable an heuristic",
                                        "action": "append",
                                        "choices": heur_names,
                                        "default": []}),
    ]

    def run(self):
        # Architecture
        architecture = False
        if self.args.architecture:
            architecture = self.args.architecture
        else:
            with open(self.args.filename) as fdesc:
                architecture = ArchHeuristic(fdesc).guess()
            if not architecture:
                raise ValueError("Unable to recognize the architecture, please specify it")
            if self.args.verbose:
                print "Guessed architecture: %s" % architecture

        cont = Container.from_stream(open(self.args.filename))
        machine = Machine(architecture)
        addr_size = machine.ira().pc.size / 4
        fh = FuncHeuristic(cont, machine, self.args.filename)

        # Default: force only IDA if available
        if config.idaq64_path:
            fh.heuristics = [ida_funcs]

        # Enable / disable heuristics
        for name in self.args.enable_heuristic:
            heur = fh.name2heuristic(name)
            if heur not in fh.heuristics:
                fh.heuristics.append(heur)
        for name in self.args.disable_heuristic:
            heur = fh.name2heuristic(name)
            fh.heuristics.remove(heur)

        if self.args.verbose:
            print "Heuristics to run: %s" % ", ".join(fh.heuristic_names)


        # Launch guess
        fmt = "0x{:0%dx}" % addr_size
        for addr in fh.guess():
            print fmt.format(addr)

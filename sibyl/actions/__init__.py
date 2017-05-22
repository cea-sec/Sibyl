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
"Sibyl actions implementations"

from collections import namedtuple
from importlib import import_module

ActionDesc = namedtuple("ActionDesc", ["name", "desc", "module", "classname"])

ACTIONS = [
    ActionDesc("config", "Configuration management", "config", "ActionConfig"),
    ActionDesc("find", "Function guesser", "find", "ActionFind"),
    ActionDesc("func", "Function discovering", "func", "ActionFunc"),
    ActionDesc("learn", "Learn a new function", "learn", "ActionLearn"),
]

def load_action(actiondesc, args):
    "Load the action associated to @actiondesc with arguments @args"
    mod = import_module(".%s" % actiondesc.module, "sibyl.actions")
    return getattr(mod, actiondesc.classname)(args)

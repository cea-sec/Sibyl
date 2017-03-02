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
import sys
import argparse

class Action(object):

    "Parent class for actions"

    _name_ = ""
    _desc_ = ""
    _args_ = []  # List of (*args, **kwargs)

    def __init__(self, command_line):
        # Parse command line
        parser = argparse.ArgumentParser(
            prog="%s %s" % (sys.argv[0], self._name_))
        for args, kwargs in self._args_:
            parser.add_argument(*args, **kwargs)
        self.args = parser.parse_args(command_line)

        # Run action
        self.run()

    def run(self):
        raise NotImplementedError("Abstract method")

    @property
    def name(self):
        """Action name"""
        return self._name_

    @property
    def description(self):
        """Action description"""
        return self._desc_

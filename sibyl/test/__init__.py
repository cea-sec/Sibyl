# This file is part of Sibyl.
# Copyright 2014 Camille MOUGEY <camille.mougey@cea.fr>
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


from sibyl.test.string import TESTS as TESTS_STRING
from sibyl.test.stdlib import TESTS as TESTS_STDLIB
from sibyl.test.ctype import TESTS as TESTS_CTYPE
AVAILABLE_TESTS = {"string" : TESTS_STRING,
                   "stdlib" : TESTS_STDLIB,
                   "ctype"  : TESTS_CTYPE}
__all__ = ["AVAILABLE_TESTS"]

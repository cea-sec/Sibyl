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

CC := gcc
CFLAGS := -m32 -O0 --static
PROGRAMS := test_string test_stdlib test_ctype test_stub

all: $(PROGRAMS)

.c.c:
	$(CC) $(CFLAGS) $< -o $@

test_string: test_string.c
test_stdlib: test_stdlib.c
test_ctype: test_ctype.c
test_stub: test_stub.c
	$(CC) -m32 -O0 $< -o $@



clean:
	rm -f $(PROGRAMS)

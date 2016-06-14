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


from sibyl.test.test import Test, TestSetGenerator


class TestIsCharset(Test):
    """Test for character classification routines:
    isalnum,  isalpha,  isascii,  isblank,  iscntrl,  isdigit, isgraph, islower,
    isprint, ispunct, isspace, isupper, isxdigit

    Decision tree:
    g
    |-- 0                                                             (return 1)
    |   |--
    |   |   |-- !
    |   |   |   |-- isalnum
    |   |   |   `-- isgraph
    |   |    -- \\x00
    |   |       |-- isascii
    |   |       `-- isprint
    |   `-- A
    |       |-- isalpha
    |       `-- islower
    `-- \\t                                                           (return 0)
        |--
        |   |-- iscntrl
        |   `-- \\n
        |       |-- isblank
        |       `-- isspace
        `-- A
            |-- 0
            |   |-- isupper
            |   `-- isxdigit
            `-- 0
                |-- ispunct
                `-- isdigit
    """

    def reset_full(self, *args, **kwargs):
        super(TestIsCharset, self).reset_full(*args, **kwargs)
        # Reset tests tree
        self.cur_tree = self.decision_tree
        self.next_test = self.cur_tree["t"]
        self.tests = TestSetGenerator(self.test_iter())

    def reset(self, *args, **kwargs):
        super(TestIsCharset, self).reset_full(*args, **kwargs)

    def check_gen(self, result=None):
        if result == None:
            result = self._get_result()

        # Returned values should be 0 or 1
        if result not in [0, 1]:
            return False

        # Browse decision tree
        key = "g" if result == 1 else "b"
        next_tree = self.cur_tree[key]

        if next_tree is False:
            # No more candidate
            return False
        elif isinstance(next_tree, str):
            # Candidate found
            self.func = next_tree
            self.next_test = None
            return True
        elif isinstance(next_tree, dict):
            # Browse next candidates
            self.cur_tree = next_tree
            self.next_test = self.cur_tree["t"]
            return True
        raise ValueError("Impossible tree value")

    def test_iter(self):
        while self.next_test:
            yield self.next_test
        raise StopIteration()

    def init_notascii(self):
        self._add_arg(0, 255)

    def init_g(self):
        self._add_arg(0, ord('g'))

    def init_0(self):
        self._add_arg(0, ord('0'))

    def init_space(self):
        self._add_arg(0, ord(' '))

    def init_x00(self):
        self._add_arg(0, 0)

    def init_exclam(self):
        self._add_arg(0, ord('!'))

    def init_A(self):
        self._add_arg(0, ord('A'))

    def init_tab(self):
        self._add_arg(0, ord('\t'))

    def init_ret(self):
        self._add_arg(0, ord('\n'))

    def init_punct(self):
        self._add_arg(0, ord('.'))

    decision_tree = {"t": (init_notascii, check_gen),
                     "g": False, # Increase mean cost
                     "b": {"t": (init_g, check_gen),
                           "g": {"t": (init_0, check_gen),
                                 "g": {"t": (init_space, check_gen),
                                       "g": {"t": (init_x00, check_gen),
                                             "g": "isascii",
                                             "b": "isprint"
                                             },
                                       "b": {"t": (init_exclam, check_gen),
                                             "g": "isgraph",
                                             "b": "isalnum"
                                             },
                                       },
                                 "b": {"t": (init_A, check_gen),
                                       "g": "isalpha",
                                       "b": "islower"
                                       },
                                 },
                           "b": {"t": (init_tab, check_gen),
                                 "g": {"t": (init_space, check_gen),
                                       "g": {"t": (init_ret, check_gen),
                                             "g": "isspace",
                                             "b": "isblank"
                                             },
                                       "b": "iscntrl"
                                       },
                                 "b": {"t": (init_A, check_gen),
                                       "g": {"t": (init_0, check_gen),
                                             "g": "isxdigit",
                                             "b": "isupper"
                                             },
                                       "b": {"t": (init_0, check_gen),
                                             "g": "isdigit",
                                             "b": {"t": (init_punct, check_gen),
                                                   "g": "ispunct",
                                                   "b": False
                                                   # Avoid false positive
                                                   },
                                             },
                                       },
                                 },
                           }
                     }

TESTS = [TestIsCharset]

from sibyl.test.string import TESTS as TESTS_STRING
from sibyl.test.stdlib import TESTS as TESTS_STDLIB
from sibyl.test.ctype import TESTS as TESTS_CTYPE
AVAILABLE_TESTS = {"string" : TESTS_STRING,
                   "stdlib" : TESTS_STDLIB,
                   "ctype"  : TESTS_CTYPE}
__all__ = ["AVAILABLE_TESTS"]

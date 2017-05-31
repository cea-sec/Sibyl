# Python
imports = """
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE

from sibyl.test.test import TestHeader, TestSetTest
""".strip()

classDef = """
class Test{funcname}(TestHeader):
    '''This is an auto-generated class, using the Sibyl learn module'''
"""

classAttrib = """    func = "{funcname}"
    header = '''
{header}
'''
""".rstrip()

classTestList = """
tests = {testList}
""".strip()

registerTest = """
TESTS = [Test{funcname}]
""".strip()

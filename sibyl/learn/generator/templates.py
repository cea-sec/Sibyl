# Python
imports = """
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.expression.simplifications import expr_simp
from miasm2.core.objc import CTypesManagerNotPacked, CHandler
from miasm2.core.ctypesmngr import CAstTypes
from miasm2.arch.x86.ctype import CTypeAMD64_unk

from sibyl.test.test import Test, TestSetTest
from sibyl.commons import HeaderFile
""".strip()

testHeaderCls = """
class TestHeader(Test):

    header = None

    def __init__(self, *args, **kwargs):
        super(TestHeader, self).__init__(*args, **kwargs)
        ctype_manager = CTypesManagerNotPacked(CAstTypes(), CTypeAMD64_unk())

        hdr = HeaderFile(self.header, ctype_manager)
        proto = hdr.functions[self.func]
        self.c_handler = CHandler(hdr.ctype_manager,
                                  {'arg%d_%s' % (i, name): proto.args[name]
                                   for i, name in enumerate(proto.args_order)})
        self.cache_sizeof = {}
        self.cache_trad = {}
        self.cache_field_addr = {}

    def sizeof(self, Clike):
        ret = self.cache_sizeof.get(Clike, None)
        if ret is None:
            ret = self.c_handler.c_to_type(Clike).size * 8
            self.cache_sizeof[Clike] = ret
        return ret

    def trad(self, Clike):
        ret = self.cache_trad.get(Clike, None)
        if ret is None:
            ret = self.c_handler.c_to_expr(Clike)
            self.cache_trad[Clike] = ret
        return ret

    def field_addr(self, base, Clike):
        base_expr = self.trad(base)
        access_expr = self.trad("&(%s)" % Clike)
        offset = int(expr_simp(access_expr - base_expr))
        return offset
"""

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

"""Common / shared elements"""
import logging
try:
    import pycparser
except ImportError:
    pycparser = None
else:
    from miasm2.core.ctypesmngr import c_to_ast, CTypeFunc
    from miasm2.core.objc import ObjCPtr, ObjCArray

def init_logger(name):
    logger = logging.getLogger(name)

    console_handler = logging.StreamHandler()
    log_format = "%(levelname)-5s: %(message)s"
    console_handler.setFormatter(logging.Formatter(log_format))
    logger.addHandler(console_handler)

    logger.setLevel(logging.ERROR)
    return logger


class TimeoutException(Exception):
    """Exception to be called on timeouts"""
    pass


END_ADDR = 0x1337babe

def print_table(ligs, title=True, separator='|', level=0, align=""):
    "Print nicely @ligs. If title, @ligs[0] is title ligne"
    # Calc max by col
    columns = [0] * len(ligs[0])
    for lig in ligs:
        for index, element in enumerate(lig):
            columns[index] = max(columns[index], len(element))

    fmt_l = ["{%d:%s%d}" % (i, align, l + 2) for i, l in enumerate(columns)]
    fmt = separator.join(fmt_l)

    tab = "\t" * level

    for i, lig in enumerate(ligs):
        if i == 1 and title:
            print "%s%s" % (tab, "-" * len(fmt.format(*lig)))
        print "%s%s" % (tab, fmt.format(*lig))

class HeaderFile(object):
    """Abstract representation of a Header file"""

    def __init__(self, header_data, ctype_manager):
        """Parse @header_data to fill @ctype_manager
        @header_data: str of a C-like header file
        @ctype_manager: miasm2.core.objc.CTypesManager instance"""
        self.data = header_data
        self.ctype_manager = ctype_manager

        self.ast = self.parse_header(header_data)
        self.ctype_manager.types_ast.add_c_decl(header_data)
        self.functions = {} # function name -> FuncPrototype

        if pycparser is None:
            raise ImportError("pycparser module is needed to parse header file")
        self.parse_functions()

    @staticmethod
    def parse_header(header_data):
        """Return the AST corresponding to @header_data
        @header_data: str of a C-like header file
        """
        # We can't use add_c_decl, because we need the AST to get back
        # function's arguments name
        parser = pycparser.c_parser.CParser()
        return c_to_ast(parser, header_data)

    def parse_functions(self):
        """Search for function declarations"""

        for ext in self.ast.ext:
            if not (isinstance(ext, pycparser.c_ast.Decl) and
                    isinstance(ext.type, (pycparser.c_ast.FuncDecl,
                                          pycparser.c_ast.FuncDef))):
                continue
            func_name = ext.name
            objc_func = self.ctype_manager.get_objc(CTypeFunc(func_name))

            args_order = []
            args = {}
            for i, param in enumerate(ext.type.args.params):
                args_order.append(param.name)
                args[param.name] = objc_func.args[i][1]

            self.functions[func_name] = FuncPrototype(func_name,
                                                      objc_func.type_ret,
                                                      *args_order, **args)

def objc_is_dereferenceable(target_type):
    """Return True if target_type may be used as a pointer
    @target_type: ObjC"""
    return isinstance(target_type, (ObjCPtr, ObjCArray))


class FuncPrototype(object):
    """Stand for a function's prototype"""

    def __init__(self, func_name, func_type, *args, **kwargs):
        """Init a prototype for @func_type @func_name(@kwargs (name -> type) )
        """
        self.func_name = func_name
        self.func_type = func_type
        self.args = kwargs
        self.args_order = args

    def __str__(self):
        return "%s %s(%s)" % (self.func_type,
                              self.func_name,
                              ", ".join("%s %s" % (self.args[name], name)
                                        for name in self.args_order))

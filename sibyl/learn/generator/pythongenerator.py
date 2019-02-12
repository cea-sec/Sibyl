import struct
from sibyl.learn.generator.generator import Generator
from sibyl.learn.generator import templates as TPL
from sibyl.learn.trace import MemoryAccess
from miasm2.ir.ir import AssignBlock

from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.expression.expression import *
from miasm2.expression.simplifications import expr_simp

from sibyl.commons import objc_is_dereferenceable

initDefTemplate = '''def __init__(self, *args, **kwargs):
    super(Test{funcname}, self).__init__(*args, **kwargs)
    {printedException}
'''

testListElem = " TestSetTest(init{0}, check{0}) "

funcDefTemplate = "def {}{}(self):\n"

memoryAllocTemplate = '''
# Memory allocation
allocList = [{allocList}]
segSize = [{segSize}]
self.segBase{n} = []

for size in segSize:
    self.segBase{n}.append(self._reserv_mem(size))

for ((offset, segment), value, accessRight) in allocList:
    self.jitter.vm.add_memory_page(offset + self.segBase{n}[segment], accessRight, value)
'''
refUpdateTemplate = '''
# Reference update
refs = {refs}
for (offset, seg), ref in refs.iteritems():
    newAddr = offset + self.segBase{n}[seg]
    for (writenOffset, writenSeg) in ref:
        writenAddr = writenOffset + self.segBase{n}[writenSeg]
        self._write_mem( writenAddr, self.pack(newAddr, self.abi.ira.sizeof_pointer()))
'''
argInitTemplate = '''
# Argument initialization
argList = [{argList}]
for i, arg in enumerate(argList):
    if isinstance(arg, tuple):
        self._add_arg(i, int(arg[0] + self.segBase{n}[arg[1]]))
    else:
        self._add_arg(i, int(arg))
'''

checkResultTemplate = '''result = self._to_int(self._get_result())

expectedResult = {expectedResult}
if isinstance(expectedResult, tuple):
    expectedResult = expectedResult[0] + self.segBase{n}[expectedResult[1]]

ret = (result == expectedResult)
'''

# WARNING: any change to checkAllocWithoutRefTemplate have to be reported to checkAllocWithRefTemplate
checkAllocWithoutRefTemplate = '''
addrList = {addrList}

ret = ret and all([self._ensure_mem(offset + self.segBase{n}[segment], data) for ((offset, segment),data) in addrList])
'''

# WARNING: any change to checkAllocWithRefTemplate have to be reported to checkAllocWithoutRefTemplate
checkAllocWithRefTemplate = '''
addrList = {addrList}

refs = {refs}
ptrSize = self.abi.ira.sizeof_pointer()
for (offsetRef, segRef), ref in refs.iteritems():
    newData = self.pack(offsetRef + self.segBase{n}[segRef], ptrSize)
    for (writenOffset, writenSeg) in ref:
        for i, ((offsetA, segA), data) in enumerate(addrList):
            if segA == writenSeg and (offsetA <= writenOffset < offsetA + len(data)):
                data = data[0:writenOffset-offsetA] + newData + data[writenOffset-offsetA+ptrSize/8:]
                addrList[i] = ((offsetA, segA), data)

ret = ret and all([self._ensure_mem(offset + self.segBase{n}[segment], data) for ((offset, segment),data) in addrList])
'''


def my_unpack(value):
    return struct.unpack('@P', value)[0]


def argListStr(t):
    '''Return a string representing t which can be a tuple or an int'''
    return "(0x%x, %i)" % (t[0], t[1]) if isinstance(t, tuple) else str(t)


def accessToStr(access):
    '''Return a string representing the access right given in argument'''
    ret = ""
    if access & PAGE_READ:
        ret += "PAGE_READ | "
    if access & PAGE_WRITE:
        ret += "PAGE_WRITE"
    return ret.rstrip(" |")


def addrTupleStr(t):
    '''Return a string representing the memory aera given in argument'''
    ((offset, seg), value, access) = t
    return "((0x%x, %i), %r, %s)" % (offset, seg, value, accessToStr(access))


class PythonGenerator(Generator):

    def generate_test(self):
        self.printer.add_block(TPL.imports)
        self.printer.add_empty_line()

        self.printer.add_block(TPL.classDef.format(funcname=self.prototype.func_name))
        self.printer.add_empty_line()

        self.printer.add_block(TPL.classAttrib.format(funcname=self.prototype.func_name,
                                                      header=self.headerfile.data.strip()))
        self.printer.add_empty_line()
        self.printer.add_lvl()

        if self.learnexceptiontext:
            printedException = ('print "' + "\\n".join(["REPLAY ERROR: " + e for e in self.learnexceptiontext]) + '"')

            self.printer.add_block(initDefTemplate.format(funcname=self.prototype.func_name, printedException=printedException))

        for i, snapshot in enumerate(self.trace, 1):
            self.printer.add_empty_line()
            self.generate_init(snapshot, i)
            self.printer.add_empty_line()
            self.generate_check(snapshot, i)
            self.printer.add_empty_line()

        self.printer.add_empty_line()
        testList = "&".join([testListElem.format(i)
                             for i in xrange(1, len(self.trace) + 1)])
        self.printer.add_block(TPL.classTestList.format(testList=testList))

        self.printer.add_empty_line()
        self.printer.sub_lvl()
        self.printer.add_empty_line()
        self.printer.add_block(TPL.registerTest.format(funcname=self.prototype.func_name))

        return self.printer.dump()

    def sanitize_memory_accesses(self, memories, c_handler, expr_type_from_C):
        """Modify memory accesses to consider only access on "full final element"
        Example:
        struct T{
            int a;
            int b;
            int *c;
        }

        @8[T + 2] = X -> @32[T] = 00 X 00 00
        @32[T + 2] = WW XX YY ZZ -> @32[T] = 00 00 WW XX, @32[T + 4] = YY ZZ 00 00

        @memories: AssignBlock
        @ctype_manager: CHandler with argument types
        @expr_type_from_C: Name -> ObjC dict, for C -> Expr generation

        Return sanitized access, filled memory cases {Full access -> [offset filled]}
        """

        # First, identify involved fields
        fields = set()
        atomic_values = {}
        for dst, value in memories.iteritems():
            assert isinstance(dst, ExprMem)
            addr_expr = dst.ptr
            for i in xrange(dst.size / 8):
                # Split in atomic access
                offset = ExprInt(i, addr_expr.size)
                sub_addr_expr = expr_simp(addr_expr + offset)
                mem_access = ExprMem(sub_addr_expr, 8)
                value_access = expr_simp(value[i * 8:(i + 1) * 8])

                # Keep atomic value
                atomic_values[mem_access] = value_access

                # Convert atomic access -> fields access -> Expr access on the
                # full field
                info_C = list(c_handler.expr_to_c(mem_access))
                assert len(info_C) == 1

                if "__PAD__" in info_C[0]:
                    # This is a field used for padding, ignore it
                    continue

                expr_sanitize = expr_simp(c_handler.c_to_expr(info_C[0], expr_type_from_C))

                # Conserve the involved field
                fields.add(expr_sanitize)

        # Second, rebuild the fields values
        filled_memory = {}
        out = {}
        for dst in fields:
            assert isinstance(dst, ExprMem)
            accumulator = []
            addr_expr = dst.ptr
            for i in reversed(xrange(dst.size / 8)):
                # Split in atomic access
                offset = ExprInt(i, addr_expr.size)
                sub_addr_expr = expr_simp(addr_expr + offset)
                mem_access = ExprMem(sub_addr_expr, 8)

                # Get the value, or complete with 0
                if mem_access not in atomic_values:
                    value = ExprInt(0, 8)
                    filled_memory.setdefault(dst, []).append(offset)
                else:
                    value = atomic_values[mem_access]
                accumulator.append(value)

            # Save the computed value
            out[dst] = expr_simp(ExprCompose(*reversed(accumulator)))

        out = AssignBlock(out)
        if memories != out:
            self.logger.debug("SANITIZE: %s", memories)
            self.logger.debug("OUT SANITIZE: %s", out)
        return out, filled_memory

    def generate_init(self, snapshot, number):
        '''Return the string corresponding to the code of the init function'''

        self.printer.add_block(funcDefTemplate.format("init", number))
        self.printer.add_lvl()

        memory_in = snapshot.memory_in
        memory_out = snapshot.memory_out
        c_handler = snapshot.c_handler
        typed_C_ids = snapshot.typed_C_ids
        arguments_symbols = snapshot.arguments_symbols
        output_value = snapshot.output_value

        # Sanitize memory accesses
        memory_in, _ = self.sanitize_memory_accesses(memory_in, c_handler, typed_C_ids)
        memory_out, _ = self.sanitize_memory_accesses(memory_out, c_handler, typed_C_ids)

        # Allocate zones if needed

        ## First, resolve common bases
        bases_to_C = {} # expr -> C-like
        to_resolve = set()
        for expr in memory_in.keys() + memory_out.keys():
            to_resolve.update(expr.ptr.get_r(mem_read=True))

        fixed = {}
        for i, expr in enumerate(to_resolve):
            fixed[expr] = ExprId("base%d_ptr" % i, size=expr.size)
            info_type = list(c_handler.expr_to_types(expr))
            info_C = list(c_handler.expr_to_c(expr))
            assert len(info_type) == 1
            assert len(info_C) == 1
            arg_type = info_type[0]
            # Must be a pointer to be present in expr.get_r
            assert objc_is_dereferenceable(arg_type)

            bases_to_C[expr] = info_C[0]

        ## Second, alloc potential needed spaces for I/O
        todo = {}
        max_per_base_offset = {} # base -> maximum used offset
        max_per_base = {} # base -> maximum used field
        ptr_to_info = {}
        for mode, exprs in (("input", memory_in), ("output", memory_out)):
            count = 0
            for expr in exprs:
                assert isinstance(expr, ExprMem)
                addr_expr = expr.ptr

                # Expr.replace_expr is postfix, enumerate possibilities
                if addr_expr.is_id() or addr_expr.is_mem():
                    assert addr_expr in fixed
                    base = addr_expr
                    offset = 0
                elif addr_expr.is_op():
                    # X + offset
                    assert all((addr_expr.op == "+",
                                len(addr_expr.args) == 2,
                                isinstance(addr_expr.args[1], ExprInt),
                                addr_expr.args[0] in fixed))
                    base = addr_expr.args[0]
                    offset = int(addr_expr.args[1])
                else:
                    raise ValueError("Memory access should be in " \
                                     "X, X + offset, @[X]")

                if addr_expr in fixed:
                    # Already handled
                    ptr = fixed[addr_expr]
                else:
                    ptr = ExprId("%s%d_ptr" % (mode, count), size=addr_expr.size)
                    fixed[addr_expr] = ptr
                    count += 1

                info_type = list(c_handler.expr_to_types(addr_expr))
                info_C = list(c_handler.expr_to_c(expr))
                # TODO handle unknown type?
                assert len(info_type) == 1
                assert len(info_C) == 1

                expr_type = info_type[0]
                # Must be a pointer to be deref
                assert objc_is_dereferenceable(expr_type)

                assert expr_type.objtype.size >= (expr.size / 8)

                info = {"Clike": info_C[0],
                        "addr": addr_expr,
                        "ptr": ptr,
                        "base": base,
                        "offset": offset,
                }
                ptr_to_info[ptr] = info

                # Find the last field in the struct for future alloc
                if max_per_base_offset.get(base, -1) < offset:
                    max_per_base_offset[base] = offset
                    max_per_base[base] = info["Clike"]

        # Reserve memory for each bases
        for expr, Clike in bases_to_C.iteritems():
            ptr = fixed[expr]
            ptr_size = "%s_size" % ptr
            last_field = max_per_base[expr]
            self.printer.add_block("# %s\n" % Clike)
            self.printer.add_block('%s = self.field_addr("%s", "%s") ' \
                                   '+ self.sizeof("%s")\n' % (ptr_size,
                                                              Clike,
                                                              last_field,
                                                              last_field))
            self.printer.add_block('%s = self._alloc_mem(%s, read=True, ' \
                                   'write=True)\n' % (ptr,
                                                      ptr_size))

        self.printer.add_empty_line()

        # Set each pointers
        for ptr, info in sorted(ptr_to_info.iteritems(), key=lambda x:x[0]):
            base = info["base"]
            suffix = ""
            if info["offset"] != 0:
                # Only consider necessary calls to field_addr
                # (assume the first field of a struct will always be at offset 0)
                suffix = ' + self.field_addr("%s", "%s")' % (bases_to_C[base],
                                                             info["Clike"])
            elif ptr == fixed[base]:
                # Avoid unnecessary identity affectation
                continue
            self.printer.add_block("# %s\n" % info["Clike"])
            self.printer.add_block('%s = %s%s\n' % (ptr,
                                                    fixed[base],
                                                    suffix)
                                   )

        # Set initial values
        ## Arguments

        self.printer.add_empty_line()
        for i, arg_name in enumerate(self.prototype.args_order):
            arg_type = self.prototype.args[arg_name]
            symbol = arguments_symbols[i]
            if objc_is_dereferenceable(arg_type):
                if symbol not in fixed:
                    # The argument is not used as a pointer
                    #TODO
                    self.logger.warn("argument %s not used?!", arg_name)
                    continue
                else:
                    value = fixed[symbol]
            else:
                # Set real value from regs or stack

                for expr, expr_value in snapshot.init_values.iteritems():
                    if expr.name == "arg%d_%s" % (i, arg_name):
                        break
                else:
                    raise RuntimeError("Unable to find the init values of " \
                                       "argument %d" % i)

                if expr_value.is_int():
                    value = int(expr_value)
                elif expr_value.is_compose():
                    # Only a part of the argument has been read
                    # -> fill the rest with 0s
                    value = 0
                    for index, val in expr_value.iter_args():
                        if val.is_int():
                            val = int(val)
                        else:
                            val = 0
                        value |= (val << index)
                else:
                    raise TypeError("An argument should be in the form I, " \
                                    "or {I, XX}")

            self.printer.add_block("self._add_arg(%d, %s) # arg%d_%s\n" %
                                   (i, value, i, arg_name))

        ## Inputs
        self.printer.add_empty_line()
        for dst in memory_in:
            info_type = list(c_handler.expr_to_types(dst))
            info_C = list(c_handler.expr_to_c(dst))
            # TODO handle unknown type?
            assert len(info_type) == 1
            assert len(info_C) == 1
            dst_type = info_type[0]
            if objc_is_dereferenceable(dst_type):
                if dst not in fixed:
                    # The pointer is read but never deferenced
                    # Consider it as an int
                    value = memory_in[dst]
                    assert value.is_int()
                    # Fix it to this value
                    fixed[dst] = value
                else:
                    # We must have considered it before
                    value = fixed[dst]
            else:
                value = memory_in[dst]

            # We already have the pointer allocated
            addr = fixed[dst.ptr]
            self.printer.add_block('# %s = %s\n' % (info_C[0], value))
            self.printer.add_block('self._write_mem(%s, self.pack(%s, self.sizeof("%s")))\n' % (addr,
                                                                                           value,
                                                                                           info_C[0]))

        ## Returned value
        base = None
        if objc_is_dereferenceable(self.prototype.func_type):

            if output_value.is_id() or output_value.is_mem():
                assert output_value in fixed
                base = output_value
            elif output_value.is_op():
                # X + offset
                assert all((output_value.op == "+",
                            len(output_value.args) == 2,
                            isinstance(output_value.args[1], ExprInt),
                            output_value.args[0] in fixed))
                base = output_value.args[0]
            else:
                raise ValueError("Output should be in X, X + offset, @[X] form")

        # Needed for check generation
        ## For generate_check needs
        self.fixed = fixed
        self.bases_to_C = bases_to_C

        ## For the generated check needs
        to_save = set()
        to_save.update(fixed[dst.ptr] for dst in memory_out)
        if base is not None:
            to_save.add(fixed[base])

        self.printer.add_empty_line()
        for var in to_save:
            self.printer.add_block('self.%s = %s\n' % (var, var))
        self.printer.sub_lvl()


    def generate_check(self, snapshot, number):
        '''Return the string corresponding to the code of the check function'''

        self.printer.add_block(funcDefTemplate.format("check", number))
        self.printer.add_lvl()

        memory_out = snapshot.memory_out
        c_handler = snapshot.c_handler
        typed_C_ids = snapshot.typed_C_ids
        arguments_symbols = snapshot.arguments_symbols
        output_value = snapshot.output_value

        # Sanitize memory accesses
        memory_out, filled_out = self.sanitize_memory_accesses(
            memory_out,
            c_handler,
            typed_C_ids,
        )

        fixed = self.fixed
        bases_to_C = self.bases_to_C

        self.printer.add_block("return all((\n")
        self.printer.add_lvl()

        if objc_is_dereferenceable(self.prototype.func_type):

            if output_value.is_id() or output_value.is_mem():
                assert output_value in fixed
                base = output_value
            elif output_value.is_op():
                # X + offset
                assert all((output_value.op == "+",
                            len(output_value.args) == 2,
                            isinstance(output_value.args[1], ExprInt),
                            output_value.args[0] in fixed))
                base = output_value.args[0]
            else:
                raise ValueError("Output should be in X, X + offset, @[X] form")

            info_C = list(c_handler.expr_to_c(output_value))
            assert len(info_C) == 1
            Clike = info_C[0]

            suffix = ""
            if bases_to_C[base] != Clike:
                # Only consider necessary calls to field_addr
                suffix = ' + self.field_addr("%s", "%s", is_ptr=True)' % (bases_to_C[base],
                                                                          Clike)
            self.printer.add_block("# Check output value\n# result == %s\n" % Clike)
            self.printer.add_block('self._get_result() == self.%s%s,\n' % (fixed[base],
                                                                           suffix))

        elif self.prototype.func_type.name != "void":
            retvalue = int(output_value)
            self.printer.add_block("# Check output value\nself._get_result() == %s,\n" % hex(retvalue))

        for dst in memory_out:
            info_type = list(c_handler.expr_to_types(dst))
            info_C = list(c_handler.expr_to_c(dst))

            # TODO handle unknown type?
            assert len(info_type) == 1
            assert len(info_C) == 1
            dst_type = info_type[0]
            if objc_is_dereferenceable(dst_type):
                if dst not in fixed:
                    # The pointer is read but never deferenced
                    # Consider it as an int
                    value = memory_out[dst]
                    if not value.is_int():
                        # Second chance, it may have been fixed
                        value = fixed[value]
                    assert value.is_int()
                else:
                    value = "self.%s" % fixed[dst]
            else:
                value = memory_out[dst]

            # We already have the pointer allocated
            addr = fixed[dst.ptr]

            if dst in filled_out:
                # Sparse access, there are offset NOT to consider
                offsets = [int(offset) for offset in filled_out[dst]]
                self.printer.add_block('# %s == %s (without considering %s offset(s)\n' % (info_C[0], value, ", ".join(map(hex, offsets))))
                self.printer.add_block('self._ensure_mem_sparse'
                                       '(self.%s, self.pack(%s, self.sizeof("%s")), [%s]),\n' % (addr,
                                                                                            value,
                                                                                            info_C[0],
                                                                                            ", ".join(map(hex, offsets)),
                                       ))
            else:
                # Full access
                self.printer.add_block('# %s == %s\n' % (info_C[0], value))
                self.printer.add_block('self._ensure_mem(self.%s, self.pack(%s, self.sizeof("%s"))),\n' % (addr,
                                                                                            value,
                                                                                            info_C[0]))
        self.printer.sub_lvl()
        self.printer.add_block("))")
        self.printer.sub_lvl()

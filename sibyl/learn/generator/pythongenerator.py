import struct
from sibyl.learn.generator.generator import Generator
from sibyl.learn.trace import MemoryAccess

from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE

classDefTemplate = '''from sibyl.test.test import Test, TestSetTest
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from sibyl.learn.learnexception import LearnException

class Test{funcname}(Test):

{initDef}

{funcDef}

    func = "{funcname}"
    tests = {testList}

TESTS = [Test{funcname}]'''

initDefTemplate = '''    def __init__(self, *args, **kwargs):
        super(Test{funcname}, self).__init__(*args, **kwargs)
        {printedException}
'''

testListElem = " TestSetTest(init{0}, check{0}) "

funcDefTemplate = "def {}{}(self):\n{}\n"

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

    # TODO: remove the list with the ABI
    reg_list = ["RDI", "RSI", "RDX", "RCX", "R8", "R9"]

    def generate_test(self):

        if self.learnexceptiontext:
            printedException = ('print "' + "\\n".join(["REPLAY ERROR: " + e for e in self.learnexceptiontext]) + '"') if self.learnexceptiontext else ""

            initDef = initDefTemplate.format(funcname=self.functionname,
                                             printedException=printedException)
        else:
            initDef = ""

        testList = "&".join([testListElem.format(i)
                            for i in xrange(1, len(self.trace) + 1)])

        testFuncDefinitions = ""
        for i, snapshot in enumerate(self.trace, 1):
            testFuncDefinitions += self.addShiftLvl(
                self.generate_init(snapshot, i) + '\n\n' + self.generate_check(snapshot, i))

        return classDefTemplate.format(funcname=self.functionname,
                                       initDef=initDef,
                                       testList=testList,
                                       funcDef=testFuncDefinitions)
    
    def generate_init(self, snapshot, number):
        '''Return the string corresponding to the code of the init function'''
        argList = []
        refsInMem = {}

        seg_sizes = [sup - inf for (inf, sup) in snapshot.segments]

        regI = snapshot.input_reg
        memI = snapshot.in_memory
        refs = snapshot.refs

        if refs:
            for addr, ref in refs.iteritems():
                if ref.in_mem:
                    refsInMem[addr] = ref.in_mem

        # Retrieve the agruments
        for i in xrange(self.nb_arg):
            if i < len(self.reg_list):
                ref = snapshot.isRegInInputRef(self.reg_list[i])
                if ref is not None:
                    argList.append(ref)
                    refs[ref].in_reg.remove(self.reg_list[i])
                else:
                    argList.append(regI[self.reg_list[i]])
            else:
                (stackOff, stackSeg) = snapshot.getStackSegment()

                argAddr = stackOff + self.ptr_size * (i - len(self.reg_list)) + self.ptr_size

                for (offset, seg) in memI.keys():
                    addr = (offset, seg)
                    if seg != stackSeg:
                        continue

                    if offset <= argAddr < offset + memI[addr].size:

                        if not snapshot.isMemInRef((argAddr, stackSeg)) is None:
                            argList.append((argAddr, stackSeg))
                        else:
                            # Retrieve argument value
                            arg = memI[addr].data[
                                argAddr - offset:argAddr - offset + self.ptr_size]
                            arg += "\x00" * (self.ptr_size - len(arg))
                            argList.append(my_unpack(arg))

                        # Delete argument from memory not to alloc it manually
                        if argAddr + self.ptr_size < offset + memI[addr].size:
                            memaccess = MemoryAccess(memI[addr].size - (argAddr + self.ptr_size - offset),
                                                     memI[addr].data[argAddr - offset:argAddr + self.ptr_size - offset],
                                                     memI[addr].access,
                                                     stackSeg)
                            memI[(argAddr + self.ptr_size, stackSeg)] = memaccess

                        if argAddr > addr:
                            memI[addr].size = argAddr - addr

                        else:
                            del memI[addr]


        addrList = [(addr, mem.data, mem.access) for addr, mem in memI.iteritems()]

        body = ""

        if addrList:
            body += memoryAllocTemplate.format(
            allocList=",\n\t".join(addrTupleStr(addr) for addr in addrList),
            segSize=", ".join(str(size) for size in seg_sizes),
            n=number)

        if refsInMem:
            body += refUpdateTemplate.format(refs=repr(refsInMem), n=number)

        if argList:
            body += argInitTemplate.format(argList=", ".join(argListStr(arg) for arg in argList), n=number)

        if not body:
            body = "pass"

        return funcDefTemplate.format("init", number, self.addShiftLvl(body))

    def generate_check(self, snapshot, number):
        '''Return the string corresponding to the code of the check function'''

        refsInMem = {}
        refs = snapshot.refs
        if refs:
            for addr, ref in refs.iteritems():
                if ref.out_mem:
                    refsInMem[addr] = ref.out_mem

        # Remove arguments from out memory
        memO = snapshot.out_memory
        for i in xrange(self.nb_arg):
            if i >= len(self.reg_list):
                (stackOff, stackSeg) = snapshot.getStackSegment()

                argAddr = stackOff + self.ptr_size * (i - len(self.reg_list)) + self.ptr_size

                for (offset, seg) in memO.keys():
                    addr = (offset, seg)
                    if seg != stackSeg:
                        continue

                    if offset <= argAddr < offset + memO[addr].size:
                        # Delete argument from memory not to check it manually
                        if argAddr + self.ptr_size < offset + memO[addr].size:
                            memaccess = MemoryAccess(memO[addr].size - (argAddr + self.ptr_size - offset),
                                                     memO[addr].data[argAddr - offset:argAddr + self.ptr_size - offset],
                                                     memO[addr].access,
                                                     stackSeg)
                            memO[(argAddr + self.ptr_size, stackSeg)] = memaccess

                        if argAddr > addr:
                            memO[addr].size = argAddr - addr

                        else:
                            del memO[addr]


        addrList = []
        for addr, mem in snapshot.out_memory.iteritems():
            addrList.append((addr, mem.data))

        res = snapshot.isRegInOutputRef(self.ira.ret_reg.name)
        if res is None:
            res = snapshot.output_reg[self.ira.ret_reg.name]

        body = checkResultTemplate.format(expectedResult=res, n=number)

        if addrList:
            if refsInMem:
                body += checkAllocWithRefTemplate.format(addrList=addrList, n=number,refs=repr(refsInMem))
            else:
                body += checkAllocWithoutRefTemplate.format(addrList=addrList, n=number)
        body += "\nreturn ret"

        return funcDefTemplate.format("check", number, self.addShiftLvl(body))

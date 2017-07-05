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
import os
import json
import subprocess
import time
import re

import idaapi
import idc
import ida_kernwin
import idautils

# Find SIBYL find.py
identify_binary = "sibyl"
env = os.environ

# Sibyl launching
def exec_cmd(command_line):
    """Launch the command line @command_line"""
    global env
    process = subprocess.Popen(command_line,
                               stdout=subprocess.PIPE,
                               env=env)

    result, _ = process.communicate()

    if process.returncode != 0:
        # An error occured
        raise RuntimeError("An error occured, please consult the console")

    return result

def available_tests():
    """Get the available tests"""
    global identify_binary
    command_line = [identify_binary, "config", "-V", "available_tests_keys"]
    return eval(exec_cmd(command_line))

AVAILABLE_TESTS = available_tests()

def parse_output(command_line):
    """Parse the output of find.py"""
    result = exec_cmd(command_line)

    for result in json.loads(result)["results"]:
        address, candidates = result["address"], result["functions"]
        if candidates:
            yield address, map(str, candidates)


def handle_found(addr, candidates):
    """Callback when @candidates have been found for a given address @addr.
    Print and add an IDA comment at @addr
    @addr: address of the function analyzed
    @candidates: list of string of possible matched functions
    """
    print "Found %s at %s" % (",".join(candidates), hex(addr))
    idc.SetFunctionCmt(addr, "[Sibyl] %s?" % ",".join(candidates), False)


def launch_on_funcs(architecture, abi, funcs, test_set, map_addr=None,
                    jitter=None, buf_size=2000):
    """Launch identification on functions.
    @architecture: str standing for current architecture
    @abi: str standing for expected ABI
    @funcs: list of function addresses (int) to check
    @test_set: list of test sets to run
    Optional arguments:
    @map_addr: (optional) the base address where the binary has to be loaded if
    format is not recognized
    @jitter: (optional) jitter engine to use (gcc, tcc, llvm, python, qemu)
    @buf_size: (optional) number of argument to pass to each instance of sibyl.
    High number means speed; low number means less ressources and higher
    frequency of report
    """

    # Check Sibyl availability
    global identify_binary
    if not identify_binary:
        raise ValueError("A valid Sibyl path to find.py must be supplied")

    # Get binary information
    filename = str(idc.GetInputFilePath())
    nb_func = len(funcs)

    # Prepare run
    starttime = time.time()
    nb_found = 0
    add_map = []
    if isinstance(map_addr, int):
        add_map = ["-m", hex(map_addr)]

    # Launch identification
    print "Launch identification on %d function(s)" % nb_func
    options = ["-a", architecture, "-b", abi, "-o", "JSON"]
    for test_name in test_set:
        options += ["-t", test_name]
    if jitter is not None:
        options += ["-j", jitter]
    options += add_map
    res = {}

    for i in xrange(0, len(funcs), buf_size):
        # Build command line
        addresses = funcs[i:i + buf_size]
        command_line = [identify_binary, "find"]
        command_line += options
        command_line += [filename]
        command_line += addresses

        # Call Sibyl and keep only stdout
        for addr, candidates in parse_output(command_line):
            handle_found(addr, candidates)
            res[addr] = candidates
            nb_found += 1

        # Print current status and estimated time
        curtime = (time.time() - starttime)
        maxi = min(i + buf_size, len(funcs))
        estimatedtime = (curtime * nb_func) / maxi
        remaintime = estimatedtime - curtime
        print "Current: %.02f%% (sub_%s)| Estimated time remaining: %.02fs" % (((100. /nb_func) * maxi),
                                                                                     addresses[-1],
                                                                                     remaintime)

    print "Finished ! Found %d candidates in %.02fs" % (nb_found, time.time() - starttime)
    return res


# IDA Interfacing
class sibylForm(ida_kernwin.Form):
    """IDA Form to launch analysis on one or many function, according to a few
customizable parameters
    """

    def __init__(self):

        addr = idc.ScreenEA()
        func = idaapi.get_func(addr)

        tests_choice = "\n".join(map(lambda x: "<%s:{r%s}>" % (x, x), AVAILABLE_TESTS))
        ida_kernwin.Form.__init__(self,
r"""BUTTON YES* Launch
BUTTON CANCEL NONE
Sibyl Settings

{FormChangeCb}
Apply on:
<One function:{rOneFunc}>
<All functions:{rAllFunc}>{cMode}>

<Targeted function:{cbFunc}>

Testsets to use:
%s{cTest}>

""" % tests_choice, {
    'FormChangeCb': ida_kernwin.Form.FormChangeCb(self.OnFormChange),
    'cMode': ida_kernwin.Form.RadGroupControl(("rOneFunc", "rAllFunc")),
    'cTest': ida_kernwin.Form.ChkGroupControl(map(lambda x: "r%s" % x,
                                      AVAILABLE_TESTS),
                                  value=(1 << len(AVAILABLE_TESTS)) - 1),
    'cbFunc': ida_kernwin.Form.DropdownListControl(
        items=self.available_funcs,
        readonly=False,
        selval="0x%x" % func.startEA),
}
        )

        self.Compile()

    def OnFormChange(self, fid):
        if fid == self.cMode.id:
            enable = self.GetControlValue(self.cMode) == 0
            self.EnableField(self.cbFunc, enable)
        return 1

    @property
    def available_funcs(self):
        return map(lambda x:"0x%x" % x, idautils.Functions())

    @property
    def funcs(self):
        if self.cMode.value == 0:
            return [self.cbFunc.value]
        else:
            return self.available_funcs

    IDAarch2MiasmArch = {
        "msp430": "msp430",
        "mipsl": "mips32l",
        "mipsb": "mips32b",
    }

    @property
    def architecture(self):
        """Return the IDA guessed processor
        Ripped from Miasm2 / examples / ida / utils
        """

        processor_name = idc.GetLongPrm(idc.INF_PROCNAME)

        if processor_name in self.IDAarch2MiasmArch:
            name = self.IDAarch2MiasmArch[processor_name]

        elif processor_name == "metapc":

            # HACK: check 32/64 using INF_START_SP
            inf = idaapi.get_inf_structure()
            if inf.is_32bit():
                name = "x86_32"
            elif inf.is_64bit():
                name = "x86_64"
            elif idc.GetLongPrm(idc.INF_START_SP) == 0x80:
                name = "x86_16"
            else:
                raise ValueError('cannot guess 32/64 bit! (%x)' % max_size)
        elif processor_name == "ARM":
            # TODO ARM/thumb
            # hack for thumb: set armt = True in globals :/
            # set bigendiant = True is bigendian
            is_armt = globals().get('armt', False)
            is_bigendian = globals().get('bigendian', False)
            if is_armt:
                if is_bigendian:
                    name = "armtb"
                else:
                    name = "armtl"
            else:
                if is_bigendian:
                    name = "armb"
                else:
                    name = "arml"

        else:
            print repr(processor_name)
            raise ValueError("Unknown corresponding architecture")

        return name

    IDAABI2SibylABI = {
        "arml": "ABI_ARM",
        "mips32l": "ABI_MIPS_O32",
        "x86_32": {
            "__cdecl": "ABIStdCall_x86_32",
            "__stdcall": "ABIStdCall_x86_32",
            "__fastcall": "ABIFastCall_x86_32",
        },
        "x86_64": {
            "__fastcall": "ABI_AMD64_SYSTEMV",
        },
    }

    # int __cdecl(int, int) -> __cdecl
    gtype_matcher = re.compile(".+ ([^\(]+)\([^\)]*\)")

    @property
    def abi(self):
        """Return the IDA guessed ABI
        """

        architecture = self.architecture

        available_abis = self.IDAABI2SibylABI.get(architecture, None)
        if not available_abis:
            raise ValueError("No ABI available for architecture %s" % architecture)

        if isinstance(available_abis, str):
            return available_abis

        # Search for IDA guessed type
        for func_addr in idautils.Functions():
            gtype = idc.GuessType(func_addr)
            if gtype is None:
                continue
            match = self.gtype_matcher.match(gtype)
            if match is None:
                continue
            calling_conv = match.group(1)
            abi = available_abis.get(calling_conv, None)
            if abi is None:
                raise ValueError("No ABI matching %s" % calling_conv)
            return abi
        raise ValueError("Unable to guess ABI")

    @property
    def tests(self):
        """Return the list of test to launch"""
        bitfield = self.cTest.value
        tests = []
        for i, test in enumerate(AVAILABLE_TESTS):
            if bitfield & (1 << i):
                tests.append(test)
        return tests


if __name__ == "__main__":
    # Main
    settings = sibylForm()
    settings.Execute()

    sibyl_res = launch_on_funcs(settings.architecture,
                                settings.abi,
                                settings.funcs,
                                settings.tests)
    print "Results are also available in 'sibyl_res'"


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
#
# Ported to radare2 - Michael Messner @s3cur1ty_de

import r2pipe
import json
import os
import sys
import time
import re
import subprocess

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
        raise RuntimeError("[-] An error occured, please consult the console")

    return result

def available_tests():
    """Get the available tests"""
    global identify_binary
    command_line = [identify_binary, "config", "-V", "available_tests_keys"]
    return eval(exec_cmd(command_line))


def parse_output(command_line):
    """Parse the output of find.py"""
    result = exec_cmd(command_line)

    for result in json.loads(result)["results"]:
        address, candidates = result["address"], result["functions"]
        if candidates:
            yield address, map(str, candidates)

def handle_found(addr, candidates):
    """Callback when @candidates have been found for a given address @addr.
    Print and rename the function at @addr
    @addr: address of the function analyzed
    @candidates: list of string of possible matched functions
    """
    print "[+] Found %s at %s" % (",".join(candidates), hex(addr))
    #rename the functions in r2
    r2.cmd('afn ' + ",".join(candidates) +'_sibyl ' +hex(addr))
    # setup flags in r2
    r2.cmd('f ' + ",".join(candidates) +'_sibyl @ ' +hex(addr))
    #write IDA pro batch file to be able to import the stuff to ida
    #in IDA use <shift>+<F2> and copy the content from the generated file
    f.write("MakeName(" +hex(addr) +", \"" +",".join(candidates) +'_sibyl' +"\");\n")


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
        raise ValueError("[-] A valid Sibyl path to find.py must be supplied")

    # Get binary information
    bin_details=r2.cmdj('oj')
    filename = bin_details[0]['uri']
    nb_func = r2.cmd('aflc')

    # Prepare run
    starttime = time.time()
    nb_found = 0
    add_map = []
    if isinstance(map_addr, int):
        add_map = ["-m", hex(map_addr)]

    # Launch identification
    nb_func = int(nb_func)
    print "[*] Launch identification on %d function(s)" % nb_func
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
        print "[*] Current: %.02f%% (sub_%s)| Estimated time remaining: %.02fs" % (((100. /nb_func) * maxi),
                                                                                     addresses[-1],
                                                                                     remaintime)

    print "[*] Finished ! Found %d candidates in %.02fs" % (nb_found, time.time() - starttime)
    return res

def architecture(bin_info):
  processor_name = bin_info['bin']['arch']
  endian = bin_info['bin']['endian']
  bits = bin_info['bin']['bits']
  print "[*] Architecture: %s / Endianess: %s / Bits: %s" %(processor_name, endian, bits)

  if processor_name == "arm":
    # TODO ARM/thumb
    # hack for thumb: set armt = True in globals :/
    # set bigendiant = True is bigendian
    is_armt = globals().get('armt', False)
    is_bigendian = globals().get('bigendian', False)

    abi = "ABI_ARM"
    if is_armt:
      if endian == "big":
        name = "armtb"
      else:
        name = "armtl"
    else:
      if endian == "big":
        name = "armb"
      else:
        name = "arml"

  elif processor_name == "mips":
    abi = "ABI_MIPS_O32"
    if endian == "big":
      name = "mips32b"
    else:
      name = "mips32l"

  elif processor_name == "ppc":   # currently not supported
    abi = "ABI_PPC"
    if endian == "big":
      name = "ppc32b"
    else:
      name = "ppc32l"
      print "[-] not supported"

  elif processor_name == "x86":
    if endian == "little":
      if bits == 32:
        name = "x86_32"
        abi = "ABIStdCall_x86_32"
        #abi = "ABIFastCall_x86_32" #currently we have to do this manually
      elif bits == 64:  #untested and unknown if this is correct
        name = "x86_64"
        abi = "ABI_AMD64_SYSTEMV"
      elif bits == 16:  #untested and unknown if this is correct
        name = "x86_16"
        abi = ""        #untested, no ABI available
        print "[-] not supported"
    else:
      print "[-] not supported"

  else:
    print "[-] not supported"

  return name, abi

## radare2 interfacing
def main():
  print("[*] Get already known functions via r2 command aflqj ...")

  current_functionsj = r2.cmdj("aflqj")
  bin_info = r2.cmdj('ij')

  settings_architecture, settings_abi = architecture(bin_info)

  #set this up for testing
  #settings_architecture = "arml"  # [-a {arml,armb,armtl,armtb,sh4,x86_16,x86_32,x86_64,msp430,mips32b,mips32l,aarch64l,aarch64b,ppc32b,mepl,mepb}]
  #settings_abi = "ABI_ARM"      # [-b {ABIStdCall_x86_32,ABIFastCall_x86_32,ABI_AMD64_SYSTEMV,ABI_AMD64_MS,ABI_ARM,ABI_MIPS_O32}]
  settings_tests = ['string','stdlib','ctype']       # [-t {stdlib,string,ctype}]

  sibyl_res = launch_on_funcs(settings_architecture,
                                settings_abi,
                                current_functionsj,
                                settings_tests)

if __name__ == '__main__':

  r2 = r2pipe.open()
  print('\n[*] Found ' +r2.cmd('aflc')+ ' functions')

  if int(r2.cmd('aflc')) == 0:
    print('\n[-] no functions found for analyzing ... try to analyze the binary first')
    exit(0)

  # we create an IDA batch file for auto renaming the functions in IDA pro
  f = open('ida_batch_sibyl.txt', 'w', 0)

  # Find SIBYL find.py
  identify_binary = "sibyl"
  env = os.environ
  AVAILABLE_TESTS = available_tests()

  main()

  f.close()

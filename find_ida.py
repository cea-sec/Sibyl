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

import sys
import subprocess
import time

from idaapi import *
import idautils

identify_binary = ""


def identify_help():
    """Sibyl IDA API helper"""
    find = subprocess.Popen(["python", identify_binary, "-h"],
                            stdout = subprocess.PIPE,
                            stderr = subprocess.PIPE)
    res = find.communicate()[0].split("\n")

    s = ""
    beg,end = 0,0
    for i, l in enumerate(res):
        if l.strip().startswith("architecture"):
            beg = i
        if l.strip().startswith("address"):
            end = i
    info = "\n".join(res[beg:end])

    print("""Function identifier:
 - identify_help(): print this help
 - identify_me(architecture, abi, (optionals)): candidates for current
function
 - identify_all(architecture, abi, (optionals)): candidates for all
functions

Optional arguments are:
@map_addr: the base address where the binary has to be loaded if format is not
 recognized
@jitter: jitter engine to use (tcc, llvm, python)
@buf_size: number of argument to pass to each instance of sibyl. High number
means speed; low number means less ressources and higher frequency of report
@test_set: list of test sets to run

Architecture and ABI available are displayed below:
""")
    print info


def launch_on_funcs(architecture, abi, funcs, map_addr=None, jitter="tcc",
                    buf_size=2000, test_set=["all"]):
    """Launch identification on functions.
    @architecture: str standing for current architecture
    @abi: str standing for expected ABI
    @funcs: list of function addresses (int) to check
    Optional arguments:
    @map_addr: (optional) the base address where the binary has to be loaded if
    format is not recognized
    @jitter: (optional) jitter engine to use (tcc, llvm, python)
    @buf_size: (optional) number of argument to pass to each instance of sibyl.
    High number means speed; low number means less ressources and higher
    frequency of report
    @test_set: (optional) list of test sets to run
    """

    # Check Sibyl availability
    global identify_binary
    if not identify_binary:
        raise ValueError("A valid Sibyl path to find.py must be supplied")

    # Get binary information
    filename = str(GetInputFilePath())
    nb_func = len(funcs)

    # Prepare run
    starttime = time.time()
    nb_found = 0
    add_map = []
    if isinstance(map_addr, int):
        add_map = ["-m", hex(map_addr)]

    # Launch identification
    print "Launch identification on %d function(s)" % nb_func
    for i in xrange(0, len(funcs), buf_size):
        # Build command line
        addresses = map(hex, funcs[i:i + buf_size])
        command_line = ["python", identify_binary, "-j", jitter, "-q"]
        command_line += add_map
        command_line += [filename, architecture, abi]
        command_line += addresses
        command_line += ["-t"] + test_set

        # Call Sibyl and keep only stdout
        find = subprocess.Popen(command_line,
                                stdout = subprocess.PIPE,
                                stderr = subprocess.PIPE)
        res = find.communicate()[0]

        # Print current status and estimated time
        curtime = (time.time() - starttime)
        maxi = min(i + buf_size, len(funcs))
        estimatedtime = (curtime * nb_func) / maxi
        remaintime = estimatedtime - curtime
        print "Current: %.02f%% (sub_%s)| Estimated time remaining: %.02fs" % (((100. /nb_func) * maxi),
                                                                                     addresses[-1],
                                                                                     remaintime)
        # Print results
        if res.strip():
            print res.strip()
        nb_found += res.count(":")

    print "Finished ! Found %d candidates in %.02fs" % (nb_found, time.time() - starttime)


def identify_all(architecture, abi, *args, **kwargs):
    """Find candidates for all functions detected"""
    funcs = list(Functions())
    launch_on_funcs(architecture, abi, funcs, *args, **kwargs)


def identify_me(architecture, abi, *args, **kwargs):
    """Find candidates for current function"""
    funcs = [ScreenEA()]
    launch_on_funcs(architecture, abi, funcs, *args, **kwargs)


# Print helper
identify_help()


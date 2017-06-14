#!/usr/bin/python
import os
import re
import subprocess
from argparse import ArgumentParser
from utils.log import log_error, log_success, log_info

from elfesteem.elf_init import ELF
from sibyl.heuristics.func import FuncHeuristic

match_C = re.compile("\w+[ \*]+(\w+)\(.*\)")
custom_tag = "my_"
whitelist_funcs = ["main"]


def get_funcs_exe_source(c_file, filename):
    """Get function defined in @c_file"""
    with open(c_file) as fdesc:
        data = fdesc.read()
    funcs = []
    for match in match_C.finditer(data):
        funcs.append(match.groups()[0])
    funcs = list(name for name in set(funcs) if name not in whitelist_funcs)

    # Find corresponding binary offset
    to_check = []
    with open(filename) as fdesc:
        elf = ELF(fdesc.read())

    symbols = {}
    for name, symb in elf.getsectionbyname(".symtab").symbols.iteritems():
        offset = symb.value
        if name.startswith("__"):
            name = name[2:]
        symbols.setdefault(name, set()).add(offset)
        if name in funcs:
            if name.startswith(custom_tag):
                ## Custom tags can be used to write equivalent functions like
                ## 'my_strlen' for a custom strlen
                name = name[len(custom_tag):]
            to_check.append((offset, name))
    return to_check, symbols


def get_funcs_heuristics(c_file, filename):
    """Get function from Sibyl heuristics"""
    # Force the activation of all heuristics
    fh = FuncHeuristic(None, None, "")
    cmd = ["sibyl", "func"]
    for name in fh.heuristic_names:
        cmd += ["-e", name]
    cmd.append(filename)
    print " ".join(cmd)
    sibyl = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    stdout, stderr = sibyl.communicate()
    if stderr:
        raise RuntimeError("Something gone wrong...:\n%s" % stderr)

    # Parse output and merge with symtab (ground truth)
    to_check_symtab, extra = get_funcs_exe_source(c_file, filename)
    addr2name = {addr: name for addr, name in to_check_symtab}
    to_check = []
    for line in stdout.split("\n"):
        if not line:
            continue
        addr = int(line, 0)
        if addr in addr2name:
            to_check.append((addr, name))

    return to_check, extra


def test_find(args):

    if args.func_heuristic:
        get_funcs = get_funcs_heuristics
    else:
        get_funcs = get_funcs_exe_source

    # Compil tests
    log_info( "Remove old files" )
    os.system("make clean")
    log_info( "Compile C files" )
    status = os.system("make")

    # Find test names
    c_files = []

    for cur_dir, sub_dir, files in os.walk("."):
        c_files += [x for x in files if x.endswith(".c")]

    log_info( "Found:\n\t- " + "\n\t- ".join(c_files) )

    for c_file in c_files:
        filename = c_file[:-2]
        log_info( " %s:" % filename )
        # to_check: (addr, expected found)
        # extra: possible extra match
        to_check, extra = get_funcs(c_file, filename)
        print "\n".join("0x%08x: %s" % (addr, funcname)
                        for (addr, funcname) in to_check)

        # Launch Sibyl
        log_info( "Launch Sibyl" )
        options = ["-j", "gcc", "-i", "5", "-b", "ABIStdCall_x86_32"]
        if not args.arch_heuristic:
            options += ["-a", "x86_32"]

        cmd = ["sibyl", "find"] + options + [filename]
        cmd += [hex(addr) for addr, _ in to_check]
        print " ".join(cmd)
        sibyl = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

        # Parse result
        found = []
        stdout, stderr = sibyl.communicate()
        for line in stdout.split("\n"):
            if not line or not " : " in line:
                continue
            addr, func = line.split(" : ")
            found.append((int(addr, 0), func))

        if sibyl.returncode:
            log_error("Process exits with a %d code" % sibyl.returncode)
            print stderr
            exit(sibyl.returncode)

        log_info( "Evaluate results" )
        i = 0

        for element in found:
            if element not in to_check:
                offset, name = element
                if offset in extra.get(name, []):
                    # Present in symtab but not in C source file
                    print "[+] Additionnal found: %s (@0x%08x)" % (name, offset)
                else:
                    alt_names = [aname
                                 for aname, offsets in extra.iteritems()
                                 if offset in offsets]
                    log_error("Bad found: %s (@0x%08x -> '%s')" % (name,
                                                                   offset,
                                                                   ",".join(alt_names)))
            else:
                i += 1
        for element in to_check:
            if element not in found:
                log_error("Unable to find: %s (@0x%08x)" % (element[1], element[0]))

        log_success("Found %d/%d correct elements" % (i, len(to_check)))

    log_info( "Remove old files" )
    os.system("make clean")
    return False

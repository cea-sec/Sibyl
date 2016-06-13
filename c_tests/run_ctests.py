#!/usr/bin/python
import os
import re
import subprocess

from elfesteem.elf_init import ELF

custom_tag = "my_"
whitelist_funcs = ["main"]
colors = {"red": "\033[91;1m",
          "end": "\033[0m",
          "green": "\033[92;1m",
          "lightcyan": "\033[96m",
          "blue": "\033[94;1m"}

def log_error(content):
    msg = "%(red)s[-] " % colors + content + "%(end)s" % colors
    print msg

def log_success(content):
    msg = "%(green)s[+] " % colors + content + "%(end)s" % colors
    print msg

# Compil tests
print "[+] Remove old files"
os.system("make clean")
print "[+] Compile C files"
os.system("make")

# Find test names
c_files = []

for cur_dir, sub_dir, files in os.walk("."):
    c_files += [x for x in files if x.endswith(".c")]

print "[+] Found:\n\t- " + "\n\t- ".join(c_files)

m = re.compile("\w+[ \*]+(\w+)\(.*\)")
for c_file in c_files:
    # Get function defined in the source
    with open(c_file) as fdesc:
        data = fdesc.read()
    filename = c_file[:-2]
    print "[+] %s:" % filename
    funcs = []
    for p in m.finditer(data):
        funcs.append(p.groups()[0])
    funcs = list(x for x in set(funcs) if x not in whitelist_funcs)

    # Find corresponding binary offset
    to_check = []
    with open(filename) as fdesc:
        elf = ELF(fdesc.read())

    for name, symb in elf.getsectionbyname(".symtab").symbols.iteritems():
        if name in funcs:
            offset = symb.value
            if name.startswith(custom_tag):
                ## Custom tags can be used to write equivalent functions like
                ## 'my_strlen' for a custom strlen
                name = name[len(custom_tag):]
            to_check.append((offset, name))

    print "\n".join("0x%08x: %s" % (addr, funcname)
                    for (addr, funcname) in to_check)

    # Launch Sibyl
    print "[+] Launch Sibyl"
    cmd = ["python", "../find.py", filename, "x86_32", "ABIStdCall_x86_32",
           "-q"]
    cmd += [hex(addr) for addr, f in to_check]
    print " ".join(cmd)
    sibyl = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

    # Parse result
    found = []
    stdout, stderr = sibyl.communicate()
    for line in stdout.split("\n"):
        if not line:
            continue
        addr, func = line.split(" : ")
        found.append((int(addr, 16), func))

    if sibyl.returncode:
        log_error("Process exits with a %d code" % sibyl.returncode)
        print stderr
        exit(sibyl.returncode)

    print "[+] Evaluate results"
    i = 0

    for element in found:
        if element not in to_check:
            log_error("Bad found: %s (@0x%08x)" % (element[1], element[0]))
        else:
            i += 1
    for element in to_check:
        if element not in found:
            log_error("Unable to find: %s (@0x%08x)" % (element[1], element[0]))

    log_success("Found %d/%d correct elements" % (i, len(to_check)))

print "[+] Remove old files"
os.system("make clean")

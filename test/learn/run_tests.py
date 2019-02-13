import subprocess
import os
import sys
import tempfile
import imp
from utils.log import log_error, log_success, log_info

from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container

from sibyl.testlauncher import TestLauncher
from sibyl.abi.x86 import ABI_AMD64_SYSTEMV
from sibyl.config import config

# Tests to fix
unsupported = [
]

def invoke_pin(filename, func_name, header_filename, cont):
    return ["sibyl", "learn", "-t", "pin", func_name, filename, header_filename]

def invoke_miasm(filename, func_name, header_filename, cont):
    main_addr = cont.loc_db.get_name_offset("main")
    return ["sibyl", "learn", "-t", "miasm", "-m", "0x%x" % main_addr,
            func_name, filename, header_filename]

def test_learn(args):
    machine = Machine("x86_64")

    # Compil tests
    log_info("Remove old files")
    os.system("make clean")
    log_info("Compile C files")
    status = os.system("make")
    assert status == 0

    # Find test names
    c_files = []

    for cur_dir, sub_dir, files in os.walk("."):
        c_files += [x[:-2] for x in files if x.endswith(".c")]

    # Ways to invoke
    to_invoke = {
        "Miasm": invoke_miasm,
    }
    if args.pin_tracer:
        to_invoke["PIN"] = invoke_pin

    # Learn + test
    fail = False
    for filename in c_files:

        if filename in unsupported:
            log_error("Skip %s (unsupported)" % filename)
            continue

        with open(filename) as fdesc:
            cont = Container.from_stream(fdesc)

        func_name = filename
        func_addr = cont.loc_db.get_name_offset(func_name)
        header_filename = "%s.h" % filename

        for name, cb in to_invoke.iteritems():
            log_info("Learning %s over %s with %s" % (func_name,
                                                      filename, name))
            cmdline = cb(filename, func_name, header_filename, cont)

            print " ".join(cmdline)
            sibyl = subprocess.Popen(cmdline, env=os.environ,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
            stdout, stderr = sibyl.communicate()
            if sibyl.returncode != 0:
                log_error("Failed to learn with error:")
                print stderr
                fail = True
                continue

            log_info("Testing generated class")

            mod = imp.new_module("testclass")
            exec stdout in mod.__dict__
            classTest = getattr(mod, "TESTS")[0]
            tl = TestLauncher(filename, machine, ABI_AMD64_SYSTEMV, [classTest],
                              config.jit_engine)

            possible_funcs = tl.run(func_addr)
            if tl.possible_funcs and possible_funcs == [filename]:
                log_success("Generated class recognize the function " \
                            "'%s'" % func_name)
            else:
                log_error("Generated class failed to recognize the function " \
                          "'%s'" % func_name)
                fail = True

    # Clean
    log_info( "Remove old files" )
    os.system("make clean")

    return fail

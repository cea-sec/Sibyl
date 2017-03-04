import subprocess
import os
import sys
import tempfile
import imp
from utils.log import log_error, log_success, log_info

from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container

# weird, should be removed when sibyl installation is performed
sys.path.append(os.path.join(os.getcwd(), "../"))

from sibyl.testlauncher import TestLauncher
from sibyl.abi.x86 import ABI_AMD64


def test_learn(args):

    machine = Machine("x86_64")

    # Compil tests
    log_info("Remove old files")
    os.system("make clean")
    log_info("Compile C files")
    status = os.system("make")
    assert status==0

    # Find test names
    c_files = []

    for cur_dir, sub_dir, files in os.walk("."):
        c_files += [x[:-2] for x in files if x.endswith(".c")]


    for c_file in c_files:
        cont = Container.from_stream(open(c_file))

        func_name = c_file
        main_addr = cont.symbol_pool["main"].offset
        func_addr = cont.symbol_pool[func_name].offset

        log_info("Learning "+func_name+ " over "+func_name+".c")

        cmd = ["python", "../../learn.py", "-t", "miasm", "-m", hex(main_addr), func_name, c_file]
        sibyl = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = sibyl.communicate()

        log_info("Testing generated class")

        mod = imp.new_module("testclass")
        exec stdout in mod.__dict__
        classTest = getattr(mod, "Test"+c_file)
        tl = TestLauncher(c_file, machine, ABI_AMD64, [classTest], "gcc")
        
        possible_funcs = tl.run(func_addr)
        if tl.possible_funcs:
            log_success("Generated class recognize the function "+func_name)
        else:
            log_error("Generated class failed to recognize the function "+func_name)

    log_info( "Remove old files" )
    os.system("make clean")

#Sibyl "find" launcher
#@author MOUGEY Camille
#@category FunctionID

import json
import os
import subprocess
import time

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

def parse_output(command_line):
    """Parse the output of find.py"""
    result = exec_cmd(command_line)

    for result in json.loads(result)["results"]:
        address, candidates = result["address"], result["functions"]
        if candidates:
            yield address, map(str, candidates)


def handle_found(addr, candidates):
    """Callback when @candidates have been found for a given address @addr.
    Print and add an GHIDRA comment at @addr
    @addr: address of the function analyzed
    @candidates: list of string of possible matched functions
    """
    print("Found %s at %s" % (",".join(candidates), hex(addr)))
    listing = currentProgram.getListing()
    codeUnit = listing.getCodeUnitAt(toAddr(addr))
    codeUnit.setComment(codeUnit.PLATE_COMMENT, "Sibyl - %s" % ",".join(candidates))


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
    filename = str(currentProgram.getExecutablePath())
    nb_func = len(funcs)

    # Prepare run
    starttime = time.time()
    nb_found = 0
    add_map = []
    if isinstance(map_addr, int):
        add_map = ["-m", hex(map_addr)]

    # Launch identification
    monitor.setMessage("Launch identification on %d function(s)" % nb_func)
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
        monitor.setMessage("Current: %.02f%% (FUN_%s)| Estimated time remaining: %.02fs" % (((100. /nb_func) * maxi),
                                                                                            addresses[-1],
                                                                                            remaintime))
        if monitor.isCancelled():
            print "Early break asked by the user"
            break

    print "Finished ! Found %d candidates in %.02fs" % (nb_found, time.time() - starttime)
    return res


GHIDRAArch2MiasmArch = {
    "x86/little/32": "x86_32",
}

GHIDRAABI2SibylABI = {
    ("x86_32", "default"): "ABIStdCall_x86_32",
}

if __name__ == "__main__":
    processor_name, abi = str(currentProgram.getLanguage()).rsplit("/", 1)
    m_arch = GHIDRAArch2MiasmArch.get(processor_name, None)
    if processor_name is None:
        popup("Unsupported architecture: %s" % processor_name)
        os.exit(0)

    s_abi = GHIDRAABI2SibylABI.get((m_arch, abi), None)
    if s_abi is None:
        popup("Unsupported ABI: (%s, %s)" % (m_arch, abi))
        os.exit(0)

    monitor.setMessage("Get functions address...")
    cur, whole = "Current function", "Whole program"
    choice = askChoice("Target", "Target function(s)", [cur, whole], cur)
    if choice == cur:
        addrs = ["0x%x" % getFunctionContaining(currentAddress).entryPoint.getOffset()]
    else:
        addrs = []
        for func in currentProgram.getListing().getFunctions(True):
            if func.isExternal():
                continue

            # Ignore already labeled functions
            # name = func.getName()
            # if not name.startswith("FUN_"):
            #     # Ignore already labeled functions
            #     continue

            addr = func.getEntryPoint()
            if addr is not None:
                addrs.append("0x%x" % addr.getOffset())

    monitor.setMessage("Get available tests...")
    AVAILABLE_TESTS = available_tests()
    testset = askChoices(
        "Test set", "Testsets to enable", AVAILABLE_TESTS, AVAILABLE_TESTS
    )

    launch_on_funcs(m_arch, s_abi, addrs, testset)

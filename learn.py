import argparse
import logging

from miasm2.analysis.binary import Container

from sibyl.learn.tracer import AVAILABLE_TRACER
from sibyl.learn.generator import AVAILABLE_GENERATOR
from sibyl.learn.learn import TestCreator
from sibyl.abi.x86 import ABI_AMD64

parser = argparse.ArgumentParser(description="Sibyl learning module")
parser.add_argument("functionname", help="Name of the learned function")
parser.add_argument("-a", "--address", help="Address of the learned function. If not set, the corresponding symbol address is used.")
parser.add_argument("program", help="Program used to learn the function, currently only x86 64 programs are supported")
parser.add_argument("-t", "--trace", help="Used tracer. Available: " + ", ".join(AVAILABLE_TRACER.keys()), default="pin", choices=AVAILABLE_TRACER.keys())
parser.add_argument("-g", "--generator", help="Used generator. Available: " + ", ".join(AVAILABLE_GENERATOR.keys()), default="python", choices=AVAILABLE_GENERATOR.keys())
parser.add_argument("-v", "--verbose", help="Verbose mode", action="store_true")
parser.add_argument("-m", "--main", help="Address of the function that calls the learned function. Use by and only by the miasm tracer.")
parser.add_argument("-o", "--output", help="Output file. Class is printed to stdout if no output file is specified.", default=None)
args = parser.parse_args()

# Currently only AMD64 ABI is supported by the learning module
args.abi = ABI_AMD64

# Currently only x86_64 is supported by the learning module
args.machine = "x86_64"

if args.trace != "miasm" and args.main != None:
    raise ValueError("Main argument is only used by miasm tracer")

args.main = int(args.main, 0) if args.main else None

# if function address is not set then use the symbol address
if args.address == None:
    cont = Container.from_stream(open(args.program))
    try:
        args.address = cont.symbol_pool[args.functionname].offset
    except KeyError:
        raise ValueError("Symbol %s does not exists in %s" % (args.functionname, args.program))
else:
    args.address = int(args.address, 0)

testcreator = TestCreator(args.functionname, args.address, args.program, AVAILABLE_TRACER[args.trace], AVAILABLE_GENERATOR[args.generator], args.main, args.abi, args.machine)

if args.verbose:
    testcreator.logger.setLevel(logging.INFO)

createdTest = testcreator.create_test()

if args.output:
    open(args.output, "w+").write(createdTest)
else:
    print createdTest


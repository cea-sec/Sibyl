import argparse
import logging

from miasm2.analysis.binary import Container

from sibyl.actions.action import Action
from sibyl.learn.tracer import AVAILABLE_TRACER
from sibyl.learn.generator import AVAILABLE_GENERATOR
from sibyl.learn.learn import TestCreator
from sibyl.abi.x86 import ABI_AMD64_SYSTEMV


class ActionLearn(Action):
    """Automatic learning of a new function from one or multiple call"""

    _name_ = "learn"
    _desc_ = "Learn a new function"
    _args_ = [
        # Mandatory
        (["functionname"], {"help": "Name of the learned function"}),
        (["program"], {"help": "Program used to learn the function, currently" \
                       " only x86 64 programs are supported"}),
        (["headerfile"], {"help": ".h header containing function declaration" \
                          " and associated types"}),
        # Optional
        (["-a", "--address"], {"help": "Address of the learned function. If " \
                               "not set, the corresponding symbol address is used."}),
        (["-t", "--trace"], {"help": "Used tracer. Available: " \
                             ", ".join(AVAILABLE_TRACER.keys()),
                             "default": "pin",
                             "choices": AVAILABLE_TRACER.keys()}),
        (["-g", "--generator"], {"help": "Used generator. Available: " \
                                 ", ".join(AVAILABLE_GENERATOR.keys()),
                                 "default": "python",
                                 "choices": AVAILABLE_GENERATOR.keys()}),
        (["-v", "--verbose"], {"help": "Verbose mode (use multiple time to " \
                               "increase verbosity level)",
                               "action": "count",
                               "default": 0}),
        (["-m", "--main"], {"help": "Address of the function that calls the" \
                            "learned function. Use by and only by the miasm tracer."}),
        (["-o", "--output"], {"help": "Output file. Class is printed to stdout" \
                              "if no output file is specified.",
                              "default": None}),
        (["-z", "--avoid-null"], {"help": "If set, do not consider runs "\
                                  "returning a null value",
                                  "action": "store_true"}),
    ]

    def run(self):
        # Currently only AMD64 SYSTEMV ABI is supported by the learning module
        abi = ABI_AMD64_SYSTEMV

        # Currently only x86_64 is supported by the learning module
        machine = "x86_64"

        if self.args.trace != "miasm" and self.args.main != None:
            raise ValueError("Main argument is only used by miasm tracer")

        main = int(self.args.main, 0) if self.args.main else None

        # If function address is not set then use the symbol address
        if self.args.address is None:
            cont = Container.from_stream(open(self.args.program))
            address = cont.loc_db.get_name_offset(self.args.functionname)
            if address is None:
                raise ValueError("Symbol %s does not exists in %s" % (self.args.functionname, self.args.program))
        else:
            address = int(self.args.address, 0)


        testcreator = TestCreator(self.args.functionname, address,
                                  self.args.program, self.args.headerfile,
                                  AVAILABLE_TRACER[self.args.trace],
                                  AVAILABLE_GENERATOR[self.args.generator],
                                  main, abi, machine, self.args.avoid_null)

        if self.args.verbose == 0:
            testcreator.logger.setLevel(logging.WARN)
        if self.args.verbose == 1:
            testcreator.logger.setLevel(logging.INFO)
        elif self.args.verbose == 2:
            testcreator.logger.setLevel(logging.DEBUG)

        createdTest = testcreator.create_test()

        if self.args.output:
            open(self.args.output, "w+").write(createdTest)
        else:
            print createdTest


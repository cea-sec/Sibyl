import logging
import copy

from sibyl.learn.replay import Replay


class TestCreator(object):

    """Class used to create a test. Each instance is detecated to only one learned function"""

    def __init__(self, functionname, address, program, tracer_class, generator_class, main_address, abicls, machine):
        """
        @functionname: name of the symbol of the learned function
        @address: address of the learned function in the program
        @program: program that uses the learned function
        @tracer_class: class of the tracer used to run the program
        @generator_class: class of the generator used to create the test
        @main_address: address where the tracer has to begin, if none the tracer begins at the entry point
        @abicls: class of the ABI used by the program
        @machine: machine used by the program
        """
        self.functionname = functionname
        self.address = address
        self.program = program
        self.tracer_class = tracer_class
        self.generator_class = generator_class
        self.main_address = main_address
        self.abicls = abicls
        self.machine = machine

        self.learnexceptiontext = []

        self.logger = logging.getLogger("testcreator")
        console_handler = logging.StreamHandler()
        log_format = "%(levelname)-5s: %(message)s"
        console_handler.setFormatter(logging.Formatter(log_format))
        self.logger.addHandler(console_handler)
        self.logger.setLevel(logging.INFO)

    def generate_test_class(self, nb_arg):
        generator = self.generator_class(self.trace, self.functionname, nb_arg, self.learnexceptiontext, self.abicls, self.machine)

        return generator.generate_test()

    def count_arg(self):
        '''
        Count the number of argument used by the learned function.
        '''

        nbArg = 0
        # TODO: improvement dichotomic
        for snapshot in self.trace:
            while True:

                tmpSnapshot = copy.deepcopy(snapshot)

                argFoundInSnapshot = tmpSnapshot.changeArg(nbArg + 1,
                                                           0x1122334455667788)

                # If the argument is not in snapshot then it is not an argument
                if not argFoundInSnapshot:
                    break

                isFuncFound = Replay(self.program, self.address, tmpSnapshot, self.abicls, self.machine).run()

                if not isFuncFound:
                    nbArg += 1

                else:
                    break

        return nbArg

    def create_trace(self):
        '''Create the raw trace'''

        self.logger.info("Tracing the program")
        tracer = self.tracer_class(
            self.program, self.address, self.main_address, self.abicls, self.machine)
        self.trace = tracer.do_trace()

        # If the trace is empty, test can not be created
        if not self.trace:
            raise RuntimeError(
                "Test can not be created: function seems not to be called")

    def remove_useless_snapshots(self):
        '''Keep traces that expose new trace path'''

        self.logger.info("Removing snapshots that do not expose new path")
        paths = set()
        to_be_removed = []
        for snapshot in self.trace:
            # If path of current snapshot is already known,
            path = frozenset(snapshot.paths.edges())
            if path in paths:
                to_be_removed += [snapshot]
            else:
                paths.add(path)
        for snapshot in to_be_removed:
            self.trace.remove(snapshot)

    def clean_trace(self):
        '''Try to remove all implementation dependant elements from the trace'''

        # Turn the trace into an implementation independent one
        self.logger.info("Cleaning snapshots")
        self.trace.clean()

    def test_trace(self):
        '''Find snapshots that do not recognize the learned function'''

        self.logger.info("Replaying cleaned snapshots")
        for snapshot in self.trace:
            r = Replay(self.program, self.address, snapshot, self.abicls, self.machine)
            if not r.run():
                self.learnexceptiontext += r.replayexception

    def create_test_from_trace(self):

        # Identify the number of argument
        self.logger.info("Counting number of arguments")
        nb_arg = self.count_arg()

        if nb_arg == 0:
            self.learnexceptiontext += ["the function seems to use zero argument"]
        
        # Generate the Test case
        self.logger.info("Generating the final test class")
        return self.generate_test_class(nb_arg)


    def create_test(self):
        """
        Main function of the trace that is in charge of calling other methods in the right order
        Return a string that correspong to the code of the test class
        """
        self.create_trace()

        self.remove_useless_snapshots()

        self.clean_trace()

        self.test_trace()

        return self.create_test_from_trace()

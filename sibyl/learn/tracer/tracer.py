import subprocess
import os


class Tracer(object):

    '''
    Abstract class used to represent a tracer
    A tracer is a class that run a program and log the executed instruction and the memory read and write and compile all these informations in a trace class
    '''

    reg_list = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]

    def __init__(self, program, address, main_address, abicls, machine):
        '''
        @program: traced program
        @address: address of the traced function
        @main_address: address where the tracer has to begin, if none the tracer begins at the entry point
        @abicls: class of the ABI used by the program
        @machine: machine used by the program
        '''
        self.program = os.path.abspath(program)
        self.address = address
        self.main_address = main_address
        self.abicls = abicls
        self.machine = machine

    def do_trace(self):
        '''
        Abstract method.
        Should return the trace of the program
        '''

        raise NotImplementedError("Abstract method")

    @staticmethod
    def _run_cmd(cmd):
        '''
        Runs the command @cmd
        Return stdout
        raise a RuntimeError if stderr is not empty
        '''
        run = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        stdout, stderr = run.communicate()

        stdout = stdout.strip()
        stderr = stderr.strip()
        if stdout:
            print stdout

        if stderr:
            print "STDERR is not empty"
            print stderr

        return stdout

from miasm2.analysis.machine import Machine


class Generator(object):
    '''
    Abstract class used to represent a generator
    A generator is a class that create a test from a snapshot
    Here a test is a sibyl test init function and a sibyl test check function
    '''

    def __init__(self, trace, functionname, nb_arg, learnexceptiontext, abicls, machine):
        '''
        @snapshot: snapshot used to create the test
        @number: index used to distinguish init and check functions' names between two snapshots
        @nb_arg: number of argument of the learned function
        @abicls: ABI of the program used during the learning
        @machine: machine of the program used during the learning
        '''
        self.trace = trace
        self.functionname = functionname
        self.nb_arg = nb_arg
        self.learnexceptiontext = learnexceptiontext
        self.abicls = abicls

        self.ira = Machine(machine).ira()
        self.ptr_size = self.ira.sizeof_pointer()/8

    @classmethod
    def addShiftLvl(cls, s):
        return ('    ' + s).replace('\n', '\n    ').rstrip(' ')

    def generate_test(self):
        '''Abstract method that should return the string corresponding to the code of the init test'''
        raise NotImplementedError("Abstract method")


class Printer(object):

    default_indentation_size = 4
    
    def __init__(self, indentation_size=default_indentation_size):
        self._indentation_size = indentation_size
        self._indentation_level = 0
        self._whitespace = ""
        self._print = ""

    def dump(self):
        return self._print

    def sub_lvl(self, n=1):
        self._indentation_level -= self._indentation_size * n

        if self._indentation_level < 0:
            raise RuntimeError("indentation level negative")

        self._whitespace = " "*self._indentation_level

    def add_lvl(self, n=1):
        self._indentation_level += self._indentation_size * n
        self._whitespace = " "*self._indentation_level
        
    def add_block(self, block):
        self._print += (self._whitespace + block).replace('\n', '\n'+self._whitespace).rstrip(' ')
        

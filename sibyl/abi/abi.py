class ABI(object):
    "Parent class, stand for an ABI"

    def __init__(self, jitter, ira):
        self.jitter = jitter
        self.ira = ira

    def reset(self):
        "Reset the current ABI"
        pass

    def add_arg(self, number, element):
        """Add a function argument
        @number: argument number (start 0)
        @element: argument
        """
        raise NotImplementedError("Abstract method")

    def prepare_call(self, ret_addr):
        """Prepare the call to a function
        @ret_addr: return address
        """
        raise NotImplementedError("Abstract method")

    def get_result(self):
        """Return the function result value, as int"""
        raise NotImplementedError("Abstract method")


class ABIRegsStack(ABI):

    regs_mapping = None # Register mapping (list of str)
    args = None         # order => element
    RTL = False         # RightToLeft arguments pushing

    def __init__(self, *args, **kwargs):
        super(ABIRegsStack, self).__init__(*args, **kwargs)
        self.args = {}

    def add_arg(self, number, element):
        if isinstance(element, int):
            self.args[number] = element
        else:
            raise NotImplementedError()

    def vm_push(self, element):
        raise NotImplementedError("Abstract method")

    def set_ret(self, element):
        raise NotImplementedError("Abstract method")

    def prepare_call(self, ret_addr):
        # Get args
        numbers = sorted(self.args.keys())
        if self.RTL:
            numbers = numbers[::-1]

        for i, key in enumerate(numbers):
            element = self.args[key]

            if i < len(self.regs_mapping):
                # Regs argument
                setattr(self.jitter.cpu, self.regs_mapping[i], element)
            else:
                # Stack argument
                self.vm_push(element)

        self.set_ret(ret_addr)

    def reset(self):
        self.args = {}

    def get_result(self):
        return getattr(self.jitter.cpu, self.ira.ret_reg.name)

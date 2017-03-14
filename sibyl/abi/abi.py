# This file is part of Sibyl.
# Copyright 2014 Camille MOUGEY <camille.mougey@cea.fr>
#
# Sibyl is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Sibyl is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Sibyl. If not, see <http://www.gnu.org/licenses/>.


class ABI(object):
    "Parent class, stand for an ABI"

    # Associated architectures
    arch = []

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

    def __init__(self, *args, **kwargs):
        super(ABIRegsStack, self).__init__(*args, **kwargs)
        self.args = {}

    def add_arg(self, number, element):
        if isinstance(element, (int, long)):
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

        for i, key in reversed(list(enumerate(numbers))):
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

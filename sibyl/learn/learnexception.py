class LearnException(Exception):

    def __init__(self, info):
        super(LearnException, self).__init__()        
        self.info = info

    def repr_class_name(self):
        return "LearnException"

    def __repr__(self):
        return self.repr_class_name() + "(" + self.info + ")"


class ReturnPointerException(LearnException):

    def __init__(self):
        super(ReturnPointerException, self).__init__(
            "return value might be a pointer")

    def repr_class_name(self):
        return "ReturnPointerException"


class ReturnValueException(LearnException):

    def __init__(self):
        super(ReturnPointerException, self).__init__(
            "return value is incorrect after replaying snapshot, the function might return nthing")

    def repr_class_name(self):
        return "ReturnValueException"

class D810Exception(Exception):
    pass


class AstException(D810Exception):
    pass


class AstEvaluationException(AstException):
    pass


class D810Z3Exception(D810Exception):
    pass


class ControlFlowException(D810Exception):
    pass


class EmulationException(D810Exception):
    pass


class EmulationIndirectJumpException(EmulationException):
    def __init__(self, message, dest_ea, dest_serial_list):
        super().__init__(message)
        self.dest_ea = dest_ea
        self.dest_serial_list = dest_serial_list


class UnresolvedMopException(EmulationException):
    pass


class TaintedOperandException(EmulationException):
    """A decision was attempted on a value the emulator INVENTED.

    Raised when a conditional jump, a jump table or an indirect jump reads an
    operand whose value derives from an unmodeled call's synthetic return
    (ticket d81-1t9x).  The integer exists -- it is stable and it propagates --
    but it proves nothing, so the emulator publishes UNKNOWN control flow
    instead of an arbitrary-but-stable branch.
    """


class WritableMemoryReadException(EmulationException):
    pass


class UnsupportedInstructionException(EmulationException):
    pass

class UnflatteningException(Exception):
    pass


class DispatcherUnflatteningException(UnflatteningException):
    pass


class NotDuplicableFatherException(UnflatteningException):
    pass


class NotResolvableFatherException(UnflatteningException):
    pass

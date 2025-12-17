import threading
import typing

T = typing.TypeVar("T")


class SingletonMeta(type):
    """
    Thread-safe implementation of Singleton metaclass.
    Can also be used as a decorator.
    """

    _instances: dict[type, object] = {}
    _locks: dict[type, threading.Lock] = {}

    def __call__(cls: type[T], *args: typing.Any, **kwargs: typing.Any) -> T:
        if cls not in SingletonMeta._instances:
            # use class-level _lock if defined, else fallback to internal lock
            lock: threading.Lock = getattr(
                cls, "_lock", SingletonMeta._locks.setdefault(cls, threading.Lock())
            )
            with lock:
                if cls not in SingletonMeta._instances:
                    instance = type.__call__(cls, *args, **kwargs)
                    SingletonMeta._instances[cls] = instance
        return typing.cast(T, SingletonMeta._instances[cls])


def singleton(cls: typing.Type[T]) -> typing.Type[T]:
    """
    Decorator to apply SingletonMeta behavior to a class.
    """

    class SingletonWrapper(cls, metaclass=SingletonMeta):
        pass

    SingletonWrapper.__name__ = cls.__name__
    SingletonWrapper.__doc__ = cls.__doc__
    SingletonWrapper.__module__ = cls.__module__
    return typing.cast(typing.Type[T], SingletonWrapper)

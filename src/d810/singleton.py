import threading


class SingletonMeta(type):
    """
    Thread-safe implementation of Singleton metaclass.
    """

    _instances: dict[type, object] = {}
    _locks: dict[type, threading.Lock] = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            # use class-level _lock if defined, else fallback to internal lock
            lock = getattr(cls, "_lock", None)
            if lock is None:
                lock = cls._locks.setdefault(cls, threading.Lock())
            with lock:
                if cls not in cls._instances:
                    instance = super().__call__(*args, **kwargs)
                    cls._instances[cls] = instance
        return cls._instances[cls]

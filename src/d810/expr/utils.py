import abc
import collections
import contextlib
import ctypes
import logging
import threading
import time
import typing
import weakref

from d810.hexrays.hexrays_helpers import MSB_TABLE

logger = logging.getLogger("D810")

CTYPE_SIGNED_TABLE = {
    1: ctypes.c_int8,
    2: ctypes.c_int16,
    4: ctypes.c_int32,
    8: ctypes.c_int64,
}
CTYPE_UNSIGNED_TABLE = {
    1: ctypes.c_uint8,
    2: ctypes.c_uint16,
    4: ctypes.c_uint32,
    8: ctypes.c_uint64,
}


def get_all_subclasses(python_class):
    python_class.__subclasses__()

    subclasses = set()
    check_these = [python_class]

    while check_these:
        parent = check_these.pop()
        for child in parent.__subclasses__():
            if child not in subclasses:
                subclasses.add(child)
                check_these.append(child)

    return sorted(subclasses, key=lambda x: x.__name__)


def unsigned_to_signed(unsigned_value, nb_bytes):
    return CTYPE_SIGNED_TABLE[nb_bytes](unsigned_value).value


def signed_to_unsigned(signed_value, nb_bytes):
    return CTYPE_UNSIGNED_TABLE[nb_bytes](signed_value).value


def get_msb(value, nb_bytes):
    return (value & MSB_TABLE[nb_bytes]) >> (nb_bytes * 8 - 1)


def get_add_cf(op1, op2, nb_bytes):
    res = op1 + op2
    return get_msb((((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (~(op1 ^ op2)))), nb_bytes)


def get_add_of(op1, op2, nb_bytes):
    res = op1 + op2
    return get_msb(((op1 ^ res) & (~(op1 ^ op2))), nb_bytes)


def get_sub_cf(op1, op2, nb_bytes):
    res = op1 - op2
    return get_msb((((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (op1 ^ op2))), nb_bytes)


def get_sub_of(op1, op2, nb_bytes):
    res = op1 - op2
    return get_msb(((op1 ^ res) & (op1 ^ op2)), nb_bytes)


def get_parity_flag(op1, op2, nb_bytes):
    tmp = CTYPE_UNSIGNED_TABLE[nb_bytes](op1 - op2).value
    return (bin(tmp).count("1") + 1) % 2


def ror(x, n, nb_bits=32):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (nb_bits - n))


def rol(x, n, nb_bits=32):
    return ror(x, nb_bits - n, nb_bits)


def __rol__(value: int, count: int, bits: int) -> int:
    """
    Rotate left on an unsigned integer of given bit width.
    """
    mask = (1 << bits) - 1
    count %= bits
    value &= mask
    return ((value << count) & mask) | (value >> (bits - count))


def __ror__(value: int, count: int, bits: int) -> int:
    """
    Rotate right on an unsigned integer of given bit width.
    """
    return __rol__(value, -count, bits)


def rol1(value: int, count: int) -> int:
    return __rol__(value, count, 8)


def rol2(value: int, count: int) -> int:
    return __rol__(value, count, 16)


def rol4(value: int, count: int) -> int:
    return __rol__(value, count, 32)


def rol8(value: int, count: int) -> int:
    return __rol__(value, count, 64)


def ror1(value: int, count: int) -> int:
    return __ror__(value, count, 8)


def ror2(value: int, count: int) -> int:
    return __ror__(value, count, 16)


def ror4(value: int, count: int) -> int:
    return __ror__(value, count, 32)


def ror8(value: int, count: int) -> int:
    return __ror__(value, count, 64)


K = typing.TypeVar("K")
V = typing.TypeVar("V")


class OverweightError(Exception):
    pass


Eviction: typing.TypeAlias = typing.Callable[["Cache"], None]


class Cache(typing.MutableMapping[K, V]):
    """
    https://google.github.io/guava/releases/16.0/api/docs/com/google/common/cache/CacheBuilder.html
    """

    @abc.abstractmethod
    def reap(self) -> None:
        pass

    class Stats(typing.NamedTuple):
        seq: int
        size: int
        weight: float
        hits: int
        misses: int
        max_size_ever: int
        max_weight_ever: float

    @property
    @abc.abstractmethod
    def stats(self) -> Stats:
        raise NotImplementedError


def LRU(cache: "Cache") -> None:  # noqa
    cache._kill(cache._root.lru_next)  # type: ignore  # noqa


def LRI(cache: "Cache") -> None:  # noqa
    cache._kill(cache._root.ins_next)  # type: ignore  # noqa


def LFU(cache: "Cache") -> None:  # noqa
    cache._kill(cache._root.lfu_prev)  # type: ignore  # noqa


class CacheImpl(Cache[K, V]):
    SKIP = object()
    """
    https://google.github.io/guava/releases/16.0/api/docs/com/google/common/cache/CacheBuilder.html
    """

    class Link:
        __slots__ = [
            "seq",
            "ins_prev",
            "ins_next",
            "lru_prev",
            "lru_next",
            "lfu_prev",
            "lfu_next",
            "key",
            "value",
            "weight",
            "written",
            "accessed",
            "hits",
            "unlinked",
        ]

        seq: int
        ins_prev: "CacheImpl.Link"
        ins_next: "CacheImpl.Link"
        lru_prev: "CacheImpl.Link"
        lru_next: "CacheImpl.Link"
        lfu_prev: "CacheImpl.Link"
        lfu_next: "CacheImpl.Link"
        key: typing.Any | weakref.ref
        value: typing.Any | weakref.ref
        weight: float
        written: float
        accessed: float
        hits: int
        unlinked: bool

        def __repr__(self) -> str:
            return (
                f"Link@{self.seq!s}("
                f'ins_prev={("@" + str(self.ins_prev.seq)) if self.ins_prev is not None else None}, '
                f'ins_next={("@" + str(self.ins_next.seq)) if self.ins_next is not None else None}, '
                f'lru_prev={("@" + str(self.lru_prev.seq)) if self.lru_prev is not None else None}, '
                f'lru_next={("@" + str(self.lru_next.seq)) if self.lru_next is not None else None}, '
                f'lfu_prev={("@" + str(self.lfu_prev.seq)) if self.lfu_prev is not None else None}, '
                f'lfu_next={("@" + str(self.lfu_next.seq)) if self.lfu_next is not None else None}, '
                f"key={self.key!r}, "
                f"value={self.value!r}, "
                f"weight={self.weight}, "
                f"written={self.written}, "
                f"accessed={self.accessed}, "
                f"hits={self.hits}, "
                f"unlinked={self.unlinked})"
            )

    _cache: typing.MutableMapping[typing.Any, Link]

    DEFAULT_MAX_SIZE = 256

    def __init__(
        self,
        *,
        max_size: int = DEFAULT_MAX_SIZE,
        max_weight: float | None = None,
        identity_keys: bool = False,
        expire_after_access: float | None = None,
        expire_after_write: float | None = None,
        removal_listener: (
            typing.Callable[[K | weakref.ref, V | weakref.ref], None] | None
        ) = None,
        clock: typing.Callable[[], float] | None = None,
        weak_keys: bool = False,
        weak_values: bool = False,
        weigher: typing.Callable[[V], float] = lambda _: 1.0,
        lock: threading.RLock | None = None,
        raise_overweight: bool = False,
        eviction: Eviction = LRU,
        track_frequency: bool | None = None,
    ) -> None:
        super().__init__()

        if clock is None:
            if expire_after_access is not None or expire_after_write is not None:
                clock = time.time
            else:
                clock = lambda: 0.0  # noqa

        self._max_size = max_size
        self._max_weight = max_weight
        self._identity_keys = identity_keys
        self._expire_after_access = expire_after_access
        self._expire_after_write = expire_after_write
        self._removal_listener = removal_listener
        self._clock = clock
        self._weak_keys = weak_keys
        self._weak_values = weak_values
        self._weigher = weigher
        self._lock = lock or threading.RLock()
        self._raise_overweight = raise_overweight
        self._eviction = eviction
        self._track_frequency = (
            track_frequency if track_frequency is not None else (eviction is LFU)
        )

        if weak_keys and not identity_keys:
            self._cache = weakref.WeakKeyDictionary()
        else:
            self._cache = {}

        self._root = CacheImpl.Link()
        self._root.seq = 0
        self._root.ins_next = self._root.ins_prev = self._root
        self._root.lru_next = self._root.lru_prev = self._root
        if self._track_frequency:
            self._root.lfu_next = self._root.lfu_prev = self._root

        weak_dead: collections.deque[CacheImpl.Link] | None
        if weak_keys or weak_values:
            weak_dead = collections.deque()
            weak_dead_ref = weakref.ref(weak_dead)
        else:
            weak_dead = None
            weak_dead_ref = None
        self._weak_dead = weak_dead
        self._weak_dead_ref = weak_dead_ref

        self._seq = 0
        self._size = 0
        self._weight = 0.0
        self._hits = 0
        self._misses = 0
        self._max_size_ever = 0
        self._max_weight_ever = 0.0

    def _unlink(self, link: Link) -> None:
        if link is self._root:
            raise TypeError
        if link.unlinked:
            return

        link.ins_prev.ins_next = link.ins_next
        link.ins_next.ins_prev = link.ins_prev
        link.ins_next = link.ins_prev = link

        link.lru_prev.lru_next = link.lru_next
        link.lru_next.lru_prev = link.lru_prev
        link.lru_next = link.lru_prev = link

        if self._track_frequency:
            link.lfu_prev.lfu_next = link.lfu_next
            link.lfu_next.lfu_prev = link.lfu_prev
            link.lfu_next = link.lfu_prev = link

        if self._removal_listener is not None:
            try:
                self._removal_listener(link.key, link.value)
            except Exception:
                logger.exception("Removal listener raised exception")

        self._size -= 1
        self._weight -= link.weight
        link.key = link.value = None
        link.unlinked = True

    def _kill(self, link: Link) -> None:
        if link is self._root:
            raise RuntimeError

        key = link.key
        if self._weak_keys:
            if key is not None:
                key = key()
            if key is None:
                key = self.SKIP

        if key is not self.SKIP:
            cache_key = id(key) if self._identity_keys else key
            cache_link = self._cache.get(cache_key)
            if cache_link is link:
                del self._cache[cache_key]

        self._unlink(link)

    def _reap(self) -> None:
        if self._weak_dead is not None:
            while True:
                try:
                    link = self._weak_dead.popleft()
                except IndexError:
                    break
                self._kill(link)

        clock = None

        if self._expire_after_write is not None:
            clock = self._clock()
            deadline = clock - self._expire_after_write

            while self._root.ins_next is not self._root:
                link = self._root.ins_next
                if link.written > deadline:
                    break
                self._kill(link)

        if self._expire_after_access is not None:
            if clock is None:
                clock = self._clock()
            deadline = clock - self._expire_after_access

            while self._root.lru_next is not self._root:
                link = self._root.lru_next
                if link.accessed > deadline:
                    break
                self._kill(link)

    def reap(self) -> None:
        with self._lock:
            self._reap()

    def _get_link(self, key: K) -> tuple[Link, V]:
        cache_key = id(key) if self._identity_keys else key

        link = self._cache[cache_key]
        if link.unlinked:
            raise Exception

        def fail():
            with contextlib.suppress(KeyError):
                del self._cache[cache_key]
            self._unlink(link)
            raise KeyError(key)

        if self._identity_keys:
            link_key = link.key
            if self._weak_keys:
                link_key = link_key()
                if link_key is None:
                    fail()
            if key is not link_key:
                fail()

        value = link.value
        if self._weak_values:
            if value is not None:
                value = value()
            if value is None:
                fail()

        return link, value  # type: ignore

    def __getitem__(self, key: K) -> V:
        with self._lock:
            self._reap()

            try:
                link, value = self._get_link(key)
            except KeyError:
                self._misses += 1
                raise KeyError(key) from None

            if link.lru_next is not self._root:
                link.lru_prev.lru_next = link.lru_next
                link.lru_next.lru_prev = link.lru_prev

                lru_last = self._root.lru_prev
                lru_last.lru_next = self._root.lru_prev = link
                link.lru_prev = lru_last
                link.lru_next = self._root

            if self._track_frequency:
                lfu_pos = link.lfu_prev
                while lfu_pos is not self._root and lfu_pos.hits <= link.hits:
                    lfu_pos = lfu_pos.lfu_prev

                if link.lfu_prev is not lfu_pos:
                    link.lfu_prev.lfu_next = link.lfu_next
                    link.lfu_next.lfu_prev = link.lfu_prev

                    lfu_last = lfu_pos.lfu_prev
                    lfu_last.lfu_next = lfu_pos.lfu_prev = link
                    link.lfu_prev = lfu_last
                    link.lfu_next = lfu_pos

            link.accessed = self._clock()
            link.hits += 1
            self._hits += 1
            return value

    @staticmethod
    def _weak_die(
        dead_ref: weakref.ref, link: Link, key_ref: weakref.ref
    ) -> None:  # noqa
        dead = dead_ref()
        if dead is not None:
            dead.append(link)

    @property
    def _full(self) -> bool:
        if self._max_size is not None and self._size >= self._max_size:
            return True
        if self._max_weight is not None and self._weight >= self._max_weight:
            return True
        return False

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            while True:
                link = self._root.ins_prev
                if link is self._root:
                    break
                if link.unlinked:
                    raise TypeError
                self._unlink(link)

    def __setitem__(self, key: K, value: V) -> None:
        weight = self._weigher(value)

        with self._lock:
            self._reap()

            if self._max_weight is not None and weight > self._max_weight:
                if self._raise_overweight:
                    raise OverweightError
                else:
                    return

            try:
                existing_link, existing_value = self._get_link(key)
            except KeyError:
                pass
            else:
                self._unlink(existing_link)

            while self._full:
                self._eviction(self)

            link = CacheImpl.Link()

            self._seq += 1
            link.seq = self._seq

            def make_ref(o, b):
                if not b:
                    return o
                return weakref.ref(o, functools.partial(CacheImpl._weak_die, self._weak_dead_ref, link))  # type: ignore  # noqa

            link.key = make_ref(key, self._weak_keys)
            link.value = make_ref(value, self._weak_values)

            link.weight = weight
            link.written = link.accessed = self._clock()
            link.hits = 0
            link.unlinked = False

            ins_last = self._root.ins_prev
            ins_last.ins_next = self._root.ins_prev = link
            link.ins_prev = ins_last
            link.ins_next = self._root

            lru_last = self._root.lru_prev
            lru_last.lru_next = self._root.lru_prev = link
            link.lru_prev = lru_last
            link.lru_next = self._root

            if self._track_frequency:
                lfu_last = self._root.lfu_prev
                lfu_last.lfu_next = self._root.lfu_prev = link
                link.lfu_prev = lfu_last
                link.lfu_next = self._root

            self._weight += weight
            self._size += 1
            self._max_size_ever = max(self._size, self._max_size_ever)
            self._max_weight_ever = max(self._weight, self._max_weight_ever)

            cache_key = id(key) if self._identity_keys else key
            self._cache[cache_key] = link

    def __delitem__(self, key: K) -> None:
        with self._lock:
            self._reap()

            link, value = self._get_link(key)

            cache_key = id(key) if self._identity_keys else key
            del self._cache[cache_key]

            self._unlink(link)

    def __len__(self) -> int:
        with self._lock:
            self._reap()

            return self._size

    def __contains__(self, key: K) -> bool:  # type: ignore
        with self._lock:
            self._reap()

            try:
                self._get_link(key)
            except KeyError:
                return False
            else:
                return True

    def __iter__(self) -> typing.Iterator[K]:
        with self._lock:
            self._reap()

            link = self._root.ins_prev
            while link is not self._root:
                key = link.key
                if self._weak_keys:
                    if key is not None:
                        key = key()
                    if key is not None:
                        yield key
                else:
                    yield key  # type: ignore

                nxt = link.ins_prev
                if nxt is link:
                    raise ValueError
                link = nxt

    @property
    def stats(self) -> Cache.Stats:
        with self._lock:
            return Cache.Stats(
                self._seq,
                self._size,
                self._weight,
                self._hits,
                self._misses,
                self._max_size_ever,
                self._max_weight_ever,
            )

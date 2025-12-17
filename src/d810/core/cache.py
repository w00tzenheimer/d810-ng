import abc
import collections
import contextlib
import dataclasses
import functools
import threading
import time
import typing
import weakref

from .logging import getLogger

logger = getLogger(__name__)

K = typing.TypeVar("K")
V = typing.TypeVar("V")
Eviction = typing.Callable[["Cache"], None]


class OverweightError(Exception):
    pass


class Cache(typing.MutableMapping[K, V]):
    @abc.abstractmethod
    def reap(self) -> None: ...

    @property
    @abc.abstractmethod
    def stats(self) -> "Stats": ...


@dataclasses.dataclass(slots=True, frozen=True)
class Stats:
    seq: int
    size: int
    weight: float
    hits: int
    misses: int
    max_size_ever: int
    max_weight_ever: float


def LRU(cache: "Cache") -> None:
    """
    Remove the *least-recently-used* entry from *cache*.

    The concrete :class:`CacheImpl` implementation maintains a dedicated
    doubly-linked list that is updated on every access.  The sentinel node
    ``cache._root`` sits between the most-recently-used (MRU) element on its
    left and the least-recently-used (LRU) element on its right.  Therefore,
    the node referenced by ``_root.lru_next`` is guaranteed to represent the
    cache entry that has not been accessed for the longest time.

    This helper simply forwards to the private :pymeth:`CacheImpl._kill`
    routine with that node, thereby

    1. unlinking it from all internal accounting structures,
    2. adjusting the cache's size / weight counters, and
    3. invoking any *removal_listener* registered with the cache.

    Parameters
    ----------
    cache : Cache
        The cache instance from which an element should be evicted.  In
        practice this is a :class:`CacheImpl` object (or wrapper) exposing the
        expected private helpers.  The function mutates *cache* in-place and
        has no return value.
    """
    cache._kill(cache._root.lru_next)  # type: ignore


def LRI(cache: "Cache") -> None:
    """
    Remove the *least-recently-inserted* (oldest) entry from *cache*.

    Unlike LRU, which is driven by access *time*, this eviction policy is
    strictly FIFO: the element that has resided in the cache the longest—
    independent of any subsequent accesses—is expelled first.  Internally the
    cache keeps a second insertion-ordered linked list where the sentinel’s
    ``ins_next`` pointer refers to the oldest element.  Passing this link to
    :pymeth:`CacheImpl._kill` achieves the eviction.

    Parameters
    ----------
    cache : Cache
        The cache instance to operate on.  Must be compatible with
        :class:`CacheImpl`'s private interface.
    """
    cache._kill(cache._root.ins_next)  # type: ignore


def LFU(cache: "Cache") -> None:
    """
    Remove the *least-frequently-used* entry from *cache*.

    When *frequency* tracking is enabled the cache chains all entries in a
    list ordered by their individual hit-count.  The node referenced by
    ``_root.lfu_prev`` is the one with the lowest number of recorded hits and
    is therefore selected as the eviction victim.

    The function delegates the heavy lifting to
    :pymeth:`CacheImpl._kill`, which unlinks the node and updates all
    associated statistics.

    Parameters
    ----------
    cache : Cache
        The cache instance subject to eviction.  Expected to be a
        :class:`CacheImpl` or compatible object.
    """
    cache._kill(cache._root.lfu_prev)  # type: ignore


def _const_one(_: object) -> float:
    return 1.0


class CacheImpl(Cache[K, V]):
    SKIP = object()

    @dataclasses.dataclass(slots=True)
    class Link:
        seq: int = dataclasses.field(default=0)
        ins_prev: "CacheImpl.Link" = dataclasses.field(init=False)
        ins_next: "CacheImpl.Link" = dataclasses.field(init=False)
        lru_prev: "CacheImpl.Link" = dataclasses.field(init=False)
        lru_next: "CacheImpl.Link" = dataclasses.field(init=False)
        lfu_prev: "CacheImpl.Link" = dataclasses.field(init=False)
        lfu_next: "CacheImpl.Link" = dataclasses.field(init=False)
        key: typing.Any | weakref.ref = dataclasses.field(init=False)
        value: typing.Any | weakref.ref = dataclasses.field(init=False)
        weight: float = dataclasses.field(init=False)
        written: float = dataclasses.field(init=False)
        accessed: float = dataclasses.field(init=False)
        hits: int = dataclasses.field(init=False)
        unlinked: bool = dataclasses.field(init=False)

    DEFAULT_MAX_SIZE = 256

    def __init__(
        self,
        *,
        max_size: int = DEFAULT_MAX_SIZE,
        max_weight: float | None = None,
        identity_keys: bool = False,
        expire_after_access: int | None = None,
        expire_after_write: int | None = None,
        removal_listener: (
            typing.Callable[[K | weakref.ref, V | weakref.ref], None] | None
        ) = None,
        clock: typing.Callable[[], float] | None = None,
        weak_keys: bool = False,
        weak_values: bool = False,
        weigher: typing.Callable[[V], float] = _const_one,
        lock: "threading.RLock | None" = None,
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
            except Exception as e:
                logger.exception(
                    "Removal listener raised exception: %s", e, exc_info=True
                )

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

    def clear(self, reset_stats: bool = False) -> None:
        with self._lock:
            self._cache.clear()
            while True:
                link = self._root.ins_prev
                if link is self._root:
                    break
                if link.unlinked:
                    raise TypeError
                self._unlink(link)
            if reset_stats:
                self.reset_stats()

    def reset_stats(self) -> None:
        """Reset all statistics counters for this cache.

        This does not mutate the cache contents. Use in tandem with
        `clear()` if you also want to drop entries.

        After calling this, `stats()` will report zeros for `hits`, `misses`,
        `max_size_ever`, `max_weight_ever`, and `seq`.
        """
        with self._lock:
            self._hits = 0
            self._misses = 0
            self._max_size_ever = 0
            self._max_weight_ever = 0.0
            self._seq = 0

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

    def stats(self) -> Stats:
        with self._lock:
            return Stats(
                seq=self._seq,
                size=self._size,
                weight=self._weight,
                hits=self._hits,
                misses=self._misses,
                max_size_ever=self._max_size_ever,
                max_weight_ever=self._max_weight_ever,
            )


# -----------------------------------------------------------------------------
# Now the decorator factories:
# -----------------------------------------------------------------------------


def cache(
    user_function: typing.Callable | None = None,
    *,
    max_size: int = CacheImpl.DEFAULT_MAX_SIZE,
    max_weight: float | None = None,
    identity_keys: bool = False,
    expire_after_access: int | None = None,
    expire_after_write: int | None = None,
    removal_listener: typing.Callable | None = None,
    clock: typing.Callable[[], float] | None = None,
    weak_keys: bool = False,
    weak_values: bool = False,
    weigher: typing.Callable[[V], float] = _const_one,
    lock: "threading.RLock | None" = None,
    raise_overweight: bool = False,
    eviction: Eviction = LRU,
    track_frequency: bool | None = None,
) -> typing.Callable:
    """
    Usage:
        @cache
        def f(...): ...
    or
        @cache(max_size=1024, expire_after_access=60)
        def heavy(...): ...
    """

    def decorating_function(fn: typing.Callable) -> typing.Callable:
        c = CacheImpl(
            max_size=max_size,
            max_weight=max_weight,
            identity_keys=identity_keys,
            expire_after_access=expire_after_access,
            expire_after_write=expire_after_write,
            removal_listener=removal_listener,
            clock=clock,
            weak_keys=weak_keys,
            weak_values=weak_values,
            weigher=weigher,
            lock=lock,
            raise_overweight=raise_overweight,
            eviction=eviction,
            track_frequency=track_frequency,
        )

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # build a hashable key
            key = args
            if kwargs:
                # frozenset of sorted items is canonical
                key = args + (frozenset(kwargs.items()),)
            try:
                return c[key]  # type: ignore
            except KeyError:
                result = fn(*args, **kwargs)
                c[key] = result  # type: ignore
                return result

        # expose the cache instance for introspection / stats
        wrapper.cache = c  # type: ignore
        return wrapper

    # allow @cache without parentheses
    if user_function is None:
        return decorating_function
    else:
        return decorating_function(user_function)  # type: ignore


def lru_cache(
    user_function: typing.Callable | None = None,
    *,
    max_size: int | None = None,
    **kwargs,
) -> typing.Callable:
    """
    Like functools.lru_cache, but backed by our CacheImpl.
    """
    if max_size is None:
        max_size = CacheImpl.DEFAULT_MAX_SIZE
    return cache(user_function, max_size=max_size, eviction=LRU, **kwargs)


# alias to match stdlib
cache.cache = cache
cache.lru_cache = lru_cache

import gc
import unittest

from d810.cache import CacheImpl, OverweightError, cache, lru_cache


class FixedClock:
    def __init__(self):
        self.time = 0.0

    def __call__(self):
        return self.time


class TestCacheImpl(unittest.TestCase):
    def test_basic_set_get(self):
        c = CacheImpl(max_size=10, clock=FixedClock())
        c["a"] = 1
        self.assertIn("a", c)
        self.assertEqual(c["a"], 1)
        self.assertEqual(len(c), 1)
        del c["a"]
        self.assertNotIn("a", c)
        self.assertEqual(len(c), 0)

    def test_stats_hits_misses(self):
        c = CacheImpl(max_size=10, clock=FixedClock())
        stats = c.stats
        self.assertEqual(stats.hits, 0)
        self.assertEqual(stats.misses, 0)
        with self.assertRaises(KeyError):
            _ = c["missing"]
        stats = c.stats
        self.assertEqual(stats.misses, 1)
        c["x"] = 99
        _ = c["x"]
        stats = c.stats
        self.assertEqual(stats.hits, 1)

    def test_lru_eviction(self):
        c = CacheImpl(max_size=2, clock=FixedClock())
        c["a"] = 1
        c["b"] = 2
        # Access 'a' to make it most recently used
        _ = c["a"]
        c["c"] = 3  # should evict 'b'
        self.assertIn("a", c)
        self.assertIn("c", c)
        self.assertNotIn("b", c)

    def test_raise_overweight(self):
        c = CacheImpl(
            max_size=10,
            max_weight=5.0,
            raise_overweight=True,
            weigher=lambda v: float(v),  # type: ignore[arg-type]
            clock=FixedClock(),
        )
        c["k1"] = 3
        with self.assertRaises(OverweightError):
            c["k2"] = 10

    def test_expire_after_write(self):
        clock = FixedClock()
        c = CacheImpl(max_size=10, expire_after_write=5, clock=clock)
        c["a"] = 1
        clock.time = 6
        c.reap()
        self.assertNotIn("a", c)

    def test_expire_after_access(self):
        clock = FixedClock()
        c = CacheImpl(max_size=10, expire_after_access=5, clock=clock)
        c["a"] = 1
        _ = c["a"]
        clock.time = 6
        c.reap()
        self.assertNotIn("a", c)

    def test_removal_listener(self):
        removed = []

        def listener(k, v):
            removed.append((k, v))

        c = CacheImpl(max_size=1, removal_listener=listener, clock=FixedClock())
        c["x"] = "first"
        c["y"] = "second"  # should evict 'x'
        self.assertEqual(removed, [("x", "first")])

    def test_identity_keys(self):
        a = int("1000")
        b = int("1000")
        self.assertIsNot(a, b)
        c = CacheImpl(max_size=10, identity_keys=True, clock=FixedClock())
        c[a] = "value1"
        c[b] = "value2"
        self.assertEqual(len(c), 2)
        self.assertEqual(c[a], "value1")
        self.assertEqual(c[b], "value2")

    def test_weak_keys(self):
        class Key:
            pass

        k = Key()
        c = CacheImpl(max_size=10, weak_keys=True, clock=FixedClock())
        c[k] = "data"
        self.assertIn(k, c)
        del k
        gc.collect()
        c.reap()
        # original key should be removed
        self.assertEqual(len(c), 0)

    def test_weak_values(self):
        class Val:
            pass

        v = Val()
        c = CacheImpl(max_size=10, weak_values=True, clock=FixedClock())
        c["key"] = v
        self.assertIn("key", c)
        del v
        gc.collect()
        c.reap()
        self.assertNotIn("key", c)


class TestCacheDecorator(unittest.TestCase):
    def test_cache_decorator_basic(self):
        calls = []

        @cache
        def f(x):
            calls.append(x)
            return x * 2

        self.assertEqual(f(10), 20)
        self.assertEqual(f(10), 20)
        self.assertEqual(calls, [10])
        # stats via wrapper.cache
        stats = f.cache.stats
        self.assertEqual(stats.misses, 1)
        self.assertEqual(stats.hits, 1)

    def test_cache_decorator_kwargs(self):
        calls = []

        @cache(max_size=5)
        def g(x, y=1):
            calls.append((x, y))
            return x + y

        self.assertEqual(g(1, y=2), 3)
        self.assertEqual(g(1, y=2), 3)
        self.assertEqual(calls, [(1, 2)])

    def test_lru_cache_alias(self):
        calls = []

        @lru_cache(max_size=1)
        def h(x):
            calls.append(x)
            return x

        h(1)
        h(1)
        self.assertEqual(len(calls), 1)
        h(2)
        # 1 should be evicted
        self.assertEqual(h(2), 2)
        self.assertEqual(len(calls), 2)


class TestCPythonCacheBehavior(unittest.TestCase):
    def test_unlimited_cache_growth(self):
        @cache
        def f(x):
            return x

        for i in range(5):
            f(i)
        # Unlimited caching: cache grows without eviction ([stackoverflow.com](https://stackoverflow.com/questions/78875431/how-to-disable-functools-lru-cache-when-developing-locally?utm_source=chatgpt.com))
        self.assertEqual(f.cache.stats.size, 5)

    def test_cache_info_and_clear(self):
        @cache
        def f(x):
            return x

        f(1)
        f(1)
        stats = f.cache.stats
        self.assertEqual(stats.hits, 1)
        self.assertEqual(stats.misses, 1)
        # clear removes entries but does not reset stats ([docs.python.org](https://docs.python.org/3/library/functools.html?utm_source=chatgpt.com))
        f.cache.clear()
        self.assertEqual(f.cache.stats.size, 0)

    def test_unhashable_argument(self):
        @lru_cache(max_size=10)
        def f(x):
            return x

        # Arguments must be hashable ([asyncstdlib.readthedocs.io](https://asyncstdlib.readthedocs.io/en/v3.9.2/source/api/functools.html?utm_source=chatgpt.com))
        with self.assertRaises(TypeError):
            f([1, 2, 3])

    def test_maxsize_none_equals_unlimited(self):
        @lru_cache(max_size=None)  # type: ignore[arg-type]
        def f(x):
            return x

        for i in range(3):
            f(i)
        self.assertEqual(f.cache.stats.size, 3)

    def test_wrapper_attributes(self):
        @cache
        def f(x):
            return x

        # wrapper should expose __wrapped__ attribute
        self.assertTrue(hasattr(f, "__wrapped__"))


if __name__ == "__main__":
    unittest.main()

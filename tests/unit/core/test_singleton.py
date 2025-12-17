import dataclasses
import unittest

from d810.core import SingletonMeta, singleton


class TestSingleton(unittest.TestCase):

    def test_singleton_decorator(self):
        @singleton
        class MyClass:
            def __init__(self, value: int) -> None:
                self.value = value

        a = MyClass(10)
        b = MyClass(20)
        self.assertIs(a, b)
        self.assertEqual(a.value, 10)
        self.assertEqual(b.value, 10)

    def test_singleton_meta(self):
        class DirectSingleton(metaclass=SingletonMeta):
            def __init__(self, x: int) -> None:
                self.x = x

        d1: DirectSingleton = DirectSingleton(1)
        d2: DirectSingleton = DirectSingleton(2)
        self.assertIs(d1, d2)
        self.assertEqual(d1.x, 1)
        self.assertEqual(d2.x, 1)

    def test_singleton_decorator_on_dataclass(self):
        @singleton
        @dataclasses.dataclass
        class DataSingleton:
            a: int
            b: int

        ds1 = DataSingleton(5, 6)
        ds2 = DataSingleton(7, 8)
        self.assertIs(ds1, ds2)
        self.assertEqual(ds1.a, 5)
        self.assertEqual(ds1.b, 6)
        self.assertEqual(ds2.a, 5)
        self.assertEqual(ds2.b, 6)

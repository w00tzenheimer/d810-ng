import unittest
from typing import Annotated, AnyStr, Literal

from d810.registry import Registrant, deferred_property, typecheck, typename


class TestTypeFunctions(unittest.TestCase):
    def test_typename_basic(self):
        self.assertEqual(typename(int), "int")
        self.assertEqual(typename("string"), "str")
        self.assertEqual(typename(list[int]), "list[int]")

    def test_typecheck_basic(self):
        self.assertTrue(typecheck(5, int))
        self.assertFalse(typecheck(5, str))
        self.assertTrue(typecheck("a", AnyStr))
        self.assertTrue(typecheck(b"bytes", AnyStr))
        self.assertTrue(typecheck(None, None))
        self.assertTrue(typecheck(1, Literal[1, 2]))
        self.assertFalse(typecheck(3, Literal[1, 2]))
        self.assertTrue(typecheck("a", Annotated[str, "meta"]))


class TestDeferredProperty(unittest.TestCase):
    def test_deferred_property_resolution(self):
        class C:
            prop = deferred_property()

        c = C()
        C.prop.defer(c, lambda: 42)
        self.assertEqual(c.prop, 42)
        self.assertEqual(c.prop, 42)

    def test_deferred_property_no_deferral(self):
        class C:
            prop = deferred_property()

        c = C()
        with self.assertRaises(AttributeError):
            _ = c.prop

    def test_deferred_property_direct_set(self):
        class C:
            prop = deferred_property()

        c = C()
        c.prop = "value"
        self.assertEqual(c.prop, "value")


class TestRegistrant(unittest.TestCase):
    def test_registration(self):
        class Base(Registrant):
            pass

        self.assertEqual(Base.registry, {})
        self.assertEqual(Base.lazy_registry, {})

        class Sub1(Base):
            pass

        class Sub2(Base):
            pass

        self.assertIn("sub1", Base.registry)
        self.assertIs(Base.get("sub1"), Sub1)
        self.assertIs(Base.get("SUB2"), Sub2)
        all_classes = Base.all()
        self.assertCountEqual(all_classes, [Sub1, Sub2])
        subclasses = Base.get_subclasses()
        self.assertCountEqual(subclasses, [Sub1, Sub2])

    def test_normalize_key(self):
        self.assertEqual(Registrant.normalize_key("Hello"), "hello")


if __name__ == "__main__":
    unittest.main()

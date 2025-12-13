import abc
import functools
import inspect
import unittest
from typing import Annotated, AnyStr, Literal

from d810.core import (
    FilterableGenerator,
    Registrant,
    deferred_property,
    typecheck,
    typename,
)


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


class TestFilterableGenerator(unittest.TestCase):
    def test_basic_filtering_with_list(self):
        """If you give it a list and no predicates, it yields everything."""
        fl = FilterableGenerator([1, 2, 3, 4])
        self.assertEqual(list(fl), [1, 2, 3, 4])

    def test_single_predicate(self):
        """One predicate should filter down correctly."""
        fl = FilterableGenerator([1, 2, 3, 4]).filter(lambda x: x % 2 == 0)
        self.assertEqual(list(fl), [2, 4])

    def test_chained_predicates(self):
        """Chaining .filter(...) calls accumulates predicates."""
        fl = (
            FilterableGenerator([1, 2, 3, 4])
            .filter(lambda x: x % 2 == 0)
            .filter(lambda x: x > 2)
        )
        self.assertEqual(list(fl), [4])

    def test_generator_input_and_exhaustion(self):
        """Can seed with a generator; once consumed it's empty."""
        gen = (i for i in range(3))
        fg = FilterableGenerator(gen)
        # first iteration
        self.assertEqual(list(fg), [0, 1, 2])
        # second iteration: generator is exhausted
        self.assertEqual(list(fg), [])

    def test_repr_does_not_consume_source(self):
        """repr() should not pull items out of a generator."""
        gen = (i for i in range(2))
        fg = FilterableGenerator(gen).filter(lambda x: True)
        r = repr(fg)
        # repr should mention the class name and number of predicates
        self.assertIn("FilterableGenerator", r)
        self.assertIn("preds=1", r)
        # still can consume after repr()
        self.assertEqual(list(fg), [0, 1])

    def test_original_instance_unchanged_by_filter(self):
        """Calling .filter() returns a new instance, does not mutate the old."""
        base = FilterableGenerator([10, 20, 30])
        derived = base.filter(lambda x: x > 15)
        # old instance has no predicates
        self.assertEqual(len(base._preds), 0)
        # new instance got the predicate
        self.assertEqual(len(derived._preds), 1)
        self.assertEqual(list(derived), [20, 30])


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

    def test_direct_subclass_registry_initialization(self):
        class Base(Registrant):
            pass

        # direct subclass gets its own empty registries
        self.assertTrue(hasattr(Base, "registry"))
        self.assertEqual(Base.registry, {})
        self.assertTrue(hasattr(Base, "lazy_registry"))
        self.assertEqual(Base.lazy_registry, {})

    def test_subclass_automatic_registration(self):
        class Base(Registrant):
            pass

        class Sub(Base):
            pass

        # Sub was auto-registered under 'sub'
        self.assertIn("sub", Base.registry)
        self.assertIs(Base.registry["sub"], Sub)

    def test_normalize_key_respects_lowercase(self):
        class Base(Registrant):
            pass

        class Foo(Base):
            registrant_name = "CamelCase"

        # registry key is lowercased
        self.assertIn("camelcase", Base.registry)
        self.assertIs(Base.registry["camelcase"], Foo)

    def test_prevent_self_registration(self):
        class Base(Registrant):
            pass

        # Manually trying to register Base into its own registry is ignored
        Base.register(Base)
        self.assertNotIn("base", Base.registry)

    def test_get_existing_class(self):
        class Base(Registrant):
            pass

        class Sub(Base):
            pass

        found = Base.get("sub")
        self.assertIs(found, Sub)

    def test_get_case_insensitive(self):
        class Base(Registrant):
            pass

        class Sub(Base):
            pass

        # uppercase lookup works
        self.assertIs(Base.get("SUB"), Sub)

    def test_get_missing_raises_keyerror(self):
        class Base(Registrant):
            pass

        with self.assertRaises(KeyError):
            Base.get("does_not_exist")

    def test_all_returns_all_registered(self):
        class Base(Registrant):
            pass

        class A(Base):
            pass

        class B(Base):
            pass

        got = Base.all()
        # unordered comparison
        self.assertCountEqual(got, [A, B])

    def test_get_subclasses_returns_all(self):
        class Base(Registrant):
            pass

        class A(Base):
            pass

        class B(Base):
            pass

        class C(A):
            pass

        # should see A, B, C in that order
        subs = Base.get_subclasses()
        self.assertEqual(subs, [A, B, C])

    def test_get_subclasses_with_base_argument(self):
        class Base(Registrant):
            pass

        class A(Base):
            pass

        class B(Base):
            pass

        class C(A):
            pass

        subs = Registrant.get_subclasses(base=Base)
        self.assertEqual(subs, [A, B, C])

    def test_get_subclasses_invalid_base(self):
        with self.assertRaises(TypeError):
            Registrant.get_subclasses(base=int)

    def test_filter_returns_generator_of_registered(self):
        """Registry.filter(...) should give you a FilterableGenerator over registry."""

        class Base(Registrant):
            pass

        class A(Base):
            pass

        class B(Base):
            pass

        class _C(Base):
            pass

        fg = Base.filter(lambda c: not c.__name__.startswith("_"))
        self.assertIsInstance(fg, FilterableGenerator)

        names = [cls.__name__ for cls in fg]
        # should include only A and B, in registration order
        self.assertEqual(names, ["A", "B"])

    def test_chain_filters_on_registry(self):
        """You can chain filter calls on a registry filter."""

        class Base(Registrant):
            pass

        class A(Base):
            pass

        class B(Base):
            pass

        class C(Base):
            pass

        chain = Base.filter(lambda c: c.__name__ in ("A", "B", "C")).filter(
            lambda c: c.__name__ == "B"
        )
        self.assertEqual([c.__name__ for c in chain], ["B"])

    def test_filter_out_abstract_classes(self):
        """Filter by inspect.isabstract(...) to weed out ABCs."""

        class Base(Registrant):
            pass

        class AbstractX(Base, abc.ABC):
            @abc.abstractmethod
            def foo(self): ...

        class RealX(Base): ...

        # both are registered initially
        all_names = [c.__name__ for c in Base.filter(lambda c: True)]
        self.assertCountEqual(all_names, ["AbstractX", "RealX"])

        non_abs = Base.filter(lambda c: not inspect.isabstract(c))
        self.assertEqual([c.__name__ for c in non_abs], ["RealX"])

    def test_empty_filter(self):
        """A predicate that always fails yields an empty sequence."""

        class Base(Registrant):
            pass

        class A(Base):
            pass

        fg = Base.filter(lambda c: False)
        self.assertEqual(list(fg), [])

    def test_lazy_register_and_get(self):
        class Base(Registrant):
            pass

        @functools.cache
        def loader():
            class LazyCls(Base):
                pass

            return LazyCls

        Base.lazy_register(loader)
        # it sits in lazy_registry under its function name
        self.assertIn("loader", Base.lazy_registry)

        # calling get should load it, pop lazy_registry & add to registry
        inst = Base.get("loader")
        self.assertIs(inst, loader())
        self.assertNotIn("loader", Base.lazy_registry)
        self.assertIn("loader", Base.registry)
        self.assertIs(Base.registry["loader"], loader())

    def test_filter_does_not_force_lazy_loading(self):
        """Filtering over registry should not trigger lazy_registry entries."""

        class Base(Registrant):
            pass

        @functools.cache
        def loader():
            class LazyCls(Base):
                pass

            return LazyCls

        Base.lazy_register(loader)
        # at this point, LazyCls is only in lazy_registry
        fg = Base.filter(lambda c: True)
        names = [c.__name__ for c in fg]
        # should not include LazyCls yet
        self.assertNotIn("LazyCls", names)
        # confirm not yet moved into main registry
        self.assertNotIn("loader", Base.registry)
        # retrieving via .get should now load it
        got = Base.get("loader")
        self.assertIs(got, loader())

    def test_filter_preserves_registration_order(self):
        """Filtering doesn't re-order; it preserves the registry's insertion order."""

        class Base(Registrant):
            pass

        class A(Base):
            pass

        class B(Base):
            pass

        class C(Base):
            pass

        # registry order is A, B, C
        fg = Base.filter(lambda c: c.__name__ in ("C", "A"))
        # even though we asked for C,A, iteration follows [A,C] because of insertion order
        self.assertEqual([c.__name__ for c in fg], ["A", "C"])

    def test_repr_of_registry_filter(self):
        """repr() on a registry filter should show the predicate count."""

        class Base(Registrant):
            pass

        class A(Base):
            pass

        fg = Base.filter(lambda c: True)
        r = repr(fg)
        self.assertIn("FilterableGenerator", r)
        self.assertIn("preds=1", r)


if __name__ == "__main__":
    unittest.main()

from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.backends.mba.ida import IDAPatternAdapter, _LeafWrapper
from d810.hexrays.expr.ast import AstLeaf
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.mba.dsl import DynamicConst, Var


def _candidate(size: int, *, name: str = "x") -> AstLeaf:
    candidate = AstLeaf(name)
    candidate.mop = MopSnapshot(t=ida_hexrays.mop_r, size=size, reg=1)
    candidate.ea = 0x401000
    return candidate


def _binding_candidate(size: int, **bindings: int):
    leafs = {}
    for register, (name, value) in enumerate(bindings.items(), start=1):
        leaf = AstLeaf(name)
        if name.startswith("c"):
            leaf.mop = MopSnapshot(t=ida_hexrays.mop_n, size=size, value=value)
        else:
            leaf.mop = MopSnapshot(t=ida_hexrays.mop_r, size=size, reg=register)
        leafs[name] = leaf
    destination = ida_hexrays.mop_t()
    destination.make_reg(9, size)
    return SimpleNamespace(
        leafs_by_name=leafs,
        ea=0x401000,
        size=size,
        dest_size=size,
        dst_mop=destination,
    )


@pytest.mark.usefixtures("ida_database")
class TestDynamicConstReplacement:
    binary_name = "libobfuscated.dll"

    @staticmethod
    def _instruction_from_pattern(
        adapter, size: int, *, bnot_source_register: int = 1, **constant_values
    ):
        pattern = adapter.PATTERN.clone()
        for leaf in pattern.get_leaf_list():
            if leaf.name in constant_values:
                leaf.mop = MopSnapshot(
                    t=ida_hexrays.mop_n,
                    size=size,
                    value=constant_values[leaf.name],
                )
            elif leaf.name == "bnot_x_0":
                nested = ida_hexrays.minsn_t(0x401000)
                nested.opcode = ida_hexrays.m_bnot
                nested.l.make_reg(bnot_source_register, size)
                nested.d.make_reg(3, size)
                mop = ida_hexrays.mop_t()
                mop.create_from_insn(nested)
                leaf.mop = MopSnapshot.from_mop(mop)
            else:
                register = 1 if leaf.name == "x_0" else 2
                leaf.mop = MopSnapshot(
                    t=ida_hexrays.mop_r, size=size, reg=register
                )
        pattern.dest_size = size
        pattern.ea = 0x401000
        return pattern.create_minsn(0x401000)

    def test_root_dynamic_const_crosses_each_replacement_boundary(self) -> None:
        x = Var("x")
        dynamic = DynamicConst("computed", lambda _ctx: 7, size_from="x")
        rule = SimpleNamespace(name="BoundaryDynamic", pattern=x, replacement=dynamic)
        adapter = IDAPatternAdapter(rule)
        carrier = adapter._shadow_binding_context(_LeafWrapper(_candidate(4)))
        replacement = adapter.REPLACEMENT_PATTERN.clone()

        assert adapter._dynamic_replacement_constants() == {"computed": dynamic}
        assert not replacement.update_leafs_mop(carrier)
        assert adapter._replacement_only_literals_are_resolved(replacement, carrier)
        assert adapter._materialize_replacement_constants(replacement, carrier)
        assert replacement.mop is not None

    @pytest.mark.parametrize("size", (1, 2, 4, 8))
    def test_root_dynamic_const_emits_native_mov_at_matched_width(self, size: int) -> None:
        x = Var("x")

        class Rule:
            name = "RootDynamic"
            pattern = x
            replacement = DynamicConst(
                "computed",
                lambda ctx: (1 << ctx["_width"]) - 1,
                size_from="x",
            )

        replacement = IDAPatternAdapter(Rule()).get_replacement(_candidate(size))

        assert replacement is not None
        assert replacement.opcode == ida_hexrays.m_mov
        assert replacement.l.t == ida_hexrays.mop_n
        assert replacement.l.size == size
        assert replacement.l.nnn.value == (1 << (size * 8)) - 1

    @pytest.mark.parametrize(
        "rule_name,expected",
        (
            ("PredFFRule1", 0xFFFFFFFF),
            ("PredFFRule2", 0xFFFFFFFF),
            ("PredFFRule3", 0xFFFFFFFF),
            ("PredFFRule4", 0xFFFFFFFF),
            ("PredOdd1", 0),
            ("PredOdd2", 0),
        ),
    )
    def test_known_root_dynamic_rules_emit_real_native_constant(
        self, rule_name: str, expected: int
    ) -> None:
        from d810.mba.rules import predicates

        adapter = IDAPatternAdapter(getattr(predicates, rule_name)())
        replacement = adapter.get_replacement(_candidate(4, name="x_0"))

        assert replacement is not None
        assert replacement.opcode == ida_hexrays.m_mov
        assert replacement.l.t == ida_hexrays.mop_n
        assert replacement.l.nnn.value == expected

    @pytest.mark.parametrize(
        "rule_name,expected",
        (
            ("PredFFRule1", 0xFFFFFFFF),
            ("PredFFRule2", 0xFFFFFFFF),
            ("PredFFRule3", 0xFFFFFFFF),
            ("PredFFRule4", 0xFFFFFFFF),
            ("PredOdd1", 0),
            ("PredOdd2", 0),
        ),
    )
    def test_known_dynamic_rule_matches_and_emits_replacement(
        self, rule_name: str, expected: int
    ) -> None:
        from d810.mba.rules import predicates

        adapter = IDAPatternAdapter(getattr(predicates, rule_name)())
        instruction = self._instruction_from_pattern(adapter, 4)
        from d810.ir.expr.mop_ops import get_mop_ops, register_mop_ops

        previous_provider = get_mop_ops()
        if rule_name == "PredFFRule2":
            from d810.hexrays.expr_mop_ops import HexRaysMopOps

            register_mop_ops(HexRaysMopOps())
        try:
            replacement = adapter.check_and_replace(None, instruction)
        finally:
            register_mop_ops(previous_provider)

        assert replacement is not None
        assert replacement.opcode == ida_hexrays.m_mov
        assert replacement.l.nnn.value == expected

    def test_predff2_rejects_non_complement_binding(self) -> None:
        from d810.hexrays.expr_mop_ops import HexRaysMopOps
        from d810.ir.expr.mop_ops import get_mop_ops, register_mop_ops
        from d810.mba.rules.predicates import PredFFRule2

        adapter = IDAPatternAdapter(PredFFRule2())
        instruction = self._instruction_from_pattern(
            adapter, 4, bnot_source_register=7
        )
        previous_provider = get_mop_ops()
        register_mop_ops(HexRaysMopOps())
        try:
            assert adapter.check_and_replace(None, instruction) is None
        finally:
            register_mop_ops(previous_provider)

    def test_cst8_real_match_enforces_progress_and_emits_computed_mask(self) -> None:
        from d810.mba.rules.cst import CstSimplificationRule8

        adapter = IDAPatternAdapter(CstSimplificationRule8())
        progressing = self._instruction_from_pattern(
            adapter, 4, c_1=0xFFFFFFFF, c_2=0x0F
        )
        unchanged = self._instruction_from_pattern(
            adapter, 4, c_1=0xFFFFFFF0, c_2=0x0F
        )

        replacement = adapter.check_and_replace(None, progressing)

        assert replacement is not None
        assert replacement.opcode == ida_hexrays.m_or
        assert replacement.l.t == ida_hexrays.mop_d
        assert replacement.l.d.r.nnn.value == 0xFFFFFFF0
        assert adapter.check_and_replace(None, unchanged) is None

    @pytest.mark.parametrize("size", (1, 2, 4, 8))
    def test_nested_dynamic_const_emits_native_operand(self, size: int) -> None:
        x = Var("x")

        class Rule:
            name = "NestedDynamic"
            pattern = x
            replacement = x ^ DynamicConst("computed", lambda ctx: ctx["size"] + 2)

        replacement = IDAPatternAdapter(Rule()).get_replacement(_candidate(size))

        assert replacement is not None
        assert replacement.opcode == ida_hexrays.m_xor
        assert replacement.r.t == ida_hexrays.mop_n
        assert replacement.r.size == size
        assert replacement.r.nnn.value == size + 2

    def test_callback_runs_per_attempt_without_mutating_template(self) -> None:
        x = Var("x")
        values = iter((3, 9))

        class Rule:
            name = "RepeatedDynamic"
            pattern = x
            replacement = DynamicConst("computed", lambda _ctx: next(values))

        adapter = IDAPatternAdapter(Rule())
        first = adapter.get_replacement(_candidate(4))
        second = adapter.get_replacement(_candidate(4))

        assert first.l.nnn.value == 3
        assert second.l.nnn.value == 9
        assert adapter.REPLACEMENT_PATTERN.mop is None

    @pytest.mark.parametrize("nested", (False, True))
    def test_dynamic_name_collision_never_substitutes_matched_constant(
        self, nested: bool
    ) -> None:
        x = Var("x")
        dynamic = DynamicConst("c", lambda _ctx: 0x2A)
        replacement = (x ^ dynamic) if nested else dynamic
        rule = SimpleNamespace(name="CollisionDynamic", pattern=x, replacement=replacement)
        candidate = _binding_candidate(4, x=0, c=0x11)

        emitted = IDAPatternAdapter(rule).get_replacement(candidate)

        assert emitted is not None
        operand = emitted.r if nested else emitted.l
        assert operand.t == ida_hexrays.mop_n
        assert operand.nnn.value == 0x2A

    def test_malformed_root_dynamic_metadata_cannot_fall_back_to_binding(self) -> None:
        dynamic = DynamicConst("c", lambda _ctx: 0x2A)
        dynamic.compute = None
        rule = SimpleNamespace(name="MalformedRootDynamic", pattern=Var("c"), replacement=dynamic)

        assert IDAPatternAdapter(rule).get_replacement(_candidate(4, name="c")) is None

    def test_duplicate_nested_dynamic_metadata_cannot_fall_back_to_binding(self) -> None:
        from d810.mba.dsl import SymbolicExpression

        x = Var("x")
        replacement = x ^ SymbolicExpression(
            "add",
            left=DynamicConst("c", lambda _ctx: 0x2A),
            right=DynamicConst("c", lambda _ctx: 0x2A),
        )
        rule = SimpleNamespace(name="DuplicateNestedDynamic", pattern=x, replacement=replacement)
        candidate = _binding_candidate(4, x=0, c=0x11)

        assert IDAPatternAdapter(rule).get_replacement(candidate) is None

    @pytest.mark.parametrize(
        "error",
        (KeyError("missing"), IndexError("bad index"), ZeroDivisionError("zero")),
    )
    @pytest.mark.parametrize("nested", (False, True))
    def test_ordinary_callback_exceptions_fail_closed(self, error, nested: bool) -> None:
        x = Var("x")

        def fail(_ctx):
            raise error

        dynamic = DynamicConst("computed", fail)
        replacement = (x ^ dynamic) if nested else dynamic
        rule = SimpleNamespace(name="FailingDynamic", pattern=x, replacement=replacement)

        assert IDAPatternAdapter(rule).get_replacement(_candidate(4)) is None

    def test_custom_callback_exception_fails_closed(self) -> None:
        class CallbackFailure(Exception):
            pass

        x = Var("x")

        def fail(_ctx):
            raise CallbackFailure("opaque failure")

        rule = SimpleNamespace(
            name="CustomFailure",
            pattern=x,
            replacement=DynamicConst("computed", fail),
        )
        assert IDAPatternAdapter(rule).get_replacement(_candidate(4)) is None

    def test_dynamic_metadata_is_reused_across_attempts(self) -> None:
        x = Var("x")

        class Rule:
            name = "CachedDynamicMetadata"
            pattern = x
            accesses = 0

            @property
            def replacement(self):
                self.accesses += 1
                return x ^ DynamicConst("computed", lambda _ctx: 3)

        rule = Rule()
        adapter = IDAPatternAdapter(rule)
        assert adapter.get_replacement(_candidate(4)) is not None
        accesses_after_first = rule.accesses
        assert adapter.get_replacement(_candidate(4)) is not None
        assert rule.accesses == accesses_after_first

    @pytest.mark.parametrize(
        "dynamic,candidate",
        [
            (DynamicConst("computed", lambda _ctx: 1, size_from="missing"), _candidate(4)),
            (DynamicConst("computed", lambda _ctx: "1"), _candidate(4)),
            (DynamicConst("computed", lambda _ctx: (_ for _ in ()).throw(RuntimeError("boom"))), _candidate(4)),
            (DynamicConst("computed", lambda _ctx: 1), SimpleNamespace(leafs_by_name={}, ea=0x401000)),
        ],
    )
    def test_missing_width_source_invalid_value_and_callback_error_fail_closed(
        self, dynamic, candidate
    ) -> None:
        x = Var("x")
        rule = SimpleNamespace(name="InvalidDynamic", pattern=x, replacement=dynamic)

        assert IDAPatternAdapter(rule).get_replacement(candidate) is None

"""Is a loaded global's value USED as an address? (lpccp-suvl)

Modelled on what IDA actually emits at MMAT_GLBOPT1 for the target function:
the MBA is one nested expression tree inside a single instruction, with only a
handful of cross-instruction hops through registers carrying SSA valnums.

    sub ((($dword_7FF85AAE4464.4{141} - #0x225A557) | #0x97506C0B) + ...), .., edx.4{152}
    xor edx.4{152}, #0xAF863FED, r9d.4{154}

So the test is structural containment inside operand trees, plus SSA-keyed
propagation between instructions -- not a value-set query (those intermediates
never occupy a location) and not a register-name walk (names are reused).
"""

from __future__ import annotations

import pytest

from d810.backends.hexrays.evidence.dereference_use import (
    carrier_reaches_dereference,
)

GLOBAL = ("global", 0x7FF85AAE4464)


class FakeInsn:
    """address_carriers=None means the instruction is not a dereference."""

    def __init__(self, name, sources=(), defines=None, address_carriers=None):
        self.name = name
        self.sources = frozenset(sources)
        self.defines = defines
        self.address_carriers = (
            None if address_carriers is None else frozenset(address_carriers)
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{self.name}>"


class FakeGraph:
    def __init__(self, insns):
        self._insns = list(insns)
        self.raise_on_walk = False

    def instructions(self):
        if self.raise_on_walk:
            raise RuntimeError("microcode unavailable")
        return tuple(self._insns)

    def address_carriers(self, insn):
        return insn.address_carriers

    def source_carriers(self, insn):
        return insn.sources

    def defined_carrier(self, insn):
        return insn.defines


# --------------------------------------------------------------------------- #
# the real case: arithmetic into a call argument                              #
# --------------------------------------------------------------------------- #


def test_arithmetic_chain_into_a_call_argument_is_a_data_use():
    """The measured GLBOPT1 shape of sub_7FF85A5CB920's MapViewOfFile call."""
    sub = FakeInsn("sub", sources={GLOBAL}, defines=("reg", 0, 4, 152))
    xor = FakeInsn("xor", sources={("reg", 0, 4, 152)}, defines=("reg", 9, 4, 154))
    add = FakeInsn(
        "add", sources={("reg", 9, 4, 154), GLOBAL}, defines=("reg", 10, 4, 177)
    )
    call = FakeInsn("call", sources={("reg", 10, 4, 177), ("reg", 0, 4, 152)})
    graph = FakeGraph([sub, xor, add, call])

    assert carrier_reaches_dereference(graph, {GLOBAL}) is False


def test_value_never_used_at_all_is_a_data_use():
    graph = FakeGraph([FakeInsn("unrelated", sources={("reg", 5, 4, 1)})])

    assert carrier_reaches_dereference(graph, {GLOBAL}) is False


# --------------------------------------------------------------------------- #
# the pointer case, including through arithmetic (the RVA shape)              #
# --------------------------------------------------------------------------- #


def test_direct_use_as_a_load_address_is_a_dereference():
    ldx = FakeInsn("ldx", sources={GLOBAL}, address_carriers={GLOBAL})
    graph = FakeGraph([ldx])

    assert carrier_reaches_dereference(graph, {GLOBAL}) is True


def test_dereference_through_arithmetic_is_still_a_dereference():
    """imagebase + rva: containment is structural, so the wrapper does not hide it."""
    lea = FakeInsn("lea_as_add", sources={GLOBAL}, defines=("reg", 1, 8, 20))
    ldx = FakeInsn(
        "ldx",
        sources={("reg", 1, 8, 20)},
        address_carriers={("reg", 1, 8, 20)},
    )
    graph = FakeGraph([lea, ldx])

    assert carrier_reaches_dereference(graph, {GLOBAL}) is True


def test_store_address_counts_but_stored_data_does_not():
    """stx: the ADDRESS operand is a pointer use; the stored value is not."""
    as_data = FakeInsn("stx_data", sources={GLOBAL}, address_carriers={("reg", 3, 8, 7)})
    graph = FakeGraph([as_data])
    assert carrier_reaches_dereference(graph, {GLOBAL}) is False

    as_addr = FakeInsn("stx_addr", sources={GLOBAL}, address_carriers={GLOBAL})
    assert carrier_reaches_dereference(FakeGraph([as_addr]), {GLOBAL}) is True


def test_dereference_found_after_several_hops():
    a = FakeInsn("a", sources={GLOBAL}, defines=("reg", 1, 4, 10))
    b = FakeInsn("b", sources={("reg", 1, 4, 10)}, defines=("reg", 2, 4, 11))
    c = FakeInsn("c", sources={("reg", 2, 4, 11)}, defines=("reg", 3, 8, 12))
    ldx = FakeInsn(
        "ldx", sources={("reg", 3, 8, 12)}, address_carriers={("reg", 3, 8, 12)}
    )
    graph = FakeGraph([a, b, c, ldx])

    assert carrier_reaches_dereference(graph, {GLOBAL}) is True


# --------------------------------------------------------------------------- #
# SSA versioning is what stops the register-name leak                         #
# --------------------------------------------------------------------------- #


def test_same_register_different_valnum_does_not_carry_the_value():
    """The defect this replaces: (reg, size) keying matched unrelated reads."""
    define = FakeInsn("def", sources={GLOBAL}, defines=("reg", 0, 4, 152))
    # same register 0, size 4 -- but a DIFFERENT definition
    unrelated = FakeInsn(
        "unrelated_ldx",
        sources={("reg", 0, 4, 999)},
        address_carriers={("reg", 0, 4, 999)},
    )
    graph = FakeGraph([define, unrelated])

    assert carrier_reaches_dereference(graph, {GLOBAL}) is False


def test_matching_valnum_does_carry_the_value():
    define = FakeInsn("def", sources={GLOBAL}, defines=("reg", 0, 4, 152))
    same = FakeInsn(
        "ldx",
        sources={("reg", 0, 4, 152)},
        address_carriers={("reg", 0, 4, 152)},
    )
    graph = FakeGraph([define, same])

    assert carrier_reaches_dereference(graph, {GLOBAL}) is True


# --------------------------------------------------------------------------- #
# unknown must stay distinguishable from "no"                                 #
# --------------------------------------------------------------------------- #


def test_unwalkable_microcode_yields_unknown():
    graph = FakeGraph([])
    graph.raise_on_walk = True

    assert carrier_reaches_dereference(graph, {GLOBAL}) is None


def test_non_convergence_yields_unknown_not_false():
    chain = [FakeInsn("i0", sources={GLOBAL}, defines=("reg", 0, 4, 0))]
    for i in range(1, 30):
        chain.append(
            FakeInsn(
                f"i{i}",
                sources={("reg", i - 1, 4, i - 1)},
                defines=("reg", i, 4, i),
            )
        )
    graph = FakeGraph(chain)

    assert carrier_reaches_dereference(graph, {GLOBAL}, max_rounds=3) is None
    assert carrier_reaches_dereference(graph, {GLOBAL}, max_rounds=64) is False


def test_no_initial_carrier_is_unknown_rather_than_a_verdict():
    graph = FakeGraph([FakeInsn("x", sources={GLOBAL})])

    assert carrier_reaches_dereference(graph, set()) is None


# --------------------------------------------------------------------------- #
# traversal robustness                                                        #
# --------------------------------------------------------------------------- #


def test_cycle_converges_instead_of_hanging():
    a = FakeInsn("a", sources={GLOBAL, ("reg", 1, 4, 2)}, defines=("reg", 0, 4, 1))
    b = FakeInsn("b", sources={("reg", 0, 4, 1)}, defines=("reg", 1, 4, 2))
    graph = FakeGraph([a, b])

    assert carrier_reaches_dereference(graph, {GLOBAL}) is False


def test_dereference_wins_over_a_cycle():
    a = FakeInsn("a", sources={GLOBAL, ("reg", 1, 4, 2)}, defines=("reg", 0, 4, 1))
    b = FakeInsn("b", sources={("reg", 0, 4, 1)}, defines=("reg", 1, 4, 2))
    ldx = FakeInsn(
        "ldx", sources={("reg", 1, 4, 2)}, address_carriers={("reg", 1, 4, 2)}
    )
    graph = FakeGraph([a, b, ldx])

    assert carrier_reaches_dereference(graph, {GLOBAL}) is True


@pytest.mark.parametrize("rounds", [1, 2])
def test_under_budget_never_reports_a_false_data_use(rounds):
    a = FakeInsn("a", sources={GLOBAL}, defines=("reg", 0, 4, 1))
    b = FakeInsn("b", sources={("reg", 0, 4, 1)}, defines=("reg", 1, 4, 2))
    c = FakeInsn("c", sources={("reg", 1, 4, 2)}, defines=("reg", 2, 4, 3))
    ldx = FakeInsn(
        "ldx", sources={("reg", 2, 4, 3)}, address_carriers={("reg", 2, 4, 3)}
    )
    graph = FakeGraph([a, b, c, ldx])

    assert carrier_reaches_dereference(graph, {GLOBAL}, max_rounds=rounds) in (
        True,
        None,
    )

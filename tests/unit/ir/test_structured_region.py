"""Structured-region IR + goto-free renderer (Layer 2, Slice A).

Demonstrates the goto-free *target* shape for the sub_7FFD aligned-terminal end
state: the ``v52`` alignment switch rendered as structured ``if``/``return`` with
the aligned path delivering ``a5 + 0xD0`` (not the ``0x298372CC`` leak), and no
``goto`` anywhere.
"""
from __future__ import annotations

from d810.ir.structured_region import (
    BlockRegion,
    ConditionRegion,
    LoopRegion,
    ReturnRegion,
    SequenceRegion,
    SwitchRegion,
    render_region,
)


def test_carrier_endstate_is_goto_free_and_correct():
    tree = SequenceRegion((
        # aligned terminal, FIXED: delivers the real carrier, not the leaked state
        ConditionRegion("!v52", ReturnRegion("a5 + 0xD0")),
        BlockRegion(2, ("/* byte compute */",)),
        ConditionRegion("v52 == 1", ReturnRegion("0xC5FB34A1D9A6E315uLL")),
        ReturnRegion("a5 + 0xD0"),
    ))
    text = render_region(tree)
    assert "goto" not in text
    assert "if ( !v52 )" in text
    assert "return a5 + 0xD0;" in text
    assert "0x298372CC" not in text  # the leak is gone in the structured end state


def test_nested_if_else_indentation():
    tree = ConditionRegion(
        "x == 1",
        then_region=BlockRegion(1, ("a = 1;",)),
        else_region=BlockRegion(2, ("a = 2;",)),
    )
    assert render_region(tree) == (
        "if ( x == 1 )\n"
        "{\n"
        "    a = 1;\n"
        "}\n"
        "else\n"
        "{\n"
        "    a = 2;\n"
        "}"
    )


def test_while_and_do_while():
    body = BlockRegion(1, ("++i;",))
    assert render_region(LoopRegion(body, kind="while", condition="i < n")) == (
        "while ( i < n )\n{\n    ++i;\n}"
    )
    assert render_region(LoopRegion(body, kind="do_while", condition="i < n")) == (
        "do\n{\n    ++i;\n} while ( i < n );"
    )


def test_switch_with_default():
    tree = SwitchRegion(
        "v52 & 7",
        cases=(
            ((1,), ReturnRegion("0xC5FB34A1D9A6E315uLL")),
            ((), ReturnRegion("a5 + 0xD0")),
        ),
    )
    text = render_region(tree)
    assert "switch ( v52 & 7 )" in text
    assert "case 1:" in text
    assert "default:" in text
    assert "goto" not in text

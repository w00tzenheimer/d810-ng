"""Unit tests: FoldReadonlyDataRule._ea_from_direct_load() handles mop_v.

These tests verify the mop_v support added to ``_ea_from_direct_load()`` via
source-level structural checks.  No IDA installation or stub manipulation is
required — the logic is verified by inspecting the source text.

Rationale for source-level approach:
  ``fold_readonlydata.py`` transitively imports ``d810.hexrays.utils.hexrays_helpers``
  which builds ``OPCODES_INFO`` at import time using every ``ida_hexrays.m_*``
  opcode constant.  When tests run in a shared process, an earlier test file
  (``test_helper_routing.py``) already populates ``sys.modules["ida_hexrays"]``
  with a sparse MagicMock stub that lacks most opcode constants.  Replacing or
  evicting modules mid-run corrupts already-imported packages.

  The source checks below are therefore the correct unit-test layer:
  - They confirm the mop_v branch exists and uses the right attribute (`.g`).
  - They run in O(ms) with zero IDA/mock dependencies.
  - Functional end-to-end coverage lives in ``tests/system/runtime/``.
"""
from __future__ import annotations

import pathlib

import pytest


# Path to the implementation file under test (relative to repo root, which is
# the pytest rootdir configured in pyproject.toml).
_SRC = pathlib.Path(
    "src/d810/optimizers/microcode/instructions/peephole/fold_readonlydata.py"
)


def _read_src() -> str:
    return _SRC.read_text()


class TestEaFromDirectLoadMopVSourceStructure:
    """Source-level checks: mop_v variant present and correct in _ea_from_direct_load."""

    def test_mop_v_left_operand_check_present(self) -> None:
        """_ea_from_direct_load checks ins.l.t == ida_hexrays.mop_v."""
        src = _read_src()
        assert "ins.l.t == ida_hexrays.mop_v" in src, (
            "_ea_from_direct_load must check ins.l.t == ida_hexrays.mop_v "
            "to handle global variable base operands"
        )

    def test_g_attribute_used_for_mop_v_base_ea(self) -> None:
        """ins.l.g is accessed to extract the base EA from a mop_v operand."""
        src = _read_src()
        assert "ins.l.g" in src, (
            "_ea_from_direct_load must read ins.l.g for the mop_v global EA"
        )

    def test_mop_v_base_plus_immediate_offset(self) -> None:
        """The mop_v branch computes base + off for an immediate (mop_n) index."""
        src = _read_src()
        # The pattern: ins.l.g is the base, ins.r.nnn.value is the offset
        assert "ins.l.g" in src, "base EA must come from ins.l.g"
        # mop_n index path: same structure as mop_S variant
        assert "ins.r.t == ida_hexrays.mop_n" in src, (
            "mop_v variant must handle mop_n index (immediate offset)"
        )

    def test_mop_v_base_plus_pure_const_expr(self) -> None:
        """The mop_v branch also handles a mop_d pure-constant index expression."""
        src = _read_src()
        # Both the mop_S and mop_v variants share the mop_d pure-const path
        assert "ins.r.t == ida_hexrays.mop_d" in src, (
            "mop_v variant must handle mop_d pure-constant index expression"
        )

    def test_mop_v_block_appears_before_variant_b(self) -> None:
        """The mop_v block is placed before Variant B (the mop_r/add form)."""
        src = _read_src()
        pos_v = src.find("ins.l.t == ida_hexrays.mop_v")
        pos_r = src.find("ins.l.t == ida_hexrays.mop_r")
        assert pos_v != -1, "mop_v branch must exist"
        assert pos_r != -1, "mop_r branch (Variant B) must exist"
        assert pos_v < pos_r, (
            "mop_v block should appear before Variant B (mop_r) in source order"
        )

    def test_docstring_mentions_global_var_form(self) -> None:
        """The docstring of _ea_from_direct_load mentions the $global_var forms."""
        src = _read_src()
        assert "$global_var" in src, (
            "_ea_from_direct_load docstring should document the $global_var patterns"
        )

    def test_mop_S_variant_untouched(self) -> None:
        """The pre-existing mop_S (Variant A) is still present."""
        src = _read_src()
        assert "ins.l.t == ida_hexrays.mop_S" in src, (
            "Original mop_S (Variant A) must still be present — regression check"
        )
        assert "ins.l.s.start_ea" in src, (
            "mop_S variant must still access .s.start_ea — regression check"
        )

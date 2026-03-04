"""Tests for the FCP lattice types and meet strategy.

TDD: these tests are written before the implementation.
"""
from __future__ import annotations

import pytest

from d810.cfg.lattice import (
    BOTTOM,
    TOP,
    Const,
    LatticeEnv,
    LatticeValue,
    LatticeMeet,
    env_meet,
    lattice_meet,
    _Sentinel,
)


# ---------------------------------------------------------------------------
# TestLatticeValue
# ---------------------------------------------------------------------------

class TestLatticeValue:
    def test_bottom_is_singleton(self):
        assert BOTTOM is _Sentinel.BOTTOM

    def test_top_is_singleton(self):
        assert TOP is _Sentinel.TOP

    def test_bottom_not_equal_top(self):
        assert BOTTOM != TOP

    def test_const_equality(self):
        assert Const(0x10, 4) == Const(0x10, 4)

    def test_const_inequality_value(self):
        assert Const(0x10, 4) != Const(0x20, 4)

    def test_const_inequality_size(self):
        assert Const(0x10, 4) != Const(0x10, 8)

    def test_const_not_equal_bottom(self):
        assert Const(0, 4) != BOTTOM

    def test_const_not_equal_top(self):
        assert Const(0, 4) != TOP

    def test_bottom_hashable(self):
        s = {BOTTOM, BOTTOM}
        assert len(s) == 1

    def test_top_hashable(self):
        s = {TOP, TOP}
        assert len(s) == 1

    def test_const_hashable(self):
        s = {Const(1, 4), Const(1, 4), Const(2, 4)}
        assert len(s) == 2

    def test_const_repr(self):
        assert repr(Const(255, 1)) == "Const(0xff, 1)"

    def test_bottom_repr(self):
        assert repr(BOTTOM) == "BOTTOM"

    def test_top_repr(self):
        assert repr(TOP) == "TOP"


# ---------------------------------------------------------------------------
# TestLatticeMeet
# ---------------------------------------------------------------------------

class TestLatticeMeet:
    # BOTTOM × anything
    def test_bottom_meet_bottom(self):
        assert lattice_meet(BOTTOM, BOTTOM) is BOTTOM

    def test_bottom_meet_const(self):
        c = Const(0x1, 4)
        assert lattice_meet(BOTTOM, c) == c

    def test_bottom_meet_top(self):
        assert lattice_meet(BOTTOM, TOP) is TOP

    # symmetric: anything × BOTTOM
    def test_const_meet_bottom(self):
        c = Const(0x2, 4)
        assert lattice_meet(c, BOTTOM) == c

    def test_top_meet_bottom(self):
        assert lattice_meet(TOP, BOTTOM) is TOP

    # TOP × anything
    def test_top_meet_top(self):
        assert lattice_meet(TOP, TOP) is TOP

    def test_top_meet_const(self):
        assert lattice_meet(TOP, Const(0x3, 4)) is TOP

    def test_const_meet_top(self):
        assert lattice_meet(Const(0x3, 4), TOP) is TOP

    # Const × Const
    def test_const_meet_const_same(self):
        c = Const(0xdeadbeef, 4)
        assert lattice_meet(c, c) == c

    def test_const_meet_const_same_value_same_size(self):
        assert lattice_meet(Const(0x42, 2), Const(0x42, 2)) == Const(0x42, 2)

    def test_const_meet_const_different_value(self):
        assert lattice_meet(Const(0x1, 4), Const(0x2, 4)) is TOP

    def test_const_meet_const_different_size(self):
        assert lattice_meet(Const(0x1, 4), Const(0x1, 8)) is TOP

    def test_const_meet_const_different_value_and_size(self):
        assert lattice_meet(Const(0x1, 4), Const(0x2, 8)) is TOP


# ---------------------------------------------------------------------------
# TestEnvMeet
# ---------------------------------------------------------------------------

class TestEnvMeet:
    def test_both_empty(self):
        assert env_meet({}, {}) == {}

    def test_left_empty_right_has_entry(self):
        # missing key treated as BOTTOM → result is the value from right
        b: LatticeEnv = {"x": Const(1, 4)}
        result = env_meet({}, b)
        assert result == {"x": Const(1, 4)}

    def test_right_empty_left_has_entry(self):
        a: LatticeEnv = {"x": Const(1, 4)}
        result = env_meet(a, {})
        assert result == {"x": Const(1, 4)}

    def test_matching_keys_agree(self):
        a: LatticeEnv = {"x": Const(5, 4)}
        b: LatticeEnv = {"x": Const(5, 4)}
        assert env_meet(a, b) == {"x": Const(5, 4)}

    def test_matching_keys_conflict(self):
        a: LatticeEnv = {"x": Const(1, 4)}
        b: LatticeEnv = {"x": Const(2, 4)}
        result = env_meet(a, b)
        assert result == {"x": TOP}

    def test_disjoint_keys(self):
        a: LatticeEnv = {"x": Const(1, 4)}
        b: LatticeEnv = {"y": Const(2, 4)}
        result = env_meet(a, b)
        # each missing key is BOTTOM → meet(BOTTOM, Const) = Const
        assert result == {"x": Const(1, 4), "y": Const(2, 4)}

    def test_mixed_values(self):
        a: LatticeEnv = {"x": Const(1, 4), "y": TOP, "z": BOTTOM}
        b: LatticeEnv = {"x": Const(1, 4), "y": Const(9, 4), "z": Const(3, 4)}
        result = env_meet(a, b)
        assert result["x"] == Const(1, 4)
        assert result["y"] is TOP
        assert result["z"] == Const(3, 4)

    def test_explicit_top_in_one_kills(self):
        a: LatticeEnv = {"x": TOP}
        b: LatticeEnv = {"x": Const(7, 4)}
        assert env_meet(a, b) == {"x": TOP}

    def test_result_is_new_dict(self):
        a: LatticeEnv = {"x": Const(1, 4)}
        b: LatticeEnv = {"x": Const(1, 4)}
        result = env_meet(a, b)
        assert result is not a
        assert result is not b


# ---------------------------------------------------------------------------
# TestLatticeMeetStrategy
# ---------------------------------------------------------------------------

class TestLatticeMeetStrategy:
    def setup_method(self):
        self.strategy = LatticeMeet()

    def test_empty_pred_list(self):
        result = self.strategy.meet([])
        assert result == {}

    def test_single_pred_returns_copy(self):
        env: LatticeEnv = {"a": Const(0x10, 4), "b": TOP}
        result = self.strategy.meet([env])
        assert result == env
        assert result is not env  # must be a copy

    def test_two_preds_agreeing(self):
        env1: LatticeEnv = {"a": Const(1, 4)}
        env2: LatticeEnv = {"a": Const(1, 4)}
        result = self.strategy.meet([env1, env2])
        assert result == {"a": Const(1, 4)}

    def test_two_preds_conflicting(self):
        env1: LatticeEnv = {"a": Const(1, 4)}
        env2: LatticeEnv = {"a": Const(2, 4)}
        result = self.strategy.meet([env1, env2])
        assert result == {"a": TOP}

    def test_unreachable_predecessor_preserves_constants(self):
        """An unreachable predecessor has an all-BOTTOM (empty) OUT env.

        meet(BOTTOM, Const(x)) == Const(x), so the constant must survive.
        """
        live_env: LatticeEnv = {"state": Const(0xCAFE, 4)}
        dead_env: LatticeEnv = {}  # all-BOTTOM
        result = self.strategy.meet([live_env, dead_env])
        assert result == {"state": Const(0xCAFE, 4)}

    def test_cff_pattern_one_case_two_dead_blocks(self):
        """CFF: one real case block defines a constant; two dead blocks are BOTTOM.

        The result must preserve the constant (not kill it).
        """
        case_env: LatticeEnv = {"state": Const(0x1, 4)}
        dead1: LatticeEnv = {}
        dead2: LatticeEnv = {}
        result = self.strategy.meet([case_env, dead1, dead2])
        assert result == {"state": Const(0x1, 4)}

    def test_three_preds_all_agree(self):
        envs = [{"x": Const(99, 4)} for _ in range(3)]
        result = self.strategy.meet(envs)
        assert result == {"x": Const(99, 4)}

    def test_three_preds_one_conflicts(self):
        envs: list[LatticeEnv] = [
            {"x": Const(1, 4)},
            {"x": Const(1, 4)},
            {"x": Const(2, 4)},
        ]
        result = self.strategy.meet(envs)
        assert result == {"x": TOP}


# ---------------------------------------------------------------------------
# TestEnvMeetDefaultMissing
# ---------------------------------------------------------------------------

class TestEnvMeetDefaultMissing:
    def test_env_meet_default_missing_top_kills_absent(self):
        """With default_missing=TOP, a key present in only one env is killed."""
        a: LatticeEnv = {"x": Const(1, 4)}
        b: LatticeEnv = {}
        result = env_meet(a, b, default_missing=TOP)
        assert result == {"x": TOP}

    def test_env_meet_default_missing_bottom_preserves_absent(self):
        """With default_missing=BOTTOM (default), a key present in only one env survives."""
        a: LatticeEnv = {"x": Const(1, 4)}
        b: LatticeEnv = {}
        result = env_meet(a, b, default_missing=BOTTOM)
        assert result == {"x": Const(1, 4)}

    def test_env_meet_default_missing_top_both_keys_present_agree(self):
        """With default_missing=TOP, keys present in both envs that agree still yield the constant."""
        a: LatticeEnv = {"x": Const(5, 4)}
        b: LatticeEnv = {"x": Const(5, 4)}
        result = env_meet(a, b, default_missing=TOP)
        assert result == {"x": Const(5, 4)}

    def test_env_meet_default_missing_top_both_keys_present_conflict(self):
        """With default_missing=TOP, conflicting keys still produce TOP."""
        a: LatticeEnv = {"x": Const(1, 4)}
        b: LatticeEnv = {"x": Const(2, 4)}
        result = env_meet(a, b, default_missing=TOP)
        assert result == {"x": TOP}


# ---------------------------------------------------------------------------
# TestLatticeMeetConservativeAndAggressive
# ---------------------------------------------------------------------------

class TestLatticeMeetConservativeAndAggressive:
    def test_lattice_meet_conservative_kills_absent(self):
        """LatticeMeet(default_missing=TOP) kills constants from unreachable predecessors."""
        conservative = LatticeMeet(default_missing=TOP)
        live_env: LatticeEnv = {"state": Const(0xCAFE, 4)}
        dead_env: LatticeEnv = {}  # unreachable block — empty OUT
        result = conservative.meet([live_env, dead_env])
        assert result == {"state": TOP}

    def test_lattice_meet_aggressive_preserves_absent(self):
        """LatticeMeet(default_missing=BOTTOM) preserves constants from unreachable predecessors."""
        aggressive = LatticeMeet(default_missing=BOTTOM)
        live_env: LatticeEnv = {"state": Const(0xCAFE, 4)}
        dead_env: LatticeEnv = {}  # unreachable block — empty OUT
        result = aggressive.meet([live_env, dead_env])
        assert result == {"state": Const(0xCAFE, 4)}

    def test_lattice_meet_conservative_default_is_top(self):
        """LatticeMeet(default_missing=TOP) stores TOP as the default."""
        conservative = LatticeMeet(default_missing=TOP)
        assert conservative._default_missing is TOP

    def test_lattice_meet_aggressive_default_is_bottom(self):
        """LatticeMeet(default_missing=BOTTOM) stores BOTTOM as the default."""
        aggressive = LatticeMeet(default_missing=BOTTOM)
        assert aggressive._default_missing is BOTTOM

    def test_lattice_meet_default_ctor_is_bottom(self):
        """LatticeMeet() with no args defaults to BOTTOM (aggressive)."""
        strategy = LatticeMeet()
        assert strategy._default_missing is BOTTOM

    def test_lattice_meet_conservative_cff_pattern(self):
        """Conservative meet: one live predecessor + two dead empties kills the constant."""
        conservative = LatticeMeet(default_missing=TOP)
        case_env: LatticeEnv = {"state": Const(0x1, 4)}
        dead1: LatticeEnv = {}
        dead2: LatticeEnv = {}
        result = conservative.meet([case_env, dead1, dead2])
        assert result == {"state": TOP}

    def test_lattice_meet_aggressive_cff_pattern(self):
        """Aggressive meet: one live predecessor + two dead empties preserves the constant."""
        aggressive = LatticeMeet(default_missing=BOTTOM)
        case_env: LatticeEnv = {"state": Const(0x1, 4)}
        dead1: LatticeEnv = {}
        dead2: LatticeEnv = {}
        result = aggressive.meet([case_env, dead1, dead2])
        assert result == {"state": Const(0x1, 4)}

"""The pass-id vocabulary is an enum, and extensions may still use strings.

``PassId`` exists because a pass id is a *name in a shared vocabulary*: d810
declares it, config files select on it, and out-of-tree extensions bind rules to
it. As bare string literals that vocabulary drifted -- ``"mba-simplify"`` was
written out twice in two modules, so a typo in either would have produced a pass
that registers, accepts config and never runs.

The enum has to satisfy two constraints at once, which is what these tests pin:

* d810's own code gets a typo-proof symbol.
* an extension's manifest stays a plain dict of plain strings, because
  requiring ``from d810.core.pass_ids import PassId`` would make d810 a hard
  *import-time* dependency of every extension -- the coupling the CoBRA
  extraction removed.

``enum.StrEnum`` is what reconciles them: members hash and compare as their
values, so ``{"mba-solve": ...}[PassId.MBA_SOLVE]`` resolves. That is a language
guarantee, but it is the entire load-bearing assumption here, so it is tested
rather than trusted.
"""

from __future__ import annotations

import enum

from d810.core.pass_ids import PassId


class TestPassIdIsAStringEnum:
    def test_members_are_strings(self):
        """Every consumer treats a pass id as a str: config JSON, dict keys, logs."""
        for member in PassId:
            assert isinstance(member, str)

    def test_member_equals_its_wire_value(self):
        assert PassId.MBA_SOLVE == "mba-solve"

    def test_member_hashes_as_its_wire_value(self):
        """Load-bearing: extension manifests key ``implements`` by plain string.

        If the hash differed, ``manifest.implements.get(PassId.MBA_SOLVE)``
        would silently return None against ``{"mba-solve": "CobraSolveRule"}``
        and the pass would go quietly missing.
        """
        assert hash(PassId.MBA_SOLVE) == hash("mba-solve")
        assert {"mba-solve": "CobraSolveRule"}[PassId.MBA_SOLVE] == "CobraSolveRule"

    def test_formats_without_the_enum_prefix(self):
        """Pass ids reach users through logs and error text; ``PassId.MBA_SOLVE``
        would be noise there, and a plain ``str.Enum`` would render exactly that."""
        assert f"{PassId.MBA_SOLVE}" == "mba-solve"
        assert str(PassId.MBA_SOLVE) == "mba-solve"

    def test_repr_matches_a_plain_string(self):
        """Pass ids are interpolated with ``!r`` in existing error messages.

        ``StrEnum`` inherits ``Enum.__repr__``, not ``str.__repr__``, so
        aliasing a constant to a member silently rewrote

            expected 'constant-simplification', got 'mba-solve'

        into

            expected <PassId.CONSTANT_SIMPLIFICATION: '...'>, got 'mba-solve'

        -- noisier, and inconsistent with the right-hand side, which is still a
        raw string from config. No test asserted on those messages, so nothing
        caught it. Matching ``str``'s repr keeps a member substitutable for its
        value in *every* formatting context, which is the premise of using
        ``StrEnum`` at all.
        """
        for member in PassId:
            assert repr(member) == repr(member.value)

    def test_repr_survives_container_formatting(self):
        """``f"{list(...)}"`` formats elements with repr, so a container of
        members would leak the enum spelling into user-facing text."""
        assert f"{[PassId.MBA_SOLVE]}" == "['mba-solve']"

    def test_is_still_an_enum(self):
        """The repr override must not cost the symbolic half."""
        assert PassId.MBA_SOLVE.name == "MBA_SOLVE"
        assert PassId.MBA_SOLVE.value == "mba-solve"

    def test_lookup_by_wire_value(self):
        """Config files name passes by string; they must round-trip to a member."""
        assert PassId("mba-solve") is PassId.MBA_SOLVE

    def test_values_are_unique(self):
        values = [member.value for member in PassId]
        assert len(values) == len(set(values))

    def test_is_a_strenum(self):
        assert issubclass(PassId, enum.StrEnum)


class TestPassIdCoversTheShippedPasses:
    """The enum is the vocabulary, so it must actually name every pass.

    A pass id that stayed a bare literal would keep the drift this replaces.
    """

    def test_covers_every_pass_module_constant(self):
        from d810.passes.cleanup_family_adapter import (
            SIMPLE_FLATTENING_CLEANUP_PASS_ID,
        )
        from d810.passes.constant_simplification import CONSTANT_SIMPLIFICATION_PASS_ID
        from d810.passes.mba_simplify import MBA_SIMPLIFY_PASS_ID
        from d810.passes.mba_solve import MBA_SOLVE_PASS_ID

        assert MBA_SIMPLIFY_PASS_ID is PassId.MBA_SIMPLIFY
        assert MBA_SOLVE_PASS_ID is PassId.MBA_SOLVE
        assert CONSTANT_SIMPLIFICATION_PASS_ID is PassId.CONSTANT_SIMPLIFICATION
        assert (
            SIMPLE_FLATTENING_CLEANUP_PASS_ID is PassId.SIMPLE_FLATTENING_CLEANUP
        )

    def test_mba_simplify_id_is_not_duplicated(self):
        """``mba_simplify`` and ``mba_transform_options`` each defined this
        literal independently. Two sources of truth for one identity is the
        drift the enum exists to prevent, so they must now be the same object."""
        from d810.passes.mba_simplify import MBA_SIMPLIFY_PASS_ID as from_pass
        from d810.passes.mba_transform_options import (
            MBA_SIMPLIFY_PASS_ID as from_options,
        )

        assert from_pass is from_options is PassId.MBA_SIMPLIFY

    def test_covers_the_state_machine_native_spine(self):
        """These five are a pass sequence, not a family of one, and they are
        compared as a whole tuple -- so they belong to the same vocabulary."""
        from d810.passes.state_machine_options import STATE_MACHINE_NATIVE_PASS_IDS

        assert STATE_MACHINE_NATIVE_PASS_IDS == (
            PassId.RECOVER_DISPATCHER,
            PassId.RECOVER_STATE_TRANSITIONS,
            PassId.PLAN_SEMANTIC_REGIONS,
            PassId.LOWER_STATE_MACHINE,
            PassId.CLEANUP_RESIDUAL_DISPATCHER,
        )

    def test_state_machine_spine_still_compares_against_raw_strings(self):
        """``_state_machine_rule_config`` compares a tuple of raw config
        strings against this tuple. Members must compare elementwise equal or
        the complete-spine check starts rejecting valid configs."""
        from d810.passes.state_machine_options import STATE_MACHINE_NATIVE_PASS_IDS

        from_config = (
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
        )
        assert from_config == STATE_MACHINE_NATIVE_PASS_IDS
        assert not (from_config != STATE_MACHINE_NATIVE_PASS_IDS)
        assert "recover_dispatcher" in STATE_MACHINE_NATIVE_PASS_IDS

    def test_state_machine_spine_error_text_is_readable(self):
        """The incomplete-spine error interpolates ``list(...)``, which formats
        with repr -- the exact path that leaked ``<PassId.X: 'x'>``."""
        from d810.passes.state_machine_options import STATE_MACHINE_NATIVE_PASS_IDS

        rendered = f"{list(STATE_MACHINE_NATIVE_PASS_IDS)}"
        assert rendered.startswith("['recover_dispatcher'")
        assert "PassId" not in rendered

    def test_wire_values_are_unchanged(self):
        """These strings appear in shipped config JSON and in extension
        manifests. Changing one silently orphans every config that names it."""
        assert PassId.MBA_SIMPLIFY == "mba-simplify"
        assert PassId.MBA_SOLVE == "mba-solve"
        assert PassId.CONSTANT_SIMPLIFICATION == "constant-simplification"
        assert (
            PassId.SIMPLE_FLATTENING_CLEANUP
            == "simple-flattening-cleanup-unflattener"
        )


class TestPassIdStaysInTheCoreLayer:
    def test_importable_without_the_passes_package(self):
        """``core.plugins.implementation_for`` is typed with ``PassId``, and
        ``core`` is the bottom layer -- it may not import ``d810.passes``.
        Defining the enum in ``passes`` would invert that edge.
        """
        import subprocess
        import sys

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; from d810.core.pass_ids import PassId; "
                    "assert PassId.MBA_SOLVE == 'mba-solve'; "
                    "leaked = [m for m in sys.modules if m.startswith('d810.passes')]; "
                    "print(leaked)"
                ),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "[]", (
            f"importing PassId dragged in d810.passes: {result.stdout}"
        )

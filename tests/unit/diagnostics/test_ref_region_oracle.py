"""Tests for the REF region-shape oracle."""
from __future__ import annotations

from d810.diagnostics.ref_region_oracle import (
    D810SnapshotInputs,
    FeatureRegion,
    FeatureSource,
    d810_features,
    diff_features,
    format_diff_table,
    ref_features,
    spec_for,
)

_SUB7FFD_EA = "0x0000000180012df0"


def _ref_feats() -> tuple:
    spec = spec_for(_SUB7FFD_EA)
    assert spec is not None
    return tuple(ref_features(spec))


class TestRefFeatures:
    def test_ref_features_include_all_seven_byte_emits(self) -> None:
        feats = _ref_feats()
        names = {f.feature for f in feats}
        for k in range(7):
            assert f"byte_emit_{k}_present" in names
            assert f"byte_emit_{k}_source_form" in names
            assert f"byte_emit_{k}_destination_present" in names
            assert f"byte_emit_{k}_counter_update_present" in names

    def test_ref_marks_terminal_tail_acyclic(self) -> None:
        feats = _ref_feats()
        assert any(
            f.feature == "terminal_tail_acyclic" and f.value is True
            for f in feats
        )

    def test_ref_loops_isolated(self) -> None:
        feats = _ref_feats()
        assert any(
            f.feature == "head_2byte_stride_loop_isolated" and f.value is True
            for f in feats
        )
        assert any(
            f.feature == "chunk_block_loop_isolated" and f.value is True
            for f in feats
        )

    def test_ref_source_is_REF(self) -> None:
        for f in _ref_feats():
            assert f.source is FeatureSource.REF
            assert f.snapshot_id is None


class TestD810Features:
    def _inputs(self, **overrides) -> D810SnapshotInputs:
        defaults = dict(
            snapshot_id=18,
            nontrivial_scc_count=1,
            max_scc_size=31,
            max_in_degree=4,
            byte_emit_present={k: False for k in range(7)},
            byte_emit_block_serial={k: None for k in range(7)},
            byte_emit_fact_detected={k: False for k in range(7)},
            byte_emit_source_form={k: "absent" for k in range(7)},
            byte_emit_destination_present={k: False for k in range(7)},
            byte_emit_counter_update_present={k: False for k in range(7)},
            terminal_tail_acyclic=False,
            head_loop_isolated=False,
            chunk_loop_isolated=False,
            cleanup_blocks_present=False,
        )
        defaults.update(overrides)
        return D810SnapshotInputs(**defaults)

    def test_emits_features_for_every_byte(self) -> None:
        inputs = self._inputs(
            byte_emit_present={1: True, 6: True, **{k: False for k in (0, 2, 3, 4, 5)}},
            byte_emit_source_form={1: "indexed_base_plus_k", 6: "indexed_base_plus_k"},
            byte_emit_destination_present={1: True, 6: True},
            byte_emit_counter_update_present={1: True, 6: True},
        )
        feats = d810_features(inputs)
        names = {f.feature: f for f in feats}
        for k in range(7):
            assert f"byte_emit_{k}_present" in names
            assert f"byte_emit_{k}_source_form" in names
            assert f"byte_emit_{k}_destination_present" in names
            assert f"byte_emit_{k}_counter_update_present" in names
        assert names["byte_emit_1_present"].value is True
        assert names["byte_emit_2_present"].value is False
        assert names["byte_emit_1_source_form"].value == "indexed_base_plus_k"
        assert names["byte_emit_1_destination_present"].value is True
        assert names["byte_emit_1_counter_update_present"].value is True

    def test_snapshot_id_threaded_through(self) -> None:
        feats = d810_features(self._inputs())
        for f in feats:
            assert f.source is FeatureSource.D810_SNAPSHOT
            assert f.snapshot_id == 18


class TestDiffFeatures:
    def test_no_diff_when_features_match(self) -> None:
        inputs = D810SnapshotInputs(
            snapshot_id=5,
            nontrivial_scc_count=2,
            max_scc_size=1,
            max_in_degree=9,
            byte_emit_present={k: True for k in range(7)},
            byte_emit_block_serial={k: 100 + k for k in range(7)},
            byte_emit_fact_detected={k: True for k in range(7)},
            byte_emit_source_form={k: "indexed_base_plus_k" for k in range(7)},
            byte_emit_destination_present={k: True for k in range(7)},
            byte_emit_counter_update_present={k: True for k in range(7)},
            early_return_guard_present={k: True for k in range(6)},
            terminal_tail_acyclic=True,
            head_loop_isolated=True,
            chunk_loop_isolated=True,
            cleanup_blocks_present=True,
        )
        diffs = diff_features(_ref_feats(), d810_features(inputs))
        match_features = {
            "byte_emit_0_present", "byte_emit_6_present",
            "byte_emit_0_source_form", "byte_emit_6_source_form",
            "byte_emit_0_destination_present", "byte_emit_6_destination_present",
            "byte_emit_0_counter_update_present", "byte_emit_6_counter_update_present",
            "terminal_tail_acyclic", "head_2byte_stride_loop_isolated",
            "chunk_block_loop_isolated",
            "zero_store16_cleanup_blocks_present",
            "nontrivial_scc_count", "max_scc_size",
        }
        for d in diffs:
            assert d.feature not in match_features, (
                f"unexpected diff for {d.feature!r}: ref={d.ref_value}, "
                f"d810={d.d810_value}"
            )

    def test_diff_lists_byte_emit_differences(self) -> None:
        inputs = D810SnapshotInputs(
            snapshot_id=18,
            nontrivial_scc_count=1, max_scc_size=31, max_in_degree=4,
            byte_emit_present={k: (k in (1, 6)) for k in range(7)},
            byte_emit_block_serial={k: None for k in range(7)},
            byte_emit_fact_detected={k: (k in (1, 6)) for k in range(7)},
            byte_emit_source_form={k: "indexed_base_plus_k" for k in (1, 6)},
            byte_emit_destination_present={k: (k in (1, 6)) for k in range(7)},
            byte_emit_counter_update_present={k: (k in (1, 6)) for k in range(7)},
            terminal_tail_acyclic=False,
        )
        diffs = diff_features(_ref_feats(), d810_features(inputs))
        diff_features_set = {d.feature for d in diffs}
        # Bytes 0,2,3,4,5 should diff (REF=True, D810=False).
        for k in (0, 2, 3, 4, 5):
            assert f"byte_emit_{k}_present" in diff_features_set
        # SCC differences.
        assert "nontrivial_scc_count" in diff_features_set
        assert "max_scc_size" in diff_features_set
        assert "terminal_tail_acyclic" in diff_features_set

    def test_format_diff_table_renders_markdown(self) -> None:
        inputs = D810SnapshotInputs(
            snapshot_id=18,
            nontrivial_scc_count=1, max_scc_size=31, max_in_degree=4,
            byte_emit_present={k: False for k in range(7)},
            byte_emit_block_serial={k: None for k in range(7)},
            byte_emit_fact_detected={k: False for k in range(7)},
            byte_emit_source_form={k: "absent" for k in range(7)},
            byte_emit_destination_present={k: False for k in range(7)},
            byte_emit_counter_update_present={k: False for k in range(7)},
        )
        diffs = diff_features(_ref_feats(), d810_features(inputs))
        text = format_diff_table(diffs)
        assert "| feature | region | REF | D810 |" in text
        assert "byte_emit_0_present" in text


def test_spec_for_known_function_returns_spec():
    from d810.diagnostics.ref_region_oracle import spec_for, RefSpec
    spec = spec_for("0x0000000180012df0")
    assert spec is not None
    assert isinstance(spec, RefSpec)
    assert spec.func_name == "sub_7FFD3338C040"


def test_spec_for_unknown_function_returns_none():
    from d810.diagnostics.ref_region_oracle import spec_for
    assert spec_for("0x00000000DEADBEEF") is None


def test_spec_for_is_case_insensitive_in_hex_digits():
    from d810.diagnostics.ref_region_oracle import spec_for
    assert spec_for("0X0000000180012DF0") is not None
    assert spec_for("0x0000000180012DF0") is not None


def test_is_registered_matches_spec_for():
    from d810.diagnostics.ref_region_oracle import is_registered, spec_for
    assert is_registered("0x0000000180012df0") is (spec_for("0x0000000180012df0") is not None)
    assert is_registered("0x00000000DEADBEEF") is (spec_for("0x00000000DEADBEEF") is not None)


def test_spec_carries_snap_label_preferences():
    from d810.diagnostics.ref_region_oracle import spec_for
    spec = spec_for("0x0000000180012df0")
    assert spec is not None
    assert spec.snap17_label_preferences[0] == "post_bundle_stabilize"
    assert "GLBOPT1_post_d810" in spec.snap18_label_preferences


def test_ref_features_requires_spec_arg():
    from d810.diagnostics.ref_region_oracle import ref_features, spec_for
    spec = spec_for("0x0000000180012df0")
    assert spec is not None
    feats = list(ref_features(spec))
    assert len(feats) >= 40  # full sub_7FFD spec
    assert all(f.source.value == "REF" for f in feats)

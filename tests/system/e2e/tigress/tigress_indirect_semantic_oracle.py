"""Fixture-specific semantic oracle for Tigress indirect flattening.

This mirrors the sub7FFD region oracle pattern: hardcoded REF facts live in
test support, D810 facts are normalized from diagnostic artifacts, and the
diff is read-only. This module must not become production unflattening policy.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from d810.core.typing import Mapping


class FeatureSource(str, Enum):
    REF = "REF"
    D810 = "D810"


class FeatureRegion(str, Enum):
    DISPATCHER = "dispatcher"
    STATE_GRAPH = "state_graph"
    STATE_HANDOFF = "state_handoff"
    PSEUDOCODE = "pseudocode"
    OUTPUT = "output"


@dataclass(frozen=True, slots=True)
class SemanticFeature:
    source: FeatureSource
    region: FeatureRegion
    feature: str
    value: object
    evidence: dict = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class FeatureDiff:
    feature: str
    region: FeatureRegion
    ref_value: object
    d810_value: object

    @property
    def matches(self) -> bool:
        return self.ref_value == self.d810_value


@dataclass(frozen=True, slots=True)
class TigressIndirectCheck:
    name: str
    passed: bool
    detail: str
    blocker: bool = True


@dataclass(frozen=True, slots=True)
class TigressIndirectOracleResult:
    checks: tuple[TigressIndirectCheck, ...]
    diffs: tuple[FeatureDiff, ...]

    @property
    def passed(self) -> bool:
        return all(check.passed or not check.blocker for check in self.checks)

    @property
    def blockers(self) -> tuple[TigressIndirectCheck, ...]:
        return tuple(
            check for check in self.checks if check.blocker and not check.passed
        )


@dataclass(frozen=True, slots=True)
class RefSpec:
    func_name: str
    flattened_func_name: str
    initial_state: int
    state_count: int
    states: tuple[int, ...]
    direct_handoff_targets: Mapping[int, int]
    terminal_states: tuple[int, ...]
    conditional_states: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class D810SemanticInputs:
    func_name: str
    initial_state: int
    states: tuple[int, ...]
    table_bounds_proved: bool
    table_invariant_proved: bool
    transfers: Mapping[int, tuple[int, ...]]
    terminal_states: tuple[int, ...]
    conditional_states: tuple[int, ...]
    unresolved_states: tuple[int, ...] = ()
    pseudocode: str = ""


_TIGRESS_INDIRECT_SPEC = RefSpec(
    func_name="test_function_original",
    flattened_func_name="tigress_flatten_indirect",
    initial_state=0x22,
    state_count=37,
    states=tuple(range(1, 38)),
    direct_handoff_targets={
        0x11: 0x24,
        0x16: 0x1B,
    },
    terminal_states=(0x17,),
    conditional_states=(0x05, 0x1C, 0x1D, 0x21, 0x24),
)


def spec_for(func_name: str) -> RefSpec | None:
    if func_name in {
        _TIGRESS_INDIRECT_SPEC.func_name,
        _TIGRESS_INDIRECT_SPEC.flattened_func_name,
    }:
        return _TIGRESS_INDIRECT_SPEC
    return None


def is_registered(func_name: str) -> bool:
    return spec_for(func_name) is not None


def ref_features(spec: RefSpec) -> tuple[SemanticFeature, ...]:
    features: list[SemanticFeature] = [
        SemanticFeature(
            FeatureSource.REF,
            FeatureRegion.DISPATCHER,
            "state_count",
            spec.state_count,
        ),
        SemanticFeature(
            FeatureSource.REF,
            FeatureRegion.DISPATCHER,
            "initial_state",
            spec.initial_state,
        ),
        SemanticFeature(
            FeatureSource.REF,
            FeatureRegion.DISPATCHER,
            "all_states_present",
            True,
            {"states": list(spec.states)},
        ),
        SemanticFeature(
            FeatureSource.REF,
            FeatureRegion.STATE_GRAPH,
            "terminal_states",
            spec.terminal_states,
        ),
        SemanticFeature(
            FeatureSource.REF,
            FeatureRegion.STATE_GRAPH,
            "conditional_states",
            spec.conditional_states,
        ),
        SemanticFeature(
            FeatureSource.REF,
            FeatureRegion.OUTPUT,
            "final_output_xor_present",
            True,
            {"xor_const": "0x173063c1"},
        ),
        SemanticFeature(
            FeatureSource.REF,
            FeatureRegion.PSEUDOCODE,
            "password_zeroing_present",
            True,
        ),
        SemanticFeature(
            FeatureSource.REF,
            FeatureRegion.PSEUDOCODE,
            "password_check_present",
            True,
        ),
        SemanticFeature(
            FeatureSource.REF,
            FeatureRegion.PSEUDOCODE,
            "failure_zero_write_present",
            True,
        ),
        SemanticFeature(
            FeatureSource.REF,
            FeatureRegion.PSEUDOCODE,
            "no_raw_indirect_jump",
            True,
        ),
    ]
    for state, target in sorted(spec.direct_handoff_targets.items()):
        features.append(
            SemanticFeature(
                FeatureSource.REF,
                FeatureRegion.STATE_HANDOFF,
                f"state_0x{state:02x}_handoff_target",
                target,
            )
        )
    return tuple(features)


def inputs_from_transfer_report(
    report: Mapping[str, object],
    *,
    initial_state: int,
    repaired_handoffs: Mapping[int, int] | None = None,
    pseudocode: str = "",
    func_name: str = "tigress_flatten_indirect",
) -> D810SemanticInputs:
    repaired_handoffs = repaired_handoffs or {}
    transfers: dict[int, tuple[int, ...]] = {}
    terminal_states: list[int] = []
    conditional_states: list[int] = []
    unresolved_states: list[int] = []
    state_set: set[int] = set()

    for raw_transfer in report.get("transfers", ()):  # type: ignore[union-attr]
        transfer = raw_transfer  # type: ignore[assignment]
        state = int(transfer["state"])
        state_set.add(state)
        if state in repaired_handoffs:
            transfers[state] = (int(repaired_handoffs[state]),)
            continue
        if transfer.get("unresolved"):
            unresolved_states.append(state)
        if transfer.get("terminal"):
            terminal_states.append(state)
        next_states = tuple(int(value) for value in transfer.get("next_states", ()))
        if next_states:
            transfers[state] = tuple(sorted(next_states))
            if len(next_states) > 1:
                conditional_states.append(state)

    bounds = report.get("z3_bounds_proof", {})
    invariance = report.get("table_invariance", {})
    return D810SemanticInputs(
        func_name=func_name,
        initial_state=initial_state,
        states=tuple(sorted(state_set)),
        table_bounds_proved=bool(
            bounds.get("proved_non_negative_index")
            and bounds.get("proved_table_upper_bound")
        ),
        table_invariant_proved=bool(invariance.get("proved_invariant")),
        transfers=transfers,
        terminal_states=tuple(sorted(terminal_states)),
        conditional_states=tuple(sorted(conditional_states)),
        unresolved_states=tuple(sorted(unresolved_states)),
        pseudocode=pseudocode,
    )


def d810_features(inputs: D810SemanticInputs) -> tuple[SemanticFeature, ...]:
    states = tuple(sorted(inputs.states))
    pseudocode = inputs.pseudocode
    final_xor_present = (
        "389047233" in pseudocode
        or "0x173063C1" in pseudocode
        or (
            "0xE8CF9C3E" in pseudocode
            and "0x173063C3" in pseudocode
        )
    )
    features: list[SemanticFeature] = [
        SemanticFeature(
            FeatureSource.D810,
            FeatureRegion.DISPATCHER,
            "state_count",
            len(states),
        ),
        SemanticFeature(
            FeatureSource.D810,
            FeatureRegion.DISPATCHER,
            "initial_state",
            inputs.initial_state,
        ),
        SemanticFeature(
            FeatureSource.D810,
            FeatureRegion.DISPATCHER,
            "all_states_present",
            states == tuple(range(1, 38)),
            {"states": list(states)},
        ),
        SemanticFeature(
            FeatureSource.D810,
            FeatureRegion.DISPATCHER,
            "table_bounds_proved",
            inputs.table_bounds_proved,
        ),
        SemanticFeature(
            FeatureSource.D810,
            FeatureRegion.DISPATCHER,
            "table_invariant_proved",
            inputs.table_invariant_proved,
        ),
        SemanticFeature(
            FeatureSource.D810,
            FeatureRegion.STATE_GRAPH,
            "terminal_states",
            tuple(sorted(inputs.terminal_states)),
        ),
        SemanticFeature(
            FeatureSource.D810,
            FeatureRegion.STATE_GRAPH,
            "conditional_states",
            tuple(sorted(inputs.conditional_states)),
        ),
        SemanticFeature(
            FeatureSource.D810,
            FeatureRegion.STATE_GRAPH,
            "unresolved_states",
            tuple(sorted(inputs.unresolved_states)),
        ),
        SemanticFeature(
            FeatureSource.D810,
            FeatureRegion.OUTPUT,
            "final_output_xor_present",
            final_xor_present,
        ),
        SemanticFeature(
            FeatureSource.D810,
            FeatureRegion.PSEUDOCODE,
            "password_zeroing_present",
            "[0] = 0" in pseudocode and "0x64" in pseudocode,
        ),
        SemanticFeature(
            FeatureSource.D810,
            FeatureRegion.PSEUDOCODE,
            "password_check_present",
            '"secret"' in pseudocode and "0x64" in pseudocode,
        ),
        SemanticFeature(
            FeatureSource.D810,
            FeatureRegion.PSEUDOCODE,
            "failure_zero_write_present",
            "*a2 = 0" in pseudocode or "*output = 0" in pseudocode,
        ),
        SemanticFeature(
            FeatureSource.D810,
            FeatureRegion.PSEUDOCODE,
            "no_raw_indirect_jump",
            "JUMPOUT" not in pseudocode and "__asm { jmp" not in pseudocode,
        ),
    ]
    for state in (0x11, 0x16):
        targets = inputs.transfers.get(state, ())
        features.append(
            SemanticFeature(
                FeatureSource.D810,
                FeatureRegion.STATE_HANDOFF,
                f"state_0x{state:02x}_handoff_target",
                targets[0] if len(targets) == 1 else None,
                {"targets": list(targets)},
            )
        )
    return tuple(features)


def diff_features(
    ref: tuple[SemanticFeature, ...],
    d810: tuple[SemanticFeature, ...],
) -> tuple[FeatureDiff, ...]:
    by_name = {feature.feature: feature for feature in d810}
    diffs: list[FeatureDiff] = []
    for ref_feature in ref:
        d810_feature = by_name.get(ref_feature.feature)
        if d810_feature is None:
            diffs.append(
                FeatureDiff(
                    ref_feature.feature,
                    ref_feature.region,
                    ref_feature.value,
                    "<missing>",
                )
            )
            continue
        if ref_feature.value != d810_feature.value:
            diffs.append(
                FeatureDiff(
                    ref_feature.feature,
                    ref_feature.region,
                    ref_feature.value,
                    d810_feature.value,
                )
            )
    return tuple(diffs)


def format_diff_table(diffs: tuple[FeatureDiff, ...]) -> str:
    lines = ["| feature | region | REF | D810 |", "|-|-|-|-|"]
    for diff in diffs:
        lines.append(
            f"| {diff.feature} | {diff.region.value} | "
            f"{diff.ref_value!r} | {diff.d810_value!r} |"
        )
    return "\n".join(lines)


def evaluate_tigress_indirect_semantic_oracle(
    inputs: D810SemanticInputs,
    *,
    spec: RefSpec | None = None,
) -> TigressIndirectOracleResult:
    spec = spec or _TIGRESS_INDIRECT_SPEC
    ref = ref_features(spec)
    d810 = d810_features(inputs)
    diffs = diff_features(ref, d810)
    d810_by_name = {feature.feature: feature for feature in d810}
    failed_names = {diff.feature for diff in diffs}
    checks: list[TigressIndirectCheck] = [
        TigressIndirectCheck(
            diff.feature,
            False,
            f"{diff.region.value}: expected {diff.ref_value!r}, got {diff.d810_value!r}",
        )
        for diff in diffs
    ]

    for feature_name in (
        "state_count",
        "initial_state",
        "all_states_present",
        "terminal_states",
        "conditional_states",
        "state_0x11_handoff_target",
        "state_0x16_handoff_target",
        "final_output_xor_present",
        "password_zeroing_present",
        "password_check_present",
        "failure_zero_write_present",
        "no_raw_indirect_jump",
    ):
        if feature_name not in failed_names:
            checks.append(
                TigressIndirectCheck(
                    feature_name,
                    True,
                    "matches REF semantic witness",
                )
            )

    for feature_name in ("table_bounds_proved", "table_invariant_proved"):
        feature = d810_by_name[feature_name]
        checks.append(
            TigressIndirectCheck(
                feature_name,
                bool(feature.value),
                "indirect jump-table evidence is proven",
            )
        )

    unresolved = d810_by_name["unresolved_states"].value
    checks.append(
        TigressIndirectCheck(
            "no_unresolved_states",
            unresolved == (),
            f"unresolved state rows: {unresolved!r}",
        )
    )

    return TigressIndirectOracleResult(checks=tuple(checks), diffs=diffs)


def render_tigress_indirect_semantic_oracle_report(
    result: TigressIndirectOracleResult,
    *,
    func_name: str,
) -> str:
    lines = [
        "# tigress_flatten_indirect Oracle",
        "",
        f"Function: `{func_name}`",
        f"Status: `{'pass' if result.passed else 'fail'}`",
        "",
        "| Check | Status | Detail |",
        "|-|-|-|",
    ]
    for check in result.checks:
        status = "pass" if check.passed else ("warn" if not check.blocker else "fail")
        lines.append(f"| `{check.name}` | `{status}` | {check.detail} |")

    if result.diffs:
        lines.extend(["", "## Feature Diff", "", format_diff_table(result.diffs)])

    return "\n".join(lines) + "\n"


__all__ = [
    "D810SemanticInputs",
    "FeatureDiff",
    "FeatureRegion",
    "FeatureSource",
    "RefSpec",
    "SemanticFeature",
    "TigressIndirectCheck",
    "TigressIndirectOracleResult",
    "d810_features",
    "diff_features",
    "evaluate_tigress_indirect_semantic_oracle",
    "format_diff_table",
    "inputs_from_transfer_report",
    "is_registered",
    "ref_features",
    "render_tigress_indirect_semantic_oracle_report",
    "spec_for",
]

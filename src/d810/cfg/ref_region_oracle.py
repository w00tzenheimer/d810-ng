"""REF region-shape oracle (read-only).

Compares D810 snapshot region-shape against REF (the manually
unflattened ``tools/equivalence/ref.c``) and produces a normalized
feature diff. Feeds into ``terminal_tail_dce_diagnosis`` to explain
which snap17 → snap18 IDA finalization decisions kill byte_emit[k].

The REF features are hard-encoded because REF for ``sub_7FFD3338C040``
is a fixed reference artifact (the unflattened source compiled with
trace mocks). A future pass can derive REF features from the actual
source/microcode dump if a second function with a REF artifact is
introduced.

D810 features are computed from a diag DB snapshot using the same
queries as ``terminal_tail_loss_localizer`` (block-level presence by
``start_ea_hex``) plus the existing ``TerminalByteEmitterFact``
observations for fact-level detection.

Strictly read-only. No CFG edits, no behavior change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from d810.core.logging import getLogger
from d810.core.typing import Iterable, Mapping

logger = getLogger(__name__)


class FeatureSource(str, Enum):
    REF = "REF"
    D810_SNAPSHOT = "D810_SNAPSHOT"


class FeatureRegion(str, Enum):
    HEAD_LOOP = "head_loop"
    CHUNK_LOOP = "chunk_loop"
    BLOCK_EMIT_LOOP = "block_emit_loop"
    TERMINAL_TAIL = "terminal_tail"
    CLEANUP = "cleanup"
    SCC = "scc"


@dataclass(frozen=True, slots=True)
class RegionFeature:
    """One normalized feature with evidence."""

    source: FeatureSource
    region: FeatureRegion
    feature: str
    value: str | bool | int
    evidence: dict = field(default_factory=dict)
    snapshot_id: int | None = None


@dataclass(frozen=True, slots=True)
class FeatureDiff:
    """One diff between REF and a D810 snapshot."""

    feature: str
    region: FeatureRegion
    ref_value: object
    d810_value: object
    snapshot_id: int

    @property
    def matches(self) -> bool:
        return self.ref_value == self.d810_value


@dataclass(frozen=True, slots=True)
class RefSpec:
    """Function-keyed REF spec.

    Holds the hardcoded REF features for a given function and the label
    preference order used to resolve snap17/snap18 IDs from the diag DB.
    """

    func_ea_hex: str  # lowercase, 0x-prefixed
    func_name: str
    feature_table: tuple[tuple[FeatureRegion, str, object, str], ...]
    snap17_label_preferences: tuple[str, ...]
    snap18_label_preferences: tuple[str, ...]


def _normalize_func_ea_hex(func_ea_hex: str) -> str:
    """Lowercase 0x-prefixed canonical form."""
    s = func_ea_hex.strip().lower()
    if not s.startswith("0x"):
        s = "0x" + s
    return s


_REF_SPEC_BY_FUNC: dict[str, RefSpec] = {}


def _register_spec(spec: RefSpec) -> None:
    _REF_SPEC_BY_FUNC[_normalize_func_ea_hex(spec.func_ea_hex)] = spec


def spec_for(func_ea_hex: str) -> RefSpec | None:
    return _REF_SPEC_BY_FUNC.get(_normalize_func_ea_hex(func_ea_hex))


def is_registered(func_ea_hex: str) -> bool:
    return spec_for(func_ea_hex) is not None


# ---------------------------------------------------------------------------
# Microblock evidence model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InstructionView:
    """Pure view onto one microcode instruction.

    The implementer fills this from a real ``minsn_t`` at runtime, but
    the oracle module never imports IDA — only the opcode name is
    needed for canonical signatures.
    """

    opcode_name: str


@dataclass(frozen=True, slots=True)
class BlockView:
    """Pure view onto one microcode block.

    Populated by adapters that read either the diag DB or a live mba.
    The oracle never touches IDA types directly.
    """

    serial: int
    start_ea: int
    end_ea: int
    instructions: tuple[InstructionView, ...]
    preds: tuple[int, ...]
    succs: tuple[int, ...]
    in_scc: bool
    scc_size: int | None
    block_type: str


def _ea_hex(ea: int) -> str:
    return f"0x{ea & ((1 << 64) - 1):016x}"


def opcode_signature(block: BlockView) -> str:
    """Canonical ``; ``-joined opcode names. Operand-independent.

    Stable under operand reordering or value changes. Used so
    snap17/snap18 microblocks can be matched even if local IDs drifted.
    """
    return "; ".join(ins.opcode_name for ins in block.instructions)


@dataclass(frozen=True, slots=True)
class RefEvidence:
    """Microblock evidence for a REF-side feature."""

    side: str  # always "ref"
    ref_block: str
    ref_ea_or_line_range: str
    opcode_signature: str
    region_role: str
    preds: tuple[str, ...]
    succs: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.side != "ref":
            raise ValueError(f"RefEvidence.side must be 'ref', got {self.side!r}")
        if not self.ref_block:
            raise ValueError("RefEvidence.ref_block is required")
        if not self.region_role:
            raise ValueError("RefEvidence.region_role is required")

    def to_json_dict(self) -> dict:
        return {
            "side": self.side,
            "ref_block": self.ref_block,
            "ref_ea_or_line_range": self.ref_ea_or_line_range,
            "opcode_signature": self.opcode_signature,
            "region_role": self.region_role,
            "preds": list(self.preds),
            "succs": list(self.succs),
        }


@dataclass(frozen=True, slots=True)
class D810Evidence:
    """Microblock evidence for a D810-side feature at a snapshot."""

    side: str  # always "d810"
    snapshot_id: int
    snapshot_label: str
    block_serial: int
    start_ea_hex: str
    end_ea_hex: str
    opcode_signature: str
    preds: tuple[int, ...]
    succs: tuple[int, ...]
    in_scc: bool
    scc_size: int | None
    block_type: str
    region_role: str

    def __post_init__(self) -> None:
        if self.side != "d810":
            raise ValueError(f"D810Evidence.side must be 'd810', got {self.side!r}")
        if self.block_serial is None:
            raise ValueError("D810Evidence.block_serial is required")
        if not self.start_ea_hex:
            raise ValueError("D810Evidence.start_ea_hex is required")
        if not self.region_role:
            raise ValueError("D810Evidence.region_role is required")

    def to_json_dict(self) -> dict:
        return {
            "side": self.side,
            "snapshot_id": self.snapshot_id,
            "snapshot_label": self.snapshot_label,
            "block_serial": self.block_serial,
            "start_ea_hex": self.start_ea_hex,
            "end_ea_hex": self.end_ea_hex,
            "opcode_signature": self.opcode_signature,
            "preds": list(self.preds),
            "succs": list(self.succs),
            "in_scc": self.in_scc,
            "scc_size": self.scc_size,
            "block_type": self.block_type,
            "region_role": self.region_role,
        }


def build_d810_evidence(
    block: BlockView,
    *,
    snapshot_id: int,
    snapshot_label: str,
    region_role: str,
) -> D810Evidence:
    return D810Evidence(
        side="d810",
        snapshot_id=snapshot_id,
        snapshot_label=snapshot_label,
        block_serial=block.serial,
        start_ea_hex=_ea_hex(block.start_ea),
        end_ea_hex=_ea_hex(block.end_ea),
        opcode_signature=opcode_signature(block),
        preds=block.preds,
        succs=block.succs,
        in_scc=block.in_scc,
        scc_size=block.scc_size,
        block_type=block.block_type,
        region_role=region_role,
    )


def build_ref_evidence_from_spec_path(
    *,
    ref_block: str,
    path_string: str,
    opcode_signature_str: str,
    region_role: str,
    preds: tuple[str, ...] = (),
    succs: tuple[str, ...] = (),
) -> RefEvidence:
    return RefEvidence(
        side="ref",
        ref_block=ref_block,
        ref_ea_or_line_range=path_string,
        opcode_signature=opcode_signature_str,
        region_role=region_role,
        preds=preds,
        succs=succs,
    )


# ---------------------------------------------------------------------------
# REF feature spec
# ---------------------------------------------------------------------------

# Hard-encoded REF features for sub_7FFD3338C040.
# Source: tools/equivalence/ref.c lines 466-549 (terminal byte-tail) and
# .tmp/ref_microcode_dump.txt MMAT_GLBOPT1 (215 blocks, 2 self-loops).
#
# Each tuple is (region, feature_name, value, evidence_path).

_REF_FEATURE_TABLE: tuple[tuple[FeatureRegion, str, object, str], ...] = (
    # Real loops — both isolated as self-loops in REF GLBOPT1.
    (FeatureRegion.HEAD_LOOP, "head_2byte_stride_loop_isolated", True,
     "ref_microcode_dump.txt:MMAT_GLBOPT1:blk[9] BLT_2WAY succs=[10,9] self-loop"),
    (FeatureRegion.CHUNK_LOOP, "chunk_block_loop_isolated", True,
     "ref_microcode_dump.txt:MMAT_GLBOPT1:blk[21] BLT_2WAY succs=[22,21] self-loop"),

    # Terminal-tail byte_emit blocks present.
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_0_present", True, "ref.c:494"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_1_present", True, "ref.c:503"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_2_present", True, "ref.c:521"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_3_present", True, "ref.c:527"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_4_present", True, "ref.c:532"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_5_present", True, "ref.c:537"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_6_present", True, "ref.c:541"),

    # Source form: each emit reads v52[k] explicitly.
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_0_source_form", "indexed_base_plus_k", "ref.c:494 *v52"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_1_source_form", "indexed_base_plus_k", "ref.c:503 v52[1]"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_2_source_form", "indexed_base_plus_k", "ref.c:521 v52[2]"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_3_source_form", "indexed_base_plus_k", "ref.c:527 v52[3]"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_4_source_form", "indexed_base_plus_k", "ref.c:532 v52[4]"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_5_source_form", "indexed_base_plus_k", "ref.c:537 v52[5]"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_6_source_form", "indexed_base_plus_k", "ref.c:541 v52[6]"),

    # Destination + counter update for each byte.
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_0_destination_present", True, "ref.c:494 *(_QWORD*)"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_0_counter_update_present", True, "ref.c:495 *v49 + 1"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_1_destination_present", True, "ref.c:503"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_1_counter_update_present", True, "ref.c:504"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_2_destination_present", True, "ref.c:521"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_2_counter_update_present", True, "ref.c:523"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_3_destination_present", True, "ref.c:527"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_3_counter_update_present", True, "ref.c:528"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_4_destination_present", True, "ref.c:532"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_4_counter_update_present", True, "ref.c:533"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_5_destination_present", True, "ref.c:537"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_5_counter_update_present", True, "ref.c:539"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_6_destination_present", True, "ref.c:541"),
    (FeatureRegion.TERMINAL_TAIL, "byte_emit_6_counter_update_present", True, "ref.c:542"),

    # Early-return guards before each emit (REF cascade).
    (FeatureRegion.TERMINAL_TAIL, "early_return_guard_0_present", True, "ref.c:497 if(v152==1) return"),
    (FeatureRegion.TERMINAL_TAIL, "early_return_guard_1_present", True, "ref.c:515 if(v152==2)"),
    (FeatureRegion.TERMINAL_TAIL, "early_return_guard_2_present", True, "ref.c:525 if(v152!=3)"),
    (FeatureRegion.TERMINAL_TAIL, "early_return_guard_3_present", True, "ref.c:530 if(v152!=4)"),
    (FeatureRegion.TERMINAL_TAIL, "early_return_guard_4_present", True, "ref.c:535 if(v152!=6)"),
    (FeatureRegion.TERMINAL_TAIL, "early_return_guard_5_present", True, "ref.c:535 same gate"),
    (FeatureRegion.TERMINAL_TAIL, "byte_6_fallthrough_return_present", True, "ref.c:542 ++*v49 then return"),

    # Terminal tail topology.
    (FeatureRegion.TERMINAL_TAIL, "terminal_tail_acyclic", True,
     "ref_microcode_dump.txt:MMAT_GLBOPT1: terminal blocks 107..213 acyclic"),
    (FeatureRegion.TERMINAL_TAIL, "tail_init_present", True, "ref.c:466 v53 = ... ;if (!v53) return"),

    # Cleanup (zero store16) — present and separated from byte emits.
    (FeatureRegion.CLEANUP, "zero_store16_cleanup_blocks_present", True,
     "ref.c:245-252 + 291-298 + 306-313 (3x8=24 STORE_OWORD_N)"),
    (FeatureRegion.CLEANUP, "cleanup_separated_from_byte_emits", True,
     "ref_microcode_dump.txt: cleanup blocks 25..105 separate from terminal_tail"),

    # SCC structure.
    (FeatureRegion.SCC, "nontrivial_scc_count", 2,
     "ref_microcode_dump.txt:MMAT_GLBOPT1: 2 self-loops, no giant SCC"),
    (FeatureRegion.SCC, "max_scc_size", 1,
     "self-loops are size-1 SCCs"),
    (FeatureRegion.SCC, "max_in_degree", 9,
     "blk[213] exit fanout"),
)


_register_spec(
    RefSpec(
        func_ea_hex="0x0000000180012df0",
        func_name="sub_7FFD3338C040",
        feature_table=_REF_FEATURE_TABLE,
        snap17_label_preferences=(
            "post_bundle_stabilize",
            "post_pipeline",
            "handler_chain_composer_post_apply",
        ),
        snap18_label_preferences=(
            "maturity_MMAT_GLBOPT1_post_d810",
            "GLBOPT1_post_d810",
            "post_d810",
        ),
    )
)


def ref_features(spec: RefSpec) -> Iterable[RegionFeature]:
    """Yield REF features from a registered spec."""
    for region, name, value, evidence_path in spec.feature_table:
        yield RegionFeature(
            source=FeatureSource.REF,
            region=region,
            feature=name,
            value=value,
            evidence={"path": evidence_path},
        )


# ---------------------------------------------------------------------------
# D810 snapshot feature extraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class D810SnapshotInputs:
    """Inputs needed to compute a D810 snapshot's region-shape features."""

    snapshot_id: int
    nontrivial_scc_count: int
    max_scc_size: int
    max_in_degree: int
    byte_emit_present: dict[int, bool]
    byte_emit_block_serial: dict[int, int | None]
    byte_emit_fact_detected: dict[int, bool]
    early_return_guard_present: dict[int, bool] = field(default_factory=dict)
    terminal_tail_acyclic: bool = False
    head_loop_isolated: bool = False
    chunk_loop_isolated: bool = False
    cleanup_blocks_present: bool = False


def d810_features(inputs: D810SnapshotInputs) -> tuple[RegionFeature, ...]:
    """Compose normalized features from a D810 snapshot input record."""
    snap = inputs.snapshot_id
    out: list[RegionFeature] = []

    def add(region: FeatureRegion, feature: str, value: object, **evidence: object) -> None:
        out.append(
            RegionFeature(
                source=FeatureSource.D810_SNAPSHOT,
                region=region,
                feature=feature,
                value=value,
                evidence=dict(evidence),
                snapshot_id=snap,
            )
        )

    add(FeatureRegion.HEAD_LOOP, "head_2byte_stride_loop_isolated", inputs.head_loop_isolated)
    add(FeatureRegion.CHUNK_LOOP, "chunk_block_loop_isolated", inputs.chunk_loop_isolated)
    add(FeatureRegion.SCC, "nontrivial_scc_count", inputs.nontrivial_scc_count)
    add(FeatureRegion.SCC, "max_scc_size", inputs.max_scc_size)
    add(FeatureRegion.SCC, "max_in_degree", inputs.max_in_degree)
    add(FeatureRegion.TERMINAL_TAIL, "terminal_tail_acyclic", inputs.terminal_tail_acyclic)
    add(FeatureRegion.CLEANUP, "zero_store16_cleanup_blocks_present", inputs.cleanup_blocks_present)

    for k in range(7):
        present = inputs.byte_emit_present.get(k, False)
        add(FeatureRegion.TERMINAL_TAIL, f"byte_emit_{k}_present", present,
            block_serial=inputs.byte_emit_block_serial.get(k),
            fact_detected=inputs.byte_emit_fact_detected.get(k, False))

    for k in range(6):
        add(FeatureRegion.TERMINAL_TAIL, f"early_return_guard_{k}_present",
            inputs.early_return_guard_present.get(k, False))

    return tuple(out)


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


def diff_features(
    ref: Iterable[RegionFeature],
    d810: Iterable[RegionFeature],
) -> tuple[FeatureDiff, ...]:
    """Compute (feature, region) -> (ref_value vs d810_value) diffs."""
    ref_index: dict[str, RegionFeature] = {f.feature: f for f in ref}
    d810_index: dict[str, RegionFeature] = {f.feature: f for f in d810}
    diffs: list[FeatureDiff] = []
    keys = sorted(set(ref_index) | set(d810_index))
    for key in keys:
        rf = ref_index.get(key)
        df = d810_index.get(key)
        if rf is None or df is None:
            # Feature only on one side — count as diff with placeholder.
            diffs.append(
                FeatureDiff(
                    feature=key,
                    region=(rf.region if rf else df.region),
                    ref_value=rf.value if rf else "MISSING",
                    d810_value=df.value if df else "MISSING",
                    snapshot_id=df.snapshot_id if df else -1,
                )
            )
            continue
        if rf.value != df.value:
            diffs.append(
                FeatureDiff(
                    feature=key, region=rf.region,
                    ref_value=rf.value, d810_value=df.value,
                    snapshot_id=df.snapshot_id or -1,
                )
            )
    return tuple(diffs)


def format_diff_table(diffs: tuple[FeatureDiff, ...]) -> str:
    """Render markdown diff table."""
    lines = [
        "| feature | region | REF | D810 |",
        "|-|-|-|-|",
    ]
    for d in diffs:
        lines.append(
            f"| {d.feature} | {d.region.value} | {d.ref_value!r} | {d.d810_value!r} |"
        )
    return "\n".join(lines)


__all__ = [
    "BlockView",
    "D810Evidence",
    "D810SnapshotInputs",
    "FeatureDiff",
    "FeatureRegion",
    "FeatureSource",
    "InstructionView",
    "RefEvidence",
    "RefSpec",
    "RegionFeature",
    "build_d810_evidence",
    "build_ref_evidence_from_spec_path",
    "d810_features",
    "diff_features",
    "format_diff_table",
    "is_registered",
    "opcode_signature",
    "ref_features",
    "spec_for",
]

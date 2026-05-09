"""Topology-only tail-distinct shaping for one terminal byte_emit.

Goal: prevent IDA's mba_t.optimize_global() from folding byte_emit
blocks that share an identical tail topology. The transform inserts
a single empty trampoline block between byte_emit[k] and its
shared successor:

    byte_emit[k] -> trampoline -> original_successor

The trampoline carries zero semantic instructions — only an
unconditional jump. This is a topology-only nudge: it changes the
shape of byte_emit[k]'s tail without altering any byte computation,
state-write, or carrier.

Strict scope:
- Single byte_index per call.
- No multi-byte mode.
- No semantic instructions.
- No carrier reconstruction.
- No-op (ShapingReport.applied=False) on any precondition failure.

The module is split into:
- pure dataclasses + helpers (no IDA): testable in tests/unit/.
- isolate_byte_emit_tail(mba, ...): IDA-coupled mutator. The actual
  block-insertion call is left as a small adapter; the shape of the
  call site is fixed here so the runtime test can exercise it later.

The historical fact source is the diag DB's fact_observations table
queried at the highest snapshot whose label matches GLBOPT1 pre_d810.
The caller resolves that for us via FactView.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from d810.core.typing import Iterable, Protocol


def parse_tail_distinct_byte_env(value: str | None) -> int | None:
    """Parse the D810_TAIL_DISTINCT_BYTE env value.

    Returns the byte index (0..6) when valid; None for any of:
    - unset / empty string
    - non-integer value
    - integer outside [0, 6]
    """
    if not value:
        return None
    try:
        idx = int(value.strip())
    except ValueError:
        return None
    if not (0 <= idx <= 6):
        return None
    return idx


@dataclass(frozen=True, slots=True)
class FactRow:
    """Pure view of one TerminalByteEmitterFact row.

    Populated from the diag DB by an adapter; this module never
    touches sqlite directly.
    """

    snapshot_id: int
    byte_index: int
    block_serial: int
    start_ea_hex: str
    corridor_role: str  # 'terminal_tail' preferred when multiple match


@dataclass(frozen=True, slots=True)
class BlockView:
    """Pure view of one live microcode block at the boundary where
    isolate_byte_emit_tail() runs.

    The fields cover only what the precondition check needs:
    - serial: live block serial in the mba
    - start_ea: int, used to match by EA
    - nsucc: number of successors
    - succ_serial: the unique successor's serial when nsucc == 1
    - succ_npred: predecessor count of the successor
    - tail_kind: opaque string describing the tail (e.g. "goto",
      "fallthrough", "cond_branch") — the precondition gate uses
      this to refuse non-redirectable tails.
    """

    serial: int
    start_ea: int
    nsucc: int
    succ_serial: int | None
    succ_npred: int | None
    tail_kind: str


class FactView(Protocol):
    """Read-only protocol for fact lookups.

    Implementations come from two sources:
    - diag DB adapter (production): queries fact_observations.
    - in-memory list (tests): wraps a tuple of FactRow.
    """

    def terminal_byte_emit_facts(self, byte_index: int) -> Iterable[FactRow]:
        """Yield all TerminalByteEmitterFact rows for the given byte.

        Order is unspecified; the caller selects the best candidate
        via _resolve_target_ea.
        """
        ...


@dataclass(frozen=True, slots=True)
class PrecheckResult:
    """Tagged precheck outcome.

    ``ok=True`` means the block is shapeable; ``block`` is populated.
    ``ok=False`` means a no-op; ``reason`` carries the structured tag.
    A single class with a discriminator avoids ``isinstance`` against
    concrete classes (which the project's pre-commit lint rejects).
    """

    ok: bool
    block: BlockView | None = None
    reason: str = ""

    @classmethod
    def success(cls, block: BlockView) -> PrecheckResult:
        return cls(ok=True, block=block, reason="")

    @classmethod
    def failure(cls, reason: str) -> PrecheckResult:
        return cls(ok=False, block=None, reason=reason)


@dataclass(frozen=True, slots=True)
class ShapingReport:
    """Result of one isolate_byte_emit_tail call."""

    applied: bool
    byte_index: int
    reason: str
    byte_emit_ea: int | None = None
    byte_emit_serial: int | None = None
    trampoline_serial: int | None = None
    split_block_serial: int | None = None
    successor_serial_before: int | None = None
    successor_npred_before: int | None = None
    successor_npred_after: int | None = None


# ---------------------------------------------------------------------------
# Pure helpers (testable in tests/unit/)
# ---------------------------------------------------------------------------


def _resolve_target_ea(
    facts: Iterable[FactRow], byte_index: int,
) -> str | None:
    """Pick the start_ea_hex for the requested byte_index.

    Preference order:
    1. fact with corridor_role == 'terminal_tail'
    2. otherwise: the fact with the highest snapshot_id

    Returns None if no fact for that byte_index exists.
    """
    matches = [f for f in facts if f.byte_index == byte_index]
    if not matches:
        return None
    # Prefer terminal_tail role.
    tail_role = [f for f in matches if f.corridor_role == "terminal_tail"]
    if tail_role:
        chosen = max(tail_role, key=lambda f: f.snapshot_id)
    else:
        chosen = max(matches, key=lambda f: f.snapshot_id)
    return chosen.start_ea_hex


def _check_preconditions(block: BlockView) -> PrecheckResult:
    """Decide whether byte_emit[k]'s tail is safely shapeable.

    Required:
    - nsucc == 1
    - the unique successor has npred >= 2 (i.e. shared with siblings)
    - tail_kind in {'goto', 'fallthrough'} (redirectable)
    """
    if block.nsucc != 1:
        return PrecheckResult.failure(
            f"preconditions_unmet:multi_succ:{block.nsucc}"
        )
    if block.succ_serial is None:
        return PrecheckResult.failure("preconditions_unmet:no_successor")
    if block.succ_npred is None or block.succ_npred < 2:
        return PrecheckResult.failure("no_shared_tail")
    if block.tail_kind not in ("goto", "fallthrough"):
        return PrecheckResult.failure(
            f"preconditions_unmet:tail_kind:{block.tail_kind}"
        )
    return PrecheckResult.success(block)


# ---------------------------------------------------------------------------
# Adapter Protocol for the IDA-coupled mutator
# ---------------------------------------------------------------------------


class MicrocodeAdapter(Protocol):
    """Abstract over the small set of IDA mutation operations.

    Production: a real adapter wrapping mba operations.
    Tests: a fake adapter recording every call.
    """

    def find_block_by_ea(self, ea: int) -> BlockView | None:
        ...

    def insert_trampoline_after(
        self, predecessor_serial: int, successor_serial: int,
    ) -> int:
        """Insert an empty BLT_0WAY-style trampoline between
        predecessor_serial and successor_serial; rewire predecessor's
        sole successor edge to point at the trampoline; the trampoline
        contains exactly one unconditional jump to successor_serial.

        Returns the new trampoline's serial.
        """
        ...

    def successor_npred(self, successor_serial: int) -> int:
        ...

    def split_block_at_tail_jcnd(self, block_serial: int) -> int:
        """Split a 2-way block immediately before its tail conditional jump.

        The instructions before the jcnd remain in the original block (now
        BLT_1WAY, fallthrough/goto to the new block). The jcnd and its
        two-arm successor list move to the new block.

        Returns the new block's serial.

        Raises if the block is not 2-way or its tail is not a conditional
        jump.
        """
        ...


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def isolate_byte_emit_tail(
    *,
    byte_index: int,
    fact_view: FactView,
    adapter: MicrocodeAdapter,
) -> ShapingReport:
    """Topology-only tail-distinct insertion for one byte_emit.

    Pure orchestration. The adapter holds all live-mba access.
    """
    if not (0 <= byte_index <= 6):
        return ShapingReport(
            applied=False,
            byte_index=byte_index,
            reason="invalid_byte_index",
        )

    target_ea_hex = _resolve_target_ea(
        fact_view.terminal_byte_emit_facts(byte_index),
        byte_index,
    )
    if target_ea_hex is None:
        return ShapingReport(
            applied=False, byte_index=byte_index, reason="no_fact",
        )

    try:
        target_ea = int(target_ea_hex, 16)
    except ValueError:
        return ShapingReport(
            applied=False,
            byte_index=byte_index,
            reason=f"malformed_ea:{target_ea_hex!r}",
        )

    block = adapter.find_block_by_ea(target_ea)
    if block is None:
        return ShapingReport(
            applied=False,
            byte_index=byte_index,
            reason="block_not_resolvable_at_runtime",
            byte_emit_ea=target_ea,
        )

    # If the resolved block is 2-way with a conditional tail, split first
    # so the v1 trampoline path can run on the now-1-way head.
    split_serial: int | None = None
    if block.nsucc == 2 and block.tail_kind == "cond_branch":
        try:
            split_serial = adapter.split_block_at_tail_jcnd(block.serial)
        except Exception as e:  # noqa: BLE001 — adapter raises on split failure
            return ShapingReport(
                applied=False,
                byte_index=byte_index,
                reason=f"split_failed:{type(e).__name__}",
                byte_emit_ea=target_ea,
                byte_emit_serial=block.serial,
            )
        # Re-resolve the block by EA — should now be 1-way to split_serial.
        block = adapter.find_block_by_ea(target_ea)
        if block is None:
            return ShapingReport(
                applied=False,
                byte_index=byte_index,
                reason="post_split_block_not_resolvable",
                byte_emit_ea=target_ea,
            )
        if block.nsucc != 1:
            return ShapingReport(
                applied=False,
                byte_index=byte_index,
                reason=f"post_split_not_1way:nsucc={block.nsucc}",
                byte_emit_ea=target_ea,
                byte_emit_serial=block.serial,
            )

    pre = _check_preconditions(block)
    if not pre.ok:
        return ShapingReport(
            applied=False,
            byte_index=byte_index,
            reason=pre.reason,
            byte_emit_ea=target_ea,
            byte_emit_serial=block.serial,
            successor_serial_before=block.succ_serial,
            successor_npred_before=block.succ_npred,
        )

    # Mutate. pre.ok is True so pre.block is populated.
    pre_block = pre.block
    assert pre_block is not None  # narrowed by precheck contract
    successor_serial = pre_block.succ_serial
    assert successor_serial is not None  # narrowed by precheck
    npred_before = pre_block.succ_npred

    trampoline_serial = adapter.insert_trampoline_after(
        predecessor_serial=pre_block.serial,
        successor_serial=successor_serial,
    )
    npred_after = adapter.successor_npred(successor_serial)

    return ShapingReport(
        applied=True,
        byte_index=byte_index,
        reason="ok",
        byte_emit_ea=target_ea,
        byte_emit_serial=pre_block.serial,
        trampoline_serial=trampoline_serial,
        split_block_serial=split_serial,
        successor_serial_before=successor_serial,
        successor_npred_before=npred_before,
        successor_npred_after=npred_after,
    )

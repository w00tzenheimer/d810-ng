"""Layered proof orchestrator for terminal return handlers.

Given an MBA and a :class:`TerminalReturnAuditReport` from recon, determine
whether each terminal handler has a provable return-carrier (rax.8) definition
using progressively heavier analysis layers:

1. **Topology** -- consume audit report (no live analysis)
2. **Single-predecessor walk** -- backward walk through single-pred chain
3. **Chain-backed merge** -- UD chain query at merge points
4. **Reaching-def** -- forward dataflow on handler subgraph
5. **Emulator** -- MopTracker fallback (future)

All layers are fault-tolerant: if any layer throws, it is logged and the
orchestrator continues to the next layer.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.core.typing import TYPE_CHECKING, NamedTuple, Optional

if TYPE_CHECKING:
    from d810.recon.flow.terminal_return_audit import (
        TerminalReturnAuditReport,
        TerminalReturnSiteAudit,
        TerminalReturnSourceKind,
    )

# String constants matching TerminalReturnSourceKind values for runtime comparison
# without importing from recon at runtime (layering: evaluator must not import recon).
_DIRECT_RETURN = "direct_return"
_EPILOGUE_CORRIDOR = "epilogue_corridor"

logger = getLogger(__name__)


# ---------------------------------------------------------------------------
# Lazy IDA import helper
# ---------------------------------------------------------------------------


def _get_ida():  # type: ignore[return]
    """Lazily import ida_hexrays to avoid hard dependency in unit tests."""
    import ida_hexrays

    return ida_hexrays


# ---------------------------------------------------------------------------
# Core types
# ---------------------------------------------------------------------------


class ProofLayer(str, enum.Enum):
    """Which analysis layer resolved the return-carrier proof."""

    TOPOLOGY = "topology"
    """From recon audit (has_rax_write field)."""

    SINGLE_PRED_WALK = "single_pred_walk"
    """Backward single-predecessor walk found a definition."""

    CHAIN_BACKED = "chain_backed"
    """UD chain confirmed definition at merge point."""

    REACHING_DEF = "reaching_def"
    """Forward dataflow reaching-def confirmed definition."""

    EMULATOR = "emulator"
    """Emulator/tracker fallback (future)."""

    UNRESOLVED = "unresolved"
    """No layer could prove a return-carrier definition."""


class DefSiteLike(NamedTuple):
    """Lightweight definition site descriptor.

    Attributes:
        block_serial: Serial number of the block containing the definition.
        ins_ea: Effective address of the defining instruction.
        opcode: Microcode opcode of the defining instruction (None if unknown).
    """

    block_serial: int
    ins_ea: int
    opcode: Optional[int] = None


@dataclass(frozen=True)
class TerminalReturnValueProof:
    """Proof result for a single terminal handler's return-carrier definition.

    Attributes:
        handler_serial: Entry block serial of the terminal handler.
        carrier_kind: Description of the carrier, e.g. ``"rax.8"``, ``"stack_slot"``.
        def_sites: Where the carrier was defined (empty if unresolved).
        ambiguous: True if multiple conflicting definitions were found.
        topology_kind: The :class:`TerminalReturnSourceKind` value from the audit.
        proof_layer_used: Which analysis layer resolved the proof.
        notes: Free-form diagnostic note.
    """

    handler_serial: int
    carrier_kind: str
    def_sites: tuple[DefSiteLike, ...]
    ambiguous: bool
    topology_kind: str
    proof_layer_used: ProofLayer
    notes: str = ""


@dataclass(frozen=True)
class TerminalReturnProofReport:
    """Aggregate proof report for all terminal handlers in a function.

    Attributes:
        function_ea: Function entry address.
        proofs: Per-handler proof results.
    """

    function_ea: int
    proofs: tuple[TerminalReturnValueProof, ...]

    def summary(self) -> str:
        """One-line summary of proof results.

        Returns:
            String of the form ``"N handlers: X resolved, Y ambiguous, Z unresolved"``.
        """
        resolved = 0
        ambiguous = 0
        unresolved = 0
        for p in self.proofs:
            if p.proof_layer_used == ProofLayer.UNRESOLVED:
                unresolved += 1
            elif p.ambiguous:
                ambiguous += 1
            else:
                resolved += 1
        return (
            f"{len(self.proofs)} handlers: "
            f"{resolved} resolved, {ambiguous} ambiguous, {unresolved} unresolved"
        )


# ---------------------------------------------------------------------------
# Helper: single-predecessor backward walk
# ---------------------------------------------------------------------------


def _single_pred_walk_for_carrier(
    mba: object,
    start_serial: int,
    carrier_mreg: int,
    carrier_size: int,
    max_depth: int = 10,
) -> Optional[DefSiteLike]:
    """Walk backward through a single-predecessor chain looking for a carrier def.

    Starting at *start_serial*, walk predecessor blocks (only following
    single-predecessor edges) and scan each block's instructions from tail
    to head for a write to *carrier_mreg* with *carrier_size*.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        start_serial: Serial number of the block to start from.
        carrier_mreg: Micro-register number (e.g. ``mr_rax``).
        carrier_size: Operand size in bytes.
        max_depth: Maximum number of predecessor hops.

    Returns:
        A :class:`DefSiteLike` if a definition is found, ``None`` otherwise.
    """
    try:
        ida_hexrays = _get_ida()
    except ImportError:
        return None

    current_serial = start_serial
    visited: set[int] = set()

    for _ in range(max_depth):
        if current_serial in visited:
            break
        visited.add(current_serial)

        try:
            blk = mba.get_mblock(current_serial)  # type: ignore[attr-defined]
        except (AttributeError, IndexError):
            break

        # Scan instructions tail-to-head.
        ins = blk.tail  # type: ignore[attr-defined]
        while ins:
            d = getattr(ins, "d", None)
            if d is not None:
                if (
                    getattr(d, "t", None) == ida_hexrays.mop_r
                    and getattr(d, "r", None) == carrier_mreg
                    and getattr(d, "size", 0) == carrier_size
                ):
                    return DefSiteLike(
                        block_serial=current_serial,
                        ins_ea=getattr(ins, "ea", 0),
                        opcode=getattr(ins, "opcode", None),
                    )
            ins = getattr(ins, "prev", None)

        # Move to single predecessor.
        preds = list(getattr(blk, "predset", []))
        if len(preds) != 1:
            break
        current_serial = preds[0]

    return None


# ---------------------------------------------------------------------------
# Layer 3: chain-backed merge proof
# ---------------------------------------------------------------------------


def _chain_backed_proof(
    mba: object,
    return_block_serial: int,
    carrier_mreg: int,
    carrier_size: int,
) -> tuple[tuple[DefSiteLike, ...], bool]:
    """Use UD chains to find reaching defs for the carrier at the return block.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        return_block_serial: Serial of the return block.
        carrier_mreg: Micro-register number.
        carrier_size: Operand size in bytes.

    Returns:
        Tuple of ``(def_sites, ambiguous)``. Empty def_sites if chains
        are unavailable or return no results.
    """
    from d810.evaluator.hexrays_microcode.chains import find_reaching_defs_for_reg

    chain_defs = find_reaching_defs_for_reg(mba, return_block_serial, carrier_mreg, carrier_size)
    if not chain_defs:
        return (), False

    sites = tuple(
        DefSiteLike(
            block_serial=d.block_serial,
            ins_ea=d.ins_ea,
            opcode=d.ins_opcode,
        )
        for d in chain_defs
    )
    ambiguous = len(sites) > 1
    return sites, ambiguous


# ---------------------------------------------------------------------------
# Layer 4: path-restricted reaching-def
# ---------------------------------------------------------------------------


def _reaching_def_proof(
    mba: object,
    handler_entry_serial: int,
    return_block_serial: int,
    carrier_mreg: int,
    carrier_size: int,
) -> tuple[tuple[DefSiteLike, ...], bool]:
    """Run forward reaching-def dataflow on the handler subgraph.

    Builds a subgraph from *handler_entry_serial* to *return_block_serial*
    via BFS, then runs the generic fixpoint engine with reaching-def domain.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        handler_entry_serial: Entry block serial of the handler.
        return_block_serial: Serial of the return block.
        carrier_mreg: Micro-register number.
        carrier_size: Operand size in bytes.

    Returns:
        Tuple of ``(def_sites, ambiguous)``. Empty if analysis fails.
    """
    from collections import deque

    from d810.cfg.lattice import BOTTOM
    from d810.evaluator.hexrays_microcode.domains.reaching_defs import (
        DefSite as RDDefSite,
        ReachingDefEnv,
        VarKey,
        reaching_defs_meet,
        reaching_defs_transfer_block,
    )
    from d810.evaluator.hexrays_microcode.forward_dataflow import run_forward_fixpoint

    try:
        _get_ida()
    except ImportError:
        return (), False

    # BFS to discover subgraph nodes reachable from handler entry.
    subgraph_nodes: set[int] = set()
    bfs_queue: deque[int] = deque([handler_entry_serial])
    subgraph_nodes.add(handler_entry_serial)

    while bfs_queue:
        serial = bfs_queue.popleft()
        try:
            blk = mba.get_mblock(serial)  # type: ignore[attr-defined]
        except (AttributeError, IndexError):
            continue
        for succ in getattr(blk, "succset", []):
            if succ not in subgraph_nodes:
                subgraph_nodes.add(succ)
                bfs_queue.append(succ)

    if return_block_serial not in subgraph_nodes:
        return (), False

    # Build predecessor/successor maps restricted to subgraph.
    pred_map: dict[int, list[int]] = {n: [] for n in subgraph_nodes}
    succ_map: dict[int, list[int]] = {n: [] for n in subgraph_nodes}
    for n in subgraph_nodes:
        try:
            blk = mba.get_mblock(n)  # type: ignore[attr-defined]
        except (AttributeError, IndexError):
            continue
        for s in getattr(blk, "succset", []):
            if s in subgraph_nodes:
                succ_map[n].append(s)
                pred_map[s].append(n)

    # Transfer wrapper: adapt block-level transfer to fixpoint engine interface.
    def transfer_fn(node_id: int, in_state: ReachingDefEnv) -> ReachingDefEnv:
        try:
            blk = mba.get_mblock(node_id)  # type: ignore[attr-defined]
        except (AttributeError, IndexError):
            return dict(in_state)
        return reaching_defs_transfer_block(blk, in_state)

    result = run_forward_fixpoint(
        nodes=subgraph_nodes,
        entry_node=handler_entry_serial,
        entry_state={},
        bottom={},
        predecessors_of=lambda n: pred_map.get(n, []),
        successors_of=lambda n: succ_map.get(n, []),
        meet=reaching_defs_meet,
        transfer=transfer_fn,
        max_iterations=500,
    )

    # Check OUT[return_block] for the carrier VarKey.
    carrier_key = VarKey(kind="reg", identifier=carrier_mreg, size=carrier_size)
    out_env = result.out_states.get(return_block_serial, {})
    value = out_env.get(carrier_key, BOTTOM)

    if value is BOTTOM or not isinstance(value, frozenset):
        return (), False

    sites = tuple(
        DefSiteLike(
            block_serial=ds.block_serial,
            ins_ea=ds.ins_ea,
            opcode=ds.opcode,
        )
        for ds in value
        if isinstance(ds, RDDefSite)
    )
    ambiguous = len(sites) > 1
    return sites, ambiguous


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

# Default carrier: rax micro-register number.
# IDA's mr_rax = 0 for 64-bit code. Callers can override.
_DEFAULT_CARRIER_MREG: int = 0


def prove_terminal_returns(
    mba: object,
    audit_report: TerminalReturnAuditReport,
    *,
    carrier_mreg: int = _DEFAULT_CARRIER_MREG,
    carrier_size: int = 8,
) -> TerminalReturnProofReport:
    """Orchestrate layered proof for all terminal return handlers.

    For each site in *audit_report*, run progressively heavier analysis
    layers until one resolves or all are exhausted.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance (or ``None`` for topology-only).
        audit_report: The terminal return audit from recon.
        carrier_mreg: Micro-register number for the return carrier (default: mr_rax=0).
        carrier_size: Operand size in bytes for the return carrier (default: 8).

    Returns:
        A :class:`TerminalReturnProofReport` with per-handler proof results.
    """
    carrier_kind = f"mreg{carrier_mreg}.{carrier_size}"
    proofs: list[TerminalReturnValueProof] = []

    for site in audit_report.sites:
        proof = _prove_single_site(
            mba, site, carrier_mreg=carrier_mreg, carrier_size=carrier_size,
            carrier_kind=carrier_kind,
        )
        proofs.append(proof)

    report = TerminalReturnProofReport(
        function_ea=audit_report.function_ea,
        proofs=tuple(proofs),
    )
    logger.info("Terminal return proof: %s", report.summary())
    return report


def _prove_single_site(
    mba: object,
    site: TerminalReturnSiteAudit,
    *,
    carrier_mreg: int,
    carrier_size: int,
    carrier_kind: str,
) -> TerminalReturnValueProof:
    """Run the layered proof for a single terminal handler site.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance (or ``None`` for topology-only).
        site: A single audit site from the recon report.
        carrier_mreg: Micro-register number for the return carrier.
        carrier_size: Operand size in bytes.
        carrier_kind: Human-readable carrier description.

    Returns:
        A :class:`TerminalReturnValueProof` for this handler.
    """
    # --- Layer 1: Topology ---
    try:
        if (
            site.has_rax_write is True
            and site.source_kind == _DIRECT_RETURN
        ):
            return TerminalReturnValueProof(
                handler_serial=site.handler_serial,
                carrier_kind=carrier_kind,
                def_sites=(),
                ambiguous=False,
                topology_kind=str(site.source_kind),
                proof_layer_used=ProofLayer.TOPOLOGY,
                notes="topology: direct return with rax write confirmed by audit",
            )
    except Exception:
        logger.debug(
            "Layer TOPOLOGY failed for handler %d", site.handler_serial, exc_info=True
        )

    # --- Layer 2: Single-predecessor walk ---
    if mba is not None and site.return_block_serial is not None:
        try:
            def_site = _single_pred_walk_for_carrier(
                mba, site.return_block_serial, carrier_mreg, carrier_size,
            )
            if def_site is not None:
                return TerminalReturnValueProof(
                    handler_serial=site.handler_serial,
                    carrier_kind=carrier_kind,
                    def_sites=(def_site,),
                    ambiguous=False,
                    topology_kind=str(site.source_kind),
                    proof_layer_used=ProofLayer.SINGLE_PRED_WALK,
                    notes=f"single-pred walk found def at blk {def_site.block_serial}",
                )
        except Exception:
            logger.debug(
                "Layer SINGLE_PRED_WALK failed for handler %d",
                site.handler_serial,
                exc_info=True,
            )

    # --- Layer 3: Chain-backed merge proof ---
    if mba is not None and site.return_block_serial is not None:
        try:
            chain_sites, chain_ambiguous = _chain_backed_proof(
                mba, site.return_block_serial, carrier_mreg, carrier_size,
            )
            if chain_sites:
                return TerminalReturnValueProof(
                    handler_serial=site.handler_serial,
                    carrier_kind=carrier_kind,
                    def_sites=chain_sites,
                    ambiguous=chain_ambiguous,
                    topology_kind=str(site.source_kind),
                    proof_layer_used=ProofLayer.CHAIN_BACKED,
                    notes=f"chain-backed: {len(chain_sites)} def(s)",
                )
        except Exception:
            logger.debug(
                "Layer CHAIN_BACKED failed for handler %d",
                site.handler_serial,
                exc_info=True,
            )

    # --- Layer 4: Reaching-def on subgraph ---
    if (
        mba is not None
        and site.return_block_serial is not None
        and site.handler_serial is not None
    ):
        try:
            rd_sites, rd_ambiguous = _reaching_def_proof(
                mba,
                site.handler_serial,
                site.return_block_serial,
                carrier_mreg,
                carrier_size,
            )
            if rd_sites:
                return TerminalReturnValueProof(
                    handler_serial=site.handler_serial,
                    carrier_kind=carrier_kind,
                    def_sites=rd_sites,
                    ambiguous=rd_ambiguous,
                    topology_kind=str(site.source_kind),
                    proof_layer_used=ProofLayer.REACHING_DEF,
                    notes=f"reaching-def: {len(rd_sites)} def(s)",
                )
        except Exception:
            logger.debug(
                "Layer REACHING_DEF failed for handler %d",
                site.handler_serial,
                exc_info=True,
            )

    # --- Layer 5: Emulator (future) ---
    # Not implemented; fall through to UNRESOLVED.

    return TerminalReturnValueProof(
        handler_serial=site.handler_serial,
        carrier_kind=carrier_kind,
        def_sites=(),
        ambiguous=False,
        topology_kind=str(site.source_kind),
        proof_layer_used=ProofLayer.UNRESOLVED,
        notes="no layer could resolve",
    )


__all__ = [
    "DefSiteLike",
    "ProofLayer",
    "TerminalReturnProofReport",
    "TerminalReturnValueProof",
    "prove_terminal_returns",
]

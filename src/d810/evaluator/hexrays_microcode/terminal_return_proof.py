"""Diagnostic evidence for terminal return handlers.

Observe topology, backward definitions, merge chains and reaching definitions
without granting mutation permission. Live analysis rebinds audit EAs uniquely;
block serials from an earlier snapshot are never used as live identities.
Topology-only observations remain distinct from resolved definitions.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, replace

from d810.analyses.control_flow.terminal_return_audit import (
    TerminalReturnSourceKind,
    TerminalReturnSiteAudit,
    TerminalReturnAuditReport,
)
from d810.core.logging import getLogger
from d810.core.typing import Optional

logger = getLogger(__name__)

try:
    import ida_hexrays

    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


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


class CarrierValueKind(str, enum.Enum):
    """Classification of the source operand that defines the return carrier."""

    CONST = "const"
    """Source operand is ``mop_n`` (literal constant)."""

    STACK_SLOT = "stack_slot"
    """Source operand is ``mop_S`` (stack variable)."""

    REGISTER = "register"
    """Source operand is ``mop_r`` (register)."""

    EXPRESSION = "expression"
    """Source is complex (``mop_d``, ``mop_a``, etc.)."""

    UNKNOWN = "unknown"
    """Could not classify."""


@dataclass(frozen=True)
class ReturnCarrierRegister:
    """Typed register coordinate; its display name cannot establish a proof."""

    micro_register: int
    width: int

    def __post_init__(self) -> None:
        if type(self.micro_register) is not int or self.micro_register < 0:
            raise TypeError("carrier register must be a non-negative integer")
        if type(self.width) is not int or self.width <= 0:
            raise TypeError("carrier width must be a positive integer")


class TerminalReturnProofStatus(str, enum.Enum):
    TOPOLOGY_OBSERVED = "topology_observed"
    RESOLVED = "resolved"
    AMBIGUOUS = "ambiguous"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class CarrierValueClassification:
    """Classification result for the return-carrier's source operand.

    Attributes:
        kind: The category of the source operand.
        const_value: Literal constant value if *kind* is ``CONST``.
        source_stkoff: Stack offset if *kind* is ``STACK_SLOT``.
        source_mreg: Micro-register number if *kind* is ``REGISTER``.
        materializer_sites: Exact block and instruction coordinates for the definition
            (relevant for ``EXPRESSION``, ``STACK_SLOT``, ``REGISTER``).
    """

    kind: CarrierValueKind
    const_value: int | None = None
    source_stkoff: int | None = None
    source_mreg: int | None = None
    materializer_sites: tuple[DefSiteLike, ...] = ()

    @property
    def materializer_serials(self) -> tuple[int, ...]:
        return tuple(site.block_serial for site in self.materializer_sites)


class ProofLayer(str, enum.Enum):
    """Which analysis layer resolved the return-carrier proof."""

    TOPOLOGY = "topology"
    "From preanalysis audit (has_rax_write field)."

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


@dataclass(frozen=True)
class DefSiteLike:
    """Lightweight definition site descriptor.

    Attributes:
        block_serial: Serial number of the block containing the definition.
        ins_ea: Effective address of the defining instruction.
        opcode: Microcode opcode of the defining instruction (None if unknown).
    """

    block_serial: int
    ins_ea: int
    opcode: Optional[int] = None

    def __post_init__(self) -> None:
        if type(self.block_serial) is not int or self.block_serial < 0:
            raise TypeError("definition block must be a non-negative integer")
        if type(self.ins_ea) is not int or not 0 < self.ins_ea < 0xFFFFFFFFFFFFFFFF:
            raise ValueError("definition requires a native instruction EA")
        if self.opcode is not None and type(self.opcode) is not int:
            raise TypeError("definition opcode must be an integer")


@dataclass(frozen=True)
class TerminalReturnValueProof:
    """Proof result for a single terminal handler's return-carrier definition.

    Attributes:
        handler_serial: Entry block serial of the terminal handler.
        carrier: Typed return register and byte width.
        def_sites: Where the carrier was defined (empty if unresolved).
        ambiguous: True if multiple conflicting definitions were found.
        topology_kind: The :class:`TerminalReturnSourceKind` value from the audit.
        proof_layer_used: Which analysis layer resolved the proof.
        notes: Free-form diagnostic note.
    """

    handler_serial: int
    carrier: ReturnCarrierRegister
    def_sites: tuple[DefSiteLike, ...]
    ambiguous: bool
    topology_kind: TerminalReturnSourceKind
    proof_layer_used: ProofLayer
    notes: str = ""
    value_kind: CarrierValueKind = CarrierValueKind.UNKNOWN
    const_value: int | None = None
    source_stkoff: int | None = None
    source_mreg: int | None = None
    materializer_sites: tuple[DefSiteLike, ...] = ()
    handler_ea: int | None = None

    def __post_init__(self) -> None:
        if type(self.carrier) is not ReturnCarrierRegister:
            raise TypeError("terminal proof requires a typed carrier register")
        if type(self.topology_kind) is not TerminalReturnSourceKind:
            raise TypeError("terminal topology must be a typed source kind")
        if (
            type(self.proof_layer_used) is not ProofLayer
            or type(self.ambiguous) is not bool
        ):
            raise TypeError(
                "terminal proof requires a typed layer and boolean ambiguity"
            )
        if type(self.value_kind) is not CarrierValueKind:
            raise TypeError("terminal value kind must be typed")
        for sites in (self.def_sites, self.materializer_sites):
            if type(sites) is not tuple or any(
                type(site) is not DefSiteLike for site in sites
            ):
                raise TypeError("terminal definitions require anchored sites")
            for site in sites:
                site.__post_init__()
        if (
            self.proof_layer_used not in (ProofLayer.UNRESOLVED, ProofLayer.TOPOLOGY)
            and not self.def_sites
        ):
            raise ValueError("a resolved analysis layer requires exact definitions")

    @property
    def carrier_kind(self) -> str:
        return f"mreg{self.carrier.micro_register}.{self.carrier.width}"

    @property
    def materializer_serials(self) -> tuple[int, ...]:
        return tuple(site.block_serial for site in self.materializer_sites)

    @property
    def status(self) -> TerminalReturnProofStatus:
        if self.proof_layer_used is ProofLayer.UNRESOLVED:
            return TerminalReturnProofStatus.UNRESOLVED
        if self.ambiguous:
            return TerminalReturnProofStatus.AMBIGUOUS
        if self.proof_layer_used is ProofLayer.TOPOLOGY:
            return TerminalReturnProofStatus.TOPOLOGY_OBSERVED
        return TerminalReturnProofStatus.RESOLVED


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
        topology = 0
        for p in self.proofs:
            if p.status is TerminalReturnProofStatus.UNRESOLVED:
                unresolved += 1
            elif p.status is TerminalReturnProofStatus.AMBIGUOUS:
                ambiguous += 1
            elif p.status is TerminalReturnProofStatus.TOPOLOGY_OBSERVED:
                topology += 1
            else:
                resolved += 1
        return (
            f"{len(self.proofs)} handlers: "
            f"{resolved} resolved, {ambiguous} ambiguous, {unresolved} unresolved, "
            f"{topology} topology-only"
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

    chain_defs = find_reaching_defs_for_reg(
        mba, return_block_serial, carrier_mreg, carrier_size
    )
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

    from d810.ir.lattice import BOTTOM
    from d810.evaluator.hexrays_microcode.forward_dataflow import (
        DefSite as RDDefSite,
        FixpointDidNotConverge,
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

    # Soundness gate: pass raise_on_nonconvergence=True so a partial
    # fixpoint (max_iterations exhausted with worklist still non-empty)
    # can never reach the OUT-read below.  Without this, reading
    # ``out_states[return_block]`` from a partial fixpoint can mis-resolve
    # the carrier and propagate unsound facts downstream.
    try:
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
            raise_on_nonconvergence=True,
        )
    except FixpointDidNotConverge as exc:
        logger.warning(
            "terminal_return_proof: reaching-defs fixpoint did not converge "
            "for handler=blk[%d] -> return=blk[%d] (iterations=%d, "
            "subgraph_size=%d); refusing to resolve carrier",
            handler_entry_serial,
            return_block_serial,
            exc.iterations,
            len(subgraph_nodes),
        )
        return (), False

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
# Value classification
# ---------------------------------------------------------------------------


def classify_carrier_value(
    mba: object,
    proof: TerminalReturnValueProof,
) -> CarrierValueClassification:
    """Classify the source operand of the defining instruction for the carrier.

    Inspects the first :class:`DefSiteLike` in *proof* to determine what kind
    of value flows into the return carrier (constant, stack slot, register, or
    complex expression).

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        proof: A proof with at least one resolved def site.

    Returns:
        A :class:`CarrierValueClassification` describing the source operand.
    """
    unknown = CarrierValueClassification(kind=CarrierValueKind.UNKNOWN)

    if not IDA_AVAILABLE:
        return unknown

    if not proof.def_sites or proof.ambiguous:
        return unknown

    def_site = proof.def_sites[0]

    # Find the block containing the definition.
    try:
        blk = mba.get_mblock(def_site.block_serial)  # type: ignore[attr-defined]
    except (AttributeError, IndexError):
        return unknown

    # Iterate instructions to find the one at ins_ea.
    ins = blk.head  # type: ignore[attr-defined]
    target_ins = None
    while ins:
        if getattr(ins, "ea", None) == def_site.ins_ea:
            target_ins = ins
            break
        ins = getattr(ins, "next", None)

    if target_ins is None:
        return unknown

    # For m_mov, the source is ins.l; for other opcodes the source operand
    # may differ, but we inspect ins.l as the most common case.
    src = getattr(target_ins, "l", None)
    if src is None:
        return unknown

    src_type = getattr(src, "t", None)
    if src_type is None:
        return unknown

    if src_type == ida_hexrays.mop_n:
        nnn = getattr(src, "nnn", None)
        val = getattr(nnn, "value", None) if nnn is not None else None
        return CarrierValueClassification(
            kind=CarrierValueKind.CONST,
            const_value=val,
        )

    if src_type == ida_hexrays.mop_S:
        stkvar = getattr(src, "s", None)
        off = getattr(stkvar, "off", None) if stkvar is not None else None
        return CarrierValueClassification(
            kind=CarrierValueKind.STACK_SLOT,
            source_stkoff=off,
            materializer_sites=(def_site,),
        )

    if src_type == ida_hexrays.mop_r:
        reg = getattr(src, "r", None)
        return CarrierValueClassification(
            kind=CarrierValueKind.REGISTER,
            source_mreg=reg,
            materializer_sites=(def_site,),
        )

    # Anything else (mop_d, mop_a, mop_b, etc.) is an expression.
    return CarrierValueClassification(
        kind=CarrierValueKind.EXPRESSION,
        materializer_sites=(def_site,),
    )


def _enrich_proof_with_classification(
    mba: object,
    proof: TerminalReturnValueProof,
) -> TerminalReturnValueProof:
    """Merge carrier value classification into an existing proof.

    If the proof is UNRESOLVED or has no def sites, returns it unchanged.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        proof: The proof to enrich.

    Returns:
        A new :class:`TerminalReturnValueProof` with value classification fields set.
    """
    if proof.proof_layer_used == ProofLayer.UNRESOLVED or not proof.def_sites:
        return proof

    cls = classify_carrier_value(mba, proof)

    # Reconstruct with classification fields via dataclass replace.
    return replace(
        proof,
        value_kind=cls.kind,
        const_value=cls.const_value,
        source_stkoff=cls.source_stkoff,
        source_mreg=cls.source_mreg,
        materializer_sites=cls.materializer_sites,
    )


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

# Default carrier: rax micro-register number.
# IDA's mr_rax = 0 for 64-bit code. Callers can override.
_DEFAULT_CARRIER_MREG: int = 0


def _rebind_audit_site(
    mba: object, site: TerminalReturnSiteAudit
) -> TerminalReturnSiteAudit | None:
    """Resolve audit anchors uniquely; pre-mutation serials are diagnostics."""
    if site.handler_ea is None or site.return_ea is None:
        return None
    try:
        by_ea: dict[int, list[int]] = {}
        for serial in range(int(mba.qty)):
            block = mba.get_mblock(serial)
            by_ea.setdefault(int(block.start), []).append(serial)
        handlers = by_ea.get(site.handler_ea, ())
        returns = by_ea.get(site.return_ea, ())
        if len(handlers) != 1 or len(returns) != 1:
            return None
        return replace(site, handler_serial=handlers[0], return_block_serial=returns[0])
    except (AttributeError, IndexError, TypeError, ValueError):
        return None


def prove_terminal_returns(
    mba: object,
    audit_report: TerminalReturnAuditReport,
    *,
    carrier_mreg: int = _DEFAULT_CARRIER_MREG,
    carrier_size: int = 8,
) -> TerminalReturnProofReport:
    "Orchestrate layered proof for all terminal return handlers.\n\n    For each site in *audit_report*, run progressively heavier analysis\n    layers until one resolves or all are exhausted.\n\n    Args:\n        mba: An ``ida_hexrays.mba_t`` instance (or ``None`` for topology-only).\n        audit_report: The terminal return audit from preanalysis.\n        carrier_mreg: Micro-register number for the return carrier (default: mr_rax=0).\n        carrier_size: Operand size in bytes for the return carrier (default: 8).\n\n    Returns:\n        A :class:`TerminalReturnProofReport` with per-handler proof results.\n"
    carrier = ReturnCarrierRegister(carrier_mreg, carrier_size)
    proofs: list[TerminalReturnValueProof] = []

    for site in audit_report.sites:
        current_mba = mba
        current_site = site
        if mba is not None:
            rebound = (
                _rebind_audit_site(mba, site)
                if getattr(mba, "entry_ea", None) == audit_report.function_ea
                else None
            )
            if rebound is None:
                current_mba = None
            else:
                current_site = rebound
        proof = _prove_single_site(
            current_mba,
            current_site,
            carrier_mreg=carrier_mreg,
            carrier_size=carrier_size,
            carrier=carrier,
        )
        proof = replace(proof, handler_ea=site.handler_ea)
        proof = _enrich_proof_with_classification(current_mba, proof)
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
    carrier: ReturnCarrierRegister,
) -> TerminalReturnValueProof:
    "Run the layered proof for a single terminal handler site.\n\n    Args:\n        mba: An ``ida_hexrays.mba_t`` instance (or ``None`` for topology-only).\n        site: A single audit site from the preanalysis report.\n        carrier_mreg: Micro-register number for the return carrier.\n        carrier_size: Operand size in bytes.\n        carrier_kind: Human-readable carrier description.\n\n    Returns:\n        A :class:`TerminalReturnValueProof` for this handler.\n"
    # --- Layer 1: Topology ---
    try:
        if (
            site.has_rax_write is True
            and site.source_kind == TerminalReturnSourceKind.DIRECT_RETURN
        ):
            return TerminalReturnValueProof(
                handler_serial=site.handler_serial,
                carrier=carrier,
                def_sites=(),
                ambiguous=False,
                topology_kind=site.source_kind,
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
                mba,
                site.return_block_serial,
                carrier_mreg,
                carrier_size,
            )
            if def_site is not None:
                return TerminalReturnValueProof(
                    handler_serial=site.handler_serial,
                    carrier=carrier,
                    def_sites=(def_site,),
                    ambiguous=False,
                    topology_kind=site.source_kind,
                    proof_layer_used=ProofLayer.SINGLE_PRED_WALK,
                    notes=f"single-pred walk found def at blk{def_site.block_serial}@{def_site.ins_ea:#x}",
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
                mba,
                site.return_block_serial,
                carrier_mreg,
                carrier_size,
            )
            if chain_sites:
                return TerminalReturnValueProof(
                    handler_serial=site.handler_serial,
                    carrier=carrier,
                    def_sites=chain_sites,
                    ambiguous=chain_ambiguous,
                    topology_kind=site.source_kind,
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
                    carrier=carrier,
                    def_sites=rd_sites,
                    ambiguous=rd_ambiguous,
                    topology_kind=site.source_kind,
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
        carrier=carrier,
        def_sites=(),
        ambiguous=False,
        topology_kind=site.source_kind,
        proof_layer_used=ProofLayer.UNRESOLVED,
        notes="no layer could resolve",
    )


__all__ = [
    "ReturnCarrierRegister",
    "TerminalReturnProofStatus",
    "CarrierValueClassification",
    "CarrierValueKind",
    "DefSiteLike",
    "ProofLayer",
    "TerminalReturnProofReport",
    "TerminalReturnValueProof",
    "classify_carrier_value",
    "prove_terminal_returns",
]

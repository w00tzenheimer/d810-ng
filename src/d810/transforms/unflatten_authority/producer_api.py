"""Producer-side, serial-free inputs for unflatten authority.

The producer is deliberately a small adapter layer.  It consumes the complete
portable source graph, the exact identity-index export for that graph, and one
canonical route-evidence object.  It does not inspect metadata, attach a
proposal, or invoke transaction code.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
)
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.flowgraph import BlockKind, FlowGraph, InsnKind
from d810.ir.semantics import ControlTransferKind
from d810.ir.storage_identity import StorageIdentity
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef
from d810.transforms.use_def_redirect_filter import UseDefSeveranceAudit

from .model import (
    AuthoritativeHandlerInput,
    EffectSiteKind,
    EffectSubjectLocator,
    SourceBlockIdentityWitness,
    SourceIdentityCatalog,
    TerminalKind,
    TerminalSubjectLocator,
    UnflattenPlanInputCatalog,
    UnflattenPlanShape,
    UseDefFragmentWitness,
    BlockSubjectLocator,
)


_BADADDR = 0xFFFFFFFFFFFFFFFF
AuthorityBlockRef = NativeBlockRef | LogicalBlockRef


@dataclass(frozen=True, slots=True)
class DiscoveredEffect:
    """One reachable effect site with its exact serial-free locator."""

    locator: EffectSubjectLocator

    @property
    def effect_kind(self) -> EffectSiteKind:
        return self.locator.effect_kind


@dataclass(frozen=True, slots=True)
class DiscoveredTerminal:
    """One reachable terminal site with its exact serial-free locator."""

    locator: TerminalSubjectLocator

    @property
    def terminal_kind(self) -> TerminalKind:
        return self.locator.terminal_kind


@dataclass(frozen=True, slots=True)
class SourceEffectTerminalCatalog:
    """The disjoint reachable effect and terminal discovery result."""

    effects: tuple[DiscoveredEffect, ...]
    terminals: tuple[DiscoveredTerminal, ...]

    def __iter__(self):
        yield self.effects
        yield self.terminals


def _valid_ea(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < _BADADDR


def _as_serial(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative serial")
    return int(value)


def _native_instruction_origins(block: object) -> tuple[int, ...]:
    instructions = tuple(getattr(block, "insn_snapshots", ()))
    origins: list[int] = []
    for instruction in instructions:
        native_ea = getattr(instruction, "native_ea", None)
        ea = native_ea if _valid_ea(native_ea) else getattr(instruction, "ea", None)
        if not _valid_ea(ea):
            raise ValueError("source instruction has no valid native origin")
        origins.append(int(ea))
    if not origins:
        raise ValueError("source block has empty native origins")
    if len(set(origins)) != len(origins):
        raise ValueError("source block has duplicate native origins")
    return tuple(sorted(origins))


def _block_anchor(block: object, origins: tuple[int, ...]) -> int:
    anchor = getattr(block, "native_start_ea", None)
    if not _valid_ea(anchor):
        anchor = getattr(block, "start_ea", None)
    if not _valid_ea(anchor) or int(anchor) not in origins:
        raise ValueError("source block anchor is invalid or outside native origins")
    return int(anchor)


def _require_ref(ref: object, label: str = "block_ref") -> AuthorityBlockRef:
    if type(ref) not in (NativeBlockRef, LogicalBlockRef):
        raise TypeError(f"{label} must be a NativeBlockRef or LogicalBlockRef")
    return ref  # type: ignore[return-value]


def _catalog_ref_by_serial(
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
) -> dict[int, SourceBlockIdentityWitness]:
    expected = {_as_serial(serial, "source serial") for serial in source.blocks}
    actual = {_as_serial(serial, "source serial") for serial in block_refs_by_serial}
    if actual != expected:
        raise ValueError("block_refs_by_serial must exactly cover the source graph")
    witnesses = tuple(source_catalog.blocks)
    refs = tuple(block_refs_by_serial[serial] for serial in sorted(expected))
    if any(source.blocks[serial].serial != serial for serial in sorted(expected)):
        raise ValueError("source block serial does not match mapping key")
    if any(type(ref) not in (NativeBlockRef, LogicalBlockRef) for ref in refs):
        raise TypeError("block_refs_by_serial contains an invalid block reference")
    by_ref = {witness.block_ref: witness for witness in witnesses}
    if len(by_ref) != len(witnesses) or set(by_ref) != set(refs):
        raise ValueError("source catalog does not exactly cover block references")
    return {serial: by_ref[block_refs_by_serial[serial]] for serial in sorted(expected)}


def build_source_identity_catalog(
    source: FlowGraph,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    *,
    native_key: NativePreanalysisKey | None = None,
    source_generation: int | None = None,
    canonical_route_evidence: CanonicalSemanticEvidence | None = None,
) -> SourceIdentityCatalog:
    """Build one complete source catalog without exposing graph serials."""

    if type(source) is not FlowGraph:
        raise TypeError("source must be a FlowGraph")
    if canonical_route_evidence is not None:
        if type(canonical_route_evidence) is not CanonicalSemanticEvidence:
            raise TypeError("canonical_route_evidence must be CanonicalSemanticEvidence")
        if native_key is not None and native_key != canonical_route_evidence.native_key:
            raise ValueError("source native key disagrees with canonical route evidence")
        native_key = canonical_route_evidence.native_key
        if source_generation is not None and source_generation != canonical_route_evidence.generation:
            raise ValueError("source generation is stale relative to canonical route evidence")
        source_generation = canonical_route_evidence.generation
    if type(native_key) is not NativePreanalysisKey:
        raise TypeError("native_key is required for source identity catalog")
    if source_generation is None or isinstance(source_generation, bool) or not isinstance(source_generation, int) or source_generation < 0:
        raise ValueError("source_generation must be a non-negative integer")

    if not source.blocks:
        raise ValueError("source graph must contain at least one block")
    serials = {_as_serial(serial, "source serial") for serial in source.blocks}
    ref_serials = {_as_serial(serial, "source serial") for serial in block_refs_by_serial}
    if serials != ref_serials:
        raise ValueError("block_refs_by_serial must exactly cover the source graph")
    refs = tuple(_require_ref(block_refs_by_serial[serial]) for serial in sorted(serials))
    if len(set(refs)) != len(refs):
        raise ValueError("source block references must be unique")

    witnesses: list[SourceBlockIdentityWitness] = []
    all_origins: set[int] = set()
    anchors: set[int] = set()
    for serial in sorted(serials):
        block = source.blocks[serial]
        if block.serial != serial:
            raise ValueError("source block serial does not match mapping key")
        origins = _native_instruction_origins(block)
        anchor = _block_anchor(block, origins)
        if anchor in anchors:
            raise ValueError("source block anchors must be unique")
        if all_origins.intersection(origins):
            raise ValueError("source native instruction origins must be unique")
        ref = refs[sorted(serials).index(serial)]
        if type(ref) is NativeBlockRef:
            if ref.identity.native_key != native_key:
                raise ValueError("native source reference key does not match catalog key")
            if set(ref.identity.exact_instruction_eas) != set(origins):
                raise ValueError("native source reference origins do not match source block")
            if not ref.identity.native_ranges.contains(anchor):
                raise ValueError("source anchor is outside native reference range")
        witnesses.append(
            SourceBlockIdentityWitness(
                block_ref=ref,
                anchor_ea=anchor,
                native_instruction_eas=origins,
            )
        )
        anchors.add(anchor)
        all_origins.update(origins)
    return SourceIdentityCatalog(native_key=native_key, generation=source_generation, blocks=tuple(witnesses))


def _witness_for_serial(
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    serial: object,
) -> SourceBlockIdentityWitness:
    serial_int = _as_serial(serial, "block serial")
    if serial_int not in source.blocks or serial_int not in block_refs_by_serial:
        raise ValueError("block serial is absent from source catalog")
    by_ref = {item.block_ref: item for item in source_catalog.blocks}
    try:
        return by_ref[block_refs_by_serial[serial_int]]
    except KeyError as exc:
        raise ValueError("block serial reference is absent from source catalog") from exc


def resolve_block_locator(
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    serial: int,
    anchor_ea: int,
) -> BlockSubjectLocator:
    """Resolve an exact serial/EA pair; never invent a logical reference."""

    witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, serial)
    if not _valid_ea(anchor_ea) or int(anchor_ea) not in witness.native_instruction_eas:
        raise ValueError("block anchor is absent from source native origins")
    return BlockSubjectLocator(witness.block_ref, int(anchor_ea))


def resolve_effect_locator(
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    serial: int,
    instruction_ea: int,
    effect_kind: EffectSiteKind,
) -> EffectSubjectLocator:
    witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, serial)
    if not _valid_ea(instruction_ea) or int(instruction_ea) not in witness.native_instruction_eas:
        raise ValueError("effect instruction anchor is absent from source native origins")
    return EffectSubjectLocator(witness.block_ref, witness.anchor_ea, int(instruction_ea), effect_kind)


def resolve_terminal_locator(
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    serial: int,
    instruction_ea: int,
    terminal_kind: TerminalKind,
) -> TerminalSubjectLocator:
    witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, serial)
    if not _valid_ea(instruction_ea) or int(instruction_ea) not in witness.native_instruction_eas:
        raise ValueError("terminal instruction anchor is absent from source native origins")
    return TerminalSubjectLocator(witness.block_ref, witness.anchor_ea, terminal_kind, int(instruction_ea))


def _destination_matches_witness(destination: object, witness: SourceBlockIdentityWitness, native_key: NativePreanalysisKey) -> bool:
    target_identity = getattr(destination, "target_identity", None)
    target_anchor = getattr(destination, "target_anchor_ea", None)
    if target_identity is None or target_identity.native_key != native_key:
        return False
    if target_anchor not in witness.native_instruction_eas:
        return False
    if type(witness.block_ref) is NativeBlockRef:
        return target_identity == witness.block_ref.identity
    return True


def build_unflatten_plan_input_catalog(
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef] | None = None,
    canonical_route_evidence: CanonicalSemanticEvidence | None,
    source_entry_serial: int,
    dispatcher_entry_serial: int,
    dispatcher_member_serials: Iterable[int],
    authoritative_handler_serials: Iterable[int],
    state_identity: StorageIdentity,
    shape: UnflattenPlanShape | str,
) -> UnflattenPlanInputCatalog:
    """Lift only the explicit plan serial inputs into typed refs."""

    if type(source) is not FlowGraph or type(source_catalog) is not SourceIdentityCatalog:
        raise TypeError("source and source_catalog are required")
    if type(canonical_route_evidence) is not CanonicalSemanticEvidence:
        raise ValueError("canonical route evidence is required")
    if source_catalog.native_key != canonical_route_evidence.native_key or source_catalog.generation != canonical_route_evidence.generation:
        raise ValueError("source catalog is stale relative to canonical route evidence")
    if type(state_identity) is not StorageIdentity:
        raise TypeError("state_identity must be a StorageIdentity")
    if block_refs_by_serial is None:
        raise ValueError("block_refs_by_serial is required")
    _catalog_ref_by_serial(source, source_catalog, block_refs_by_serial)
    shape_value = shape if isinstance(shape, UnflattenPlanShape) else UnflattenPlanShape(shape)
    raw_members = tuple(_as_serial(serial, "dispatcher member serial") for serial in dispatcher_member_serials)
    if len(set(raw_members)) != len(raw_members):
        raise ValueError("dispatcher_member_serials must not contain duplicates")
    members = tuple(sorted(raw_members))
    raw_handlers = tuple(_as_serial(serial, "authoritative_handler_serials item") for serial in authoritative_handler_serials)
    if len(set(raw_handlers)) != len(raw_handlers):
        raise ValueError("authoritative_handler_serials must not contain duplicates")
    handlers = tuple(sorted(raw_handlers))
    dispatcher_entry = _as_serial(dispatcher_entry_serial, "dispatcher entry serial")
    source_entry = _as_serial(source_entry_serial, "source entry serial")
    if source_entry != int(source.entry_serial):
        raise ValueError("source_entry_serial must equal FlowGraph.entry_serial")
    if dispatcher_entry not in members:
        raise ValueError("dispatcher_member_serials must include dispatcher entry")
    source_entry_witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, source_entry)
    dispatcher_witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, dispatcher_entry)
    member_refs = tuple(_witness_for_serial(source, source_catalog, block_refs_by_serial, serial).block_ref for serial in members)

    authoritative_inputs: list[AuthoritativeHandlerInput] = []
    for serial in handlers:
        try:
            witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, serial)
        except ValueError as exc:
            raise ValueError("authoritative_handler_serials contains an unknown serial") from exc
        state_to_anchors: dict[int, set[int]] = {}
        for proof in canonical_route_evidence.route_proofs:
            for destination in proof.destinations:
                if _destination_matches_witness(destination, witness, canonical_route_evidence.native_key):
                    proof_state_identities = tuple(
                        identity
                        for identity in (
                            getattr(getattr(proof, "state_write", None), "state_variable", None),
                            getattr(getattr(proof, "predicate", None), "storage_identity", None),
                        )
                        if identity is not None
                    )
                    if any(identity != state_identity for identity in proof_state_identities):
                        raise ValueError("canonical route state identity disagrees with plan input")
                    state_to_anchors.setdefault(int(destination.state_constant), set()).add(int(destination.target_anchor_ea))
        if not state_to_anchors:
            raise ValueError("authoritative handler has no canonical route destination")
        if any(len(anchors) != 1 for anchors in state_to_anchors.values()):
            raise ValueError("authoritative handler route state is ambiguous")
        authoritative_inputs.append(
            AuthoritativeHandlerInput(
                block_ref=witness.block_ref,
                anchor_ea=witness.anchor_ea,
                normalized_states=tuple(sorted(state_to_anchors)),
            )
        )

    return UnflattenPlanInputCatalog(
        shape=shape_value,
        source_entry_ref=source_entry_witness.block_ref,
        dispatcher_entry_ref=dispatcher_witness.block_ref,
        dispatcher_member_refs=member_refs,
        authoritative_handlers=tuple(authoritative_inputs),
        state_identity=state_identity,
    )


def discover_reachable_effects_and_terminals(
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
) -> SourceEffectTerminalCatalog:
    """Discover the exact, disjoint Section 15.3 effect/terminal inventory."""

    _catalog_ref_by_serial(source, source_catalog, block_refs_by_serial)
    reachable: list[int] = []
    pending = deque([int(source.entry_serial)])
    seen: set[int] = set()
    while pending:
        serial = pending.popleft()
        if serial in seen:
            continue
        if serial not in source.blocks:
            raise ValueError("reachable source successor is absent from source graph")
        seen.add(serial)
        reachable.append(serial)
        pending.extend(sorted(int(succ) for succ in source.blocks[serial].succs))

    effects: list[DiscoveredEffect] = []
    terminals: list[DiscoveredTerminal] = []
    effect_keys: set[tuple[AuthorityBlockRef, int, EffectSiteKind]] = set()
    terminal_keys: set[tuple[AuthorityBlockRef, int, TerminalKind]] = set()
    for serial in reachable:
        block = source.blocks[serial]
        witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, serial)
        tail_terminal_produced = False
        for ordinal, insn in enumerate(block.insn_snapshots):
            native_ea = getattr(insn, "native_ea", None)
            native_ea = native_ea if _valid_ea(native_ea) else getattr(insn, "ea", None)
            kind = getattr(insn, "kind", InsnKind.UNKNOWN)
            transfer = getattr(insn, "control_transfer_kind", None)
            is_call = kind is InsnKind.CALL or bool(getattr(insn, "is_call", False)) or getattr(insn, "call_kind", None) is not None
            is_return = kind is InsnKind.RET or transfer is ControlTransferKind.RETURN
            is_trap = kind is InsnKind.TRAP
            is_store = kind is InsnKind.STORE
            matching = sum((bool(is_store), bool(is_trap), bool(is_return), bool(is_call)))
            if matching > 1:
                raise ValueError("InsnSnapshot effect semantics overlap")
            if matching == 0:
                continue
            if not _valid_ea(native_ea):
                raise ValueError("required effect has no valid native instruction EA")
            instruction_ea = int(native_ea)
            effect_kind = (EffectSiteKind.STORE if is_store else EffectSiteKind.TRAP if is_trap else EffectSiteKind.RETURN if is_return else EffectSiteKind.CALL)
            effect_key = (witness.block_ref, instruction_ea, effect_kind)
            if effect_key in effect_keys:
                raise ValueError("duplicate reachable effect site")
            effect_keys.add(effect_key)
            effects.append(DiscoveredEffect(resolve_effect_locator(source, source_catalog, block_refs_by_serial, serial, instruction_ea, effect_kind)))
            terminal_kind: TerminalKind | None = None
            if is_trap:
                terminal_kind = TerminalKind.TRAP
            elif is_return:
                terminal_kind = TerminalKind.RETURN
            elif is_call and ordinal == len(block.insn_snapshots) - 1 and not block.succs:
                terminal_kind = TerminalKind.NORETURN_CALL
            if terminal_kind is not None:
                if ordinal == len(block.insn_snapshots) - 1:
                    tail_terminal_produced = True
                terminal_key = (witness.block_ref, instruction_ea, terminal_kind)
                if terminal_key in terminal_keys:
                    raise ValueError("duplicate reachable terminal site")
                terminal_keys.add(terminal_key)
                terminals.append(DiscoveredTerminal(resolve_terminal_locator(source, source_catalog, block_refs_by_serial, serial, instruction_ea, terminal_kind)))
        if block.kind is BlockKind.STOP and not tail_terminal_produced:
            terminal_key = (witness.block_ref, witness.anchor_ea, TerminalKind.STOP)
            if terminal_key in terminal_keys:
                raise ValueError("duplicate reachable STOP terminal site")
            terminal_keys.add(terminal_key)
            terminals.append(DiscoveredTerminal(resolve_terminal_locator(source, source_catalog, block_refs_by_serial, serial, witness.anchor_ea, TerminalKind.STOP)))
    return SourceEffectTerminalCatalog(tuple(effects), tuple(terminals))


def build_use_def_fragment_witness(
    audit: UseDefSeveranceAudit,
    *,
    fragment_id: str,
    state_identity: StorageIdentity,
    redirect_owner_refs: Iterable[object] = (),
    redirect_digest: str | None = None,
) -> UseDefFragmentWitness | None:
    """Convert only a clean executed audit into authoritative witness input."""

    if type(audit) is not UseDefSeveranceAudit or not audit.clean:
        return None
    refs = tuple(redirect_owner_refs)
    if redirect_digest is None:
        payload = repr(tuple(refs)).encode("utf-8")
        redirect_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if audit.violations:
        return None
    violations: tuple[str, ...] = ()
    return UseDefFragmentWitness(
        fragment_id=fragment_id,
        state_identity=state_identity,
        redirect_owner_refs=refs,
        redirect_digest=redirect_digest,
        executed=True,
        fragment_atomic=True,
        actionable_non_state_severance_count=0,
        violation_ids=violations,
    )


__all__ = [
    "DiscoveredEffect",
    "DiscoveredTerminal",
    "SourceEffectTerminalCatalog",
    "build_source_identity_catalog",
    "build_unflatten_plan_input_catalog",
    "build_use_def_fragment_witness",
    "discover_reachable_effects_and_terminals",
    "resolve_block_locator",
    "resolve_effect_locator",
    "resolve_terminal_locator",
]

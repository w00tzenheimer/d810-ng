"""Materialize a proven detached handler as a verifier-valid microcode island."""

from __future__ import annotations

from dataclasses import dataclass, replace

import ida_bytes
import ida_frame
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_idp
import ida_range
import ida_ua
import idautils

from d810.core.typing import Callable, Collection, Mapping

from d810.analyses.control_flow.detached_handler_island import (
    AppliedDetachedSnippetConditionalBoundaryPort,
    AppliedDetachedSnippetDirectBoundaryPort,
    DetachedHandlerIslandPlan,
    DetachedSnippetBoundaryPortOwner,
    DetachedSnippetBoundaryPorts,
    DetachedSnippetConditionalBoundaryPort,
    DetachedSnippetDirectBoundaryPort,
    DetachedSnippetReplacementEvidence,
    normalize_detached_snippet_boundary_ports,
    select_unique_block_native_ea,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    TerminalReturnCarrierRequest,
)
from d810.core.logging import getLogger
from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
from d810.hexrays.mutation.cfg_verify import (
    clear_owned_fake_block_registrations,
    register_owned_fake_block,
    safe_verify,
)

logger = getLogger("D810.mutation.detached_handler_island")
_MISSING_BOUNDARY_PORT_SERIAL = object()


def stable_mba_identity(mba: object) -> int:
    """Return the underlying mba_t address, stable across SWIG proxy wrappers."""
    try:
        return int(mba.this)
    except (AttributeError, TypeError, ValueError):
        return id(mba)


def _normalize_template_ida_stkoff(
    function_ea: int,
    mba: object,
    ida_stkoff: int,
) -> int:
    """Convert a fragment-local negative stack offset to function identity."""
    value = int(ida_stkoff)
    if value >= 0:
        return value
    function = ida_funcs.get_func(int(function_ea))
    persistent_frame_size = (
        int(function.frsize) + int(function.frregs)
        if function is not None
        else int(mba.frsize) + int(mba.frregs)
    )
    normalized = value + persistent_frame_size
    return normalized if persistent_frame_size > 0 and normalized >= 0 else value


def _native_instruction_stack_frame_offsets(
    function_ea: int,
    instruction_ea: int,
) -> tuple[int, ...]:
    """Return IDA-frame identities proven by one native instruction.

    A detached explicit-range MBA can choose a different ``tmpstk_size`` from
    the owning function.  Its ``mop_S`` VD offset is therefore not a stable
    identity.  IDA's native stack-variable annotation is authoritative when
    present.  Resolver-owned detached tails are often not annotated, so an
    ESP/RSP displacement is projected through IDA's native SP delta and the
    owning function frame size as an equally stable fallback.
    """
    function = ida_funcs.get_func(int(function_ea))
    if function is None:
        return ()
    instruction = ida_ua.insn_t()
    native_ea = int(instruction_ea)
    if ida_ua.decode_insn(instruction, native_ea) <= 0:
        return ()
    flags = ida_bytes.get_flags(native_ea)
    offsets: list[int] = []
    pointer_size = 8 if ida_ida.inf_is_64bit() else 4
    displacement_bits = pointer_size * 8
    displacement_mask = (1 << displacement_bits) - 1
    displacement_sign = 1 << (displacement_bits - 1)
    persistent_frame_size = int(function.frsize) + int(function.frregs)
    for operand_index, operand in enumerate(instruction.ops):
        if int(operand.type) == int(ida_ua.o_void):
            break
        annotated_frame_offset: int | None = None
        if ida_bytes.is_stkvar(flags, operand_index):
            frame_offset = int(
                ida_frame.calc_stkvar_struc_offset(
                    function,
                    instruction,
                    operand_index,
                )
            )
            if frame_offset != int(ida_idaapi.BADADDR):
                annotated_frame_offset = frame_offset
        if int(operand.type) not in {
            int(ida_ua.o_displ),
            int(ida_ua.o_phrase),
        }:
            if annotated_frame_offset is not None:
                offsets.append(annotated_frame_offset)
            continue
        register_name = ida_idp.get_reg_name(int(operand.reg), pointer_size)
        if str(register_name or "").lower() not in {"sp", "esp", "rsp"}:
            if annotated_frame_offset is not None:
                offsets.append(annotated_frame_offset)
            continue
        raw_displacement = (
            int(operand.addr) & displacement_mask
            if int(operand.type) == int(ida_ua.o_displ)
            else 0
        )
        displacement = (
            raw_displacement - (1 << displacement_bits)
            if raw_displacement & displacement_sign
            else raw_displacement
        )
        try:
            stack_pointer_delta = int(ida_frame.get_spd(function, native_ea))
        except Exception:
            if annotated_frame_offset is not None:
                offsets.append(annotated_frame_offset)
            continue
        frame_offset = persistent_frame_size + stack_pointer_delta + displacement
        if frame_offset >= 0:
            offsets.append(frame_offset)
        elif annotated_frame_offset is not None:
            offsets.append(annotated_frame_offset)
    return tuple(dict.fromkeys(offsets))


def native_stack_frame_offsets_for_ranges(
    function_ea: int,
    ranges: Collection[tuple[int, int]],
) -> dict[int, tuple[int, ...]]:
    """Capture native stack identities before explicit-range generation.

    Hex-Rays may transiently annotate a detached range as a standalone
    function while generating its MBA.  Snapshot the owning function's SP
    coordinate first so those temporary annotations cannot replace it.
    """
    result: dict[int, tuple[int, ...]] = {}
    for start_ea, end_ea in ranges:
        for instruction_ea in idautils.Heads(int(start_ea), int(end_ea)):
            if not ida_bytes.is_code(ida_bytes.get_flags(int(instruction_ea))):
                continue
            offsets = _native_instruction_stack_frame_offsets(
                int(function_ea),
                int(instruction_ea),
            )
            if offsets:
                result[int(instruction_ea)] = offsets
    return result


def _instructions(block: object) -> tuple[object, ...]:
    result: list[object] = []
    instruction = block.head
    while instruction is not None:
        result.append(instruction)
        if instruction is block.tail:
            break
        instruction = instruction.next
    return tuple(result)


def _remove_all_instructions(
    modifier: DeferredGraphModifier,
    block: object,
) -> None:
    modifier.remove_all_instructions_now(block)


def _remove_nops(modifier: DeferredGraphModifier, block: object) -> None:
    modifier.remove_nops_now(block)


def _blocks_containing_ea(mba: object, ea: int) -> tuple[object, ...]:
    matches: list[object] = []
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        if int(block.start) == int(ea) or any(
            int(instruction.ea) == int(ea) for instruction in _instructions(block)
        ):
            matches.append(block)
    return tuple(matches)


def find_unique_live_block_by_ea(
    mba: object,
    ea: int,
    *,
    exact_instruction_ea: int | None = None,
) -> object | None:
    if exact_instruction_ea is not None:
        matches = tuple(
            block
            for serial in range(int(mba.qty))
            for block in (mba.get_mblock(serial),)
            if any(
                int(instruction.ea) == int(exact_instruction_ea)
                for instruction in _instructions(block)
            )
        )
        return matches[0] if len(matches) == 1 else None
    imported_root = _IMPORTED_SNIPPET_ROOTS.get((stable_mba_identity(mba), int(ea)))
    if imported_root is not None:
        serial_hint = int(imported_root.serial_hint)
        if 0 <= serial_hint < int(mba.qty):
            hinted = mba.get_mblock(serial_hint)
            if any(
                int(instruction.ea) in imported_root.anchor_eas
                for instruction in _instructions(hinted)
            ):
                return hinted
        for anchor_ea in imported_root.anchor_eas:
            relocated = _blocks_containing_ea(mba, int(anchor_ea))
            if len(relocated) == 1:
                imported_root.serial_hint = int(relocated[0].serial)
                return relocated[0]
        identity = stable_mba_identity(mba)
        surviving_origins: list[tuple[int, int, object]] = []
        for imported_ea in imported_root.owned_instruction_eas:
            native_ea = _IMPORTED_INSTRUCTION_ORIGINS.get((identity, int(imported_ea)))
            if native_ea is None:
                continue
            relocated = _blocks_containing_ea(mba, int(imported_ea))
            if len(relocated) == 1:
                surviving_origins.append(
                    (int(native_ea), int(imported_ea), relocated[0])
                )
        if surviving_origins:
            first_native_ea = min(row[0] for row in surviving_origins)
            first_blocks = {
                int(block.serial): block
                for native_ea, _imported_ea, block in surviving_origins
                if int(native_ea) == int(first_native_ea)
            }
            if len(first_blocks) == 1:
                relocated = next(iter(first_blocks.values()))
                imported_root.serial_hint = int(relocated.serial)
                return relocated
        return None
    matches = _blocks_containing_ea(mba, int(ea))
    return matches[0] if len(matches) == 1 else None


def imported_detached_snippet_target_eas(mba: object) -> tuple[int, ...]:
    """Return imported root EAs owned by the current underlying mba_t."""
    identity = stable_mba_identity(mba)
    return tuple(
        sorted(
            int(target_ea)
            for (mba_identity, target_ea) in _IMPORTED_SNIPPET_ROOTS
            if int(mba_identity) == int(identity)
        )
    )


def imported_detached_snippet_conditional_boundary_evidence(
    mba: object,
) -> tuple[AppliedDetachedSnippetConditionalBoundaryPort, ...]:
    """Return exact conditional ports successfully applied to this MBA.

    Template capture alone is not evidence that a port reached the live graph.
    The registry is populated only after the complete boundary-port batch has
    applied and the imported roots have passed their anchor checks.
    """
    evidence_rows = _IMPORTED_CONDITIONAL_BOUNDARY_EVIDENCE.get(
        stable_mba_identity(mba),
        (),
    )

    def live_anchors(target_ea: int, fallback: tuple[int, ...]) -> tuple[int, ...]:
        target = find_unique_live_block_by_ea(mba, int(target_ea))
        if target is None:
            return fallback
        anchors = tuple(
            dict.fromkeys(
                int(instruction.ea)
                for instruction in _instructions(target)
                if int(instruction.ea) > 0
            )
        )
        return anchors or fallback

    return tuple(
        replace(
            evidence,
            taken_target_anchor_eas=live_anchors(
                evidence.port.taken_target_ea,
                evidence.taken_target_anchor_eas,
            ),
            fallthrough_target_anchor_eas=live_anchors(
                evidence.port.fallthrough_target_ea,
                evidence.fallthrough_target_anchor_eas,
            ),
        )
        for evidence in evidence_rows
    )


def imported_detached_snippet_direct_boundary_evidence(
    mba: object,
) -> tuple[AppliedDetachedSnippetDirectBoundaryPort, ...]:
    """Return exact direct ports successfully applied to this MBA.

    A surviving imported instruction anchor is preferred over native-EA
    lookup because PREOPT import reanchors instructions to fictitious EAs.
    Target-root lineage is the fallback when CALLS merged the original target
    block but retained another instruction owned by that imported root.
    """
    evidence_rows = _IMPORTED_DIRECT_BOUNDARY_EVIDENCE.get(
        stable_mba_identity(mba),
        (),
    )

    def live_anchors(native_ea: int, fallback: tuple[int, ...]) -> tuple[int, ...]:
        anchor_blocks = {
            int(block.serial): block
            for anchor_ea in fallback
            for block in _blocks_containing_ea(mba, int(anchor_ea))
        }
        block = (
            next(iter(anchor_blocks.values()))
            if len(anchor_blocks) == 1
            else find_unique_live_block_by_ea(mba, int(native_ea))
        )
        if block is None:
            return fallback
        anchors = tuple(
            dict.fromkeys(
                int(instruction.ea)
                for instruction in _instructions(block)
                if int(instruction.ea) > 0
            )
        )
        return anchors or fallback

    return tuple(
        replace(
            evidence,
            endpoint_anchor_eas=live_anchors(
                evidence.port.endpoint_block_ea,
                evidence.endpoint_anchor_eas,
            ),
            target_anchor_eas=live_anchors(
                evidence.port.target_ea,
                evidence.target_anchor_eas,
            ),
        )
        for evidence in evidence_rows
    )


@dataclass(frozen=True, slots=True)
class _CallTemplate:
    instruction: object
    argument_size: int


@dataclass(frozen=True, slots=True)
class _AnalyzedCallReplacement:
    instruction: object
    call_opcode: int


@dataclass(frozen=True, slots=True)
class _AnalyzedCallResultDefinition:
    call_ea: int
    call_opcode: int
    callee_ea: int | None
    result_mreg: int
    result_size: int


@dataclass(frozen=True, slots=True)
class CallResultCarrier:
    call_ea: int
    carrier_ea: int
    branch_ea: int
    callee_ea: int
    carrier_ida_stkoff: int
    value_size: int
    branch_opcode: int


@dataclass(frozen=True, slots=True)
class _TerminalReturnCarrierTemplate:
    request: TerminalReturnCarrierRequest
    instruction: object


@dataclass(frozen=True, slots=True)
class DetachedSnippetBlockTemplate:
    """Owned microcode body and CFG topology for one explicit-range block."""

    source_serial: int
    native_entry_ea: int
    instructions: tuple[object, ...]
    block_type: int
    block_flags: int
    successor_serials: tuple[int, ...]
    external_successor_eas: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class DetachedSnippetTemplateDirectBoundaryPort:
    """A direct port bound to template-local serials at capture time."""

    port: DetachedSnippetDirectBoundaryPort
    source_serial: int | None
    endpoint_serial: int | None
    target_serial: int | None
    old_successor_serials: tuple[int | None, ...] = ()


@dataclass(frozen=True, slots=True)
class DetachedSnippetTemplateConditionalBoundaryPort:
    """A conditional port bound to template-local serials at capture time."""

    port: DetachedSnippetConditionalBoundaryPort
    source_serial: int | None
    taken_target_serial: int | None
    fallthrough_target_serial: int | None


@dataclass(frozen=True, slots=True)
class DetachedSnippetTemplateBoundaryPorts:
    """Validated boundary ports retained with one detached template."""

    direct: tuple[DetachedSnippetTemplateDirectBoundaryPort, ...]
    conditional: tuple[DetachedSnippetTemplateConditionalBoundaryPort, ...]


@dataclass(frozen=True, slots=True)
class DetachedSnippetBoundaryPortResult:
    """One applied or abstained port, identified only by stable native EAs."""

    source_block_ea: int
    source_instruction_ea: int
    endpoint_block_ea: int
    target_eas: tuple[int, ...]
    reason: str | None = None


@dataclass(frozen=True, slots=True, eq=False)
class DetachedSnippetImportResult(Mapping[int, int]):
    """Imported roots plus EA-anchored boundary-port outcomes."""

    roots: tuple[tuple[int, int], ...]
    applied_boundary_ports: tuple[DetachedSnippetBoundaryPortResult, ...] = ()
    abstained_boundary_ports: tuple[DetachedSnippetBoundaryPortResult, ...] = ()

    def __getitem__(self, target_ea: int) -> int:
        for candidate_ea, serial in self.roots:
            if int(candidate_ea) == int(target_ea):
                return int(serial)
        raise KeyError(target_ea)

    def __iter__(self):
        return (int(target_ea) for target_ea, _serial in self.roots)

    def __len__(self) -> int:
        return len(self.roots)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Mapping):
            return False
        return dict(self.items()) == dict(other.items())


@dataclass(frozen=True, slots=True)
class DetachedSnippetTemplate:
    """Function-frame-normalized microcode for one detached native target."""

    function_ea: int
    target_ea: int
    maturity: int
    root_source_serial: int
    blocks: tuple[DetachedSnippetBlockTemplate, ...]
    stack_vd_to_ida: tuple[tuple[int, int], ...]
    owned_ranges: tuple[tuple[int, int], ...]
    call_result_carriers: tuple[CallResultCarrier, ...] = ()
    stable_stack_vd_to_ida: tuple[tuple[int, int], ...] = ()
    boundary_ports: DetachedSnippetTemplateBoundaryPorts = (
        DetachedSnippetTemplateBoundaryPorts((), ())
    )
    instruction_stack_vd_to_ida: tuple[tuple[int, int, int], ...] = ()


@dataclass(slots=True)
class _ImportedSnippetRoot:
    """Renumbering-stable identity for one imported snippet root."""

    serial_hint: int
    anchor_eas: tuple[int, ...]
    owned_instruction_eas: tuple[int, ...]


_ANALYZED_CALL_TEMPLATES: dict[tuple[int, int], _CallTemplate] = {}
_ANALYZED_CALL_RESULT_DEFINITIONS: dict[
    tuple[int, int],
    _AnalyzedCallResultDefinition,
] = {}
_ANALYZED_CALL_RESULT_DEFINITION_CONFLICTS: set[tuple[int, int]] = set()
_DETACHED_SNIPPET_TEMPLATES: dict[
    tuple[int, int],
    DetachedSnippetTemplate,
] = {}
_DETACHED_REPLACEMENT_SNIPPET_TEMPLATES: dict[
    tuple[int, int],
    DetachedSnippetTemplate,
] = {}
_DETACHED_CALLINFO_TEMPLATES: dict[tuple[int, int], object] = {}
_DETACHED_CALLINFO_CONFLICTS: set[tuple[int, int]] = set()
_DETACHED_SNIPPET_GENERATIONS: dict[int, int] = {}
_IMPORTED_SNIPPET_ROOTS: dict[tuple[int, int], _ImportedSnippetRoot] = {}
_IMPORTED_INSTRUCTION_ORIGINS: dict[tuple[int, int], int] = {}
_LAST_IMPORTED_INSTRUCTION_ORIGINS: dict[
    int,
    tuple[tuple[int, int], ...],
] = {}
_IMPORTED_DIRECT_BOUNDARY_EVIDENCE: dict[
    int,
    tuple[AppliedDetachedSnippetDirectBoundaryPort, ...],
] = {}
_IMPORTED_CONDITIONAL_BOUNDARY_EVIDENCE: dict[
    int,
    tuple[AppliedDetachedSnippetConditionalBoundaryPort, ...],
] = {}
_TERMINAL_RETURN_CARRIER_TEMPLATES: dict[
    tuple[int, int, int],
    _TerminalReturnCarrierTemplate,
] = {}


def imported_detached_snippet_instruction_origins(
    mba: object,
) -> tuple[tuple[int, int], ...]:
    """Return live ``(imported fict EA, native EA)`` instruction provenance."""
    identity = stable_mba_identity(mba)
    live_eas = {
        int(instruction.ea)
        for serial in range(int(mba.qty))
        for instruction in _instructions(mba.get_mblock(serial))
    }
    return tuple(
        sorted(
            (int(imported_ea), int(native_ea))
            for (mba_identity, imported_ea), native_ea in (
                _IMPORTED_INSTRUCTION_ORIGINS.items()
            )
            if int(mba_identity) == int(identity) and int(imported_ea) in live_eas
        )
    )


def last_imported_detached_snippet_instruction_origins(
    function_ea: int,
) -> tuple[tuple[int, int], ...]:
    """Return provenance published by the last successful PREOPT import.

    ``hxe_stkpnts`` runs before the current MBA reaches ``hxe_preoptimized``,
    so that callback cannot inspect imports which have not happened yet.  The
    importer assigns deterministic fictitious EAs; retain the preceding
    successful import's native ownership so the next transient stack-point
    table can be populated before the same semantic closure is imported.
    """
    return _LAST_IMPORTED_INSTRUCTION_ORIGINS.get(int(function_ea), ())


def imported_detached_snippet_terminal_origins(
    mba: object,
) -> tuple[tuple[int, int], ...]:
    """Return ``(imported fict EA, native EA)`` for live zero-way m_ijmps."""
    identity = stable_mba_identity(mba)
    result: list[tuple[int, int]] = []
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        tail = block.tail
        if (
            int(block.nsucc()) != 0
            or tail is None
            or int(tail.opcode) != int(ida_hexrays.m_ijmp)
        ):
            continue
        imported_ea = int(tail.ea)
        native_ea = _IMPORTED_INSTRUCTION_ORIGINS.get((identity, imported_ea))
        if native_ea is not None:
            result.append((imported_ea, int(native_ea)))
    return tuple(sorted(result))


def reconcile_imported_callinfo_with_live_native_calls(mba: object) -> int:
    """Replace isolated imported callinfo with unique live-MBA authority.

    Detached snippets are analyzed in isolation so their calls satisfy the
    Hex-Rays ``mop_f`` invariant.  When the full-function MBA still owns the
    same native call EA, its analyzed argument list has strictly better frame
    and use-def context.  Reuse it only when native provenance, opcode, and
    callee all agree uniquely; otherwise abstain.
    """
    origins = dict(imported_detached_snippet_instruction_origins(mba))
    if not origins:
        return 0

    call_opcodes = {
        int(ida_hexrays.m_call),
        int(ida_hexrays.m_icall),
    }
    native_by_ea: dict[int, list[tuple[object, object]]] = {}
    imported: list[tuple[object, object, int]] = []
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        for instruction in _instructions(block):
            if int(instruction.opcode) not in call_opcodes or int(
                instruction.d.t
            ) != int(ida_hexrays.mop_f):
                continue
            instruction_ea = int(instruction.ea)
            native_ea = origins.get(instruction_ea)
            if native_ea is None:
                native_by_ea.setdefault(instruction_ea, []).append((block, instruction))
            else:
                imported.append((block, instruction, int(native_ea)))

    changed_blocks: list[object] = []
    for block, instruction, native_ea in imported:
        candidates = tuple(
            candidate
            for _candidate_block, candidate in native_by_ea.get(native_ea, ())
            if int(candidate.opcode) == int(instruction.opcode)
            and candidate.l.equal_mops(
                instruction.l,
                int(ida_hexrays.EQ_IGNSIZE),
            )
        )
        if len(candidates) != 1:
            continue
        authority = candidates[0]
        if instruction.d.equal_mops(
            authority.d,
            int(ida_hexrays.EQ_IGNSIZE),
        ):
            continue
        instruction.d.assign(authority.d)
        changed_blocks.append(block)
        logger.info(
            "detached imported callinfo reconciled: native_call=0x%X "
            "imported_call=0x%X",
            native_ea,
            int(instruction.ea),
        )

    if not changed_blocks:
        return 0
    modifier = DeferredGraphModifier(mba)
    modifier.mark_blocks_dirty_now(*(dict.fromkeys(changed_blocks)))
    mba.verify(True)
    return len(changed_blocks)


def _operand_children(operand: object) -> tuple[object, ...]:
    operand_type = int(operand.t)
    if operand_type == int(ida_hexrays.mop_d):
        nested = operand.d
        return (nested.l, nested.r, nested.d)
    if operand_type == int(ida_hexrays.mop_a):
        return (operand.a,)
    if operand_type == int(ida_hexrays.mop_f):
        return tuple(operand.f.args)
    if operand_type == int(ida_hexrays.mop_p):
        return (operand.pair.lop, operand.pair.hop)
    return ()


def _walk_operand_tree(operand: object) -> tuple[object, ...]:
    pending = [operand]
    result: list[object] = []
    while pending:
        current = pending.pop()
        result.append(current)
        pending.extend(reversed(_operand_children(current)))
    return tuple(result)


def _instruction_operands(instruction: object) -> tuple[object, ...]:
    result: list[object] = []
    for root in (instruction.l, instruction.r, instruction.d):
        result.extend(_walk_operand_tree(root))
    return tuple(result)


def _block_native_eas(block: object) -> tuple[int, ...]:
    return tuple(
        sorted(
            {
                int(instruction.ea)
                for instruction in _instructions(block)
                if int(instruction.ea) > 0
            }
        )
    )


def _ea_in_ranges(ea: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(int(start) <= int(ea) < int(end) for start, end in ranges)


def _unique_block_native_ea(block: object) -> int | None:
    return select_unique_block_native_ea(
        int(block.start),
        _block_native_eas(block),
    )


def _anchored_template_root_serial(
    included: dict[int, object],
    root_serial: int,
) -> int | None:
    """Skip a unique transparent entry chain to the first anchored block."""
    cursor = int(root_serial)
    visited: set[int] = set()
    while cursor not in visited:
        visited.add(cursor)
        block = included.get(cursor)
        if block is None:
            return None
        if block.head is not None:
            return cursor
        successors = tuple(
            dict.fromkeys(
                int(successor_serial)
                for successor_serial in block.succset
                if int(successor_serial) in included
            )
        )
        if len(successors) != 1 or int(block.nsucc()) != 1:
            return None
        cursor = successors[0]
    return None


def _resolve_template_root_aliases(
    included: dict[int, object],
    roots: tuple[int, ...],
) -> tuple[int, tuple[int, ...]] | None:
    anchored_by_root = {
        int(root_serial): _anchored_template_root_serial(
            included,
            int(root_serial),
        )
        for root_serial in roots
    }
    anchored_roots = {
        int(serial) for serial in anchored_by_root.values() if serial is not None
    }
    if len(anchored_roots) != 1:
        return None
    anchored_root = next(iter(anchored_roots))
    if any(
        serial is None or int(serial) != anchored_root
        for serial in anchored_by_root.values()
    ):
        return None

    aliases = tuple(
        int(root_serial) for root_serial in roots if int(root_serial) != anchored_root
    )
    if anchored_root not in roots:
        return (anchored_root, ()) if len(roots) == 1 else None
    alias_set = set(aliases)
    predecessors: dict[int, set[int]] = {int(serial): set() for serial in included}
    for source_serial, block in included.items():
        for successor_serial in block.succset:
            successor = int(successor_serial)
            if successor in predecessors:
                predecessors[successor].add(int(source_serial))
    if any(
        included[alias].head is not None or not predecessors[alias].issubset(alias_set)
        for alias in aliases
    ):
        return None
    return anchored_root, aliases


def _split_nonterminal_raw_call_blocks(
    blocks: tuple[DetachedSnippetBlockTemplate, ...],
) -> tuple[DetachedSnippetBlockTemplate, ...] | None:
    """Give every nonterminal raw call its own verifier-valid block."""
    next_serial = (
        max(
            (int(block.source_serial) for block in blocks),
            default=-1,
        )
        + 1
    )
    result: list[DetachedSnippetBlockTemplate] = []
    for block in blocks:
        split_after = tuple(
            index
            for index, instruction in enumerate(block.instructions[:-1])
            if int(instruction.opcode)
            in {int(ida_hexrays.m_call), int(ida_hexrays.m_icall)}
        )
        if not split_after:
            result.append(block)
            continue
        starts = (0, *(index + 1 for index in split_after))
        ends = (*(index + 1 for index in split_after), len(block.instructions))
        chunks = tuple(
            block.instructions[start:end] for start, end in zip(starts, ends)
        )
        chunk_serials = [int(block.source_serial)]
        for _chunk in chunks[1:]:
            chunk_serials.append(next_serial)
            next_serial += 1
        for index, chunk in enumerate(chunks):
            if not chunk:
                return None
            if index == 0:
                native_entry_ea = int(block.native_entry_ea)
            else:
                native_entry_ea = next(
                    (
                        int(instruction.ea)
                        for instruction in chunk
                        if int(instruction.ea) > 0
                    ),
                    0,
                )
                if native_entry_ea <= 0:
                    return None
            if index + 1 == len(chunks):
                block_type = int(block.block_type)
                successor_serials = block.successor_serials
                external_successor_eas = block.external_successor_eas
            else:
                block_type = int(ida_hexrays.BLT_1WAY)
                successor_serials = (int(chunk_serials[index + 1]),)
                external_successor_eas = (0,)
            result.append(
                DetachedSnippetBlockTemplate(
                    source_serial=int(chunk_serials[index]),
                    native_entry_ea=native_entry_ea,
                    instructions=chunk,
                    block_type=block_type,
                    block_flags=int(block.block_flags),
                    successor_serials=successor_serials,
                    external_successor_eas=external_successor_eas,
                )
            )
    return tuple(result)


def _capture_template_boundary_ports(
    blocks: tuple[DetachedSnippetBlockTemplate, ...],
    boundary_ports: DetachedSnippetBoundaryPorts,
) -> DetachedSnippetTemplateBoundaryPorts | None:
    blocks_by_serial = {int(block.source_serial): block for block in blocks}
    serials_by_ea: dict[int, list[int]] = {}
    serials_by_instruction_ea: dict[int, list[int]] = {}
    for block in blocks:
        serial = int(block.source_serial)
        serials_by_ea.setdefault(int(block.native_entry_ea), []).append(serial)
        for instruction_ea in {
            int(instruction.ea) for instruction in block.instructions
        }:
            serials_by_instruction_ea.setdefault(int(instruction_ea), []).append(serial)

    def bound_serial(
        owner: DetachedSnippetBoundaryPortOwner,
        ea: int,
        *,
        exact_instruction_ea: int | None = None,
    ) -> int | None | object:
        if owner == DetachedSnippetBoundaryPortOwner.LIVE:
            return None
        if exact_instruction_ea is not None:
            instruction_matches = serials_by_instruction_ea.get(
                int(exact_instruction_ea), ()
            )
            if len(instruction_matches) == 1:
                return int(instruction_matches[0])
        matches = serials_by_ea.get(int(ea), ())
        return int(matches[0]) if len(matches) == 1 else _MISSING_BOUNDARY_PORT_SERIAL

    direct: list[DetachedSnippetTemplateDirectBoundaryPort] = []
    for port in boundary_ports.direct:
        source_serial = bound_serial(
            port.source_owner,
            port.source_block_ea,
            exact_instruction_ea=port.source_instruction_ea,
        )
        endpoint_serial = bound_serial(
            port.endpoint_owner,
            port.endpoint_block_ea,
            exact_instruction_ea=(
                port.source_instruction_ea
                if port.delivery_mode == "terminal_goto"
                and int(port.endpoint_block_ea) == int(port.source_block_ea)
                else None
            ),
        )
        target_serial = bound_serial(port.target_owner, port.target_ea)
        if _MISSING_BOUNDARY_PORT_SERIAL in {
            source_serial,
            endpoint_serial,
            target_serial,
        }:
            logger.info(
                "detached snippet capture boundary port abstained: "
                "kind=direct source=0x%X instruction=0x%X "
                "endpoint=0x%X target=0x%X "
                "source_bound=%s endpoint_bound=%s target_bound=%s "
                "reason=imported_owner_missing",
                int(port.source_block_ea),
                int(port.source_instruction_ea),
                int(port.endpoint_block_ea),
                int(port.target_ea),
                source_serial is not _MISSING_BOUNDARY_PORT_SERIAL,
                endpoint_serial is not _MISSING_BOUNDARY_PORT_SERIAL,
                target_serial is not _MISSING_BOUNDARY_PORT_SERIAL,
            )
            return None
        endpoint_successor_serials = (
            set()
            if endpoint_serial is None
            else {
                int(serial)
                for serial in blocks_by_serial[int(endpoint_serial)].successor_serials
            }
        )
        old_successor_serials: list[int | None] = []
        explicit_old_owners = (
            port.old_successor_owners
            if len(port.old_successor_owners) == len(port.old_successor_eas)
            else (None,) * len(port.old_successor_eas)
        )
        for old_successor_ea, old_owner in zip(
            port.old_successor_eas,
            explicit_old_owners,
        ):
            if old_owner == DetachedSnippetBoundaryPortOwner.LIVE:
                old_successor_serials.append(None)
                continue
            matches = tuple(
                int(serial)
                for serial in serials_by_ea.get(int(old_successor_ea), ())
                if int(serial) in endpoint_successor_serials
            )
            old_successor_serials.append(int(matches[0]) if len(matches) == 1 else None)
        direct.append(
            DetachedSnippetTemplateDirectBoundaryPort(
                port=port,
                source_serial=source_serial,
                endpoint_serial=endpoint_serial,
                target_serial=target_serial,
                old_successor_serials=tuple(old_successor_serials),
            )
        )

    conditional: list[DetachedSnippetTemplateConditionalBoundaryPort] = []
    for port in boundary_ports.conditional:
        source_serial = bound_serial(
            port.source_owner,
            port.source_block_ea,
            exact_instruction_ea=port.predicate_ea,
        )
        taken_target_serial = bound_serial(
            port.taken_target_owner,
            port.taken_target_ea,
        )
        fallthrough_target_serial = bound_serial(
            port.fallthrough_target_owner,
            port.fallthrough_target_ea,
        )
        if _MISSING_BOUNDARY_PORT_SERIAL in {
            source_serial,
            taken_target_serial,
            fallthrough_target_serial,
        }:
            logger.info(
                "detached snippet capture boundary port abstained: "
                "kind=conditional source=0x%X predicate=0x%X "
                "taken=0x%X fallthrough=0x%X "
                "reason=imported_owner_missing",
                int(port.source_block_ea),
                int(port.predicate_ea),
                int(port.taken_target_ea),
                int(port.fallthrough_target_ea),
            )
            return None
        conditional.append(
            DetachedSnippetTemplateConditionalBoundaryPort(
                port=port,
                source_serial=source_serial,
                taken_target_serial=taken_target_serial,
                fallthrough_target_serial=fallthrough_target_serial,
            )
        )
    return DetachedSnippetTemplateBoundaryPorts(
        direct=tuple(direct),
        conditional=tuple(conditional),
    )


def _normalize_capture_boundary_ports(
    boundary_ports: DetachedSnippetBoundaryPorts
    | tuple[
        DetachedSnippetDirectBoundaryPort | DetachedSnippetConditionalBoundaryPort,
        ...,
    ],
) -> DetachedSnippetBoundaryPorts | None:
    if isinstance(boundary_ports, DetachedSnippetBoundaryPorts):
        direct = boundary_ports.direct
        conditional = boundary_ports.conditional
    else:
        direct = tuple(
            port
            for port in boundary_ports
            if isinstance(port, DetachedSnippetDirectBoundaryPort)
        )
        conditional = tuple(
            port
            for port in boundary_ports
            if isinstance(port, DetachedSnippetConditionalBoundaryPort)
        )
        if len(direct) + len(conditional) != len(boundary_ports):
            return None
    try:
        return normalize_detached_snippet_boundary_ports(direct, conditional)
    except ValueError as error:
        logger.info(
            "detached snippet capture boundary ports abstained: reason=%s",
            str(error),
        )
        return None


def _resolver_cut_target_for_synthetic_successor(
    boundary_ports: DetachedSnippetBoundaryPorts
    | tuple[
        DetachedSnippetDirectBoundaryPort | DetachedSnippetConditionalBoundaryPort,
        ...,
    ],
    source_instruction_ea: int,
) -> int | None:
    """Resolve one synthetic snippet exit from an explicit resolver cut."""
    direct = (
        boundary_ports.direct
        if isinstance(boundary_ports, DetachedSnippetBoundaryPorts)
        else tuple(
            port
            for port in boundary_ports
            if isinstance(port, DetachedSnippetDirectBoundaryPort)
        )
    )
    targets = {
        int(port.target_ea)
        for port in direct
        if port.delivery_mode == "terminal_goto"
        and port.source_owner == DetachedSnippetBoundaryPortOwner.IMPORTED
        and port.target_owner == DetachedSnippetBoundaryPortOwner.LIVE
        and int(port.source_instruction_ea) == int(source_instruction_ea)
    }
    return next(iter(targets)) if len(targets) == 1 else None


def _capture_detached_snippet_template(
    function_ea: int,
    target_ea: int,
    mba: object,
    ranges: tuple[tuple[int, int], ...],
    template_cache: dict[tuple[int, int], DetachedSnippetTemplate],
    boundary_ports: DetachedSnippetBoundaryPorts,
    owned_block_entry_eas: Collection[int] | None,
    native_stack_frame_offsets_by_ea: Mapping[int, tuple[int, ...]],
) -> bool:
    """Cache one explicit-range MBA and its optional stable frame identities."""
    normalized_ranges = tuple(
        sorted((int(start), int(end)) for start, end in ranges if start < end)
    )
    owned_entries = (
        None
        if owned_block_entry_eas is None
        else {int(ea) for ea in owned_block_entry_eas}
    )
    included: dict[int, object] = {}
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        native_entry = _unique_block_native_ea(block)
        if (
            native_entry is not None
            and owned_entries is not None
            and int(native_entry) in owned_entries
        ) or (
            owned_entries is None
            and any(
                _ea_in_ranges(native_ea, normalized_ranges)
                for native_ea in _block_native_eas(block)
            )
        ):
            included[int(block.serial)] = block
    roots = tuple(
        serial
        for serial, block in included.items()
        if int(target_ea) in _block_native_eas(block)
        or int(block.start) == int(target_ea)
    )
    resolved_root = _resolve_template_root_aliases(included, roots)
    if resolved_root is None:
        logger.info(
            "detached snippet capture abstained: target=0x%X "
            "reason=non_unique_root roots=%s",
            int(target_ea),
            tuple(
                "blk%d@0x%X" % (int(serial), int(included[serial].start))
                for serial in roots
            ),
        )
        return False
    root_source_serial, transparent_root_aliases = resolved_root
    for alias_serial in transparent_root_aliases:
        del included[int(alias_serial)]

    stack_map: dict[int, int] = {}
    instruction_stack_map: dict[tuple[int, int], int] = {}
    stable_identities_by_vd: dict[int, set[int]] = {}
    templates: list[DetachedSnippetBlockTemplate] = []
    for serial, block in sorted(included.items()):
        instructions = tuple(
            ida_hexrays.minsn_t(instruction) for instruction in _instructions(block)
        )
        for instruction in instructions:
            if int(instruction.opcode) in (
                int(ida_hexrays.m_call),
                int(ida_hexrays.m_icall),
            ):
                logger.info(
                    "detached snippet capture call: target=0x%X "
                    "blk%d@0x%X call_ea=0x%X l=%d r=%d d=%d args=%d",
                    int(target_ea),
                    int(block.serial),
                    int(block.start),
                    int(instruction.ea),
                    int(instruction.l.t),
                    int(instruction.r.t),
                    int(instruction.d.t),
                    (
                        len(instruction.d.f.args)
                        if int(instruction.d.t) == int(ida_hexrays.mop_f)
                        else -1
                    ),
                )
        for instruction in instructions:
            stack_operands = tuple(
                operand
                for operand in _instruction_operands(instruction)
                if int(operand.t) == int(ida_hexrays.mop_S)
            )
            source_vd_offsets = tuple(
                dict.fromkeys(int(operand.s.off) for operand in stack_operands)
            )
            native_frame_offsets = native_stack_frame_offsets_by_ea.get(
                int(instruction.ea),
            )
            if native_frame_offsets is None:
                native_frame_offsets = _native_instruction_stack_frame_offsets(
                    int(function_ea),
                    int(instruction.ea),
                )
            native_frame_identity = (
                int(native_frame_offsets[0])
                if len(source_vd_offsets) == 1 and len(native_frame_offsets) == 1
                else None
            )
            for operand in stack_operands:
                vd_offset = int(operand.s.off)
                ida_offset = int(mba.stkoff_vd2ida(vd_offset))
                stable_ida_offset = (
                    native_frame_identity
                    if native_frame_identity is not None
                    else _normalize_template_ida_stkoff(
                        int(function_ea),
                        mba,
                        ida_offset,
                    )
                )
                previous = stack_map.setdefault(vd_offset, ida_offset)
                if previous != ida_offset:
                    logger.info(
                        "detached snippet capture abstained: target=0x%X "
                        "blk%d@0x%X reason=unstable_stack_mapping "
                        "vd=%d previous=%d current=%d",
                        int(target_ea),
                        int(block.serial),
                        int(block.start),
                        vd_offset,
                        previous,
                        ida_offset,
                    )
                    return False
                if stable_ida_offset >= 0:
                    instruction_stack_key = (
                        int(instruction.ea),
                        vd_offset,
                    )
                    previous_stable = instruction_stack_map.setdefault(
                        instruction_stack_key,
                        stable_ida_offset,
                    )
                    if previous_stable != stable_ida_offset:
                        logger.info(
                            "detached snippet capture abstained: target=0x%X "
                            "blk%d@0x%X instruction_ea=0x%X "
                            "reason=unstable_instruction_stack_mapping "
                            "vd=%d previous=%d current=%d",
                            int(target_ea),
                            int(block.serial),
                            int(block.start),
                            int(instruction.ea),
                            vd_offset,
                            previous_stable,
                            stable_ida_offset,
                        )
                        return False
                    stable_identities_by_vd.setdefault(
                        vd_offset,
                        set(),
                    ).add(stable_ida_offset)

        internal_successors: list[int] = []
        external_successors: list[int] = []
        lower_synthetic_exit_to_return = False
        for successor_serial in block.succset:
            successor = int(successor_serial)
            if successor in included:
                internal_successors.append(successor)
                external_successors.append(0)
                continue
            successor_block = mba.get_mblock(successor)
            if successor_block is not None and successor_block.head is None:
                successor_native_ea = _unique_block_native_ea(successor_block)
                if (
                    successor_native_ea is None
                    and block.tail is not None
                    and int(block.tail.opcode) == int(ida_hexrays.m_ret)
                ):
                    continue
                if (
                    successor_native_ea is None
                    and block.tail is not None
                    and int(block.tail.opcode) == int(ida_hexrays.m_goto)
                    and int(block.tail.l.t) == int(ida_hexrays.mop_b)
                    and int(block.tail.l.b) == successor
                    and successor == int(mba.qty) - 1
                    and int(block.nsucc()) == 1
                ):
                    lower_synthetic_exit_to_return = True
                    continue
            successor_ea = (
                _unique_block_native_ea(successor_block)
                if successor_block is not None
                else None
            )
            if successor_ea is None and block.tail is not None:
                successor_ea = _resolver_cut_target_for_synthetic_successor(
                    boundary_ports,
                    int(block.tail.ea),
                )
            if successor_ea is None:
                logger.info(
                    "detached snippet capture abstained: target=0x%X "
                    "source=blk%d@0x%X successor=%s "
                    "source_type=%d tail_opcode=%s tail_ea=%s "
                    "successor_empty=%s "
                    "reason=external_successor_without_unique_native_ea",
                    int(target_ea),
                    int(block.serial),
                    int(block.start),
                    (
                        "missing"
                        if successor_block is None
                        else "blk%d@0x%X"
                        % (
                            int(successor_block.serial),
                            int(successor_block.start),
                        )
                    ),
                    int(block.type),
                    ("missing" if block.tail is None else str(int(block.tail.opcode))),
                    ("missing" if block.tail is None else "0x%X" % int(block.tail.ea)),
                    successor_block is not None and successor_block.head is None,
                )
                return False
            internal_successors.append(successor)
            external_successors.append(int(successor_ea))

        template_block_type = int(block.type)
        if lower_synthetic_exit_to_return:
            terminal_return = ida_hexrays.minsn_t(int(block.tail.ea))
            terminal_return.opcode = int(ida_hexrays.m_ret)
            instructions = (*instructions[:-1], terminal_return)
            template_block_type = int(ida_hexrays.BLT_STOP)

        native_entry = _unique_block_native_ea(block)
        if native_entry is None:
            logger.info(
                "detached snippet capture abstained: target=0x%X "
                "blk%d@0x%X reason=block_without_unique_native_entry",
                int(target_ea),
                int(block.serial),
                int(block.start),
            )
            return False
        templates.append(
            DetachedSnippetBlockTemplate(
                source_serial=int(serial),
                native_entry_ea=int(native_entry),
                instructions=instructions,
                block_type=template_block_type,
                block_flags=int(block.flags),
                successor_serials=tuple(internal_successors),
                external_successor_eas=tuple(external_successors),
            )
        )

    owned_instruction_eas = {
        int(instruction.ea)
        for block in included.values()
        for instruction in _instructions(block)
    }
    call_result_carriers = tuple(
        replace(
            fact,
            carrier_ida_stkoff=_normalize_template_ida_stkoff(
                int(function_ea),
                mba,
                int(fact.carrier_ida_stkoff),
            ),
        )
        for fact in capture_call_result_carriers(mba)
        if {
            int(fact.call_ea),
            int(fact.carrier_ea),
            int(fact.branch_ea),
        }.issubset(owned_instruction_eas)
    )
    normalized_templates = (
        _split_nonterminal_raw_call_blocks(tuple(templates))
        if int(mba.maturity) == int(ida_hexrays.MMAT_PREOPTIMIZED)
        else tuple(templates)
    )
    if normalized_templates is None:
        logger.info(
            "detached snippet capture abstained: target=0x%X "
            "reason=raw_call_split_without_native_anchor",
            int(target_ea),
        )
        return False
    if stack_map:
        logger.info(
            "detached snippet capture stack identities: target=0x%X "
            "raw=%s stable=%s instruction=%s",
            int(target_ea),
            sorted(stack_map.items()),
            sorted(
                (source_vd, sorted(ida_offsets))
                for source_vd, ida_offsets in stable_identities_by_vd.items()
            ),
            sorted(
                (instruction_ea, source_vd, ida_offset)
                for (instruction_ea, source_vd), ida_offset in instruction_stack_map.items()
            ),
        )
    template_boundary_ports = _capture_template_boundary_ports(
        normalized_templates,
        boundary_ports,
    )
    if template_boundary_ports is None:
        return False
    template_cache[(int(function_ea), int(target_ea))] = DetachedSnippetTemplate(
        function_ea=int(function_ea),
        target_ea=int(target_ea),
        maturity=int(mba.maturity),
        root_source_serial=int(root_source_serial),
        blocks=normalized_templates,
        stack_vd_to_ida=tuple(sorted(stack_map.items())),
        owned_ranges=normalized_ranges,
        call_result_carriers=call_result_carriers,
        stable_stack_vd_to_ida=tuple(
            sorted(
                (source_vd, next(iter(ida_offsets)))
                for source_vd, ida_offsets in stable_identities_by_vd.items()
                if len(ida_offsets) == 1
            )
        ),
        boundary_ports=template_boundary_ports,
        instruction_stack_vd_to_ida=tuple(
            sorted(
                (instruction_ea, source_vd, ida_offset)
                for (
                    instruction_ea,
                    source_vd,
                ), ida_offset in instruction_stack_map.items()
            )
        ),
    )
    key = int(function_ea)
    _DETACHED_SNIPPET_GENERATIONS[key] = _DETACHED_SNIPPET_GENERATIONS.get(key, 0) + 1
    return True


def capture_detached_snippet_template(
    function_ea: int,
    target_ea: int,
    mba: object,
    ranges: tuple[tuple[int, int], ...],
    *,
    boundary_ports: DetachedSnippetBoundaryPorts
    | tuple[
        DetachedSnippetDirectBoundaryPort | DetachedSnippetConditionalBoundaryPort,
        ...,
    ] = (),
    owned_block_entry_eas: Collection[int] | None = None,
    native_stack_frame_offsets_by_ea: Mapping[int, tuple[int, ...]] | None = None,
) -> bool:
    """Cache one LOCOPT template used for missing detached handlers."""
    normalized_boundary_ports = _normalize_capture_boundary_ports(boundary_ports)
    if normalized_boundary_ports is None:
        return False
    return _capture_detached_snippet_template(
        function_ea,
        target_ea,
        mba,
        ranges,
        _DETACHED_SNIPPET_TEMPLATES,
        normalized_boundary_ports,
        owned_block_entry_eas,
        (
            {}
            if native_stack_frame_offsets_by_ea is None
            else native_stack_frame_offsets_by_ea
        ),
    )


def capture_detached_replacement_snippet_template(
    function_ea: int,
    target_ea: int,
    mba: object,
    ranges: tuple[tuple[int, int], ...],
    *,
    boundary_ports: DetachedSnippetBoundaryPorts
    | tuple[
        DetachedSnippetDirectBoundaryPort | DetachedSnippetConditionalBoundaryPort,
        ...,
    ] = (),
    owned_block_entry_eas: Collection[int] | None = None,
    native_stack_frame_offsets_by_ea: Mapping[int, tuple[int, ...]] | None = None,
) -> bool:
    """Cache one CALLS template whose detached conditional arm must survive."""
    normalized_boundary_ports = _normalize_capture_boundary_ports(boundary_ports)
    if normalized_boundary_ports is None:
        return False
    return _capture_detached_snippet_template(
        function_ea,
        target_ea,
        mba,
        ranges,
        _DETACHED_REPLACEMENT_SNIPPET_TEMPLATES,
        normalized_boundary_ports,
        owned_block_entry_eas,
        (
            {}
            if native_stack_frame_offsets_by_ea is None
            else native_stack_frame_offsets_by_ea
        ),
    )


def detached_snippet_template_generation(function_ea: int) -> int:
    """Return the cache epoch used to retry a fresh top-level LOCOPT MBA."""
    return int(_DETACHED_SNIPPET_GENERATIONS.get(int(function_ea), 0))


def has_detached_snippet_template(function_ea: int, target_ea: int) -> bool:
    """Return whether one exact native target already owns a cached template."""
    return (int(function_ea), int(target_ea)) in _DETACHED_SNIPPET_TEMPLATES


def has_detached_replacement_snippet_template(
    function_ea: int,
    target_ea: int,
) -> bool:
    """Return whether one CALLS replacement template is cached."""
    return (
        int(function_ea),
        int(target_ea),
    ) in _DETACHED_REPLACEMENT_SNIPPET_TEMPLATES


def detached_snippet_template_block_eas(
    function_ea: int,
    target_ea: int,
) -> tuple[int, ...]:
    """Return stable native anchors for every owned block in one template."""
    template = _DETACHED_SNIPPET_TEMPLATES.get((int(function_ea), int(target_ea)))
    if template is None:
        return ()
    return tuple(sorted({int(block.native_entry_ea) for block in template.blocks}))


def detached_snippet_template_stack_map(
    function_ea: int,
    target_ea: int,
) -> tuple[tuple[int, int], ...]:
    """Return snippet VD -> stable IDA-frame stack identities for diagnostics."""
    template = _DETACHED_SNIPPET_TEMPLATES.get((int(function_ea), int(target_ea)))
    return () if template is None else template.stack_vd_to_ida


def detached_callinfo_template_eas(function_ea: int) -> tuple[int, ...]:
    """Return native call EAs with unique route-scoped CALLS authority."""
    function_key = int(function_ea)
    return tuple(
        sorted(
            call_ea
            for profile_ea, call_ea in _DETACHED_CALLINFO_TEMPLATES
            if int(profile_ea) == function_key
            and (function_key, int(call_ea)) not in _DETACHED_CALLINFO_CONFLICTS
        )
    )


def _instruction_tree(instruction: object) -> tuple[object, ...]:
    """Return one instruction and every nested ``mop_d`` instruction."""
    pending = [instruction]
    result: list[object] = []
    while pending:
        current = pending.pop()
        result.append(current)
        for operand in _instruction_operands(current):
            if int(operand.t) == int(ida_hexrays.mop_d):
                pending.append(operand.d)
    return tuple(result)


_MBA_INDEPENDENT_CALLINFO_OPERAND_TYPES = frozenset(
    {
        int(ida_hexrays.mop_z),
        int(ida_hexrays.mop_n),
        int(ida_hexrays.mop_v),
        int(ida_hexrays.mop_d),
    }
)


def _callinfo_argument_is_mba_independent(argument: object) -> bool:
    """Accept only expressions whose copied operands own no source MBA state."""
    return all(
        int(operand.t) in _MBA_INDEPENDENT_CALLINFO_OPERAND_TYPES
        for operand in _walk_operand_tree(argument)
    )


def _callinfo_stack_span(callinfo: object) -> int | None:
    span = int(callinfo.stkargs_top) - int(callinfo.call_spd)
    return span if span >= 0 else None


def _callinfo_templates_equivalent(first: object, second: object) -> bool:
    if int(first.opcode) != int(second.opcode):
        return False
    if not first.l.equal_mops(second.l, int(ida_hexrays.EQ_IGNSIZE)):
        return False
    if not first.d.equal_mops(second.d, int(ida_hexrays.EQ_IGNSIZE)):
        return False
    return _callinfo_stack_span(first.d.f) == _callinfo_stack_span(second.d.f)


def capture_detached_callinfo_templates(
    function_ea: int,
    calls_mba: object,
) -> tuple[int, ...]:
    """Merge route-scoped CALLS authority by exact native call EA.

    No CALLS topology is imported.  Each retained instruction is a deep clone
    whose arguments are composed only from constants, globals, and nested pure
    expressions.  Source-MBA stack/local/register operands abstain because
    their storage identity is not portable across an isolated snippet MBA.
    Conflicting observations permanently suppress that call EA for the cache
    epoch instead of selecting one route arbitrarily.
    """
    if int(calls_mba.maturity) != int(ida_hexrays.MMAT_CALLS):
        return ()
    function_key = int(function_ea)
    captured: set[int] = set()
    observed: set[int] = set()
    call_opcodes = {
        int(ida_hexrays.m_call),
        int(ida_hexrays.m_icall),
    }
    for serial in range(int(calls_mba.qty)):
        block = calls_mba.get_mblock(serial)
        for owner in _instructions(block):
            for instruction in _instruction_tree(owner):
                if (
                    int(instruction.opcode) not in call_opcodes
                    or int(instruction.d.t) != int(ida_hexrays.mop_f)
                    or _callinfo_stack_span(instruction.d.f) is None
                    or not all(
                        _callinfo_argument_is_mba_independent(argument)
                        for argument in instruction.d.f.args
                    )
                ):
                    continue
                call_ea = int(instruction.ea)
                key = (function_key, call_ea)
                if call_ea in observed:
                    _DETACHED_CALLINFO_TEMPLATES.pop(key, None)
                    _DETACHED_CALLINFO_CONFLICTS.add(key)
                    captured.discard(call_ea)
                    continue
                observed.add(call_ea)
                if key in _DETACHED_CALLINFO_CONFLICTS:
                    continue
                candidate = ida_hexrays.minsn_t(instruction)
                existing = _DETACHED_CALLINFO_TEMPLATES.get(key)
                if existing is not None and not _callinfo_templates_equivalent(
                    existing,
                    candidate,
                ):
                    _DETACHED_CALLINFO_TEMPLATES.pop(key, None)
                    _DETACHED_CALLINFO_CONFLICTS.add(key)
                    captured.discard(call_ea)
                    logger.info(
                        "detached callinfo template abstained: func=0x%X "
                        "call=0x%X reason=conflicting_route_templates",
                        function_key,
                        call_ea,
                    )
                    continue
                if existing is None:
                    _DETACHED_CALLINFO_TEMPLATES[key] = candidate
                captured.add(call_ea)
    return tuple(sorted(captured))


def prepare_detached_callinfo_template(
    function_ea: int,
    native_call_ea: int,
    raw_call: object,
    destination_mba: object,
    *,
    copy_callinfo: Callable[[object, object], bool],
) -> object | None:
    """Clone one exact route CALLS template into the destination stack space."""
    key = (int(function_ea), int(native_call_ea))
    if key in _DETACHED_CALLINFO_CONFLICTS:
        return None
    template = _DETACHED_CALLINFO_TEMPLATES.get(key)
    if template is None:
        return None
    if int(raw_call.opcode) != int(template.opcode) or not raw_call.l.equal_mops(
        template.l,
        int(ida_hexrays.EQ_IGNSIZE),
    ):
        return None
    source_callinfo = template.d.f
    stack_span = _callinfo_stack_span(source_callinfo)
    if stack_span is None:
        return None
    prepared = ida_hexrays.mcallinfo_t()
    try:
        copied = bool(copy_callinfo(prepared, source_callinfo))
    except Exception:
        logger.debug(
            "detached callinfo copy failed: func=0x%X call=0x%X",
            int(function_ea),
            int(native_call_ea),
            exc_info=True,
        )
        return None
    if not copied or len(prepared.args) != len(source_callinfo.args):
        return None
    # Hex-Rays stack coordinates are nonnegative VD offsets.  Native IDA
    # stack offset zero maps to ``tmpstk_size`` in that coordinate system;
    # preserve the analyzed outgoing-argument span relative to that top.
    destination_top = int(destination_mba.stkoff_ida2vd(0))
    prepared.stkargs_top = destination_top
    prepared.call_spd = destination_top - int(stack_span)
    return prepared


@dataclass(frozen=True, slots=True)
class DetachedCallCompanionValidation:
    """Native-EA proof that PREOPT and CALLS call sites correspond exactly."""

    accepted: bool
    call_eas: tuple[int, ...] = ()
    reason: str | None = None
    mismatch_ea: int | None = None


@dataclass(frozen=True, slots=True)
class DetachedSnippetCompanionCaptureResult:
    """Atomic publication result for one PREOPT/CALLS template pair."""

    captured: bool
    replacement_required: bool
    call_eas: tuple[int, ...] = ()
    reason: str | None = None
    mismatch_ea: int | None = None


@dataclass(frozen=True, slots=True)
class _DetachedCallSignature:
    opcode: int
    direct_callee_ea: int | None
    has_arglist: bool


def _detached_call_signatures(
    mba: object,
) -> tuple[dict[int, _DetachedCallSignature], int | None]:
    signatures: dict[int, _DetachedCallSignature] = {}
    call_opcodes = {
        int(ida_hexrays.m_call),
        int(ida_hexrays.m_icall),
    }
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        for owner in _instructions(block):
            for instruction in _instruction_tree(owner):
                opcode = int(instruction.opcode)
                if opcode not in call_opcodes:
                    continue
                call_ea = int(instruction.ea)
                if call_ea in signatures:
                    return signatures, call_ea
                signatures[call_ea] = _DetachedCallSignature(
                    opcode=opcode,
                    direct_callee_ea=(
                        int(instruction.l.g)
                        if opcode == int(ida_hexrays.m_call)
                        and int(instruction.l.t) == int(ida_hexrays.mop_v)
                        else None
                    ),
                    has_arglist=(int(instruction.d.t) == int(ida_hexrays.mop_f)),
                )
    return signatures, None


def validate_detached_call_companion(
    preopt_mba: object,
    calls_mba: object,
) -> DetachedCallCompanionValidation:
    """Match complete CALLS authority to raw PREOPT calls by native EA."""
    if int(preopt_mba.maturity) != int(ida_hexrays.MMAT_PREOPTIMIZED):
        return DetachedCallCompanionValidation(
            accepted=False,
            reason="preopt_maturity_mismatch",
        )
    if int(calls_mba.maturity) != int(ida_hexrays.MMAT_CALLS):
        return DetachedCallCompanionValidation(
            accepted=False,
            reason="calls_maturity_mismatch",
        )

    preopt, duplicate_ea = _detached_call_signatures(preopt_mba)
    if duplicate_ea is not None:
        return DetachedCallCompanionValidation(
            accepted=False,
            call_eas=tuple(sorted(preopt)),
            reason="preopt_duplicate_call_ea",
            mismatch_ea=int(duplicate_ea),
        )
    calls, duplicate_ea = _detached_call_signatures(calls_mba)
    if duplicate_ea is not None:
        return DetachedCallCompanionValidation(
            accepted=False,
            call_eas=tuple(sorted(preopt)),
            reason="calls_duplicate_call_ea",
            mismatch_ea=int(duplicate_ea),
        )

    preopt_eas = frozenset(preopt)
    calls_eas = frozenset(calls)
    if preopt_eas != calls_eas:
        return DetachedCallCompanionValidation(
            accepted=False,
            call_eas=tuple(sorted(preopt_eas)),
            reason="call_ea_set_mismatch",
            mismatch_ea=min(preopt_eas.symmetric_difference(calls_eas)),
        )

    for call_ea in sorted(preopt_eas):
        raw = preopt[call_ea]
        analyzed = calls[call_ea]
        if raw.opcode != analyzed.opcode:
            return DetachedCallCompanionValidation(
                accepted=False,
                call_eas=tuple(sorted(preopt_eas)),
                reason="call_opcode_mismatch",
                mismatch_ea=int(call_ea),
            )
        if raw.direct_callee_ea != analyzed.direct_callee_ea:
            return DetachedCallCompanionValidation(
                accepted=False,
                call_eas=tuple(sorted(preopt_eas)),
                reason="direct_callee_mismatch",
                mismatch_ea=int(call_ea),
            )
        if not analyzed.has_arglist:
            return DetachedCallCompanionValidation(
                accepted=False,
                call_eas=tuple(sorted(preopt_eas)),
                reason="analyzed_arglist_missing",
                mismatch_ea=int(call_ea),
            )
    return DetachedCallCompanionValidation(
        accepted=True,
        call_eas=tuple(sorted(preopt_eas)),
    )


def capture_detached_snippet_companion_templates(
    function_ea: int,
    target_ea: int,
    preopt_mba: object,
    calls_mba: object | None,
    ranges: tuple[tuple[int, int], ...],
    *,
    boundary_ports: DetachedSnippetBoundaryPorts
    | tuple[
        DetachedSnippetDirectBoundaryPort | DetachedSnippetConditionalBoundaryPort,
        ...,
    ] = (),
    owned_block_entry_eas: Collection[int] | None = None,
) -> DetachedSnippetCompanionCaptureResult:
    """Publish a PREOPT template and its exact analyzed-call companion."""
    preopt_calls, duplicate_ea = _detached_call_signatures(preopt_mba)
    call_eas = tuple(sorted(preopt_calls))
    if int(preopt_mba.maturity) != int(ida_hexrays.MMAT_PREOPTIMIZED):
        return DetachedSnippetCompanionCaptureResult(
            captured=False,
            replacement_required=bool(call_eas),
            call_eas=call_eas,
            reason="preopt_maturity_mismatch",
        )
    if duplicate_ea is not None:
        return DetachedSnippetCompanionCaptureResult(
            captured=False,
            replacement_required=True,
            call_eas=call_eas,
            reason="preopt_duplicate_call_ea",
            mismatch_ea=int(duplicate_ea),
        )
    if calls_mba is None and call_eas:
        return DetachedSnippetCompanionCaptureResult(
            captured=False,
            replacement_required=True,
            call_eas=call_eas,
            reason="calls_companion_missing",
            mismatch_ea=int(call_eas[0]),
        )
    if calls_mba is not None:
        validation = validate_detached_call_companion(preopt_mba, calls_mba)
        if not validation.accepted:
            logger.info(
                "detached call companion capture abstained: func=0x%X "
                "target=0x%X calls=%s mismatch=%s reason=%s",
                int(function_ea),
                int(target_ea),
                [hex(ea) for ea in validation.call_eas],
                (
                    None
                    if validation.mismatch_ea is None
                    else hex(int(validation.mismatch_ea))
                ),
                validation.reason,
            )
            return DetachedSnippetCompanionCaptureResult(
                captured=False,
                replacement_required=bool(call_eas),
                call_eas=validation.call_eas,
                reason=validation.reason,
                mismatch_ea=validation.mismatch_ea,
            )

    key = (int(function_ea), int(target_ea))
    missing = object()
    old_primary = _DETACHED_SNIPPET_TEMPLATES.get(key, missing)
    old_replacement = _DETACHED_REPLACEMENT_SNIPPET_TEMPLATES.get(key, missing)
    old_generation = _DETACHED_SNIPPET_GENERATIONS.get(
        int(function_ea),
        missing,
    )

    def restore() -> None:
        for cache, previous in (
            (_DETACHED_SNIPPET_TEMPLATES, old_primary),
            (_DETACHED_REPLACEMENT_SNIPPET_TEMPLATES, old_replacement),
        ):
            if previous is missing:
                cache.pop(key, None)
            else:
                cache[key] = previous
        if old_generation is missing:
            _DETACHED_SNIPPET_GENERATIONS.pop(int(function_ea), None)
        else:
            _DETACHED_SNIPPET_GENERATIONS[int(function_ea)] = int(old_generation)

    replacement_required = bool(call_eas)
    if replacement_required:
        assert calls_mba is not None
        if not capture_detached_replacement_snippet_template(
            int(function_ea),
            int(target_ea),
            calls_mba,
            ranges,
        ):
            restore()
            return DetachedSnippetCompanionCaptureResult(
                captured=False,
                replacement_required=True,
                call_eas=call_eas,
                reason="replacement_capture_failed",
            )
    if not capture_detached_snippet_template(
        int(function_ea),
        int(target_ea),
        preopt_mba,
        ranges,
        boundary_ports=boundary_ports,
        owned_block_entry_eas=owned_block_entry_eas,
    ):
        restore()
        return DetachedSnippetCompanionCaptureResult(
            captured=False,
            replacement_required=replacement_required,
            call_eas=call_eas,
            reason="primary_capture_failed",
        )

    previous_generation = 0 if old_generation is missing else int(old_generation)
    _DETACHED_SNIPPET_GENERATIONS[int(function_ea)] = previous_generation + 1
    logger.info(
        "detached call companion captured: func=0x%X target=0x%X "
        "calls=%s replacement=%s",
        int(function_ea),
        int(target_ea),
        [hex(ea) for ea in call_eas],
        replacement_required,
    )
    return DetachedSnippetCompanionCaptureResult(
        captured=True,
        replacement_required=replacement_required,
        call_eas=call_eas,
    )


def _analyzed_replacement_calls_by_ea(
    function_ea: int,
    target_ea: int,
) -> dict[int, _AnalyzedCallReplacement]:
    """Return exact analyzed call-bearing replacements keyed by call EA.

    The native call EA is the stable identity across the pre-CALLS and
    analyzed template maturities.  ``MBA2_NO_DUP_CALLS`` makes that identity
    unique inside one MBA.  Preserve a direct ``m_mov(call) -> carrier`` owner
    instead of returning only its nested call; dropping that owner loses the
    analyzed return-value destination when the raw detached call is imported.
    """
    template = _DETACHED_REPLACEMENT_SNIPPET_TEMPLATES.get(
        (int(function_ea), int(target_ea))
    )
    if template is None:
        return {}
    calls: dict[int, _AnalyzedCallReplacement] = {}
    for block in template.blocks:
        for instruction in block.instructions:
            for nested in _instruction_tree(instruction):
                if int(nested.opcode) not in (
                    int(ida_hexrays.m_call),
                    int(ida_hexrays.m_icall),
                ) or int(nested.d.t) != int(ida_hexrays.mop_f):
                    continue
                replacement = nested
                if (
                    int(instruction.opcode) == int(ida_hexrays.m_mov)
                    and int(instruction.l.t) == int(ida_hexrays.mop_d)
                    and int(instruction.l.d.opcode) == int(nested.opcode)
                    and int(instruction.l.d.ea) == int(nested.ea)
                    and int(instruction.d.t) != int(ida_hexrays.mop_z)
                ):
                    replacement = instruction
                calls.setdefault(
                    int(nested.ea),
                    _AnalyzedCallReplacement(
                        instruction=replacement,
                        call_opcode=int(nested.opcode),
                    ),
                )
    return calls


def _subsumed_raw_call_setup_instruction_eas(
    raw_template: DetachedSnippetTemplate,
    analyzed_template: DetachedSnippetTemplate | None,
    analyzed_calls: dict[int, _AnalyzedCallReplacement],
) -> frozenset[int]:
    """Return transient raw stack stores represented by analyzed call args.

    A PREOPTIMIZED call still has explicit outgoing-argument stores. Its CALLS
    counterpart owns the same call EA with a complete ``mop_f`` argument list
    and no longer contains those stores. Only same-block stores with a negative
    raw IDA stack identity are eligible; positive identities are persistent
    function locals and must survive import.
    """
    if analyzed_template is None or not analyzed_calls:
        return frozenset()
    analyzed_instruction_eas = {
        int(instruction.ea)
        for block in analyzed_template.blocks
        for instruction in block.instructions
    }
    raw_ida_by_vd = {
        int(source_vd): int(ida_stkoff)
        for source_vd, ida_stkoff in raw_template.stack_vd_to_ida
    }
    subsumed: set[int] = set()
    for block in raw_template.blocks:
        instructions = tuple(block.instructions)
        previous_call_index = -1
        for call_index, call in enumerate(instructions):
            if int(call.opcode) not in {
                int(ida_hexrays.m_call),
                int(ida_hexrays.m_icall),
            }:
                continue
            if int(call.ea) not in analyzed_calls:
                previous_call_index = call_index
                continue
            for candidate in instructions[previous_call_index + 1 : call_index]:
                candidate_ea = int(candidate.ea)
                if candidate_ea in analyzed_instruction_eas:
                    continue
                if int(candidate.d.t) != int(ida_hexrays.mop_S):
                    continue
                source_vd = int(candidate.d.s.off)
                ida_stkoff = raw_ida_by_vd.get(source_vd)
                if ida_stkoff is not None and int(ida_stkoff) < 0:
                    subsumed.add(candidate_ea)
            previous_call_index = call_index
    return frozenset(subsumed)


def detached_snippet_requires_analyzed_calls(
    function_ea: int,
    target_ea: int,
) -> bool:
    """Whether a cached pre-CALLS template owns an untyped call.

    Such a template needs an exact CALLS-maturity authority before it can be
    imported safely.  Hex-Rays may later set ``MBL_CALL`` on the destination
    block, at which point verify.cpp requires every call destination to be a
    real ``mop_f`` argument list (INTERR 50824).
    """
    template = _DETACHED_SNIPPET_TEMPLATES.get((int(function_ea), int(target_ea)))
    if template is None:
        return False
    for block in template.blocks:
        for instruction in block.instructions:
            for nested in _instruction_tree(instruction):
                if int(nested.opcode) in (
                    int(ida_hexrays.m_call),
                    int(ida_hexrays.m_icall),
                ) and int(nested.d.t) != int(ida_hexrays.mop_f):
                    return True
    return False


def _detached_snippet_conditional_evidence_from_template(
    function_ea: int,
    target_ea: int,
    template: DetachedSnippetTemplate,
    *,
    template_kind: str,
) -> DetachedSnippetReplacementEvidence | None:
    """Summarize one exact two-arm template without exposing Hex-Rays objects."""
    native_entry_by_serial = {
        int(block.source_serial): int(block.native_entry_ea)
        for block in template.blocks
    }
    conditional_rows: list[tuple[int, int, tuple[int, int]]] = []
    conditional_debug_rows: list[tuple[object, ...]] = []
    terminal_exit_eas: set[int] = set()
    calls_verify_safe = True
    contains_calls = False
    detached_ranges = tuple(
        (int(start), int(end))
        for start, end in template.owned_ranges
        if not int(start) <= int(target_ea) < int(end)
    )
    for block in template.blocks:
        for instruction in block.instructions:
            for nested in _instruction_tree(instruction):
                if int(nested.opcode) in (
                    int(ida_hexrays.m_call),
                    int(ida_hexrays.m_icall),
                ):
                    contains_calls = True
                    if int(nested.d.t) != int(ida_hexrays.mop_f):
                        calls_verify_safe = False
            if int(instruction.opcode) == int(ida_hexrays.m_ijmp):
                terminal_exit_eas.add(int(instruction.ea))

        if (
            int(block.block_type) != int(ida_hexrays.BLT_2WAY)
            or len(block.successor_serials) != 2
            or len(block.external_successor_eas) != 2
            or not block.instructions
        ):
            continue
        tail = block.instructions[-1]
        conditional_debug_rows.append(
            (
                f"blk{int(block.source_serial)}@0x{int(block.native_entry_ea):X}",
                int(block.block_type),
                tuple(int(serial) for serial in block.successor_serials),
                tuple(hex(int(ea)) for ea in block.external_successor_eas),
                hex(int(tail.ea)),
                int(tail.opcode),
                int(tail.d.t),
                (int(tail.d.b) if int(tail.d.t) == int(ida_hexrays.mop_b) else None),
            )
        )
        if (
            not ida_hexrays.is_mcode_jcond(int(tail.opcode))
            or int(tail.d.t) != int(ida_hexrays.mop_b)
            or int(tail.d.b) != int(block.successor_serials[1])
        ):
            continue
        successor_eas: list[int] = []
        for successor_serial, external_ea in zip(
            block.successor_serials,
            block.external_successor_eas,
        ):
            successor_ea = (
                int(external_ea)
                if int(external_ea) > 0
                else native_entry_by_serial.get(int(successor_serial))
            )
            if successor_ea is None or int(successor_ea) <= 0:
                successor_eas = []
                break
            successor_eas.append(int(successor_ea))
        if (
            len(successor_eas) == 2
            and sum(_ea_in_ranges(ea, detached_ranges) for ea in successor_eas) == 1
        ):
            conditional_rows.append(
                (
                    int(block.source_serial),
                    int(tail.ea),
                    (successor_eas[0], successor_eas[1]),
                )
            )

    distance_by_serial = {int(template.root_source_serial): 0}
    pending_serials = [int(template.root_source_serial)]
    successors_by_serial = {
        int(block.source_serial): tuple(int(ea) for ea in block.successor_serials)
        for block in template.blocks
    }
    while pending_serials:
        source_serial = pending_serials.pop(0)
        next_distance = int(distance_by_serial[source_serial]) + 1
        for successor_serial in successors_by_serial.get(source_serial, ()):
            if (
                successor_serial not in native_entry_by_serial
                or successor_serial in distance_by_serial
            ):
                continue
            distance_by_serial[successor_serial] = next_distance
            pending_serials.append(successor_serial)
    candidate_distances = tuple(
        (
            int(distance_by_serial[source_serial]),
            int(source_serial),
            int(branch_ea),
            targets,
        )
        for source_serial, branch_ea, targets in conditional_rows
        if source_serial in distance_by_serial
    )
    nearest_distance = (
        min(row[0] for row in candidate_distances) if candidate_distances else None
    )
    nearest_rows = tuple(
        row
        for row in candidate_distances
        if nearest_distance is not None and int(row[0]) == int(nearest_distance)
    )
    if len(nearest_rows) != 1:
        logger.info(
            "detached %s evidence abstained: func=0x%X target=0x%X "
            "owned_ranges=%s detached_ranges=%s conditional_rows=%s "
            "conditional_debug=%s terminal_exits=%s contains_calls=%s "
            "calls_verify_safe=%s",
            template_kind,
            int(function_ea),
            int(target_ea),
            template.owned_ranges,
            tuple((hex(start), hex(end)) for start, end in detached_ranges),
            [
                (
                    f"blk{source_serial}@0x{native_entry_by_serial[source_serial]:X}",
                    hex(branch_ea),
                    [hex(ea) for ea in targets],
                    distance_by_serial.get(source_serial),
                )
                for source_serial, branch_ea, targets in conditional_rows
            ],
            conditional_debug_rows,
            [hex(ea) for ea in sorted(terminal_exit_eas)],
            bool(contains_calls),
            bool(calls_verify_safe),
        )
        return None
    _distance, _source_serial, branch_ea, branch_targets = nearest_rows[0]
    return DetachedSnippetReplacementEvidence(
        target_ea=int(target_ea),
        conditional_branch_ea=int(branch_ea),
        conditional_target_eas=branch_targets,
        terminal_exit_eas=tuple(sorted(terminal_exit_eas)),
        calls_verify_safe=bool(calls_verify_safe),
        contains_calls=bool(contains_calls),
    )


def detached_snippet_replacement_evidence(
    function_ea: int,
    target_ea: int,
) -> DetachedSnippetReplacementEvidence | None:
    """Summarize one analyzed CALLS replacement template."""
    template = _DETACHED_REPLACEMENT_SNIPPET_TEMPLATES.get(
        (int(function_ea), int(target_ea))
    )
    if template is None:
        return None
    return _detached_snippet_conditional_evidence_from_template(
        function_ea,
        target_ea,
        template,
        template_kind="replacement",
    )


def detached_snippet_conditional_evidence(
    function_ea: int,
    target_ea: int,
) -> DetachedSnippetReplacementEvidence | None:
    """Summarize one regular LOCOPT template's exact conditional topology."""
    template = _DETACHED_SNIPPET_TEMPLATES.get((int(function_ea), int(target_ea)))
    if template is None:
        return None
    return _detached_snippet_conditional_evidence_from_template(
        function_ea,
        target_ea,
        template,
        template_kind="conditional",
    )


def _template_last_immediate_state_write(
    instructions: tuple[object, ...],
    *,
    state_register: int,
    inherited_state: int | None,
) -> int | None:
    state = inherited_state
    for instruction in instructions:
        if int(instruction.d.t) != int(ida_hexrays.mop_r) or int(
            instruction.d.r
        ) != int(state_register):
            continue
        if int(instruction.opcode) != int(ida_hexrays.m_mov) or int(
            instruction.l.t
        ) != int(ida_hexrays.mop_n):
            return None
        state = int(instruction.l.nnn.value) & 0xFFFFFFFF
    return state


def _template_writes_state_register(
    instructions: tuple[object, ...],
    *,
    state_register: int,
) -> bool:
    return any(
        int(instruction.d.t) == int(ida_hexrays.mop_r)
        and int(instruction.d.r) == int(state_register)
        for instruction in instructions
    )


def _template_inherited_state_at_block(
    template: DetachedSnippetTemplate,
    block: DetachedSnippetBlockTemplate,
    instructions: tuple[object, ...],
    *,
    state_register: int,
) -> int | None:
    """Find an exact state along the block's unique predecessor corridor."""
    state = _template_last_immediate_state_write(
        instructions,
        state_register=int(state_register),
        inherited_state=None,
    )
    if state is not None:
        return int(state)
    if _template_writes_state_register(
        instructions,
        state_register=int(state_register),
    ):
        return None

    blocks_by_serial = {
        int(candidate.source_serial): candidate for candidate in template.blocks
    }
    predecessors: dict[int, list[int]] = {}
    for candidate in template.blocks:
        for successor_serial in candidate.successor_serials:
            predecessors.setdefault(int(successor_serial), []).append(
                int(candidate.source_serial)
            )

    current_serial = int(block.source_serial)
    visited = {current_serial}
    while True:
        predecessor_serials = predecessors.get(current_serial, [])
        if len(predecessor_serials) != 1:
            return None
        predecessor_serial = int(predecessor_serials[0])
        if predecessor_serial in visited:
            return None
        visited.add(predecessor_serial)
        predecessor = blocks_by_serial.get(predecessor_serial)
        if predecessor is None:
            return None
        state = _template_last_immediate_state_write(
            predecessor.instructions,
            state_register=int(state_register),
            inherited_state=None,
        )
        if state is not None:
            return int(state)
        if _template_writes_state_register(
            predecessor.instructions,
            state_register=int(state_register),
        ):
            return None
        current_serial = predecessor_serial


def _template_owned_range_for_ea(
    template: DetachedSnippetTemplate,
    ea: int,
) -> tuple[int, int] | None:
    matches = tuple(
        (int(start), int(end))
        for start, end in template.owned_ranges
        if int(start) <= int(ea) < int(end)
    )
    return matches[0] if len(matches) == 1 else None


def _template_range_instructions(
    template: DetachedSnippetTemplate,
    owned_range: tuple[int, int],
    *,
    before_ea: int | None = None,
) -> tuple[object, ...]:
    start_ea, end_ea = owned_range
    instructions: list[object] = []
    for block in sorted(
        template.blocks,
        key=lambda candidate: (
            int(candidate.native_entry_ea),
            int(candidate.source_serial),
        ),
    ):
        for instruction in block.instructions:
            instruction_ea = int(instruction.ea)
            if not int(start_ea) <= instruction_ea < int(end_ea):
                continue
            if before_ea is not None and instruction_ea >= int(before_ea):
                continue
            instructions.append(instruction)
    return tuple(instructions)


def _template_cross_maturity_arm_states(
    template: DetachedSnippetTemplate,
    *,
    state_register: int,
    conditional_branch_ea: int,
    conditional_target_eas: tuple[int, int],
) -> tuple[int, int] | None:
    """Join a suppressed predicate to LOCOPT arm-local state writes."""
    if len(conditional_target_eas) != 2 or int(conditional_target_eas[0]) == int(
        conditional_target_eas[1]
    ):
        return None
    branch_range = _template_owned_range_for_ea(
        template,
        int(conditional_branch_ea),
    )
    arm_ranges = tuple(
        _template_owned_range_for_ea(template, int(target_ea))
        for target_ea in conditional_target_eas
    )
    if (
        branch_range is None
        or any(owned_range is None for owned_range in arm_ranges)
        or arm_ranges[0] == arm_ranges[1]
    ):
        return None
    inherited_instructions = _template_range_instructions(
        template,
        branch_range,
        before_ea=int(conditional_branch_ea),
    )
    inherited_state = _template_last_immediate_state_write(
        inherited_instructions,
        state_register=int(state_register),
        inherited_state=None,
    )
    if inherited_state is None:
        return None
    arm_states: list[int] = []
    for owned_range in arm_ranges:
        if owned_range is None:
            return None
        instructions = _template_range_instructions(template, owned_range)
        state = _template_last_immediate_state_write(
            instructions,
            state_register=int(state_register),
            inherited_state=int(inherited_state),
        )
        if state is None:
            return None
        arm_states.append(int(state))
    if len(arm_states) != 2 or arm_states[0] == arm_states[1]:
        return None
    return arm_states[0], arm_states[1]


def detached_snippet_replacement_arm_states(
    function_ea: int,
    target_ea: int,
    *,
    state_register: int,
    conditional_branch_ea: int,
    conditional_target_eas: tuple[int, int],
) -> tuple[int, int] | None:
    """Recover ``(fallthrough, taken)`` states from the LOCOPT template.

    CALLS may fold an arm-local state write after resolving the shared
    dispatcher corridor.  The earlier LOCOPT template retains that write.  The
    branch identity and successor ordering must still be exact and unambiguous.
    """
    template = _DETACHED_SNIPPET_TEMPLATES.get((int(function_ea), int(target_ea)))
    if template is None:
        return None
    candidates = tuple(
        block
        for block in template.blocks
        if len(block.successor_serials) == 2
        and block.instructions
        and int(block.instructions[-1].ea) == int(conditional_branch_ea)
        and ida_hexrays.is_mcode_jcond(int(block.instructions[-1].opcode))
        and int(block.instructions[-1].d.t) == int(ida_hexrays.mop_b)
        and int(block.instructions[-1].d.b)
        in {int(serial) for serial in block.successor_serials}
    )
    if not candidates:
        cross_maturity_states = _template_cross_maturity_arm_states(
            template,
            state_register=int(state_register),
            conditional_branch_ea=int(conditional_branch_ea),
            conditional_target_eas=conditional_target_eas,
        )
        if cross_maturity_states is not None:
            return cross_maturity_states
    if len(candidates) != 1:
        logger.info(
            "detached replacement arm-state abstained: func=0x%X target=0x%X "
            "predicate=0x%X reason=predicate_candidates count=%d topology=%s",
            int(function_ea),
            int(target_ea),
            int(conditional_branch_ea),
            len(candidates),
            [
                (
                    "blk%d@0x%X"
                    % (int(candidate.source_serial), int(candidate.native_entry_ea)),
                    tuple(int(serial) for serial in candidate.successor_serials),
                    tuple(
                        (
                            hex(int(instruction.ea)),
                            int(instruction.opcode),
                            int(instruction.d.t),
                            (
                                int(instruction.d.b)
                                if int(instruction.d.t) == int(ida_hexrays.mop_b)
                                else None
                            ),
                        )
                        for instruction in candidate.instructions
                    ),
                )
                for candidate in template.blocks
            ],
        )
        return None
    branch_block = candidates[0]
    inherited_state = _template_inherited_state_at_block(
        template,
        branch_block,
        branch_block.instructions[:-1],
        state_register=int(state_register),
    )
    if inherited_state is None:
        logger.info(
            "detached replacement arm-state abstained: func=0x%X target=0x%X "
            "predicate=0x%X reason=inherited_state topology=%s",
            int(function_ea),
            int(target_ea),
            int(conditional_branch_ea),
            [
                (
                    "blk%d@0x%X"
                    % (int(candidate.source_serial), int(candidate.native_entry_ea)),
                    tuple(int(serial) for serial in candidate.successor_serials),
                    tuple(
                        hex(int(instruction.ea))
                        for instruction in candidate.instructions
                    ),
                )
                for candidate in template.blocks
            ],
        )
        return None
    blocks_by_serial = {int(block.source_serial): block for block in template.blocks}
    taken_serial = int(branch_block.instructions[-1].d.b)
    fallthrough_serials = tuple(
        int(serial)
        for serial in branch_block.successor_serials
        if int(serial) != taken_serial
    )
    if len(fallthrough_serials) != 1:
        return None
    arm_states: list[int] = []
    for successor_serial in (int(fallthrough_serials[0]), taken_serial):
        successor = blocks_by_serial.get(int(successor_serial))
        if successor is None:
            logger.info(
                "detached replacement arm-state abstained: func=0x%X target=0x%X "
                "predicate=0x%X reason=missing_successor serial=%d",
                int(function_ea),
                int(target_ea),
                int(conditional_branch_ea),
                int(successor_serial),
            )
            return None
        state = _template_last_immediate_state_write(
            successor.instructions,
            state_register=int(state_register),
            inherited_state=int(inherited_state),
        )
        if state is None:
            logger.info(
                "detached replacement arm-state abstained: func=0x%X target=0x%X "
                "predicate=0x%X reason=arm_state successor=blk%d@0x%X",
                int(function_ea),
                int(target_ea),
                int(conditional_branch_ea),
                int(successor.source_serial),
                int(successor.native_entry_ea),
            )
            return None
        arm_states.append(int(state))
    if len(arm_states) != 2 or arm_states[0] == arm_states[1]:
        logger.info(
            "detached replacement arm-state abstained: func=0x%X target=0x%X "
            "predicate=0x%X reason=non_distinct states=%s",
            int(function_ea),
            int(target_ea),
            int(conditional_branch_ea),
            [hex(int(state)) for state in arm_states],
        )
        return None
    return arm_states[0], arm_states[1]


def _rebase_template_operand(
    mba: object,
    operand: object,
    main_vd_by_source_vd: dict[int, int],
) -> bool:
    for current in _walk_operand_tree(operand):
        if int(current.t) != int(ida_hexrays.mop_S):
            continue
        source_vd = int(current.s.off)
        main_vd = main_vd_by_source_vd.get(source_vd)
        if main_vd is None:
            return False
        size = int(current.size)
        current.make_stkvar(mba, int(main_vd))
        current.size = size
    return True


def _destination_stack_map(
    mba: object,
    template: DetachedSnippetTemplate,
) -> dict[int, int]:
    """Map raw template VD offsets into the live MBA's positive VD space."""
    live_vd_base = int(mba.stkoff_ida2vd(0))
    return {
        int(source_vd): int(source_vd) + live_vd_base
        for source_vd, _ida_offset in template.stack_vd_to_ida
    }


def _stable_destination_stack_map(
    mba: object,
    template: DetachedSnippetTemplate,
) -> dict[int, int]:
    """Map template VD offsets through exact IDA frame identities."""
    return {
        int(source_vd): int(mba.stkoff_ida2vd(int(ida_offset)))
        for source_vd, ida_offset in template.stable_stack_vd_to_ida
    }


def _instruction_destination_stack_map(
    mba: object,
    template: DetachedSnippetTemplate | None,
    instruction_ea: int,
) -> dict[int, int]:
    """Map one native instruction's stack operands by owning-frame identity.

    Detached explicit-range MBAs can reuse one VD offset before and after a
    native stack-pointer adjustment.  The native instruction EA therefore
    participates in the identity; a template-wide ``VD -> IDA`` map is only a
    valid fallback when every occurrence agrees.
    """
    if template is None:
        return {}
    return {
        int(source_vd): int(mba.stkoff_ida2vd(int(ida_offset)))
        for native_ea, source_vd, ida_offset in template.instruction_stack_vd_to_ida
        if int(native_ea) == int(instruction_ea)
    }


def _stack_map_with_positive_identity_overrides(
    fallback: dict[int, int],
    preferred: dict[int, int],
) -> dict[int, int]:
    """Overlay verifier-valid persistent identities onto the legacy map."""
    result = dict(fallback)
    result.update(
        {
            int(source_vd): int(destination_vd)
            for source_vd, destination_vd in preferred.items()
            if int(destination_vd) > 0
        }
    )
    return result


def _template_vd_to_ida_delta(
    template: DetachedSnippetTemplate,
) -> int | None:
    deltas = {
        int(ida_offset) - int(source_vd)
        for source_vd, ida_offset in template.stack_vd_to_ida
    }
    if len(deltas) != 1:
        return None
    return next(iter(deltas))


def _analyzed_destination_stack_map(
    mba: object,
    raw_template: DetachedSnippetTemplate,
    analyzed_template: DetachedSnippetTemplate | None,
) -> dict[int, int]:
    """Translate CALLS VD offsets through the raw template's frame identity."""
    if analyzed_template is None:
        return {}
    raw_destination = _destination_stack_map(mba, raw_template)
    destination_by_ida = {
        int(ida_offset): raw_destination[int(source_vd)]
        for source_vd, ida_offset in raw_template.stack_vd_to_ida
    }
    raw_delta = _template_vd_to_ida_delta(raw_template)
    analyzed_delta = _template_vd_to_ida_delta(analyzed_template)
    live_vd_base = int(mba.stkoff_ida2vd(0))
    result: dict[int, int] = {}
    for source_vd, ida_offset in analyzed_template.stack_vd_to_ida:
        destination_vd = destination_by_ida.get(int(ida_offset))
        if destination_vd is None:
            if raw_delta is None or analyzed_delta is None:
                continue
            equivalent_raw_vd = int(source_vd) + int(analyzed_delta) - int(raw_delta)
            destination_vd = equivalent_raw_vd + live_vd_base
        result[int(source_vd)] = int(destination_vd)
    return result


def _remap_template_block_refs(
    instruction: object,
    serial_map: dict[int, int],
    external_map: dict[int, int],
) -> bool:
    for operand in _instruction_operands(instruction):
        if int(operand.t) != int(ida_hexrays.mop_b):
            continue
        source_serial = int(operand.b)
        target_serial = serial_map.get(source_serial)
        if target_serial is None:
            target_serial = external_map.get(source_serial)
        if target_serial is None:
            return False
        operand.make_blkref(int(target_serial))
    return True


@dataclass(frozen=True, slots=True)
class _BoundaryPortBlockBinding:
    native_ea: int
    imported_key: tuple[int, int] | None = None
    live_block: object | None = None


def _boundary_port_binding_identity(
    binding: _BoundaryPortBlockBinding,
) -> tuple[tuple[int, int] | None, int | None]:
    """Return an identity stable across fresh SWIG block proxies."""
    return (
        binding.imported_key,
        (None if binding.live_block is None else int(binding.live_block.serial)),
    )


@dataclass(frozen=True, slots=True)
class _DirectBoundaryPortMutation:
    records: tuple[DetachedSnippetTemplateDirectBoundaryPort, ...]
    endpoint: _BoundaryPortBlockBinding
    old_targets: tuple[_BoundaryPortBlockBinding, ...]
    target: _BoundaryPortBlockBinding


@dataclass(frozen=True, slots=True)
class _ConditionalBoundaryPortMutation:
    record: DetachedSnippetTemplateConditionalBoundaryPort
    source: _BoundaryPortBlockBinding
    old_taken_target: _BoundaryPortBlockBinding | None
    old_fallthrough_target: _BoundaryPortBlockBinding | None
    taken_target: _BoundaryPortBlockBinding
    fallthrough_target: _BoundaryPortBlockBinding
    restore_pruned_source: bool = False
    materialize_logical_source: bool = False


@dataclass(frozen=True, slots=True)
class _BoundaryPortMutationBatch:
    direct: tuple[_DirectBoundaryPortMutation, ...]
    conditional: tuple[_ConditionalBoundaryPortMutation, ...]


@dataclass(frozen=True, slots=True)
class _ImportedTerminalReturnCarrierInsertion:
    """One carrier bound to the exact imported terminal arm it protects."""

    template: _TerminalReturnCarrierTemplate
    target: _BoundaryPortBlockBinding
    target_block: object
    owner_target_ea: int
    already_present: bool = False


def _boundary_port_result(
    record: DetachedSnippetTemplateDirectBoundaryPort
    | DetachedSnippetTemplateConditionalBoundaryPort,
    *,
    reason: str | None = None,
) -> DetachedSnippetBoundaryPortResult:
    port = record.port
    if isinstance(record, DetachedSnippetTemplateDirectBoundaryPort):
        return DetachedSnippetBoundaryPortResult(
            source_block_ea=int(port.source_block_ea),
            source_instruction_ea=int(port.source_instruction_ea),
            endpoint_block_ea=int(port.endpoint_block_ea),
            target_eas=(int(port.target_ea),),
            reason=reason,
        )
    return DetachedSnippetBoundaryPortResult(
        source_block_ea=int(port.source_block_ea),
        source_instruction_ea=int(port.predicate_ea),
        endpoint_block_ea=int(port.source_block_ea),
        target_eas=(
            int(port.taken_target_ea),
            int(port.fallthrough_target_ea),
        ),
        reason=reason,
    )


def _all_template_boundary_port_records(
    selected: tuple[DetachedSnippetTemplate, ...],
) -> tuple[
    DetachedSnippetTemplateDirectBoundaryPort
    | DetachedSnippetTemplateConditionalBoundaryPort,
    ...,
]:
    return tuple(
        record
        for template in selected
        for record in (
            *template.boundary_ports.direct,
            *template.boundary_ports.conditional,
        )
    )


def _empty_import_result_for_boundary_ports(
    selected: tuple[DetachedSnippetTemplate, ...],
    reason: str,
) -> DetachedSnippetImportResult:
    return DetachedSnippetImportResult(
        roots=(),
        abstained_boundary_ports=tuple(
            _boundary_port_result(record, reason=reason)
            for record in _all_template_boundary_port_records(selected)
        ),
    )


def _template_block_by_serial(
    template: DetachedSnippetTemplate,
    source_serial: int,
) -> DetachedSnippetBlockTemplate | None:
    matches = tuple(
        block
        for block in template.blocks
        if int(block.source_serial) == int(source_serial)
    )
    return matches[0] if len(matches) == 1 else None


def _template_successor_eas(
    template: DetachedSnippetTemplate,
    block: DetachedSnippetBlockTemplate,
) -> tuple[int, ...] | None:
    result: list[int] = []
    for successor_serial, external_ea in zip(
        block.successor_serials,
        block.external_successor_eas,
    ):
        if int(external_ea) > 0:
            result.append(int(external_ea))
            continue
        successor = _template_block_by_serial(template, int(successor_serial))
        if successor is None:
            return None
        result.append(int(successor.native_entry_ea))
    return tuple(result)


def _template_conditional_taken_ea(
    template: DetachedSnippetTemplate,
    block: DetachedSnippetBlockTemplate,
) -> int | None:
    if not block.instructions:
        return None
    tail = block.instructions[-1]
    if not ida_hexrays.is_mcode_jcond(int(tail.opcode)) or int(tail.d.t) != int(
        ida_hexrays.mop_b
    ):
        return None
    target_serial = int(tail.d.b)
    target = _template_block_by_serial(template, target_serial)
    if target is not None:
        return int(target.native_entry_ea)
    external_targets = {
        int(external_ea)
        for successor_serial, external_ea in zip(
            block.successor_serials,
            block.external_successor_eas,
        )
        if int(successor_serial) == target_serial and int(external_ea) > 0
    }
    return next(iter(external_targets)) if len(external_targets) == 1 else None


def _live_successor_eas(mba: object, block: object) -> tuple[int, ...] | None:
    result: list[int] = []
    for successor_serial in block.succset:
        successor = mba.get_mblock(int(successor_serial))
        successor_ea = None if successor is None else _unique_block_native_ea(successor)
        if successor_ea is None:
            return None
        result.append(int(successor_ea))
    return tuple(result)


def _live_conditional_taken_ea(mba: object, block: object) -> int | None:
    tail = block.tail
    if (
        tail is None
        or not ida_hexrays.is_mcode_jcond(int(tail.opcode))
        or int(tail.d.t) != int(ida_hexrays.mop_b)
    ):
        return None
    target = mba.get_mblock(int(tail.d.b))
    return None if target is None else _unique_block_native_ea(target)


def _conditional_fallthrough_serial(block: object) -> int | None:
    tail = block.tail
    if (
        tail is None
        or int(block.nsucc()) != 2
        or not ida_hexrays.is_mcode_jcond(int(tail.opcode))
        or int(tail.d.t) != int(ida_hexrays.mop_b)
    ):
        return None
    conditional_target = int(tail.d.b)
    fallthroughs = tuple(
        int(successor)
        for successor in block.succset
        if int(successor) != conditional_target
    )
    return fallthroughs[0] if len(fallthroughs) == 1 else None


def _preflight_boundary_port_batch(
    mba: object,
    selected: tuple[DetachedSnippetTemplate, ...],
) -> _BoundaryPortMutationBatch | None:
    imported_by_ea: dict[int, list[tuple[int, int]]] = {}
    template_by_target = {int(template.target_ea): template for template in selected}
    for template in selected:
        for block in template.blocks:
            imported_by_ea.setdefault(int(block.native_entry_ea), []).append(
                (int(template.target_ea), int(block.source_serial))
            )

    def bind(
        owner: DetachedSnippetBoundaryPortOwner,
        native_ea: int,
        *,
        template: DetachedSnippetTemplate,
        template_serial: int | None,
        exact_instruction_ea: int | None = None,
    ) -> _BoundaryPortBlockBinding | None:
        if owner == DetachedSnippetBoundaryPortOwner.IMPORTED:
            if template_serial is None:
                return None
            block = _template_block_by_serial(template, int(template_serial))
            instruction_eas = (
                ()
                if block is None
                else tuple(int(instruction.ea) for instruction in block.instructions)
            )
            if block is None or (
                int(block.native_entry_ea) != int(native_ea)
                and (
                    exact_instruction_ea is None
                    or int(exact_instruction_ea) not in instruction_eas
                )
            ):
                return None
            return _BoundaryPortBlockBinding(
                native_ea=int(native_ea),
                imported_key=(int(template.target_ea), int(template_serial)),
            )
        live = find_unique_live_block_by_ea(
            mba,
            int(native_ea),
            exact_instruction_ea=exact_instruction_ea,
        )
        if live is None:
            return None
        return _BoundaryPortBlockBinding(
            native_ea=int(native_ea),
            live_block=live,
        )

    def bind_existing(native_ea: int) -> _BoundaryPortBlockBinding | None:
        imported = imported_by_ea.get(int(native_ea), ())
        if len(imported) > 1:
            return None
        if len(imported) == 1:
            return _BoundaryPortBlockBinding(
                native_ea=int(native_ea),
                imported_key=imported[0],
            )
        live = find_unique_live_block_by_ea(mba, int(native_ea))
        if live is None:
            return None
        return _BoundaryPortBlockBinding(
            native_ea=int(native_ea),
            live_block=live,
        )

    direct_candidates: dict[
        tuple[str, int, int],
        list[
            tuple[
                DetachedSnippetTemplateDirectBoundaryPort,
                DetachedSnippetTemplate,
                _BoundaryPortBlockBinding,
                _BoundaryPortBlockBinding,
                tuple[_BoundaryPortBlockBinding, ...],
            ]
        ],
    ] = {}
    conditional: list[_ConditionalBoundaryPortMutation] = []
    conditional_source_eas: set[int] = set()
    for template in selected:
        for record in template.boundary_ports.direct:
            port = record.port
            source = (
                bind(
                    port.source_owner,
                    int(port.source_block_ea),
                    template=template,
                    template_serial=record.source_serial,
                    exact_instruction_ea=port.source_instruction_ea,
                )
                if port.source_owner == DetachedSnippetBoundaryPortOwner.IMPORTED
                else (
                    _BoundaryPortBlockBinding(
                        native_ea=int(port.source_block_ea),
                        live_block=source_block,
                    )
                    if (
                        source_block := find_unique_live_block_by_ea(
                            mba,
                            int(port.source_instruction_ea),
                        )
                    )
                    is not None
                    else None
                )
            )
            endpoint = bind(
                port.endpoint_owner,
                int(port.endpoint_block_ea),
                template=template,
                template_serial=record.endpoint_serial,
                exact_instruction_ea=(
                    port.source_instruction_ea
                    if port.delivery_mode == "terminal_goto"
                    and int(port.endpoint_block_ea) == int(port.source_block_ea)
                    else None
                ),
            )
            target = bind(
                port.target_owner,
                int(port.target_ea),
                template=template,
                template_serial=record.target_serial,
            )
            old_successor_serials = (
                record.old_successor_serials
                if len(record.old_successor_serials) == len(port.old_successor_eas)
                else (None,) * len(port.old_successor_eas)
            )
            explicit_old_owners = (
                port.old_successor_owners
                if len(port.old_successor_owners) == len(port.old_successor_eas)
                else (None,) * len(port.old_successor_eas)
            )
            old_target_rows = tuple(
                (
                    int(old_ea),
                    (
                        bind(
                            old_owner,
                            int(old_ea),
                            template=template,
                            template_serial=(
                                int(old_serial) if old_serial is not None else None
                            ),
                        )
                        if old_owner is not None
                        else (
                            bind(
                                DetachedSnippetBoundaryPortOwner.IMPORTED,
                                int(old_ea),
                                template=template,
                                template_serial=int(old_serial),
                            )
                            if old_serial is not None
                            else bind_existing(int(old_ea))
                        )
                    ),
                )
                for old_ea, old_serial, old_owner in zip(
                    port.old_successor_eas,
                    old_successor_serials,
                    explicit_old_owners,
                )
            )
            old_targets = tuple(
                binding for _, binding in old_target_rows if binding is not None
            )
            if source is None or endpoint is None or target is None:
                logger.info(
                    "detached snippet boundary-port preflight abstained: "
                    "kind=direct source=0x%X instruction=0x%X "
                    "endpoint=0x%X target=0x%X source_bound=%s "
                    "endpoint_bound=%s target_bound=%s missing_old=%s "
                    "reason=direct_binding",
                    int(port.source_block_ea),
                    int(port.source_instruction_ea),
                    int(port.endpoint_block_ea),
                    int(port.target_ea),
                    source is not None,
                    endpoint is not None,
                    target is not None,
                    [
                        f"0x{int(old_ea):X}"
                        for old_ea, binding in old_target_rows
                        if binding is None
                    ],
                )
                return None
            if endpoint.imported_key is not None:
                endpoint_template = template_by_target[int(endpoint.imported_key[0])]
                endpoint_block = _template_block_by_serial(
                    endpoint_template,
                    int(endpoint.imported_key[1]),
                )
                successor_eas = (
                    None
                    if endpoint_block is None
                    else _template_successor_eas(
                        endpoint_template,
                        endpoint_block,
                    )
                )
                endpoint_tail_is_call = bool(
                    endpoint_block is not None
                    and endpoint_block.instructions
                    and int(endpoint_block.instructions[-1].opcode)
                    in {
                        int(ida_hexrays.m_call),
                        int(ida_hexrays.m_icall),
                    }
                )
            else:
                successor_eas = _live_successor_eas(mba, endpoint.live_block)
                endpoint_tail_is_call = bool(
                    endpoint.live_block is not None
                    and endpoint.live_block.tail is not None
                    and int(endpoint.live_block.tail.opcode)
                    in {
                        int(ida_hexrays.m_call),
                        int(ida_hexrays.m_icall),
                    }
                )
            old_successors = {int(ea) for ea in port.old_successor_eas}
            pruned_live_frontier = (
                endpoint.imported_key is None
                and successor_eas == ()
                and bool(old_successors)
                and port.delivery_mode == "redirect_edge"
            )
            if not pruned_live_frontier and len(old_targets) != len(
                port.old_successor_eas
            ):
                logger.info(
                    "detached snippet boundary-port preflight abstained: "
                    "kind=direct source=0x%X instruction=0x%X "
                    "endpoint=0x%X target=0x%X missing_old=%s "
                    "reason=direct_binding",
                    int(port.source_block_ea),
                    int(port.source_instruction_ea),
                    int(port.endpoint_block_ea),
                    int(port.target_ea),
                    [
                        f"0x{int(old_ea):X}"
                        for old_ea, binding in old_target_rows
                        if binding is None
                    ],
                )
                return None
            if (
                successor_eas is None
                or (
                    old_successors
                    and not old_successors.issubset({int(ea) for ea in successor_eas})
                    and not pruned_live_frontier
                )
                or (
                    not old_successors
                    and port.delivery_mode not in {"terminal_goto", "preserve_call"}
                )
                or (port.delivery_mode == "preserve_call" and not endpoint_tail_is_call)
            ):
                logger.info(
                    "detached snippet boundary-port preflight abstained: "
                    "kind=direct source=0x%X instruction=0x%X "
                    "endpoint=0x%X expected_old=%s actual=%s "
                    "delivery=%s reason=direct_topology",
                    int(port.source_block_ea),
                    int(port.source_instruction_ea),
                    int(port.endpoint_block_ea),
                    [f"0x{ea:X}" for ea in sorted(old_successors)],
                    None
                    if successor_eas is None
                    else [f"0x{int(ea):X}" for ea in successor_eas],
                    port.delivery_mode,
                )
                return None
            endpoint_key = (
                "imported" if endpoint.imported_key is not None else "live",
                int(endpoint.imported_key[0])
                if endpoint.imported_key is not None
                else int(endpoint.live_block.serial),
                int(endpoint.imported_key[1])
                if endpoint.imported_key is not None
                else 0,
            )
            direct_candidates.setdefault(endpoint_key, []).append(
                (record, template, endpoint, target, old_targets)
            )

        for record in template.boundary_ports.conditional:
            port = record.port
            source = bind(
                port.source_owner,
                int(port.source_block_ea),
                template=template,
                template_serial=record.source_serial,
                exact_instruction_ea=port.predicate_ea,
            )
            logical_source_complete = (
                port.source_owner == DetachedSnippetBoundaryPortOwner.LIVE
                and port.logical_source_anchor_ea is not None
                and int(port.logical_source_anchor_ea) > 0
                and port.predicate_ida_stkoff is not None
                and port.predicate_size is not None
                and int(port.predicate_size) > 0
                and port.condition_code in (4, 5)
            )
            materialize_logical_source = False
            if source is None and logical_source_complete:
                assert port.logical_source_anchor_ea is not None
                source = bind(
                    DetachedSnippetBoundaryPortOwner.LIVE,
                    int(port.logical_source_anchor_ea),
                    template=template,
                    template_serial=None,
                    exact_instruction_ea=int(port.logical_source_anchor_ea),
                )
                materialize_logical_source = source is not None
            taken_target = bind(
                port.taken_target_owner,
                int(port.taken_target_ea),
                template=template,
                template_serial=record.taken_target_serial,
            )
            fallthrough_target = bind(
                port.fallthrough_target_owner,
                int(port.fallthrough_target_ea),
                template=template,
                template_serial=record.fallthrough_target_serial,
            )
            old_taken_target = (
                None
                if port.old_taken_target_ea is None
                else (
                    bind(
                        port.old_taken_target_owner,
                        int(port.old_taken_target_ea),
                        template=template,
                        template_serial=None,
                    )
                    if port.old_taken_target_owner is not None
                    else bind_existing(int(port.old_taken_target_ea))
                )
            )
            old_fallthrough_target = (
                None
                if port.old_fallthrough_target_ea is None
                else (
                    bind(
                        port.old_fallthrough_target_owner,
                        int(port.old_fallthrough_target_ea),
                        template=template,
                        template_serial=None,
                    )
                    if port.old_fallthrough_target_owner is not None
                    else bind_existing(int(port.old_fallthrough_target_ea))
                )
            )
            distinct_bindings = (
                source is not None
                and taken_target is not None
                and fallthrough_target is not None
                and _boundary_port_binding_identity(source)
                not in {
                    _boundary_port_binding_identity(taken_target),
                    _boundary_port_binding_identity(fallthrough_target),
                }
                and _boundary_port_binding_identity(taken_target)
                != _boundary_port_binding_identity(fallthrough_target)
            )
            if (
                source is None
                or taken_target is None
                or fallthrough_target is None
                or int(port.taken_target_ea) == int(port.fallthrough_target_ea)
                or not distinct_bindings
            ):
                logger.info(
                    "detached snippet boundary-port preflight abstained: "
                    "kind=conditional source=0x%X predicate=0x%X "
                    "old_taken=%s old_fallthrough=%s "
                    "taken=0x%X fallthrough=0x%X source_bound=%s "
                    "old_taken_bound=%s old_fallthrough_bound=%s "
                    "taken_bound=%s fallthrough_bound=%s "
                    "logical_anchor=%s logical_bound=%s "
                    "reason=conditional_binding",
                    int(port.source_block_ea),
                    int(port.predicate_ea),
                    (
                        None
                        if port.old_taken_target_ea is None
                        else f"0x{int(port.old_taken_target_ea):X}"
                    ),
                    (
                        None
                        if port.old_fallthrough_target_ea is None
                        else f"0x{int(port.old_fallthrough_target_ea):X}"
                    ),
                    int(port.taken_target_ea),
                    int(port.fallthrough_target_ea),
                    source is not None,
                    old_taken_target is not None,
                    old_fallthrough_target is not None,
                    taken_target is not None,
                    fallthrough_target is not None,
                    (
                        None
                        if port.logical_source_anchor_ea is None
                        else f"0x{int(port.logical_source_anchor_ea):X}"
                    ),
                    materialize_logical_source,
                )
                return None
            if materialize_logical_source and (
                source.imported_key is not None
                or source.live_block is None
                or source.live_block.head is None
                or int(source.live_block.nsucc()) not in (0, 1)
            ):
                logger.info(
                    "detached snippet boundary-port preflight abstained: "
                    "kind=conditional source=0x%X predicate=0x%X "
                    "logical_anchor=0x%X nsucc=%s "
                    "reason=logical_source_shape",
                    int(port.source_block_ea),
                    int(port.predicate_ea),
                    int(port.logical_source_anchor_ea),
                    (
                        None
                        if source.live_block is None
                        else int(source.live_block.nsucc())
                    ),
                )
                return None
            if source.imported_key is not None:
                source_template = template_by_target[int(source.imported_key[0])]
                source_block = _template_block_by_serial(
                    source_template,
                    int(source.imported_key[1]),
                )
                successor_eas = (
                    None
                    if source_block is None
                    else _template_successor_eas(source_template, source_block)
                )
                taken_ea = (
                    None
                    if source_block is None
                    else _template_conditional_taken_ea(
                        source_template,
                        source_block,
                    )
                )
                tail_ea = (
                    None
                    if source_block is None or not source_block.instructions
                    else int(source_block.instructions[-1].ea)
                )
            else:
                successor_eas = _live_successor_eas(mba, source.live_block)
                taken_ea = _live_conditional_taken_ea(mba, source.live_block)
                tail_ea = (
                    None
                    if source.live_block.tail is None
                    else int(source.live_block.tail.ea)
                )
            pruned_live_conditional = (
                source.imported_key is None
                and source.live_block is not None
                and successor_eas == ()
                and source.live_block.tail is not None
                and ida_hexrays.is_mcode_jcond(int(source.live_block.tail.opcode))
                and tail_ea == int(port.predicate_ea)
            )
            if (
                not materialize_logical_source
                and not pruned_live_conditional
                and (
                    port.old_taken_target_ea is None
                    or port.old_fallthrough_target_ea is None
                    or old_taken_target is None
                    or old_fallthrough_target is None
                )
            ):
                logger.info(
                    "detached snippet boundary-port preflight abstained: "
                    "kind=conditional source=0x%X predicate=0x%X "
                    "old_taken=%s old_fallthrough=%s "
                    "reason=conditional_binding",
                    int(port.source_block_ea),
                    int(port.predicate_ea),
                    (
                        None
                        if port.old_taken_target_ea is None
                        else f"0x{int(port.old_taken_target_ea):X}"
                    ),
                    (
                        None
                        if port.old_fallthrough_target_ea is None
                        else f"0x{int(port.old_fallthrough_target_ea):X}"
                    ),
                )
                return None
            if (
                not materialize_logical_source
                and not pruned_live_conditional
                and (
                    port.old_taken_target_ea is None
                    or port.old_fallthrough_target_ea is None
                    or successor_eas is None
                    or len(successor_eas) != 2
                    or {int(ea) for ea in successor_eas}
                    != {
                        int(port.old_taken_target_ea),
                        int(port.old_fallthrough_target_ea),
                    }
                    or taken_ea != int(port.old_taken_target_ea)
                    or tail_ea != int(port.predicate_ea)
                )
            ):
                logger.info(
                    "detached snippet boundary-port preflight abstained: "
                    "kind=conditional source=0x%X predicate=0x%X "
                    "expected_old=[%s,%s] actual=%s taken=%s "
                    "tail=%s reason=conditional_topology",
                    int(port.source_block_ea),
                    int(port.predicate_ea),
                    (
                        None
                        if port.old_taken_target_ea is None
                        else f"0x{int(port.old_taken_target_ea):X}"
                    ),
                    (
                        None
                        if port.old_fallthrough_target_ea is None
                        else f"0x{int(port.old_fallthrough_target_ea):X}"
                    ),
                    None
                    if successor_eas is None
                    else [f"0x{int(ea):X}" for ea in successor_eas],
                    None if taken_ea is None else f"0x{int(taken_ea):X}",
                    None if tail_ea is None else f"0x{int(tail_ea):X}",
                )
                return None
            conditional_source_eas.add(int(source.native_ea))
            conditional.append(
                _ConditionalBoundaryPortMutation(
                    record=record,
                    source=source,
                    old_taken_target=old_taken_target,
                    old_fallthrough_target=old_fallthrough_target,
                    taken_target=taken_target,
                    fallthrough_target=fallthrough_target,
                    restore_pruned_source=pruned_live_conditional,
                    materialize_logical_source=materialize_logical_source,
                )
            )

    direct: list[_DirectBoundaryPortMutation] = []
    for rows in direct_candidates.values():
        target_keys = {
            _boundary_port_binding_identity(target)
            for _record, _template, _endpoint, target, _old_targets in rows
        }
        if len(target_keys) != 1:
            logger.info(
                "detached snippet boundary-port preflight abstained: "
                "kind=direct endpoint=0x%X targets=%s "
                "bindings=%s "
                "reason=direct_target_conflict",
                int(rows[0][2].native_ea),
                [f"0x{int(row[3].native_ea):X}" for row in rows],
                [
                    (
                        f"0x{int(row[0].port.source_block_ea):X}",
                        f"0x{int(row[0].port.source_instruction_ea):X}",
                        row[0].port.target_owner.value,
                        row[3].imported_key,
                        (
                            None
                            if row[3].live_block is None
                            else (
                                f"blk{int(row[3].live_block.serial)}"
                                f"@0x{int(row[3].native_ea):X}"
                            )
                        ),
                    )
                    for row in rows
                ],
            )
            return None
        records = tuple(row[0] for row in rows)
        endpoint = rows[0][2]
        target = rows[0][3]
        old_by_ea: dict[int, _BoundaryPortBlockBinding] = {}
        for _record, _template, _endpoint, _target, old_targets in rows:
            for old_target in old_targets:
                old_by_ea[int(old_target.native_ea)] = old_target
        if int(endpoint.native_ea) in conditional_source_eas:
            logger.info(
                "detached snippet boundary-port preflight abstained: "
                "kind=direct endpoint=0x%X reason=source_kind_conflict",
                int(endpoint.native_ea),
            )
            return None
        direct.append(
            _DirectBoundaryPortMutation(
                records=records,
                endpoint=endpoint,
                old_targets=tuple(old_by_ea[ea] for ea in sorted(old_by_ea)),
                target=target,
            )
        )
    return _BoundaryPortMutationBatch(
        direct=tuple(sorted(direct, key=lambda row: int(row.endpoint.native_ea))),
        conditional=tuple(
            sorted(
                conditional,
                key=lambda row: int(row.source.native_ea),
            )
        ),
    )


def _resolve_boundary_port_block(
    binding: _BoundaryPortBlockBinding,
    created: Mapping[tuple[int, int], object],
) -> object | None:
    if binding.imported_key is not None:
        return created.get(binding.imported_key)
    return binding.live_block


def _same_terminal_carrier_write(
    left: object,
    right: object,
) -> bool:
    return (
        int(left.opcode) == int(right.opcode)
        and left.l.equal_mops(right.l, int(ida_hexrays.EQ_IGNSIZE))
        and left.r.equal_mops(right.r, int(ida_hexrays.EQ_IGNSIZE))
        and left.d.equal_mops(right.d, int(ida_hexrays.EQ_IGNSIZE))
    )


def _preflight_imported_terminal_return_carriers(
    mba: object,
    function_ea: int,
    batch: _BoundaryPortMutationBatch,
    created: Mapping[tuple[int, int], object],
    pending_instruction_origins: Mapping[tuple[int, int], int],
) -> tuple[_ImportedTerminalReturnCarrierInsertion, ...] | None:
    """Bind each terminal port to one private imported return block.

    The conditional port and its captured ABI return assignment are one
    semantic transaction.  The carrier is selected by terminal identity, not
    by predicate EA: multiple native state writers can prove the same terminal
    route, while only one may still retain the early-maturity return write.
    """
    templates_by_identity: dict[
        tuple[int, int, int],
        list[_TerminalReturnCarrierTemplate],
    ] = {}
    for (
        owner_ea,
        _source_ea,
        _state,
    ), template in _TERMINAL_RETURN_CARRIER_TEMPLATES.items():
        if int(owner_ea) != int(function_ea):
            continue
        request = template.request
        identity = (
            int(request.terminal_target_ea),
            int(request.state_var_reg),
            int(request.state_constant) & 0xFFFFFFFF,
        )
        templates_by_identity.setdefault(identity, []).append(template)

    mba_identity = stable_mba_identity(mba)
    planned_by_target: dict[
        tuple[int, int],
        _ImportedTerminalReturnCarrierInsertion,
    ] = {}
    closing_opcodes = {
        int(ida_hexrays.m_call),
        int(ida_hexrays.m_icall),
        int(ida_hexrays.m_ext),
        int(ida_hexrays.m_goto),
        int(ida_hexrays.m_ijmp),
        int(ida_hexrays.m_jtbl),
        int(ida_hexrays.m_ret),
    }
    for mutation in batch.conditional:
        port = mutation.record.port
        if port.resolver_kind != "preopt_terminal_return_boundary":
            continue
        if port.state_register is None:
            logger.info(
                "detached snippet terminal carrier preflight abstained: "
                "predicate=0x%X reason=state_register_missing",
                int(port.predicate_ea),
            )
            return None
        terminal_arms = tuple(
            (target_ea, state, owner, binding)
            for target_ea, state, owner, binding in (
                (
                    port.taken_target_ea,
                    port.taken_state,
                    port.taken_target_owner,
                    mutation.taken_target,
                ),
                (
                    port.fallthrough_target_ea,
                    port.fallthrough_state,
                    port.fallthrough_target_owner,
                    mutation.fallthrough_target,
                ),
            )
            if state is not None
        )
        if len(terminal_arms) != 1:
            logger.info(
                "detached snippet terminal carrier preflight abstained: "
                "predicate=0x%X terminal_arms=%d reason=terminal_arm_identity",
                int(port.predicate_ea),
                len(terminal_arms),
            )
            return None
        terminal_target_ea, state_constant, owner, target_binding = terminal_arms[0]
        if (
            owner != DetachedSnippetBoundaryPortOwner.IMPORTED
            or target_binding.imported_key is None
        ):
            logger.info(
                "detached snippet terminal carrier preflight abstained: "
                "predicate=0x%X target=0x%X reason=terminal_arm_not_imported",
                int(port.predicate_ea),
                int(terminal_target_ea),
            )
            return None
        identity = (
            int(terminal_target_ea),
            int(port.state_register),
            int(state_constant) & 0xFFFFFFFF,
        )
        carrier_templates = templates_by_identity.get(identity, ())
        if len(carrier_templates) != 1:
            logger.info(
                "detached snippet terminal carrier preflight abstained: "
                "predicate=0x%X target=0x%X state=0x%X templates=%d "
                "reason=carrier_identity",
                int(port.predicate_ea),
                int(terminal_target_ea),
                int(state_constant) & 0xFFFFFFFF,
                len(carrier_templates),
            )
            return None
        template = carrier_templates[0]
        if not _is_stable_terminal_carrier_write(template.instruction):
            logger.info(
                "detached snippet terminal carrier preflight abstained: "
                "predicate=0x%X target=0x%X reason=carrier_drift",
                int(port.predicate_ea),
                int(terminal_target_ea),
            )
            return None
        target_block = _resolve_boundary_port_block(target_binding, created)
        if target_block is None:
            return None
        target_instructions = _instructions(target_block)
        target_native_origins = {
            int(native_ea)
            for instruction in target_instructions
            if (
                native_ea := pending_instruction_origins.get(
                    (mba_identity, int(instruction.ea))
                )
            )
            is not None
        }
        return_instructions = tuple(
            instruction
            for instruction in target_instructions
            if int(instruction.opcode) == int(ida_hexrays.m_ret)
        )
        source_block = _resolve_boundary_port_block(mutation.source, created)
        predecessor_serials = {int(serial) for serial in target_block.predset}
        allowed_predecessors = (
            set() if source_block is None else {int(source_block.serial)}
        )
        if (
            int(terminal_target_ea) not in target_native_origins
            or int(target_block.type) != int(ida_hexrays.BLT_0WAY)
            or int(target_block.nsucc()) != 0
            or len(return_instructions) != 1
            or not target_instructions
            or target_block.tail is None
            or int(target_instructions[-1].opcode) != int(ida_hexrays.m_ret)
            or int(target_block.tail.opcode) != int(ida_hexrays.m_ret)
            or any(
                int(instruction.opcode) in closing_opcodes
                or ida_hexrays.is_mcode_jcond(int(instruction.opcode))
                for instruction in target_instructions[:-1]
            )
            or not predecessor_serials.issubset(allowed_predecessors)
        ):
            logger.info(
                "detached snippet terminal carrier preflight abstained: "
                "predicate=0x%X target=blk%d@0x%X origins=%s preds=%s "
                "type=%d nsucc=%d returns=%d tail=%s reason=terminal_block_shape",
                int(port.predicate_ea),
                int(target_block.serial),
                int(terminal_target_ea),
                [f"0x{ea:X}" for ea in sorted(target_native_origins)],
                sorted(predecessor_serials),
                int(target_block.type),
                int(target_block.nsucc()),
                len(return_instructions),
                (None if target_block.tail is None else int(target_block.tail.opcode)),
            )
            return None
        return_writes = tuple(
            instruction
            for instruction in target_instructions
            if int(instruction.d.t) == int(ida_hexrays.mop_r)
            and int(instruction.d.r) == _return_mreg()
        )
        already_present = len(return_writes) == 1 and _same_terminal_carrier_write(
            return_writes[0],
            template.instruction,
        )
        if return_writes and not already_present:
            logger.info(
                "detached snippet terminal carrier preflight abstained: "
                "predicate=0x%X target=blk%d@0x%X "
                "reason=return_register_conflict",
                int(port.predicate_ea),
                int(target_block.serial),
                int(terminal_target_ea),
            )
            return None
        target_key = target_binding.imported_key
        insertion = _ImportedTerminalReturnCarrierInsertion(
            template=template,
            target=target_binding,
            target_block=target_block,
            owner_target_ea=int(target_key[0]),
            already_present=already_present,
        )
        previous = planned_by_target.setdefault(target_key, insertion)
        if previous != insertion:
            logger.info(
                "detached snippet terminal carrier preflight abstained: "
                "target=blk%d@0x%X reason=conflicting_terminal_carrier",
                int(target_block.serial),
                int(terminal_target_ea),
            )
            return None
    return tuple(planned_by_target[key] for key in sorted(planned_by_target))


def _apply_imported_terminal_return_carriers(
    mba: object,
    insertions: tuple[_ImportedTerminalReturnCarrierInsertion, ...],
    modifier: DeferredGraphModifier,
    pending_instruction_origins: dict[tuple[int, int], int],
    pending_owned_instruction_eas: dict[int, list[int]],
) -> int:
    mba_identity = stable_mba_identity(mba)
    changed = 0
    for insertion in insertions:
        if insertion.already_present:
            continue
        assignment = ida_hexrays.minsn_t(insertion.template.instruction)
        native_carrier_ea = int(assignment.ea)
        imported_carrier_ea = int(mba.alloc_fict_ea(int(mba.entry_ea) + 1))
        assignment.setaddr(imported_carrier_ea)
        target_instructions = _instructions(insertion.target_block)
        previous = target_instructions[-2] if len(target_instructions) > 1 else None
        modifier.insert_instruction_now(
            insertion.target_block,
            assignment,
            previous,
            mark_dirty=True,
        )
        pending_instruction_origins[(mba_identity, imported_carrier_ea)] = (
            native_carrier_ea
        )
        pending_owned_instruction_eas[insertion.owner_target_ea].append(
            imported_carrier_ea
        )
        request = insertion.template.request
        logger.info(
            "imported terminal return carrier restored: "
            "target=blk%d@0x%X carrier=0x%X imported_ea=0x%X state=0x%X",
            int(insertion.target_block.serial),
            int(request.terminal_target_ea),
            native_carrier_ea,
            imported_carrier_ea,
            int(request.state_constant) & 0xFFFFFFFF,
        )
        changed += 1
    return changed


def _apply_boundary_port_batch(
    mba: object,
    batch: _BoundaryPortMutationBatch,
    created: Mapping[tuple[int, int], object],
    *,
    transparent_helpers: Collection[object] = (),
    pending_instruction_origins: Mapping[tuple[int, int], int] | None = None,
) -> tuple[DetachedSnippetBoundaryPortResult, ...] | None:
    applied: list[DetachedSnippetBoundaryPortResult] = []
    instruction_origins = (
        {} if pending_instruction_origins is None else pending_instruction_origins
    )
    mba_identity = stable_mba_identity(mba)
    transparent_helper_serials = {int(block.serial) for block in transparent_helpers}
    for mutation in batch.direct:
        delivery_modes = {record.port.delivery_mode for record in mutation.records}
        if len(delivery_modes) != 1:
            return None
        delivery_mode = next(iter(delivery_modes))
        endpoint = _resolve_boundary_port_block(mutation.endpoint, created)
        target = _resolve_boundary_port_block(mutation.target, created)
        old_targets = tuple(
            _resolve_boundary_port_block(binding, created)
            for binding in mutation.old_targets
        )
        if (
            endpoint is None
            or target is None
            or any(old_target is None for old_target in old_targets)
        ):
            return None
        current_successors = {int(serial) for serial in endpoint.succset}
        old_successors = {
            int(old_target.serial)
            for old_target in old_targets
            if old_target is not None
        }
        edge_source_by_semantic_successor: dict[int, object] = {}
        for current_successor in current_successors:
            semantic_successor = int(current_successor)
            edge_source = endpoint
            if int(current_successor) in transparent_helper_serials:
                candidate = mba.get_mblock(int(current_successor))
                if (
                    candidate is not None
                    and int(candidate.type) == int(ida_hexrays.BLT_1WAY)
                    and int(candidate.nsucc()) == 1
                    and candidate.tail is not None
                    and int(candidate.tail.opcode) == int(ida_hexrays.m_goto)
                ):
                    semantic_successor = int(candidate.succset[0])
                    edge_source = candidate
            previous = edge_source_by_semantic_successor.setdefault(
                semantic_successor,
                edge_source,
            )
            if previous is not edge_source:
                return None
        semantic_successors = set(edge_source_by_semantic_successor)
        modifier = DeferredGraphModifier(mba)
        if delivery_mode == "terminal_goto" and not old_successors:
            source_instruction_eas = {
                int(record.port.source_instruction_ea)
                for record in mutation.records
            }
            if len(source_instruction_eas) != 1:
                return None
            source_instruction_ea = next(iter(source_instruction_eas))
            cut_instructions = tuple(
                instruction
                for instruction in _instructions(endpoint)
                if (
                    int(instruction.ea) == source_instruction_ea
                    or instruction_origins.get(
                        (mba_identity, int(instruction.ea))
                    )
                    == source_instruction_ea
                )
                and int(instruction.opcode)
                in {
                    int(ida_hexrays.m_mov),
                    int(ida_hexrays.m_call),
                    int(ida_hexrays.m_icall),
                    int(ida_hexrays.m_ijmp),
                }
            )
            logger.info(
                "resolver-cut call lowering preflight: "
                "endpoint=blk%d@0x%X instruction=0x%X "
                "ops=%s exact_calls=%d successors=%s target=blk%d@0x%X",
                int(endpoint.serial),
                int(mutation.endpoint.native_ea),
                source_instruction_ea,
                [
                    (
                        int(instruction.opcode),
                        int(instruction.ea),
                        instruction_origins.get(
                            (mba_identity, int(instruction.ea))
                        ),
                    )
                    for instruction in _instructions(endpoint)
                ],
                len(cut_instructions),
                sorted(current_successors),
                int(target.serial),
                int(mutation.target.native_ea),
            )
            if cut_instructions:
                if (
                    len(cut_instructions) != 1
                    or not modifier.lower_proven_indirect_transfer_to_goto_now(
                        endpoint,
                        target,
                        int(cut_instructions[0].ea),
                    )
                ):
                    return None
                applied.extend(
                    _boundary_port_result(record) for record in mutation.records
                )
                continue
        if not current_successors:
            restored = (
                modifier.restore_pruned_call_continuation_now(endpoint, target)
                if delivery_mode == "preserve_call"
                else modifier.restore_pruned_direct_now(endpoint, target)
            )
            if not restored:
                return None
            expected = 0
        elif not old_successors:
            if semantic_successors == {int(target.serial)}:
                expected = 0
            else:
                return None
        elif old_successors == semantic_successors:
            if len(semantic_successors) == 1:
                redirect_endpoint = edge_source_by_semantic_successor[
                    next(iter(semantic_successors))
                ]
                if not modifier.redirect_one_way_now(
                    int(redirect_endpoint.serial),
                    int(target.serial),
                    verify=False,
                ):
                    return None
                expected = 0
            elif len(current_successors) == 2:
                modifier.queue_convert_to_goto(
                    block_serial=int(endpoint.serial),
                    goto_target=int(target.serial),
                    description="collapse resolver routing predicate",
                )
                expected = 1
            else:
                return None
        elif len(semantic_successors) == 2 and old_successors.issubset(
            semantic_successors
        ):
            for old_target in old_targets:
                edge_source = edge_source_by_semantic_successor[int(old_target.serial)]
                if edge_source is endpoint:
                    modifier.queue_conditional_target_change(
                        block_serial=int(endpoint.serial),
                        old_target=int(old_target.serial),
                        new_target=int(target.serial),
                        description="redirect resolver routing arm",
                    )
                else:
                    modifier.queue_goto_change(
                        block_serial=int(edge_source.serial),
                        new_target=int(target.serial),
                        description=("redirect resolver routing fallthrough bridge"),
                    )
            expected = len(old_targets)
        else:
            return None
        if (
            expected
            and int(modifier.apply(defer_post_apply_maintenance=True)) != expected
        ):
            return None
        applied.extend(_boundary_port_result(record) for record in mutation.records)

    for mutation in batch.conditional:
        source = _resolve_boundary_port_block(mutation.source, created)
        old_taken = (
            None
            if mutation.old_taken_target is None
            else _resolve_boundary_port_block(
                mutation.old_taken_target,
                created,
            )
        )
        old_fallthrough = (
            None
            if mutation.old_fallthrough_target is None
            else _resolve_boundary_port_block(
                mutation.old_fallthrough_target,
                created,
            )
        )
        taken = _resolve_boundary_port_block(mutation.taken_target, created)
        fallthrough = _resolve_boundary_port_block(
            mutation.fallthrough_target,
            created,
        )
        if any(
            block is None
            for block in (
                source,
                taken,
                fallthrough,
            )
        ):
            return None
        modifier = DeferredGraphModifier(mba)
        if mutation.materialize_logical_source:
            port = mutation.record.port
            if (
                port.predicate_ida_stkoff is None
                or port.predicate_size is None
                or int(port.predicate_size) <= 0
                or port.condition_code not in (4, 5)
                or source.head is None
                or int(source.nsucc()) not in (0, 1)
            ):
                return None
            condition = ida_hexrays.mop_t()
            condition.make_stkvar(
                mba,
                int(mba.stkoff_ida2vd(int(port.predicate_ida_stkoff))),
            )
            condition.size = int(port.predicate_size)
            nonzero_true = taken if int(port.condition_code) == 5 else fallthrough
            nonzero_false = fallthrough if int(port.condition_code) == 5 else taken
            expected = 1
            if int(source.nsucc()) == 0:
                modifier.queue_terminal_goto_change(
                    block_serial=int(source.serial),
                    goto_target=int(nonzero_true.serial),
                    description="seed logical resolver conditional source",
                    priority=5,
                )
                old_dispatcher_serial = int(nonzero_true.serial)
                expected += 1
            else:
                old_dispatcher_serial = int(source.succset[0])
            rewrite_from_ea = int(source.head.ea)
            modifier.queue_lower_conditional_state_transition(
                source_serial=int(source.serial),
                old_dispatcher_serial=old_dispatcher_serial,
                rewrite_from_ea=rewrite_from_ea,
                condition_operand=condition,
                false_target_serial=int(nonzero_false.serial),
                true_target_serial=int(nonzero_true.serial),
                proof_id=(
                    f"resolver_logical_entry_bridge:0x{int(port.predicate_ea):X}"
                ),
                description=(
                    "materialize resolver-proven logical entry bridge "
                    f"source=0x{int(port.source_block_ea):X} "
                    f"predicate=0x{int(port.predicate_ea):X} "
                    f"anchor=0x{int(mutation.source.native_ea):X}"
                ),
                rule_priority=1000,
            )
            if int(modifier.apply(defer_post_apply_maintenance=True)) != expected:
                return None
            applied.append(_boundary_port_result(mutation.record))
            continue
        if mutation.restore_pruned_source:
            if not modifier.restore_pruned_conditional_now(
                source,
                taken_target=taken,
                fallthrough_target=fallthrough,
            ):
                return None
            applied.append(_boundary_port_result(mutation.record))
            continue
        if old_taken is None or old_fallthrough is None:
            return None
        direct_fallthrough = _conditional_fallthrough_serial(source)
        if direct_fallthrough is None:
            return None
        fallthrough_bridge = None
        if int(direct_fallthrough) != int(old_fallthrough.serial):
            candidate = mba.get_mblock(int(direct_fallthrough))
            if (
                candidate is None
                or int(candidate.serial) not in transparent_helper_serials
                or int(candidate.type) != int(ida_hexrays.BLT_1WAY)
                or int(candidate.nsucc()) != 1
                or int(candidate.succset[0]) != int(old_fallthrough.serial)
                or candidate.tail is None
                or int(candidate.tail.opcode) != int(ida_hexrays.m_goto)
            ):
                return None
            fallthrough_bridge = candidate
        expected = 0
        if int(old_taken.serial) != int(taken.serial):
            modifier.queue_conditional_target_change(
                block_serial=int(source.serial),
                old_target=int(old_taken.serial),
                new_target=int(taken.serial),
                description="retarget resolver conditional taken arm",
            )
            expected += 1
        if int(old_fallthrough.serial) != int(fallthrough.serial):
            if fallthrough_bridge is None:
                modifier.queue_conditional_target_change(
                    block_serial=int(source.serial),
                    old_target=int(old_fallthrough.serial),
                    new_target=int(fallthrough.serial),
                    description="retarget resolver conditional fallthrough",
                )
            else:
                modifier.queue_goto_change(
                    block_serial=int(fallthrough_bridge.serial),
                    new_target=int(fallthrough.serial),
                    description=("retarget resolver conditional fallthrough bridge"),
                )
            expected += 1
        if (
            expected
            and int(modifier.apply(defer_post_apply_maintenance=True)) != expected
        ):
            return None
        applied.append(_boundary_port_result(mutation.record))
    return tuple(applied)


def _materialize_detached_snippet_templates(
    mba: object,
    function_ea: int,
    target_eas: tuple[int, ...],
    template_cache: dict[tuple[int, int], DetachedSnippetTemplate],
    *,
    expected_template_maturity: int | None = None,
    allow_raw_preopt_calls: bool = False,
    import_native_preopt_ranges: bool = False,
) -> dict[int, int]:
    """Import cached snippets atomically and return target EA -> root serial."""
    templates = tuple(
        template_cache.get((int(function_ea), int(target_ea)))
        for target_ea in sorted(set(int(ea) for ea in target_eas))
    )
    if not templates or any(template is None for template in templates):
        logger.info(
            "detached snippet import abstained: func=0x%X targets=%s "
            "reason=template_missing",
            int(function_ea),
            [hex(int(target_ea)) for target_ea in target_eas],
        )
        return {}
    selected = tuple(template for template in templates if template is not None)
    required_maturity = (
        int(mba.maturity)
        if expected_template_maturity is None
        else int(expected_template_maturity)
    )
    if any(int(template.maturity) != required_maturity for template in selected):
        logger.info(
            "detached snippet import abstained: destination_maturity=%d "
            "required_template_maturity=%d "
            "template_maturities=%s reason=maturity_mismatch",
            int(mba.maturity),
            required_maturity,
            sorted({int(template.maturity) for template in selected}),
        )
        return {}
    preserve_raw_calls = bool(allow_raw_preopt_calls)
    preserve_native_call_eas = bool(import_native_preopt_ranges)
    if preserve_raw_calls and (
        int(mba.maturity)
        not in {
            int(ida_hexrays.MMAT_GENERATED),
            int(ida_hexrays.MMAT_PREOPTIMIZED),
        }
        or required_maturity != int(ida_hexrays.MMAT_PREOPTIMIZED)
    ):
        logger.info(
            "detached snippet import abstained: destination_maturity=%d "
            "required_template_maturity=%d reason=raw_calls_require_preopt",
            int(mba.maturity),
            required_maturity,
        )
        return {}
    if preserve_native_call_eas and not preserve_raw_calls:
        logger.info(
            "detached snippet import abstained: reason="
            "native_preopt_ranges_require_raw_calls"
        )
        return {}
    raw_preopt_import = preserve_raw_calls and required_maturity == int(
        ida_hexrays.MMAT_PREOPTIMIZED
    )

    imported_block_types: dict[tuple[int, int], int] = {}
    for template in selected:
        for block in template.blocks:
            block_type = int(block.block_type)
            if block_type == int(ida_hexrays.BLT_STOP):
                if not block.instructions or int(block.instructions[-1].opcode) != int(
                    ida_hexrays.m_ret
                ):
                    logger.info(
                        "detached snippet import abstained: target=0x%X "
                        "block_ea=0x%X reason=nonreturn_stop_template",
                        int(template.target_ea),
                        int(block.native_entry_ea),
                    )
                    return {}
                block_type = int(ida_hexrays.BLT_0WAY)
            imported_block_types[
                (int(template.target_ea), int(block.source_serial))
            ] = block_type

    if preserve_native_call_eas:
        native_call_eas = [
            int(instruction.ea)
            for template in selected
            for block in template.blocks
            for instruction in block.instructions
            if int(instruction.opcode)
            in (int(ida_hexrays.m_call), int(ida_hexrays.m_icall))
        ]
        if len(native_call_eas) != len(set(native_call_eas)):
            logger.info(
                "detached snippet import abstained: duplicate_call_eas=%s "
                "reason=native_preopt_call_ea_collision",
                [hex(ea) for ea in native_call_eas],
            )
            return {}

    stack_maps_by_target: dict[int, dict[int, int]] = {}
    stable_stack_maps_by_target: dict[int, dict[int, int]] = {}
    analyzed_stack_maps_by_target: dict[int, dict[int, int]] = {}
    stable_analyzed_stack_maps_by_target: dict[int, dict[int, int]] = {}
    for template in selected:
        stack_map = _destination_stack_map(mba, template)
        stack_maps_by_target[int(template.target_ea)] = stack_map
        stable_stack_maps_by_target[int(template.target_ea)] = (
            _stable_destination_stack_map(mba, template)
        )
        replacement_template = _DETACHED_REPLACEMENT_SNIPPET_TEMPLATES.get(
            (int(function_ea), int(template.target_ea))
        )
        analyzed_stack_maps_by_target[int(template.target_ea)] = (
            _analyzed_destination_stack_map(
                mba,
                template,
                replacement_template,
            )
        )
        stable_analyzed_stack_maps_by_target[int(template.target_ea)] = (
            {}
            if replacement_template is None
            else _stable_destination_stack_map(mba, replacement_template)
        )
        for source_vd, destination_vd in (
            stack_map | analyzed_stack_maps_by_target[int(template.target_ea)]
        ).items():
            if int(destination_vd) < 0:
                logger.info(
                    "detached snippet import abstained: target=0x%X "
                    "source_vd=%d destination_vd=%d "
                    "reason=negative_main_vd",
                    int(template.target_ea),
                    int(source_vd),
                    int(destination_vd),
                )
                return {}

    analyzed_calls_by_target: dict[
        int,
        dict[int, _AnalyzedCallReplacement],
    ] = {}
    subsumed_call_setup_eas_by_target: dict[int, frozenset[int]] = {}
    for template in selected:
        analyzed_calls = (
            {}
            if preserve_raw_calls
            else _analyzed_replacement_calls_by_ea(
                int(function_ea),
                int(template.target_ea),
            )
        )
        analyzed_calls_by_target[int(template.target_ea)] = analyzed_calls
        replacement_template = _DETACHED_REPLACEMENT_SNIPPET_TEMPLATES.get(
            (int(function_ea), int(template.target_ea))
        )
        subsumed_call_setup_eas_by_target[int(template.target_ea)] = (
            frozenset()
            if preserve_raw_calls
            else _subsumed_raw_call_setup_instruction_eas(
                template,
                replacement_template,
                analyzed_calls,
            )
        )
        for block in template.blocks:
            for captured in block.instructions:
                captured_opcode = int(captured.opcode)
                if (
                    captured_opcode
                    not in (
                        int(ida_hexrays.m_call),
                        int(ida_hexrays.m_icall),
                    )
                    or int(captured.d.t) == int(ida_hexrays.mop_f)
                    or preserve_raw_calls
                ):
                    continue
                analyzed_call = analyzed_calls.get(int(captured.ea))
                if (
                    analyzed_call is not None
                    and int(analyzed_call.call_opcode) == captured_opcode
                ):
                    continue
                logger.info(
                    "detached snippet import abstained: target=0x%X "
                    "block_ea=0x%X call_ea=0x%X "
                    "reason=analyzed_call_missing",
                    int(template.target_ea),
                    int(block.native_entry_ea),
                    int(captured.ea),
                )
                return {}

    # Rebase validation must finish before create_standalone_block allocates
    # anything.  In particular, analyzed CALLS replacements use the CALLS
    # template's VD coordinate system, not the raw PREOPT template's map.
    for template in selected:
        raw_stack_map = _stack_map_with_positive_identity_overrides(
            stack_maps_by_target[int(template.target_ea)],
            stable_stack_maps_by_target[int(template.target_ea)],
        )
        analyzed_stack_map = _stack_map_with_positive_identity_overrides(
            analyzed_stack_maps_by_target[int(template.target_ea)],
            stable_analyzed_stack_maps_by_target[int(template.target_ea)],
        )
        analyzed_calls = analyzed_calls_by_target[int(template.target_ea)]
        subsumed_setup_eas = subsumed_call_setup_eas_by_target[int(template.target_ea)]
        for block in template.blocks:
            for captured in block.instructions:
                if int(captured.ea) in subsumed_setup_eas:
                    continue
                instruction = captured
                instruction_stack_map = raw_stack_map
                instruction_template: DetachedSnippetTemplate | None = template
                captured_opcode = int(captured.opcode)
                if (
                    captured_opcode
                    in (int(ida_hexrays.m_call), int(ida_hexrays.m_icall))
                    and int(captured.d.t) != int(ida_hexrays.mop_f)
                    and not preserve_raw_calls
                ):
                    instruction = analyzed_calls[int(captured.ea)].instruction
                    instruction_stack_map = analyzed_stack_map
                    instruction_template = replacement_template
                instruction_stack_map = _stack_map_with_positive_identity_overrides(
                    instruction_stack_map,
                    _instruction_destination_stack_map(
                        mba,
                        instruction_template,
                        int(captured.ea),
                    ),
                )
                missing_source_vd = next(
                    (
                        int(operand.s.off)
                        for operand in _instruction_operands(instruction)
                        if int(operand.t) == int(ida_hexrays.mop_S)
                        and int(operand.s.off) not in instruction_stack_map
                    ),
                    None,
                )
                if missing_source_vd is not None:
                    logger.info(
                        "detached snippet import abstained: target=0x%X "
                        "block_ea=0x%X source_vd=%d "
                        "reason=stack_rebase_preflight",
                        int(template.target_ea),
                        int(block.native_entry_ea),
                        int(missing_source_vd),
                    )
                    return {}

    root_source_by_ea = {
        int(template.target_ea): (
            int(template.target_ea),
            int(template.root_source_serial),
        )
        for template in selected
    }
    live_target_serials: dict[int, int] = {}
    for template in selected:
        for block in template.blocks:
            for external_ea in block.external_successor_eas:
                if int(external_ea) <= 0 or int(external_ea) in root_source_by_ea:
                    continue
                live = find_unique_live_block_by_ea(mba, int(external_ea))
                if live is None:
                    logger.info(
                        "detached snippet import abstained: target=0x%X "
                        "external_ea=0x%X reason=external_successor_missing",
                        int(template.target_ea),
                        int(external_ea),
                    )
                    return {}
                live_target_serials[int(external_ea)] = int(live.serial)

    boundary_port_batch = _preflight_boundary_port_batch(mba, selected)
    if boundary_port_batch is None:
        logger.info(
            "detached snippet import abstained: reason=boundary_port_batch_preflight"
        )
        return _empty_import_result_for_boundary_ports(
            selected,
            "boundary_port_batch_preflight",
        )
    needs_conditional_fallthrough_helpers = raw_preopt_import or bool(
        boundary_port_batch.conditional
    )

    modifier = DeferredGraphModifier(mba)
    mba_identity = stable_mba_identity(mba)
    pending_instruction_origins: dict[tuple[int, int], int] = {}
    pending_owned_instruction_eas: dict[int, list[int]] = {
        int(template.target_ea): [] for template in selected
    }
    created: dict[tuple[int, int], object] = {}
    imported_fallthrough_helpers: list[object] = []
    for template in selected:
        for block in template.blocks:
            created_serial = modifier.create_standalone_block(
                ref_serial=0,
                is_0_way=True,
                verify=False,
            )
            if created_serial is None:
                return {}
            created[(int(template.target_ea), int(block.source_serial))] = (
                mba.get_mblock(int(created_serial))
            )

    roots = {
        int(template.target_ea): int(
            created[(int(template.target_ea), int(template.root_source_serial))].serial
        )
        for template in selected
    }
    if preserve_native_call_eas:
        native_ranges = sorted(
            {
                (int(start_ea), int(end_ea))
                for template in selected
                for start_ea, end_ea in template.owned_ranges
            }
        )
        combined_ranges = [
            (
                int(mba.mbr.ranges[index].start_ea),
                int(mba.mbr.ranges[index].end_ea),
            )
            for index in range(int(mba.mbr.ranges.size()))
        ]
        combined_ranges.extend(native_ranges)
        merged_ranges: list[tuple[int, int]] = []
        for start_ea, end_ea in sorted(combined_ranges):
            if not merged_ranges or start_ea > merged_ranges[-1][1]:
                merged_ranges.append((start_ea, end_ea))
                continue
            previous_start, previous_end = merged_ranges[-1]
            merged_ranges[-1] = (
                previous_start,
                max(previous_end, end_ea),
            )
        mba.mbr.ranges.clear()
        for start_ea, end_ea in merged_ranges:
            mba.mbr.ranges.push_back(ida_range.range_t(start_ea, end_ea))
        mba.set_mba_flags2(int(ida_hexrays.MBA2_HAS_OUTLINES))
    for template in selected:
        serial_map = {
            int(block.source_serial): int(
                created[(int(template.target_ea), int(block.source_serial))].serial
            )
            for block in template.blocks
        }
        stack_map = _stack_map_with_positive_identity_overrides(
            stack_maps_by_target[int(template.target_ea)],
            stable_stack_maps_by_target[int(template.target_ea)],
        )
        analyzed_stack_map = _stack_map_with_positive_identity_overrides(
            analyzed_stack_maps_by_target[int(template.target_ea)],
            stable_analyzed_stack_maps_by_target[int(template.target_ea)],
        )
        analyzed_calls = analyzed_calls_by_target[int(template.target_ea)]
        subsumed_setup_eas = subsumed_call_setup_eas_by_target[int(template.target_ea)]
        external_map: dict[int, int] = {}
        for block in template.blocks:
            for source_successor, external_ea in zip(
                block.successor_serials,
                block.external_successor_eas,
            ):
                if int(external_ea) <= 0:
                    continue
                target_serial = roots.get(int(external_ea))
                if target_serial is None:
                    target_serial = live_target_serials.get(int(external_ea))
                if target_serial is None:
                    logger.info(
                        "detached snippet import abstained: target=0x%X "
                        "external_ea=0x%X reason=external_target_unresolved",
                        int(template.target_ea),
                        int(external_ea),
                    )
                    return {}
                external_map[int(source_successor)] = int(target_serial)

        for block in template.blocks:
            destination = created[(int(template.target_ea), int(block.source_serial))]
            _remove_all_instructions(modifier, destination)
            for captured in block.instructions:
                if int(captured.ea) in subsumed_setup_eas:
                    continue
                captured_opcode = int(captured.opcode)
                if (
                    captured_opcode
                    in (
                        int(ida_hexrays.m_call),
                        int(ida_hexrays.m_icall),
                    )
                    and int(captured.d.t) != int(ida_hexrays.mop_f)
                    and not preserve_raw_calls
                ):
                    analyzed_call = analyzed_calls.get(int(captured.ea))
                    if (
                        analyzed_call is None
                        or int(analyzed_call.call_opcode) != captured_opcode
                    ):
                        logger.info(
                            "detached snippet import abstained: target=0x%X "
                            "block_ea=0x%X call_ea=0x%X "
                            "reason=analyzed_call_missing",
                            int(template.target_ea),
                            int(block.native_entry_ea),
                            int(captured.ea),
                        )
                        return {}
                    instruction = ida_hexrays.minsn_t(analyzed_call.instruction)
                    instruction_stack_map = analyzed_stack_map
                    instruction_template: DetachedSnippetTemplate | None = (
                        replacement_template
                    )
                else:
                    instruction = ida_hexrays.minsn_t(captured)
                    instruction_stack_map = stack_map
                    instruction_template = template
                instruction_stack_map = _stack_map_with_positive_identity_overrides(
                    instruction_stack_map,
                    _instruction_destination_stack_map(
                        mba,
                        instruction_template,
                        int(captured.ea),
                    ),
                )
                native_instruction_ea = int(captured.ea)
                if not all(
                    _rebase_template_operand(
                        mba,
                        root,
                        instruction_stack_map,
                    )
                    for root in (instruction.l, instruction.r, instruction.d)
                ):
                    logger.info(
                        "detached snippet import abstained: target=0x%X "
                        "block_ea=0x%X reason=stack_rebase_failed",
                        int(template.target_ea),
                        int(block.native_entry_ea),
                    )
                    return {}
                if not _remap_template_block_refs(
                    instruction,
                    serial_map,
                    external_map,
                ):
                    logger.info(
                        "detached snippet import abstained: target=0x%X "
                        "block_ea=0x%X reason=block_ref_remap_failed",
                        int(template.target_ea),
                        int(block.native_entry_ea),
                    )
                    return {}
                # Multiple detached roots can define the same location and
                # later converge.  Reusing the function entry EA makes those
                # definitions indistinguishable to Hex-Rays value numbering
                # (INTERR 50342).  Detached native EAs may also lie outside the
                # destination MBA ranges (INTERR 50863/50870), so every imported
                # instruction receives a unique fictitious EA mapped to the live
                # function entry.  At LOCOPT/CALLS, analyzed mop_f argument
                # lists were preserved above and no longer depend on native-EA
                # call analysis.  The PREOPT-only raw-call mode deliberately
                # keeps the original call setup so the destination MBA can
                # perform its own call analysis.
                # Native provenance is retained separately for resolver and
                # diagnostics consumers.
                imported_instruction_ea = (
                    native_instruction_ea
                    if preserve_native_call_eas
                    and captured_opcode
                    in (int(ida_hexrays.m_call), int(ida_hexrays.m_icall))
                    else int(mba.alloc_fict_ea(int(mba.entry_ea) + 1))
                )
                instruction.setaddr(imported_instruction_ea)
                if native_instruction_ea > 0:
                    pending_instruction_origins[
                        (mba_identity, imported_instruction_ea)
                    ] = native_instruction_ea
                    pending_owned_instruction_eas[int(template.target_ea)].append(
                        imported_instruction_ea
                    )
                if int(instruction.opcode) in (
                    int(ida_hexrays.m_call),
                    int(ida_hexrays.m_icall),
                ):
                    logger.info(
                        "detached snippet import call: target=0x%X "
                        "blk%d@0x%X call_ea=0x%X imported_ea=0x%X "
                        "l=%d r=%d d=%d args=%d",
                        int(template.target_ea),
                        int(destination.serial),
                        int(block.native_entry_ea),
                        native_instruction_ea,
                        imported_instruction_ea,
                        int(instruction.l.t),
                        int(instruction.r.t),
                        int(instruction.d.t),
                        (
                            len(instruction.d.f.args)
                            if int(instruction.d.t) == int(ida_hexrays.mop_f)
                            else -1
                        ),
                    )
                modifier.insert_instruction_now(
                    destination,
                    instruction,
                    destination.tail,
                )
            modifier.configure_block_now(
                destination,
                block_type=imported_block_types[
                    (int(template.target_ea), int(block.source_serial))
                ],
                flags=(
                    (
                        int(block.block_flags)
                        & (
                            int(ida_hexrays.MBL_GOTO)
                            | (int(ida_hexrays.MBL_PUSH) if preserve_raw_calls else 0)
                        )
                    )
                    | int(ida_hexrays.MBL_KEEP)
                    | int(ida_hexrays.MBL_FAKE)
                ),
                start_ea=int(mba.entry_ea),
                end_ea=int(mba.entry_ea) + 1,
            )

        for block in template.blocks:
            source = created[(int(template.target_ea), int(block.source_serial))]
            for source_successor, external_ea in zip(
                block.successor_serials,
                block.external_successor_eas,
            ):
                if int(external_ea) <= 0:
                    target_serial = serial_map[int(source_successor)]
                else:
                    target_serial = roots.get(int(external_ea))
                    if target_serial is None:
                        target_serial = live_target_serials[int(external_ea)]
                target = mba.get_mblock(int(target_serial))
                modifier.connect_blocks_now(source, target)

    # BLT_2WAY encodes its fallthrough structurally as the physically-adjacent
    # block.  Importing a semantic subset can separate a conditional from that
    # successor even though the captured edge remains valid.  Reify only those
    # displaced fallthroughs as adjacent one-way helpers before any deferred
    # mutation verifies the destination MBA.
    if needs_conditional_fallthrough_helpers:
        for destination in tuple(created.values()):
            fallthrough_serial = _conditional_fallthrough_serial(destination)
            if (
                fallthrough_serial is None
                or int(fallthrough_serial) == int(destination.serial) + 1
            ):
                continue
            helper_serial = modifier.insert_nop_block_now(int(destination.serial))
            helper = mba.get_mblock(int(helper_serial))
            if helper is None:
                logger.info(
                    "detached snippet import abstained: "
                    "source=blk%d@0x%X "
                    "reason=conditional_fallthrough_helper",
                    int(destination.serial),
                    int(_unique_block_native_ea(destination) or 0),
                )
                return {}
            imported_fallthrough_helpers.append(helper)

    # Calls are closing instructions too, but their continuation remains an
    # implicit physical fallthrough.  When partial ownership places that
    # successor elsewhere, insert an adjacent one-way bridge; never append a
    # goto after the call itself.
    if raw_preopt_import:
        for destination in tuple(created.values()):
            if (
                int(destination.type) != int(ida_hexrays.BLT_1WAY)
                or int(destination.nsucc()) != 1
                or int(destination.succset[0]) == int(destination.serial) + 1
                or destination.tail is None
                or int(destination.tail.opcode)
                not in {int(ida_hexrays.m_call), int(ida_hexrays.m_icall)}
            ):
                continue
            helper_serial = modifier.insert_nop_block_now(
                int(destination.serial),
                force_adjacent=True,
            )
            helper = mba.get_mblock(int(helper_serial))
            if helper is None:
                logger.info(
                    "detached snippet import abstained: "
                    "source=blk%d@0x%X reason=call_fallthrough_helper",
                    int(destination.serial),
                    int(_unique_block_native_ea(destination) or 0),
                )
                return {}
            imported_fallthrough_helpers.append(helper)

    # A source MBA may encode a one-way edge as ordinary fallthrough.  Once
    # its block is appended to another MBA, that edge is still implicit only
    # when the remapped successor is the imported block's new ``serial+1``.
    # Otherwise verifier.cpp derives ``serial+1`` from the non-closing tail
    # and rejects the explicit non-adjacent succset with INTERR 50860.  Preserve
    # the source edge by making precisely those displaced fallthroughs explicit.
    for destination in created.values():
        tail = destination.tail
        if (
            int(destination.type) != int(ida_hexrays.BLT_1WAY)
            or int(destination.nsucc()) != 1
            or int(destination.succset[0]) == int(destination.serial) + 1
            or (
                tail is not None
                and (
                    bool(ida_hexrays.is_mcode_jcond(int(tail.opcode)))
                    or int(tail.opcode)
                    in {
                        int(ida_hexrays.m_goto),
                        int(ida_hexrays.m_ext),
                        int(ida_hexrays.m_ijmp),
                        int(ida_hexrays.m_jtbl),
                        int(ida_hexrays.m_ret),
                    }
                    or (
                        raw_preopt_import
                        and int(tail.opcode)
                        in {
                            int(ida_hexrays.m_call),
                            int(ida_hexrays.m_icall),
                        }
                    )
                )
            )
        ):
            continue
        modifier.make_displaced_fallthrough_explicit_now(destination)

    terminal_carrier_insertions = _preflight_imported_terminal_return_carriers(
        mba,
        function_ea,
        boundary_port_batch,
        created,
        pending_instruction_origins,
    )
    if terminal_carrier_insertions is None:
        logger.info(
            "detached snippet import abstained: reason="
            "terminal_return_carrier_preflight"
        )
        return _empty_import_result_for_boundary_ports(
            selected,
            "terminal_return_carrier_preflight",
        )

    applied_boundary_ports = _apply_boundary_port_batch(
        mba,
        boundary_port_batch,
        created,
        transparent_helpers=tuple(imported_fallthrough_helpers),
        pending_instruction_origins=pending_instruction_origins,
    )
    if applied_boundary_ports is None:
        logger.error(
            "detached snippet import failed after boundary-port preflight: "
            "reason=boundary_port_apply"
        )
        return _empty_import_result_for_boundary_ports(
            selected,
            "boundary_port_apply",
        )

    _apply_imported_terminal_return_carriers(
        mba,
        terminal_carrier_insertions,
        modifier,
        pending_instruction_origins,
        pending_owned_instruction_eas,
    )

    roots = {
        int(template.target_ea): int(
            created[(int(template.target_ea), int(template.root_source_serial))].serial
        )
        for template in selected
    }

    for destination in (
        *created.values(),
        *imported_fallthrough_helpers,
    ):
        register_owned_fake_block(mba, destination)
    modifier.mark_blocks_dirty_now(*created.values())
    safe_verify(
        mba,
        "detached snippet import",
        logger_func=logger.error,
    )
    for target_ea, root_serial in roots.items():
        root_block = mba.get_mblock(int(root_serial))
        if root_block is None or root_block.head is None:
            logger.info(
                "detached snippet import abstained: target=0x%X "
                "reason=root_anchor_missing",
                int(target_ea),
            )
            return {}
        _IMPORTED_SNIPPET_ROOTS[(stable_mba_identity(mba), int(target_ea))] = (
            _ImportedSnippetRoot(
                serial_hint=int(root_serial),
                anchor_eas=tuple(
                    int(instruction.ea) for instruction in _instructions(root_block)
                ),
                owned_instruction_eas=tuple(
                    pending_owned_instruction_eas[int(target_ea)]
                ),
            )
        )
    _IMPORTED_INSTRUCTION_ORIGINS.update(pending_instruction_origins)
    identity = stable_mba_identity(mba)
    _LAST_IMPORTED_INSTRUCTION_ORIGINS[int(function_ea)] = tuple(
        sorted(
            (int(imported_ea), int(native_ea))
            for (mba_identity, imported_ea), native_ea in (
                _IMPORTED_INSTRUCTION_ORIGINS.items()
            )
            if int(mba_identity) == int(identity)
        )
    )
    direct_evidence: list[AppliedDetachedSnippetDirectBoundaryPort] = []
    for mutation in boundary_port_batch.direct:
        endpoint = _resolve_boundary_port_block(mutation.endpoint, created)
        target = _resolve_boundary_port_block(mutation.target, created)
        if endpoint is None or target is None:
            continue
        endpoint_anchors = tuple(
            dict.fromkeys(
                int(instruction.ea)
                for instruction in _instructions(endpoint)
                if int(instruction.ea) > 0
            )
        )
        target_anchors = tuple(
            dict.fromkeys(
                int(instruction.ea)
                for instruction in _instructions(target)
                if int(instruction.ea) > 0
            )
        )
        if not endpoint_anchors or not target_anchors:
            continue
        direct_evidence.extend(
            AppliedDetachedSnippetDirectBoundaryPort(
                port=record.port,
                endpoint_anchor_eas=endpoint_anchors,
                target_anchor_eas=target_anchors,
            )
            for record in mutation.records
        )
    if direct_evidence:
        identity = stable_mba_identity(mba)
        _IMPORTED_DIRECT_BOUNDARY_EVIDENCE[identity] = tuple(
            dict.fromkeys(
                (
                    *_IMPORTED_DIRECT_BOUNDARY_EVIDENCE.get(identity, ()),
                    *direct_evidence,
                )
            )
        )
    conditional_evidence: list[AppliedDetachedSnippetConditionalBoundaryPort] = []
    for mutation in boundary_port_batch.conditional:
        taken_target = _resolve_boundary_port_block(mutation.taken_target, created)
        fallthrough_target = _resolve_boundary_port_block(
            mutation.fallthrough_target,
            created,
        )
        if taken_target is None or fallthrough_target is None:
            continue
        taken_anchors = tuple(
            dict.fromkeys(
                int(instruction.ea)
                for instruction in _instructions(taken_target)
                if int(instruction.ea) > 0
            )
        )
        fallthrough_anchors = tuple(
            dict.fromkeys(
                int(instruction.ea)
                for instruction in _instructions(fallthrough_target)
                if int(instruction.ea) > 0
            )
        )
        if not taken_anchors or not fallthrough_anchors:
            continue
        conditional_evidence.append(
            AppliedDetachedSnippetConditionalBoundaryPort(
                port=mutation.record.port,
                taken_target_anchor_eas=taken_anchors,
                fallthrough_target_anchor_eas=fallthrough_anchors,
            )
        )
    if conditional_evidence:
        identity = stable_mba_identity(mba)
        _IMPORTED_CONDITIONAL_BOUNDARY_EVIDENCE[identity] = tuple(
            dict.fromkeys(
                (
                    *_IMPORTED_CONDITIONAL_BOUNDARY_EVIDENCE.get(identity, ()),
                    *conditional_evidence,
                )
            )
        )
    return DetachedSnippetImportResult(
        roots=tuple(sorted(roots.items())),
        applied_boundary_ports=applied_boundary_ports,
    )


def materialize_detached_snippet_templates(
    mba: object,
    function_ea: int,
    target_eas: tuple[int, ...],
    *,
    expected_template_maturity: int | None = None,
    allow_raw_preopt_calls: bool = False,
    import_native_preopt_ranges: bool = False,
) -> dict[int, int]:
    """Import cached snippets for missing detached handlers.

    ``allow_raw_preopt_calls`` is valid only for a PREOPTIMIZED template at
    the ``hxe_preoptimized`` boundary.  Hex-Rays invokes that callback before
    advancing ``mba.maturity`` from GENERATED, so both observed destination
    values are accepted.  The mode preserves raw call setup so the live
    destination MBA, rather than an isolated snippet, owns later call analysis.

    ``import_native_preopt_ranges`` additionally imports the template-owned
    native ranges and preserves native call EAs.  This gives Hex-Rays the
    address-domain evidence required for destination-side call analysis.  It
    is an experimental PREOPT-only mode and therefore requires
    ``allow_raw_preopt_calls``.
    """
    return _materialize_detached_snippet_templates(
        mba,
        function_ea,
        target_eas,
        _DETACHED_SNIPPET_TEMPLATES,
        expected_template_maturity=expected_template_maturity,
        allow_raw_preopt_calls=allow_raw_preopt_calls,
        import_native_preopt_ranges=import_native_preopt_ranges,
    )


def materialize_detached_replacement_snippet_templates(
    mba: object,
    function_ea: int,
    target_eas: tuple[int, ...],
) -> dict[int, int]:
    """Import CALLS templates selected to restore lost conditional arms."""
    return _materialize_detached_snippet_templates(
        mba,
        function_ea,
        target_eas,
        _DETACHED_REPLACEMENT_SNIPPET_TEMPLATES,
        expected_template_maturity=int(ida_hexrays.MMAT_CALLS),
    )


def redirect_live_target_predecessors(
    mba: object,
    replacement_roots_by_old_serial: Mapping[int, int],
) -> int:
    """Atomically retarget one-way incoming edges to imported roots.

    Append-only snippet import is not replacement by itself.  This operation
    completes the replacement only when every predecessor is a non-entry
    one-way block whose sole edge still targets the old live handler.
    """
    rows: list[tuple[object, int]] = []
    seen_predecessors: dict[int, int] = {}
    for old_serial, new_serial in sorted(replacement_roots_by_old_serial.items()):
        old_target = mba.get_mblock(int(old_serial))
        new_target = mba.get_mblock(int(new_serial))
        if (
            old_target is None
            or new_target is None
            or int(old_serial) == int(new_serial)
        ):
            return 0
        predecessor_serials = tuple(int(serial) for serial in old_target.predset)
        if not predecessor_serials:
            return 0
        for predecessor_serial in predecessor_serials:
            predecessor = mba.get_mblock(int(predecessor_serial))
            if (
                predecessor is None
                or int(predecessor.serial) == 0
                or int(predecessor.nsucc()) != 1
                or int(predecessor.succset[0]) != int(old_serial)
            ):
                return 0
            previous_target = seen_predecessors.setdefault(
                int(predecessor_serial),
                int(new_serial),
            )
            if int(previous_target) != int(new_serial):
                return 0
            rows.append((predecessor, int(new_serial)))

    modifier = DeferredGraphModifier(mba)
    for predecessor, new_serial in rows:
        if not modifier.redirect_one_way_now(
            int(predecessor.serial),
            int(new_serial),
            verify=False,
        ):
            raise RuntimeError(
                "preflighted detached replacement predecessor redirect failed"
            )
    modifier.mark_blocks_dirty_now(*(predecessor for predecessor, _new_serial in rows))
    mba.verify(True)
    return len(rows)


def _return_mreg() -> int:
    return int(ida_hexrays.reg2mreg(0))


def clear_terminal_return_carrier_templates() -> None:
    """Drop cross-maturity terminal return-carrier templates."""
    _TERMINAL_RETURN_CARRIER_TEMPLATES.clear()


def has_terminal_return_carrier_template(
    function_ea: int,
    request: TerminalReturnCarrierRequest,
) -> bool:
    key = (
        int(function_ea),
        int(request.source_handler_ea),
        int(request.state_constant) & 0xFFFFFFFF,
    )
    return key in _TERMINAL_RETURN_CARRIER_TEMPLATES


def _exact_register_state_write(
    instruction: object,
    request: TerminalReturnCarrierRequest,
) -> bool:
    return (
        int(instruction.opcode) == int(ida_hexrays.m_mov)
        and int(instruction.l.t) == int(ida_hexrays.mop_n)
        and (int(instruction.l.nnn.value) & 0xFFFFFFFF)
        == (int(request.state_constant) & 0xFFFFFFFF)
        and int(instruction.d.t) == int(ida_hexrays.mop_r)
        and int(instruction.d.r) == int(request.state_var_reg)
    )


def _is_stable_terminal_carrier_write(instruction: object) -> bool:
    return (
        int(instruction.opcode) == int(ida_hexrays.m_mov)
        and int(instruction.l.t)
        in {
            int(ida_hexrays.mop_a),
            int(ida_hexrays.mop_v),
            int(ida_hexrays.mop_n),
        }
        and int(instruction.d.t) == int(ida_hexrays.mop_r)
        and int(instruction.d.r) == _return_mreg()
        and int(instruction.d.size) > 0
    )


def capture_terminal_return_carrier_template(
    function_ea: int,
    request: TerminalReturnCarrierRequest,
    mba: object,
) -> bool:
    """Cache one exact early-maturity return-register assignment.

    The request is produced only after CALLS proves a terminal state route.
    Capture additionally requires the matching state write and one stable
    address/constant assignment to the ABI return register in the same bounded
    microcode block.  Ambiguity abstains.
    """
    blocks = _blocks_containing_ea(mba, int(request.source_handler_ea))
    candidates: list[object] = []
    for block in blocks:
        instructions = _instructions(block)
        state_writes = tuple(
            instruction
            for instruction in instructions
            if _exact_register_state_write(instruction, request)
        )
        if len(state_writes) != 1:
            continue
        state_index = instructions.index(state_writes[0])
        block_carriers = tuple(
            instruction
            for instruction in instructions[state_index + 1 :]
            if _is_stable_terminal_carrier_write(instruction)
        )
        if len(block_carriers) == 1:
            candidates.append(block_carriers[0])
    if len(candidates) != 1 or int(candidates[0].ea) <= 0:
        return False
    key = (
        int(function_ea),
        int(request.source_handler_ea),
        int(request.state_constant) & 0xFFFFFFFF,
    )
    _TERMINAL_RETURN_CARRIER_TEMPLATES[key] = _TerminalReturnCarrierTemplate(
        request=request,
        instruction=ida_hexrays.minsn_t(candidates[0]),
    )
    return True


def restore_terminal_return_carriers(mba: object, function_ea: int) -> int:
    """Replay exact terminal carriers into matching live handler blocks."""
    modifier = DeferredGraphModifier(mba)
    templates = tuple(
        template
        for (owner_ea, _source_ea, _state), template in (
            _TERMINAL_RETURN_CARRIER_TEMPLATES.items()
        )
        if int(owner_ea) == int(function_ea)
    )
    by_source: dict[int, list[_TerminalReturnCarrierTemplate]] = {}
    for template in templates:
        by_source.setdefault(
            int(template.request.source_handler_ea),
            [],
        ).append(template)

    changed = 0
    for source_ea, source_templates in sorted(by_source.items()):
        if len(source_templates) != 1:
            continue
        template = source_templates[0]
        blocks = _blocks_containing_ea(mba, int(source_ea))
        if len(blocks) != 1:
            continue
        block = blocks[0]
        instructions = _instructions(block)
        state_writes = tuple(
            instruction
            for instruction in instructions
            if _exact_register_state_write(instruction, template.request)
        )
        if len(state_writes) != 1:
            continue
        carrier_ea = int(template.instruction.ea)
        existing_at_ea = tuple(
            instruction
            for instruction in instructions
            if int(instruction.ea) == carrier_ea
        )
        if existing_at_ea:
            continue
        if any(
            int(instruction.d.t) == int(ida_hexrays.mop_r)
            and int(instruction.d.r) == _return_mreg()
            for instruction in instructions
        ):
            continue
        assignment = ida_hexrays.minsn_t(template.instruction)
        modifier.insert_instruction_now(
            block,
            assignment,
            state_writes[0],
            mark_dirty=True,
        )
        logger.info(
            "terminal return carrier restored: source=0x%X carrier=0x%X "
            "epilogue=0x%X state=0x%X",
            int(source_ea),
            carrier_ea,
            int(template.request.terminal_target_ea),
            int(template.request.state_constant) & 0xFFFFFFFF,
        )
        changed += 1

    by_terminal_identity: dict[
        tuple[int, int, int],
        list[_TerminalReturnCarrierTemplate],
    ] = {}
    for template in templates:
        request = template.request
        identity = (
            int(request.terminal_target_ea),
            int(request.state_var_reg),
            int(request.state_constant) & 0xFFFFFFFF,
        )
        by_terminal_identity.setdefault(identity, []).append(template)

    for _identity, terminal_templates in sorted(by_terminal_identity.items()):
        if len(terminal_templates) != 1:
            continue
        template = terminal_templates[0]
        request = template.request
        carrier_ea = int(template.instruction.ea)
        for serial in range(int(mba.qty)):
            block = mba.get_mblock(serial)
            if int(block.type) != int(ida_hexrays.BLT_1WAY) or int(block.nsucc()) != 1:
                continue
            instructions = _instructions(block)
            state_register_writes = tuple(
                instruction
                for instruction in instructions
                if int(instruction.opcode) == int(ida_hexrays.m_mov)
                and int(instruction.d.t) == int(ida_hexrays.mop_r)
                and int(instruction.d.r) == int(request.state_var_reg)
            )
            if (
                len(state_register_writes) != 1
                or not _exact_register_state_write(
                    state_register_writes[0],
                    request,
                )
                or any(
                    int(instruction.d.t) == int(ida_hexrays.mop_r)
                    and int(instruction.d.r) == _return_mreg()
                    for instruction in instructions
                )
            ):
                continue
            assignment = ida_hexrays.minsn_t(template.instruction)
            modifier.insert_instruction_now(
                block,
                assignment,
                state_register_writes[0],
                mark_dirty=True,
            )
            logger.info(
                "terminal return carrier restored to equivalent state writer: "
                "writer=blk%d@0x%X carrier=0x%X epilogue=0x%X state=0x%X",
                int(block.serial),
                int(block.start),
                carrier_ea,
                int(request.terminal_target_ea),
                int(request.state_constant) & 0xFFFFFFFF,
            )
            changed += 1
    if changed:
        modifier.mark_blocks_dirty_now()
        mba.verify(True)
    return changed


def _is_zero_operand(operand: object) -> bool:
    return int(operand.t) == int(ida_hexrays.mop_n) and int(operand.nnn.value) == 0


def _call_predecessors(mba: object, block_serial: int) -> tuple[object, ...]:
    result: list[object] = []
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        if (
            int(block.nsucc()) == 1
            and int(block.succset[0]) == int(block_serial)
            and block.tail is not None
            and int(block.tail.opcode) == int(ida_hexrays.m_call)
            and int(block.tail.l.t) == int(ida_hexrays.mop_v)
        ):
            result.append(block)
    return tuple(result)


def _carrier_write_before_branch(
    block: object,
    branch: object,
    return_mreg: int,
) -> object | None:
    candidate = None
    instruction = block.head
    while instruction is not None and instruction is not branch:
        if candidate is not None:
            if int(instruction.opcode) in (
                int(ida_hexrays.m_call),
                int(ida_hexrays.m_icall),
            ):
                return None
            destination = instruction.d
            if int(destination.t) == int(ida_hexrays.mop_r) and int(
                destination.r
            ) == int(return_mreg):
                return None
            if int(destination.t) == int(ida_hexrays.mop_S) and int(
                destination.s.off
            ) == int(candidate.d.s.off):
                return None
        if (
            int(instruction.opcode) == int(ida_hexrays.m_mov)
            and int(instruction.l.t) == int(ida_hexrays.mop_r)
            and int(instruction.l.r) == int(return_mreg)
            and int(instruction.d.t) == int(ida_hexrays.mop_S)
            and int(instruction.l.size) == int(instruction.d.size)
        ):
            candidate = instruction
        instruction = instruction.next
    return candidate


def capture_call_result_carriers(mba: object) -> tuple[CallResultCarrier, ...]:
    """Capture exact raw call-result stack carriers before LOCOPT can fold them."""
    return_mreg = _return_mreg()
    facts: list[CallResultCarrier] = []
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        branch = block.tail
        if (
            branch is None
            or int(branch.opcode) not in (int(ida_hexrays.m_jz), int(ida_hexrays.m_jnz))
            or int(branch.l.t) != int(ida_hexrays.mop_r)
            or int(branch.l.r) != int(return_mreg)
            or not _is_zero_operand(branch.r)
        ):
            continue
        call_blocks = _call_predecessors(mba, int(block.serial))
        if len(call_blocks) != 1:
            continue
        carrier_write = _carrier_write_before_branch(block, branch, return_mreg)
        if carrier_write is None:
            continue
        call = call_blocks[0].tail
        carrier = carrier_write.d
        facts.append(
            CallResultCarrier(
                call_ea=int(call.ea),
                carrier_ea=int(carrier_write.ea),
                branch_ea=int(branch.ea),
                callee_ea=int(call.l.g),
                carrier_ida_stkoff=int(mba.stkoff_vd2ida(int(carrier.s.off))),
                value_size=int(carrier.size),
                branch_opcode=int(branch.opcode),
            )
        )
    return tuple(facts)


def _find_instruction(
    mba: object,
    instruction_ea: int,
    opcode: int,
) -> tuple[object, object, object | None] | None:
    matches: list[tuple[object, object, object | None]] = []
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        previous = None
        instruction = block.head
        while instruction is not None:
            if int(instruction.ea) == int(instruction_ea) and int(
                instruction.opcode
            ) == int(opcode):
                matches.append((block, instruction, previous))
            previous = instruction
            instruction = instruction.next
    return matches[0] if len(matches) == 1 else None


def _operand_reads_stack(operand: object, stack_offset: int) -> bool:
    operand_type = int(operand.t)
    if operand_type == int(ida_hexrays.mop_S):
        return int(operand.s.off) == int(stack_offset)
    if operand_type == int(ida_hexrays.mop_d):
        nested = operand.d
        return (
            _operand_reads_stack(nested.l, stack_offset)
            or _operand_reads_stack(nested.r, stack_offset)
            or (
                int(nested.d.t) == int(ida_hexrays.mop_f)
                and any(
                    _operand_reads_stack(argument, stack_offset)
                    for argument in nested.d.f.args
                )
            )
        )
    if operand_type == int(ida_hexrays.mop_f):
        return any(
            _operand_reads_stack(argument, stack_offset) for argument in operand.f.args
        )
    return False


def _has_nonpredicate_carrier_consumer(
    mba: object,
    stack_offset: int,
    branch_ea: int,
) -> bool:
    for serial in range(int(mba.qty)):
        instruction = mba.get_mblock(serial).head
        while instruction is not None:
            if int(instruction.ea) != int(branch_ea) and (
                _operand_reads_stack(instruction.l, stack_offset)
                or _operand_reads_stack(instruction.r, stack_offset)
                or (
                    int(instruction.d.t) == int(ida_hexrays.mop_f)
                    and _operand_reads_stack(instruction.d, stack_offset)
                )
            ):
                return True
            instruction = instruction.next
    return False


def restore_call_result_carriers(
    mba: object,
    facts: tuple[CallResultCarrier, ...],
) -> int:
    """Restore cached call-result assignments after CALLS unflattening reconnects uses."""
    modifier = DeferredGraphModifier(mba)
    changed = 0
    for fact in facts:
        match = _find_instruction(mba, fact.branch_ea, fact.branch_opcode)
        if match is None:
            logger.info(
                "call-result carrier restore abstained: branch=0x%X reason=branch_missing",
                int(fact.branch_ea),
            )
            continue
        block, branch, previous = match
        if (
            int(branch.l.t) != int(ida_hexrays.mop_d)
            or int(branch.l.d.opcode) != int(ida_hexrays.m_call)
            or int(branch.l.d.l.t) != int(ida_hexrays.mop_v)
            or int(branch.l.d.l.g) != int(fact.callee_ea)
            or not _is_zero_operand(branch.r)
        ):
            logger.info(
                "call-result carrier restore abstained: branch=0x%X "
                "reason=fused_call_mismatch",
                int(fact.branch_ea),
            )
            continue
        carrier_stkoff = int(mba.stkoff_ida2vd(fact.carrier_ida_stkoff))
        if not _has_nonpredicate_carrier_consumer(
            mba,
            carrier_stkoff,
            fact.branch_ea,
        ):
            logger.info(
                "call-result carrier restore abstained: branch=0x%X carrier=0x%X "
                "reason=no_live_consumer",
                int(fact.branch_ea),
                int(fact.carrier_ea),
            )
            continue
        call_expression = ida_hexrays.minsn_t(branch.l.d)
        assignment = ida_hexrays.minsn_t(int(fact.carrier_ea))
        assignment.opcode = ida_hexrays.m_mov
        assignment.l.make_insn(call_expression)
        assignment.l.size = int(fact.value_size)
        assignment.d.make_stkvar(mba, carrier_stkoff)
        assignment.d.size = int(fact.value_size)
        branch.l.erase()
        branch.l.make_stkvar(mba, carrier_stkoff)
        branch.l.size = int(fact.value_size)
        modifier.insert_instruction_now(
            block,
            assignment,
            previous,
            mark_dirty=True,
        )
        logger.info(
            "call-result carrier restored: call=0x%X carrier=0x%X branch=0x%X",
            int(fact.call_ea),
            int(fact.carrier_ea),
            int(fact.branch_ea),
        )
        changed += 1
    if changed:
        modifier.mark_blocks_dirty_now()
    return changed


def _analyzed_call_templates(mba: object) -> tuple[tuple[int, _CallTemplate], ...]:
    matches: list[tuple[int, _CallTemplate]] = []
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        for instruction in _instructions(block):
            if (
                int(instruction.opcode) == int(ida_hexrays.m_call)
                and int(instruction.l.t) == int(ida_hexrays.mop_v)
                and int(instruction.d.t) == int(ida_hexrays.mop_f)
                and len(instruction.d.f.args) == 1
            ):
                argument = instruction.d.f.args[0]
                matches.append(
                    (
                        int(instruction.l.g),
                        _CallTemplate(
                            instruction=instruction,
                            argument_size=(
                                int(argument.size) if int(argument.size) > 0 else 4
                            ),
                        ),
                    )
                )
    return tuple(matches)


def _analyzed_call_result_definitions(
    mba: object,
) -> tuple[_AnalyzedCallResultDefinition, ...]:
    origins = dict(imported_detached_snippet_instruction_origins(mba))
    call_opcodes = (int(ida_hexrays.m_call), int(ida_hexrays.m_icall))
    definitions: list[_AnalyzedCallResultDefinition] = []
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        for instruction in _instructions(block):
            if (
                int(instruction.opcode) != int(ida_hexrays.m_mov)
                or int(instruction.l.t) != int(ida_hexrays.mop_d)
                or int(instruction.d.t) != int(ida_hexrays.mop_r)
            ):
                continue
            call = instruction.l.d
            if int(call.opcode) not in call_opcodes or int(call.d.t) != int(
                ida_hexrays.mop_f
            ):
                continue
            call_opcode = int(call.opcode)
            if call_opcode == int(ida_hexrays.m_call):
                if int(call.l.t) != int(ida_hexrays.mop_v):
                    continue
                callee_ea: int | None = int(call.l.g)
            else:
                callee_ea = None
            result_size = int(instruction.d.size)
            if result_size <= 0:
                continue
            call_ea = int(
                origins.get(
                    int(call.ea),
                    origins.get(int(instruction.ea), int(call.ea)),
                )
            )
            definitions.append(
                _AnalyzedCallResultDefinition(
                    call_ea=call_ea,
                    call_opcode=call_opcode,
                    callee_ea=callee_ea,
                    result_mreg=int(instruction.d.r),
                    result_size=result_size,
                )
            )
    return tuple(definitions)


def _call_matches_result_definition(
    instruction: object,
    definition: _AnalyzedCallResultDefinition,
) -> bool:
    if int(instruction.opcode) != int(definition.call_opcode) or int(
        instruction.d.t
    ) != int(ida_hexrays.mop_f):
        return False
    if definition.callee_ea is None:
        return int(instruction.opcode) == int(ida_hexrays.m_icall)
    return int(instruction.l.t) == int(ida_hexrays.mop_v) and int(
        instruction.l.g
    ) == int(definition.callee_ea)


def _owner_matches_result_definition(
    instruction: object,
    definition: _AnalyzedCallResultDefinition,
) -> bool:
    return (
        int(instruction.opcode) == int(ida_hexrays.m_mov)
        and int(instruction.l.t) == int(ida_hexrays.mop_d)
        and _call_matches_result_definition(instruction.l.d, definition)
        and int(instruction.d.t) == int(ida_hexrays.mop_r)
        and int(instruction.d.r) == int(definition.result_mreg)
        and int(instruction.d.size) == int(definition.result_size)
    )


def restore_detached_call_result_definitions(
    mba: object,
    function_ea: int,
) -> int:
    """Restore CALLS-analyzed result owners lost while replaying snippets.

    The cache retains only native identity and the result location.  The live
    replayed ``m_call``/``m_icall`` supplies its own ``mop_f`` callinfo, so no
    MBA-owned callinfo object crosses a decompilation boundary.
    """
    owner_ea = int(function_ea)
    origins = dict(imported_detached_snippet_instruction_origins(mba))
    definitions = tuple(
        definition
        for (profile_ea, call_ea), definition in sorted(
            _ANALYZED_CALL_RESULT_DEFINITIONS.items()
        )
        if int(profile_ea) == owner_ea
        and (owner_ea, int(call_ea)) not in _ANALYZED_CALL_RESULT_DEFINITION_CONFLICTS
    )
    changed_blocks: list[object] = []
    changed = 0
    for definition in definitions:
        raw_matches: list[tuple[object, object]] = []
        preserved_matches: list[tuple[object, object]] = []
        conflicting_call_owner = False
        for serial in range(int(mba.qty)):
            block = mba.get_mblock(serial)
            for instruction in _instructions(block):
                native_ea = int(origins.get(int(instruction.ea), int(instruction.ea)))
                if native_ea != int(definition.call_ea):
                    continue
                if _call_matches_result_definition(instruction, definition):
                    raw_matches.append((block, instruction))
                    continue
                if int(instruction.opcode) == int(ida_hexrays.m_mov) and int(
                    instruction.l.t
                ) == int(ida_hexrays.mop_d):
                    nested = instruction.l.d
                    if _call_matches_result_definition(nested, definition):
                        if _owner_matches_result_definition(instruction, definition):
                            preserved_matches.append((block, instruction))
                        else:
                            conflicting_call_owner = True
                elif int(instruction.opcode) in (
                    int(ida_hexrays.m_call),
                    int(ida_hexrays.m_icall),
                ):
                    conflicting_call_owner = True

        if preserved_matches:
            if len(preserved_matches) != 1 or raw_matches or conflicting_call_owner:
                logger.info(
                    "call-result definition restore abstained: call=0x%X "
                    "reason=ambiguous_preserved_owner preserved=%d raw=%d",
                    int(definition.call_ea),
                    len(preserved_matches),
                    len(raw_matches),
                )
            continue
        if len(raw_matches) != 1 or conflicting_call_owner:
            if raw_matches or conflicting_call_owner:
                logger.info(
                    "call-result definition restore abstained: call=0x%X "
                    "reason=ambiguous_raw_owner raw=%d conflict=%s",
                    int(definition.call_ea),
                    len(raw_matches),
                    conflicting_call_owner,
                )
            continue

        block, instruction = raw_matches[0]
        call_expression = ida_hexrays.minsn_t(instruction)
        call_expression.d.size = int(definition.result_size)
        instruction.opcode = ida_hexrays.m_mov
        instruction.l.erase()
        instruction.l.make_insn(call_expression)
        instruction.l.size = int(definition.result_size)
        instruction.r.erase()
        instruction.d.erase()
        instruction.d.make_reg(
            int(definition.result_mreg),
            int(definition.result_size),
        )
        changed_blocks.append(block)
        changed += 1
        logger.info(
            "call-result definition restored: call=0x%X "
            "owner=blk%d@0x%X result_mreg=%d size=%d",
            int(definition.call_ea),
            int(block.serial),
            int(block.start),
            int(definition.result_mreg),
            int(definition.result_size),
        )
    if changed:
        DeferredGraphModifier(mba).mark_blocks_dirty_now(
            *tuple(dict.fromkeys(changed_blocks))
        )
        mba.verify(True)
    return changed


def capture_detached_handler_call_templates(function_ea: int, mba: object) -> None:
    """Retain analyzed CALLS templates and result owners for later replay."""
    key = int(function_ea)
    for callee_ea, template in _analyzed_call_templates(mba):
        _ANALYZED_CALL_TEMPLATES[(key, int(callee_ea))] = _CallTemplate(
            instruction=ida_hexrays.minsn_t(template.instruction),
            argument_size=int(template.argument_size),
        )
    for definition in _analyzed_call_result_definitions(mba):
        definition_key = (key, int(definition.call_ea))
        previous = _ANALYZED_CALL_RESULT_DEFINITIONS.get(definition_key)
        if previous is None:
            _ANALYZED_CALL_RESULT_DEFINITIONS[definition_key] = definition
        elif previous != definition:
            _ANALYZED_CALL_RESULT_DEFINITION_CONFLICTS.add(definition_key)


def clear_detached_handler_call_templates() -> None:
    """Clear CALLS templates at resolver teardown or project reload."""
    _ANALYZED_CALL_TEMPLATES.clear()
    _ANALYZED_CALL_RESULT_DEFINITIONS.clear()
    _ANALYZED_CALL_RESULT_DEFINITION_CONFLICTS.clear()
    _DETACHED_SNIPPET_TEMPLATES.clear()
    _DETACHED_REPLACEMENT_SNIPPET_TEMPLATES.clear()
    _DETACHED_CALLINFO_TEMPLATES.clear()
    _DETACHED_CALLINFO_CONFLICTS.clear()
    _DETACHED_SNIPPET_GENERATIONS.clear()
    _IMPORTED_SNIPPET_ROOTS.clear()
    _IMPORTED_INSTRUCTION_ORIGINS.clear()
    _LAST_IMPORTED_INSTRUCTION_ORIGINS.clear()
    _IMPORTED_DIRECT_BOUNDARY_EVIDENCE.clear()
    _IMPORTED_CONDITIONAL_BOUNDARY_EVIDENCE.clear()
    clear_owned_fake_block_registrations()


def clear_imported_detached_snippet_roots() -> None:
    """Forget live-MBA identities while retaining cross-decompile evidence."""
    _IMPORTED_SNIPPET_ROOTS.clear()
    _IMPORTED_INSTRUCTION_ORIGINS.clear()
    _IMPORTED_DIRECT_BOUNDARY_EVIDENCE.clear()
    _IMPORTED_CONDITIONAL_BOUNDARY_EVIDENCE.clear()


def _unique_call_template(
    mba: object,
    function_ea: int,
    callee_ea: int,
) -> _CallTemplate | None:
    live = tuple(
        template
        for target_ea, template in _analyzed_call_templates(mba)
        if int(target_ea) == int(callee_ea)
    )
    if live:
        return live[0]
    return _ANALYZED_CALL_TEMPLATES.get((int(function_ea), int(callee_ea)))


def _state_write(ea: int, state_register: int, state: int) -> object:
    instruction = ida_hexrays.minsn_t(int(ea))
    instruction.opcode = ida_hexrays.m_mov
    instruction.l.make_number(int(state) & 0xFFFFFFFF, 4, int(ea))
    instruction.d.make_reg(int(state_register), 4)
    return instruction


def materialize_detached_handler_island(
    mba: object,
    plan: DetachedHandlerIslandPlan,
) -> bool:
    """Apply one call + conditional-state island atomically or abstain."""
    source = find_unique_live_block_by_ea(mba, int(plan.source_predicate_ea))
    true_handler = find_unique_live_block_by_ea(mba, int(plan.true_target_ea))
    false_handler = find_unique_live_block_by_ea(mba, int(plan.false_target_ea))
    call_template = _unique_call_template(
        mba,
        int(mba.entry_ea),
        int(plan.call_target_ea),
    )
    if (
        source is None
        or int(source.nsucc()) != 2
        or true_handler is None
        or false_handler is None
        or call_template is None
    ):
        return False

    anchor_ea = int(plan.source_predicate_ea)
    call = ida_hexrays.minsn_t(call_template.instruction)
    call.setaddr(anchor_ea)
    source_argument_stkoff = int(mba.stkoff_ida2vd(int(plan.call_argument_ida_stkoff)))
    argument = call.d.f.args[0]
    argument.erase()
    argument.make_stkvar(mba, source_argument_stkoff)
    argument.size = int(call_template.argument_size)
    call_instructions = (call,)

    predicate_stkoff = int(mba.stkoff_ida2vd(int(plan.predicate_ida_stkoff)))
    default_state_write = _state_write(
        anchor_ea,
        int(plan.state_register),
        int(plan.false_state),
    )
    true_state_write = _state_write(
        anchor_ea,
        int(plan.state_register),
        int(plan.true_state),
    )

    modifier = DeferredGraphModifier(mba)
    free_block = mba.get_mblock(modifier.insert_nop_block_now(int(source.serial)))
    true_handler = find_unique_live_block_by_ea(mba, int(plan.true_target_ea))
    false_handler = find_unique_live_block_by_ea(mba, int(plan.false_target_ea))
    if true_handler is None or false_handler is None:
        return False
    true_block_serial = modifier.create_standalone_block(
        ref_serial=int(source.serial),
        blk_ins=[true_state_write],
        target_serial=int(true_handler.serial),
        verify=False,
    )
    true_block = (
        mba.get_mblock(int(true_block_serial))
        if true_block_serial is not None
        else None
    )
    predicate_block_serial = modifier.create_standalone_block(
        ref_serial=int(source.serial),
        blk_ins=[default_state_write],
        is_0_way=True,
        verify=False,
    )
    predicate_block = (
        mba.get_mblock(int(predicate_block_serial))
        if predicate_block_serial is not None
        else None
    )
    false_block_serial = modifier.create_standalone_block(
        ref_serial=int(source.serial),
        target_serial=int(false_handler.serial),
        verify=False,
    )
    false_block = (
        mba.get_mblock(int(false_block_serial))
        if false_block_serial is not None
        else None
    )
    if (
        free_block is None
        or true_block_serial is None
        or predicate_block_serial is None
        or false_block_serial is None
    ):
        return False
    if true_block is None or predicate_block is None or false_block is None:
        return False

    branch = ida_hexrays.minsn_t(anchor_ea)
    branch.opcode = ida_hexrays.m_jnz
    branch.l.make_stkvar(mba, predicate_stkoff)
    branch.l.size = 4
    branch.r.make_number(0, 4, anchor_ea)
    branch.d.make_blkref(int(true_block.serial))
    modifier.insert_instruction_now(predicate_block, branch, predicate_block.tail)
    _remove_nops(modifier, predicate_block)
    modifier.configure_block_now(
        predicate_block,
        block_type=int(ida_hexrays.BLT_2WAY),
        flags=int(predicate_block.flags) & ~int(ida_hexrays.MBL_GOTO),
    )
    modifier.connect_blocks_now(predicate_block, false_block)
    modifier.connect_blocks_now(predicate_block, true_block)

    _remove_all_instructions(modifier, free_block)
    placeholder = ida_hexrays.minsn_t(anchor_ea)
    placeholder.opcode = ida_hexrays.m_nop
    modifier.insert_instruction_now(free_block, placeholder, free_block.head)
    for instruction in call_instructions:
        modifier.insert_instruction_now(free_block, instruction, free_block.tail)
    _remove_nops(modifier, free_block)
    modifier.configure_block_now(
        free_block,
        flags=int(free_block.flags) & ~int(ida_hexrays.MBL_GOTO),
    )
    if not modifier.redirect_one_way_now(
        int(free_block.serial),
        int(predicate_block.serial),
        verify=False,
    ):
        return False

    for block in (free_block, predicate_block, false_block, true_block):
        modifier.reanchor_block_instructions_now(block, anchor_ea)
    modifier.mark_blocks_dirty_now(
        free_block,
        predicate_block,
        false_block,
        true_block,
    )
    mba.verify(True)
    return True


__all__ = [
    "capture_detached_callinfo_templates",
    "CallResultCarrier",
    "DetachedCallCompanionValidation",
    "DetachedSnippetCompanionCaptureResult",
    "DetachedSnippetBlockTemplate",
    "DetachedSnippetTemplate",
    "capture_call_result_carriers",
    "capture_terminal_return_carrier_template",
    "capture_detached_handler_call_templates",
    "capture_detached_replacement_snippet_template",
    "capture_detached_snippet_companion_templates",
    "capture_detached_snippet_template",
    "clear_detached_handler_call_templates",
    "prepare_detached_callinfo_template",
    "clear_terminal_return_carrier_templates",
    "clear_imported_detached_snippet_roots",
    "detached_snippet_template_generation",
    "detached_callinfo_template_eas",
    "detached_snippet_conditional_evidence",
    "detached_snippet_replacement_evidence",
    "detached_snippet_replacement_arm_states",
    "detached_snippet_requires_analyzed_calls",
    "detached_snippet_template_block_eas",
    "detached_snippet_template_stack_map",
    "find_unique_live_block_by_ea",
    "imported_detached_snippet_instruction_origins",
    "last_imported_detached_snippet_instruction_origins",
    "imported_detached_snippet_direct_boundary_evidence",
    "imported_detached_snippet_conditional_boundary_evidence",
    "imported_detached_snippet_terminal_origins",
    "has_detached_snippet_template",
    "has_detached_replacement_snippet_template",
    "has_terminal_return_carrier_template",
    "imported_detached_snippet_target_eas",
    "materialize_detached_handler_island",
    "materialize_detached_replacement_snippet_templates",
    "materialize_detached_snippet_templates",
    "native_stack_frame_offsets_for_ranges",
    "reconcile_imported_callinfo_with_live_native_calls",
    "redirect_live_target_predecessors",
    "restore_call_result_carriers",
    "restore_detached_call_result_definitions",
    "restore_terminal_return_carriers",
    "stable_mba_identity",
    "validate_detached_call_companion",
]

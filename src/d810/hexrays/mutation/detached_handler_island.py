"""Materialize a proven detached handler as a verifier-valid microcode island."""
from __future__ import annotations

from dataclasses import dataclass, replace

import ida_funcs
import ida_hexrays
import ida_range

from d810.core.typing import Mapping

from d810.analyses.control_flow.detached_handler_island import (
    DetachedHandlerIslandPlan,
    DetachedSnippetReplacementEvidence,
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
    return (
        normalized
        if persistent_frame_size > 0 and normalized >= 0
        else value
    )


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
            int(instruction.ea) == int(ea)
            for instruction in _instructions(block)
        ):
            matches.append(block)
    return tuple(matches)


def find_unique_live_block_by_ea(mba: object, ea: int) -> object | None:
    imported_root = _IMPORTED_SNIPPET_ROOTS.get(
        (stable_mba_identity(mba), int(ea))
    )
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
            native_ea = _IMPORTED_INSTRUCTION_ORIGINS.get(
                (identity, int(imported_ea))
            )
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


@dataclass(frozen=True, slots=True)
class _CallTemplate:
    instruction: object
    argument_size: int


@dataclass(frozen=True, slots=True)
class _AnalyzedCallReplacement:
    instruction: object
    call_opcode: int


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


@dataclass(slots=True)
class _ImportedSnippetRoot:
    """Renumbering-stable identity for one imported snippet root."""

    serial_hint: int
    anchor_eas: tuple[int, ...]
    owned_instruction_eas: tuple[int, ...]


_ANALYZED_CALL_TEMPLATES: dict[tuple[int, int], _CallTemplate] = {}
_DETACHED_SNIPPET_TEMPLATES: dict[
    tuple[int, int],
    DetachedSnippetTemplate,
] = {}
_DETACHED_REPLACEMENT_SNIPPET_TEMPLATES: dict[
    tuple[int, int],
    DetachedSnippetTemplate,
] = {}
_DETACHED_SNIPPET_GENERATIONS: dict[int, int] = {}
_IMPORTED_SNIPPET_ROOTS: dict[tuple[int, int], _ImportedSnippetRoot] = {}
_IMPORTED_INSTRUCTION_ORIGINS: dict[tuple[int, int], int] = {}
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
            if (
                int(instruction.opcode) not in call_opcodes
                or int(instruction.d.t) != int(ida_hexrays.mop_f)
            ):
                continue
            instruction_ea = int(instruction.ea)
            native_ea = origins.get(instruction_ea)
            if native_ea is None:
                native_by_ea.setdefault(instruction_ea, []).append(
                    (block, instruction)
                )
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


def _capture_detached_snippet_template(
    function_ea: int,
    target_ea: int,
    mba: object,
    ranges: tuple[tuple[int, int], ...],
    template_cache: dict[tuple[int, int], DetachedSnippetTemplate],
) -> bool:
    """Cache one explicit-range MBA and its optional stable frame identities."""
    normalized_ranges = tuple(
        sorted((int(start), int(end)) for start, end in ranges if start < end)
    )
    included: dict[int, object] = {}
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        if any(
            _ea_in_ranges(ea, normalized_ranges)
            for ea in _block_native_eas(block)
        ):
            included[int(block.serial)] = block
    roots = tuple(
        serial
        for serial, block in included.items()
        if int(target_ea) in _block_native_eas(block)
        or int(block.start) == int(target_ea)
    )
    if len(roots) != 1:
        return False

    stack_map: dict[int, int] = {}
    stable_stack_map: dict[int, int] = {}
    templates: list[DetachedSnippetBlockTemplate] = []
    for serial, block in sorted(included.items()):
        instructions = tuple(
            ida_hexrays.minsn_t(instruction)
            for instruction in _instructions(block)
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
            for operand in _instruction_operands(instruction):
                if int(operand.t) != int(ida_hexrays.mop_S):
                    continue
                vd_offset = int(operand.s.off)
                ida_offset = int(mba.stkoff_vd2ida(vd_offset))
                stable_ida_offset = _normalize_template_ida_stkoff(
                    int(function_ea),
                    mba,
                    ida_offset,
                )
                previous = stack_map.setdefault(vd_offset, ida_offset)
                if previous != ida_offset:
                    return False
                if stable_ida_offset >= 0:
                    previous_stable = stable_stack_map.setdefault(
                        vd_offset,
                        stable_ida_offset,
                    )
                    if previous_stable != stable_ida_offset:
                        return False

        internal_successors: list[int] = []
        external_successors: list[int] = []
        for successor_serial in block.succset:
            successor = int(successor_serial)
            if successor in included:
                internal_successors.append(successor)
                external_successors.append(0)
                continue
            successor_block = mba.get_mblock(successor)
            successor_ea = (
                _unique_block_native_ea(successor_block)
                if successor_block is not None
                else None
            )
            if successor_ea is None:
                return False
            internal_successors.append(successor)
            external_successors.append(int(successor_ea))

        native_entry = _unique_block_native_ea(block)
        if native_entry is None:
            return False
        templates.append(
            DetachedSnippetBlockTemplate(
                source_serial=int(serial),
                native_entry_ea=int(native_entry),
                instructions=instructions,
                block_type=int(block.type),
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
    template_cache[(int(function_ea), int(target_ea))] = (
        DetachedSnippetTemplate(
            function_ea=int(function_ea),
            target_ea=int(target_ea),
            maturity=int(mba.maturity),
            root_source_serial=int(roots[0]),
            blocks=tuple(templates),
            stack_vd_to_ida=tuple(sorted(stack_map.items())),
            owned_ranges=normalized_ranges,
            call_result_carriers=call_result_carriers,
            stable_stack_vd_to_ida=tuple(sorted(stable_stack_map.items())),
        )
    )
    key = int(function_ea)
    _DETACHED_SNIPPET_GENERATIONS[key] = (
        _DETACHED_SNIPPET_GENERATIONS.get(key, 0) + 1
    )
    return True


def capture_detached_snippet_template(
    function_ea: int,
    target_ea: int,
    mba: object,
    ranges: tuple[tuple[int, int], ...],
) -> bool:
    """Cache one LOCOPT template used for missing detached handlers."""
    return _capture_detached_snippet_template(
        function_ea,
        target_ea,
        mba,
        ranges,
        _DETACHED_SNIPPET_TEMPLATES,
    )


def capture_detached_replacement_snippet_template(
    function_ea: int,
    target_ea: int,
    mba: object,
    ranges: tuple[tuple[int, int], ...],
) -> bool:
    """Cache one CALLS template whose detached conditional arm must survive."""
    return _capture_detached_snippet_template(
        function_ea,
        target_ea,
        mba,
        ranges,
        _DETACHED_REPLACEMENT_SNIPPET_TEMPLATES,
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
    template = _DETACHED_SNIPPET_TEMPLATES.get(
        (int(function_ea), int(target_ea))
    )
    if template is None:
        return ()
    return tuple(
        sorted({int(block.native_entry_ea) for block in template.blocks})
    )


def detached_snippet_template_stack_map(
    function_ea: int,
    target_ea: int,
) -> tuple[tuple[int, int], ...]:
    """Return snippet VD -> stable IDA-frame stack identities for diagnostics."""
    template = _DETACHED_SNIPPET_TEMPLATES.get(
        (int(function_ea), int(target_ea))
    )
    return () if template is None else template.stack_vd_to_ida


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
                if (
                    int(nested.opcode)
                    not in (
                        int(ida_hexrays.m_call),
                        int(ida_hexrays.m_icall),
                    )
                    or int(nested.d.t) != int(ida_hexrays.mop_f)
                ):
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
    template = _DETACHED_SNIPPET_TEMPLATES.get(
        (int(function_ea), int(target_ea))
    )
    if template is None:
        return False
    for block in template.blocks:
        for instruction in block.instructions:
            for nested in _instruction_tree(instruction):
                if (
                    int(nested.opcode)
                    in (
                        int(ida_hexrays.m_call),
                        int(ida_hexrays.m_icall),
                    )
                    and int(nested.d.t) != int(ida_hexrays.mop_f)
                ):
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
                (
                    int(tail.d.b)
                    if int(tail.d.t) == int(ida_hexrays.mop_b)
                    else None
                ),
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
            and sum(
                _ea_in_ranges(ea, detached_ranges) for ea in successor_eas
            )
            == 1
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
        min(row[0] for row in candidate_distances)
        if candidate_distances
        else None
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
    template = _DETACHED_SNIPPET_TEMPLATES.get(
        (int(function_ea), int(target_ea))
    )
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
        if (
            int(instruction.d.t) != int(ida_hexrays.mop_r)
            or int(instruction.d.r) != int(state_register)
        ):
            continue
        if (
            int(instruction.opcode) != int(ida_hexrays.m_mov)
            or int(instruction.l.t) != int(ida_hexrays.mop_n)
        ):
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
    if (
        len(conditional_target_eas) != 2
        or int(conditional_target_eas[0]) == int(conditional_target_eas[1])
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
    template = _DETACHED_SNIPPET_TEMPLATES.get(
        (int(function_ea), int(target_ea))
    )
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
                    tuple(hex(int(instruction.ea)) for instruction in candidate.instructions),
                )
                for candidate in template.blocks
            ],
        )
        return None
    blocks_by_serial = {
        int(block.source_serial): block for block in template.blocks
    }
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
            equivalent_raw_vd = (
                int(source_vd) + int(analyzed_delta) - int(raw_delta)
            )
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
    if any(
        int(template.maturity) != required_maturity for template in selected
    ):
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
            stack_map
            | analyzed_stack_maps_by_target[int(template.target_ea)]
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
        subsumed_setup_eas = subsumed_call_setup_eas_by_target[
            int(template.target_ea)
        ]
        for block in template.blocks:
            for captured in block.instructions:
                if int(captured.ea) in subsumed_setup_eas:
                    continue
                instruction = captured
                instruction_stack_map = raw_stack_map
                captured_opcode = int(captured.opcode)
                if (
                    captured_opcode
                    in (int(ida_hexrays.m_call), int(ida_hexrays.m_icall))
                    and int(captured.d.t) != int(ida_hexrays.mop_f)
                    and not preserve_raw_calls
                ):
                    instruction = analyzed_calls[int(captured.ea)].instruction
                    instruction_stack_map = analyzed_stack_map
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

    modifier = DeferredGraphModifier(mba)
    mba_identity = stable_mba_identity(mba)
    pending_instruction_origins: dict[tuple[int, int], int] = {}
    pending_owned_instruction_eas: dict[int, list[int]] = {
        int(template.target_ea): [] for template in selected
    }
    created: dict[tuple[int, int], object] = {}
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
            created[
                (int(template.target_ea), int(template.root_source_serial))
            ].serial
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
        subsumed_setup_eas = subsumed_call_setup_eas_by_target[
            int(template.target_ea)
        ]
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
            destination = created[
                (int(template.target_ea), int(block.source_serial))
            ]
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
                    instruction = ida_hexrays.minsn_t(
                        analyzed_call.instruction
                    )
                    instruction_stack_map = analyzed_stack_map
                else:
                    instruction = ida_hexrays.minsn_t(captured)
                    instruction_stack_map = stack_map
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
                    pending_owned_instruction_eas[
                        int(template.target_ea)
                    ].append(imported_instruction_ea)
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
                block_type=int(block.block_type),
                flags=(
                    (
                        int(block.block_flags)
                        & (
                            int(ida_hexrays.MBL_GOTO)
                            | (
                                int(ida_hexrays.MBL_PUSH)
                                if preserve_raw_calls
                                else 0
                            )
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

    # A source MBA may encode a one-way edge as ordinary fallthrough.  Once
    # its block is appended to another MBA, that edge is still implicit only
    # when the remapped successor is the imported block's new ``serial+1``.
    # Otherwise verifier.cpp derives ``serial+1`` from the non-closing tail
    # and rejects the explicit non-adjacent succset with INTERR 50860.  Preserve
    # the source edge by making precisely those displaced fallthroughs explicit.
    for destination in created.values():
        if (
            int(destination.type) != int(ida_hexrays.BLT_1WAY)
            or int(destination.nsucc()) != 1
            or int(destination.succset[0]) == int(destination.serial) + 1
            or destination.tail is None
            or bool(ida_hexrays.is_mcode_jcond(int(destination.tail.opcode)))
            or int(destination.tail.opcode)
            in {
                int(ida_hexrays.m_goto),
                int(ida_hexrays.m_ext),
                int(ida_hexrays.m_ijmp),
                int(ida_hexrays.m_jtbl),
                int(ida_hexrays.m_ret),
            }
        ):
            continue
        modifier.make_displaced_fallthrough_explicit_now(destination)

    for destination in created.values():
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
        _IMPORTED_SNIPPET_ROOTS[
            (stable_mba_identity(mba), int(target_ea))
        ] = _ImportedSnippetRoot(
            serial_hint=int(root_serial),
            anchor_eas=tuple(
                int(instruction.ea)
                for instruction in _instructions(root_block)
            ),
            owned_instruction_eas=tuple(
                pending_owned_instruction_eas[int(target_ea)]
            ),
        )
    _IMPORTED_INSTRUCTION_ORIGINS.update(pending_instruction_origins)
    return roots


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
    modifier.mark_blocks_dirty_now(
        *(predecessor for predecessor, _new_serial in rows)
    )
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
    """Replay exact terminal carriers into matching CALLS handler blocks."""
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
            if (
                int(block.type) != int(ida_hexrays.BLT_1WAY)
                or int(block.nsucc()) != 1
            ):
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
    return (
        int(operand.t) == int(ida_hexrays.mop_n)
        and int(operand.nnn.value) == 0
    )


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
            if (
                int(destination.t) == int(ida_hexrays.mop_r)
                and int(destination.r) == int(return_mreg)
            ):
                return None
            if (
                int(destination.t) == int(ida_hexrays.mop_S)
                and int(destination.s.off) == int(candidate.d.s.off)
            ):
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
            or int(branch.opcode)
            not in (int(ida_hexrays.m_jz), int(ida_hexrays.m_jnz))
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
            if (
                int(instruction.ea) == int(instruction_ea)
                and int(instruction.opcode) == int(opcode)
            ):
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
            _operand_reads_stack(argument, stack_offset)
            for argument in operand.f.args
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


def capture_detached_handler_call_templates(function_ea: int, mba: object) -> None:
    """Retain owned one-argument CALLS templates for the next LOCOPT MBA."""
    key = int(function_ea)
    for callee_ea, template in _analyzed_call_templates(mba):
        _ANALYZED_CALL_TEMPLATES[(key, int(callee_ea))] = _CallTemplate(
            instruction=ida_hexrays.minsn_t(template.instruction),
            argument_size=int(template.argument_size),
        )


def clear_detached_handler_call_templates() -> None:
    """Clear CALLS templates at resolver teardown or project reload."""
    _ANALYZED_CALL_TEMPLATES.clear()
    _DETACHED_SNIPPET_TEMPLATES.clear()
    _DETACHED_SNIPPET_GENERATIONS.clear()
    _IMPORTED_SNIPPET_ROOTS.clear()
    _IMPORTED_INSTRUCTION_ORIGINS.clear()
    clear_owned_fake_block_registrations()


def clear_imported_detached_snippet_roots() -> None:
    """Forget live-MBA serials while retaining cross-decompile templates."""
    _IMPORTED_SNIPPET_ROOTS.clear()
    _IMPORTED_INSTRUCTION_ORIGINS.clear()


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
    source_argument_stkoff = int(
        mba.stkoff_ida2vd(int(plan.call_argument_ida_stkoff))
    )
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
    free_block = mba.get_mblock(
        modifier.insert_nop_block_now(int(source.serial))
    )
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
    "CallResultCarrier",
    "DetachedSnippetBlockTemplate",
    "DetachedSnippetTemplate",
    "capture_call_result_carriers",
    "capture_terminal_return_carrier_template",
    "capture_detached_handler_call_templates",
    "capture_detached_replacement_snippet_template",
    "capture_detached_snippet_template",
    "clear_detached_handler_call_templates",
    "clear_terminal_return_carrier_templates",
    "clear_imported_detached_snippet_roots",
    "detached_snippet_template_generation",
    "detached_snippet_conditional_evidence",
    "detached_snippet_replacement_evidence",
    "detached_snippet_replacement_arm_states",
    "detached_snippet_requires_analyzed_calls",
    "detached_snippet_template_block_eas",
    "detached_snippet_template_stack_map",
    "find_unique_live_block_by_ea",
    "imported_detached_snippet_instruction_origins",
    "imported_detached_snippet_terminal_origins",
    "has_detached_snippet_template",
    "has_detached_replacement_snippet_template",
    "has_terminal_return_carrier_template",
    "imported_detached_snippet_target_eas",
    "materialize_detached_handler_island",
    "materialize_detached_replacement_snippet_templates",
    "materialize_detached_snippet_templates",
    "reconcile_imported_callinfo_with_live_native_calls",
    "redirect_live_target_predecessors",
    "restore_call_result_carriers",
    "restore_terminal_return_carriers",
    "stable_mba_identity",
]

"""Diagnostics-only OLLVM semantic carrier collector.

The state DAG tells us which dispatcher states exist, but OLLVM parity also
needs named semantic carriers before CFG planning can safely rewrite.  This
collector records conservative microcode evidence for those carriers without
authorizing any rewrite:

* argument pointer copies from the ABI registers;
* password buffer / compare-result call sites;
* loop-index bound predicates;
* accumulator updates;
* argument-output stores when the store target is tied to the ``rdx`` carrier;
* local working-value stores when the target is an address-of-local alias.

The facts are intentionally descriptive.  Consumers must still prove branch
ownership and block exclusivity before using them for materialization.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from d810.core.typing import Any, Iterable
from d810.recon.facts.collectors.induction_carrier import (
    _MATURITY_VALUES,
    _InstructionView,
    _iter_instruction_views,
    _maturity_name,
)
from d810.recon.facts.collectors.state_write_anchor import (
    _block_start_ea_lookup,
    _instruction_anchor_ea,
)
from d810.recon.facts.model import FactObservation

_TARGET_MATURITIES = frozenset({
    _MATURITY_VALUES["MMAT_LOCOPT"],
    _MATURITY_VALUES["MMAT_CALLS"],
    _MATURITY_VALUES["MMAT_GLBOPT1"],
    _MATURITY_VALUES["MMAT_GLBOPT2"],
    _MATURITY_VALUES["MMAT_GLBOPT3"],
    _MATURITY_VALUES["MMAT_LVARS"],
})

_VAR_TOKEN_RE = re.compile(r"(?:%var_[0-9A-Fa-f]+|v\d+)")
_ARG_MOVE_RE = re.compile(
    r"^\s*mov\s+(?P<reg>rcx|rdx)\.8(?:\{[^}]*\})?,\s*"
    r"(?P<dst>(?:%var_[0-9A-Fa-f]+|v\d+))\.8",
    re.IGNORECASE,
)
_LOCAL_ADDR_MOVE_RE = re.compile(
    r"^\s*mov\s+&\((?P<src>(?:%var_[0-9A-Fa-f]+|v\d+))(?:\{[^}]*\})?\)"
    r"\.8,\s*(?P<dst>(?:%var_[0-9A-Fa-f]+|v\d+))\.8",
    re.IGNORECASE,
)
_VAR_COPY_RE = re.compile(
    r"^\s*mov\s+(?P<src>(?:%var_[0-9A-Fa-f]+|v\d+))\.8(?:\{[^}]*\})?,\s*"
    r"(?P<dst>(?:%var_[0-9A-Fa-f]+|v\d+))\.8",
    re.IGNORECASE,
)
_CALL_DEST_RE = re.compile(
    r"=>\s*[^,]+,\s*(?P<dst>(?:%var_[0-9A-Fa-f]+|v\d+))\.\d+",
    re.IGNORECASE,
)
_ADDR_TOKEN_RE = re.compile(
    r"&\((?P<token>(?:%var_[0-9A-Fa-f]+|v\d+))(?:\{[^}]*\})?\)\.8",
    re.IGNORECASE,
)
_DS_INDIRECT_TARGET_RE = re.compile(
    r"\[ds[^\]]*:(?P<token>%var_[0-9A-Fa-f]+|v\d+)\.8",
    re.IGNORECASE,
)
_DIRECT_TARGET_RE = re.compile(
    r"(?P<token>%var_[0-9A-Fa-f]+|v\d+)\.8",
    re.IGNORECASE,
)
_LOOP_BOUND_RE = re.compile(
    r"\bset[blge]+\s+\[ds[^\]]*:(?P<token>%var_[0-9A-Fa-f]+|v\d+)"
    r"\.8[^\]]*\]\.4,\s*#0x64\.4",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _CarrierHit:
    role: str
    token: str
    insn: _InstructionView
    confidence: float
    details: dict[str, Any]


def _canonical_token(token: str | None) -> str | None:
    if token is None:
        return None
    if token.startswith("%var_"):
        return f"%var_{token[5:].upper()}"
    return token


def _tokens(text: str) -> tuple[str, ...]:
    return tuple(
        token for token in (
            _canonical_token(match.group(0)) for match in _VAR_TOKEN_RE.finditer(text)
        )
        if token is not None
    )


def _first_addr_token(text: str) -> str | None:
    match = _ADDR_TOKEN_RE.search(text)
    if match is None:
        return None
    return _canonical_token(match.group("token"))


def _call_dest_token(text: str) -> str | None:
    match = _CALL_DEST_RE.search(text)
    if match is None:
        return None
    return _canonical_token(match.group("dst"))


def _store_target_token(text: str) -> str | None:
    if ", ds" not in text:
        return None
    tail = text.rsplit(", ds", 1)[-1]
    match = _DS_INDIRECT_TARGET_RE.search(tail)
    if match is None:
        match = _DIRECT_TARGET_RE.search(tail)
    if match is None:
        return None
    return _canonical_token(match.group("token"))


def _looks_like_ollvm_function(instructions: tuple[_InstructionView, ...]) -> bool:
    text = "\n".join(insn.dstr for insn in instructions)
    return (
        "$aSecret" in text
        or "$aPleaseEnterPas" in text
        or "$dword_18001D508" in text
        or "$dword_18001D50C" in text
    )


def _carrier_alias_sets(
    instructions: tuple[_InstructionView, ...],
) -> tuple[frozenset[str], frozenset[str], dict[str, str]]:
    output_aliases: set[str] = set()
    local_pointer_aliases: set[str] = set()
    local_pointer_base: dict[str, str] = {}

    for insn in instructions:
        dstr = insn.dstr
        arg_match = _ARG_MOVE_RE.search(dstr)
        if arg_match is not None and arg_match.group("reg").lower() == "rdx":
            token = _canonical_token(arg_match.group("dst"))
            if token is not None:
                output_aliases.add(token)
            continue

        local_match = _LOCAL_ADDR_MOVE_RE.search(dstr)
        if local_match is not None:
            source = _canonical_token(local_match.group("src"))
            target = _canonical_token(local_match.group("dst"))
            if source is not None and target is not None:
                local_pointer_aliases.add(target)
                local_pointer_base[target] = source
            continue

        copy_match = _VAR_COPY_RE.search(dstr)
        if copy_match is None:
            continue
        source = _canonical_token(copy_match.group("src"))
        target = _canonical_token(copy_match.group("dst"))
        if source is None or target is None:
            continue
        if source in output_aliases:
            output_aliases.add(target)
        if source in local_pointer_aliases:
            local_pointer_aliases.add(target)
            local_pointer_base[target] = local_pointer_base.get(source, source)

    return (
        frozenset(sorted(output_aliases)),
        frozenset(sorted(local_pointer_aliases)),
        local_pointer_base,
    )


def _masked_store_role(
    target: str,
    *,
    output_pointer_aliases: frozenset[str],
    local_pointer_aliases: frozenset[str],
) -> str:
    if target in output_pointer_aliases:
        return "ARG_OUTPUT_STORE_CANDIDATE"
    if target in local_pointer_aliases:
        return "LOCAL_WORKING_STORE_CANDIDATE"
    return "INDIRECT_STORE_CANDIDATE"


def _iter_carrier_hits(instructions: tuple[_InstructionView, ...]) -> Iterable[_CarrierHit]:
    (
        output_pointer_aliases,
        local_pointer_aliases,
        local_pointer_base,
    ) = _carrier_alias_sets(instructions)

    for insn in instructions:
        dstr = insn.dstr
        arg_match = _ARG_MOVE_RE.search(dstr)
        if arg_match is not None:
            reg = arg_match.group("reg").lower()
            role = "ARG_INPUT_POINTER" if reg == "rcx" else "ARG_OUTPUT_POINTER"
            token = _canonical_token(arg_match.group("dst"))
            if token is not None:
                yield _CarrierHit(
                    role=role,
                    token=token,
                    insn=insn,
                    confidence=0.90,
                    details={"register": reg},
                )

        local_match = _LOCAL_ADDR_MOVE_RE.search(dstr)
        if local_match is not None:
            target = _canonical_token(local_match.group("dst"))
            source = _canonical_token(local_match.group("src"))
            if target is not None and source is not None:
                yield _CarrierHit(
                    role="LOCAL_WORKING_POINTER",
                    token=target,
                    insn=insn,
                    confidence=0.86,
                    details={"local_base_token": source},
                )

        if "$aS" in dstr and "$aSecret" not in dstr and "call" in dstr:
            token = _first_addr_token(dstr)
            if token is not None:
                yield _CarrierHit(
                    role="PASSWORD_BUFFER",
                    token=token,
                    insn=insn,
                    confidence=0.85,
                    details={"call_kind": "scanf_like"},
                )

        if "$aSecret" in dstr and "call" in dstr:
            token = _call_dest_token(dstr)
            buffer_token = _first_addr_token(dstr)
            if token is not None:
                yield _CarrierHit(
                    role="PASSWORD_COMPARE_RESULT",
                    token=token,
                    insn=insn,
                    confidence=0.88,
                    details={
                        "call_kind": "strncmp_like",
                        "password_buffer_token": buffer_token,
                    },
                )

        loop_match = _LOOP_BOUND_RE.search(dstr)
        if loop_match is not None:
            token = _canonical_token(loop_match.group("token"))
            if token is not None:
                details: dict[str, Any] = {"bound": 0x64}
                if token in local_pointer_base:
                    details["local_base_token"] = local_pointer_base[token]
                yield _CarrierHit(
                    role="LOOP_INDEX_CARRIER",
                    token=token,
                    insn=insn,
                    confidence=0.82,
                    details=details,
                )

        if insn.opcode_name in {"m_stx", "op_1"}:
            target = _store_target_token(dstr)
            if target is None:
                continue
            all_tokens = _tokens(dstr)
            if target in all_tokens[:-1] and any(
                marker in dstr
                for marker in ("#5.4*", "+#0x42", "-#0x42", "#0xFFFFFFBD")
            ):
                details: dict[str, Any] = {"store_kind": "self_update"}
                if "#5.4*" in dstr:
                    target_base = local_pointer_base.get(target)
                    same_base_aliases = tuple(sorted(
                        token for token in set(all_tokens[:-1])
                        if (
                            token != target
                            and target_base is not None
                            and local_pointer_base.get(token) == target_base
                        )
                    ))
                    details.update({
                        "multiply_add_operand_tokens": tuple(sorted(set(all_tokens[:-1]))),
                        "multiply_add_base_token": target_base,
                        "multiply_add_same_base_alias_tokens": same_base_aliases,
                        "same_carrier_alias_proof": bool(same_base_aliases),
                    })
                yield _CarrierHit(
                    role="ACCUMULATOR_CARRIER",
                    token=target,
                    insn=insn,
                    confidence=0.80,
                    details=details,
                )
            if any(
                marker in dstr
                for marker in (
                    "#0x173063C1",
                    "#0xE8CF9C3E",
                    "#0xCD536960",
                    "#0x32AC969F",
                    "#0x259CF55E",
                )
            ):
                role = _masked_store_role(
                    target,
                    output_pointer_aliases=output_pointer_aliases,
                    local_pointer_aliases=local_pointer_aliases,
                )
                details = {"store_kind": "masked_output_transform"}
                if target in local_pointer_base:
                    details["local_base_token"] = local_pointer_base[target]
                yield _CarrierHit(
                    role=role,
                    token=target,
                    insn=insn,
                    confidence=0.78,
                    details=details,
                )


class OllvmValueFlowEvidenceCollector:
    """Observe OLLVM value-flow evidence without changing behavior.

    Canonical class name (value-flow rename Phase 4). The legacy class
    name ``OllvmSemanticCarrierFactCollector`` is preserved as an alias
    at the end of this module. The serialized ``FactObservation.kind``
    value stays ``"OllvmSemanticCarrierFact"`` so old diag SQLite
    snapshots remain queryable via the Phase 3 alias registry. This
    collector remains fixture/oracle evidence per ADR-12; it is not the
    generic value-flow ontology.
    """

    name = "OllvmSemanticCarrierFactCollector"
    fact_kinds = frozenset({"OllvmSemanticCarrierFact"})
    maturities = _TARGET_MATURITIES

    def collect(
        self,
        target: Any,
        *,
        func_ea: int,
        maturity: int,
        phase: str,
    ) -> tuple[FactObservation, ...]:
        maturity_text = _maturity_name(maturity)
        instructions = tuple(_iter_instruction_views(target))
        if not instructions or not _looks_like_ollvm_function(instructions):
            return ()

        block_start_ea = _block_start_ea_lookup(target)
        observations: list[FactObservation] = []
        seen: set[tuple[str, str, int, int]] = set()

        for hit in _iter_carrier_hits(instructions):
            key = (
                hit.role,
                hit.token,
                int(hit.insn.block_serial),
                int(hit.insn.insn_index),
            )
            if key in seen:
                continue
            seen.add(key)

            source_ea = _instruction_anchor_ea(hit.insn, block_start_ea)
            semantic_key = f"ollvm_carrier:{hit.role}:{hit.token}"
            fact_id = (
                f"{semantic_key}:blk={int(hit.insn.block_serial)}:"
                f"insn={int(hit.insn.insn_index)}:"
                f"maturity={maturity_text}:phase={phase}"
            )
            payload = {
                "role": hit.role,
                "carrier_token": hit.token,
                "source_block": int(hit.insn.block_serial),
                "instruction_index": int(hit.insn.insn_index),
                "instruction_ea": source_ea,
                "instruction_ea_hex": (
                    f"0x{int(source_ea) & 0xFFFFFFFFFFFFFFFF:016x}"
                    if source_ea is not None
                    else None
                ),
                "instruction_opcode_name": hit.insn.opcode_name,
                "instruction_dstr": hit.insn.dstr,
                **hit.details,
            }
            observations.append(
                FactObservation(
                    fact_id=fact_id,
                    kind="OllvmSemanticCarrierFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=hit.confidence,
                    source_block=int(hit.insn.block_serial),
                    source_ea=source_ea,
                    block_fingerprint=(
                        f"blk[{int(hit.insn.block_serial)}]."
                        f"{int(hit.insn.insn_index)}:{hit.insn.opcode_name}"
                    ),
                    mop_signature=f"ollvm_carrier:{hit.role}:{hit.token}",
                    payload=payload,
                    evidence=(hit.insn.dstr,),
                )
            )

        return tuple(observations)


__all__ = [
    "OllvmSemanticCarrierFactCollector",
    "OllvmValueFlowEvidenceCollector",
]


# Legacy class name kept as an alias during the value-flow rename.
OllvmSemanticCarrierFactCollector = OllvmValueFlowEvidenceCollector

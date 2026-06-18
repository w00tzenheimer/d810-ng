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
import hashlib
import re

from d810.core.logging import getLogger
from d810.core.project import register_recon_fact_collector_registration_handler
from d810.core.typing import Any, Iterable
from d810.capabilities.providers import get_condition_chain_walkers, get_microcode_evidence
from d810.capabilities.source_lifter import select_lifter
from d810.analyses.control_flow.branch_ownership import (
    BranchOwnershipProof,
    BranchOwnershipProofKind,
)
from d810.analyses.control_flow.branch_ownership_oracle import (
    MopTrackerBranchOwnershipOracle,
    PredicateOwnershipKind,
    Z3BranchOwnershipOracle,
)
from d810.analyses.value_flow.induction_carrier import (
    _MATURITY_VALUES,
    _InstructionView,
    _iter_instruction_views,
    _maturity_name,
)
from d810.analyses.value_flow.state_write_anchor import (
    _block_start_ea_lookup,
    _instruction_anchor_ea,
)
from d810.analyses.value_flow.model import FactObservation
from d810.analyses.value_flow.observation import JsonMapping
from d810.analyses.value_flow.projection import (
    CALL_RETURN_VALUE_FACT_TYPE,
    LOOP_PREDICATE_VALUE_FACT_TYPE,
    MAY_ALIAS_FACT_TYPE,
    MUST_ALIAS_FACT_TYPE,
    OBSERVABLE_MEMORY_DEF_FACT_TYPE,
    OBSERVABLE_OUTPUT_FACT_TYPE,
    POINTS_TO_FACT_TYPE,
    SCALAR_PROMOTION_FACT_TYPE,
    SCALAR_REPLACEMENT_FACT_TYPE,
    SYMBOLIC_EXPRESSION_FACT_TYPE,
    VALUE_FLOW_FACT_TYPES,
    make_projected_value_flow_fact,
    value_flow_hex,
    value_flow_producer_fact_ids,
    value_flow_source_identity,
)

logger = getLogger(__name__)

OLLVM_CARRIER_PROFILE_MODULE = __name__
OLLVM_CARRIER_PROFILE_NAME = "ollvm_carrier"
_OLLVM_CARRIER_REGISTRATION_HANDLER = "ollvm_carrier_fact_collectors"

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


def _config_values(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        items = (value,)
    else:
        try:
            items = tuple(value)  # type: ignore[arg-type]
        except TypeError:
            items = (value,)
    return tuple(str(item).strip() for item in items if str(item).strip())


def _ollvm_carrier_profile_enabled(project_config: dict[str, object]) -> bool:
    modules = set(_config_values(project_config.get("recon_fact_profile_modules")))
    profiles = set(_config_values(project_config.get("recon_fact_profiles")))
    return (
        bool(project_config.get("enable_ollvm_carrier_evidence"))
        or OLLVM_CARRIER_PROFILE_MODULE in modules
        or OLLVM_CARRIER_PROFILE_NAME in profiles
    )


def _register_ollvm_carrier_fact_collectors(
    *,
    runtime: object,
    project_config: dict[str, object],
) -> None:
    if not _ollvm_carrier_profile_enabled(project_config):
        return
    register = getattr(runtime, "register_fact_collector", None)
    if not callable(register):
        logger.warning("OLLVM carrier profile runtime has no fact collector registrar")
        return
    try:
        register(OllvmCarrierProfileFactCollector())
    except ValueError as exc:
        if "already registered" not in str(exc):
            raise


register_recon_fact_collector_registration_handler(
    _OLLVM_CARRIER_REGISTRATION_HANDLER,
    _register_ollvm_carrier_fact_collectors,
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
    token = str(token).strip()
    if not token:
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


def _looks_like_native_secret_compare_call(text: str) -> bool:
    """Native IDA can render ``strncmp(buffer, "secret", 100)`` as ``__ImageBase``.

    On macOS-hosted IDA the string literal may appear as ``$hinstDLL@3`` instead
    of ``$aSecret`` while the call still carries the same semantic shape:
    password-buffer address, global string address, and bound ``0x64``.
    """
    return (
        "call" in text
        and "$__ImageBase" in text
        and "$hinstDLL@3" in text
        and "#0x64" in text
        and _first_addr_token(text) is not None
        and _call_dest_token(text) is not None
    )


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

        if _looks_like_native_secret_compare_call(dstr):
            token = _call_dest_token(dstr)
            buffer_token = _first_addr_token(dstr)
            if buffer_token is not None:
                yield _CarrierHit(
                    role="PASSWORD_BUFFER",
                    token=buffer_token,
                    insn=insn,
                    confidence=0.82,
                    details={"call_kind": "native_imagebase_strncmp_like"},
                )
            if token is not None:
                yield _CarrierHit(
                    role="PASSWORD_COMPARE_RESULT",
                    token=token,
                    insn=insn,
                    confidence=0.86,
                    details={
                        "call_kind": "native_imagebase_strncmp_like",
                        "password_buffer_token": buffer_token,
                        "password_literal_token": "$hinstDLL@3",
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

        if insn.opcode_name in {"m_stx", "op_1", "store"}:
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


class OllvmCarrierRawEvidenceCollector:
    """Observe OLLVM value-flow evidence without changing behavior.

    Profile-local collector for OLLVM-specific raw evidence. Observations keep
    the persisted ``"OllvmValueFlowEvidence"`` kind for diagnostics, but generic
    value-flow consumers must use projected canonical fact families instead.
    """

    name = "OllvmCarrierRawEvidenceCollector"
    fact_kinds = frozenset({"OllvmValueFlowEvidence"})
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
            source_ea_text = (
                f"0x{int(source_ea) & 0xFFFFFFFFFFFFFFFF:016x}"
                if source_ea is not None
                else "?"
            )
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
                    source_ea_text if source_ea is not None else None
                ),
                "instruction_opcode_name": hit.insn.opcode_name,
                "instruction_dstr": hit.insn.dstr,
                **hit.details,
            }
            observations.append(
                FactObservation(
                    fact_id=fact_id,
                    kind="OllvmValueFlowEvidence",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=hit.confidence,
                    source_block=int(hit.insn.block_serial),
                    source_ea=source_ea,
                    block_fingerprint=(
                        f"blk[{int(hit.insn.block_serial)}]@{source_ea_text}."
                        f"{int(hit.insn.insn_index)}:{hit.insn.opcode_name}"
                    ),
                    mop_signature=f"ollvm_carrier:{hit.role}:{hit.token}",
                    payload=payload,
                    evidence=(hit.insn.dstr,),
                )
            )

        return tuple(observations)


class OllvmCarrierProfileFactCollector:
    """Profile-local collector that publishes raw and projected OLLVM facts."""

    name = "OllvmCarrierProfileFactCollector"
    fact_kinds = frozenset({
        "OllvmValueFlowEvidence",
        OBSERVABLE_MEMORY_DEF_FACT_TYPE,
        SCALAR_PROMOTION_FACT_TYPE,
        MUST_ALIAS_FACT_TYPE,
        MAY_ALIAS_FACT_TYPE,
        SCALAR_REPLACEMENT_FACT_TYPE,
        SYMBOLIC_EXPRESSION_FACT_TYPE,
        LOOP_PREDICATE_VALUE_FACT_TYPE,
        CALL_RETURN_VALUE_FACT_TYPE,
        OBSERVABLE_OUTPUT_FACT_TYPE,
        POINTS_TO_FACT_TYPE,
    })
    maturities = _TARGET_MATURITIES

    def __init__(
        self,
        raw_collector: OllvmCarrierRawEvidenceCollector | None = None,
    ) -> None:
        self._raw_collector = raw_collector or OllvmCarrierRawEvidenceCollector()

    def collect(
        self,
        target: Any,
        *,
        func_ea: int,
        maturity: int,
        phase: str,
    ) -> tuple[FactObservation, ...]:
        raw = self._raw_collector.collect(
            target,
            func_ea=func_ea,
            maturity=maturity,
            phase=phase,
        )
        return (*raw, *project_ollvm_value_flow_evidence(raw))


class OllvmCarrierBranchOwnershipOracle:
    """Classify OLLVM semantic branches from observed carrier facts.

    This oracle is intentionally conservative and read-only. It upgrades an
    unresolved conditional edge only when the branch predicate text references a
    predicate token derived from OLLVM semantic carrier facts.
    """

    def __init__(
        self,
        *,
        mba: object | None,
        carrier_facts: tuple[object, ...] = (),
    ) -> None:
        self._mba = mba
        self._carrier_facts = _normalized_carrier_facts(tuple(carrier_facts or ()))
        instruction_texts = tuple(_iter_mba_instruction_texts(mba))
        self._password_predicate_tokens = _derive_data_predicate_tokens(
            _carrier_projection_tokens(
                self._carrier_facts,
                fact_kinds=frozenset({CALL_RETURN_VALUE_FACT_TYPE}),
            ),
            instruction_texts,
        )
        self._loop_predicate_tokens = _derive_loop_predicate_tokens(
            _carrier_projection_tokens(
                self._carrier_facts,
                fact_kinds=frozenset({LOOP_PREDICATE_VALUE_FACT_TYPE}),
            ),
            instruction_texts,
        )

    def refine(
        self,
        proof: BranchOwnershipProof,
        edge: object,
    ) -> BranchOwnershipProof | None:
        """Return a semantic branch proof for *edge*, or ``None``."""

        if not _carrier_oracle_may_refine(proof):
            return None
        if proof.source_block is None or proof.branch_arm is None:
            return None
        if proof.source_state is None or proof.target_state is None:
            return None
        if proof.target_entry is None:
            return None
        if _edge_kind_name(edge) != "CONDITIONAL_TRANSITION":
            return None

        block = self._get_block(proof.source_block)
        if block is None or _block_nsucc(block) != 2:
            return None
        tail = getattr(block, "tail", None)
        if tail is None:
            return None

        tail_text = _format_insn_text(tail)
        tail_tokens = frozenset(_tokens(tail_text))
        if not tail_tokens:
            return None

        password_matches = tuple(
            sorted(tail_tokens & self._password_predicate_tokens)
        )
        if password_matches:
            return self._replace_proof(
                proof,
                reason="ollvm_carrier_password_compare_predicate",
                carrier_kind="call_result",
                expression_class="call_result",
                predicate_tokens=password_matches,
                tail_text=tail_text,
                edge=edge,
            )

        loop_matches = tuple(sorted(tail_tokens & self._loop_predicate_tokens))
        if loop_matches:
            return self._replace_proof(
                proof,
                reason="ollvm_carrier_loop_index_predicate",
                carrier_kind="induction",
                expression_class="loop_predicate_carrier",
                predicate_tokens=loop_matches,
                tail_text=tail_text,
                edge=edge,
            )

        return None

    def _replace_proof(
        self,
        proof: BranchOwnershipProof,
        *,
        reason: str,
        carrier_kind: str,
        expression_class: str,
        predicate_tokens: tuple[str, ...],
        tail_text: str,
        edge: object,
    ) -> BranchOwnershipProof:
        evidence = dict(proof.evidence)
        evidence.update({
            "predicate_ownership_kind": (
                PredicateOwnershipKind.REAL_DATA_DEPENDENT.value
            ),
            "predicate_ownership_reason": reason,
            "carrier_kind": carrier_kind,
            "expression_class": expression_class,
            "predicate_tokens": predicate_tokens,
            "tail_text": tail_text,
            "via_pred": _path_predecessor(edge, proof.source_block),
        })
        return BranchOwnershipProof(
            proof_id=proof.proof_id,
            proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
            trusted=True,
            reason=reason,
            source_block=proof.source_block,
            branch_arm=proof.branch_arm,
            source_state=proof.source_state,
            target_state=proof.target_state,
            target_entry=proof.target_entry,
            predicate_block=proof.predicate_block,
            dispatcher_entry_block=proof.dispatcher_entry_block,
            oracle_kind="ollvm_carrier_branch_ownership",
            evidence=evidence,
            payload=dict(proof.payload),
        )

    def _get_block(self, serial: int) -> object | None:
        if self._mba is None:
            return None
        try:
            return get_condition_chain_walkers().get_block(self._mba, int(serial))
        except Exception:
            return None


def _collector_target(target: object) -> object | None:
    if target is None:
        return None
    if hasattr(target, "blocks") and not (
        hasattr(target, "qty") and hasattr(target, "get_mblock")
    ):
        return target
    lifter = select_lifter(target)
    if lifter is None:
        return None
    try:
        return lifter.lift(target)
    except Exception:
        return None


def collect_ollvm_raw_semantic_carrier_facts(mba: object) -> tuple[object, ...]:
    if mba is None:
        return ()
    target = _collector_target(mba)
    if target is None:
        return ()
    try:
        return tuple(
            OllvmCarrierRawEvidenceCollector().collect(
                target,
                func_ea=int(getattr(mba, "entry_ea", 0) or 0),
                maturity=int(getattr(mba, "maturity", 0) or 0),
                phase="pre_d810",
            )
        )
    except Exception:
        return ()


def collect_ollvm_post_execute_carrier_facts(mba: object) -> tuple[object, ...]:
    return project_ollvm_value_flow_evidence(
        collect_ollvm_raw_semantic_carrier_facts(mba)
    )


def collect_ollvm_profile_fact_observations(mba: object) -> tuple[object, ...]:
    raw_facts = collect_ollvm_raw_semantic_carrier_facts(mba)
    if not raw_facts:
        return ()
    projected_facts = project_ollvm_value_flow_evidence(raw_facts)
    return (*raw_facts, *projected_facts)


def _microcode_opcode_label_resolver(mba: object):
    try:
        constants = get_microcode_evidence().microcode_constants(mba)
    except Exception:
        return None
    opcode_names = {
        int(getattr(constants, name)): name
        for name in (
            "m_jz",
            "m_jnz",
            "m_jge",
            "m_jg",
            "m_jle",
            "m_jl",
            "m_jae",
            "m_ja",
            "m_jbe",
            "m_jb",
            "m_jcnd",
            "m_stx",
            "m_call",
            "m_icall",
        )
        if getattr(constants, name, -1) is not None
        and int(getattr(constants, name, -1)) >= 0
    }
    if not opcode_names:
        return None

    def _resolve(insn_or_opcode: object) -> str | None:
        opcode = getattr(insn_or_opcode, "opcode", insn_or_opcode)
        try:
            return opcode_names.get(int(opcode))
        except (TypeError, ValueError):
            return None

    return _resolve


def collect_ollvm_branch_ownership_refiners(
    mba: object,
    logger: object,
) -> tuple[object, ...]:
    try:
        opcode_label_resolver = _microcode_opcode_label_resolver(mba)
        return (
            OllvmCarrierBranchOwnershipOracle(
                mba=mba,
                carrier_facts=collect_ollvm_post_execute_carrier_facts(mba),
            ).refine,
            Z3BranchOwnershipOracle(
                mba=mba,
                opcode_label_resolver=opcode_label_resolver,
            ).refine,
            MopTrackerBranchOwnershipOracle(
                mba=mba,
                opcode_label_resolver=opcode_label_resolver,
            ).refine,
        )
    except Exception:
        log_debug = getattr(logger, "debug", None)
        if callable(log_debug):
            log_debug(
                "Microcode branch ownership oracle unavailable",
                exc_info=True,
            )
        return ()


def project_ollvm_value_flow_evidence(
    observations: Iterable[FactObservation],
) -> tuple[FactObservation, ...]:
    """Project OLLVM raw evidence into canonical value-flow fact families."""

    projected: list[FactObservation] = []
    for observation in observations:
        if observation.kind != "OllvmValueFlowEvidence":
            continue
        projected.extend(_project_ollvm_oracle_fact(observation))
    return tuple(projected)


def _project_ollvm_oracle_fact(
    observation: FactObservation,
) -> tuple[FactObservation, ...]:
    payload = observation.payload
    role = str(payload.get("role") or "")
    token = _canonical_token(str(payload.get("carrier_token") or ""))
    producer_ids = value_flow_producer_fact_ids(observation)
    if token is None:
        return ()
    exact = _ollvm_exact_source_identity(observation, token=token)
    if exact is None:
        return ()

    if role in {
        "ARG_OUTPUT_STORE_CANDIDATE",
        "LOCAL_WORKING_STORE_CANDIDATE",
    }:
        extra_details = _ollvm_local_scalarization_details(payload)
        return (
            _ollvm_exact_fact(
                observation,
                exact=exact,
                kind=OBSERVABLE_MEMORY_DEF_FACT_TYPE,
                semantic_key=f"observable_store:token:{token}",
                expression_class="output_store_carrier_proof",
                observable_effect="output_store",
                proof_family="observable_output_store_carrier",
                producer_ids=producer_ids,
                role=role,
                extra_details=extra_details,
            ),
            _ollvm_exact_fact(
                observation,
                exact=exact,
                kind=SCALAR_PROMOTION_FACT_TYPE,
                semantic_key=f"carrier_store_promotion:token:{token}",
                expression_class="carrier_store_promotion_proof",
                observable_effect="output_store",
                proof_family="observable_output_store_carrier_promotion",
                producer_ids=producer_ids,
                role=role,
                extra_details=extra_details,
            ),
            _ollvm_exact_fact(
                observation,
                exact=exact,
                kind=OBSERVABLE_OUTPUT_FACT_TYPE,
                semantic_key=f"observable_output:token:{token}",
                expression_class="output_store_carrier_proof",
                observable_effect="output_store",
                proof_family="observable_output_store_carrier",
                producer_ids=producer_ids,
                role=role,
                extra_details=extra_details,
            ),
        )

    if role == "LOCAL_WORKING_POINTER":
        local_details = _ollvm_local_scalarization_details(payload)
        return (
            _ollvm_exact_fact(
                observation,
                exact=exact,
                kind=SCALAR_REPLACEMENT_FACT_TYPE,
                semantic_key=f"local_storage_scalarization:token:{token}",
                expression_class="local_storage_scalarization_proof",
                observable_effect="none",
                proof_family="local_pointer_storage_scalarization",
                producer_ids=producer_ids,
                role=role,
                extra_details=local_details,
            ),
            _ollvm_exact_fact(
                observation,
                exact=exact,
                kind=MAY_ALIAS_FACT_TYPE,
                semantic_key=f"may_alias:token:{token}",
                expression_class="local_pointer_alias_set",
                observable_effect="none",
                proof_family="local_pointer_alias_evidence",
                producer_ids=producer_ids,
                role=role,
                extra_details=local_details,
            ),
        )

    if role == "ARG_OUTPUT_POINTER":
        return (_ollvm_exact_fact(
            observation,
            exact=exact,
            kind=POINTS_TO_FACT_TYPE,
            semantic_key=f"output_pointer:token:{token}",
            expression_class="argument_output_pointer",
            observable_effect="output_buffer_pointer",
            proof_family="argument_output_pointer_identity",
            producer_ids=producer_ids,
            role=role,
        ),)

    if role == "INDIRECT_STORE_CANDIDATE":
        return (_ollvm_exact_fact(
            observation,
            exact=exact,
            kind=SCALAR_PROMOTION_FACT_TYPE,
            semantic_key=f"carrier_store_promotion:token:{token}",
            expression_class="carrier_store_promotion_proof",
            observable_effect="output_store",
            proof_family="observable_carrier_store",
            producer_ids=producer_ids,
            role=role,
        ),)

    if role == "LOOP_INDEX_CARRIER":
        return (_ollvm_exact_fact(
            observation,
            exact=exact,
            kind=LOOP_PREDICATE_VALUE_FACT_TYPE,
            semantic_key=f"loop_predicate:token:{token}",
            expression_class="loop_predicate_carrier_proof",
            observable_effect="none",
            proof_family="local_loop_predicate_carrier",
            producer_ids=producer_ids,
            role=role,
            extra_details=_ollvm_local_scalarization_details(payload),
        ),)

    if role == "PASSWORD_COMPARE_RESULT":
        return (_ollvm_exact_fact(
            observation,
            exact=exact,
            kind=CALL_RETURN_VALUE_FACT_TYPE,
            semantic_key=f"call_result:token:{token}",
            expression_class="call_result",
            observable_effect="branch_predicate",
            proof_family="call_result_predicate_carrier",
            producer_ids=producer_ids,
            role=role,
        ),)

    if role == "ACCUMULATOR_CARRIER":
        facts = []
        local_details = _ollvm_local_scalarization_details(payload)
        # Local scalarization is a mutation-authorizing proof. It requires a
        # concrete local-base relation so the consumer can revalidate the live
        # anchor before queueing any rewrite. Other accumulator facts stay
        # diagnostic/semantic even when the local-base proof is absent.
        if (
            local_details.get("local_base_token") is not None
            or local_details.get("multiply_add_base_token") is not None
        ):
            facts.append(_ollvm_exact_fact(
                observation,
                exact=exact,
                kind=SCALAR_REPLACEMENT_FACT_TYPE,
                semantic_key=f"local_storage_scalarization:token:{token}",
                expression_class="local_storage_scalarization_proof",
                observable_effect="none",
                proof_family="local_expression_storage_scalarization",
                producer_ids=producer_ids,
                role=role,
                extra_details=local_details,
            ))
        facts.extend([
            _ollvm_exact_fact(
                observation,
                exact=exact,
                kind=SYMBOLIC_EXPRESSION_FACT_TYPE,
                semantic_key=f"expression_carrier:token:{token}",
                expression_class="semantic_expression_carrier_proof",
                observable_effect="none",
                proof_family="local_alias_expression_carrier",
                producer_ids=producer_ids,
                role=role,
            ),
            _ollvm_exact_fact(
                observation,
                exact=exact,
                kind=SCALAR_PROMOTION_FACT_TYPE,
                semantic_key=f"carrier_store_promotion:token:{token}",
                expression_class="carrier_store_promotion_proof",
                observable_effect="carrier_store",
                proof_family="semantic_expression_store_promotion",
                producer_ids=producer_ids,
                role=role,
            ),
        ])
        alias = _ollvm_same_carrier_alias_fact(
            observation,
            exact=exact,
            token=token,
            producer_ids=producer_ids,
            role=role,
        )
        if alias is not None:
            facts.append(alias)
        return tuple(facts)

    return ()


def _ollvm_exact_fact(
    observation: FactObservation,
    *,
    exact: JsonMapping,
    kind: str,
    semantic_key: str,
    expression_class: str,
    observable_effect: str,
    proof_family: str,
    producer_ids: tuple[str, ...],
    role: str,
    extra_details: JsonMapping | None = None,
) -> FactObservation:
    token = str(exact["carrier_token"])
    source_block = int(exact["source_block"])
    source_ea = int(exact["instruction_ea"])
    instruction_index = int(exact["instruction_index"])
    source_identity = {
        **value_flow_source_identity(observation, producer_ids=producer_ids),
        "source_block": source_block,
        "source_ea": source_ea,
        "source_ea_hex": value_flow_hex(source_ea),
        "instruction_index": instruction_index,
    }
    details = {
        "source_ontology": observation.kind,
        "source_role": role,
        "fixture_specific": True,
        "proof_family": proof_family,
        "proof_basis": [
            "exact_source_block",
            "exact_instruction_ea",
            "exact_instruction_index",
            "exact_instruction_text",
            "carrier_token_identity",
        ],
        "producer_payload_role": role,
        "carrier_token": token,
        "instruction_dstr": str(observation.payload.get("instruction_dstr") or ""),
    }
    if extra_details:
        details.update(extra_details)
    return make_projected_value_flow_fact(
        observation,
        kind=kind,
        semantic_key=semantic_key,
        storage_kind="token",
        storage_identity=token,
        source_block=source_block,
        source_ea=source_ea,
        instruction_index=instruction_index,
        expression_class=expression_class,
        observable_effect=observable_effect,
        producer_fact_ids=producer_ids,
        producer_kinds=(observation.kind,),
        source_identity=source_identity,
        details=details,
        anchor_locator=_ollvm_anchor_locator(observation, exact=exact, token=token),
        storage_overlap_proof=_ollvm_overlap_proof(
            payload=observation.payload,
            token=token,
            role=role,
            details=details,
        ),
    )


def _ollvm_same_carrier_alias_fact(
    observation: FactObservation,
    *,
    exact: JsonMapping,
    token: str,
    producer_ids: tuple[str, ...],
    role: str,
) -> FactObservation | None:
    payload = observation.payload
    if role != "ACCUMULATOR_CARRIER":
        return None
    if payload.get("same_carrier_alias_proof") is not True:
        return None
    alias_tokens = tuple(
        sorted(
            alias
            for alias in (
                _canonical_token(str(raw_alias))
                for raw_alias in (
                    payload.get("multiply_add_same_base_alias_tokens") or ()
                )
            )
            if alias is not None
        )
    )
    carrier_token = _canonical_token(token)
    if carrier_token is None or not alias_tokens:
        return None
    source_block = int(exact["source_block"])
    source_ea = int(exact["instruction_ea"])
    instruction_index = int(exact["instruction_index"])
    source_identity = {
        **value_flow_source_identity(observation, producer_ids=producer_ids),
        "source_block": source_block,
        "source_ea": source_ea,
        "source_ea_hex": value_flow_hex(source_ea),
        "instruction_index": instruction_index,
    }
    details = {
        "source_ontology": observation.kind,
        "source_role": role,
        "carrier_token": carrier_token,
        "alias_tokens": list(alias_tokens),
        "proof_family": "same_carrier_alias_identity",
        "instruction_dstr": str(payload.get("instruction_dstr") or ""),
    }
    return make_projected_value_flow_fact(
        observation,
        kind=MUST_ALIAS_FACT_TYPE,
        semantic_key=f"same_carrier_alias:{carrier_token}:{','.join(alias_tokens)}",
        storage_kind="token_pair",
        storage_identity=f"{carrier_token}->{','.join(alias_tokens)}",
        source_block=source_block,
        source_ea=source_ea,
        instruction_index=instruction_index,
        expression_class="same_carrier_alias",
        observable_effect="none",
        producer_fact_ids=producer_ids,
        producer_kinds=(observation.kind,),
        source_identity=source_identity,
        details=details,
        anchor_locator=_ollvm_anchor_locator(
            observation,
            exact=exact,
            token=carrier_token,
        ),
        storage_overlap_proof=_ollvm_overlap_proof(
            payload=payload,
            token=carrier_token,
            role=role,
            details=details,
        ),
    )


def _ollvm_local_scalarization_details(payload: JsonMapping) -> JsonMapping:
    """Return serializable alias-to-base details for local storage facts."""

    details: dict[str, object] = {}
    local_base = _canonical_token(str(payload.get("local_base_token") or ""))
    multiply_base = _canonical_token(str(payload.get("multiply_add_base_token") or ""))
    if local_base is not None:
        details["local_base_token"] = local_base
    if multiply_base is not None:
        details["multiply_add_base_token"] = multiply_base
    aliases = tuple(
        alias for alias in (
            _canonical_token(str(raw_alias))
            for raw_alias in (payload.get("multiply_add_same_base_alias_tokens") or ())
        )
        if alias is not None
    )
    if aliases:
        details["same_base_alias_tokens"] = aliases
    return details


def _instruction_text_digest(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()[:16]


_TOKEN_WIDTH_RE = re.compile(r"(?P<token>(?:%var_[0-9A-Fa-f]+|v\d+))\.(?P<size>\d+)")


def _token_widths(text: str) -> dict[str, int]:
    widths: dict[str, int] = {}
    for match in _TOKEN_WIDTH_RE.finditer(text):
        token = _canonical_token(match.group("token"))
        if token is None:
            continue
        try:
            size = int(match.group("size"))
        except Exception:
            continue
        previous = widths.get(token)
        if previous is None or size > previous:
            widths[token] = size
    return widths


def _ollvm_anchor_locator(
    observation: FactObservation,
    *,
    exact: JsonMapping,
    token: str,
) -> JsonMapping:
    text = str(observation.payload.get("instruction_dstr") or "")
    opcode_name = str(observation.payload.get("instruction_opcode_name") or "")
    return {
        "requires_live_revalidation": True,
        "source_block": int(exact["source_block"]),
        "instruction_ea": int(exact["instruction_ea"]),
        "instruction_ea_hex": value_flow_hex(int(exact["instruction_ea"])),
        "instruction_index": int(exact["instruction_index"]),
        "instruction_opcode_name": opcode_name,
        "instruction_text_sha1": _instruction_text_digest(text),
        "instruction_dstr": text,
        "carrier_token": _canonical_token(token),
        "token_widths": _token_widths(text),
    }


def _ollvm_overlap_proof(
    *,
    payload: JsonMapping,
    token: str,
    role: str,
    details: JsonMapping,
) -> JsonMapping:
    token = _canonical_token(token) or str(token)
    text = str(payload.get("instruction_dstr") or "")
    token_widths = _token_widths(text)
    local_base = _canonical_token(str(details.get("local_base_token") or ""))
    multiply_base = _canonical_token(str(details.get("multiply_add_base_token") or ""))
    alias_tokens = tuple(
        alias for alias in (
            _canonical_token(str(raw_alias))
            for raw_alias in (
                details.get("alias_tokens")
                or details.get("same_base_alias_tokens")
                or ()
            )
        )
        if alias is not None
    )
    proof_basis = "exact_token_and_width_signature"
    if local_base is not None or multiply_base is not None or alias_tokens:
        proof_basis = "same_local_pointer_base"
    return {
        "proof_status": "producer_checked",
        "proof_basis": proof_basis,
        "carrier_token": token,
        "base_token": local_base or multiply_base,
        "alias_tokens": list(alias_tokens),
        "token_widths": token_widths,
        "carrier_width_bytes": token_widths.get(token),
        "fully_included": True,
        "partial_overlap": False,
        "requires_live_mlist_revalidation": True,
        "source_role": role,
    }


def _ollvm_exact_source_identity(
    observation: FactObservation,
    *,
    token: str,
) -> JsonMapping | None:
    payload = observation.payload
    source_block = payload.get("source_block", observation.source_block)
    instruction_ea = payload.get("instruction_ea", observation.source_ea)
    instruction_index = payload.get("instruction_index")
    instruction_dstr = str(payload.get("instruction_dstr") or "")
    if source_block is None or instruction_ea is None or instruction_index is None:
        return None
    if not instruction_dstr:
        return None
    canonical = _canonical_token(token)
    if canonical is None or canonical not in _tokens(instruction_dstr):
        return None
    return {
        "carrier_token": canonical,
        "source_block": int(source_block),
        "instruction_ea": int(instruction_ea),
        "instruction_index": int(instruction_index),
    }


def _normalized_carrier_facts(
    facts: tuple[object, ...],
) -> tuple[object, ...]:
    normalized: list[object] = []
    for fact in facts:
        kind = str(_fact_kind(fact) or "")
        if kind in VALUE_FLOW_FACT_TYPES:
            normalized.append(fact)
    return tuple(normalized)


def _carrier_projection_tokens(
    facts: tuple[object, ...],
    *,
    fact_kinds: frozenset[str],
) -> frozenset[str]:
    tokens: set[str] = set()
    for fact in facts:
        payload = _fact_payload(fact)
        if not payload:
            continue
        if str(_fact_kind(fact) or "") not in fact_kinds:
            continue
        token = _canonical_token(payload.get("storage_identity"))
        if token is None:
            continue
        tokens.add(token)
    return frozenset(sorted(tokens))


def _carrier_oracle_may_refine(proof: BranchOwnershipProof) -> bool:
    if proof.proof_kind == BranchOwnershipProofKind.UNRESOLVED:
        return True
    if proof.proof_kind != BranchOwnershipProofKind.TERMINAL_RETURN_FRONTIER:
        return False
    return (
        str(proof.reason) == "target_state_terminal_return_frontier"
        and str(proof.evidence.get("edge_kind")) == "CONDITIONAL_TRANSITION"
    )


def _fact_kind(fact: object) -> object | None:
    if isinstance(fact, dict):
        return fact.get("kind")
    return getattr(fact, "kind", None)


def _fact_payload(fact: object) -> dict[str, object]:
    if isinstance(fact, dict):
        payload = fact.get("payload")
    else:
        payload = getattr(fact, "payload", None)
    return dict(payload or {}) if isinstance(payload, dict) else {}


def _derive_data_predicate_tokens(
    seed_tokens: frozenset[str],
    instruction_texts: tuple[str, ...],
) -> frozenset[str]:
    if not seed_tokens:
        return frozenset()

    derived: set[str] = set(seed_tokens)
    changed = True
    while changed:
        changed = False
        for text in instruction_texts:
            text_tokens = tuple(_tokens(text))
            if not text_tokens or not (set(text_tokens) & derived):
                continue
            dst = _dest_token(text)
            if dst is not None and dst not in derived:
                derived.add(dst)
                changed = True

    return frozenset(sorted(derived))


def _derive_loop_predicate_tokens(
    loop_carrier_tokens: frozenset[str],
    instruction_texts: tuple[str, ...],
) -> frozenset[str]:
    if not loop_carrier_tokens:
        return frozenset()

    predicate_tokens: set[str] = set(loop_carrier_tokens)
    for text in instruction_texts:
        match = _LOOP_BOUND_RE.search(text)
        if match is None:
            continue
        carrier = _canonical_token(match.group("token"))
        if carrier not in loop_carrier_tokens:
            continue
        dst = _dest_token(text)
        if dst is not None:
            predicate_tokens.add(dst)
    return frozenset(sorted(predicate_tokens))


def _iter_mba_instruction_texts(mba: object | None) -> tuple[str, ...]:
    if mba is None:
        return ()
    try:
        qty = int(getattr(mba, "qty", 0) or 0)
    except (TypeError, ValueError):
        qty = 0
    walkers = get_condition_chain_walkers()
    texts: list[str] = []
    for serial in range(max(0, qty)):
        try:
            block = walkers.get_block(mba, int(serial))
        except Exception:
            continue
        if block is None:
            continue
        for insn in _iter_block_insns(block):
            text = _format_insn_text(insn)
            if text:
                texts.append(text)
        tail = getattr(block, "tail", None)
        if tail is not None:
            text = _format_insn_text(tail)
            if text:
                texts.append(text)
    return tuple(texts)


def _dest_token(text: str) -> str | None:
    tokens = _tokens(text)
    if not tokens:
        return None
    return tokens[-1]


def _iter_block_insns(block: object, *, max_insns: int = 512):
    insn = getattr(block, "head", None)
    seen = 0
    while insn is not None and seen < max_insns:
        yield insn
        seen += 1
        insn = getattr(insn, "next", None)


def _format_insn_text(insn: object) -> str:
    dstr = getattr(insn, "dstr", None)
    if callable(dstr):
        try:
            return str(dstr())
        except Exception:
            return repr(insn)
    text = getattr(insn, "text", None)
    if text is not None:
        return str(text)
    display = getattr(insn, "display", None)
    if display is not None:
        return str(display)
    return repr(insn)


def _edge_kind_name(edge: object) -> str:
    kind = getattr(edge, "kind", None)
    name = getattr(kind, "name", None)
    return str(name if name is not None else kind)


def _path_predecessor(edge: object, source_block: int) -> int | None:
    path = tuple(getattr(edge, "ordered_path", ()) or ())
    try:
        index = path.index(int(source_block))
    except ValueError:
        return None
    if index <= 0:
        return None
    return int(path[index - 1])


def _block_nsucc(block: object) -> int | None:
    nsucc = getattr(block, "nsucc", None)
    if callable(nsucc):
        try:
            return int(nsucc())
        except Exception:
            return None
    if nsucc is not None:
        try:
            return int(nsucc)
        except (TypeError, ValueError):
            return None
    return None


__all__ = [
    "OLLVM_CARRIER_PROFILE_MODULE",
    "OLLVM_CARRIER_PROFILE_NAME",
    "OllvmCarrierBranchOwnershipOracle",
    "OllvmCarrierProfileFactCollector",
    "OllvmCarrierRawEvidenceCollector",
    "collect_ollvm_branch_ownership_refiners",
    "collect_ollvm_post_execute_carrier_facts",
    "collect_ollvm_profile_fact_observations",
    "collect_ollvm_raw_semantic_carrier_facts",
    "project_ollvm_value_flow_evidence",
]

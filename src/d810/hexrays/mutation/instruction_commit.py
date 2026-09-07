"""Callback-local instruction candidate and native commit contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.typing import Any, Callable, MutableMapping
from d810.hexrays.ir.native_identity import native_object_identity
from d810.hexrays.mutation.return_carrier_corruption import (
    CandidateSite,
    ReturnRegisterConsumptionSnapshot,
    find_droppable_return_const_corruptions,
    is_empty_nop,
)
from d810.hexrays.mutation.fragment_publication_lifecycle import (
    NativeMutationQuarantined,
)

REASON_COMMITTED = "committed"
REASON_STALE_EPOCH = "stale-epoch"
REASON_STALE_FINGERPRINT = "stale-fingerprint"
REASON_BLOCK_CONTEXT_REQUIRED = "block-context-required"
REASON_CAPABILITY_REJECTED = "capability-rejected"
REASON_INVALID_OPERAND_SIZE = "invalid-operand-size"
REASON_PROOF_REJECTED = "proof-rejected"
REASON_COST_REJECTED = "cost-rejected"
REASON_SEMANTIC_RANK_REJECTED = "semantic-rank-rejected"
REASON_LOWER_REJECTED = "lower-rejected"
REASON_EXPRESSION_BLOAT = "expression-bloat"
REASON_REWRITE_NOOP = "rewrite-noop"
REASON_REWRITE_CYCLE = "rewrite-cycle"
REASON_VERIFICATION_FAILED = "verification-failed"
REASON_NATIVE_MUTATION_QUARANTINED = "native-mutation-quarantined"
REASON_NON_IMPROVING_COST = REASON_COST_REJECTED
REASON_RECOVER_RANK_REJECTED = REASON_SEMANTIC_RANK_REJECTED


def _non_negative(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be a non-negative integer")
    if value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return int(value)


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a bool")
    return value


@dataclass(frozen=True, slots=True)
class NativeEpoch:
    """Primitive identity for one callback-local live MBA generation."""

    function_ea: int
    mba_identity: int
    maturity: int
    generation: int

    def __post_init__(self) -> None:
        for name in ("function_ea", "mba_identity", "maturity", "generation"):
            object.__setattr__(self, name, _non_negative(getattr(self, name), name))

    @classmethod
    def from_mba(
        cls,
        mba: object,
        *,
        function_ea: int | None = None,
        maturity: int | None = None,
        generation: int = 0,
    ) -> "NativeEpoch":
        """Capture only primitive MBA identity; never retain the live object."""

        raw_maturity = (
            int(getattr(mba, "maturity", 0) or 0) if maturity is None else int(maturity)
        )
        # Hex-Rays callback code uses -1 for an unknown/null-block maturity;
        # keep NativeEpoch itself non-negative and map only at this capture
        # boundary to the synthetic unknown value 0.
        safe_maturity = 0 if raw_maturity == -1 else raw_maturity
        # ``mblock_t.mba`` may manufacture a new SWIG proxy on every access.
        # The Python wrapper identity is therefore not a native-epoch identity.
        # Prefer the underlying C++ address and retain ``id`` only for fakes
        # and compatibility objects that do not expose a SWIG ``this`` field.
        try:
            mba_identity = int(mba.this)
        except (AttributeError, TypeError, ValueError):
            mba_identity = id(mba)
        return cls(
            function_ea=(
                int(getattr(mba, "entry_ea", 0) or 0)
                if function_ea is None
                else int(function_ea)
            ),
            mba_identity=mba_identity,
            maturity=safe_maturity,
            generation=int(generation),
        )


@dataclass(frozen=True, slots=True)
class NativeCallbackCapabilities:
    block_context_available: bool
    may_touch_neighboring_instructions: bool
    may_mark_lists_dirty: bool
    may_verify_mba: bool

    def __post_init__(self) -> None:
        for name in (
            "block_context_available",
            "may_touch_neighboring_instructions",
            "may_mark_lists_dirty",
            "may_verify_mba",
        ):
            object.__setattr__(self, name, _bool(getattr(self, name), name))


class RewriteMode(str, Enum):
    SIMPLIFY = "simplify"
    RECOVER = "recover"
    LOWER = "lower"
    SOLVE = "solve"


@dataclass(frozen=True, slots=True)
class RewriteCost:
    noncanonical_ops: int = 0
    opaque_ops: int = 0
    depth: int = 0
    node_count: int = 0
    target_risk: int = 0

    def __post_init__(self) -> None:
        for name in (
            "noncanonical_ops",
            "opaque_ops",
            "depth",
            "node_count",
            "target_risk",
        ):
            object.__setattr__(self, name, _non_negative(getattr(self, name), name))

    def key(self) -> tuple[int, int, int, int, int]:
        return (
            self.noncanonical_ops,
            self.opaque_ops,
            self.depth,
            self.node_count,
            self.target_risk,
        )


@dataclass(frozen=True, slots=True)
class InstructionCommitContext:
    """Borrowed instruction/block context and captured callback epoch."""

    instruction: object
    block: object | None
    epoch: NativeEpoch
    capabilities: NativeCallbackCapabilities

    def __post_init__(self) -> None:
        if self.instruction is None:
            raise ValueError("instruction is required")
        if not isinstance(self.epoch, NativeEpoch):
            raise TypeError("epoch must be a NativeEpoch")
        if not isinstance(self.capabilities, NativeCallbackCapabilities):
            raise TypeError("capabilities must be NativeCallbackCapabilities")

    @classmethod
    def from_live(
        cls,
        instruction: object,
        block: object | None,
        *,
        function_ea: int | None = None,
        maturity: int | None = None,
        generation: int = 0,
        capabilities: NativeCallbackCapabilities | None = None,
    ) -> "InstructionCommitContext":
        """Capture callback values, mapping the existing ``maturity=-1`` sentinel."""

        mba = None if block is None else getattr(block, "mba", None)
        has_block = block is not None and mba is not None
        if capabilities is None:
            capabilities = NativeCallbackCapabilities(
                block_context_available=has_block,
                may_touch_neighboring_instructions=has_block,
                may_mark_lists_dirty=has_block,
                may_verify_mba=has_block,
            )
        if mba is None:
            epoch = NativeEpoch(
                function_ea=0 if function_ea is None else int(function_ea),
                mba_identity=0,
                maturity=0 if maturity in (None, -1) else int(maturity),
                generation=int(generation),
            )
        else:
            epoch = NativeEpoch.from_mba(
                mba,
                function_ea=function_ea,
                maturity=maturity,
                generation=generation,
            )
        return cls(instruction, block, epoch, capabilities)


@dataclass(frozen=True, slots=True)
class InstructionRewriteCandidate:
    """One detached replacement proposed for the current instruction."""

    replacement: object
    before_fingerprint: int
    mode: RewriteMode
    cost_before: RewriteCost
    cost_after: RewriteCost
    pass_id: str
    stage_id: str
    rule_id: str
    semantic_rank_before: int = 0
    semantic_rank_after: int = 0
    proof_required: bool = False
    proof: object | None = None
    may_touch_neighboring_instructions: bool = False
    may_mark_lists_dirty: bool = False
    may_verify_mba: bool = False
    optimize_solo: bool = True
    legacy_compatibility: bool = False
    producer_rule_name: str = ""
    history_key: object | None = None
    epoch_before: NativeEpoch | None = None

    def __post_init__(self) -> None:
        if self.replacement is None:
            raise ValueError("replacement is required")
        if isinstance(self.before_fingerprint, bool) or not isinstance(
            self.before_fingerprint, int
        ):
            raise TypeError("before_fingerprint must be an integer")
        if not isinstance(self.mode, RewriteMode):
            raise TypeError("mode must be a RewriteMode")
        if not isinstance(self.cost_before, RewriteCost) or not isinstance(
            self.cost_after, RewriteCost
        ):
            raise TypeError("costs must be RewriteCost values")
        for name in ("pass_id", "stage_id", "rule_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        for name in ("semantic_rank_before", "semantic_rank_after"):
            object.__setattr__(self, name, _non_negative(getattr(self, name), name))
        for name in (
            "proof_required",
            "may_touch_neighboring_instructions",
            "may_mark_lists_dirty",
            "may_verify_mba",
            "optimize_solo",
            "legacy_compatibility",
        ):
            object.__setattr__(self, name, _bool(getattr(self, name), name))
        if not isinstance(self.producer_rule_name, str):
            raise TypeError("producer_rule_name must be a string")
        if self.producer_rule_name and self.producer_rule_name != self.rule_id:
            raise ValueError("producer_rule_name must match rule_id")
        object.__setattr__(self, "producer_rule_name", self.rule_id)
        if self.epoch_before is not None and not isinstance(
            self.epoch_before, NativeEpoch
        ):
            raise TypeError("epoch_before must be a NativeEpoch")


@dataclass(frozen=True, slots=True)
class InstructionRewriteReceipt:
    """Primitive-only outcome of one instruction transaction."""

    committed: bool
    applied_count: int
    epoch_before: NativeEpoch
    epoch_after: NativeEpoch
    before_fingerprint: int | None
    after_fingerprint: int | None
    reason: str
    pass_id: str
    stage_id: str
    rule_id: str
    mode: RewriteMode | None = None
    semantic_rank_before: int = 0
    semantic_rank_after: int = 0
    producer_rule_name: str = ""
    legacy_compatibility: bool = False

    def __post_init__(self) -> None:
        committed = _bool(self.committed, "committed")
        applied_count = _non_negative(self.applied_count, "applied_count")
        if (committed, applied_count) not in ((True, 1), (False, 0)):
            raise ValueError("receipt applied_count does not match committed state")
        if not isinstance(self.epoch_before, NativeEpoch) or not isinstance(
            self.epoch_after, NativeEpoch
        ):
            raise TypeError("receipt epochs must be NativeEpoch values")
        # An instruction transaction is inside one lifecycle-owned native
        # snapshot. It may change the instruction but cannot mint a lifecycle
        # generation; only the lifecycle may advance that epoch after it owns
        # an actual MBA transition.
        if self.epoch_after != self.epoch_before:
            raise ValueError("receipt must retain its lifecycle snapshot epoch")
        for name in ("before_fingerprint", "after_fingerprint"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int)
            ):
                raise TypeError(f"{name} must be an integer or None")
        if not isinstance(self.reason, str) or not self.reason:
            raise ValueError("receipt reason is required")
        for name in ("pass_id", "stage_id", "rule_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if self.mode is not None and not isinstance(self.mode, RewriteMode):
            raise TypeError("receipt mode must be a RewriteMode")
        for name in ("semantic_rank_before", "semantic_rank_after"):
            object.__setattr__(self, name, _non_negative(getattr(self, name), name))
        object.__setattr__(
            self,
            "legacy_compatibility",
            _bool(self.legacy_compatibility, "legacy_compatibility"),
        )
        if not isinstance(self.producer_rule_name, str):
            raise TypeError("producer_rule_name must be a string")
        if self.producer_rule_name and self.producer_rule_name != self.rule_id:
            raise ValueError("producer_rule_name must match rule_id")
        object.__setattr__(self, "producer_rule_name", self.rule_id)

    @property
    def pre_fingerprint(self) -> int | None:
        return self.before_fingerprint

    @property
    def post_fingerprint(self) -> int | None:
        return self.after_fingerprint

    def primitive_fields(self) -> dict[str, object]:
        """Return fields safe for journal publication (no native objects)."""

        return {
            "committed": self.committed,
            "applied_count": self.applied_count,
            "function_ea": self.epoch_before.function_ea,
            "mba_identity": self.epoch_before.mba_identity,
            "maturity": self.epoch_before.maturity,
            "generation_before": self.epoch_before.generation,
            "generation_after": self.epoch_after.generation,
            "before_fingerprint": self.before_fingerprint,
            "after_fingerprint": self.after_fingerprint,
            "reason": self.reason,
            "pass_id": self.pass_id,
            "stage_id": self.stage_id,
            "rule_id": self.rule_id,
            "mode": None if self.mode is None else self.mode.value,
            "semantic_rank_before": self.semantic_rank_before,
            "semantic_rank_after": self.semantic_rank_after,
            "producer_rule_name": self.producer_rule_name,
            "legacy_compatibility": self.legacy_compatibility,
        }


def fingerprint_minsn(instruction: object, function_ea: int = 0) -> int:
    try:
        rendered = instruction._print()
    except (AttributeError, TypeError):
        rendered = repr(instruction)
    return hash((getattr(instruction, "opcode", 0), rendered, function_ea))


def _invoke(function: Callable[..., Any], *args: object) -> Any:
    """Call a port using its production arity or a compact fake arity."""

    try:
        return function(*args)
    except TypeError as error:
        if len(args) > 1:
            try:
                return function(args[0])
            except TypeError:
                pass
        if args:
            try:
                return function()
            except TypeError:
                pass
        raise error


class HexRaysInstructionCommitter:
    """Perform one admitted instruction swap and publish its receipt."""

    def __init__(
        self,
        *,
        hash_minsn: Callable[..., int] = fingerprint_minsn,
        count_minsn_nodes: Callable[..., int] = lambda _instruction: 0,
        check_ins_mop_size_are_ok: Callable[..., bool] = lambda _instruction: True,
        build_z3_equivalence_proof: Callable[..., object | None] = (
            lambda _replacement, _original: None
        ),
        safe_verify: Callable[..., object] = lambda _mba, _context: None,
        rewrite_history: MutableMapping[object, set[int]] | None = None,
        producer_cycle_quarantine: Callable[..., object] | None = None,
        native_failure_quarantine: Callable[[BaseException], object] | None = None,
        lifecycle_authority: object | None = None,
    ) -> None:
        self._hash = hash_minsn
        self._count = count_minsn_nodes
        self._size_ok = check_ins_mop_size_are_ok
        self._proof = build_z3_equivalence_proof
        self._verify = safe_verify
        self._history = rewrite_history
        self._cycle_quarantine = producer_cycle_quarantine
        self._native_failure_quarantine = native_failure_quarantine
        self._lifecycle_authority = lifecycle_authority

    @staticmethod
    def _rejected(
        context: InstructionCommitContext,
        candidate: InstructionRewriteCandidate,
        reason: str,
        fingerprint: int | None,
    ) -> InstructionRewriteReceipt:
        return InstructionRewriteReceipt(
            committed=False,
            applied_count=0,
            epoch_before=context.epoch,
            epoch_after=context.epoch,
            before_fingerprint=fingerprint,
            after_fingerprint=fingerprint,
            reason=reason,
            pass_id=candidate.pass_id,
            stage_id=candidate.stage_id,
            rule_id=candidate.rule_id,
            mode=candidate.mode,
            semantic_rank_before=candidate.semantic_rank_before,
            semantic_rank_after=candidate.semantic_rank_after,
            producer_rule_name=candidate.producer_rule_name,
            legacy_compatibility=candidate.legacy_compatibility,
        )

    def _quarantine(self, error: BaseException) -> None:
        if self._native_failure_quarantine is None:
            return
        try:
            _invoke(self._native_failure_quarantine, error)
        except Exception:
            return

    def _rollback(
        self,
        instruction: object,
        replacement: object,
        error: BaseException,
        *,
        quarantine: bool,
    ) -> None:
        try:
            _invoke(getattr(instruction, "swap"), replacement)
        except Exception as rollback_error:
            self._quarantine(rollback_error)
            raise NativeMutationQuarantined(
                "instruction rollback failed"
            ) from rollback_error
        if quarantine:
            self._quarantine(error)

    def _record_cycle_producer(self, key: object, producer: str) -> None:
        if self._cycle_quarantine is None:
            return
        try:
            self._cycle_quarantine(key, producer)
        except TypeError:
            try:
                self._cycle_quarantine(producer)
            except TypeError:
                try:
                    self._cycle_quarantine()
                except TypeError:
                    return

    def commit_return_carrier_cleanup(
        self,
        context: InstructionCommitContext,
        site: CandidateSite,
        replacement: object,
        *,
        prefold_snapshot: ReturnRegisterConsumptionSnapshot | None,
    ) -> InstructionRewriteReceipt | None:
        """Revalidate typed value-flow evidence before normal native admission.

        A producer's successful analysis is a candidate, not permission. The
        current MBA must still have the same exact anchored definition and
        premises. The normal commit path owns the swap, rollback and receipt.
        """
        if type(site) is not CandidateSite or context.block is None:
            return None
        try:
            site.__post_init__()
            mba = context.block.mba
            if (
                native_object_identity(mba) != site.mba_identity
                or int(mba.entry_ea) != site.function_ea
                or int(mba.maturity) != site.maturity
                or NativeEpoch.from_mba(mba, generation=context.epoch.generation)
                != context.epoch
                or int(context.block.serial) != site.block_serial
                or int(context.instruction.ea) != site.insn_ea
                or not is_empty_nop(replacement)
            ):
                return None
            # A duplicated EA in this block cannot identify one instruction.
            matches = []
            insn = context.block.head
            while insn is not None:
                if int(insn.ea) == site.insn_ea:
                    matches.append(insn)
                insn = insn.next
            if len(matches) != 1 or native_object_identity(
                matches[0]
            ) != native_object_identity(context.instruction):
                return None
            observed = find_droppable_return_const_corruptions(
                mba,
                prefold_snapshot=prefold_snapshot,
            )
            if (
                sum(
                    type(current) is CandidateSite and current == site
                    for current in observed
                )
                != 1
            ):
                return None
            fingerprint = int(
                _invoke(self._hash, context.instruction, context.epoch.function_ea)
            )
        except (AttributeError, TypeError, ValueError, IndexError):
            return None
        return self.commit(
            context,
            InstructionRewriteCandidate(
                replacement=replacement,
                before_fingerprint=fingerprint,
                mode=RewriteMode.SIMPLIFY,
                cost_before=RewriteCost(node_count=1),
                cost_after=RewriteCost(),
                pass_id="return-carrier-cleanup",
                stage_id="glbopt",
                rule_id="return-constant-corruption",
                proof_required=True,
                proof=site.proof,
                may_mark_lists_dirty=True,
                optimize_solo=False,
                epoch_before=context.epoch,
            ),
        )

    def commit(
        self,
        context: InstructionCommitContext,
        candidate: InstructionRewriteCandidate,
    ) -> InstructionRewriteReceipt:
        """Run admission, one swap, and native postconditions in fixed order."""

        if not isinstance(context, InstructionCommitContext):
            raise TypeError("context must be an InstructionCommitContext")
        if not isinstance(candidate, InstructionRewriteCandidate):
            raise TypeError("candidate must be an InstructionRewriteCandidate")
        if (
            candidate.epoch_before is not None
            and candidate.epoch_before != context.epoch
        ):
            return self._rejected(context, candidate, REASON_STALE_EPOCH, None)
        authority = self._lifecycle_authority
        quarantined = (
            False
            if authority is None
            else getattr(authority, "native_mutation_quarantined", False)
        )
        if callable(quarantined):
            quarantined = quarantined()
        if quarantined:
            return self._rejected(
                context,
                candidate,
                REASON_NATIVE_MUTATION_QUARANTINED,
                None,
            )

        instruction = context.instruction
        fingerprint = int(_invoke(self._hash, instruction, context.epoch.function_ea))
        if fingerprint != candidate.before_fingerprint:
            return self._rejected(
                context, candidate, REASON_STALE_FINGERPRINT, fingerprint
            )

        block = context.block
        has_block = (
            block is not None
            and context.capabilities.block_context_available
            and getattr(block, "mba", None) is not None
        )
        effectful = any(
            (
                candidate.may_touch_neighboring_instructions,
                candidate.may_mark_lists_dirty,
                candidate.may_verify_mba,
            )
        )
        if effectful and not has_block:
            return self._rejected(
                context, candidate, REASON_BLOCK_CONTEXT_REQUIRED, fingerprint
            )
        if (
            (
                candidate.may_touch_neighboring_instructions
                and not context.capabilities.may_touch_neighboring_instructions
            )
            or (
                candidate.may_mark_lists_dirty
                and not context.capabilities.may_mark_lists_dirty
            )
            or (candidate.may_verify_mba and not context.capabilities.may_verify_mba)
        ):
            return self._rejected(
                context, candidate, REASON_CAPABILITY_REJECTED, fingerprint
            )
        if not candidate.legacy_compatibility and candidate.mode is RewriteMode.LOWER:
            return self._rejected(
                context, candidate, REASON_LOWER_REJECTED, fingerprint
            )

        try:
            size_ok = bool(_invoke(self._size_ok, candidate.replacement))
        except Exception:
            size_ok = False
        if not size_ok:
            return self._rejected(
                context, candidate, REASON_INVALID_OPERAND_SIZE, fingerprint
            )

        proof_required = candidate.proof_required or candidate.mode is RewriteMode.SOLVE
        if not candidate.legacy_compatibility and proof_required:
            proof = candidate.proof
            if proof is None:
                try:
                    proof = _invoke(self._proof, candidate.replacement, instruction)
                except Exception:
                    proof = None
            if not proof:
                return self._rejected(
                    context, candidate, REASON_PROOF_REJECTED, fingerprint
                )

        try:
            old_nodes = int(_invoke(self._count, instruction))
            new_nodes = int(_invoke(self._count, candidate.replacement))
        except Exception:
            old_nodes = new_nodes = 0
        if old_nodes > 0 and new_nodes > old_nodes * 2:
            return self._rejected(
                context, candidate, REASON_EXPRESSION_BLOAT, fingerprint
            )

        if not candidate.legacy_compatibility:
            before_key = candidate.cost_before.key()
            after_key = candidate.cost_after.key()
            if candidate.mode is RewriteMode.SIMPLIFY and not after_key < before_key:
                return self._rejected(
                    context, candidate, REASON_COST_REJECTED, fingerprint
                )
            if candidate.mode is RewriteMode.RECOVER:
                if candidate.semantic_rank_after <= candidate.semantic_rank_before:
                    return self._rejected(
                        context, candidate, REASON_SEMANTIC_RANK_REJECTED, fingerprint
                    )
                if candidate.cost_after.target_risk > candidate.cost_before.target_risk:
                    return self._rejected(
                        context, candidate, REASON_COST_REJECTED, fingerprint
                    )
            if candidate.mode is RewriteMode.SOLVE and after_key > before_key:
                return self._rejected(
                    context, candidate, REASON_COST_REJECTED, fingerprint
                )

        try:
            _invoke(getattr(instruction, "swap"), candidate.replacement)
        except Exception as error:
            self._quarantine(error)
            raise NativeMutationQuarantined("instruction swap failed") from error

        try:
            post_fingerprint = int(
                _invoke(self._hash, instruction, context.epoch.function_ea)
            )
            if post_fingerprint == fingerprint:
                self._rollback(
                    instruction,
                    candidate.replacement,
                    RuntimeError(REASON_REWRITE_NOOP),
                    quarantine=False,
                )
                return self._rejected(
                    context, candidate, REASON_REWRITE_NOOP, fingerprint
                )

            key = candidate.history_key or (
                context.epoch.function_ea,
                context.epoch.maturity,
                int(getattr(instruction, "ea", 0) or 0),
            )
            seen = set() if self._history is None else self._history.get(key, set())

            if candidate.optimize_solo:
                optimize_solo = getattr(instruction, "optimize_solo", None)
                if callable(optimize_solo):
                    _invoke(optimize_solo)
            if candidate.may_mark_lists_dirty:
                mark_lists_dirty = getattr(block, "mark_lists_dirty", None)
                if not callable(mark_lists_dirty):
                    raise RuntimeError("block cannot mark lists dirty")
                mark_lists_dirty()
            if candidate.may_verify_mba:
                _invoke(
                    self._verify,
                    getattr(block, "mba"),
                    f"instruction rewrite at 0x{int(getattr(instruction, 'ea', 0) or 0):X}",
                )

            # optimize_solo is native follow-up and may itself change the
            # instruction.  The receipt and cycle history must describe this
            # final callback-local state, not the pre-follow-up swap state.
            final_fingerprint = int(
                _invoke(self._hash, instruction, context.epoch.function_ea)
            )
            if final_fingerprint == fingerprint:
                self._rollback(
                    instruction,
                    candidate.replacement,
                    RuntimeError(REASON_REWRITE_NOOP),
                    quarantine=False,
                )
                return self._rejected(
                    context, candidate, REASON_REWRITE_NOOP, fingerprint
                )
            if final_fingerprint in seen:
                self._rollback(
                    instruction,
                    candidate.replacement,
                    RuntimeError(REASON_REWRITE_CYCLE),
                    quarantine=False,
                )
                self._record_cycle_producer(key, candidate.rule_id)
                return self._rejected(
                    context, candidate, REASON_REWRITE_CYCLE, fingerprint
                )
            if self._history is not None:
                self._history.setdefault(key, seen).add(final_fingerprint)
            return InstructionRewriteReceipt(
                committed=True,
                applied_count=1,
                epoch_before=context.epoch,
                # This committer does not own the lifecycle epoch transition.
                # Hex-Rays may revisit this live MBA before lifecycle obtains a
                # fresh generation, so claiming G -> G+1 here would fabricate
                # an ordering edge. The receipt records the current snapshot.
                epoch_after=context.epoch,
                before_fingerprint=fingerprint,
                after_fingerprint=final_fingerprint,
                reason=REASON_COMMITTED,
                pass_id=candidate.pass_id,
                stage_id=candidate.stage_id,
                rule_id=candidate.rule_id,
                mode=candidate.mode,
                semantic_rank_before=candidate.semantic_rank_before,
                semantic_rank_after=candidate.semantic_rank_after,
                producer_rule_name=candidate.producer_rule_name,
                legacy_compatibility=candidate.legacy_compatibility,
            )
        except Exception as error:
            self._rollback(
                instruction,
                candidate.replacement,
                error,
                quarantine=True,
            )
            if isinstance(error, NativeMutationQuarantined):
                raise
            raise NativeMutationQuarantined(
                f"{REASON_VERIFICATION_FAILED}: {error}"
            ) from error

    __call__ = commit


NativeCallbackContext = InstructionCommitContext

__all__ = [
    "HexRaysInstructionCommitter",
    "InstructionCommitContext",
    "InstructionRewriteCandidate",
    "InstructionRewriteReceipt",
    "NativeCallbackCapabilities",
    "NativeCallbackContext",
    "NativeEpoch",
    "fingerprint_minsn",
    "REASON_BLOCK_CONTEXT_REQUIRED",
    "REASON_CAPABILITY_REJECTED",
    "REASON_COMMITTED",
    "REASON_COST_REJECTED",
    "REASON_EXPRESSION_BLOAT",
    "REASON_INVALID_OPERAND_SIZE",
    "REASON_LOWER_REJECTED",
    "REASON_NATIVE_MUTATION_QUARANTINED",
    "REASON_NON_IMPROVING_COST",
    "REASON_PROOF_REJECTED",
    "REASON_RECOVER_RANK_REJECTED",
    "REASON_REWRITE_CYCLE",
    "REASON_REWRITE_NOOP",
    "REASON_SEMANTIC_RANK_REJECTED",
    "REASON_STALE_EPOCH",
    "REASON_STALE_FINGERPRINT",
    "REASON_VERIFICATION_FAILED",
    "RewriteCost",
    "RewriteMode",
]

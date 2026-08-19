"""Callback-local instruction rewrite contract tests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from d810.hexrays.mutation.fragment_publication_lifecycle import (
    NativeMutationQuarantined,
)
from d810.hexrays.mutation.instruction_commit import (
    InstructionCommitContext,
    InstructionRewriteCandidate,
    HexRaysInstructionCommitter,
    NativeCallbackCapabilities,
    NativeEpoch,
    REASON_BLOCK_CONTEXT_REQUIRED,
    REASON_COST_REJECTED,
    REASON_INVALID_OPERAND_SIZE,
    REASON_PROOF_REJECTED,
    REASON_REWRITE_NOOP,
    REASON_SEMANTIC_RANK_REJECTED,
    REASON_STALE_FINGERPRINT,
    RewriteCost,
    RewriteMode,
)


class FakeMba:
    def __init__(self, maturity: int = 7) -> None:
        self.maturity = maturity


class FakeInstruction:
    def __init__(
        self,
        *,
        ea: int = 0x401000,
        opcode: int = 1,
        fingerprint: int = 1,
        operand_size_ok: bool = True,
        optimize_fingerprint: int | None = None,
    ) -> None:
        self.ea = ea
        self.opcode = opcode
        self.fingerprint = fingerprint
        self.operand_size_ok = operand_size_ok
        self.optimize_fingerprint = optimize_fingerprint
        self.swap_count = 0
        self.optimize_solo_count = 0

    def _print(self) -> str:
        return f"op{self.opcode}:{self.fingerprint}"

    def swap(self, other: "FakeInstruction") -> None:
        self.swap_count += 1
        other.swap_count += 1
        self.opcode, other.opcode = other.opcode, self.opcode
        self.fingerprint, other.fingerprint = other.fingerprint, self.fingerprint
        self.operand_size_ok, other.operand_size_ok = (
            other.operand_size_ok,
            self.operand_size_ok,
        )

    def optimize_solo(self) -> None:
        self.optimize_solo_count += 1
        if self.optimize_fingerprint is not None:
            self.fingerprint = self.optimize_fingerprint


class FakeBlock:
    def __init__(self, mba: FakeMba) -> None:
        self.mba = mba
        self.mark_lists_dirty_count = 0

    def mark_lists_dirty(self) -> None:
        self.mark_lists_dirty_count += 1


def _context(
    instruction: FakeInstruction,
    *,
    block: FakeBlock | None,
    capabilities: NativeCallbackCapabilities,
    generation: int = 4,
) -> InstructionCommitContext:
    mba = block.mba if block is not None else FakeMba()
    return InstructionCommitContext(
        instruction=instruction,
        block=block,
        epoch=NativeEpoch(
            function_ea=0x401000,
            mba_identity=id(mba),
            maturity=int(mba.maturity),
            generation=generation,
        ),
        capabilities=capabilities,
    )


def _candidate(
    replacement: FakeInstruction,
    *,
    before_fingerprint: int = 1,
    mode: RewriteMode = RewriteMode.RECOVER,
    cost_before: RewriteCost | None = None,
    cost_after: RewriteCost | None = None,
    semantic_rank_before: int = 1,
    semantic_rank_after: int = 2,
    proof_required: bool = False,
    proof: object | None = None,
    may_touch_neighboring_instructions: bool = False,
    may_mark_lists_dirty: bool = True,
    may_verify_mba: bool = True,
    optimize_solo: bool = True,
    pass_id: str = "test-pass",
    stage_id: str = "test-stage",
    rule_id: str = "test-rule",
    producer_rule_name: str = "",
    history_key: object | None = None,
    legacy_compatibility: bool = False,
) -> InstructionRewriteCandidate:
    fields = dict(
        replacement=replacement,
        before_fingerprint=before_fingerprint,
        mode=mode,
        cost_before=cost_before
        or RewriteCost(
            noncanonical_ops=3, opaque_ops=1, depth=3, node_count=4, target_risk=2
        ),
        cost_after=cost_after
        or RewriteCost(
            noncanonical_ops=2, opaque_ops=1, depth=3, node_count=4, target_risk=2
        ),
        pass_id=pass_id,
        stage_id=stage_id,
        rule_id=rule_id,
        semantic_rank_before=semantic_rank_before,
        semantic_rank_after=semantic_rank_after,
        proof_required=proof_required,
        proof=proof,
        may_touch_neighboring_instructions=may_touch_neighboring_instructions,
        may_mark_lists_dirty=may_mark_lists_dirty,
        may_verify_mba=may_verify_mba,
        optimize_solo=optimize_solo,
        producer_rule_name=producer_rule_name,
        history_key=history_key,
    )
    if legacy_compatibility:
        fields["legacy_compatibility"] = True
    return InstructionRewriteCandidate(**fields)


def _committer(
    *,
    proof_result: object = "proof",
    proof_calls: list[bool] | None = None,
    verify=None,
    quarantine=None,
    native_failure_quarantine=None,
    history=None,
) -> HexRaysInstructionCommitter:
    return HexRaysInstructionCommitter(
        hash_minsn=lambda instruction, _function_ea=0: instruction.fingerprint,
        count_minsn_nodes=lambda instruction: int(instruction.fingerprint),
        check_ins_mop_size_are_ok=lambda instruction: bool(instruction.operand_size_ok),
        build_z3_equivalence_proof=lambda _original, _replacement: (
            proof_calls.append(True) if proof_calls is not None else None
        )
        or proof_result,
        safe_verify=verify or (lambda _mba, _ctx: None),
        rewrite_history=history if history is not None else {},
        producer_cycle_quarantine=quarantine,
        native_failure_quarantine=native_failure_quarantine,
    )


def test_recover_candidate_commits_one_instruction_transaction() -> None:
    mba = FakeMba()
    block = FakeBlock(mba)
    instruction = FakeInstruction(fingerprint=1)
    replacement = FakeInstruction(opcode=2, fingerprint=2)
    verified = []
    context = _context(
        instruction,
        block=block,
        capabilities=NativeCallbackCapabilities(True, True, True, True),
    )

    committer = _committer(verify=lambda live_mba, _ctx: verified.append(live_mba))
    receipt = committer.commit(context, _candidate(replacement))

    assert instruction.swap_count == 1
    assert instruction.optimize_solo_count == 1
    assert block.mark_lists_dirty_count == 1
    assert verified == [mba]
    assert receipt.committed is True
    assert receipt.applied_count == 1
    assert receipt.epoch_after == receipt.epoch_before
    assert receipt.after_fingerprint == 2
    assert receipt.pass_id == "test-pass"
    assert receipt.stage_id == "test-stage"
    assert receipt.rule_id == "test-rule"
    assert receipt.producer_rule_name == "test-rule"
    primitive = receipt.primitive_fields()
    assert primitive["pass_id"] == "test-pass"
    assert primitive["stage_id"] == "test-stage"
    assert primitive["rule_id"] == "test-rule"


def test_stale_source_fingerprint_is_rejected_before_swap() -> None:
    instruction = FakeInstruction(fingerprint=9)
    replacement = FakeInstruction(fingerprint=2)
    context = _context(
        instruction,
        block=FakeBlock(FakeMba()),
        capabilities=NativeCallbackCapabilities(True, True, True, True),
    )

    receipt = _committer().commit(
        context,
        _candidate(replacement, before_fingerprint=1),
    )

    assert instruction.swap_count == 0
    assert receipt.committed is False
    assert receipt.reason == REASON_STALE_FINGERPRINT


def test_same_fingerprint_rolls_back_without_follow_up_operations() -> None:
    instruction = FakeInstruction(fingerprint=1)
    replacement = FakeInstruction(opcode=2, fingerprint=1)
    context = _context(
        instruction,
        block=FakeBlock(FakeMba()),
        capabilities=NativeCallbackCapabilities(True, True, True, True),
    )

    receipt = _committer().commit(context, _candidate(replacement))

    assert instruction.swap_count == 2
    assert instruction.optimize_solo_count == 0
    assert receipt.committed is False
    assert receipt.reason == REASON_REWRITE_NOOP


def test_receipt_and_history_use_final_fingerprint_after_optimize_solo() -> None:
    mba = FakeMba()
    block = FakeBlock(mba)
    instruction = FakeInstruction(fingerprint=1, optimize_fingerprint=3)
    replacement = FakeInstruction(opcode=2, fingerprint=2)
    history = {}
    context = _context(
        instruction,
        block=block,
        capabilities=NativeCallbackCapabilities(True, True, True, True),
    )

    receipt = _committer(history=history).commit(
        context,
        _candidate(replacement, history_key=("final",)),
    )

    assert receipt.committed is True
    assert receipt.after_fingerprint == 3
    assert history[("final",)] == {3}


def test_provenance_fields_are_required_and_stable() -> None:
    replacement = FakeInstruction(fingerprint=2)
    with pytest.raises(ValueError, match="pass_id"):
        _candidate(replacement, pass_id="")
    with pytest.raises(ValueError, match="stage_id"):
        _candidate(replacement, stage_id=" ")
    with pytest.raises(ValueError, match="rule_id"):
        _candidate(replacement, rule_id="")

    receipt = _committer().commit(
        _context(
            FakeInstruction(),
            block=FakeBlock(FakeMba()),
            capabilities=NativeCallbackCapabilities(True, True, True, True),
        ),
        _candidate(replacement),
    )
    for field in ("pass_id", "stage_id", "rule_id"):
        with pytest.raises(ValueError, match=field):
            replace(receipt, **{field: ""})


def test_context_capture_maps_unknown_maturity_sentinel_to_safe_zero() -> None:
    mba = FakeMba(maturity=-1)
    context = InstructionCommitContext.from_live(
        FakeInstruction(),
        FakeBlock(mba),
    )

    assert context.epoch.maturity == 0


def test_context_capture_null_block_uses_zero_mba_identity_and_no_capabilities() -> None:
    context = InstructionCommitContext.from_live(
        FakeInstruction(),
        None,
        maturity=-1,
    )

    assert context.epoch.mba_identity == 0
    assert context.epoch.maturity == 0
    assert context.capabilities == NativeCallbackCapabilities(False, False, False, False)


def test_invalid_operand_size_is_rejected_without_swap() -> None:
    instruction = FakeInstruction(fingerprint=1)
    replacement = FakeInstruction(fingerprint=2, operand_size_ok=False)
    context = _context(
        instruction,
        block=FakeBlock(FakeMba()),
        capabilities=NativeCallbackCapabilities(True, True, True, True),
    )

    receipt = _committer().commit(context, _candidate(replacement))

    assert instruction.swap_count == 0
    assert receipt.reason == REASON_INVALID_OPERAND_SIZE


def test_required_proof_rejection_happens_before_swap() -> None:
    instruction = FakeInstruction(fingerprint=1)
    replacement = FakeInstruction(fingerprint=2)
    context = _context(
        instruction,
        block=FakeBlock(FakeMba()),
        capabilities=NativeCallbackCapabilities(True, True, True, True),
    )

    receipt = _committer(proof_result=None).commit(
        context,
        _candidate(replacement, proof_required=True),
    )

    assert instruction.swap_count == 0
    assert receipt.reason == REASON_PROOF_REJECTED


def test_directional_cost_and_semantic_rank_admission_is_stable() -> None:
    instruction = FakeInstruction(fingerprint=1)
    context = _context(
        instruction,
        block=FakeBlock(FakeMba()),
        capabilities=NativeCallbackCapabilities(True, True, True, True),
    )
    replacement = FakeInstruction(fingerprint=2)
    cost = RewriteCost(
        noncanonical_ops=2, opaque_ops=1, depth=3, node_count=4, target_risk=2
    )

    simplify = _committer().commit(
        context,
        _candidate(
            replacement,
            mode=RewriteMode.SIMPLIFY,
            cost_before=cost,
            cost_after=cost,
            may_mark_lists_dirty=False,
            may_verify_mba=False,
        ),
    )
    assert simplify.reason == REASON_COST_REJECTED
    assert instruction.swap_count == 0

    recover = _committer().commit(
        context,
        _candidate(
            replacement,
            semantic_rank_before=2,
            semantic_rank_after=2,
            may_mark_lists_dirty=False,
            may_verify_mba=False,
        ),
    )
    assert recover.reason == REASON_SEMANTIC_RANK_REJECTED
    assert instruction.swap_count == 0


def test_legacy_compatibility_accepts_equal_cost_without_proof_and_runs_postconditions() -> None:
    mba = FakeMba()
    block = FakeBlock(mba)
    instruction = FakeInstruction(fingerprint=1)
    replacement = FakeInstruction(fingerprint=2)
    verified = []
    proof_calls = []
    context = _context(
        instruction,
        block=block,
        capabilities=NativeCallbackCapabilities(True, True, True, True),
    )

    receipt = _committer(
        proof_result=None,
        proof_calls=proof_calls,
        verify=lambda live_mba, _ctx: verified.append(live_mba),
    ).commit(
        context,
        _candidate(
            replacement,
            mode=RewriteMode.SIMPLIFY,
            cost_before=RewriteCost(node_count=4),
            cost_after=RewriteCost(node_count=4),
            proof_required=True,
            legacy_compatibility=True,
        ),
    )

    assert receipt.committed is True
    assert proof_calls == []
    assert block.mark_lists_dirty_count == 1
    assert verified == [mba]
    assert receipt.primitive_fields()["legacy_compatibility"] is True


def test_null_block_rejects_effectful_candidate_but_allows_instruction_only() -> None:
    instruction = FakeInstruction(fingerprint=1)
    context = _context(
        instruction,
        block=None,
        capabilities=NativeCallbackCapabilities(False, False, False, False),
    )
    replacement = FakeInstruction(fingerprint=2)

    effectful = _committer().commit(context, _candidate(replacement))
    assert effectful.reason == REASON_BLOCK_CONTEXT_REQUIRED
    assert instruction.swap_count == 0

    instruction_only = _committer().commit(
        context,
        _candidate(
            replacement,
            may_mark_lists_dirty=False,
            may_verify_mba=False,
        ),
    )
    assert instruction_only.committed is True
    assert instruction_only.applied_count == 1
    assert instruction.optimize_solo_count == 1


def test_verification_failure_restores_instruction_and_quarantines() -> None:
    mba = FakeMba()
    block = FakeBlock(mba)
    instruction = FakeInstruction(fingerprint=1)
    replacement = FakeInstruction(opcode=2, fingerprint=2)
    quarantined = []
    context = _context(
        instruction,
        block=block,
        capabilities=NativeCallbackCapabilities(True, True, True, True),
    )

    def verify(_mba, _ctx):
        raise RuntimeError("verify exploded")

    with pytest.raises(NativeMutationQuarantined):
        _committer(
            verify=verify,
            native_failure_quarantine=lambda _error: quarantined.append(True),
        ).commit(
            context,
            _candidate(replacement),
        )

    assert instruction.swap_count == 2
    assert instruction.fingerprint == 1
    assert quarantined == [True]


def test_existing_history_rejects_cycle_and_quarantines_only_the_producer() -> None:
    mba = FakeMba()
    block = FakeBlock(mba)
    instruction = FakeInstruction(fingerprint=1)
    replacement = FakeInstruction(opcode=2, fingerprint=2)
    history = {("site",): {2}}
    quarantined = []
    context = _context(
        instruction,
        block=block,
        capabilities=NativeCallbackCapabilities(True, True, True, True),
    )

    receipt = _committer(
        history=history,
        quarantine=lambda *args: quarantined.append(args),
    ).commit(
        context,
        _candidate(
            replacement,
            rule_id="producer",
            producer_rule_name="producer",
            history_key=("site",),
        ),
    )

    assert receipt.reason == "rewrite-cycle"
    assert instruction.fingerprint == 1
    assert instruction.swap_count == 2
    assert quarantined == [(("site",), "producer")]


def test_lower_is_rejected_and_solve_requires_proof_and_non_worse_cost() -> None:
    instruction = FakeInstruction(fingerprint=1)
    replacement = FakeInstruction(opcode=2, fingerprint=2)
    context = _context(
        instruction,
        block=FakeBlock(FakeMba()),
        capabilities=NativeCallbackCapabilities(True, True, True, True),
    )

    lower = _committer().commit(
        context,
        _candidate(replacement, mode=RewriteMode.LOWER),
    )
    assert lower.reason == "lower-rejected"
    assert instruction.swap_count == 0

    solve = _committer(proof_result="proof").commit(
        context,
        _candidate(
            replacement,
            mode=RewriteMode.SOLVE,
            cost_before=RewriteCost(2, 1, 3, 4, 2),
            cost_after=RewriteCost(2, 1, 3, 4, 2),
        ),
    )
    assert solve.committed is True

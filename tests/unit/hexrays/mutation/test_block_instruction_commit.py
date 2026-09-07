"""Hosted block instruction transaction contract tests."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace

import pytest

from d810.hexrays.mutation.block_instruction_commit import (
    AllocatedKreg,
    BlockInstructionAnchor,
    BlockInstructionBatchCandidate,
    BlockInstructionBatchReceipt,
    BlockInstructionEditIntent,
    BlockInstructionMaterializationContext,
    HexRaysBlockInstructionCommitter,
    MaterializedBlockInstructionEdit,
    fingerprint_minsn,
)
from d810.hexrays.mutation.instruction_commit import NativeEpoch
from d810.hexrays.mutation.fragment_publication_lifecycle import (
    NativeMutationQuarantined,
)

try:
    from d810.hexrays.mutation import deferred_modifier as deferred_modifier_module
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
except ModuleNotFoundError:
    # The pure contract suite intentionally runs without IDAPython.  The
    # DGM integration examples below are exercised in the IDA Docker runtime.
    deferred_modifier_module = None
    DeferredGraphModifier = None


requires_ida_runtime = pytest.mark.skipif(
    DeferredGraphModifier is None,
    reason="hosted instruction batch integration requires IDAPython",
)


class FakeMaterializer:
    def materialize(self, _context):
        return MaterializedBlockInstructionEdit(replacement=object())


def _epoch(*, generation: int = 4) -> NativeEpoch:
    return NativeEpoch(
        function_ea=0x401000,
        mba_identity=0x100,
        maturity=7,
        generation=generation,
    )


def _anchor(
    *,
    ordinal: int = 0,
    instruction_ea: int = 0x401010,
) -> BlockInstructionAnchor:
    return BlockInstructionAnchor(
        block_serial=3,
        block_start_ea=0x401000,
        ordinal=ordinal,
        instruction_ea=instruction_ea,
        opcode=42,
        before_fingerprint=99,
    )


def _anchor_with(**changes: int) -> BlockInstructionAnchor:
    fields = {
        "block_serial": 3,
        "block_start_ea": 0x401000,
        "ordinal": 0,
        "instruction_ea": 0x401010,
        "opcode": 42,
        "before_fingerprint": 99,
    }
    fields.update(changes)
    return BlockInstructionAnchor(**fields)


def _intent(anchor: BlockInstructionAnchor) -> BlockInstructionEditIntent:
    return BlockInstructionEditIntent(
        anchor=anchor,
        materializer=FakeMaterializer(),
        description="test edit",
    )


def _candidate(*intents: BlockInstructionEditIntent) -> BlockInstructionBatchCandidate:
    return BlockInstructionBatchCandidate(
        edits=tuple(intents),
        epoch_before=_epoch(),
        pass_id="test-pass",
        stage_id="test-stage",
        rule_id="test-rule",
    )


def _receipt(
    *,
    committed: bool = False,
    callback_result: int = 0,
    applied_edit_count: int = 0,
    inserted_instruction_count: int = 0,
    epoch_after: NativeEpoch | None = None,
) -> BlockInstructionBatchReceipt:
    epoch_before = _epoch()
    return BlockInstructionBatchReceipt(
        committed=committed,
        callback_result=callback_result,
        applied_edit_count=applied_edit_count,
        inserted_instruction_count=inserted_instruction_count,
        epoch_before=epoch_before,
        epoch_after=epoch_before if epoch_after is None else epoch_after,
        reason="rejected",
        pass_id="test-pass",
        stage_id="test-stage",
        rule_id="test-rule",
        mutation_batch_id=None,
    )


@pytest.mark.parametrize(
    "field",
    ("block_serial", "block_start_ea", "ordinal", "instruction_ea", "opcode"),
)
def test_anchor_rejects_negative_identity_fields(field: str) -> None:
    with pytest.raises(ValueError, match="non-negative"):
        _anchor_with(**{field: -1})


@pytest.mark.parametrize("field", ("register", "size"))
def test_allocated_kreg_rejects_negative_fields(field: str) -> None:
    with pytest.raises(ValueError, match="non-negative"):
        fields = {"register": 5, "size": 1}
        fields[field] = -1
        AllocatedKreg(**fields)


def test_candidate_rejects_empty_edits() -> None:
    with pytest.raises(ValueError, match="at least one edit"):
        _candidate()


def test_candidate_rejects_repeated_complete_anchors() -> None:
    intent = _intent(_anchor())

    with pytest.raises(ValueError, match="duplicate anchor"):
        _candidate(intent, intent)


def test_candidate_accepts_same_instruction_ea_with_distinct_ordinals() -> None:
    candidate = _candidate(_intent(_anchor(ordinal=0)), _intent(_anchor(ordinal=1)))

    assert len(candidate.edits) == 2
    assert (
        candidate.edits[0].anchor.instruction_ea
        == candidate.edits[1].anchor.instruction_ea
    )
    assert candidate.edits[0].anchor.ordinal != candidate.edits[1].anchor.ordinal


def test_contracts_are_frozen() -> None:
    anchor = _anchor()

    with pytest.raises(FrozenInstanceError):
        anchor.ordinal = 1


def test_materialization_context_uses_backend_allocation_port_and_ledger() -> None:
    allocations: list[int] = []
    ledger: list[AllocatedKreg] = []
    context = BlockInstructionMaterializationContext(
        block=object(),
        instruction=object(),
        allocate_kreg=lambda size: allocations.append(size) or 7,
        allocated_kregs=ledger,
    )

    assert context.alloc_kreg(4) == 7
    assert allocations == [4]
    assert ledger == [AllocatedKreg(register=7, size=4)]
    assert not hasattr(context, "mba")


def test_fingerprint_minsn_is_exported_as_the_common_helper() -> None:
    class Instruction:
        opcode = 42

        def _print(self) -> str:
            return "op42"

    instruction = Instruction()

    assert fingerprint_minsn(instruction, 0x401000) == hash(
        (instruction.opcode, instruction._print(), 0x401000)
    )


@pytest.mark.parametrize(
    "kwargs",
    (
        {"committed": True, "callback_result": 0, "applied_edit_count": 1},
        {"committed": True, "callback_result": 1, "applied_edit_count": 0},
        {"committed": False, "callback_result": 1},
        {"committed": False, "applied_edit_count": 1},
        {"committed": False, "inserted_instruction_count": 1},
    ),
)
def test_receipt_rejects_mismatched_callback_and_counts(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="receipt counts"):
        _receipt(**kwargs)


def test_receipt_rejects_non_retained_epoch() -> None:
    with pytest.raises(ValueError, match="retain"):
        _receipt(
            epoch_after=replace(_epoch(), generation=_epoch().generation + 1),
        )


def test_committed_receipt_requires_a_positive_edit_count() -> None:
    with pytest.raises(ValueError, match="receipt counts"):
        _receipt(committed=True, callback_result=1, applied_edit_count=0)


def test_receipt_primitive_fields_are_json_safe_and_omit_native_objects() -> None:
    receipt = BlockInstructionBatchReceipt(
        committed=True,
        callback_result=1,
        applied_edit_count=2,
        inserted_instruction_count=1,
        epoch_before=_epoch(),
        epoch_after=_epoch(),
        reason="committed",
        pass_id="test-pass",
        stage_id="test-stage",
        rule_id="test-rule",
        mutation_batch_id="batch-1",
    )

    fields = receipt.primitive_fields()

    json.dumps(fields, allow_nan=False)
    assert all(
        value is None or type(value) in (bool, int, str) for value in fields.values()
    )
    assert fields["callback_result"] == 1
    assert fields["applied_edit_count"] == 2
    assert fields["inserted_instruction_count"] == 1
    assert fields["generation_before"] == fields["generation_after"]
    assert "epoch_before" not in fields
    assert "epoch_after" not in fields


class _BatchInstruction:
    def __init__(self, ea: int, opcode: int, text: str) -> None:
        self.ea = ea
        self.opcode = opcode
        self._text = text
        self.next = None
        self.prev = None
        self.swap_calls = 0

    def _print(self) -> str:
        return self._text

    def swap(self, other: object) -> None:
        self.swap_calls += 1
        other_opcode = getattr(other, "opcode", self.opcode)
        other_text = getattr(other, "_text", self._text)
        self.opcode, other.opcode = other_opcode, self.opcode
        self._text, other._text = other_text, self._text


class _BatchBlock:
    def __init__(self, mba, instructions: list[_BatchInstruction]) -> None:
        self.mba = mba
        self.serial = 1
        self.start = 0x401000
        self.head = instructions[0]
        self.tail = instructions[-1]
        self.inserted: list[object] = []
        self.removed: list[object] = []
        self.dirty_count = 0
        self.fail_insert = False
        for previous, current in zip(instructions, instructions[1:]):
            previous.next = current
            current.prev = previous

    def insert_into_block(self, instruction: object, anchor: object | None) -> None:
        self.inserted.append((instruction, anchor))
        if self.fail_insert:
            raise RuntimeError("insert")

    def remove_from_block(self, instruction: object) -> None:
        self.removed.append(instruction)

    def mark_lists_dirty(self) -> None:
        self.dirty_count += 1


class _BatchGateway:
    def __init__(self) -> None:
        self.active = False
        self.events: list[object] = []

    def begin_batch(self, *_args, **_kwargs) -> None:
        self.active = True
        self.events.append("begin")

    def record_external_sdk_operations(self, _mba, *, operation_count: int) -> None:
        self.events.append(("record", operation_count))

    def commit(self):
        self.active = False
        self.events.append("commit")
        return SimpleNamespace(mutation_batch_id="batch-1")

    def abort(self, *, reason: str) -> None:
        self.active = False
        self.events.append(("abort", reason))


class _BatchMba:
    def __init__(self) -> None:
        self.entry_ea = 0x401000
        self.qty = 2
        self.allocations: list[tuple[int, bool]] = []
        self.freed: list[tuple[int, int]] = []
        self.blocks: dict[int, object] = {}

    def get_mblock(self, serial: int):
        return self.blocks.get(serial)

    def alloc_kreg(self, size: int, persistent: bool) -> int:
        self.allocations.append((size, persistent))
        return 90 + len(self.allocations)

    def free_kreg(self, register: int, size: int) -> None:
        self.freed.append((register, size))


class _BatchMaterializer:
    def __init__(self, *, allocate: tuple[int, ...] = (), helpers: int = 0, reject=False) -> None:
        self.allocate = allocate
        self.helpers = helpers
        self.reject = reject
        self.calls = 0

    def materialize(self, context):
        self.calls += 1
        for size in self.allocate:
            assert context.alloc_kreg(size) is not None
        if self.reject:
            return None
        return MaterializedBlockInstructionEdit(
            replacement=_BatchInstruction(0x401010, 99, "replacement"),
            insert_before=tuple(
                _BatchInstruction(0x500000 + index, 77, "helper")
                for index in range(self.helpers)
            ),
        )


def _batch_candidate(mba, block, instruction, materializer) -> BlockInstructionBatchCandidate:
    anchor = BlockInstructionAnchor(
        block_serial=block.serial,
        block_start_ea=block.start,
        ordinal=0,
        instruction_ea=instruction.ea,
        opcode=instruction.opcode,
        before_fingerprint=fingerprint_minsn(instruction, mba.entry_ea),
    )
    return BlockInstructionBatchCandidate(
        edits=(
            BlockInstructionEditIntent(
                anchor=anchor,
                materializer=materializer,
                description="batch test",
            ),
        ),
        epoch_before=NativeEpoch.from_mba(mba, generation=4),
        pass_id="test-pass",
        stage_id="test-stage",
        rule_id="test-rule",
    )


def _batch_fixture():
    mba = _BatchMba()
    instruction = _BatchInstruction(0x401010, 42, "original")
    block = _BatchBlock(mba, [instruction])
    mba.blocks[block.serial] = block
    gateway = _BatchGateway()
    modifier = DeferredGraphModifier(mba, mutation_gateway=gateway)
    return mba, block, instruction, gateway, modifier


def _queue_configured_batch(
    modifier: DeferredGraphModifier,
    candidate: BlockInstructionBatchCandidate,
) -> None:
    modifier.configure_instruction_batch_epoch(candidate.epoch_before)
    modifier.queue_instruction_rewrite_batch(candidate)


@requires_ida_runtime
def test_batch_preflight_rejects_changed_anchor_before_materialization() -> None:
    mba, block, instruction, gateway, modifier = _batch_fixture()
    materializer = _BatchMaterializer(allocate=(1,))
    candidate = _batch_candidate(mba, block, instruction, materializer)
    instruction.opcode = 43

    _queue_configured_batch(modifier, candidate)
    receipt = modifier.apply_instruction_rewrite_batch()

    assert not receipt.committed
    assert receipt.callback_result == 0
    assert materializer.calls == 0
    assert mba.allocations == []
    assert gateway.events == []


@requires_ida_runtime
def test_batch_materialization_rejection_frees_ledger_and_aborts() -> None:
    mba, block, instruction, gateway, modifier = _batch_fixture()
    materializer = _BatchMaterializer(allocate=(1, 4), reject=True)
    candidate = _batch_candidate(mba, block, instruction, materializer)

    _queue_configured_batch(modifier, candidate)
    receipt = modifier.apply_instruction_rewrite_batch()

    assert not receipt.committed
    assert mba.freed == [(92, 4), (91, 1)]
    assert block.inserted == []
    assert instruction.swap_calls == 0
    assert gateway.events[0] == "begin"
    assert gateway.events[-1][0] == "abort"


@requires_ida_runtime
def test_batch_post_write_verify_failure_rolls_back_and_poison_lifecycle(monkeypatch) -> None:
    mba, block, instruction, gateway, modifier = _batch_fixture()
    materializer = _BatchMaterializer(allocate=(1,), helpers=1)
    candidate = _batch_candidate(mba, block, instruction, materializer)
    poisoned: list[dict[str, object]] = []
    lifecycle = SimpleNamespace(
        quarantine_native_mutation=lambda **kwargs: poisoned.append(kwargs),
    )
    modifier.configure_instruction_batch_lifecycle(lifecycle)
    monkeypatch.setattr(
        deferred_modifier_module,
        "safe_verify",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("verify")),
    )

    _queue_configured_batch(modifier, candidate)
    with pytest.raises(NativeMutationQuarantined):
        modifier.apply_instruction_rewrite_batch()

    assert instruction.swap_calls == 2
    assert len(block.inserted) == 1
    assert len(block.removed) == 1
    assert mba.freed == [(91, 1)]
    assert poisoned and "verify" in str(poisoned[0]["reason"])
    assert gateway.events[-1][0] == "abort"


@requires_ida_runtime
def test_batch_partial_insert_failure_is_not_misclassified_as_clean_rejection() -> None:
    mba, block, instruction, gateway, modifier = _batch_fixture()
    block.fail_insert = True
    candidate = _batch_candidate(
        mba,
        block,
        instruction,
        _BatchMaterializer(allocate=(1,), helpers=1),
    )
    poisoned: list[dict[str, object]] = []
    modifier.configure_instruction_batch_lifecycle(
        SimpleNamespace(
            quarantine_native_mutation=lambda **kwargs: poisoned.append(kwargs),
        )
    )

    _queue_configured_batch(modifier, candidate)
    with pytest.raises(NativeMutationQuarantined):
        modifier.apply_instruction_rewrite_batch()

    assert len(block.inserted) == 1
    assert len(block.removed) == 1
    assert instruction.swap_calls == 0
    assert mba.freed == [(91, 1)]
    assert poisoned
    assert gateway.events[-1][0] == "abort"


@requires_ida_runtime
def test_direct_dgm_batch_requires_adapter_epoch_configuration() -> None:
    mba, block, instruction, gateway, modifier = _batch_fixture()
    candidate = _batch_candidate(mba, block, instruction, _BatchMaterializer())

    modifier.queue_instruction_rewrite_batch(candidate)
    receipt = modifier.apply_instruction_rewrite_batch()

    assert not receipt.committed
    assert receipt.reason == "epoch-context-required"
    assert gateway.events == []


@requires_ida_runtime
def test_thin_committer_rejects_quarantined_lifecycle_without_queueing() -> None:
    mba, block, instruction, _gateway, modifier = _batch_fixture()
    candidate = _batch_candidate(mba, block, instruction, _BatchMaterializer())
    committer = HexRaysBlockInstructionCommitter(
        lifecycle_authority=SimpleNamespace(native_mutation_quarantined=True),
    )

    receipt = committer.commit(block=block, candidate=candidate, modifier=modifier)

    assert not receipt.committed
    assert receipt.reason == "native-mutation-quarantined"


def test_thin_committer_rejects_same_mba_with_stale_lifecycle_generation() -> None:
    mba = _BatchMba()
    instruction = _BatchInstruction(0x401010, 42, "original")
    block = _BatchBlock(mba, [instruction])
    mba.blocks[block.serial] = block
    candidate = _batch_candidate(mba, block, instruction, _BatchMaterializer())
    committer = HexRaysBlockInstructionCommitter(
        epoch_provider=lambda _block: replace(
            candidate.epoch_before,
            generation=candidate.epoch_before.generation + 1,
        ),
    )

    receipt = committer.commit(block=block, candidate=candidate, modifier=object())

    assert not receipt.committed
    assert receipt.reason == "stale-epoch"


def test_thin_committer_rejects_anchor_outside_callback_block_before_queueing() -> None:
    mba = _BatchMba()
    instruction = _BatchInstruction(0x401010, 42, "original")
    callback_block = _BatchBlock(mba, [instruction])
    mba.blocks[callback_block.serial] = callback_block
    candidate = _batch_candidate(
        mba,
        callback_block,
        instruction,
        _BatchMaterializer(),
    )
    foreign_anchor = replace(
        candidate.edits[0].anchor,
        block_serial=callback_block.serial + 1,
        block_start_ea=callback_block.start + 0x100,
    )
    foreign_candidate = replace(
        candidate,
        edits=(
            replace(candidate.edits[0], anchor=foreign_anchor),
        ),
    )

    class _TrackingModifier:
        def __init__(self):
            self.queue_calls = 0

        def queue_instruction_rewrite_batch(self, _candidate):
            self.queue_calls += 1

        def apply_instruction_rewrite_batch(self):
            return HexRaysBlockInstructionCommitter._rejected(
                foreign_candidate,
                "unexpected-apply",
            )

    modifier = _TrackingModifier()
    receipt = HexRaysBlockInstructionCommitter(
        epoch_provider=lambda _block: foreign_candidate.epoch_before,
    ).commit(
        block=callback_block,
        candidate=foreign_candidate,
        modifier=modifier,
    )

    assert not receipt.committed
    assert receipt.reason == "callback-block-mismatch"
    assert modifier.queue_calls == 0


def test_thin_committer_requires_adapter_epoch_provenance() -> None:
    mba = _BatchMba()
    instruction = _BatchInstruction(0x401010, 42, "original")
    block = _BatchBlock(mba, [instruction])
    mba.blocks[block.serial] = block
    candidate = _batch_candidate(mba, block, instruction, _BatchMaterializer())

    receipt = HexRaysBlockInstructionCommitter().commit(
        block=block,
        candidate=candidate,
        modifier=object(),
    )

    assert not receipt.committed
    assert receipt.reason == "epoch-context-required"

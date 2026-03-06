"""Runtime tests for Hodur executor translation path."""
import sys
import types

import pytest

# Minimal stub so modules importing ida_hexrays remain importable in unit tests.
if "ida_hexrays" not in sys.modules:
    ida_hexrays_stub = types.ModuleType("ida_hexrays")
    ida_hexrays_stub.mop_z = 0
    sys.modules["ida_hexrays"] = ida_hexrays_stub

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.cfg.graph_modification import (
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    NopInstructions,
    RedirectGoto,
)
from d810.cfg.plan import PatchPlan
from d810.optimizers.microcode.flow.flattening.hodur import executor as _executor_mod
from d810.optimizers.microcode.flow.flattening.hodur.executor import TransactionalExecutor
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)


def _block(serial: int, succs: tuple[int, ...], preds: tuple[int, ...]) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1 if succs else 0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0,
        insn_snapshots=(),
    )


def _base_fragment() -> dict:
    return {
        "strategy_name": "test_strategy",
        "family": FAMILY_DIRECT,
        "ownership": OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        ),
        "prerequisites": [],
        "expected_benefit": BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        ),
        "risk_score": 0.1,
        "metadata": {},
    }


class _FakeTranslator:
    def __init__(
        self,
        pre_cfg: FlowGraph,
        post_cfg: FlowGraph | None = None,
        *,
        contract: object | None = None,
    ):
        self.pre_cfg = pre_cfg
        self.post_cfg = post_cfg if post_cfg is not None else pre_cfg
        self.lift_calls = 0
        self.lower_calls: list[PatchPlan] = []
        self.contract = contract

    def lift(self, mba: object) -> FlowGraph:  # noqa: ARG002
        self.lift_calls += 1
        return self.pre_cfg if self.lift_calls == 1 else self.post_cfg

    def prepare_patch_plan(self, patch_plan: PatchPlan, mba: object) -> PatchPlan:  # noqa: ARG002
        raise AssertionError("executor should not call translator.prepare_patch_plan()")

    def lower(
        self,
        patch_plan: PatchPlan,
        mba: object,
        *,
        post_apply_hook=None,
    ) -> int:
        self.lower_calls.append(patch_plan)
        if post_apply_hook is not None:
            post_apply_hook()
        if self.contract is not None:
            self.contract.verify(mba, plan=patch_plan, phase="post")
        return len(patch_plan.as_graph_modifications())


def test_executor_uses_fragment_modifications(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        _executor_mod, "should_apply_cfg_modifications",
        lambda *args, **kwargs: True,
    )

    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), ()),
            1: _block(1, (2,), (0,)),
            2: _block(2, (), (1,)),
        },
        entry_serial=0,
        func_ea=0,
    )
    translator = _FakeTranslator(pre_cfg=cfg)

    fragment = PlanFragment(
        modifications=[
            RedirectGoto(from_serial=0, old_target=1, new_target=1),
            RedirectGoto(from_serial=1, old_target=2, new_target=2),
            RedirectGoto(from_serial=0, old_target=1, new_target=2),
        ],
        **_base_fragment(),
    )

    executor = TransactionalExecutor(mba=object(), translator=translator)
    result = executor.execute_stage(fragment, total_handlers=1)

    assert result.success
    assert result.edits_applied == 3
    assert translator.lift_calls == 2
    assert len(translator.lower_calls) == 1
    assert isinstance(translator.lower_calls[0], PatchPlan)
    assert translator.lower_calls[0].as_graph_modifications() == fragment.modifications
    assert not translator.lower_calls[0].contains_block_creation


def test_executor_preflight_uses_backend_order(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        _executor_mod, "should_apply_cfg_modifications",
        lambda *args, **kwargs: True,
    )

    cfg = FlowGraph(
        blocks={
            44: _block(44, (99, 45), ()),
            122: _block(122, (45,), ()),
            45: _block(45, (2,), (44, 122)),
            2: _block(2, (99,), (45,)),
            99: _block(99, (), (2, 127, 180)),
            127: _block(127, (99,), ()),
            180: _block(180, (99,), ()),
        },
        entry_serial=44,
        func_ea=0,
    )
    translator = _FakeTranslator(pre_cfg=cfg)

    fragment = PlanFragment(
        modifications=[
            RedirectGoto(from_serial=45, old_target=2, new_target=127),
            EdgeRedirectViaPredSplit(
                src_block=45,
                old_target=2,
                new_target=180,
                via_pred=122,
                rule_priority=550,
            ),
        ],
        **_base_fragment(),
    )

    executor = TransactionalExecutor(mba=object(), translator=translator)
    result = executor.execute_stage(fragment, total_handlers=1)

    assert result.success
    assert len(translator.lower_calls) == 1
    assert translator.lower_calls[0].as_graph_modifications() == fragment.modifications
    assert translator.lower_calls[0].contains_block_creation
    assert not translator.lower_calls[0].legacy_block_operations


def test_executor_rejects_legacy_block_creation_when_policy_disabled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        _executor_mod, "should_apply_cfg_modifications",
        lambda *args, **kwargs: True,
    )

    cfg = FlowGraph(
        blocks={
            44: _block(44, (99, 45), ()),
            122: _block(122, (45,), ()),
            45: _block(45, (2,), (44, 122)),
            2: _block(2, (99,), (45,)),
            99: _block(99, (), (2, 127, 180)),
            127: _block(127, (99,), ()),
            180: _block(180, (99,), ()),
        },
        entry_serial=44,
        func_ea=0,
    )
    translator = _FakeTranslator(pre_cfg=cfg)

    fragment = PlanFragment(
        modifications=[
            DuplicateBlock(
                source_block=45,
                target_block=2,
                pred_serial=44,
            ),
        ],
        **{**_base_fragment(), "metadata": {"handler_entry_serials": {180}, "dispatcher_serial": 44}},
    )

    executor = TransactionalExecutor(
        mba=object(),
        translator=translator,
        allow_legacy_block_creation=False,
    )
    result = executor.execute_stage(fragment, total_handlers=1)

    assert not result.success
    assert result.error == "block-creating edits disabled by policy"
    assert not translator.lower_calls


def test_cycle_filter_preserves_non_redirect_modifications():
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), ()),
            1: _block(1, (2,), (0,)),
            2: _block(2, (3,), (1,)),
            3: _block(3, (), (2,)),
        },
        entry_serial=0,
        func_ea=0,
    )

    fragment = PlanFragment(
        modifications=[],
        **_base_fragment(),
    )
    executor = TransactionalExecutor(mba=object(), translator=_FakeTranslator(pre_cfg=cfg))

    cycle_mod = EdgeRedirectViaPredSplit(
        src_block=2,
        old_target=3,
        new_target=1,
        via_pred=1,
        rule_priority=550,
    )
    nop_mod = NopInstructions(block_serial=2, insn_eas=(0x1234,))

    filtered = executor._filter_cycle_modifications(
        fragment=fragment,
        pre_adj=cfg.as_adjacency_dict(),
        terminal_exits={3},
        handler_entries={1},
        dispatcher=0,
        original_modifications=[nop_mod, cycle_mod],
    )

    assert filtered == [nop_mod]


def test_executor_runs_cfg_contract_pre_and_post(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        _executor_mod, "should_apply_cfg_modifications",
        lambda *args, **kwargs: True,
    )

    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), ()),
            1: _block(1, (2,), (0,)),
            2: _block(2, (), (1,)),
        },
        entry_serial=0,
        func_ea=0,
    )

    class _Contract:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def verify_projected(
            self,
            pre_cfg: FlowGraph,  # noqa: ARG002
            plan: PatchPlan,  # noqa: ARG002
        ) -> None:
            self.calls.append("projected")

        def verify(
            self,
            mba: object,  # noqa: ARG002
            plan: PatchPlan,  # noqa: ARG002
            *,
            phase: str,
        ) -> tuple:
            self.calls.append(phase)
            return ()

    contract = _Contract()
    translator = _FakeTranslator(pre_cfg=cfg, contract=contract)

    fragment = PlanFragment(
        modifications=[RedirectGoto(from_serial=1, old_target=2, new_target=2)],
        **_base_fragment(),
    )
    live_mba = types.SimpleNamespace(qty=0, get_mblock=lambda _i: None)

    executor = TransactionalExecutor(
        mba=live_mba,
        translator=translator,
        cfg_contract=contract,
    )
    result = executor.execute_stage(fragment, total_handlers=1)

    assert result.success
    assert contract.calls == ["projected", "pre", "post"]
    assert len(translator.lower_calls) == 1


def test_executor_rejects_cfg_contract_pre_failures(monkeypatch: pytest.MonkeyPatch):
    """Engine's live_pre_check phase rejects before lowering; rollback_needed=False (pre-mutation)."""
    monkeypatch.setattr(
        _executor_mod, "should_apply_cfg_modifications",
        lambda *args, **kwargs: True,
    )

    from d810.cfg.contracts.ida_contract import CfgContractViolationError
    from d810.cfg.contracts.report import InvariantViolation

    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), ()),
            1: _block(1, (2,), (0,)),
            2: _block(2, (), (1,)),
        },
        entry_serial=0,
        func_ea=0,
    )
    translator = _FakeTranslator(pre_cfg=cfg)

    class _Contract:
        def verify_projected(self, pre_cfg, plan):  # noqa: ARG002
            pass  # projected passes

        def verify(self, mba, plan, *, phase):  # noqa: ARG002
            if phase == "pre":
                raise CfgContractViolationError(
                    phase="pre",
                    violations=[
                        InvariantViolation(
                            code="CFG_BAD", message="bad", phase="pre", block_serial=1,
                        ),
                    ],
                )

    fragment = PlanFragment(
        modifications=[RedirectGoto(from_serial=1, old_target=2, new_target=2)],
        **_base_fragment(),
    )
    live_mba = types.SimpleNamespace(qty=0, get_mblock=lambda _i: None)

    executor = TransactionalExecutor(
        mba=live_mba,
        translator=translator,
        cfg_contract=_Contract(),
    )
    result = executor.execute_stage(fragment, total_handlers=1)

    assert not result.success
    # Pre-mutation failure: rollback_needed is False (fixed behavior via transaction_policy)
    assert not result.rollback_needed
    assert "CFG_BAD" in result.error
    assert not translator.lower_calls


def test_executor_rejects_projected_cfg_contract_failures(monkeypatch: pytest.MonkeyPatch):
    """Engine's projected_contract phase rejects before live checks; rollback_needed=False."""
    monkeypatch.setattr(
        _executor_mod, "should_apply_cfg_modifications",
        lambda *args, **kwargs: True,
    )

    from d810.cfg.contracts.ida_contract import CfgContractViolationError
    from d810.cfg.contracts.report import InvariantViolation

    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), ()),
            1: _block(1, (2,), (0,)),
            2: _block(2, (), (1,)),
        },
        entry_serial=0,
        func_ea=0,
    )
    translator = _FakeTranslator(pre_cfg=cfg)

    class _Contract:
        def verify_projected(self, pre_cfg, plan):  # noqa: ARG002
            raise CfgContractViolationError(
                phase="projected",
                violations=[
                    InvariantViolation(
                        code="CFG_50858_SUCC_PRED_MISMATCH",
                        message="mismatch",
                        phase="projected",
                        block_serial=1,
                    ),
                ],
            )

        def verify(self, mba, plan, *, phase):  # noqa: ARG002
            raise AssertionError("projected contract failures should reject before live pre-check")

    fragment = PlanFragment(
        modifications=[RedirectGoto(from_serial=1, old_target=2, new_target=2)],
        **_base_fragment(),
    )
    live_mba = types.SimpleNamespace(qty=0, get_mblock=lambda _i: None)

    executor = TransactionalExecutor(
        mba=live_mba,
        translator=translator,
        cfg_contract=_Contract(),
    )
    result = executor.execute_stage(fragment, total_handlers=1)

    assert not result.success
    # Pre-mutation failure: rollback_needed is False (fixed behavior via transaction_policy)
    assert not result.rollback_needed
    assert "CFG_50858_SUCC_PRED_MISMATCH" in result.error
    assert not translator.lower_calls


def test_executor_routes_through_transaction_engine(monkeypatch: pytest.MonkeyPatch):
    """Verify execute_stage() creates a CfgTransactionEngine and calls apply()."""
    monkeypatch.setattr(
        _executor_mod, "should_apply_cfg_modifications",
        lambda *args, **kwargs: True,
    )

    from d810.cfg.contracts.transaction_engine import CfgTransactionEngine, TransactionResult

    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), ()),
            1: _block(1, (2,), (0,)),
            2: _block(2, (), (1,)),
        },
        entry_serial=0,
        func_ea=0,
    )
    translator = _FakeTranslator(pre_cfg=cfg)

    # Track whether CfgTransactionEngine.apply was called
    engine_apply_calls: list[dict] = []
    original_apply = CfgTransactionEngine.apply

    def _tracking_apply(self, plan, *, pre_cfg, mba, post_apply_hook=None):
        engine_apply_calls.append({"plan": plan, "pre_cfg": pre_cfg})
        return TransactionResult.ok(3)

    monkeypatch.setattr(CfgTransactionEngine, "apply", _tracking_apply)

    fragment = PlanFragment(
        modifications=[
            RedirectGoto(from_serial=0, old_target=1, new_target=1),
            RedirectGoto(from_serial=1, old_target=2, new_target=2),
            RedirectGoto(from_serial=0, old_target=1, new_target=2),
        ],
        **_base_fragment(),
    )

    executor = TransactionalExecutor(mba=object(), translator=translator)
    result = executor.execute_stage(fragment, total_handlers=1)

    assert result.success
    assert result.edits_applied == 3
    assert len(engine_apply_calls) == 1
    assert engine_apply_calls[0]["pre_cfg"] is cfg


def test_executor_premutation_failure_no_rollback(monkeypatch: pytest.MonkeyPatch):
    """Pre-mutation engine failure (projected_contract) yields rollback_needed=False."""
    monkeypatch.setattr(
        _executor_mod, "should_apply_cfg_modifications",
        lambda *args, **kwargs: True,
    )

    from d810.cfg.contracts.transaction_engine import CfgTransactionEngine, TransactionResult

    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), ()),
            1: _block(1, (2,), (0,)),
            2: _block(2, (), (1,)),
        },
        entry_serial=0,
        func_ea=0,
    )
    translator = _FakeTranslator(pre_cfg=cfg)

    def _failing_apply(self, plan, *, pre_cfg, mba, post_apply_hook=None):
        return TransactionResult.failed(
            "projected_contract",
            RuntimeError("pred/succ mismatch on block 5"),
        )

    monkeypatch.setattr(CfgTransactionEngine, "apply", _failing_apply)

    fragment = PlanFragment(
        modifications=[RedirectGoto(from_serial=1, old_target=2, new_target=2)],
        **_base_fragment(),
    )

    executor = TransactionalExecutor(mba=object(), translator=translator)
    result = executor.execute_stage(fragment, total_handlers=1)

    assert not result.success
    # projected_contract is a pre-mutation phase: no rollback needed
    assert not result.rollback_needed
    assert not result.quarantine
    assert "pred/succ mismatch" in result.error
    assert not translator.lower_calls

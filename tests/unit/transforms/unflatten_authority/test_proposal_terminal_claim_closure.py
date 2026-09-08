"""Terminal claim descendants remain constructor-checked owned values."""
import pytest
from d810.core.structural_identity import StructuralTable
from d810.transforms.unflatten_authority import model, proposal_inputs
from d810.transforms.unflatten_authority.ids import authority_id, canonical_bytes, validate_canonical_roundtrip
from .test_model import _subject, block_ref


def _terminal_claim():
    b0, b1 = block_ref("b0"), block_ref("b1")
    corridor = _subject(model, model.SemanticSubjectKind.CORRIDOR,
        model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
        model.CorridorSubjectLocator(authority_id("corridor"), b0, 0x1000,
                                    (b0, b1), (0x1000, 0x1100)))
    source = _subject(model, model.SemanticSubjectKind.BLOCK,
        model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
        model.BlockSubjectLocator(b0, 0x1000))
    terminal = _subject(model, model.SemanticSubjectKind.TERMINAL,
        model.SemanticSubjectRole.TERMINAL_SITE,
        model.TerminalSubjectLocator(b1, 0x1100, model.TerminalKind.RETURN, 0x1104))
    return model.TerminalCycleBreakClaim(model.UnflattenClaimKind.TERMINAL_CYCLE_BREAK,
        corridor, source, terminal, (authority_id("terminal-proof"),), 0)


def test_terminal_claim_detaches_terminal_and_corridor_descendants():
    value = _terminal_claim()
    expected = canonical_bytes(validate_canonical_roundtrip(value, type(value)))
    table = StructuralTable()
    ref = proposal_inputs.capture_terminal_claim(table, value)
    object.__setattr__(value.terminal_subject.locator, "instruction_ea", 0x9999)
    restored = proposal_inputs.materialize_terminal_claim(table, ref)
    assert canonical_bytes(restored) == expected
    assert restored.terminal_subject.locator is not value.terminal_subject.locator


def test_terminal_claim_reconstruction_checks_supplied_identity():
    value = _terminal_claim()
    object.__setattr__(value, "claim_id", "sha256:" + "f" * 64)
    with pytest.raises(ValueError):
        validate_canonical_roundtrip(value, type(value))
    table = StructuralTable()
    ref = proposal_inputs.capture_terminal_claim(table, value)
    with pytest.raises(ValueError):
        proposal_inputs.materialize_terminal_claim(table, ref)


def test_terminal_claim_supports_anchorless_logical_function_exit():
    from dataclasses import replace
    from d810.transforms.cfg_transaction import LogicalBlockRef
    value = _terminal_claim()
    locator = model.LogicalFunctionExitSubjectLocator(LogicalBlockRef("session", "exit", 1), 3)
    terminal = _subject(model, model.SemanticSubjectKind.TERMINAL,
                        model.SemanticSubjectRole.TERMINAL_SITE, locator)
    value = replace(value, terminal_subject=terminal)
    expected = canonical_bytes(validate_canonical_roundtrip(value, type(value)))
    table = StructuralTable()
    ref = proposal_inputs.capture_terminal_claim(table, value)
    restored = proposal_inputs.materialize_terminal_claim(table, ref)
    assert restored.terminal_subject.anchor_ea is None
    assert canonical_bytes(restored) == expected

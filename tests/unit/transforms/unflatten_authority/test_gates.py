from __future__ import annotations

from dataclasses import dataclass, fields, replace

import pytest

from d810.analyses.control_flow.graph_checks import (
    EffectfulReachabilityResult,
    EntryReachabilityResult,
    TerminalReachabilityResult,
)
from d810.transforms.unflatten_authority.gates import (
    GenericCfgGateFacts,
    GenericEffectfulGateFacts,
    GenericEntryGateFacts,
    GenericTerminalGateFacts,
    generic_cfg_gate_facts_from_bundle,
)
from d810.transforms.unflatten_authority.ids import canonical_bytes, canonical_decode


def _facts() -> GenericCfgGateFacts:
    entry = GenericEntryGateFacts.from_result(
        EntryReachabilityResult(True, 2, 2, 1.0, 1, 0.5, "entry-ok")
    )
    raw = GenericEffectfulGateFacts.from_result(
        EffectfulReachabilityResult(False, frozenset({1}), frozenset(), frozenset({1}), "raw-loss")
    )
    effective = GenericEffectfulGateFacts.from_result(
        EffectfulReachabilityResult(True, frozenset({1}), frozenset({1}), frozenset(), "receipt-restored")
    )
    terminal = GenericTerminalGateFacts.from_result(
        TerminalReachabilityResult(True, frozenset({2}), frozenset({2}), 1, 1, "terminal-ok")
    )
    return GenericCfgGateFacts(entry, raw, effective, terminal)


def test_generic_gate_facts_are_lossless_and_canonical() -> None:
    facts = _facts()
    assert generic_cfg_gate_facts_from_bundle(facts.to_bundle()) == facts
    assert canonical_decode(canonical_bytes(facts)) == facts
    assert not any("subject" in field.name for field in fields(GenericCfgGateFacts))
    assert not any("subject" in field.name for field in fields(GenericEffectfulGateFacts))


def test_generic_gate_facts_reject_lossy_or_mutated_reconstructions() -> None:
    facts = _facts()
    with pytest.raises(ValueError, match="partition"):
        replace(
            facts,
            effectful_raw=replace(facts.effectful_raw, lost_block_serials=frozenset()),
        )
    with pytest.raises(ValueError, match="threshold|recomputed"):
        replace(facts.entry, retained_ratio=0.5)


def test_canonical_external_schema_drift_is_checked_for_early_gate_records() -> None:
    from d810.transforms.unflatten_authority import ids

    facts = _facts()
    external_type = type(facts.entry)
    ready = ids._REGISTRIES_READY
    original_fields = ids.fields

    @dataclass
    class ForgedField:
        forged_schema_field: int

    def forged_fields(record_type):
        result = original_fields(record_type)
        if record_type is external_type:
            return (*result, original_fields(ForgedField)[0])
        return result

    ids.fields = forged_fields
    ids._REGISTRIES_READY = False
    try:
        with pytest.raises(RuntimeError, match="GenericEntryGateFacts"):
            ids._ensure_registries()
    finally:
        ids.fields = original_fields
        ids._REGISTRIES_READY = ready

"""Canonical native pass-contract vocabulary and legacy aliases."""
from __future__ import annotations

from dataclasses import dataclass
from warnings import warn


class ContractVocabularyWarning(UserWarning):
    """A config used a legacy native contract vocabulary name."""


@dataclass(frozen=True)
class ContractVocabularyEntry:
    """One public native contract vocabulary term."""

    name: str
    namespace: str
    kind: str
    status: str = "canonical"
    description: str = ""
    legacy_aliases: tuple[str, ...] = ()


_ENTRIES: tuple[ContractVocabularyEntry, ...] = (
    ContractVocabularyEntry(
        name="ir.def_use",
        namespace="ir",
        kind="analysis",
        description="Def-use analysis over the current IR snapshot.",
    ),
    ContractVocabularyEntry(
        name="ir.memory_def",
        namespace="ir",
        kind="fact",
        description="Memory definition fact.",
    ),
    ContractVocabularyEntry(
        name="ir.memory_use",
        namespace="ir",
        kind="fact",
        description="Memory use fact.",
    ),
    ContractVocabularyEntry(
        name="ir.memory_phi",
        namespace="ir",
        kind="fact",
        description="Memory join fact.",
    ),
    ContractVocabularyEntry(
        name="ir.branch_cond",
        namespace="ir",
        kind="evidence",
        description="Branch condition observation or candidate.",
    ),
    ContractVocabularyEntry(
        name="ir.branch_target",
        namespace="ir",
        kind="evidence",
        description="Branch target observation.",
        legacy_aliases=("branch_targets",),
    ),
    ContractVocabularyEntry(
        name="ir.state_variable_write",
        namespace="ir",
        kind="evidence",
        description="State-variable write observation.",
        legacy_aliases=("state_variable_writes",),
    ),
    ContractVocabularyEntry(
        name="ir.induction_var",
        namespace="ir",
        kind="evidence",
        description="Induction variable candidate or observation.",
    ),
    ContractVocabularyEntry(
        name="ir.loop_carried",
        namespace="ir",
        kind="fact",
        description="Loop-carried value relation.",
    ),
    ContractVocabularyEntry(
        name="ir.known_bits",
        namespace="ir",
        kind="analysis",
        description="Known-bits analysis result.",
    ),
    ContractVocabularyEntry(
        name="ir.const_range",
        namespace="ir",
        kind="analysis",
        description="Constant/range analysis result.",
    ),
    ContractVocabularyEntry(
        name="ir.no_alias",
        namespace="ir",
        kind="fact",
        description="No-alias fact.",
    ),
    ContractVocabularyEntry(
        name="ir.clobbers",
        namespace="ir",
        kind="fact",
        description="Clobber summary fact.",
    ),
    ContractVocabularyEntry(
        name="ir.cfg_shape.stale",
        namespace="ir",
        kind="fact",
        description="Stale CFG-shape marker.",
        legacy_aliases=("stale_cfg_shape",),
    ),
    ContractVocabularyEntry(
        name="effect.memory_def.observable",
        namespace="effect",
        kind="effect",
        description="Observable memory definition preservation root.",
    ),
    ContractVocabularyEntry(
        name="effect.sink.return_value",
        namespace="effect",
        kind="effect",
        description="Return-value observable sink.",
    ),
    ContractVocabularyEntry(
        name="effect.sink.external_memory",
        namespace="effect",
        kind="effect",
        description="External-memory observable sink.",
    ),
    ContractVocabularyEntry(
        name="effect.sink.call_effect",
        namespace="effect",
        kind="effect",
        description="Call-effect observable sink.",
    ),
    ContractVocabularyEntry(
        name="effect.sink.control_dependence",
        namespace="effect",
        kind="effect",
        description="Control-dependence observable sink.",
    ),
    ContractVocabularyEntry(
        name="role.payload",
        namespace="role",
        kind="role",
        description="Validated payload role.",
    ),
    ContractVocabularyEntry(
        name="role.dispatcher",
        namespace="role",
        kind="role",
        description="Validated dispatcher role.",
        legacy_aliases=("dispatcher_family",),
    ),
    ContractVocabularyEntry(
        name="role.dispatcher_predicate",
        namespace="role",
        kind="role",
        description="Dispatcher predicate role.",
        legacy_aliases=("dispatcher_predicates",),
    ),
    ContractVocabularyEntry(
        name="role.opaque_predicate",
        namespace="role",
        kind="role",
        description="Opaque predicate verdict.",
    ),
    ContractVocabularyEntry(
        name="role.junk",
        namespace="role",
        kind="role",
        description="Junk-code verdict.",
    ),
    ContractVocabularyEntry(
        name="recovered.state_transition",
        namespace="recovered",
        kind="recovered",
        description="Recovered state transition.",
        legacy_aliases=("state_transition",),
    ),
    ContractVocabularyEntry(
        name="recovered.cfg_edge",
        namespace="recovered",
        kind="recovered",
        description="Recovered CFG edge.",
        legacy_aliases=("recovered_cfg_edge",),
    ),
    ContractVocabularyEntry(
        name="recovered.region",
        namespace="recovered",
        kind="recovered",
        description="Recovered semantic region.",
        legacy_aliases=("semantic_region",),
    ),
    ContractVocabularyEntry(
        name="recovered.devirt_target",
        namespace="recovered",
        kind="recovered",
        description="Recovered devirtualized target.",
    ),
)

_BY_NAME: dict[str, ContractVocabularyEntry] = {
    entry.name: entry for entry in _ENTRIES
}
_ALIASES: dict[str, str] = {
    alias: entry.name for entry in _ENTRIES for alias in entry.legacy_aliases
}


def contract_vocabulary_entries() -> tuple[ContractVocabularyEntry, ...]:
    """Return the known canonical public vocabulary entries."""
    return _ENTRIES


def contract_vocabulary_entry(name: str) -> ContractVocabularyEntry | None:
    """Return the canonical entry for ``name`` if it is known."""
    return _BY_NAME.get(resolve_contract_name(name))


def legacy_contract_aliases() -> dict[str, str]:
    """Return legacy contract names mapped to canonical vocabulary names."""
    return dict(_ALIASES)


def is_legacy_contract_name(name: str) -> bool:
    """Return whether ``name`` is a known legacy alias."""
    return name in _ALIASES


def resolve_contract_name(name: str) -> str:
    """Return the canonical vocabulary name for ``name`` when known."""
    return _ALIASES.get(name, name)


def warn_legacy_contract_names(
    field_name: str,
    names: frozenset[str],
) -> None:
    """Warn once per parsed field when legacy aliases appear in config payloads."""
    legacy = tuple(sorted(name for name in names if is_legacy_contract_name(name)))
    if not legacy:
        return
    replacements = ", ".join(
        f"{name}->{resolve_contract_name(name)}" for name in legacy
    )
    warn(
        f"{field_name} uses legacy contract vocabulary aliases: {replacements}",
        ContractVocabularyWarning,
        stacklevel=3,
    )

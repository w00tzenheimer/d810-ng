"""Pure, bounded learned composite rewrites for the portable MBA term layer.

This module is intentionally independent from IDA, Egglog, Z3, and native
objects.  A rewrite contains only an alpha-normalized pair of
``TypedBvTerm`` shapes plus the semantic context that admitted it.  A caller
may decode the record for syntax-only inspection, or provide the currently
active semantic descriptor to enforce exact invalidation before replay.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, replace
from d810.core.typing import ClassVar, TypeAlias

from d810.mba.typed_term import (
    FIXED_SHIFT_OPERATIONS,
    SUPPORTED_OPERATIONS,
    TypedBvTerm,
    term_cost,
)


SUPPORTED_WIDTHS = frozenset({8, 16, 32, 64})
MAX_INPUT_LEAF_SLOTS = 8
# One record must be bounded independently of the aggregate IDB cache limit.
# This leaves room for Task 11 to enforce its 2 MiB aggregate bound without
# allowing one malformed shape to consume it.
MAX_SERIALIZED_ENTRY_BYTES = 64 * 1024
SCHEMA_VERSION = 1
ACTIVE_SEMANTICS_SCHEMA_VERSION = 1

_DIGEST_LENGTH = 64
_PROOF_MODES = frozenset({"legacy", "shadow"})
_ALPHA_FIELDS = frozenset(
    {"width", "operation", "value", "leaf_slot", "shift_count", "children"}
)
_REWRITE_FIELDS = frozenset(
    {
        "schema_version",
        "template_id",
        "canonicalizer_version",
        "catalogue_digest",
        "profile_digest",
        "egglog_version",
        "proof_mode",
        "width",
        "root_operation",
        "coarse_arity",
        "input_template",
        "output_template",
        "raw_input_cost",
        "output_cost",
        "derivation_trace",
        "created_sequence",
        "last_used_sequence",
    }
)
_SEMANTICS_FIELDS = frozenset(
    {
        "schema_version",
        "canonicalizer_version",
        "catalogue_digest",
        "profile_digest",
        "egglog_version",
        "proof_mode",
        "active_rule_names",
    }
)


class CompositeRewriteMalformed(ValueError):
    """Raised when a rewrite cannot be trusted for matching or replay."""


JsonObject: TypeAlias = dict[str, object]
RuleKey: TypeAlias = tuple[str, str]


def _is_exact_int(value: object) -> bool:
    return type(value) is int


def _require_nonempty_string(value: object, field_name: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _require_digest(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != _DIGEST_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_nonnegative_int(value: object, field_name: str) -> int:
    if not _is_exact_int(value) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def _normalize_rule_key(value: object) -> RuleKey:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError("active rule names must be (family, source_name) pairs")
    if len(value) != 2:
        raise ValueError("active rule pair must contain family and source name")
    family = _require_nonempty_string(value[0], "rule family")
    source_name = _require_nonempty_string(value[1], "rule source name")
    return (family, source_name)


def _normalize_active_rule_names(values: object) -> tuple[RuleKey, ...]:
    if (
        isinstance(values, (str, bytes))
        or isinstance(values, Mapping)
        or not isinstance(values, Collection)
    ):
        raise ValueError("active_rule_names must be a collection")
    normalized = {_normalize_rule_key(value) for value in values}
    return tuple(sorted(normalized))


@dataclass(frozen=True, slots=True)
class CompositeRewriteSemantics:
    """JSON-safe semantic context required to admit a learned rewrite.

    ``active_rule_names`` contains exact ``(family, source_name)`` pairs.
    Family and source names are both required and are never treated as
    wildcards.
    """

    canonicalizer_version: int
    catalogue_digest: str
    profile_digest: str
    egglog_version: str
    proof_mode: str
    active_rule_names: tuple[RuleKey, ...] = ()

    def __post_init__(self) -> None:
        if not _is_exact_int(self.canonicalizer_version) or (
            self.canonicalizer_version <= 0
        ):
            raise ValueError("canonicalizer_version must be a positive integer")
        _require_digest(self.catalogue_digest, "catalogue_digest")
        _require_digest(self.profile_digest, "profile_digest")
        _require_nonempty_string(self.egglog_version, "egglog_version")
        if self.proof_mode not in _PROOF_MODES:
            raise ValueError("proof_mode must be legacy or shadow")
        object.__setattr__(
            self,
            "active_rule_names",
            _normalize_active_rule_names(self.active_rule_names),
        )

    @property
    def rules(self) -> tuple[RuleKey, ...]:
        """Compatibility spelling for callers that call these rule keys."""

        return self.active_rule_names

    def has_rule(self, family: str, source_name: str) -> bool:
        key = (family, source_name)
        return key in self.active_rule_names

    def to_dict(self) -> JsonObject:
        return {
            "schema_version": ACTIVE_SEMANTICS_SCHEMA_VERSION,
            "canonicalizer_version": self.canonicalizer_version,
            "catalogue_digest": self.catalogue_digest,
            "profile_digest": self.profile_digest,
            "egglog_version": self.egglog_version,
            "proof_mode": self.proof_mode,
            "active_rule_names": [list(item) for item in self.active_rule_names],
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, payload: object) -> "CompositeRewriteSemantics":
        if type(payload) is not dict or set(payload) != _SEMANTICS_FIELDS:
            raise CompositeRewriteMalformed("invalid active semantics schema")
        try:
            if payload["schema_version"] != ACTIVE_SEMANTICS_SCHEMA_VERSION:
                raise ValueError("unknown active semantics schema")
            names = payload["active_rule_names"]
            if type(names) is not list:
                raise ValueError("active_rule_names must be a list")
            # A JSON rule name is always an explicit [family, source] pair.
            for item in names:
                if type(item) is not list or len(item) != 2:
                    raise ValueError("malformed active rule name")
            return cls(
                canonicalizer_version=payload["canonicalizer_version"],
                catalogue_digest=payload["catalogue_digest"],
                profile_digest=payload["profile_digest"],
                egglog_version=payload["egglog_version"],
                proof_mode=payload["proof_mode"],
                active_rule_names=tuple(tuple(item) for item in names),
            )
        except CompositeRewriteMalformed:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise CompositeRewriteMalformed(str(exc)) from exc

    @classmethod
    def from_json(cls, encoded: str) -> "CompositeRewriteSemantics":
        if type(encoded) is not str:
            raise CompositeRewriteMalformed("semantics JSON must be a string")
        try:
            payload = json.loads(encoded)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise CompositeRewriteMalformed("invalid active semantics JSON") from exc
        return cls.from_dict(payload)


# The short spelling was used in the initial RED fixture and is intentionally
# retained as a public alias for callers that prefer it.
ActiveSemantics = CompositeRewriteSemantics


@dataclass(frozen=True, slots=True)
class AlphaTerm:
    """Portable alpha-normalized fixed-width term node."""

    width: int
    operation: str | None = None
    value: int | None = None
    leaf_slot: int | None = None
    shift_count: int | None = None
    children: tuple["AlphaTerm", ...] = ()

    SUPPORTED_WIDTHS: ClassVar[frozenset[int]] = SUPPORTED_WIDTHS

    def __post_init__(self) -> None:
        if not _is_exact_int(self.width) or self.width not in SUPPORTED_WIDTHS:
            raise ValueError("AlphaTerm width must be one of 8, 16, 32, or 64")
        children = tuple(self.children)
        object.__setattr__(self, "children", children)
        if any(not isinstance(child, AlphaTerm) for child in children):
            raise ValueError("AlphaTerm children must be AlphaTerm values")
        if self.operation is not None:
            if type(self.operation) is not str or self.operation not in SUPPORTED_OPERATIONS:
                raise ValueError("unsupported AlphaTerm operation")
            if self.value is not None or self.leaf_slot is not None:
                raise ValueError("operator AlphaTerm cannot carry a terminal value")
            expected_arity = (
                1
                if self.operation in {"bnot", "neg"} | FIXED_SHIFT_OPERATIONS
                else 2
            )
            if len(children) != expected_arity:
                raise ValueError("AlphaTerm operation has the wrong arity")
            if any(child.width != self.width for child in children):
                raise ValueError("AlphaTerm children must have the same width")
            if self.operation in FIXED_SHIFT_OPERATIONS:
                if not _is_exact_int(self.shift_count) or not (
                    0 <= self.shift_count < self.width
                ):
                    raise ValueError("fixed shift count is out of range")
            elif self.shift_count is not None:
                raise ValueError("only fixed shifts accept shift_count")
            return

        if children:
            raise ValueError("terminal AlphaTerm cannot have children")
        if (self.value is None) == (self.leaf_slot is None):
            raise ValueError("terminal AlphaTerm needs exactly one value or leaf slot")
        if self.value is not None:
            if not _is_exact_int(self.value) or not 0 <= self.value < (1 << self.width):
                raise ValueError("AlphaTerm value is out of range")
        else:
            if not _is_exact_int(self.leaf_slot) or self.leaf_slot < 0:
                raise ValueError("AlphaTerm leaf_slot must be non-negative")
        if self.shift_count is not None:
            raise ValueError("terminal AlphaTerm cannot carry shift_count")

    def to_dict(self) -> JsonObject:
        return {
            "width": self.width,
            "operation": self.operation,
            "value": self.value,
            "leaf_slot": self.leaf_slot,
            "shift_count": self.shift_count,
            "children": [child.to_dict() for child in self.children],
        }


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _alpha_normalize(
    term: TypedBvTerm,
    *,
    slots: dict[tuple[object, ...], int],
    allow_new_slots: bool,
) -> AlphaTerm:
    if not isinstance(term, TypedBvTerm):
        raise CompositeRewriteMalformed("terms must be TypedBvTerm values")
    if term.leaf_key is not None:
        slot = slots.get(term.leaf_key)
        if slot is None:
            if not allow_new_slots:
                raise CompositeRewriteMalformed(
                    "output references a leaf absent from the input"
                )
            slot = len(slots)
            slots[term.leaf_key] = slot
        return AlphaTerm(width=term.width, leaf_slot=slot)
    if term.value is not None:
        return AlphaTerm(width=term.width, value=term.value)
    if term.operation is None:
        raise CompositeRewriteMalformed("malformed terminal TypedBvTerm")
    return AlphaTerm(
        width=term.width,
        operation=term.operation,
        shift_count=term.shift_count,
        children=tuple(
            _alpha_normalize(child, slots=slots, allow_new_slots=allow_new_slots)
            for child in term.children
        ),
    )


def alpha_normalize_pair(
    input_term: TypedBvTerm,
    output_term: TypedBvTerm,
) -> tuple[AlphaTerm, AlphaTerm]:
    """Normalize a pair using one first-preorder slot map."""

    slots: dict[tuple[object, ...], int] = {}
    normalized_input = _alpha_normalize(
        input_term, slots=slots, allow_new_slots=True
    )
    normalized_output = _alpha_normalize(
        output_term, slots=slots, allow_new_slots=False
    )
    return normalized_input, normalized_output


def _parse_alpha(payload: object) -> AlphaTerm:
    if type(payload) is not dict or set(payload) != _ALPHA_FIELDS:
        raise CompositeRewriteMalformed("malformed AlphaTerm payload")
    children = payload["children"]
    if type(children) is not list:
        raise CompositeRewriteMalformed("AlphaTerm children must be a list")
    try:
        return AlphaTerm(
            width=payload["width"],
            operation=payload["operation"],
            value=payload["value"],
            leaf_slot=payload["leaf_slot"],
            shift_count=payload["shift_count"],
            children=tuple(_parse_alpha(child) for child in children),
        )
    except CompositeRewriteMalformed:
        raise
    except (TypeError, ValueError) as exc:
        raise CompositeRewriteMalformed(str(exc)) from exc


def _collect_leaf_slots(term: AlphaTerm) -> tuple[int, ...]:
    found: list[int] = []

    def visit(node: AlphaTerm) -> None:
        if node.leaf_slot is not None:
            found.append(node.leaf_slot)
        for child in node.children:
            visit(child)

    visit(term)
    return tuple(found)


def _validate_alpha_pair(input_template: AlphaTerm, output_template: AlphaTerm) -> None:
    input_slots = _collect_leaf_slots(input_template)
    unique_input_slots = tuple(dict.fromkeys(input_slots))
    if len(unique_input_slots) > MAX_INPUT_LEAF_SLOTS:
        raise CompositeRewriteMalformed("input template has too many leaf slots")
    if unique_input_slots != tuple(range(len(unique_input_slots))):
        raise CompositeRewriteMalformed("input leaf slots are not first-preorder canonical")
    output_slots = set(_collect_leaf_slots(output_template))
    if not output_slots.issubset(set(unique_input_slots)):
        raise CompositeRewriteMalformed("output references an unknown leaf slot")


def _normalize_cost(value: object, field_name: str) -> tuple[int, int]:
    if type(value) is not tuple or len(value) != 2:
        raise ValueError(f"{field_name} must be a two-item tuple")
    if any(not _is_exact_int(item) or item < 0 for item in value):
        raise ValueError(f"{field_name} must contain non-negative integers")
    return (value[0], value[1])


def _json_cost(value: object, field_name: str) -> tuple[int, int]:
    if type(value) is not list or len(value) != 2:
        raise CompositeRewriteMalformed(f"{field_name} must be a two-item list")
    if any(not _is_exact_int(item) or item < 0 for item in value):
        raise CompositeRewriteMalformed(f"{field_name} must contain integers")
    return (value[0], value[1])


def _normalize_trace(trace: object) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    if isinstance(trace, (str, bytes)) or not isinstance(trace, Sequence) or not trace:
        raise ValueError("derivation_trace must be non-empty")
    rows: list[tuple[str, str, tuple[str, ...]]] = []
    for item in trace:
        if type(item) is str:
            family, source_name, aliases = "", item, ()
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes)):
            if len(item) == 1:
                family, source_name, aliases = "", item[0], ()
            elif len(item) == 2:
                family, source_name, aliases = item[0], item[1], ()
            elif len(item) == 3:
                family, source_name, aliases = item
            else:
                raise ValueError("malformed derivation trace row")
        else:
            raise ValueError("malformed derivation trace row")
        family = _require_nonempty_string(family, "trace family") if family else ""
        source_name = _require_nonempty_string(source_name, "trace source name")
        if isinstance(aliases, (str, bytes)) or not isinstance(aliases, Sequence):
            raise ValueError("trace aliases must be a sequence")
        normalized_aliases = tuple(
            _require_nonempty_string(alias, "trace alias") for alias in aliases
        )
        rows.append((family, source_name, normalized_aliases))
    return tuple(rows)


def _trace_has_active_rules(
    trace: tuple[tuple[str, str, tuple[str, ...]], ...],
    semantics: CompositeRewriteSemantics,
) -> bool:
    return all(semantics.has_rule(family, source_name) for family, source_name, _ in trace)


def _template_id(
    *,
    schema_version: int,
    canonicalizer_version: int,
    catalogue_digest: str,
    profile_digest: str,
    egglog_version: str,
    proof_mode: str,
    width: int,
    root_operation: str | None,
    coarse_arity: int,
    input_template: AlphaTerm,
    output_template: AlphaTerm,
    raw_input_cost: tuple[int, int],
    output_cost: tuple[int, int],
    derivation_trace: tuple[tuple[str, str, tuple[str, ...]], ...],
) -> str:
    identity = {
        "schema_version": schema_version,
        "canonicalizer_version": canonicalizer_version,
        "catalogue_digest": catalogue_digest,
        "profile_digest": profile_digest,
        "egglog_version": egglog_version,
        "proof_mode": proof_mode,
        "width": width,
        "root_operation": root_operation,
        "coarse_arity": coarse_arity,
        "input_template": input_template.to_dict(),
        "output_template": output_template.to_dict(),
        "raw_input_cost": list(raw_input_cost),
        "output_cost": list(output_cost),
        "derivation_trace": [
            [family, source_name, list(aliases)]
            for family, source_name, aliases in derivation_trace
        ],
    }
    return hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class EgglogCompositeRewrite:
    """One immutable accepted composite rewrite and its portable matcher."""

    schema_version: int
    template_id: str
    canonicalizer_version: int
    catalogue_digest: str
    profile_digest: str
    egglog_version: str
    proof_mode: str
    width: int
    root_operation: str | None
    coarse_arity: int
    input_template: AlphaTerm
    output_template: AlphaTerm
    raw_input_cost: tuple[int, int]
    output_cost: tuple[int, int]
    derivation_trace: tuple[tuple[str, str, tuple[str, ...]], ...]
    created_sequence: int = 0
    last_used_sequence: int = 0

    def __post_init__(self) -> None:
        try:
            if self.schema_version != SCHEMA_VERSION:
                raise ValueError("unknown composite rewrite schema")
            _require_nonempty_string(self.template_id, "template_id")
            if not _is_exact_int(self.canonicalizer_version) or (
                self.canonicalizer_version <= 0
            ):
                raise ValueError("canonicalizer_version must be positive")
            _require_digest(self.catalogue_digest, "catalogue_digest")
            _require_digest(self.profile_digest, "profile_digest")
            _require_nonempty_string(self.egglog_version, "egglog_version")
            if self.proof_mode not in _PROOF_MODES:
                raise ValueError("unknown proof mode")
            if not _is_exact_int(self.width) or self.width not in SUPPORTED_WIDTHS:
                raise ValueError("unsupported rewrite width")
            if not isinstance(self.input_template, AlphaTerm) or not isinstance(
                self.output_template, AlphaTerm
            ):
                raise ValueError("templates must be AlphaTerm values")
            if self.input_template.width != self.width or self.output_template.width != self.width:
                raise ValueError("template width does not match rewrite width")
            if self.root_operation != self.input_template.operation:
                raise ValueError("root_operation does not match input template")
            if not _is_exact_int(self.coarse_arity) or self.coarse_arity < 0:
                raise ValueError("coarse_arity must be non-negative")
            if self.coarse_arity != len(self.input_template.children):
                raise ValueError("coarse_arity does not match input template")
            _validate_alpha_pair(self.input_template, self.output_template)
            object.__setattr__(self, "raw_input_cost", _normalize_cost(self.raw_input_cost, "raw_input_cost"))
            object.__setattr__(self, "output_cost", _normalize_cost(self.output_cost, "output_cost"))
            expected_raw = term_cost(_alpha_to_typed_term(self.input_template))
            expected_output = term_cost(_alpha_to_typed_term(self.output_template))
            if self.raw_input_cost != expected_raw:
                raise ValueError("raw_input_cost does not match input template")
            if self.output_cost != expected_output:
                raise ValueError("output_cost does not match output template")
            if not self.output_cost < self.raw_input_cost:
                raise ValueError("output cost must be strictly lower than raw input cost")
            object.__setattr__(self, "derivation_trace", _normalize_trace(self.derivation_trace))
            _require_nonnegative_int(self.created_sequence, "created_sequence")
            _require_nonnegative_int(self.last_used_sequence, "last_used_sequence")
            if self.last_used_sequence < self.created_sequence:
                raise ValueError("last_used_sequence cannot precede created_sequence")
            expected_id = _template_id(
                schema_version=self.schema_version,
                canonicalizer_version=self.canonicalizer_version,
                catalogue_digest=self.catalogue_digest,
                profile_digest=self.profile_digest,
                egglog_version=self.egglog_version,
                proof_mode=self.proof_mode,
                width=self.width,
                root_operation=self.root_operation,
                coarse_arity=self.coarse_arity,
                input_template=self.input_template,
                output_template=self.output_template,
                raw_input_cost=self.raw_input_cost,
                output_cost=self.output_cost,
                derivation_trace=self.derivation_trace,
            )
            if self.template_id != expected_id:
                raise ValueError("template_id does not match canonical payload")
            if len(_canonical_json(self.to_dict()).encode("utf-8")) > MAX_SERIALIZED_ENTRY_BYTES:
                raise ValueError("serialized composite rewrite exceeds hard bound")
        except CompositeRewriteMalformed:
            raise
        except (TypeError, ValueError) as exc:
            raise ValueError(str(exc)) from exc

    @property
    def bucket_key(self) -> tuple[object, ...]:
        """Exact cache lookup context shared with Task 11/12."""

        return (
            self.catalogue_digest,
            self.profile_digest,
            self.canonicalizer_version,
            self.egglog_version,
            self.proof_mode,
            self.width,
            self.root_operation,
            self.coarse_arity,
        )

    @property
    def semantic_fingerprint(self) -> tuple[object, ...]:
        return self.bucket_key

    @classmethod
    def from_extraction(
        cls,
        *,
        input_term: TypedBvTerm,
        output_term: TypedBvTerm,
        derivation_trace: object,
        semantics: CompositeRewriteSemantics,
        created_sequence: int = 0,
        last_used_sequence: int = 0,
    ) -> "EgglogCompositeRewrite":
        if not isinstance(semantics, CompositeRewriteSemantics):
            raise CompositeRewriteMalformed("semantics must be CompositeRewriteSemantics")
        try:
            input_template, output_template = alpha_normalize_pair(input_term, output_term)
            if input_template.width not in SUPPORTED_WIDTHS or output_template.width != input_template.width:
                raise ValueError("unsupported or inconsistent extraction width")
            _validate_alpha_pair(input_template, output_template)
            normalized_trace = _normalize_trace(derivation_trace)
            if not _trace_has_active_rules(normalized_trace, semantics):
                raise ValueError("derivation trace contains a rule absent from active semantics")
            raw_input_cost = term_cost(input_term)
            output_cost = term_cost(output_term)
            if not output_cost < raw_input_cost:
                raise ValueError("output cost must be strictly lower than raw input cost")
            template_id = _template_id(
                schema_version=SCHEMA_VERSION,
                canonicalizer_version=semantics.canonicalizer_version,
                catalogue_digest=semantics.catalogue_digest,
                profile_digest=semantics.profile_digest,
                egglog_version=semantics.egglog_version,
                proof_mode=semantics.proof_mode,
                width=input_template.width,
                root_operation=input_template.operation,
                coarse_arity=len(input_template.children),
                input_template=input_template,
                output_template=output_template,
                raw_input_cost=raw_input_cost,
                output_cost=output_cost,
                derivation_trace=normalized_trace,
            )
            rewrite = cls(
                schema_version=SCHEMA_VERSION,
                template_id=template_id,
                canonicalizer_version=semantics.canonicalizer_version,
                catalogue_digest=semantics.catalogue_digest,
                profile_digest=semantics.profile_digest,
                egglog_version=semantics.egglog_version,
                proof_mode=semantics.proof_mode,
                width=input_template.width,
                root_operation=input_template.operation,
                coarse_arity=len(input_template.children),
                input_template=input_template,
                output_template=output_template,
                raw_input_cost=raw_input_cost,
                output_cost=output_cost,
                derivation_trace=normalized_trace,
                created_sequence=created_sequence,
                last_used_sequence=last_used_sequence,
            )
            if len(rewrite.to_json().encode("utf-8")) > MAX_SERIALIZED_ENTRY_BYTES:
                raise ValueError("serialized composite rewrite exceeds hard bound")
            return rewrite
        except CompositeRewriteMalformed:
            raise
        except (TypeError, ValueError, KeyError) as exc:
            raise CompositeRewriteMalformed(str(exc)) from exc

    def to_dict(self) -> JsonObject:
        return {
            "schema_version": self.schema_version,
            "template_id": self.template_id,
            "canonicalizer_version": self.canonicalizer_version,
            "catalogue_digest": self.catalogue_digest,
            "profile_digest": self.profile_digest,
            "egglog_version": self.egglog_version,
            "proof_mode": self.proof_mode,
            "width": self.width,
            "root_operation": self.root_operation,
            "coarse_arity": self.coarse_arity,
            "input_template": self.input_template.to_dict(),
            "output_template": self.output_template.to_dict(),
            "raw_input_cost": list(self.raw_input_cost),
            "output_cost": list(self.output_cost),
            "derivation_trace": [
                [family, source_name, list(aliases)]
                for family, source_name, aliases in self.derivation_trace
            ],
            "created_sequence": self.created_sequence,
            "last_used_sequence": self.last_used_sequence,
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(
        cls,
        payload: object,
        *,
        semantics: CompositeRewriteSemantics | None = None,
    ) -> "EgglogCompositeRewrite":
        if type(payload) is not dict or set(payload) != _REWRITE_FIELDS:
            raise CompositeRewriteMalformed("invalid composite rewrite schema")
        try:
            if payload["schema_version"] != SCHEMA_VERSION:
                raise ValueError("unknown composite rewrite schema")
            input_template = _parse_alpha(payload["input_template"])
            output_template = _parse_alpha(payload["output_template"])
            raw_cost = _json_cost(payload["raw_input_cost"], "raw_input_cost")
            output_cost = _json_cost(payload["output_cost"], "output_cost")
            trace = _normalize_json_trace(payload["derivation_trace"])
            rewrite = cls(
                schema_version=payload["schema_version"],
                template_id=payload["template_id"],
                canonicalizer_version=payload["canonicalizer_version"],
                catalogue_digest=payload["catalogue_digest"],
                profile_digest=payload["profile_digest"],
                egglog_version=payload["egglog_version"],
                proof_mode=payload["proof_mode"],
                width=payload["width"],
                root_operation=payload["root_operation"],
                coarse_arity=payload["coarse_arity"],
                input_template=input_template,
                output_template=output_template,
                raw_input_cost=raw_cost,
                output_cost=output_cost,
                derivation_trace=trace,
                created_sequence=payload["created_sequence"],
                last_used_sequence=payload["last_used_sequence"],
            )
            if semantics is not None:
                _validate_semantics_match(rewrite, semantics)
            return rewrite
        except CompositeRewriteMalformed:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise CompositeRewriteMalformed(str(exc)) from exc

    @classmethod
    def from_json(
        cls,
        encoded: str,
        *,
        semantics: CompositeRewriteSemantics | None = None,
    ) -> "EgglogCompositeRewrite":
        if type(encoded) is not str:
            raise CompositeRewriteMalformed("composite JSON must be a string")
        try:
            payload = json.loads(encoded)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise CompositeRewriteMalformed("invalid composite rewrite JSON") from exc
        return cls.from_dict(payload, semantics=semantics)

    def with_sequences(
        self,
        *,
        created_sequence: int | None = None,
        last_used_sequence: int | None = None,
    ) -> "EgglogCompositeRewrite":
        """Return the same immutable record with cache-owned sequence metadata."""

        return replace(
            self,
            created_sequence=(
                self.created_sequence if created_sequence is None else created_sequence
            ),
            last_used_sequence=(
                self.last_used_sequence
                if last_used_sequence is None
                else last_used_sequence
            ),
        )

    def match(
        self,
        term: TypedBvTerm,
        *,
        semantics: CompositeRewriteSemantics | None = None,
    ) -> dict[int, TypedBvTerm] | None:
        """Match transactionally and return fresh current-term bindings."""

        _validate_semantics_match(self, semantics)
        if not isinstance(term, TypedBvTerm):
            return None
        bindings: dict[int, TypedBvTerm] = {}
        if _match_alpha(self.input_template, term, bindings):
            return dict(bindings)
        return None

    def materialize(
        self,
        bindings: Mapping[int, TypedBvTerm] | None,
        *,
        semantics: CompositeRewriteSemantics | None = None,
    ) -> TypedBvTerm:
        """Build output only from the caller's current typed-term bindings."""

        _validate_semantics_match(self, semantics)
        if not isinstance(bindings, Mapping):
            raise CompositeRewriteMalformed("bindings must be a mapping")
        normalized: dict[int, TypedBvTerm] = {}
        for slot, value in bindings.items():
            if not _is_exact_int(slot) or slot < 0 or not isinstance(value, TypedBvTerm):
                raise CompositeRewriteMalformed("bindings contain a non-portable value")
            if value.width != self.width or value.operation is not None or value.leaf_key is None:
                raise CompositeRewriteMalformed("bindings must contain current live leaves")
            normalized[slot] = value
        try:
            return _materialize_alpha(self.output_template, normalized)
        except CompositeRewriteMalformed:
            raise
        except (TypeError, ValueError) as exc:
            raise CompositeRewriteMalformed(str(exc)) from exc


def _normalize_json_trace(value: object) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    if type(value) is not list:
        raise CompositeRewriteMalformed("derivation_trace must be a list")
    for row in value:
        if type(row) is not list or len(row) != 3 or type(row[2]) is not list:
            raise CompositeRewriteMalformed("malformed derivation trace payload")
    try:
        return _normalize_trace(value)
    except (TypeError, ValueError) as exc:
        raise CompositeRewriteMalformed(str(exc)) from exc


def _validate_semantics_match(
    rewrite: EgglogCompositeRewrite,
    semantics: CompositeRewriteSemantics | None,
) -> None:
    if not isinstance(semantics, CompositeRewriteSemantics):
        raise CompositeRewriteMalformed("semantics must be CompositeRewriteSemantics")
    if (
        rewrite.canonicalizer_version != semantics.canonicalizer_version
        or rewrite.catalogue_digest != semantics.catalogue_digest
        or rewrite.profile_digest != semantics.profile_digest
        or rewrite.egglog_version != semantics.egglog_version
        or rewrite.proof_mode != semantics.proof_mode
    ):
        raise CompositeRewriteMalformed("rewrite semantics are stale")
    if not _trace_has_active_rules(rewrite.derivation_trace, semantics):
        raise CompositeRewriteMalformed("rewrite trace is absent from active semantics")


def _alpha_to_typed_term(term: AlphaTerm) -> TypedBvTerm:
    """Use placeholders only for validation cost; never used for materialization."""

    if term.leaf_slot is not None:
        return TypedBvTerm(None, term.width, leaf_key=("slot", term.leaf_slot))
    if term.value is not None:
        return TypedBvTerm(None, term.width, value=term.value)
    return TypedBvTerm(
        term.operation,
        term.width,
        children=tuple(_alpha_to_typed_term(child) for child in term.children),
        shift_count=term.shift_count,
    )


def _match_alpha(
    pattern: AlphaTerm,
    candidate: TypedBvTerm,
    bindings: dict[int, TypedBvTerm],
) -> bool:
    if candidate.width != pattern.width:
        return False
    if pattern.leaf_slot is not None:
        if candidate.operation is not None or candidate.leaf_key is None:
            return False
        previous = bindings.get(pattern.leaf_slot)
        if previous is None:
            bindings[pattern.leaf_slot] = candidate
            return True
        return previous == candidate
    if pattern.value is not None:
        return candidate.operation is None and candidate.value == pattern.value
    if candidate.operation != pattern.operation:
        return False
    if candidate.shift_count != pattern.shift_count:
        return False
    if len(candidate.children) != len(pattern.children):
        return False
    snapshot = dict(bindings)
    for child_pattern, child_candidate in zip(pattern.children, candidate.children):
        if not _match_alpha(child_pattern, child_candidate, bindings):
            bindings.clear()
            bindings.update(snapshot)
            return False
    return True


def _materialize_alpha(
    template: AlphaTerm,
    bindings: Mapping[int, TypedBvTerm],
) -> TypedBvTerm:
    if template.leaf_slot is not None:
        try:
            value = bindings[template.leaf_slot]
        except KeyError as exc:
            raise CompositeRewriteMalformed("output binding is missing") from exc
        if value.width != template.width:
            raise CompositeRewriteMalformed("binding width does not match output")
        return value
    if template.value is not None:
        return TypedBvTerm(None, template.width, value=template.value)
    children = tuple(_materialize_alpha(child, bindings) for child in template.children)
    return TypedBvTerm(
        template.operation,
        template.width,
        children=children,
        shift_count=template.shift_count,
    )


__all__ = [
    "ACTIVE_SEMANTICS_SCHEMA_VERSION",
    "ActiveSemantics",
    "AlphaTerm",
    "CompositeRewriteMalformed",
    "CompositeRewriteSemantics",
    "EgglogCompositeRewrite",
    "MAX_INPUT_LEAF_SLOTS",
    "MAX_SERIALIZED_ENTRY_BYTES",
    "SCHEMA_VERSION",
    "SUPPORTED_WIDTHS",
    "alpha_normalize_pair",
]

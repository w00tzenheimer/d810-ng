"""Stable, IDA-free contracts for native MBA extensions.

The extension package must be able to depend on this module without loading
Hex-Rays, an optimizer manager, or a provider implementation.  Native objects
therefore cross this boundary only through the deliberately opaque
``native_context`` field.  The IDA-bound host owns that context and keeps it
immutable for the lifetime of one callback candidate.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from d810.core.typing import Protocol
import d810.mba.typed_term as typed_term_module
from d810.mba.ac_matching import AcMatchStopReason
from d810.mba.certified_rule_compiler import (
    CompiledMbaRule,
    require_admitted_compiled_rules,
)
from d810.mba.canonical_pattern import (
    CanonicalCompiledPattern,
    CanonicalPatternMalformed,
    CanonicalPatternUnsupported,
    compile_canonical_pattern,
    evaluate_frozen_constraints,
    match_canonical_term_pattern,
)
from d810.mba.egraph_contracts import EgraphExtractionReceipt, EgraphSkipReason
from d810.mba.island_profile import (
    IslandBlocker,
    MbaIslandClass,
    MbaIslandProfile,
    profile_to_dict,
    profile_typed_term,
)
from d810.mba.semantic_canonicalization import (
    CANONICALIZER_SCHEMA_VERSION,
    CanonicalMbaTermView,
    canonicalize_mba_term,
)
from d810.mba.typed_term import (
    FIXED_SHIFT_OPERATIONS,
    SUPPORTED_OPERATIONS,
    TypedBvTerm,
)
from d810.mba.typed_term import (
    canonicalize_ac_term,
    fixed_shift_term,
    leaf_key_fingerprint,
    term_cost,
    term_fingerprint,
)
from d810.mba.certified_catalogue import (
    enroll_structural_rule,
    is_enrolled_structural_rule,
)


_VALID_DESTINATION_SIZES = frozenset({1, 2, 4, 8})


class NativeMbaUnsupportedCandidate(ValueError):
    """The native host cannot lower a candidate into the portable term model."""


class PortableContractReloaded(RuntimeError):
    """A provider module retained a stale class after a portable reload."""


def typed_term_identity_is_current() -> bool:
    """Return whether the API's typed-term class is the currently loaded one."""

    current_type = getattr(typed_term_module, "TypedBvTerm", None)
    return TypedBvTerm is current_type


def assert_current_typed_term_type(
    expected_type: type[TypedBvTerm] | None = None,
) -> None:
    """Reject stale typed-term classes before an extension crosses its API."""

    expected = TypedBvTerm if expected_type is None else expected_type
    current = getattr(typed_term_module, "TypedBvTerm", None)
    if expected is not current or not typed_term_identity_is_current():
        raise PortableContractReloaded(
            "typed-term class identity changed; reload the extension runtime"
        )


class CanonicalPatternComparisonBudgetExceeded(RuntimeError):
    """A canonical rule matcher exhausted its caller-supplied comparison cap."""


class CanonicalMbaRuleCatalogue(Protocol):
    """Narrow typed-term projection consumed by portable providers.

    Concrete native matcher classes stay in their owning backend.  The
    extension receives only this callable view, which is enough to construct
    bounded rewrite candidates without importing a backend implementation.
    """

    def canonical_applications(
        self,
        candidate: TypedBvTerm,
        *,
        comparison_budget: int = 256,
    ) -> tuple[tuple[CompiledMbaRule, TypedBvTerm, int], ...]: ...


def _is_validated_typed_term(term: object, *, width: int, active: set[int]) -> bool:
    """Validate a proof input without retaining solver or native state."""

    if type(term) is not TypedBvTerm or id(term) in active:
        return False
    active.add(id(term))
    try:
        if term.width != width or type(term.children) is not tuple:
            return False
        if term.operation is None:
            if term.children or term.shift_count is not None:
                return False
            if (term.value is None) == (term.leaf_key is None):
                return False
            if term.value is not None:
                return type(term.value) is int and 0 <= term.value < (1 << width)
            if type(term.leaf_key) is not tuple or not term.leaf_key:
                return False
            try:
                hash(term.leaf_key)
            except (TypeError, ValueError):
                return False
            return True
        if (
            type(term.operation) is not str
            or term.operation not in SUPPORTED_OPERATIONS
            or term.value is not None
            or term.leaf_key is not None
        ):
            return False
        expected_arity = (
            1
            if term.operation in {"bnot", "neg"} | FIXED_SHIFT_OPERATIONS
            else 2
        )
        if len(term.children) != expected_arity:
            return False
        if term.operation in FIXED_SHIFT_OPERATIONS:
            if type(term.shift_count) is not int or not 0 <= term.shift_count < width:
                return False
            if term.operation in {"rol", "ror"} and width not in {8, 16, 32, 64}:
                return False
        elif term.shift_count is not None:
            return False
        return all(
            _is_validated_typed_term(child, width=width, active=active)
            for child in term.children
        )
    finally:
        active.remove(id(term))


def _lower_typed_term(term: TypedBvTerm, *, variables: dict[tuple[object, ...], object], z3):
    if term.operation is None:
        if term.value is not None:
            return z3.BitVecVal(term.value, term.width)
        assert term.leaf_key is not None
        return variables.setdefault(
            term.leaf_key,
            z3.BitVec(f"mba_extension_leaf_{len(variables)}", term.width),
        )
    children = tuple(
        _lower_typed_term(child, variables=variables, z3=z3) for child in term.children
    )
    if term.operation == "shl":
        return children[0] << term.shift_count
    if term.operation == "lshr":
        return z3.LShR(children[0], term.shift_count)
    if term.operation == "rol":
        return z3.RotateLeft(children[0], term.shift_count)
    if term.operation == "ror":
        return z3.RotateRight(children[0], term.shift_count)
    if term.operation == "add":
        return children[0] + children[1]
    if term.operation == "sub":
        return children[0] - children[1]
    if term.operation == "mul":
        return children[0] * children[1]
    if term.operation == "and":
        return children[0] & children[1]
    if term.operation == "or":
        return children[0] | children[1]
    if term.operation == "xor":
        return children[0] ^ children[1]
    if term.operation == "neg":
        return -children[0]
    if term.operation == "bnot":
        return ~children[0]
    raise ValueError(f"unsupported typed-term operation: {term.operation}")


def prove_typed_term_equivalence(
    original: TypedBvTerm, replacement: TypedBvTerm
) -> bool:
    """Prove two portable fixed-width terms with a fresh bounded Z3 solver."""

    if type(original) is not TypedBvTerm or type(replacement) is not TypedBvTerm:
        return False
    if original.width != replacement.width or original.width not in {8, 16, 32, 64}:
        return False
    if not _is_validated_typed_term(original, width=original.width, active=set()):
        return False
    if not _is_validated_typed_term(replacement, width=original.width, active=set()):
        return False
    try:
        import z3
    except ImportError:
        return False
    variables: dict[tuple[object, ...], object] = {}
    left = _lower_typed_term(original, variables=variables, z3=z3)
    right = _lower_typed_term(replacement, variables=variables, z3=z3)
    solver = z3.Solver()
    solver.set(timeout=50)
    solver.add(left != right)
    return solver.check() == z3.unsat


def _copy_json_value(
    value: object, *, _active_containers: set[int] | None = None
) -> object:
    """Copy one JSON value into a plain, validated storage structure.

    This helper is intentionally private: the extension contract exposes the
    persistence protocol, not a second JSON implementation.  Keeping the
    value boundary here makes the host's storage implementation independent of
    caller-owned containers while remaining IDA-free.
    """

    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise TypeError("persistence values must contain finite JSON numbers")
        return value
    if isinstance(value, (Mapping, list)):
        active_containers = set() if _active_containers is None else _active_containers
        identity = id(value)
        if identity in active_containers:
            raise TypeError("persistence values must not contain cycles")
        active_containers.add(identity)
        try:
            if isinstance(value, Mapping):
                copied: dict[str, object] = {}
                for key, item in value.items():
                    if type(key) is not str:
                        raise TypeError("persistence mapping keys must be strings")
                    copied[key] = _copy_json_value(
                        item, _active_containers=active_containers
                    )
                return copied
            return [
                _copy_json_value(item, _active_containers=active_containers)
                for item in value
            ]
        finally:
            active_containers.remove(identity)
    raise TypeError("persistence value must be JSON-safe")


def _freeze_json_value(value: object) -> object:
    """Return a recursively immutable snapshot of a copied JSON value."""

    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_json_value(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_json_value(item) for item in value)
    if value is None or type(value) in {bool, int, float, str}:
        return value
    raise TypeError("persistence value must be JSON-safe")


@dataclass(frozen=True, slots=True)
class NativeMbaCandidate:
    """An immutable native candidate with canonical and source terms.

    ``term`` is the canonical term used by extension algorithms.  ``raw_term``
    retains source order and is optional only for callers that intentionally
    do not expose a source representation.  ``native_context`` is opaque by
    design: portable extensions can carry it through callbacks but cannot
    inspect or construct IDA values.
    """

    destination_size: int
    term: TypedBvTerm
    raw_term: TypedBvTerm | None
    profile: MbaIslandProfile
    native_context: object

    def __post_init__(self) -> None:
        if (
            type(self.destination_size) is not int
            or self.destination_size not in _VALID_DESTINATION_SIZES
        ):
            raise ValueError("destination_size must be one of 1, 2, 4, or 8 bytes")
        if not isinstance(self.term, TypedBvTerm):
            raise TypeError("term must be a TypedBvTerm")
        expected_width = self.destination_size * 8
        if self.term.width != expected_width:
            raise ValueError("term width must match destination_size")
        if self.raw_term is not None:
            if not isinstance(self.raw_term, TypedBvTerm):
                raise TypeError("raw_term must be a TypedBvTerm or None")
            if self.raw_term.width != expected_width:
                raise ValueError("raw_term width must match destination_size")
        if not isinstance(self.profile, MbaIslandProfile):
            raise TypeError("profile must be an MbaIslandProfile")
        if self.profile.width_bits != expected_width:
            raise ValueError("profile width must match destination_size")
        if self.native_context is None:
            raise TypeError("native_context must be a non-null opaque context")


@dataclass(frozen=True, slots=True)
class NativeMbaReconstruction:
    """Native replacement AST and instruction produced by the host facade."""

    replacement_ast: object
    replacement_instruction: object

    def __post_init__(self) -> None:
        if self.replacement_ast is None:
            raise TypeError("replacement_ast must be a native object")
        if self.replacement_instruction is None:
            raise TypeError("replacement_instruction must be a native object")


class EgraphPersistenceService(Protocol):
    """Namespace-scoped JSON persistence supplied by the native host."""

    def get_json(self, key: str) -> Mapping[str, object] | None: ...

    def put_json(self, key: str, value: Mapping[str, object]) -> None: ...

    def delete(self, key: str) -> None: ...

    def keys(self, *, prefix: str = "") -> tuple[str, ...]: ...


class NativeMbaHostServices(Protocol):
    """The sole extension-facing native MBA composition facade."""

    def capture_instruction(self, instruction: object) -> NativeMbaCandidate | None: ...

    def capture_ast(
        self, ast: object, *, destination_size: int
    ) -> NativeMbaCandidate: ...

    def prepare_cross_block(
        self,
        candidate: NativeMbaCandidate,
        *,
        block: object,
        instruction: object,
        use_constants: bool,
        use_def_use: bool,
    ) -> NativeMbaCandidate: ...

    def rebuild(
        self,
        candidate: NativeMbaCandidate,
        replacement: TypedBvTerm,
    ) -> NativeMbaReconstruction | None: ...

    def prove(
        self,
        candidate: NativeMbaCandidate,
        reconstruction: NativeMbaReconstruction,
        *,
        certificate: str | None,
        known_constants: object | None,
    ) -> bool: ...

    def profile_metadata(
        self, candidate: NativeMbaCandidate
    ) -> Mapping[str, object]: ...

    def persistence(self, namespace: str) -> EgraphPersistenceService: ...


__all__ = [
    "CANONICALIZER_SCHEMA_VERSION",
    "AcMatchStopReason",
    "CanonicalCompiledPattern",
    "CanonicalMbaTermView",
    "CanonicalMbaRuleCatalogue",
    "CanonicalPatternComparisonBudgetExceeded",
    "CanonicalPatternMalformed",
    "CanonicalPatternUnsupported",
    "CompiledMbaRule",
    "EgraphPersistenceService",
    "EgraphExtractionReceipt",
    "EgraphSkipReason",
    "IslandBlocker",
    "MbaIslandClass",
    "MbaIslandProfile",
    "NativeMbaCandidate",
    "NativeMbaHostServices",
    "NativeMbaReconstruction",
    "NativeMbaUnsupportedCandidate",
    "PortableContractReloaded",
    "TypedBvTerm",
    "assert_current_typed_term_type",
    "canonicalize_ac_term",
    "canonicalize_mba_term",
    "compile_canonical_pattern",
    "evaluate_frozen_constraints",
    "fixed_shift_term",
    "enroll_structural_rule",
    "is_enrolled_structural_rule",
    "leaf_key_fingerprint",
    "profile_to_dict",
    "profile_typed_term",
    "prove_typed_term_equivalence",
    "require_admitted_compiled_rules",
    "match_canonical_term_pattern",
    "term_cost",
    "term_fingerprint",
    "typed_term_identity_is_current",
]

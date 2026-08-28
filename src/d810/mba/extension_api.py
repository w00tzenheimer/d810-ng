"""Stable, IDA-free contracts for native MBA extensions.

The extension package must be able to depend on this module without loading
Hex-Rays, an optimizer manager, or a provider implementation.  Native objects
therefore cross this boundary only through the deliberately opaque
``native_context`` field.  The IDA-bound host owns that context and keeps it
immutable for the lifetime of one callback candidate.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from d810.core.typing import Protocol
from d810.core.function_execution_identity import MbaObservationContext
import d810.mba.typed_term as typed_term_module
from d810.mba.ac_matching import AcMatchStopReason
from d810.mba.certified_rule_compiler import (
    CompiledMbaRule,
    compiled_rules_for_families,
    require_admitted_compiled_rules,
)
from d810.mba.certified_catalogue import (
    build_certified_catalogue_snapshot,
    enroll_structural_rule,
    is_enrolled_structural_rule,
)
from d810.mba.canonical_pattern import (
    CanonicalCompiledPattern,
    CanonicalFixedBindings,
    CanonicalPatternMalformed,
    CanonicalPatternUnsupported,
    compile_canonical_pattern,
    evaluate_frozen_constraints,
    match_canonical_term_pattern,
)
from d810.mba.egraph_contracts import EgraphExtractionReceipt, EgraphSkipReason
from d810.mba.differential_report import egraph_receipt_to_outcome
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
from d810.mba.term_codec import (
    TERM_WIRE_SCHEMA_VERSION,
    typed_term_from_dict,
    typed_term_to_dict,
)
from d810.mba.subterm_atomization import (
    AtomizedMbaTerm,
    MbaAtomBinding,
    atomize_repeated_subterms,
)
from d810.mba.residual_corpus import (
    MbaResidualCorpus,
    MbaResidualGroup,
    MbaResidualObservation,
    MbaResidualSource,
    RESIDUAL_CORPUS_METADATA_KEY,
    RESIDUAL_CORPUS_SCHEMA_VERSION,
    source_identity,
)
from d810.mba.bounded_synthesis import (
    CERTIFICATION_WIDTHS,
    EnumeratedTerm,
    GrammarAllOnesOrigin,
    MbaCertification,
    MbaDiscoveryReceipt,
    MbaExhaustionReceipt,
    MbaSynthesisBudget,
    MbaSynthesisResult,
    ProofReceipt,
    certify_terms,
    deterministic_witnesses,
    enumerate_terms,
    generalize_terms,
    grammar_all_ones_origins,
    synthesize_residual,
)
from d810.mba.rule_proposal import (
    MbaRuleProposal,
    proposal_fingerprint,
    render_rule_source,
)
from d810.mba.performance_timing import (
    EMPTY_MBA_STAGE_TIMINGS,
    MbaStageTimer,
)
from d810.mba.provider_history import ProviderOutcomeHistory
from d810.mba.provider_outcome import (
    MbaProviderOutcome,
    ProviderOutcomeStatus,
)


D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY = "d810.mba.residual-observation.v1"
_RESIDUAL_WIDTHS = frozenset({8, 16, 32, 64})


def _residual_cost(value: object, *, field: str) -> tuple[int, int] | None:
    if value is None:
        return None
    if type(value) is not tuple or len(value) != 2:
        raise TypeError(f"{field} must be a two-item tuple or None")
    if any(type(item) is not int or item < 0 for item in value):
        raise ValueError(f"{field} must contain finite non-negative integers")
    return value


@dataclass(frozen=True, slots=True)
class MbaResidualRecord:
    """One terminal, non-applied provider observation owned by the host."""

    context: MbaObservationContext
    attempt_uuid: str
    raw_term: TypedBvTerm
    canonical_term: TypedBvTerm
    outcome: MbaProviderOutcome
    materialized: bool = False
    candidate_cost: tuple[int, int] | None = None
    replacement_cost: tuple[int, int] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.context, MbaObservationContext):
            raise TypeError("context must be an MbaObservationContext")
        if type(self.attempt_uuid) is not str:
            raise TypeError("attempt_uuid must be a canonical UUID string")
        from uuid import UUID

        try:
            normalized_uuid = str(UUID(self.attempt_uuid))
        except (TypeError, ValueError) as exc:
            raise ValueError("attempt_uuid must be a canonical UUID string") from exc
        if normalized_uuid != self.attempt_uuid:
            raise ValueError("attempt_uuid must use canonical UUID spelling")
        if (
            type(self.raw_term) is not TypedBvTerm
            or type(self.canonical_term) is not TypedBvTerm
        ):
            raise TypeError("raw_term and canonical_term must be TypedBvTerm values")
        if (
            self.raw_term.width not in _RESIDUAL_WIDTHS
            or self.canonical_term.width not in _RESIDUAL_WIDTHS
        ):
            raise ValueError("term width must be one of 8, 16, 32, or 64")
        if self.raw_term.width != self.canonical_term.width:
            raise ValueError("raw and canonical term widths must match")
        if not isinstance(self.outcome, MbaProviderOutcome):
            raise TypeError("outcome must be an MbaProviderOutcome")
        if type(self.materialized) is not bool:
            raise TypeError("materialized must be a bool")
        candidate_cost = _residual_cost(self.candidate_cost, field="candidate_cost")
        replacement_cost = _residual_cost(
            self.replacement_cost, field="replacement_cost"
        )
        if (
            candidate_cost is not None
            and self.outcome.input_cost is not None
            and candidate_cost != self.outcome.input_cost
        ):
            raise ValueError("candidate_cost must agree with outcome.input_cost")
        if (
            replacement_cost is not None
            and self.outcome.output_cost is not None
            and replacement_cost != self.outcome.output_cost
        ):
            raise ValueError("replacement_cost must agree with outcome.output_cost")
        object.__setattr__(self, "candidate_cost", candidate_cost)
        object.__setattr__(self, "replacement_cost", replacement_cost)


@dataclass(frozen=True, slots=True)
class MbaResidualReceipt:
    """Host sink result with a deliberately tiny stable status vocabulary."""

    status: str
    reason: str | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not str or self.status not in {
            "stored",
            "duplicate",
            "rejected",
        }:
            raise ValueError("status must be stored, duplicate, or rejected")
        if self.status == "rejected":
            if type(self.reason) is not str or not self.reason:
                raise ValueError("rejected receipts require a non-empty reason")
        elif self.reason is not None:
            raise ValueError("stored and duplicate receipts cannot have a reason")


class MbaResidualObservationSink(Protocol):
    """Host-owned persistence boundary exposed to external MBA providers."""

    def record(self, observation: MbaResidualRecord) -> MbaResidualReceipt: ...


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


def structural_rule_semantic_fingerprint(rule: object) -> str:
    """Build the canonical fingerprint for one structural rule's live fields."""

    family = getattr(rule, "family")
    source_name = getattr(rule, "source_name")
    width = getattr(rule, "width")
    direction = getattr(rule, "direction")
    count = getattr(rule, "count")
    if (
        type(family) is not str
        or not family
        or type(source_name) is not str
        or not source_name
        or type(width) is not int
        or type(direction) is not str
        or type(count) is not int
    ):
        raise ValueError("structural rule fingerprint fields are malformed")
    return "|".join(
        (
            family,
            source_name,
            str(width),
            direction,
            str(count),
            term_fingerprint(getattr(rule, "pattern")),
            term_fingerprint(getattr(rule, "replacement")),
        )
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
            1 if term.operation in {"bnot", "neg"} | FIXED_SHIFT_OPERATIONS else 2
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


def _lower_typed_term(
    term: TypedBvTerm, *, variables: dict[tuple[object, ...], object], z3
):
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
        canonical_term = canonicalize_mba_term(self.term).canonical_term
        if canonical_term != self.term:
            raise ValueError("term must be semantically canonical")
        if self.raw_term is not None:
            if not isinstance(self.raw_term, TypedBvTerm):
                raise TypeError("raw_term must be a TypedBvTerm or None")
            if self.raw_term.width != expected_width:
                raise ValueError("raw_term width must match destination_size")
            if canonicalize_mba_term(self.raw_term).canonical_term != self.term:
                raise ValueError("raw_term canonical form does not match term")
        if not isinstance(self.profile, MbaIslandProfile):
            raise TypeError("profile must be an MbaIslandProfile")
        if self.profile.width_bits != expected_width:
            raise ValueError("profile width must match destination_size")
        profile_term = self.raw_term if self.raw_term is not None else self.term
        expected_profile = profile_typed_term(profile_term)
        if (
            self.profile.operator_count != expected_profile.operator_count
            or self.profile.total_node_count != expected_profile.total_node_count
            or self.profile.distinct_leaf_count != expected_profile.distinct_leaf_count
            or self.profile.constant_count != expected_profile.constant_count
            or self.profile.operations != expected_profile.operations
            or self.profile.has_boolean != expected_profile.has_boolean
            or self.profile.has_arithmetic != expected_profile.has_arithmetic
            or self.profile.nonlinear_product_count
            != expected_profile.nonlinear_product_count
            or self.profile.island_class != expected_profile.island_class
            or self.profile.blockers != expected_profile.blockers
            or self.profile.fingerprint != term_fingerprint(self.term)
        ):
            raise ValueError("profile does not describe candidate term and raw_term")
        if self.native_context is None:
            raise TypeError("native_context must be a non-null opaque context")


@dataclass(frozen=True, slots=True)
class AtomizedNativeMbaCandidate:
    """Portable atomized view paired with one opaque native candidate."""

    candidate: NativeMbaCandidate
    view: AtomizedMbaTerm

    def __post_init__(self) -> None:
        if not isinstance(self.candidate, NativeMbaCandidate):
            raise TypeError("candidate must be a NativeMbaCandidate")
        if not isinstance(self.view, AtomizedMbaTerm):
            raise TypeError("view must be an AtomizedMbaTerm")
        self.view._validate_contract()
        expected_width = self.candidate.destination_size * 8
        if self.candidate.term.width != expected_width:
            raise ValueError("candidate width does not match destination_size")
        if self.view.original_term.width != expected_width:
            raise ValueError("atomization view width does not match candidate")
        expected_term = (
            self.candidate.raw_term
            if self.candidate.raw_term is not None
            else self.candidate.term
        )
        if self.view.original_term != expected_term:
            raise ValueError("atomization view does not match candidate source term")

    @property
    def term(self) -> TypedBvTerm:
        """Return the atomized portable term consumed by a provider."""

        return self.view.atomized_term

    def restore_replacement(self, replacement: TypedBvTerm) -> TypedBvTerm:
        """Restore a provider replacement while preserving native width."""

        if not isinstance(replacement, TypedBvTerm):
            raise TypeError("replacement must be a TypedBvTerm")
        expected_width = self.candidate.destination_size * 8
        if replacement.width != expected_width:
            raise ValueError("replacement width does not match candidate")
        restored = self.view.restore(replacement)
        if restored.width != expected_width:
            raise ValueError("restored replacement width does not match candidate")
        return restored


def atomize_native_candidate(
    candidate: NativeMbaCandidate,
    *,
    max_atoms: int = 4,
) -> AtomizedNativeMbaCandidate:
    """Build the shared portable atomization view for a native candidate."""

    if not isinstance(candidate, NativeMbaCandidate):
        raise TypeError("candidate must be a NativeMbaCandidate")
    # Canonical ``term`` remains the shared identity used by catalogues and
    # fingerprints.  Atomization consumes the immutable source view so AC
    # canonicalization cannot erase repeated raw evidence needed by a provider.
    source = candidate.raw_term if candidate.raw_term is not None else candidate.term
    view = atomize_repeated_subterms(source, max_atoms=max_atoms)
    return AtomizedNativeMbaCandidate(candidate=candidate, view=view)


def reconstruct_native_provider_result(
    host: NativeMbaHostServices,
    candidate: NativeMbaCandidate,
    provider: Callable[[TypedBvTerm], TypedBvTerm],
    *,
    proof_certificate: str | None = None,
    known_constants: object | None = None,
    proof_timeout_ms: int | None = None,
) -> NativeMbaReconstruction | None:
    """Return a provider replacement only after native proof succeeds.

    The provider sees only the atomized portable term.  Restoration and native
    reconstruction remain host-owned, and the caller receives no replacement
    to apply or swap until the final native equivalence proof accepts it.
    """

    if proof_timeout_ms is not None and (
        type(proof_timeout_ms) is not int or not 0 < proof_timeout_ms <= 250
    ):
        return None
    try:
        atomized = atomize_native_candidate(candidate)
        replacement = provider(atomized.term)
        restored = atomized.restore_replacement(replacement)
        reconstruction = host.rebuild(candidate, restored)
        if reconstruction is None:
            return None
        if not host.prove(
            candidate,
            reconstruction,
            certificate=proof_certificate,
            known_constants=known_constants,
            proof_timeout_ms=proof_timeout_ms,
        ):
            return None
        return reconstruction
    except Exception:
        return None


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

    def rebuild_ast(
        self,
        candidate: NativeMbaCandidate,
        replacement: TypedBvTerm,
    ) -> object | None: ...

    def prove_ast(
        self,
        candidate: NativeMbaCandidate,
        replacement_ast: object,
        *,
        certificate: str | None,
        known_constants: object | None,
    ) -> bool: ...

    def prove(
        self,
        candidate: NativeMbaCandidate,
        reconstruction: NativeMbaReconstruction,
        *,
        certificate: str | None,
        known_constants: object | None,
        proof_timeout_ms: int | None = None,
    ) -> bool: ...

    def profile_metadata(
        self, candidate: NativeMbaCandidate
    ) -> Mapping[str, object]: ...

    def persistence(self, namespace: str) -> EgraphPersistenceService: ...

    def maturities_for_names(self, names: object) -> tuple[int, ...]: ...


__all__ = [
    "D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY",
    "CANONICALIZER_SCHEMA_VERSION",
    "AcMatchStopReason",
    "CanonicalCompiledPattern",
    "CanonicalFixedBindings",
    "CanonicalMbaTermView",
    "CanonicalMbaRuleCatalogue",
    "CanonicalPatternComparisonBudgetExceeded",
    "CanonicalPatternMalformed",
    "CanonicalPatternUnsupported",
    "AtomizedMbaTerm",
    "AtomizedNativeMbaCandidate",
    "CompiledMbaRule",
    "compiled_rules_for_families",
    "build_certified_catalogue_snapshot",
    "EgraphPersistenceService",
    "EgraphExtractionReceipt",
    "EgraphSkipReason",
    "egraph_receipt_to_outcome",
    "IslandBlocker",
    "MbaIslandClass",
    "MbaIslandProfile",
    "NativeMbaCandidate",
    "NativeMbaHostServices",
    "NativeMbaReconstruction",
    "NativeMbaUnsupportedCandidate",
    "MbaAtomBinding",
    "MbaProviderOutcome",
    "MbaResidualObservationSink",
    "MbaResidualReceipt",
    "MbaResidualRecord",
    "ProviderOutcomeHistory",
    "ProviderOutcomeStatus",
    "EMPTY_MBA_STAGE_TIMINGS",
    "MbaStageTimer",
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
    "structural_rule_semantic_fingerprint",
    "term_cost",
    "term_fingerprint",
    "TERM_WIRE_SCHEMA_VERSION",
    "typed_term_from_dict",
    "typed_term_to_dict",
    "atomize_native_candidate",
    "reconstruct_native_provider_result",
    "atomize_repeated_subterms",
    "typed_term_identity_is_current",
    "MbaResidualCorpus",
    "MbaResidualGroup",
    "MbaResidualObservation",
    "MbaResidualSource",
    "RESIDUAL_CORPUS_METADATA_KEY",
    "RESIDUAL_CORPUS_SCHEMA_VERSION",
    "source_identity",
    "CERTIFICATION_WIDTHS",
    "EnumeratedTerm",
    "GrammarAllOnesOrigin",
    "MbaCertification",
    "MbaDiscoveryReceipt",
    "MbaExhaustionReceipt",
    "MbaSynthesisBudget",
    "MbaSynthesisResult",
    "ProofReceipt",
    "certify_terms",
    "deterministic_witnesses",
    "enumerate_terms",
    "generalize_terms",
    "grammar_all_ones_origins",
    "synthesize_residual",
    "MbaRuleProposal",
    "proposal_fingerprint",
    "render_rule_source",
]

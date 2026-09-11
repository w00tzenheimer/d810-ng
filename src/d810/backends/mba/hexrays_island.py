"""Native Hex-Rays boundary for one fixed-width MBA expression island.

This module is deliberately the only place where portable MBA terms meet live
Hex-Rays AST objects.  It preserves live leaf identity for reconstruction and
classifies unsafe native shapes without allowing them into an untyped term.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from d810.core.typing import Any
from d810.backends.mba.native_mba_term_view import semantic_native_leaf_key

from d810.mba.island_profile import (
    IslandBlocker,
    MbaIslandProfile,
    profile_typed_term,
)
from d810.mba.semantic_canonicalization import (
    CanonicalMbaTermView,
    canonicalize_mba_term,
)
from d810.mba.typed_term import (
    AC_OPERATIONS,
    TypedBvTerm,
    _leaf_key_fingerprint,
    term_fingerprint,
)
from d810.mba.typed_term import fixed_shift_term


_VALID_DESTINATION_SIZES = frozenset({1, 2, 4, 8})
_UNARY_OPERATIONS = frozenset({"bnot", "neg"})
_ROTATE_HELPERS = {
    "__ROL1__": ("rol", 1),
    "__ROL2__": ("rol", 2),
    "__ROL4__": ("rol", 4),
    "__ROL8__": ("rol", 8),
    "__ROR1__": ("ror", 1),
    "__ROR2__": ("ror", 2),
    "__ROR4__": ("ror", 4),
    "__ROR8__": ("ror", 8),
}


@dataclass(frozen=True)
class HexRaysIslandLowering:
    """Portable island facts paired with the original native identity objects."""

    term: TypedBvTerm | None
    raw_term: TypedBvTerm | None
    profile: MbaIslandProfile
    leafs: Mapping[tuple[object, ...], Any]
    native_nodes_by_path: Mapping[tuple[int, ...], Any]
    raw_native_nodes_by_path: Mapping[tuple[int, ...], Any]
    canonical_view: CanonicalMbaTermView | None = None


@dataclass(frozen=True)
class _NativeAstRuntime:
    AstNode: type[Any]
    AstLeaf: type[Any]
    AstConstant: type[Any]
    AstProxy: type[Any]
    operation_by_opcode: Mapping[int, str]
    opcode_by_operation: Mapping[str, int]
    blocker_by_opcode: Mapping[int, IslandBlocker]
    get_mop_key: Any
    call_opcode: int | None = None
    xdu_opcode: int | None = None
    setnz_opcode: int | None = None
    ldx_opcode: int | None = None
    mop_z: int | None = None
    mop_n: int | None = None
    mop_r: int | None = None
    mop_d: int | None = None
    mop_stack: int | None = None


def _load_native_runtime() -> _NativeAstRuntime:
    ida_hexrays = importlib.import_module("ida_hexrays")
    ast_module = importlib.import_module("d810.hexrays.expr.ast")
    opcode_by_operation = {
        "add": ida_hexrays.m_add,
        "and": ida_hexrays.m_and,
        "bnot": ida_hexrays.m_bnot,
        "mul": ida_hexrays.m_mul,
        "neg": ida_hexrays.m_neg,
        "or": ida_hexrays.m_or,
        "sub": ida_hexrays.m_sub,
        "xor": ida_hexrays.m_xor,
        "shl": ida_hexrays.m_shl,
        "lshr": ida_hexrays.m_shr,
    }
    blockers: dict[int, IslandBlocker] = {}
    for name, blocker in (
        ("m_xdu", IslandBlocker.CAST),
        ("m_xds", IslandBlocker.CAST),
        ("m_low", IslandBlocker.CAST),
        ("m_high", IslandBlocker.CAST),
        ("m_sar", IslandBlocker.AMBIGUOUS_SHIFT),
        ("m_ldx", IslandBlocker.LOAD),
        ("m_call", IslandBlocker.CALL),
        ("m_icall", IslandBlocker.CALL),
    ):
        opcode = getattr(ida_hexrays, name, None)
        if type(opcode) is int:
            blockers[opcode] = blocker
    for name in (
        "m_jcnd",
        "m_jz",
        "m_jnz",
        "m_setz",
        "m_setnz",
        "m_sets",
        "m_setns",
        "m_setb",
        "m_setae",
        "m_setl",
        "m_setge",
        "m_setbe",
        "m_seta",
        "m_setg",
        "m_setle",
        "m_seto",
        "m_setno",
        "m_setp",
        "m_setnp",
        "m_jb",
        "m_jae",
        "m_jbe",
        "m_ja",
        "m_jl",
        "m_jge",
        "m_jg",
        "m_jle",
    ):
        opcode = getattr(ida_hexrays, name, None)
        if type(opcode) is int:
            blockers[opcode] = IslandBlocker.PREDICATE
    return _NativeAstRuntime(
        AstNode=ast_module.AstNode,
        AstLeaf=ast_module.AstLeaf,
        AstConstant=ast_module.AstConstant,
        AstProxy=ast_module.AstProxy,
        operation_by_opcode={
            opcode: name for name, opcode in opcode_by_operation.items()
        },
        opcode_by_operation=opcode_by_operation,
        blocker_by_opcode=MappingProxyType(blockers),
        get_mop_key=ast_module.get_mop_key,
        call_opcode=getattr(ida_hexrays, "m_call", None),
        xdu_opcode=getattr(ida_hexrays, "m_xdu", None),
        setnz_opcode=getattr(ida_hexrays, "m_setnz", None),
        ldx_opcode=getattr(ida_hexrays, "m_ldx", None),
        mop_z=getattr(ida_hexrays, "mop_z", None),
        mop_n=getattr(ida_hexrays, "mop_n", None),
        mop_r=getattr(ida_hexrays, "mop_r", None),
        mop_d=getattr(ida_hexrays, "mop_d", None),
        mop_stack=getattr(ida_hexrays, "mop_S", None),
    )


def _unwrap_runtime_ast_node(ast: Any, runtime: _NativeAstRuntime) -> Any | None:
    current = ast
    seen: set[int] = set()
    for _ in range(4):
        if type(current) is not runtime.AstProxy:
            return (
                current
                if isinstance(current, (runtime.AstNode, runtime.AstLeaf))
                else None
            )
        identity = id(current)
        if identity in seen:
            return None
        seen.add(identity)
        try:
            current = object.__getattribute__(current, "_target")
        except (AttributeError, TypeError):
            return None
    return None


def unwrap_hexrays_island_ast(ast: Any) -> Any | None:
    """Return one exact active-runtime node/leaf behind bounded proxies.

    Consumers that need to make a disposable native-AST clone use this instead
    of duplicating proxy traversal or trusting module/name lookalikes.
    """

    try:
        return _unwrap_runtime_ast_node(ast, _load_native_runtime())
    except Exception:
        return None


def _native_width_witnesses(ast: Any) -> tuple[int, ...] | None:
    witnesses: list[int] = []
    for attribute in ("size", "expected_size", "dest_size"):
        try:
            value = getattr(ast, attribute, None)
        except Exception:
            return None
        if value is None:
            continue
        if type(value) is not int or value < 0:
            return None
        if value:
            witnesses.append(value)
    return tuple(witnesses)


def _native_width_matches(
    ast: Any, destination_size: int, *, require_destination_witness: bool = False
) -> bool:
    witnesses = _native_width_witnesses(ast)
    if witnesses is None or not witnesses:
        return False
    if require_destination_witness:
        destination_witness = getattr(ast, "dest_size", None)
        if type(destination_witness) is not int or destination_witness == 0:
            return False
    return all(witness == destination_size for witness in witnesses)


def _live_leaf_key(leaf: Any, runtime: _NativeAstRuntime) -> tuple[object, ...] | None:
    mop = getattr(leaf, "mop", None)
    if mop is None:
        return None
    try:
        # Direct-native matching and delayed AST lowering must agree even when
        # the active Python/Cython AST cache uses a different tuple encoding.
        # The direct matcher admits only these exact native location leaves;
        # retain the runtime key as a fail-closed fallback for other AST paths.
        try:
            raw_key = semantic_native_leaf_key(mop)
        except (ImportError, ValueError):
            raw_key = runtime.get_mop_key(mop)
        key = tuple(raw_key)
        hash(key)
        live_key = ("mop", *key)
        _leaf_key_fingerprint(live_key)
    except Exception:
        return None
    return live_key


def _freeze_widened_boolean_identity(value: Any) -> tuple[object, ...]:
    """Freeze exact raw POD without trusting a digest or object identity."""

    if value is None:
        return ("none",)
    if type(value) is bool:
        return ("bool", value)
    if type(value) is int:
        return ("int", value)
    if type(value) is str:
        return ("str", value)
    if type(value) is bytes:
        return ("bytes", value)
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ValueError("raw identity keys must be strings")
        return (
            "dict",
            tuple(
                (key, _freeze_widened_boolean_identity(value[key]))
                for key in sorted(value)
            ),
        )
    if type(value) is list:
        return (
            "list",
            tuple(_freeze_widened_boolean_identity(item) for item in value),
        )
    if type(value) is tuple:
        return (
            "tuple",
            tuple(_freeze_widened_boolean_identity(item) for item in value),
        )
    raise ValueError("raw identity contains a non-POD value")


def _owned_raw_mop_identity(mop: Any, *, require_snapshot: bool = False):
    """Return full POD from an owned snapshot/copy, never a borrowed mop."""

    snapshot_module = importlib.import_module("d810.hexrays.ir.mop_snapshot")
    MopSnapshot = snapshot_module.MopSnapshot
    raw_mop_identity = snapshot_module.raw_mop_identity

    if isinstance(mop, MopSnapshot):
        if require_snapshot and getattr(mop, "owned_mop", None) is None:
            return None
        owned = mop.to_mop()
    else:
        if require_snapshot:
            return None
        ida_hexrays = importlib.import_module("ida_hexrays")
        if not isinstance(mop, ida_hexrays.mop_t):
            return None
        owned = ida_hexrays.mop_t()
        owned.assign(mop)
    return raw_mop_identity(owned)


def _widened_boolean_input_supported(
    identity: dict[str, Any], runtime: _NativeAstRuntime
) -> bool:
    """Recognize the register or captured stack-load predicate input.

    This is not a general load-purity rule. The caller retains the entire
    widened predicate's raw identity and emits its original owned subtree.
    """

    if identity.get("type") == runtime.mop_r:
        return True
    if (
        runtime.ldx_opcode is None
        or runtime.mop_stack is None
        or identity.get("type") != runtime.mop_d
        or identity.get("oprops") != 0
    ):
        return False
    instruction = identity.get("instruction")
    if (
        type(instruction) is not dict
        or instruction.get("opcode") != runtime.ldx_opcode
        or instruction.get("iprops") != 0
    ):
        return False
    for field, kind, size in (
        ("l", runtime.mop_r, 2),
        ("r", runtime.mop_stack, 8),
        ("d", runtime.mop_z, 4),
    ):
        operand = instruction.get(field)
        if (
            type(operand) is not dict
            or operand.get("type") != kind
            or operand.get("size") != size
            or operand.get("oprops") != 0
        ):
            return False
    return True


def _exact_widened_boolean_leaf_key(
    node: Any,
    runtime: _NativeAstRuntime,
    *,
    destination_size: int,
) -> tuple[object, ...] | None:
    """Admit an exact register/load-backed xdu.4(setnz.1(x.4, #0.4))."""

    if (
        destination_size != 4
        or getattr(node, "opcode", None) != runtime.xdu_opcode
        or not _native_width_matches(
            node, destination_size, require_destination_witness=True
        )
        or getattr(node, "right", None) is not None
    ):
        return None
    comparison = getattr(node, "left", None)
    if (
        not isinstance(comparison, runtime.AstNode)
        or getattr(comparison, "opcode", None) != runtime.setnz_opcode
        or not _native_width_matches(comparison, 1, require_destination_witness=True)
    ):
        return None
    register = getattr(comparison, "left", None)
    zero = getattr(comparison, "right", None)
    if (
        not isinstance(register, runtime.AstLeaf)
        or isinstance(register, runtime.AstConstant)
        or not _native_width_matches(register, destination_size)
        or not isinstance(zero, runtime.AstConstant)
        or not _native_width_matches(zero, destination_size)
        or getattr(zero, "value", None) != 0
    ):
        return None

    root_identity = _owned_raw_mop_identity(
        getattr(node, "mop", None), require_snapshot=True
    )
    comparison_identity = _owned_raw_mop_identity(getattr(comparison, "mop", None))
    register_identity = _owned_raw_mop_identity(getattr(register, "mop", None))
    zero_identity = _owned_raw_mop_identity(getattr(zero, "mop", None))
    if not all(
        type(identity) is dict
        for identity in (
            root_identity,
            comparison_identity,
            register_identity,
            zero_identity,
        )
    ):
        return None

    instruction = root_identity.get("instruction")
    if (
        root_identity.get("type") != runtime.mop_d
        or root_identity.get("size") != destination_size
        or type(instruction) is not dict
        or instruction.get("opcode") != runtime.xdu_opcode
        or instruction.get("l") != comparison_identity
        or instruction.get("r", {}).get("type") != runtime.mop_z
        or instruction.get("d", {}).get("type") != runtime.mop_z
        or instruction.get("d", {}).get("size") != destination_size
    ):
        return None
    comparison_instruction = comparison_identity.get("instruction")
    if (
        comparison_identity.get("type") != runtime.mop_d
        or comparison_identity.get("size") != 1
        or type(comparison_instruction) is not dict
        or comparison_instruction.get("opcode") != runtime.setnz_opcode
        or comparison_instruction.get("l") != register_identity
        or comparison_instruction.get("r") != zero_identity
        or comparison_instruction.get("d", {}).get("type") != runtime.mop_z
        or comparison_instruction.get("d", {}).get("size") != 1
        or not _widened_boolean_input_supported(register_identity, runtime)
        or register_identity.get("size") != destination_size
        or zero_identity.get("type") != runtime.mop_n
        or zero_identity.get("size") != destination_size
        or zero_identity.get("value") != 0
    ):
        return None

    key = (
        "native-widened-boolean-v1",
        _freeze_widened_boolean_identity(root_identity),
    )
    hash(key)
    _leaf_key_fingerprint(key)
    return key


def _unsupported_profile(
    destination_size: int,
    blockers: set[IslandBlocker],
) -> MbaIslandProfile:
    width = max(1, destination_size) * 8
    witness = TypedBvTerm(operation=None, width=width, value=0)
    return profile_typed_term(witness, blockers=blockers)


def _canonical_native_nodes_by_path(
    raw_term: TypedBvTerm,
    canonical_term: TypedBvTerm,
    raw_nodes_by_path: Mapping[tuple[int, ...], Any],
) -> Mapping[tuple[int, ...], Any]:
    """Retain only exact source nodes at their canonical portable paths.

    AC flattening can create a binary grouping which never existed in the
    native input. Such synthetic portable paths deliberately have no native
    node entry. Terminals and structurally unchanged native subtrees retain
    their exact original identities, which makes future binding fail closed
    rather than resolve a canonical path to the wrong subtree.
    """

    correspondence = _direct_permutation_correspondence(raw_term, canonical_term)
    if correspondence is not None:
        matched = {
            canonical_path: raw_nodes_by_path[raw_path]
            for canonical_path, raw_path in correspondence.path_pairs
            if raw_path in raw_nodes_by_path
        }
        return MappingProxyType(matched)

    raw_occurrences: dict[TypedBvTerm, list[Any]] = {}

    def collect_raw(term: TypedBvTerm, path: tuple[int, ...]) -> None:
        node = raw_nodes_by_path.get(path)
        if node is not None:
            raw_occurrences.setdefault(term, []).append(node)
        for index, child in enumerate(term.children):
            collect_raw(child, path + (index,))

    collect_raw(raw_term, ())
    matched: dict[tuple[int, ...], Any] = {}

    def collect_canonical(term: TypedBvTerm, path: tuple[int, ...]) -> None:
        candidates = raw_occurrences.get(term)
        if candidates:
            matched[path] = candidates.pop(0)
        for index, child in enumerate(term.children):
            collect_canonical(child, path + (index,))

    collect_canonical(canonical_term, ())
    return MappingProxyType(matched)


@dataclass(frozen=True, slots=True)
class _DirectPermutationCorrespondence:
    """One unique ancestry-preserving raw/canonical path bijection."""

    path_pairs: tuple[tuple[tuple[int, ...], tuple[int, ...]], ...]
    pair_evaluations: int
    path_pair_allocations: int


def _direct_permutation_correspondence(
    raw_term: TypedBvTerm,
    canonical_term: TypedBvTerm,
) -> _DirectPermutationCorrespondence | None:
    """Match trees differing only by unique direct commutative child swaps.

    The memoized result contains relative canonical/raw path pairs. Associative
    regrouping and every semantic rewrite fail closed; callers retain the
    existing exact-subtree mapper for those cases.
    """

    memo: dict[
        tuple[int, int],
        tuple[tuple[tuple[int, ...], tuple[int, ...]], ...] | None,
    ] = {}
    pair_evaluations = 0
    path_pair_allocations = 0

    def node_count(root: TypedBvTerm) -> int:
        count = 0
        pending = [root]
        while pending:
            current = pending.pop()
            count += 1
            pending.extend(current.children)
        return count

    # Identity keys avoid recursively hashing immutable terms at every state.
    # Retaining both roots for this call keeps those occurrence identities live.
    raw_node_count = node_count(raw_term)
    canonical_node_count = node_count(canonical_term)
    pair_budget = raw_node_count * canonical_node_count
    allocation_budget = 4 * pair_budget

    def prefixed(
        pairs: tuple[tuple[tuple[int, ...], tuple[int, ...]], ...],
        canonical_index: int,
        raw_index: int,
    ) -> tuple[tuple[tuple[int, ...], tuple[int, ...]], ...]:
        nonlocal path_pair_allocations
        path_pair_allocations += len(pairs)
        if path_pair_allocations > allocation_budget:
            raise _CorrespondenceBudgetExceeded
        return tuple(
            (
                (canonical_index,) + canonical_path,
                (raw_index,) + raw_path,
            )
            for canonical_path, raw_path in pairs
        )

    def match(
        raw: TypedBvTerm,
        canonical: TypedBvTerm,
    ) -> tuple[tuple[tuple[int, ...], tuple[int, ...]], ...] | None:
        nonlocal pair_evaluations, path_pair_allocations
        key = (id(raw), id(canonical))
        if key in memo:
            return memo[key]
        pair_evaluations += 1
        if pair_evaluations > pair_budget:
            raise _CorrespondenceBudgetExceeded
        if (
            raw.operation != canonical.operation
            or raw.width != canonical.width
            or raw.value != canonical.value
            or raw.leaf_key != canonical.leaf_key
            or raw.shift_count != canonical.shift_count
            or len(raw.children) != len(canonical.children)
        ):
            memo[key] = None
            return None
        if not raw.children:
            result = (((), ()),)
            memo[key] = result
            return result

        pairings = tuple((index, index) for index in range(len(raw.children)))
        alternatives = (pairings,)
        if raw.operation in AC_OPERATIONS and len(raw.children) == 2:
            alternatives = (pairings, ((0, 1), (1, 0)))

        successes = []
        for pairing in alternatives:
            combined: list[tuple[tuple[int, ...], tuple[int, ...]]] = [((), ())]
            path_pair_allocations += 1
            if path_pair_allocations > allocation_budget:
                raise _CorrespondenceBudgetExceeded
            for canonical_index, raw_index in pairing:
                child_pairs = match(
                    raw.children[raw_index], canonical.children[canonical_index]
                )
                if child_pairs is None:
                    break
                combined.extend(prefixed(child_pairs, canonical_index, raw_index))
            else:
                successes.append(tuple(combined))
        result = successes[0] if len(successes) == 1 else None
        memo[key] = result
        return result

    try:
        pairs = match(raw_term, canonical_term)
    except _CorrespondenceBudgetExceeded:
        return None
    if pairs is None:
        return None
    return _DirectPermutationCorrespondence(
        pairs, pair_evaluations, path_pair_allocations
    )


class _CorrespondenceBudgetExceeded(Exception):
    """Internal signal to fall back when direct correspondence exceeds its bound."""


def _ast_shift_count(
    node: Any,
    *,
    width: int,
    runtime: _NativeAstRuntime,
) -> tuple[int | None, IslandBlocker]:
    """Read a one-byte literal count without making it a semantic child."""

    if isinstance(node, runtime.AstConstant):
        if not _native_width_matches(node, 1):
            return None, IslandBlocker.AMBIGUOUS_SHIFT
        value = getattr(node, "value", None)
        if type(value) is not int or not 0 <= value < width:
            return None, IslandBlocker.AMBIGUOUS_SHIFT
        return value, IslandBlocker.AMBIGUOUS_SHIFT
    if isinstance(node, runtime.AstNode):
        blocker = runtime.blocker_by_opcode.get(
            getattr(node, "opcode", None), IslandBlocker.AMBIGUOUS_SHIFT
        )
        if blocker is IslandBlocker.CAST:
            return None, IslandBlocker.CAST
    return None, IslandBlocker.AMBIGUOUS_SHIFT


def _rotate_helper(node: Any, runtime: _NativeAstRuntime) -> tuple[str, int] | None:
    helper = getattr(node, "func_name", None)
    if type(helper) is not str:
        return None
    return _ROTATE_HELPERS.get(helper)


def lower_hexrays_island(
    ast: Any,
    *,
    destination_size: int,
) -> HexRaysIslandLowering:
    """Lower one exact, same-width native tree or return a blocker profile.

    The input tree is never canonicalized or mutated.  Canonicalization occurs
    only on the portable term, while ``native_nodes_by_path`` retains the
    untouched native tree for future exact binding and reconstruction.
    """

    if (
        type(destination_size) is not int
        or destination_size not in _VALID_DESTINATION_SIZES
    ):
        return HexRaysIslandLowering(
            term=None,
            raw_term=None,
            profile=_unsupported_profile(1, {IslandBlocker.MIXED_WIDTH}),
            leafs=MappingProxyType({}),
            native_nodes_by_path=MappingProxyType({}),
            raw_native_nodes_by_path=MappingProxyType({}),
            canonical_view=None,
        )
    try:
        runtime = _load_native_runtime()
        root = _unwrap_runtime_ast_node(ast, runtime)
        if root is None:
            return HexRaysIslandLowering(
                term=None,
                raw_term=None,
                profile=_unsupported_profile(
                    destination_size, {IslandBlocker.UNSUPPORTED_OPCODE}
                ),
                leafs=MappingProxyType({}),
                native_nodes_by_path=MappingProxyType({}),
                raw_native_nodes_by_path=MappingProxyType({}),
                canonical_view=None,
            )
        blockers: set[IslandBlocker] = set()
        leafs: dict[tuple[object, ...], Any] = {}
        nodes: dict[tuple[int, ...], Any] = {}

        def lower(node: Any, path: tuple[int, ...]) -> TypedBvTerm | None:
            if isinstance(node, runtime.AstConstant):
                nodes[path] = node
                if not _native_width_matches(node, destination_size):
                    blockers.add(IslandBlocker.MIXED_WIDTH)
                    return None
                value = getattr(node, "value", None)
                if type(value) is not int:
                    blockers.add(IslandBlocker.UNSUPPORTED_OPCODE)
                    return None
                return TypedBvTerm(None, destination_size * 8, value=value)
            if isinstance(node, runtime.AstLeaf):
                nodes[path] = node
                if not _native_width_matches(node, destination_size):
                    blockers.add(IslandBlocker.MIXED_WIDTH)
                    return None
                key = _live_leaf_key(node, runtime)
                if key is None:
                    blockers.add(IslandBlocker.UNSUPPORTED_OPCODE)
                    return None
                leafs.setdefault(key, node)
                return TypedBvTerm(None, destination_size * 8, leaf_key=key)
            if not isinstance(node, runtime.AstNode):
                blockers.add(IslandBlocker.UNSUPPORTED_OPCODE)
                return None
            nodes[path] = node
            if not _native_width_matches(
                node, destination_size, require_destination_witness=True
            ):
                blockers.add(IslandBlocker.MIXED_WIDTH)
                return None
            opcode = getattr(node, "opcode", None)
            if opcode == runtime.xdu_opcode:
                widened_boolean_key = _exact_widened_boolean_leaf_key(
                    node,
                    runtime,
                    destination_size=destination_size,
                )
                if widened_boolean_key is not None:
                    # The actual fallback consumer reconstructs this binding
                    # from its exact native path.  Deliberately omit the
                    # compound node from ``leafs`` so the generic island
                    # rebuilder keeps refusing it instead of treating an
                    # AstNode as a scalar AstLeaf.
                    return TypedBvTerm(
                        None,
                        destination_size * 8,
                        leaf_key=widened_boolean_key,
                    )
            operation = runtime.operation_by_opcode.get(opcode)
            if opcode == getattr(runtime, "call_opcode", None):
                helper = _rotate_helper(node, runtime)
                if helper is None:
                    blockers.add(IslandBlocker.CALL)
                    return None
                helper_operation, helper_size = helper
                if helper_size != destination_size:
                    blockers.add(IslandBlocker.MIXED_WIDTH)
                    return None
                value = getattr(node, "left", None)
                count = getattr(node, "right", None)
                if value is None or count is None:
                    blockers.add(IslandBlocker.CALL)
                    return None
                lowered_value = lower(value, path + (0,))
                nodes[path + (1,)] = count
                if lowered_value is None:
                    return None
                literal_count, blocker = _ast_shift_count(
                    count, width=destination_size * 8, runtime=runtime
                )
                if literal_count is None:
                    blockers.add(blocker)
                    return None
                return fixed_shift_term(
                    helper_operation,
                    destination_size * 8,
                    lowered_value,
                    literal_count,
                )
            if operation is None:
                blockers.add(
                    getattr(runtime, "blocker_by_opcode", {}).get(
                        opcode, IslandBlocker.UNSUPPORTED_OPCODE
                    )
                )
                return None
            left = getattr(node, "left", None)
            if left is None:
                blockers.add(IslandBlocker.UNSUPPORTED_OPCODE)
                return None
            lowered_left = lower(left, path + (0,))
            if lowered_left is None:
                return None
            if operation in {"shl", "lshr"}:
                right = getattr(node, "right", None)
                if right is None:
                    blockers.add(IslandBlocker.AMBIGUOUS_SHIFT)
                    return None
                nodes[path + (1,)] = right
                literal_count, blocker = _ast_shift_count(
                    right,
                    width=destination_size * 8,
                    runtime=runtime,
                )
                if literal_count is None:
                    blockers.add(blocker)
                    return None
                return fixed_shift_term(
                    operation,
                    destination_size * 8,
                    lowered_left,
                    literal_count,
                )
            right = getattr(node, "right", None)
            if operation in _UNARY_OPERATIONS:
                if right is not None:
                    blockers.add(IslandBlocker.UNSUPPORTED_OPCODE)
                    return None
                return TypedBvTerm(
                    operation, destination_size * 8, children=(lowered_left,)
                )
            if right is None:
                blockers.add(IslandBlocker.UNSUPPORTED_OPCODE)
                return None
            lowered_right = lower(right, path + (1,))
            if lowered_right is None or lowered_right.width != lowered_left.width:
                blockers.add(IslandBlocker.MIXED_WIDTH)
                return None
            return TypedBvTerm(
                operation, destination_size * 8, children=(lowered_left, lowered_right)
            )

        raw_term = lower(root, ())
        if raw_term is None or blockers:
            return HexRaysIslandLowering(
                term=None,
                raw_term=None,
                profile=_unsupported_profile(
                    destination_size, blockers or {IslandBlocker.UNSUPPORTED_OPCODE}
                ),
                leafs=MappingProxyType(dict(leafs)),
                native_nodes_by_path=MappingProxyType(dict(nodes)),
                raw_native_nodes_by_path=MappingProxyType(dict(nodes)),
                canonical_view=None,
            )
        canonical_view = canonicalize_mba_term(raw_term)
        normalized = canonical_view.canonical_term
        raw_profile = profile_typed_term(raw_term)
        profile = replace(
            raw_profile,
            fingerprint=term_fingerprint(canonical_view.canonical_term),
        )
        return HexRaysIslandLowering(
            term=normalized,
            raw_term=raw_term,
            profile=profile,
            leafs=MappingProxyType(dict(leafs)),
            native_nodes_by_path=_canonical_native_nodes_by_path(
                raw_term,
                normalized,
                nodes,
            ),
            raw_native_nodes_by_path=MappingProxyType(dict(nodes)),
            canonical_view=canonical_view,
        )
    except Exception:
        return HexRaysIslandLowering(
            term=None,
            raw_term=None,
            profile=_unsupported_profile(
                destination_size, {IslandBlocker.UNSUPPORTED_OPCODE}
            ),
            leafs=MappingProxyType({}),
            native_nodes_by_path=MappingProxyType({}),
            raw_native_nodes_by_path=MappingProxyType({}),
            canonical_view=None,
        )


def rebuild_hexrays_island(
    term: TypedBvTerm,
    *,
    lowering: HexRaysIslandLowering,
    destination_size: int,
    block: Any | None = None,
    destination: Any | None = None,
) -> Any | None:
    """Rebuild a native AST exclusively from the lowerer's preserved leafs."""

    if (
        type(destination_size) is not int
        or destination_size not in _VALID_DESTINATION_SIZES
        or lowering.term is None
        or term.width != destination_size * 8
    ):
        return None
    try:
        runtime = _load_native_runtime()

        def rebuild(node: TypedBvTerm, *, top_level: bool = False) -> Any | None:
            if node.width != destination_size * 8:
                return None
            if node.operation is None and node.value is not None:
                constant = runtime.AstConstant(
                    str(node.value), node.value, destination_size
                )
                constant.dest_size = destination_size
                return constant
            if node.operation is None:
                assert node.leaf_key is not None
                leaf = lowering.leafs.get(node.leaf_key)
                if (
                    not isinstance(leaf, runtime.AstLeaf)
                    or isinstance(leaf, runtime.AstConstant)
                    or not _native_width_matches(leaf, destination_size)
                ):
                    return None
                current_key = _live_leaf_key(leaf, runtime)
                if current_key is None or _leaf_key_fingerprint(
                    current_key
                ) != _leaf_key_fingerprint(node.leaf_key):
                    return None
                return leaf.clone()
            if node.operation in {"rol", "ror"}:
                if not top_level or block is None or destination is None:
                    return None
                from d810.backends.mba.native_rotate_helper import (
                    materialize_rotate_term,
                )

                return materialize_rotate_term(
                    node,
                    lowering=lowering,
                    block=block,
                    destination=destination,
                )
            if node.operation in {"shl", "lshr"}:
                if (
                    type(node.shift_count) is not int
                    or not 0 <= node.shift_count < node.width
                ):
                    return None
                child = rebuild(node.children[0])
                if child is None:
                    return None
                count = runtime.AstConstant(str(node.shift_count), node.shift_count, 1)
                count.dest_size = 1
                native = runtime.AstNode(
                    runtime.opcode_by_operation[node.operation], child, count
                )
                native.dest_size = destination_size
                return native
            opcode = runtime.opcode_by_operation.get(node.operation)
            if opcode is None:
                return None
            children = tuple(rebuild(child) for child in node.children)
            if any(child is None for child in children):
                return None
            native = runtime.AstNode(
                opcode, children[0], children[1] if len(children) == 2 else None
            )
            native.dest_size = destination_size
            return native

        rebuilt = rebuild(term, top_level=True)
        if isinstance(rebuilt, (runtime.AstNode, runtime.AstLeaf)):
            return rebuilt
        # Rotate helpers are instruction-level value producers.  The shared
        # materializer intentionally returns a live minsn_t rather than a
        # synthetic AstNode, so preserve that native seam for callers that
        # supplied the active block/destination context.
        if term.operation in {"rol", "ror"}:
            return rebuilt
        return None
    except Exception:
        return None


__all__ = [
    "HexRaysIslandLowering",
    "lower_hexrays_island",
    "rebuild_hexrays_island",
    "unwrap_hexrays_island_ast",
]

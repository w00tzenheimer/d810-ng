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
from d810.mba.typed_term import TypedBvTerm, _leaf_key_fingerprint, term_fingerprint
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
            operation = runtime.operation_by_opcode.get(opcode)
            if opcode == getattr(importlib.import_module("ida_hexrays"), "m_call"):
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
                count = runtime.AstConstant(
                    str(node.shift_count), node.shift_count, 1
                )
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
        if isinstance(rebuilt, runtime.AstNode):
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

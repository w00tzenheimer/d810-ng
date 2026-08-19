"""IDA-bound composition facade for the stable native MBA extension API.

This module owns the live-object seam.  Extensions only import
``d810.mba.extension_api`` and receive the immutable DTOs defined there; all
Hex-Rays conversion, preparation, reconstruction, proof, and persistence stay
behind this facade.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from d810.backends.mba.cross_block_preparation import (
    PreparedCrossBlockAst,
    prepare_ast_with_cross_block_constants,
    prepare_ast_with_def_use_constants,
)
from d810.backends.mba.hexrays_island import (
    HexRaysIslandLowering,
    lower_hexrays_island,
    rebuild_hexrays_island,
)
from d810.backends.mba.native_mba_term_view import NativeMbaTermView
from d810.backends.mba.native_z3 import prove_native_ast_equivalence
from d810.core.persistence import NetnodeOptimizationStorage
from d810.mba.extension_api import (
    EgraphPersistenceService,
    NativeMbaCandidate,
    NativeMbaHostServices,
    NativeMbaReconstruction,
)
from d810.mba.island_profile import profile_to_dict
from d810.mba.typed_term import TypedBvTerm, term_fingerprint


_VALID_DESTINATION_SIZES = frozenset({1, 2, 4, 8})
_PERSISTENCE_SCOPE = "egraph-extension"


@dataclass(frozen=True, slots=True)
class _NativeMbaContext:
    """Callback-local native state kept opaque from portable extensions."""

    source_ast: object | None
    source_instruction: object | None
    source_block: object | None
    destination: object | None
    destination_size: int
    lowering: HexRaysIslandLowering | None
    native_view: NativeMbaTermView | None = None
    source_context: _NativeMbaContext | None = None
    known_constants: Mapping[tuple[object, ...], int] = MappingProxyType({})


class _JsonPersistenceService:
    """Namespace view over the existing IDB JSON blob storage."""

    def __init__(self, storage: NetnodeOptimizationStorage, namespace: str):
        if type(namespace) is not str or not namespace.strip():
            raise ValueError("persistence namespace must be a non-empty string")
        self._storage = storage
        self._namespace = namespace.strip()
        # Encode the caller namespace so one namespace cannot become a prefix
        # of another namespace's key listing (for example ``a`` vs ``a:b``).
        encoded_namespace = self._namespace.encode("utf-8").hex()
        self._scope = f"{_PERSISTENCE_SCOPE}:{encoded_namespace}"

    @staticmethod
    def _validate_key(key: str) -> str:
        if type(key) is not str or not key:
            raise ValueError("persistence key must be a non-empty string")
        return key

    @staticmethod
    def _validate_json_mapping(value: Mapping[str, object]) -> dict[str, object]:
        if not isinstance(value, Mapping):
            raise TypeError("persistence values must be mappings")
        if any(type(key) is not str for key in value):
            raise TypeError("persistence mapping keys must be strings")
        try:
            json.dumps(dict(value), ensure_ascii=True, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise TypeError("persistence value must be JSON-safe") from exc
        return dict(value)

    def get_json(self, key: str) -> Mapping[str, object] | None:
        key = self._validate_key(key)
        value = self._storage.get_native_patch_blob(self._scope, key)
        if value is None or not isinstance(value, Mapping):
            return None
        try:
            return MappingProxyType(self._validate_json_mapping(value))
        except (TypeError, ValueError):
            return None

    def put_json(self, key: str, value: Mapping[str, object]) -> None:
        key = self._validate_key(key)
        self._storage.set_native_patch_blob(
            self._scope,
            key,
            self._validate_json_mapping(value),
        )

    def delete(self, key: str) -> None:
        self._storage.clear_native_patch_blob(self._scope, self._validate_key(key))

    def keys(self, *, prefix: str = "") -> tuple[str, ...]:
        if type(prefix) is not str:
            raise TypeError("persistence key prefix must be a string")
        # NetnodeOptimizationStorage exposes the blob namespace through its
        # existing state object.  Reading that state is intentionally kept here
        # rather than adding a generic storage dependency to the portable API.
        state = getattr(self._storage, "_state", {})
        blobs = state.get("native_patch_blobs", {})
        if not isinstance(blobs, Mapping):
            return ()
        scope_prefix = f"{self._scope}:"
        return tuple(
            sorted(
                key[len(scope_prefix) :]
                for key in blobs
                if isinstance(key, str)
                and key.startswith(scope_prefix)
                and key[len(scope_prefix) :].startswith(prefix)
            )
        )


class _NativeMbaHostServices:
    """Concrete IDA-bound implementation of :class:`NativeMbaHostServices`."""

    def __init__(self) -> None:
        self._persistence_storage: NetnodeOptimizationStorage | None = None

    def capture_instruction(self, instruction: object) -> NativeMbaCandidate | None:
        destination_size = _instruction_destination_size(instruction)
        if destination_size is None:
            return None
        result = NativeMbaTermView.from_instruction(
            instruction,
            destination_size=destination_size,
        )
        if result.view is None:
            return None
        canonical_view = result.view.to_canonical_view()
        ast, lowering = _ast_and_lowering(instruction, destination_size)
        context = _NativeMbaContext(
            source_ast=ast,
            source_instruction=instruction,
            source_block=None,
            destination=getattr(instruction, "d", None),
            destination_size=destination_size,
            lowering=lowering,
            native_view=result.view,
        )
        return NativeMbaCandidate(
            destination_size=destination_size,
            term=canonical_view.canonical_term,
            raw_term=canonical_view.raw_term,
            profile=result.profile,
            native_context=context,
        )

    def capture_ast(
        self,
        ast: object,
        *,
        destination_size: int,
    ) -> NativeMbaCandidate:
        lowering = lower_hexrays_island(ast, destination_size=destination_size)
        if lowering.term is None or lowering.raw_term is None:
            blockers = ", ".join(str(blocker) for blocker in lowering.profile.blockers)
            raise ValueError(
                "native MBA AST is unsupported" + (f": {blockers}" if blockers else "")
            )
        context = _NativeMbaContext(
            source_ast=ast,
            source_instruction=None,
            source_block=None,
            destination=getattr(ast, "dst_mop", None),
            destination_size=destination_size,
            lowering=lowering,
        )
        return _candidate_from_lowering(destination_size, lowering, context)

    def prepare_cross_block(
        self,
        candidate: NativeMbaCandidate,
        *,
        block: object,
        instruction: object,
        use_constants: bool,
        use_def_use: bool,
    ) -> NativeMbaCandidate:
        if type(use_constants) is not bool or type(use_def_use) is not bool:
            raise TypeError("preparation flags must be booleans")
        if not use_constants and not use_def_use:
            return candidate
        context = _host_context(candidate)
        if context is None or context.source_ast is None:
            return candidate
        mba = getattr(block, "mba", None)
        if mba is None:
            return candidate

        prepared: PreparedCrossBlockAst | None = None
        if use_constants:
            prepared = prepare_ast_with_cross_block_constants(
                mba,
                block,
                instruction,
                context.source_ast,
            )
        if prepared is None and use_def_use:
            prepared = prepare_ast_with_def_use_constants(
                mba,
                block,
                instruction,
                context.source_ast,
            )
        if prepared is None:
            return candidate

        lowering = lower_hexrays_island(
            prepared.ast,
            destination_size=candidate.destination_size,
        )
        if lowering.term is None or lowering.raw_term is None:
            return candidate
        prepared_context = _NativeMbaContext(
            source_ast=context.source_ast,
            source_instruction=instruction,
            source_block=block,
            destination=getattr(instruction, "d", context.destination),
            destination_size=candidate.destination_size,
            lowering=lowering,
            native_view=context.native_view,
            source_context=context,
            known_constants=MappingProxyType(dict(prepared.known_constants)),
        )
        return _candidate_from_lowering(
            candidate.destination_size,
            lowering,
            prepared_context,
        )

    def rebuild(
        self,
        candidate: NativeMbaCandidate,
        replacement: TypedBvTerm,
    ) -> NativeMbaReconstruction | None:
        if not isinstance(replacement, TypedBvTerm):
            return None
        if replacement.width != candidate.destination_size * 8:
            return None
        context = _host_context(candidate)
        if context is None or context.lowering is None:
            return None
        replacement_ast = rebuild_hexrays_island(
            replacement,
            lowering=context.lowering,
            destination_size=candidate.destination_size,
            block=context.source_block,
            destination=context.destination,
        )
        if replacement_ast is None:
            return None
        replacement_instruction = _materialize_instruction(
            replacement_ast,
            context,
            candidate.destination_size,
        )
        if replacement_instruction is None:
            return None
        return NativeMbaReconstruction(replacement_ast, replacement_instruction)

    def prove(
        self,
        candidate: NativeMbaCandidate,
        reconstruction: NativeMbaReconstruction,
        *,
        certificate: str | None,
        known_constants: object | None,
    ) -> bool:
        context = _host_context(candidate)
        if context is None or context.source_ast is None:
            return False
        assumptions = (
            context.known_constants if known_constants is None else known_constants
        )
        if not isinstance(assumptions, Mapping):
            return False
        try:
            return prove_native_ast_equivalence(
                context.source_ast,
                reconstruction.replacement_ast,
                width=candidate.destination_size * 8,
                certificate=certificate,
                known_constants=assumptions,
            )
        except Exception:
            return False

    def profile_metadata(self, candidate: NativeMbaCandidate) -> Mapping[str, object]:
        context = _host_context(candidate)
        raw_term = candidate.raw_term
        metadata: dict[str, object] = {
            "destination_size": candidate.destination_size,
            "width_bits": candidate.term.width,
            "term_fingerprint": term_fingerprint(candidate.term),
            "raw_term_fingerprint": (
                term_fingerprint(raw_term) if raw_term is not None else None
            ),
            "profile": profile_to_dict(candidate.profile),
        }
        if context is not None and context.known_constants:
            metadata["known_constant_count"] = len(context.known_constants)
        return MappingProxyType(metadata)

    def persistence(self, namespace: str) -> EgraphPersistenceService:
        if self._persistence_storage is None:
            self._persistence_storage = NetnodeOptimizationStorage(
                "$ d810.egraph.extension"
            )
        return _JsonPersistenceService(self._persistence_storage, namespace)


def native_mba_host_services() -> NativeMbaHostServices:
    """Return the IDA-bound composition facade for native MBA extensions."""

    return _NativeMbaHostServices()


def _instruction_destination_size(instruction: object) -> int | None:
    try:
        size = getattr(getattr(instruction, "d", None), "size", None)
    except Exception:
        return None
    return size if type(size) is int and size in _VALID_DESTINATION_SIZES else None


def _ast_and_lowering(
    instruction: object,
    destination_size: int,
) -> tuple[object | None, HexRaysIslandLowering | None]:
    try:
        from d810.hexrays.ir.minsn_utils import minsn_to_ast

        ast = minsn_to_ast(instruction)
        if ast is None:
            return None, None
        lowering = lower_hexrays_island(ast, destination_size=destination_size)
        if lowering.term is None:
            return ast, None
        return ast, lowering
    except Exception:
        return None, None


def _candidate_from_lowering(
    destination_size: int,
    lowering: HexRaysIslandLowering,
    context: _NativeMbaContext,
) -> NativeMbaCandidate:
    assert lowering.term is not None
    assert lowering.raw_term is not None
    return NativeMbaCandidate(
        destination_size=destination_size,
        term=lowering.term,
        raw_term=lowering.raw_term,
        profile=lowering.profile,
        native_context=context,
    )


def _host_context(candidate: NativeMbaCandidate) -> _NativeMbaContext | None:
    context = candidate.native_context
    return context if isinstance(context, _NativeMbaContext) else None


def _materialize_instruction(
    replacement_ast: object,
    context: _NativeMbaContext,
    destination_size: int,
) -> object | None:
    # Rotate helper reconstruction already returns a live minsn_t.  Preserve
    # that exact native result instead of wrapping it in a synthetic move.
    if not hasattr(replacement_ast, "create_minsn"):
        if getattr(replacement_ast, "opcode", None) is not None and not hasattr(
            replacement_ast, "is_leaf"
        ):
            return replacement_ast

    ea = _native_ea(context.source_instruction, context.source_ast)
    destination = _copy_destination(context.destination)
    try:
        create_minsn = getattr(replacement_ast, "create_minsn", None)
        if callable(create_minsn):
            return create_minsn(ea, destination)
    except Exception:
        return None

    try:
        import ida_hexrays

        if not callable(getattr(replacement_ast, "create_mop", None)):
            return None
        instruction = ida_hexrays.minsn_t(ea)
        instruction.opcode = ida_hexrays.m_mov
        instruction.l = replacement_ast.create_mop(ea)
        instruction.r = ida_hexrays.mop_t()
        instruction.r.erase()
        instruction.d = destination or ida_hexrays.mop_t()
        if destination is None:
            instruction.d.erase()
            instruction.d.size = destination_size
        return instruction
    except Exception:
        return None


def _native_ea(instruction: object | None, ast: object | None) -> int:
    for value in (
        getattr(instruction, "ea", None),
        getattr(ast, "ea", None),
    ):
        if type(value) is int and value >= 0:
            return value
    return 0


def _copy_destination(destination: object | None) -> object | None:
    if destination is None:
        return None
    try:
        to_mop = getattr(destination, "to_mop", None)
        if callable(to_mop):
            return to_mop()
        import ida_hexrays

        copied = ida_hexrays.mop_t()
        copied.assign(destination)
        return copied
    except Exception:
        return None


__all__ = ["native_mba_host_services"]

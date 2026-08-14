"""Read-only native bytes/metadata/origin snapshot capture.

Task 5 ("Read-only capture, lowering, and preflight") of
``_gitless/profile-guided-native-mutation-implementer-plan.md``. This is the
authoritative capture module for the plan/preflight pipeline: it reads
current/original bytes, inherited patch rows, item shapes, incoming refs, and
function ownership for one candidate byte range, and assembles them into a
:class:`~d810.transforms.native_patch_lowering.NativeEdgeCaptureEvidence`
that ``native_patch_lowering.py`` combines with an ``EncodingProvider`` result
to build a full ``NativePatchOperation``.

Relationship to ``observation.py`` -- extended, not superseded
--------------------------------------------------------------------------

``d810.backends.ida.native_patch.observation`` (Task 4, already committed) is
a *narrower*, earlier-stage read: given a function EA, it decodes every
conditional branch and reports whether Mode A could plausibly represent it
(``BranchObservation.encodable``), for the flowchart-preanalysis seam's
RUN/SUPPRESS decision. It never builds a restore snapshot, never reads patch
rows, item shapes, or full incoming-ref/ownership evidence, and it is not
meant to (its own docstring: "It proposes; it never writes and never requests
a redo" -- a lightweight per-function triage, not per-operation authorization
evidence).

This module is a **different, complementary read**, not a competing
implementation of the same job: :func:`capture_range_evidence` operates on
one already-identified candidate *range* (not a whole function) and returns
the complete evidence bundle a ``NativePatchOperation`` requires -- current
bytes, original bytes, patch rows, item shape, incoming refs, and function
ownership, wrapped into a restore snapshot. There is no overlapping/duplicate
capture path: ``observation.py`` answers "is this function worth building a
plan for at all," and this module answers "here is the exact live evidence
for the one range a plan candidate already picked." Both may legitimately
read overlapping IDA facts (e.g. loaded-state, incoming refs) because they
serve different callers at different pipeline stages; see the report for this
being an explicit choice rather than a silently-resolved ambiguity.

Read-only, and pure where it can be
--------------------------------------------------------------------------

No call in this module ever writes: no ``patch_bytes``/``patch_byte``/
``put_bytes``/``del_items``/``create_insn``/``add_cref``/``add_func``/
``set_func_*``. :func:`capture_range_evidence` is a pure function of an
injected :class:`LiveDatabaseReader`, so it -- and every abstention path -- is
unit-testable with a plain fake reader, never a mocked ``ida_*`` module (see
``tests/unit/conftest.py``'s no-IDA-mocking rule).
:class:`IdaLiveDatabaseReader` is the one concrete implementation that
actually calls ``ida_*``; every one of its methods lazy-imports its module
(this repository's established pattern -- see e.g.
``d810.backends.hexrays.native_preanalysis_key``) so importing this module
never requires a live IDA runtime. It is exercised only by the Docker
system-test suite.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.typing import Protocol, runtime_checkable
from d810.transforms.native_patch_lowering import NativeEdgeCaptureEvidence
from d810.transforms.native_patch_plan import (
    InheritedPatchRow,
    NativeAddressRange,
    NativeFunctionFlowRef,
    NativeFunctionOwnership,
    NativeFunctionTypeInfo,
    NativeIncomingRef,
    NativeItemHead,
    NativeItemKind,
    NativeItemShape,
    NativeRestoreSnapshot,
)

__all__ = [
    "CaptureAbstentionReason",
    "CaptureOutcome",
    "IdaLiveDatabaseReader",
    "LiveDatabaseReader",
    "capture_range_evidence",
]


class CaptureAbstentionReason(str, Enum):
    """Stable capture-level abstention reasons.

    Both are cases where capture cannot produce evidence honest enough to
    authorize anything built from it: an unreadable byte can confirm neither
    a before- nor an after-image, and a range with no owning function has no
    ownership evidence to capture at all.
    """

    LOADED_STATE_CHANGED = "LOADED_STATE_CHANGED"
    FUNCTION_OWNERSHIP_CHANGE_REQUIRED = "FUNCTION_OWNERSHIP_CHANGE_REQUIRED"


@runtime_checkable
class LiveDatabaseReader(Protocol):
    """Read-only live-database facts :func:`capture_range_evidence` needs.

    Every method is a plain read returning primitives/plain dataclasses --
    no live IDA object crosses this boundary. :class:`IdaLiveDatabaseReader`
    is the concrete production implementation; unit tests inject a plain
    fake instead.
    """

    def read_current_bytes(self, start_ea: int, end_ea: int) -> bytes | None:
        """Current bytes, or ``None`` if any byte in range is unloaded."""
        ...

    def read_original_bytes(self, start_ea: int, end_ea: int) -> bytes | None:
        """IDA's original-layer bytes, or ``None`` if unreadable."""
        ...

    def read_patch_rows(
        self, start_ea: int, end_ea: int
    ) -> tuple[InheritedPatchRow, ...]: ...

    def read_item_shape(self, start_ea: int, end_ea: int) -> NativeItemShape: ...

    def read_incoming_refs(
        self, start_ea: int, end_ea: int
    ) -> tuple[NativeIncomingRef, ...]: ...

    def read_function_ownership(self, ea: int) -> NativeFunctionOwnership | None:
        """``None`` when ``ea`` is not owned by any function."""
        ...


@dataclass(frozen=True, slots=True)
class CaptureOutcome:
    """Either a captured evidence bundle or a stable abstention reason.

    ``ea`` is always the range's ``start_ea`` -- the native EA anchor every
    block-level diagnostic must carry, present on the abstention path too.
    """

    ea: int
    evidence: NativeEdgeCaptureEvidence | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if (self.evidence is None) == (self.reason is None):
            raise ValueError("exactly one of evidence/reason must be set")

    @property
    def ok(self) -> bool:
        return self.evidence is not None


def capture_range_evidence(
    reader: LiveDatabaseReader,
    address_range: NativeAddressRange,
    *,
    function_ea: int,
    switch_fixup_metadata: tuple[str, ...] = (),
) -> CaptureOutcome:
    """Read-only capture of everything a ``NativePatchOperation`` needs for
    one candidate range.

    Rereads current bytes, original bytes, patch rows, item shape, incoming
    refs, and function ownership, then assembles a
    ``NativeEdgeCaptureEvidence`` including its ``NativeRestoreSnapshot``.
    Abstains -- rather than returning partial or inferred evidence -- when a
    byte cannot be read or the range has no owning function.
    """
    start_ea, end_ea = address_range.start_ea, address_range.end_ea

    current_bytes = reader.read_current_bytes(start_ea, end_ea)
    if current_bytes is None:
        return CaptureOutcome(
            ea=start_ea, reason=CaptureAbstentionReason.LOADED_STATE_CHANGED.value
        )

    original_bytes = reader.read_original_bytes(start_ea, end_ea)
    if original_bytes is None:
        return CaptureOutcome(
            ea=start_ea, reason=CaptureAbstentionReason.LOADED_STATE_CHANGED.value
        )

    function_ownership = reader.read_function_ownership(function_ea)
    if function_ownership is None:
        return CaptureOutcome(
            ea=start_ea,
            reason=CaptureAbstentionReason.FUNCTION_OWNERSHIP_CHANGE_REQUIRED.value,
        )

    patch_rows = reader.read_patch_rows(start_ea, end_ea)
    item_shape = reader.read_item_shape(start_ea, end_ea)
    incoming_refs = reader.read_incoming_refs(start_ea, end_ea)

    evidence = NativeEdgeCaptureEvidence(
        expected_current_bytes=current_bytes,
        expected_original_bytes=original_bytes,
        expected_patch_rows=patch_rows,
        expected_item_shape=item_shape,
        expected_incoming_refs=incoming_refs,
        expected_function_ownership=function_ownership,
        restore_snapshot=NativeRestoreSnapshot(
            inherited_bytes=current_bytes,
            inherited_patch_rows=patch_rows,
            item_shape=item_shape,
            incoming_refs=incoming_refs,
            function_ownership=function_ownership,
            switch_fixup_metadata=switch_fixup_metadata,
        ),
    )
    return CaptureOutcome(ea=start_ea, evidence=evidence)


class IdaLiveDatabaseReader:
    """:class:`LiveDatabaseReader` backed by the live IDA database.

    Every method is read-only and lazy-imports its ``ida_*`` module, so
    constructing/importing this class never requires a live IDA runtime --
    only calling one of its methods does. No method here ever calls
    ``patch_bytes``/``patch_byte``/``put_bytes``/``del_items``/
    ``create_insn``/``add_cref``/``add_func``/``set_func_*``. Exercised only
    by the Docker system-test suite; the unit-test suite never constructs
    this class.
    """

    def read_current_bytes(self, start_ea: int, end_ea: int) -> bytes | None:
        import ida_bytes

        if not all(ida_bytes.is_loaded(ea) for ea in range(start_ea, end_ea)):
            return None
        return ida_bytes.get_bytes(start_ea, end_ea - start_ea)

    def read_original_bytes(self, start_ea: int, end_ea: int) -> bytes | None:
        import ida_bytes

        values = [ida_bytes.get_original_byte(ea) for ea in range(start_ea, end_ea)]
        if any(value is None for value in values):
            return None
        return bytes(value & 0xFF for value in values)

    def read_patch_rows(
        self, start_ea: int, end_ea: int
    ) -> tuple[InheritedPatchRow, ...]:
        import ida_bytes

        rows: list[InheritedPatchRow] = []

        def _visit(ea: int, fpos: int, org_val: int, patch_val: int) -> int:
            rows.append(
                InheritedPatchRow(
                    ea=ea,
                    file_position=fpos,
                    ida_original_value=org_val,
                    inherited_current_value=patch_val,
                )
            )
            return 0

        ida_bytes.visit_patched_bytes(start_ea, end_ea, _visit)
        return tuple(rows)

    def read_item_shape(self, start_ea: int, end_ea: int) -> NativeItemShape:
        import ida_bytes

        heads: list[NativeItemHead] = []
        cursor = start_ea
        while cursor < end_ea:
            head_ea = ida_bytes.get_item_head(cursor)
            size = max(int(ida_bytes.get_item_size(head_ea)), 1)
            flags = ida_bytes.get_flags(head_ea)
            if ida_bytes.is_code(flags):
                kind = NativeItemKind.CODE
            elif ida_bytes.is_data(flags):
                kind = NativeItemKind.DATA
            else:
                kind = NativeItemKind.UNKNOWN
            user_defined = bool(ida_bytes.has_user_name(flags)) or bool(
                ida_bytes.is_manual_insn(head_ea)
            )
            heads.append(
                NativeItemHead(
                    ea=int(head_ea), size=size, kind=kind, user_defined=user_defined
                )
            )
            cursor = int(head_ea) + size
        return NativeItemShape(heads=tuple(heads))

    def read_incoming_refs(
        self, start_ea: int, end_ea: int
    ) -> tuple[NativeIncomingRef, ...]:
        import ida_xref

        refs: list[NativeIncomingRef] = []
        for target_ea in range(start_ea, end_ea):
            xref = ida_xref.xrefblk_t()
            ok = xref.first_to(target_ea, ida_xref.XREF_ALL)
            while ok:
                ownership = "user" if xref.user else "auto"
                kind = "code" if xref.iscode else "data"
                refs.append(
                    NativeIncomingRef(
                        source_ea=int(xref.frm),
                        target_ea=int(target_ea),
                        kind=kind,
                        ownership=ownership,
                    )
                )
                ok = xref.next_to()
        return tuple(refs)

    def read_function_ownership(self, ea: int) -> NativeFunctionOwnership | None:
        import ida_funcs
        import ida_nalt
        import ida_typeinf
        import ida_xref

        func = ida_funcs.get_func(ea)
        if func is None:
            return None

        chunk_ranges: list[NativeAddressRange] = []
        tail_iterator = ida_funcs.func_tail_iterator_t(func)
        ok = tail_iterator.main()
        while ok:
            chunk = tail_iterator.chunk()
            chunk_ranges.append(
                NativeAddressRange(int(chunk.start_ea), int(chunk.end_ea))
            )
            ok = tail_iterator.next()
        if not chunk_ranges:
            chunk_ranges = [NativeAddressRange(int(func.start_ea), int(func.end_ea))]

        def _inside_function(candidate_ea: int) -> bool:
            return any(
                chunk.start_ea <= candidate_ea < chunk.end_ea for chunk in chunk_ranges
            )

        flow_refs: set[NativeFunctionFlowRef] = set()
        for chunk in chunk_ranges:
            for source_ea in range(chunk.start_ea, chunk.end_ea):
                xref = ida_xref.xrefblk_t()
                ok = xref.first_from(source_ea, ida_xref.XREF_ALL)
                while ok:
                    target_ea = int(xref.to)
                    if xref.iscode and _inside_function(target_ea):
                        flow_refs.add(
                            NativeFunctionFlowRef(
                                source_ea=int(source_ea),
                                target_ea=target_ea,
                                xref_type=int(xref.type),
                                user=bool(xref.user),
                            )
                        )
                    ok = xref.next_from()

        type_info = None
        tif = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tif, int(func.start_ea)):
            serialized = tif.serialize()
            if not isinstance(serialized, tuple) or len(serialized) != 3:
                return None
            type_bytes, field_bytes, field_comment_bytes = serialized
            if not isinstance(type_bytes, bytes) or not type_bytes:
                return None
            type_info = NativeFunctionTypeInfo(
                type_bytes=type_bytes,
                field_bytes=(bytes(field_bytes) if field_bytes is not None else None),
                field_comment_bytes=(
                    bytes(field_comment_bytes)
                    if field_comment_bytes is not None
                    else None
                ),
            )

        return NativeFunctionOwnership(
            owning_function_entry_ea=int(func.start_ea),
            chunk_ranges=tuple(chunk_ranges),
            flow_refs=tuple(sorted(flow_refs)),
            function_flags=int(ida_funcs.get_func_flags(int(func.start_ea))),
            type_info=type_info,
        )

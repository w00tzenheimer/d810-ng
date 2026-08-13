"""Provider-neutral native instruction/span/origin-map records.

Section 9 of ``_gitless/REVERSIBLE-NATIVE-PATCHES.md`` ("Native-origin mapping
is phase zero") and Task 5 Step 1 of
``_gitless/profile-guided-native-mutation-implementer-plan.md``. These types
answer "what real, decoded native bytes -- if any -- does this microblock
descend from, and how confidently?" *before* anything is proposed to be
rewritten. They are immutable, pure records: no live IDA object, no mutation,
and no dependency on any layer above ``d810.ir``.

Layering
--------

``d810.ir`` is rank 13 -- the second-lowest layer, with only ``d810.core``
below it. That means this module CANNOT reuse two types the section-9
pseudocode casually references:

* ``NativeIncomingRef`` (defined in ``d810.transforms.native_patch_plan``,
  rank 9 -- a *higher* layer than ``ir``). Importing it here would be the
  exact upward import the layered-architecture contract forbids, so this
  module defines its own minimal :class:`NativeOriginIncomingRef` instead.
* ``NativeInstructionHead`` / ``NativeInstructionSequenceShape`` (defined in
  ``d810.capabilities.native_patch``, rank 12 -- also higher than ``ir``).
  :class:`NativeInstructionIdentity` here is therefore a distinct, simpler
  type from the ``capabilities`` shape vocabulary, not a reuse of it.

Both higher-layer modules may (and do) import *this* module downward.

Coverage semantics (global constraint: "Origin coverage must distinguish
complete/partial/synthetic/ambiguous, and partial/ambiguous are automatic
abstention reasons")
--------------------------------------------------------------------------

:class:`NativeOriginSpan.coverage` is validated, not merely declarative --
each :class:`NativeOriginCoverage` member has a structural precondition on
``instructions`` that a caller cannot get wrong silently:

* ``COMPLETE`` -- ``instructions`` is non-empty and tiles ``[start_ea,
  end_ea)`` exactly: contiguous, no gap, no overlap, nothing outside the
  range. This is the only coverage a Mode-A lowering may act on.
* ``PARTIAL`` -- some real, decoded native bytes exist in range, but they do
  not fully and contiguously cover it (this is exactly what a "non-contiguous
  span" negative test constructs). A span that in fact tiles cleanly must be
  labelled ``COMPLETE``, not ``PARTIAL`` -- claiming partial coverage for a
  complete tiling is a modelling bug and is rejected the same way.
* ``SYNTHETIC`` -- no real decoded native instruction exists in range at all
  (``instructions == ()``). The "span" describes a range with no native
  ancestor -- e.g. a fictitious/fabricated EA correlation.
* ``AMBIGUOUS`` -- more than one decode candidate claims overlapping bytes,
  so there is no single answer. Like ``PARTIAL``, a cleanly-tiling
  instruction set can never legitimately be ``AMBIGUOUS``.

Native EA anchor (global constraint: "A microcode block serial alone is not
acceptable")
-----------------------------------------------------------------------------

:class:`MicroblockNativeOrigin.native_ea_anchor` is a **mandatory**, always-
present field, independent of ``spans`` or ``coverage``. A microblock serial
is maturity-local and meaningless once microcode is rebuilt; every
block-level origin record -- even a wholly ``SYNTHETIC`` one with zero spans
-- carries the native EA it is diagnostically anchored to.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum

__all__ = [
    "MicroblockNativeOrigin",
    "NativeFixupSite",
    "NativeInstructionIdentity",
    "NativeOriginCoverage",
    "NativeOriginIncomingRef",
    "NativeOriginMap",
    "NativeOriginSpan",
]

_OWNERSHIP_VALUES = frozenset({"user", "auto"})


def _require_identifier(value: object, label: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value.strip():
        raise ValueError(f"{label} must not be blank")


def _require_ea(value: object, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{label} must be an int")
    if value < 0:
        raise ValueError(f"{label} must be non-negative")


def _stable_hash(content: tuple) -> str:
    """Deterministic content hash -- see the identical helper and rationale
    in ``d810.transforms.native_patch_plan``; duplicated rather than shared
    because that module sits above ``d810.ir`` and cannot be imported here.
    """
    return hashlib.sha256(repr(content).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# NativeFixupSite / NativeInstructionIdentity
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NativeFixupSite:
    """One PC-relative operand site inside a decoded native instruction."""

    site_ea: int
    kind: str
    target_ea: int | None
    original_displacement: int | None

    def __post_init__(self) -> None:
        _require_ea(self.site_ea, "site_ea")
        _require_identifier(self.kind, "kind")
        if self.target_ea is not None:
            _require_ea(self.target_ea, "target_ea")


@dataclass(frozen=True, slots=True)
class NativeInstructionIdentity:
    """One decoded native instruction: bounds, content hash, and shape."""

    ea: int
    end_ea: int
    bytes_hash: str
    mnemonic: str
    operand_shape: tuple[str, ...]
    pc_relative_sites: tuple[NativeFixupSite, ...]

    def __post_init__(self) -> None:
        _require_ea(self.ea, "ea")
        _require_ea(self.end_ea, "end_ea")
        if self.end_ea <= self.ea:
            raise ValueError("end_ea must exceed ea")
        _require_identifier(self.bytes_hash, "bytes_hash")
        _require_identifier(self.mnemonic, "mnemonic")
        if not isinstance(self.operand_shape, tuple):
            raise TypeError("operand_shape must be a tuple")
        if not isinstance(self.pc_relative_sites, tuple) or not all(
            isinstance(site, NativeFixupSite) for site in self.pc_relative_sites
        ):
            raise TypeError("pc_relative_sites must be a tuple of NativeFixupSite")

    @property
    def length(self) -> int:
        return self.end_ea - self.ea


# ---------------------------------------------------------------------------
# NativeOriginIncomingRef -- ir-local, see the module docstring for why this
# is not a reuse of transforms.native_patch_plan.NativeIncomingRef.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NativeOriginIncomingRef:
    source_ea: int
    target_ea: int
    kind: str
    ownership: str  # "user" | "auto"

    def __post_init__(self) -> None:
        _require_ea(self.source_ea, "source_ea")
        _require_ea(self.target_ea, "target_ea")
        _require_identifier(self.kind, "kind")
        if self.ownership not in _OWNERSHIP_VALUES:
            raise ValueError("ownership must be 'user' or 'auto'")


# ---------------------------------------------------------------------------
# NativeOriginCoverage / NativeOriginSpan
# ---------------------------------------------------------------------------


class NativeOriginCoverage(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    SYNTHETIC = "synthetic"
    AMBIGUOUS = "ambiguous"


def _tiles_contiguously(
    start_ea: int, end_ea: int, instructions: tuple[NativeInstructionIdentity, ...]
) -> bool:
    """Whether ``instructions``, in order, exactly and contiguously covers
    ``[start_ea, end_ea)`` with no gap and no overlap."""
    if not instructions:
        return False
    cursor = start_ea
    for insn in instructions:
        if insn.ea != cursor:
            return False
        cursor = insn.end_ea
    return cursor == end_ea


@dataclass(frozen=True, slots=True)
class NativeOriginSpan:
    """One claimed native span and how confidently it is known.

    See the module docstring for the per-``coverage`` structural
    preconditions this validates.
    """

    start_ea: int
    end_ea: int
    expected_bytes_hash: str
    instructions: tuple[NativeInstructionIdentity, ...]
    terminal_ea: int | None
    incoming_refs: tuple[NativeOriginIncomingRef, ...]
    coverage: NativeOriginCoverage

    def __post_init__(self) -> None:
        _require_ea(self.start_ea, "start_ea")
        _require_ea(self.end_ea, "end_ea")
        if self.end_ea <= self.start_ea:
            raise ValueError("end_ea must exceed start_ea")
        _require_identifier(self.expected_bytes_hash, "expected_bytes_hash")
        if not isinstance(self.instructions, tuple) or not all(
            isinstance(i, NativeInstructionIdentity) for i in self.instructions
        ):
            raise TypeError("instructions must be a tuple of NativeInstructionIdentity")
        if not isinstance(self.incoming_refs, tuple) or not all(
            isinstance(r, NativeOriginIncomingRef) for r in self.incoming_refs
        ):
            raise TypeError("incoming_refs must be a tuple of NativeOriginIncomingRef")
        if not isinstance(self.coverage, NativeOriginCoverage):
            raise TypeError("coverage must be a NativeOriginCoverage")
        if self.terminal_ea is not None:
            _require_ea(self.terminal_ea, "terminal_ea")
            if not (self.start_ea <= self.terminal_ea < self.end_ea):
                raise ValueError("terminal_ea must fall inside [start_ea, end_ea)")
        # Bounds are enforced for COMPLETE/PARTIAL, which both claim to
        # describe real content strictly within the claimed window. AMBIGUOUS
        # is deliberately exempt: a decode candidate landing outside the
        # queried window is itself a form of irreconcilable/contradictory
        # evidence, which is exactly what AMBIGUOUS exists to hold rather
        # than reject outright.
        if self.coverage in (
            NativeOriginCoverage.COMPLETE,
            NativeOriginCoverage.PARTIAL,
        ):
            for insn in self.instructions:
                if insn.ea < self.start_ea or insn.end_ea > self.end_ea:
                    raise ValueError(
                        "every instruction must fall inside [start_ea, end_ea)"
                    )

        contiguous = _tiles_contiguously(self.start_ea, self.end_ea, self.instructions)

        if self.coverage is NativeOriginCoverage.COMPLETE:
            if not contiguous:
                raise ValueError(
                    "COMPLETE coverage requires instructions to fully and "
                    "contiguously tile [start_ea, end_ea) -- a gap here is a "
                    "non-contiguous span and must be PARTIAL, not COMPLETE"
                )
        elif self.coverage is NativeOriginCoverage.SYNTHETIC:
            if self.instructions:
                raise ValueError(
                    "SYNTHETIC coverage requires an empty instruction set -- "
                    "a synthetic origin has no real decoded native ancestor"
                )
        elif self.coverage is NativeOriginCoverage.PARTIAL:
            if contiguous:
                raise ValueError(
                    "PARTIAL coverage requires a genuine gap -- a fully "
                    "contiguous tiling is COMPLETE, not PARTIAL"
                )
        elif self.coverage is NativeOriginCoverage.AMBIGUOUS:
            if contiguous:
                raise ValueError(
                    "AMBIGUOUS coverage requires overlapping or otherwise "
                    "irreconcilable decode candidates -- a clean contiguous "
                    "tiling is never ambiguous"
                )


# ---------------------------------------------------------------------------
# MicroblockNativeOrigin / NativeOriginMap
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MicroblockNativeOrigin:
    """One microblock's origin claim: identity, mandatory EA anchor, spans.

    ``native_ea_anchor`` has no default -- see the module docstring's "Native
    EA anchor" section. It is required even when ``spans`` is empty.
    """

    microblock_serial: int
    microblock_maturity: str
    native_ea_anchor: int
    spans: tuple[NativeOriginSpan, ...]
    correlation_evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.microblock_serial, int) or isinstance(
            self.microblock_serial, bool
        ):
            raise TypeError("microblock_serial must be an int")
        if self.microblock_serial < 0:
            raise ValueError("microblock_serial must be non-negative")
        _require_identifier(self.microblock_maturity, "microblock_maturity")
        _require_ea(self.native_ea_anchor, "native_ea_anchor")
        if not isinstance(self.spans, tuple) or not all(
            isinstance(s, NativeOriginSpan) for s in self.spans
        ):
            raise TypeError("spans must be a tuple of NativeOriginSpan")
        if not isinstance(self.correlation_evidence, tuple):
            raise TypeError("correlation_evidence must be a tuple")

    def _content_for_hash(self) -> tuple:
        return (
            self.microblock_serial,
            self.microblock_maturity,
            self.native_ea_anchor,
            tuple(
                (
                    span.start_ea,
                    span.end_ea,
                    span.expected_bytes_hash,
                    tuple(
                        (
                            i.ea,
                            i.end_ea,
                            i.bytes_hash,
                            i.mnemonic,
                            i.operand_shape,
                            tuple(
                                (
                                    s.site_ea,
                                    s.kind,
                                    s.target_ea,
                                    s.original_displacement,
                                )
                                for s in i.pc_relative_sites
                            ),
                        )
                        for i in span.instructions
                    ),
                    span.terminal_ea,
                    tuple(
                        (r.source_ea, r.target_ea, r.kind, r.ownership)
                        for r in span.incoming_refs
                    ),
                    span.coverage.value,
                )
                for span in self.spans
            ),
            self.correlation_evidence,
        )


@dataclass(frozen=True, slots=True)
class NativeOriginMap:
    """The complete, immutable native-origin correlation for one function.

    Multiple microblocks may cite the same native span as provenance -- that
    is valid overlap at the origin-mapping level. Only a
    ``NativePatchPlan``'s mutation *ownership* may not overlap; that is
    enforced separately by
    ``d810.transforms.native_patch_plan.OverlappingNativePatchOperationsError``.
    """

    function_entry_ea: int
    input_fingerprint: str
    microblock_origins: tuple[MicroblockNativeOrigin, ...]

    def __post_init__(self) -> None:
        _require_ea(self.function_entry_ea, "function_entry_ea")
        _require_identifier(self.input_fingerprint, "input_fingerprint")
        if not isinstance(self.microblock_origins, tuple) or not all(
            isinstance(o, MicroblockNativeOrigin) for o in self.microblock_origins
        ):
            raise TypeError(
                "microblock_origins must be a tuple of MicroblockNativeOrigin"
            )

    @property
    def map_fingerprint(self) -> str:
        """Deterministic content fingerprint -- see ``NativePatchPlan.plan_hash``
        for why this is a computed property rather than a stored field: it is
        the only way to guarantee the fingerprint always reflects the
        immutable content it claims to fingerprint."""
        return _stable_hash(
            (
                self.function_entry_ea,
                self.input_fingerprint,
                tuple(o._content_for_hash() for o in self.microblock_origins),
            )
        )

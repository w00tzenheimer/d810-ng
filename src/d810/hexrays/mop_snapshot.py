"""Value-type snapshot of ida_hexrays.mop_t for safe caching.

IDA's mop_t wraps a C++ pointer that Hex-Rays may recycle after
micro-optimisations.  Accessing a recycled mop_t causes SIGSEGV.
MopSnapshot extracts all needed fields into pure Python, making it
safe to cache, hash, and compare without risk of use-after-free.

This module uses Cython acceleration when available, falling back to
pure Python implementation otherwise.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import NewType, TYPE_CHECKING

if TYPE_CHECKING:
    import ida_hexrays

logger = logging.getLogger(__name__)

# Type aliases for documentation and static analysis.
# OwnedMop: a mop_t created by our code (via mop_t(), make_number, dup_mop).
# BorrowedMop: a mop_t obtained from IDA's internal trees (blk.tail.l, etc.).
#   BorrowedMop MUST NOT be stored beyond the current callback scope.
try:
    import ida_hexrays
    OwnedMop = NewType("OwnedMop", ida_hexrays.mop_t)
    BorrowedMop = NewType("BorrowedMop", ida_hexrays.mop_t)
except ImportError:
    # For unit tests or non-IDA environments
    OwnedMop = NewType("OwnedMop", object)  # type: ignore
    BorrowedMop = NewType("BorrowedMop", object)  # type: ignore

from d810.core.cymode import CythonMode

# Flag to track whether Cython speedups are available
_CYTHON_AVAILABLE = False

# Try to import Cython speedups if CythonMode is enabled
if CythonMode().is_enabled():
    try:
        from d810.speedups.cythxr.mop_snapshot import MopSnapshot
        _CYTHON_AVAILABLE = True
    except ImportError:
        pass

if not _CYTHON_AVAILABLE:
    # Cython speedups not available, use pure Python implementation

    @dataclass(frozen=True, slots=True)
    class MopSnapshot:
        """Immutable, pure-Python snapshot of an ida_hexrays.mop_t.

        Use ``MopSnapshot.from_mop(mop)`` to capture values from a live
        (possibly borrowed) mop_t.  The snapshot holds no C++ pointers and
        is safe to cache indefinitely.

        >>> snap = MopSnapshot.from_mop(some_mop)
        >>> snap.t        # operand type (mop_n, mop_r, etc.)
        >>> snap.value    # numeric value if mop_n, else None
        """

        t: int
        size: int
        valnum: int = 0
        # Type-specific fields — only the relevant one is set per type.
        value: int | None = None        # mop_n: nnn.value
        reg: int | None = None          # mop_r: r
        stkoff: int | None = None       # mop_S: s.off (if s is not None)
        gaddr: int | None = None        # mop_v: g
        lvar_idx: int | None = None     # mop_l: l.idx
        lvar_off: int | None = None     # mop_l: l.off
        block_num: int | None = None    # mop_b: b
        helper_name: str | None = None  # mop_h: helper (helper function name)
        const_str: str | None = None    # mop_str: cstr
        pair_lo_t: int | None = None    # mop_p: pair.lop.t
        pair_hi_t: int | None = None    # mop_p: pair.hop.t

        @classmethod
        def from_mop(cls, mop: ida_hexrays.mop_t) -> MopSnapshot:
            """Create a snapshot from a live mop_t.

            Extracts all Python-native values in a single pass, then
            discards the C++ reference.  Safe to call on both owned
            and borrowed mops.
            """
            t = mop.t
            base: dict = dict(t=t, size=mop.size, valnum=getattr(mop, "valnum", 0))

            if t == ida_hexrays.mop_n:
                nnn = mop.nnn
                if nnn is None:
                    logger.warning("mop_n with nnn=None (stale pointer?)")
                    base["value"] = 0
                else:
                    base["value"] = int(nnn.value)
            elif t == ida_hexrays.mop_r:
                base["reg"] = mop.r
            elif t == ida_hexrays.mop_S:
                s = mop.s
                base["stkoff"] = s.off if s is not None else 0
            elif t == ida_hexrays.mop_v:
                base["gaddr"] = mop.g
            elif t == ida_hexrays.mop_l:
                lvar = mop.l
                base["lvar_idx"] = lvar.idx if lvar is not None else 0
                base["lvar_off"] = lvar.off if lvar is not None else 0
            elif t == ida_hexrays.mop_b:
                base["block_num"] = mop.b
            elif t == ida_hexrays.mop_h:
                base["helper_name"] = mop.helper
            elif t == ida_hexrays.mop_str:
                base["const_str"] = mop.cstr
            elif t == ida_hexrays.mop_d:
                pass  # Sub-instruction — AST layer handles recursion
            elif t == ida_hexrays.mop_f:
                pass  # Function call list
            elif t == ida_hexrays.mop_a:
                pass  # Address operand
            elif t == ida_hexrays.mop_p:
                pair = mop.pair
                if pair is not None:
                    base["pair_lo_t"] = pair.lop.t
                    base["pair_hi_t"] = pair.hop.t
            elif t == ida_hexrays.mop_z:
                pass  # Empty operand
            elif t == ida_hexrays.mop_c:
                pass  # Switch cases

            return cls(**base)

        @property
        def is_constant(self) -> bool:
            """True if this snapshot represents a numeric constant (mop_n)."""
            return self.t == ida_hexrays.mop_n

        @property
        def is_register(self) -> bool:
            """True if this snapshot represents a register (mop_r)."""
            return self.t == ida_hexrays.mop_r

        def to_cache_key(self) -> tuple:
            """Return a hashable tuple suitable for cache keys.

            Equivalent to the tuple produced by the existing
            ``get_mop_key()`` function in p_ast.py.
            """
            return (
                self.t, self.size, self.valnum,
                self.value, self.reg, self.stkoff, self.gaddr,
                self.lvar_idx, self.lvar_off, self.block_num,
                self.helper_name, self.const_str,
            )

        def to_mop(self) -> ida_hexrays.mop_t:
            """Reconstruct a fresh (owned) mop_t from this snapshot.

            Used by AstLeaf.create_mop() to materialize a writeable operand
            from a cached snapshot.  The returned mop_t is owned by the caller
            and safe to pass to assign() or other IDA APIs.
            """
            m = ida_hexrays.mop_t()
            if self.t == ida_hexrays.mop_n and self.value is not None:
                m.make_number(self.value, self.size)
            elif self.t == ida_hexrays.mop_r and self.reg is not None:
                m.make_reg(self.reg, self.size)
            elif self.t == ida_hexrays.mop_S and self.stkoff is not None:
                m.make_stkvar(self.stkoff, self.size)
            elif self.t == ida_hexrays.mop_v and self.gaddr is not None:
                m.make_global(self.gaddr, self.size)
            elif self.t == ida_hexrays.mop_l and self.lvar_idx is not None:
                # Local variable: requires lvar_t, which we can't fully reconstruct
                # without the parent mba_t. Log warning and return empty mop.
                logger.warning(
                    "to_mop: Cannot reconstruct mop_l (local var idx=%s) without mba_t",
                    self.lvar_idx,
                )
                return m  # Empty mop_t
            elif self.t == ida_hexrays.mop_b and self.block_num is not None:
                m.make_blkref(self.block_num)
            elif self.t == ida_hexrays.mop_h and self.helper_name is not None:
                m.make_helper(self.helper_name)
            else:
                # For complex types (mop_d, mop_f, mop_a, mop_p, mop_str, mop_c, mop_z)
                # we cannot safely reconstruct without the original IDA structures.
                logger.warning(
                    "to_mop: Cannot reconstruct complex mop type %s, returning empty mop",
                    self.t,
                )
            return m

# cython: language_level=3, embedsignature=True, boundscheck=False, wraparound=False
# distutils: language=c++
"""Cython-accelerated MopSnapshot for fast mop_t value capture.

This module provides a Cython implementation of MopSnapshot that reads
mop_t fields directly from C++ structs, bypassing SWIG overhead.
For complex operands, it also keeps an owned mop_t clone for faithful
reconstruction.

Usage:
    from d810.speedups.cythxr.mop_snapshot import MopSnapshot

    snap = MopSnapshot.from_mop(some_mop)
    cache_key = snap.to_cache_key()
    reconstructed = snap.to_mop()
"""

from libc.stdint cimport uint64_t, int64_t
from cython.operator cimport dereference as deref

from ._chexrays cimport (
    mop_t,
    minsn_t,
    mnumber_t,
    lvar_ref_t,
    stkvar_ref_t,
    mop_pair_t,
    MOPT,
    _swig_ptr,
)

import ida_hexrays


# === Duck-typing layer: proxy classes for sub-object access ===

class _NnnProxy:
    """Mimics mnumber_t for .nnn.value access."""
    __slots__ = ('value',)
    def __init__(self, value: int):
        self.value = value
    def __eq__(self, other):
        if isinstance(other, _NnnProxy):
            return self.value == other.value
        return NotImplemented
    def __hash__(self):
        return hash(self.value)
    def __bool__(self):
        return True  # mop.nnn is truthy when present


class _StkvarProxy:
    """Mimics stkvar_ref_t for .s.off access."""
    __slots__ = ('off',)
    def __init__(self, off: int):
        self.off = off
    @property
    def start_ea(self):
        return None  # not available in snapshot
    @property
    def mba(self):
        return None  # not available in snapshot
    def __eq__(self, other):
        if isinstance(other, _StkvarProxy):
            return self.off == other.off
        # For comparison with real stkvar_ref_t, compare .off
        if hasattr(other, 'off'):
            return self.off == other.off
        return NotImplemented
    def __hash__(self):
        return hash(self.off)


class _LvarProxy:
    """Mimics lvar_ref_t for .l.idx/.l.off access."""
    __slots__ = ('idx', 'off')
    def __init__(self, idx: int, off: int):
        self.idx = idx
        self.off = off
    def __eq__(self, other):
        if isinstance(other, _LvarProxy):
            return self.idx == other.idx and self.off == other.off
        if hasattr(other, 'idx') and hasattr(other, 'off'):
            return self.idx == other.idx and self.off == other.off
        return NotImplemented
    def __hash__(self):
        return hash((self.idx, self.off))


cdef class MopSnapshot:
    """Immutable, pure-Python snapshot of an ida_hexrays.mop_t.

    This is a Cython implementation that reads C++ mop_t fields directly,
    providing significant speedup over the pure Python version.

    All fields are stored as Python objects for compatibility with the
    pure Python implementation.
    """

    # Type-safe C fields for internal storage
    cdef readonly int t
    cdef readonly int size
    cdef readonly int valnum

    # Type-specific fields (using Python objects for compatibility)
    cdef readonly object value        # int | None - mop_n: nnn.value
    cdef readonly object reg          # int | None - mop_r: r
    cdef readonly object stkoff       # int | None - mop_S: s.off
    cdef readonly object gaddr        # int | None - mop_v: g
    cdef readonly object lvar_idx     # int | None - mop_l: l.idx
    cdef readonly object lvar_off     # int | None - mop_l: l.off
    cdef readonly object block_num    # int | None - mop_b: b
    cdef readonly object helper_name  # str | None - mop_h: helper
    cdef readonly object const_str    # str | None - mop_str: cstr
    cdef readonly object pair_lo_t    # int | None - mop_p: pair.lop.t
    cdef readonly object pair_hi_t    # int | None - mop_p: pair.hop.t
    cdef readonly object owned_mop    # ida_hexrays.mop_t | None - owned clone for complex types

    # Precomputed hash for fast __hash__ calls
    cdef int _hash_value
    cdef bint _hash_computed

    def __init__(self, int t, int size, int valnum=0,
                 value=None, reg=None, stkoff=None, gaddr=None,
                 lvar_idx=None, lvar_off=None, block_num=None,
                 helper_name=None, const_str=None,
                 pair_lo_t=None, pair_hi_t=None, owned_mop=None):
        """Initialize a MopSnapshot with field values.

        Normally you should use MopSnapshot.from_mop() instead of calling
        this constructor directly.
        """
        self.t = t
        self.size = size
        self.valnum = valnum
        self.value = value
        self.reg = reg
        self.stkoff = stkoff
        self.gaddr = gaddr
        self.lvar_idx = lvar_idx
        self.lvar_off = lvar_off
        self.block_num = block_num
        self.helper_name = helper_name
        self.const_str = const_str
        self.pair_lo_t = pair_lo_t
        self.pair_hi_t = pair_hi_t
        self.owned_mop = owned_mop
        self._hash_computed = False
        self._hash_value = 0

    @staticmethod
    def from_mop(object py_mop):
        """Create a snapshot from a live mop_t.

        Extracts all Python-native values in a single pass by reading
        C++ struct fields directly, then discards the C++ reference.
        Safe to call on both owned and borrowed mops.

        Args:
            py_mop: A SWIG-wrapped ida_hexrays.mop_t object

        Returns:
            MopSnapshot instance with captured values
        """
        cdef const mop_t* op = <const mop_t*> _swig_ptr(py_mop)
        cdef int t = <int>op.t
        cdef int sz = <int>op.size
        cdef int vnum = <int>op.valnum if op.valnum != 0 else 0

        # Type-specific field extraction
        cdef object value = None
        cdef object reg = None
        cdef object stkoff = None
        cdef object gaddr = None
        cdef object lvar_idx = None
        cdef object lvar_off = None
        cdef object block_num = None
        cdef object helper_name = None
        cdef object const_str = None
        cdef object pair_lo_t = None
        cdef object pair_hi_t = None
        cdef object owned_mop = None
        cdef bint needs_owned_clone = (
            t == MOPT.DEST_RESULT or   # mop_d
            t == MOPT.ARGUMENT_LIST or # mop_f
            t == MOPT.ADDRESS or       # mop_a
            t == MOPT.CASES or         # mop_c
            t == MOPT.PAIR or          # mop_p
            t == MOPT.STACK or         # mop_S
            t == MOPT.LOCAL or         # mop_l
            t == MOPT.STRING           # mop_str
        )

        cdef mnumber_t* nnn
        cdef lvar_ref_t* lvar
        cdef stkvar_ref_t* s_ptr
        cdef mop_pair_t* pair

        if t == MOPT.NUMBER:  # mop_n
            nnn = op.nnn
            if nnn != NULL:
                value = <int64_t>nnn.value
            else:
                # Stale pointer case - use 0 as fallback
                value = 0
        elif t == MOPT.REGISTER:  # mop_r
            reg = <int>op.r
        elif t == MOPT.STACK:  # mop_S
            s_ptr = op.s
            if s_ptr != NULL:
                stkoff = <int64_t>s_ptr.off
            else:
                stkoff = 0
        elif t == MOPT.GLOBAL:  # mop_v
            gaddr = <uint64_t>op.g
        elif t == MOPT.LOCAL:  # mop_l
            lvar = op.l
            if lvar != NULL:
                lvar_idx = <int>lvar.idx
                lvar_off = <int64_t>lvar.off
            else:
                lvar_idx = 0
                lvar_off = 0
        elif t == MOPT.MBLOCK:  # mop_b
            block_num = <int>op.b
        elif t == MOPT.HELPER:  # mop_h
            if op.helper != NULL:
                helper_name = (<char*>op.helper).decode('utf-8', errors='replace')
        elif t == MOPT.STRING:  # mop_str
            if op.cstr != NULL:
                const_str = (<char*>op.cstr).decode('utf-8', errors='replace')
        elif t == MOPT.PAIR:  # mop_p
            pair = op.pair
            if pair != NULL:
                pair_lo_t = <int>pair.lop.t
                pair_hi_t = <int>pair.hop.t
        # For other types (mop_d, mop_f, mop_a, mop_z, mop_c), we don't extract fields

        if needs_owned_clone:
            try:
                owned_mop = ida_hexrays.mop_t()
                owned_mop.assign(py_mop)
            except Exception:
                owned_mop = None

        return MopSnapshot(
            t=t, size=sz, valnum=vnum,
            value=value, reg=reg, stkoff=stkoff, gaddr=gaddr,
            lvar_idx=lvar_idx, lvar_off=lvar_off, block_num=block_num,
            helper_name=helper_name, const_str=const_str,
            pair_lo_t=pair_lo_t, pair_hi_t=pair_hi_t, owned_mop=owned_mop,
        )

    @property
    def is_constant(self):
        """True if this snapshot represents a numeric constant (mop_n)."""
        return self.t == ida_hexrays.mop_n

    @property
    def is_register(self):
        """True if this snapshot represents a register (mop_r)."""
        return self.t == ida_hexrays.mop_r

    def to_cache_key(self):
        """Return a hashable tuple suitable for cache keys.

        Equivalent to the tuple produced by the existing
        get_mop_key() function in p_ast.py.

        Returns:
            Tuple of all field values
        """
        return (
            self.t, self.size, self.valnum,
            self.value, self.reg, self.stkoff, self.gaddr,
            self.lvar_idx, self.lvar_off, self.block_num,
            self.helper_name, self.const_str,
        )

    def to_mop(self):
        """Reconstruct a fresh (owned) mop_t from this snapshot.

        Used by AstLeaf.create_mop() to materialize a writeable operand
        from a cached snapshot. The returned mop_t is owned by the caller
        and safe to pass to assign() or other IDA APIs.

        Returns:
            A new ida_hexrays.mop_t object
        """
        m = ida_hexrays.mop_t()
        if self.owned_mop is not None:
            try:
                m.assign(self.owned_mop)
                return m
            except Exception:
                pass
        if self.t == ida_hexrays.mop_n and self.value is not None:
            m.make_number(self.value, self.size)
        elif self.t == ida_hexrays.mop_r and self.reg is not None:
            m.make_reg(self.reg, self.size)
        elif self.t == ida_hexrays.mop_S and self.stkoff is not None:
            try:
                m.make_stkvar(self.stkoff, self.size)
            except TypeError:
                pass
        elif self.t == ida_hexrays.mop_v and self.gaddr is not None:
            m.make_global(self.gaddr, self.size)
        elif self.t == ida_hexrays.mop_l and self.lvar_idx is not None:
            # Local variable: requires lvar_t, which we can't fully reconstruct
            # without the parent mba_t. Return empty mop (matches pure Python).
            pass
        elif self.t == ida_hexrays.mop_b and self.block_num is not None:
            m.make_blkref(self.block_num)
        elif self.t == ida_hexrays.mop_h and self.helper_name is not None:
            m.make_helper(self.helper_name)
        # For complex types, return empty mop (matches pure Python behavior)
        return m

    def __hash__(self):
        """Compute hash for use in sets/dicts."""
        if not self._hash_computed:
            self._hash_value = hash(self.to_cache_key())
            self._hash_computed = True
        return self._hash_value

    def __eq__(self, other):
        """Check equality with another MopSnapshot."""
        if not isinstance(other, MopSnapshot):
            return False
        cdef MopSnapshot o = <MopSnapshot>other
        return (self.t == o.t and self.size == o.size and self.valnum == o.valnum and
                self.value == o.value and self.reg == o.reg and self.stkoff == o.stkoff and
                self.gaddr == o.gaddr and self.lvar_idx == o.lvar_idx and
                self.lvar_off == o.lvar_off and self.block_num == o.block_num and
                self.helper_name == o.helper_name and self.const_str == o.const_str and
                self.pair_lo_t == o.pair_lo_t and self.pair_hi_t == o.pair_hi_t)

    def __repr__(self):
        """Return a debug representation."""
        parts = [f"t={self.t}", f"size={self.size}"]
        if self.valnum:
            parts.append(f"valnum={self.valnum}")
        if self.value is not None:
            parts.append(f"value={self.value}")
        if self.reg is not None:
            parts.append(f"reg={self.reg}")
        if self.stkoff is not None:
            parts.append(f"stkoff={self.stkoff}")
        if self.gaddr is not None:
            parts.append(f"gaddr={self.gaddr:#x}")
        if self.lvar_idx is not None:
            parts.append(f"lvar_idx={self.lvar_idx}")
        if self.block_num is not None:
            parts.append(f"block_num={self.block_num}")
        if self.helper_name is not None:
            parts.append(f"helper={self.helper_name!r}")
        return f"MopSnapshot({', '.join(parts)})"

    # === Duck-typing layer: property aliases for mop_t attribute compatibility ===

    # Category A: Simple property aliases
    @property
    def r(self):
        """Alias for .reg (mop_r register number)."""
        return self.reg

    @property
    def g(self):
        """Alias for .gaddr (mop_v global address)."""
        return self.gaddr

    @property
    def b(self):
        """Alias for .block_num (mop_b block reference)."""
        return self.block_num

    @property
    def helper(self):
        """Alias for .helper_name (mop_h helper function name)."""
        return self.helper_name

    @property
    def cstr(self):
        """Alias for .const_str (mop_str string literal)."""
        return self.const_str

    # Category B: Proxy objects for sub-attributes
    @property
    def nnn(self):
        """Proxy for mnumber_t (.nnn.value access)."""
        return _NnnProxy(self.value) if self.value is not None else None

    @property
    def s(self):
        """Proxy for stkvar_ref_t (.s.off access)."""
        return _StkvarProxy(self.stkoff) if self.stkoff is not None else None

    @property
    def l(self):
        """Proxy for lvar_ref_t (.l.idx/.l.off access)."""
        if self.lvar_idx is not None and self.lvar_off is not None:
            return _LvarProxy(self.lvar_idx, self.lvar_off)
        return None

    # Category C: __getattr__ fallback for complex types
    def __getattr__(self, name):
        """Delegate unknown attributes to owned_mop if available.

        This covers complex attributes like .d, .pair, .a, .f, .c, .fpc,
        .dstr(), .oprops, etc. that cannot be snapshotted as scalars.
        """
        if name.startswith('_'):
            raise AttributeError(name)
        owned = object.__getattribute__(self, 'owned_mop')
        if owned is not None:
            return getattr(owned, name)
        raise AttributeError(f"'MopSnapshot' object has no attribute '{name}' (no owned_mop)")

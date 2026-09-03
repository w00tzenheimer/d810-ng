"""Value-type snapshot of ida_hexrays.mop_t for safe caching.

IDA's mop_t wraps a C++ pointer that Hex-Rays may recycle after
micro-optimisations.  Accessing a recycled mop_t causes SIGSEGV.
MopSnapshot extracts scalar fields and, for complex operand kinds,
keeps an owned mop_t clone so reconstruction remains accurate.

This module uses Cython acceleration when available, falling back to
pure Python implementation otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import ida_hexrays

from d810.core.cymode import CythonMode
from d810.core.logging import getLogger
from d810.hexrays.ir.number_operand import safe_make_number

logger = getLogger(__name__)


_RAW_IDENTITY_MAX_DEPTH = 64


def raw_instruction_identity(instruction, *, depth: int = 0) -> dict[str, object]:
    """Serialize a live instruction into complete deterministic POD fields.

    Schema: ``{opcode, ea, iprops, l, r, d}``, where each operand contains
    ``{type, oprops, valnum, size}`` plus its type-specific scalar payload.
    Nested ``mop_d`` and ``mop_a`` values recurse into this same schema;
    ``mop_p`` recurses into ``low``/``high``.  ``mop_c``, ``mop_f``, ``mop_fn``
    and ``mop_sc`` are intentionally outside this supported subset because
    their SDK payloads are opaque here and therefore fail closed.

    This is deliberately independent of canonical AST lowering and display
    formatting.  Unsupported or incomplete native objects raise so callers
    can fail closed instead of hashing an incomplete projection.
    """

    if instruction is None or depth > _RAW_IDENTITY_MAX_DEPTH:
        raise ValueError("raw identity instruction is missing or too deeply nested")
    opcode = getattr(instruction, "opcode", None)
    ea = getattr(instruction, "ea", None)
    iprops = getattr(instruction, "iprops", None)
    if type(opcode) is not int or type(ea) is not int or type(iprops) is not int:
        raise ValueError("raw identity instruction scalar fields are unavailable")
    identity: dict[str, object] = {"opcode": opcode, "ea": ea, "iprops": iprops}
    for operand_field in ("l", "r", "d"):
        if not hasattr(instruction, operand_field):
            raise ValueError(f"raw identity instruction {operand_field} is unavailable")
        operand = getattr(instruction, operand_field)
        if operand is None:
            raise ValueError(f"raw identity instruction {operand_field} is unavailable")
        identity[operand_field] = raw_mop_identity(operand, depth=depth + 1)
    return identity


def raw_mop_identity(mop, *, depth: int = 0) -> dict[str, object] | None:
    """Serialize every supported live operand field without canonicalization."""

    if mop is None:
        return None
    if depth > _RAW_IDENTITY_MAX_DEPTH:
        raise ValueError("raw identity operand is too deeply nested")
    operand_type = getattr(mop, "t", None)
    oprops = getattr(mop, "oprops", None)
    size = getattr(mop, "size", None)
    valnum = getattr(mop, "valnum", None)
    if (
        type(operand_type) is not int
        or type(oprops) is not int
        or type(size) is not int
        or type(valnum) is not int
    ):
        raise ValueError("raw identity operand scalar fields are unavailable")
    identity: dict[str, object] = {
        "type": operand_type,
        "oprops": oprops,
        "size": size,
        "valnum": valnum,
    }
    supported_names = (
        "mop_z",
        "mop_n",
        "mop_r",
        "mop_S",
        "mop_v",
        "mop_b",
        "mop_h",
        "mop_str",
        "mop_d",
        "mop_a",
        "mop_l",
        "mop_p",
    )
    supported_types = {
        getattr(ida_hexrays, name)
        for name in supported_names
        if hasattr(ida_hexrays, name)
    }
    if operand_type not in supported_types:
        raise ValueError(f"unsupported raw identity operand type: {operand_type}")

    if operand_type == ida_hexrays.mop_n:
        nnn = getattr(mop, "nnn", None)
        value = getattr(nnn, "value", None)
        original_value = getattr(nnn, "org_value", None)
        if type(value) is not int or type(original_value) is not int:
            raise ValueError("raw identity number value is unavailable")
        identity["value"] = value
        identity["original_value"] = original_value
        identity["value_width"] = size
    elif operand_type == ida_hexrays.mop_r:
        register = getattr(mop, "r", None)
        if type(register) is not int:
            raise ValueError("raw identity register is unavailable")
        identity["register"] = register
    elif operand_type == ida_hexrays.mop_S:
        stack = getattr(mop, "s", None)
        offset = getattr(stack, "off", None)
        if type(offset) is not int:
            raise ValueError("raw identity stack offset is unavailable")
        identity["stack_offset"] = offset
    elif operand_type == ida_hexrays.mop_v:
        address = getattr(mop, "g", None)
        if type(address) is not int:
            raise ValueError("raw identity global address is unavailable")
        identity["global_address"] = address
    elif operand_type == ida_hexrays.mop_b:
        block_num = getattr(mop, "b", None)
        if type(block_num) is not int:
            raise ValueError("raw identity block number is unavailable")
        identity["block_num"] = block_num
    elif operand_type == ida_hexrays.mop_h:
        helper = getattr(mop, "helper", None)
        if type(helper) is not str:
            raise ValueError("raw identity helper is unavailable")
        identity["helper"] = helper
    elif operand_type == ida_hexrays.mop_str:
        string_value = getattr(mop, "cstr", None)
        if type(string_value) is not str:
            raise ValueError("raw identity string is unavailable")
        identity["string"] = string_value
    elif operand_type == ida_hexrays.mop_l:
        local = getattr(mop, "l", None)
        index = getattr(local, "idx", None)
        offset = getattr(local, "off", None)
        if type(index) is not int or type(offset) is not int:
            raise ValueError("raw identity local reference is unavailable")
        identity["local_index"] = index
        identity["local_offset"] = offset
    elif operand_type == ida_hexrays.mop_d:
        nested = getattr(mop, "d", None)
        if nested is None:
            raise ValueError("raw identity nested instruction is unavailable")
        identity["instruction"] = raw_instruction_identity(nested, depth=depth + 1)
    elif operand_type == ida_hexrays.mop_a:
        address_operand = getattr(mop, "a", None)
        insize = getattr(address_operand, "insize", None)
        outsize = getattr(address_operand, "outsize", None)
        if type(insize) is not int or type(outsize) is not int:
            raise ValueError("raw identity address sizes are unavailable")
        identity["address"] = raw_mop_identity(
            address_operand, depth=depth + 1
        )
        identity["address_insize"] = insize
        identity["address_outsize"] = outsize
    elif operand_type == ida_hexrays.mop_p:
        pair = getattr(mop, "pair", None)
        if pair is None:
            raise ValueError("raw identity operand pair is unavailable")
        identity["low"] = raw_mop_identity(pair.lop, depth=depth + 1)
        identity["high"] = raw_mop_identity(pair.hop, depth=depth + 1)
    return identity


# Proxy classes for sub-object access (duck-typing layer)
class _NnnProxy:
    """Mimics mnumber_t for .nnn.value access."""

    __slots__ = ("value",)

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

    __slots__ = ("off",)

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
        if hasattr(other, "off"):
            return self.off == other.off
        return NotImplemented

    def __hash__(self):
        return hash(self.off)


class _LvarProxy:
    """Mimics lvar_ref_t for .l.idx/.l.off access."""

    __slots__ = ("idx", "off")

    def __init__(self, idx: int, off: int):
        self.idx = idx
        self.off = off

    def __eq__(self, other):
        if isinstance(other, _LvarProxy):
            return self.idx == other.idx and self.off == other.off
        if hasattr(other, "idx") and hasattr(other, "off"):
            return self.idx == other.idx and self.off == other.off
        return NotImplemented

    def __hash__(self):
        return hash((self.idx, self.off))


@dataclass(frozen=True, slots=True)
class MopSnapshot:
    """Immutable, pure-Python snapshot of an ida_hexrays.mop_t.

    Use ``MopSnapshot.from_mop(mop)`` to capture values from a live
    (possibly borrowed) mop_t. For complex operand kinds we retain an
    owned clone to allow faithful reconstruction.

    >>> snap = MopSnapshot.from_mop(some_mop)
    >>> snap.t        # operand type (mop_n, mop_r, etc.)
    >>> snap.value    # numeric value if mop_n, else None
    """

    t: int
    size: int
    valnum: int = 0
    # Type-specific fields - only the relevant one is set per type.
    value: int | None = None  # mop_n: nnn.value
    reg: int | None = None  # mop_r: r
    stkoff: int | None = None  # mop_S: s.off (if s is not None)
    gaddr: int | None = None  # mop_v: g
    lvar_idx: int | None = None  # mop_l: l.idx
    lvar_off: int | None = None  # mop_l: l.off
    block_num: int | None = None  # mop_b: b
    helper_name: str | None = None  # mop_h: helper (helper function name)
    const_str: str | None = None  # mop_str: cstr
    pair_lo_t: int | None = None  # mop_p: pair.lop.t
    pair_hi_t: int | None = None  # mop_p: pair.hop.t
    # Owned clone for operand types that cannot be rebuilt from scalar fields.
    # Excluded from dataclass equality/hash to keep structural semantics stable.
    owned_mop: object | None = field(
        default=None, compare=False, hash=False, repr=False
    )

    @classmethod
    def from_mop(cls, mop: ida_hexrays.mop_t) -> MopSnapshot:
        """Create a snapshot from a live mop_t.

        Extracts scalar Python-native values in a single pass and, for
        non-scalar operands, keeps an owned mop_t clone. Safe to call on
        both owned and borrowed mops.
        """
        t = mop.t
        base: dict = dict(t=t, size=mop.size, valnum=getattr(mop, "valnum", 0))
        needs_owned_clone = t in {
            ida_hexrays.mop_d,  # nested instruction
            ida_hexrays.mop_f,  # argument list
            ida_hexrays.mop_a,  # address operand
            ida_hexrays.mop_c,  # switch cases
            ida_hexrays.mop_p,  # pair
            # ``mop_r`` is scalar, but rebuilding it through ``make_reg``
            # drops its microcode valnum. Keep an owned clone so a structural
            # replacement retains the exact live operand identity required by
            # the native MBA proof gate.
            ida_hexrays.mop_r,
            ida_hexrays.mop_S,  # stack var (requires mba_t to synthesize)
            ida_hexrays.mop_l,  # local var (requires mba_t to synthesize)
            ida_hexrays.mop_str,  # string literal
        }
        if needs_owned_clone:
            try:
                owned = ida_hexrays.mop_t()
                owned.assign(mop)
                base["owned_mop"] = owned
            except Exception:
                # Keep scalar snapshot usable even if clone fails.
                pass

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
            pass  # Sub-instruction - AST layer handles recursion
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
            self.t,
            self.size,
            self.valnum,
            self.value,
            self.reg,
            self.stkoff,
            self.gaddr,
            self.lvar_idx,
            self.lvar_off,
            self.block_num,
            self.helper_name,
            self.const_str,
        )

    def to_mop(self, mba: ida_hexrays.mba_t | None = None) -> ida_hexrays.mop_t:
        """Reconstruct a fresh (owned) mop_t from this snapshot.

        Used by AstLeaf.create_mop() to materialize a writeable operand
        from a cached snapshot.  The returned mop_t is owned by the caller
        and safe to pass to assign() or other IDA APIs.

        ``mop_S`` embeds an MBA-owned ``stkvar_ref_t``.  When a destination
        MBA is available, rebuild that reference through ``make_stkvar``
        before considering the cached clone; assigning the clone preserves
        its source MBA and can fault in native def/use APIs.
        """
        m = ida_hexrays.mop_t()
        if self.t == ida_hexrays.mop_S and self.stkoff is not None and mba is not None:
            m.make_stkvar(mba, self.stkoff)
            m.size = self.size
            return m
        # Prefer the owned clone when available. This preserves complex
        # operands (e.g., mop_d) and stack/local refs exactly.
        if self.owned_mop is not None:
            try:
                m.assign(self.owned_mop)
                return m
            except Exception:
                logger.warning(
                    "to_mop: failed to assign owned_mop for type %s, falling back",
                    self.t,
                )
        if self.t == ida_hexrays.mop_n and self.value is not None:
            safe_make_number(m, self.value, self.size)
        elif self.t == ida_hexrays.mop_r and self.reg is not None:
            m.make_reg(self.reg, self.size)
        elif self.t == ida_hexrays.mop_S and self.stkoff is not None:
            # Old IDA builds exposed make_stkvar(off, size). Newer builds
            # require mba_t; without it we cannot synthesize mop_S safely.
            try:
                m.make_stkvar(self.stkoff, self.size)
            except TypeError:
                logger.warning(
                    "to_mop: Cannot reconstruct mop_S without mba_t, returning empty mop"
                )
        elif self.t == ida_hexrays.mop_v and self.gaddr is not None:
            m.make_gvar(self.gaddr)
            m.size = self.size
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

    # === Duck-typing layer: property aliases for mop_t attribute compatibility ===

    # Category A: Simple property aliases
    @property
    def r(self) -> int | None:
        """Alias for .reg (mop_r register number)."""
        return self.reg

    @property
    def g(self) -> int | None:
        """Alias for .gaddr (mop_v global address)."""
        return self.gaddr

    @property
    def b(self) -> int | None:
        """Alias for .block_num (mop_b block reference)."""
        return self.block_num

    @property
    def helper(self) -> str | None:
        """Alias for .helper_name (mop_h helper function name)."""
        return self.helper_name

    @property
    def cstr(self) -> str | None:
        """Alias for .const_str (mop_str string literal)."""
        return self.const_str

    # Category B: Proxy objects for sub-attributes
    @property
    def nnn(self) -> _NnnProxy | None:
        """Proxy for mnumber_t (.nnn.value access)."""
        return _NnnProxy(self.value) if self.value is not None else None

    @property
    def s(self) -> _StkvarProxy | None:
        """Proxy for stkvar_ref_t (.s.off access)."""
        return _StkvarProxy(self.stkoff) if self.stkoff is not None else None

    @property
    def l(self) -> _LvarProxy | None:
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
        if name.startswith("_"):
            raise AttributeError(name)
        owned = object.__getattribute__(self, "owned_mop")
        if owned is not None:
            return getattr(owned, name)
        raise AttributeError(
            f"'MopSnapshot' object has no attribute '{name}' (no owned_mop)"
        )


# Try to import Cython speedups if CythonMode is enabled
if CythonMode().is_enabled():
    try:
        from d810.speedups.cythxr.mop_snapshot import MopSnapshot
    except ImportError:
        pass

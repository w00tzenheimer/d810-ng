# cython: language_level=3, embedsignature=True
# distutils: language=c++
from libcpp.unordered_map cimport unordered_map
from libcpp.pair cimport pair
from cython.operator cimport dereference as deref
from libc.stdint cimport uintptr_t

from ._chexrays cimport (
    mop_t,
    ea_t,
    uint32,
    uint64,
    sval_t,
    MOPT,
    minsn_t,
    mop_addr_t,
    mop_pair_t,
    qstring,
    stkvar_ref_t,
    get_mreg_name,
    OPERAND_PROPERTIES,
    _swig_ptr,
)



# ---------- tiny hash combiner (FNV-1a-ish) ----------
cdef uint64 _mix64(uint64 h, uint64 x) noexcept nogil:
    h ^= x + 0x9e3779b97f4a7c15ULL + (h<<6) + (h>>2)
    return h


cdef uint64 _mask_nbits(uint64 v, int size) noexcept nogil:
    if size <= 0 or size > 16:
        return v
    if size == 8:    # common case
        return v & 0xFFFFFFFFFFFFFFFFULL
    return v & ((1ULL << (size * 8)) - 1ULL)


# ---------- core recursive hasher ----------
cdef uint64 _hash_mop_ptr(const mop_t* op,
                            ea_t func_ea,
                            unordered_map[uintptr_t, uint64]* insn_memo,
                            int depth) noexcept nogil:
    cdef:
        int t
        int sz
        uint32 oprops
        uint64 h
        const minsn_t* m
        uintptr_t key
        unordered_map[uintptr_t, uint64].iterator it
        uint64 mh
        const mop_addr_t* ap
        mop_pair_t* pr

    if op == NULL or depth > 128:
        return 0xDEADBEAFULL  # nil

    # common fields
    t = <int>op.t
    sz = <int>op.size
    oprops = (<uint32>op.oprops) & (OPERAND_PROPERTIES.OPROP_FLOAT|OPERAND_PROPERTIES.OPROP_UDT|OPERAND_PROPERTIES.OPROP_CCFLAGS|OPERAND_PROPERTIES.OPROP_LOWADDR)
    h = 0xCBF29CE484222325ULL

    h = _mix64(h, <uint64>t)
    h = _mix64(h, <uint64>sz)
    h = _mix64(h, <uint64>oprops)

    if t == MOPT.REGISTER:   # microregister
        return _mix64(h, <uint64>op.r)
    if t == MOPT.NUMBER:   # immediate
        return _mix64(h, _mask_nbits(<uint64>op.nnn.value, sz))
    if t == MOPT.GLOBAL:   # global EA
        return _mix64(h, <uint64>op.g)
    if t == MOPT.STACK:   # stack var
        h = _mix64(h, func_ea)
        return _mix64(h, <uint64>op.s.off)
    if t == MOPT.LOCAL:   # lvar ref
        h = _mix64(h, func_ea)
        h = _mix64(h, <uint64>op.l.idx)
        return _mix64(h, <uint64>op.l.off)
    if t == MOPT.ADDRESS:   # address-of
        ap = op.a
        h = _mix64(h, <uint64>ap.insize)
        h = _mix64(h, <uint64>ap.outsize)
        return _mix64(h, _hash_mop_ptr(<const mop_t*>ap, func_ea, insn_memo, depth+1))
    if t == MOPT.PAIR:   # pair (low/high)
        pr = op.pair
        h = _mix64(h, _hash_mop_ptr(<const mop_t*>&pr.lop, func_ea, insn_memo, depth+1))
        return _mix64(h, _hash_mop_ptr(<const mop_t*>&pr.hop, func_ea, insn_memo, depth+1))
    if t == MOPT.DEST_RESULT:   # result of subinstruction
        m = op.d
        key = <uintptr_t>m
        it = insn_memo.find(key)
        if it != insn_memo.end():
            return _mix64(h, (<uint64>deref(it).second))
        # compute once
        mh = 0x1234567812345678ULL
        mh = _mix64(mh, <uint64>m.opcode)
        mh = _mix64(mh, _hash_mop_ptr(&m.l, func_ea, insn_memo, depth+1))
        mh = _mix64(mh, _hash_mop_ptr(&m.r, func_ea, insn_memo, depth+1))
        mh = _mix64(mh, _hash_mop_ptr(&m.d, func_ea, insn_memo, depth+1))
        insn_memo.insert(pair[uintptr_t, uint64](key, mh))
        return _mix64(h, mh)

    # Rare kinds: produce a cheap, bounded structural salt (no strings).
    # if t == MOPT.SCATTERED:
    #     # scattered has a reg count + regs[] in most builds
    #     try:
    #         h = _mix64(h, <uint64>op.scif.nregs)
    #         for i in range(op.scattered.nregs if op.scattered.nregs < 8 else 8):
    #             h = _mix64(h, <uint64>op.scattered.regs[i])
    #         return h
    #     except Exception:
    #         pass

    # Unknown/rare kinds => tag with kind to avoid collapses
    return _mix64(h, 0xFACEB00CULL + <uint64>t)

# (Python API implemented in _chexrays_api.pyx)
cpdef uint64 hash_mop(object py_mop, uint64 func_entry_ea=0):
    """Return a stable structural hash for a Hex-Rays mop_t (no dstr()).

    The hash is salted with the function entry EA to distinguish stack/local
    references across functions. If unknown, pass 0.
    """
    cdef const mop_t* op = <const mop_t*> _swig_ptr(py_mop)
    cdef unordered_map[uintptr_t, uint64] memo
    return _hash_mop_ptr(op, <ea_t>func_entry_ea, &memo, 0)


cdef qstring stack_var_name(mop_t* op):
    cdef:
        qstring name
        qstring empty
        stkvar_ref_t* s_ptr
        sval_t ida_off
        sval_t disp

    if op.t == MOPT.STACK:
        s_ptr = <stkvar_ref_t*> op.s
        if s_ptr != NULL:
            if s_ptr.mba != NULL and s_ptr.mba.use_frame():
                # Compute IDA frame offset once, then classify via frame layout.
                ida_off = s_ptr.mba.stkoff_vd2ida(s_ptr.off)
                if ida_off < s_ptr.mba.frsize:
                    # Local: displacement from end of locals region
                    disp = s_ptr.mba.frsize - ida_off
                    name.sprnt("%%var_%X.%d", <unsigned>(disp), op.size)
                elif ida_off >= s_ptr.mba.inargoff:
                    # Argument: displacement from first argument
                    disp = ida_off - s_ptr.mba.inargoff
                    name.sprnt("arg_%X.%d", <unsigned>(disp), op.size)
                else:
                    # Middle area (saved regs/retaddr): fall back to raw labeling
                    name.sprnt("stk_%llX.%d", <uint64> s_ptr.off, op.size)
            else:
                # No frame information; fall back to raw vd off
                name.sprnt("stk_%llX.%d", <uint64> s_ptr.off, op.size)
            name.cat_sprnt("{%d}", op.valnum)
            return name
    elif op.t == MOPT.REGISTER:
        get_mreg_name(&name, op.r, op.size, <void*>NULL)
        name.cat_sprnt("{%d}", op.valnum)
        return name

    return empty

cpdef str get_stack_or_reg_name(object py_mop):
    """Return canonical name for stack/register mop, or "" if not applicable.

    Matches Hex-Rays dstr() formatting for stack/register without calling dstr().
    For stack operands with a frame: locals => "%var_%X.<size>", args => "arg_%X.<size>".
    Appends SSA valnum as "{n}".
    """
    cdef mop_t* op = <mop_t*> _swig_ptr(py_mop)
    return stack_var_name(op).c_str().decode('utf-8')
    # cdef qstring name
    # cdef bytes b
    # cdef stkvar_ref_t* s_ptr
    # cdef sval_t disp
    # cdef sval_t ida_off
    # cdef bint is_local
    # if op == NULL:
    #     return ""
    # if op.t == MOPT.STACK:
    #     s_ptr = <stkvar_ref_t*> op.s
    #     if s_ptr != NULL:
    #         if s_ptr.mba != NULL and s_ptr.mba.use_frame():
    #             # Compute IDA frame offset once, then classify via frame layout.
    #             ida_off = s_ptr.mba.stkoff_vd2ida(s_ptr.off)
    #             if ida_off < s_ptr.mba.frsize:
    #                 # Local: displacement from end of locals region
    #                 is_local = 1
    #                 disp = s_ptr.mba.frsize - ida_off
    #                 name.sprnt("%%var_%X.%d", <unsigned>(disp), op.size)
    #             elif ida_off >= s_ptr.mba.inargoff:
    #                 # Argument: displacement from first argument
    #                 is_local = 0
    #                 disp = ida_off - s_ptr.mba.inargoff
    #                 name.sprnt("arg_%X.%d", <unsigned>(disp), op.size)
    #             else:
    #                 # Middle area (saved regs/retaddr): fall back to raw labeling
    #                 name.sprnt("stk_%llX.%d", <unsigned long long> s_ptr.off, op.size)
    #         else:
    #             # No frame information; fall back to raw vd off
    #             name.sprnt("stk_%llX.%d", <unsigned long long> s_ptr.off, op.size)
    #         name.cat_sprnt("{%d}", op.valnum)
    #         b = name.c_str()
    #         return b.decode('utf-8')
    #     return ""
    # elif op.t == MOPT.REGISTER:
    #     get_mreg_name(&name, op.r, op.size, <void*>NULL)
    #     name.cat_sprnt("{%d}", op.valnum)
    #     b = name.c_str()
    #     return b.decode('utf-8')
    # return ""

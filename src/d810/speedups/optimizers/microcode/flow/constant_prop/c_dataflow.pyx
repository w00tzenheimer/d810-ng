# cython: language_level=3, embedsignature=True
# distutils: language=c++
# distutils: define_macros=__EA64__=1
"""
Simplified, container-free Cython implementation for constant-propagation data-flow.
This purposefully drops all C++ STL usage.  We only keep raw Hex-Rays SDK structs
and convert everything to plain Python data-structures at the API boundary.

Only three tiny helpers remain in C: they inspect a handful of `mop_t` / `minsn_t`
fields that are heavily used in the data-flow loop.  Everything else happens
in Python space which drastically reduces the surface-area for Cython-level
compiler errors while still giving us the hot-path speed-up we want.
"""
from cython.operator cimport preincrement as inc
from cython.operator cimport dereference as deref
from libcpp.map cimport map as cpp_map
from libcpp.utility cimport pair
import logging as _logging

# Module-level logger aligned with Python rule logger
py_logger = _logging.getLogger("d810.optimizers.microcode.flow.constant_prop.stackvars_constprop")
cdef bint debug_on = <bint>False

# ---------------------------------------------------------------------------
#  Raw C declarations from sibling pxd
# ---------------------------------------------------------------------------
from d810.speedups.cythxr._chexrays cimport (
    SwigPyObject,
    uint,
    uint64,
    intvec_t,
    qstring,
    qvector,
    mop_t,
    minsn_t,
    mba_t,
    get_mreg_name,
    mblock_t,
    sval_t,
    mop_t_ptr,
    mop_off_pair_t,
    MOPT,
    mcode_t,
    stkvar_ref_t,
    const_val_t,
    CppConstMap ,
    mnumber_t,
    mcallinfo_t,
    LOCOPT_FLAGS,
)
from d810.speedups.cythxr._chexrays_api cimport stack_var_name as _stack_var_name

# ---------------------------------------------------------------------------
#  Tiny helpers – still in C for speed
# ---------------------------------------------------------------------------

cdef inline uint64 _mask_for_bytes(int num_bytes):
    """Return an all-ones mask for the given byte width (1..8)."""
    if num_bytes >= 8:
        return <uint64>0xFFFFFFFFFFFFFFFF
    return (<uint64>1 << (num_bytes * 8)) - <uint64>1

cdef sval_t _get_mba_frame_size(mba_t* mba):
    """Return cached frame size for an MBA. Uses object identity as cache key.

    Returns `int` or `None`.
    """
    if not mba:
        return 0
    if mba.frsize:
        return mba.frsize
    if mba.stacksize:
        return mba.stacksize
    py_logger.warning("mba.frsize and mba.stacksize are 0, using minstkref and fullsize")
    if mba.minstkref:
        return mba.minstkref
    if mba.fullsize:
        return mba.fullsize
    return 0

# cdef inline qstring _stack_var_name(mop_t* mop):
#     cdef qstring rname
#     cdef stkvar_ref_t* s_ptr
#     cdef sval_t ida_off
#     if mop.t == MOPT.STACK:
#         s_ptr = <stkvar_ref_t*> mop.s
#         if s_ptr.mba != NULL and s_ptr.mba.use_frame():
#             ida_off = s_ptr.mba.stkoff_vd2ida(s_ptr.off)
#             rname.sprnt("var_%X.%d", <unsigned>(ida_off), mop.size)
#             # else:
#             #     rname.sprnt("arg_%X.%d", <unsigned>(ida_off), mop.size)
#         else:
#             rname.sprnt("stk_%llX.%d", <unsigned long long> s_ptr.off, mop.size)
#         rname.cat_sprnt("{%d}", mop.valnum)
#         return rname

#     elif mop.t == MOPT.REGISTER:
#         get_mreg_name(&rname, mop.r, mop.size, <void*>NULL)
#         rname.cat_sprnt("{%d}", mop.valnum)
#         return rname

#     cdef qstring empty
#     return empty

# cdef inline qstring _stack_var_name(mop_t* mop):
#     """Return qstring with the canonical name of a stack/register var."""
#     cdef:
#         qstring empty
#         qstring rname
#         stkvar_ref_t* s_ptr
#         int frame_size
#         int disp

#     if mop.t == MOPT.STACK:
#         s_ptr = <stkvar_ref_t*>(&mop.s)
#         frame_size = _get_mba_frame_size(s_ptr.mba)
#         if frame_size >= s_ptr.off:
#             disp = frame_size - s_ptr.off
#             rname.sprnt("%%var_%X.%d", disp, mop.size)
#         else:
#             rname.sprnt("stk_%llX.%d", s_ptr.off, mop.size)
#         # Match Python helper: append value number in braces
#         rname.cat_sprnt("{%d}", mop.valnum)
#         return rname

#     elif mop.t == MOPT.REGISTER:
#         get_mreg_name(&rname, mop.r, mop.size, <void*>NULL)
#         # The Python helper formats registers as "reg{valnum}" (no .size)
#         rname.cat_sprnt("{%d}", mop.valnum)
#         return rname
#     return empty


cdef inline mop_off_pair_t _extract_base_and_offset(mop_t* mop):
    """Return pointer to base mop if pattern (base + const) else NULL; stores offset."""
    cdef:
        mop_off_pair_t result

    if mop.t == MOPT.DEST_RESULT and mop.d != NULL and mop.d.opcode == mcode_t.m_add:
        if mop.d.l.t in (MOPT.STACK, MOPT.REGISTER):
            result.first = <mop_t_ptr>&mop.d.l
            result.second = mop.d.r.nnn.value if mop.d.r.t == MOPT.NUMBER else 0
            return result
        if mop.d.r.t in (MOPT.STACK, MOPT.REGISTER):
            result.first = <mop_t_ptr>&mop.d.r
            result.second = mop.d.l.nnn.value if mop.d.l.t == MOPT.NUMBER else 0
            return result
    result.first = <mop_t_ptr>NULL
    result.second = 0
    return result


cdef inline qstring _get_written_var_name(minsn_t* ins):
    """Return the variable name written by *ins or "" if none."""
    cdef:
        mop_t* d = &ins.d
        mop_t* base
        qstring base_name
        mop_off_pair_t result
        qstring empty

    if d.t in (MOPT.STACK, MOPT.REGISTER):
        return _stack_var_name(d)


    if ins.opcode == mcode_t.m_stx:
        result = _extract_base_and_offset(d)
        if result.first != NULL:
            base_name = _stack_var_name(result.first)
            if not base_name.empty():
                if result.second:
                    base_name.cat_sprnt("+%llX", result.second)
                return base_name
    return empty



cdef inline bint _is_constant_stack_assignment(minsn_t* ins):
    """True if instruction assigns a constant to a stack/register var."""
    cdef:
        mop_t* base
        mop_off_pair_t result

    if ins.l.t != MOPT.NUMBER:
        return <bint>False
    if ins.opcode == mcode_t.m_mov and ins.d.t in (MOPT.STACK, MOPT.REGISTER):
        return <bint>True
    if ins.opcode == mcode_t.m_stx:
        if ins.d.t == MOPT.STACK:
            return <bint>True
        result = _extract_base_and_offset(&ins.d)
        return result.first != NULL
    return <bint>False

# ---------------------------------------------------------------------------
#  Map & iteration helpers (hide iterator casting, make meet/transfer readable)
# ---------------------------------------------------------------------------

# NOTE:
# We previously exposed `_key_of`/`_val_of` helpers that cast the iterator
# storage to `pair[const qstring, const_val_t]` in order to access `.first/
# .second`. Cython chokes on `const` template args for non-trivial classes
# like `qstring`, producing errors such as "Cannot assign type 'long' to
# 'const T'". To avoid this, we now access keys/values directly using
# `deref(it).first` / `deref(it).second` at call sites.

cdef inline bint _map_equals(const CppConstMap& a, const CppConstMap& b):
    if a.size() != b.size():
        return False
    cdef CppConstMap.const_iterator it = a.begin()
    cdef CppConstMap.const_iterator f
    cdef const_val_t av, bv
    while it != a.end():
        f = b.find(deref(it).first)       # was: cast to pair[...] then .first
        if f == b.end():
            return False
        av = deref(it).second             # was: cast to pair[...] then .second
        bv = deref(f).second
        if av.first != bv.first or av.second != bv.second:
            return False
        inc(it)
    return True

cdef inline void _map_assign(CppConstMap& dst, const CppConstMap& src):
    dst = src  # C++ copy

# Intersect OUT of predecessors into 'inm'
cdef void _meet_preds(
    size_t b,
    qvector[intvec_t]& preds,
    qvector[CppConstMap]& OUT_cpp,
    CppConstMap& inm
):
    inm.clear()
    if preds[b].empty():
        return

    # Seed with first predecessor's OUT (copy if present)
    cdef unsigned int p0 = preds[b][0]
    if p0 < OUT_cpp.size():
        inm = OUT_cpp[p0]
    else:
        inm.clear()

    # Intersect with remaining predecessors
    cdef size_t i
    cdef unsigned int p
    cdef CppConstMap.iterator it
    cdef CppConstMap.iterator f
    cdef const_val_t v, w

    for i in range(1, preds[b].size()):
        p = preds[b][i]
        it = inm.begin()
        while it != inm.end():
            if p < OUT_cpp.size():
                f = OUT_cpp[p].find(deref(it).first)
                if f != OUT_cpp[p].end():
                    v = deref(it).second
                    w = deref(f).second
                    if v.first == w.first and v.second == w.second:
                        inc(it)
                        continue
            it = inm.erase(it)

cdef inline void _transfer_insn(mblock_t* blk, minsn_t* ins, CppConstMap& env):
    # conservative side-effects handling
    if ins.is_unknown_call():  # or opcode test if needed
        env.clear()
        return

    cdef bint is_const = _is_constant_stack_assignment(ins)
    cdef qstring name = _get_written_var_name(ins)
    if not is_const:
        if not name.empty():
            env.erase(name)
        return

    cdef qstring var_name
    cdef mop_off_pair_t pair

    if ins.opcode == mcode_t.m_mov or ins.d.t in (MOPT.STACK, MOPT.REGISTER):
        var_name = _stack_var_name(&ins.d)
    else:
        pair = _extract_base_and_offset(&ins.d)
        if pair.first != NULL:
            var_name = _stack_var_name(pair.first)
            if not var_name.empty() and pair.second:
                var_name.cat_sprnt("+%llX", pair.second)

    if not var_name.empty():
        env[var_name] = const_val_t(ins.l.nnn.value, ins.l.size)


cdef inline void _clear_on_side_effect(minsn_t* ins, CppConstMap& env):
    if ins.has_side_effects(False) and ins.opcode != mcode_t.m_stx:
        env.clear()

# Block transfer: OUTb = F_b(INb)
cdef void _transfer_block(mblock_t* blk, const CppConstMap& INb, CppConstMap& OUTb):
    OUTb = INb  # start from IN
    # Cython cannot declare C++ references in local scope; operate on OUTb directly.
    cdef minsn_t* ins = blk.head
    cdef bint is_const
    cdef qstring name, var_name
    cdef mop_off_pair_t res_pair


    while ins:
        _clear_on_side_effect(ins, OUTb)

        name = _get_written_var_name(ins)
        is_const = _is_constant_stack_assignment(ins)

        if not is_const:
            if not name.empty():
                OUTb.erase(name)
        else:
            if ins.opcode == mcode_t.m_mov:
                var_name = _stack_var_name(&ins.d)
            elif ins.d.t in (MOPT.STACK, MOPT.REGISTER):
                var_name = _stack_var_name(&ins.d)
            else:
                res_pair = _extract_base_and_offset(&ins.d)
                if res_pair.first != NULL:
                    var_name = _stack_var_name(res_pair.first)
                    if not var_name.empty() and res_pair.second:
                        var_name.cat_sprnt("+%llX", res_pair.second)

            if not var_name.empty():
                OUTb[var_name] = const_val_t(ins.l.nnn.value, ins.l.size)

        ins = ins.next

# C-level rewrite helper for the full pass
cdef bint _rewrite_instruction_c(minsn_t* ins, CppConstMap& consts):
    """C-level rewrite helper. Operates on C++ map directly."""
    cdef bint changed = <bint>False
    cdef uint64 lval, rval, res
    cdef bint can_fold
    cdef mop_t nm, zr
    cdef int dsize

    if _cy_process_operand(&ins.l, consts): changed = <bint>True
    if _cy_process_operand(&ins.r, consts): changed = <bint>True
    if ins.opcode == mcode_t.m_stx and _cy_process_operand(&ins.d, consts):
        changed = <bint>True

    if changed:
        ins.optimize_solo(0)

    # NOTE: The constant folding logic from the Python wrapper is omitted here
    # for simplicity, but could be added if needed. The primary gain is from
    # operand processing.

    return changed

# ---------------------------------------------------------------------------
#  Python-callable wrappers (cpdef)
# ---------------------------------------------------------------------------

cpdef str cy_get_written_var_name(object ins_py):
    """Python wrapper for _get_written_var_name."""
    cdef SwigPyObject* swig_obj = <SwigPyObject*>ins_py.this
    cdef minsn_t* ins = <minsn_t*>swig_obj.ptr
    cdef qstring qn = _get_written_var_name(ins)
    cdef bytes b
    b = qn.c_str()
    return b.decode('utf-8')


cpdef cy_is_constant_stack_assignment(object ins_py):
    """Python wrapper for _is_constant_stack_assignment."""
    cdef SwigPyObject* swig_obj = <SwigPyObject*>ins_py.this
    cdef minsn_t* ins = <minsn_t*>swig_obj.ptr
    return bool(_is_constant_stack_assignment(ins))


cpdef cy_extract_assignment(object ins_py):
    """Extracts (var_name, (value, size)) from a constant assignment."""
    cdef SwigPyObject* swig_obj = <SwigPyObject*>ins_py.this
    cdef minsn_t* ins = <minsn_t*>swig_obj.ptr
    cdef:
        mop_off_pair_t result
        qstring var_name

    if not _is_constant_stack_assignment(ins):
        return None

    cdef uint64 value = ins.l.nnn.value
    cdef int size = ins.l.size
    if ins.opcode == mcode_t.m_mov:
        var_name = _stack_var_name(&ins.d)
    elif ins.d.t in {MOPT.STACK, MOPT.REGISTER}:
        var_name = _stack_var_name(&ins.d)
    else:
        result = _extract_base_and_offset(&ins.d)
        if result.first != NULL:
            var_name = _stack_var_name(result.first)
            if not var_name.empty():
                if result.second:
                    var_name.cat_sprnt("+%llX", result.second)

    if var_name.empty():
        return None
    cdef bytes bname
    bname = var_name.c_str()
    return (bname.decode('utf-8'), (value, size))


cdef bint _cy_process_operand(mop_t* op, CppConstMap& consts):
    """C-level recursive function to replace variables with constants."""
    cdef:
        bint changed = <bint>False
        qstring name
        mop_off_pair_t result
        CppConstMap.iterator it
        uint64 val
        int size
        mop_t temp_mop
        mcallinfo_t* f_ptr
        size_t i
        mop_t* addr
        qstring base_name
        qstring full_name
        bint const_info_found

    if op.t == MOPT.STACK or op.t == MOPT.REGISTER:
        name = _stack_var_name(op)
        if not name.empty():
            it = consts.find(name)
            if it != consts.end():
                val = deref(it).second.first
                temp_mop.make_number(val & _mask_for_bytes(op.size), op.size)
                op.assign(temp_mop)
                return <bint>True
    elif op.t == MOPT.DEST_RESULT and op.d != NULL:
        # Special-case: fold loads from memory when the address is a known constant
        if op.d.opcode == mcode_t.m_ldx:
            addr = &op.d.r
            const_info_found = <bint>False

            if addr.t == MOPT.STACK or addr.t == MOPT.REGISTER:
                name = _stack_var_name(addr)
                it = consts.find(name)
                if it != consts.end():
                    const_info_found = <bint>True
            else:
                result = _extract_base_and_offset(addr)
                if result.first != NULL:
                    base_name = _stack_var_name(result.first)
                    if not base_name.empty():
                        if result.second:
                            full_name = base_name
                            full_name.cat_sprnt("+%llX", result.second)
                        else:
                            full_name = base_name
                        it = consts.find(full_name)
                        if it != consts.end():
                            const_info_found = <bint>True

            if const_info_found:
                val = deref(it).second.first
                temp_mop.make_number(val & _mask_for_bytes(op.size), op.size)
                op.assign(temp_mop)
                return <bint>True

        # Generic recursion on sub-operands
        if _cy_process_operand(&op.d.l, consts):
            changed = <bint>True
        if _cy_process_operand(&op.d.r, consts):
            changed = <bint>True
        if changed:
            op.d.optimize_solo(0)
        return changed
    elif op.t == MOPT.ARGUMENT_LIST and op.f != NULL:
        f_ptr = <mcallinfo_t*>op.f
        for i in range(f_ptr.args.size()):
             if _cy_process_operand(&f_ptr.args.at(i), consts):
                 changed = <bint>True
        return changed
    return <bint>False


cpdef int cy_rewrite_instruction(object ins_py, dict consts_py):
    """Public wrapper to process a single instruction's operands."""
    cdef SwigPyObject* swig_obj = <SwigPyObject*>ins_py.this
    cdef minsn_t* ins = <minsn_t*>swig_obj.ptr
    cdef bint changed = <bint>False
    cdef uint64 lval
    cdef uint64 rval
    cdef uint64 res
    cdef bint can_fold
    cdef mop_t nm
    cdef mop_t zr
    cdef int dsize
    cdef bytes b_string

    cdef CppConstMap consts
    cdef qstring key
    for py_key, py_val in consts_py.items():
        b_string = py_key.encode('utf-8')
        key = qstring(<char*>b_string)
        consts[key] = const_val_t(py_val[0], py_val[1])

    if _cy_process_operand(&ins.l, consts):
        changed = <bint>True
    if _cy_process_operand(&ins.r, consts):
        changed = <bint>True
    if ins.opcode == mcode_t.m_stx and _cy_process_operand(&ins.d, consts):
        changed = <bint>True

    # Let Hex-Rays perform local simplifications before folding whole instruction
    if changed:
        ins.optimize_solo(0)

    # If both operands are immediates for a pure binary op, fold to MOV
    if ins.d.t in (MOPT.STACK, MOPT.REGISTER) and ins.l.t == MOPT.NUMBER and ins.r.t == MOPT.NUMBER:
        lval = ins.l.nnn.value
        rval = ins.r.nnn.value
        res = 0
        can_fold = <bint>False
        if ins.opcode == mcode_t.m_or:
            res = lval | rval; can_fold = <bint>True
        elif ins.opcode == mcode_t.m_and:
            res = lval & rval; can_fold = <bint>True
        elif ins.opcode == mcode_t.m_xor:
            res = lval ^ rval; can_fold = <bint>True
        elif ins.opcode == mcode_t.m_add:
            res = lval + rval; can_fold = <bint>True
        elif ins.opcode == mcode_t.m_sub:
            res = lval - rval; can_fold = <bint>True
        elif ins.opcode == mcode_t.m_mul:
            res = lval * rval; can_fold = <bint>True
        elif ins.opcode == mcode_t.m_shl:
            res = lval << (rval & 0x3F); can_fold = <bint>True
        elif ins.opcode == mcode_t.m_shr or ins.opcode == mcode_t.m_sar:
            res = lval >> (rval & 0x3F); can_fold = <bint>True
        if can_fold:
            dsize = ins.d.size if ins.d.size != 0 else ins.l.size
            nm.make_number(res & _mask_for_bytes(dsize), dsize)
            ins.opcode = mcode_t.m_mov
            ins.l.assign(nm)
            # Clear r by assigning a neutral mop_t() declared above
            zr.make_number(0, ins.r.size if ins.r.size != 0 else dsize)
            ins.r.assign(zr)
            changed = <bint>True

    if not changed:
        return 0
    # In case we just folded to MOV or further changes occurred, re-run local opt
    ins.optimize_solo(0)
    return 1


# ---------------------------------------------------------------------------
#  Main Dataflow Implementation
# ---------------------------------------------------------------------------

cpdef run_dataflow_cython(object mba_py):
    """Public entry - performs constant-propagation data-flow, returns (IN, OUT)."""
    cdef:
        SwigPyObject* swig_obj = <SwigPyObject*>mba_py.this
        mba_t* mba = <mba_t*>swig_obj.ptr
        uint nb
        qvector[CppConstMap] IN_cpp
        qvector[CppConstMap] OUT_cpp
        qvector[intvec_t] preds
        intvec_t worklist
        mblock_t* blk
        unsigned int b
        intvec_t.iterator it_idx
        CppConstMap inm
        CppConstMap outb

    if not mba:
        raise ValueError("invalid mba_py - cannot get C++ pointer")

    nb = mba.qty
    if debug_on:
        py_logger.debug("Running dataflow analysis on mba %s (blocks=%d)", mba_py, nb)

    # Pre-size analysis vectors to avoid size checks
    IN_cpp.resize_with_default(nb)
    OUT_cpp.resize_with_default(nb)
    preds.resize_with_default(nb)

    # Build predecessor lists once
    for b in range(nb):
        blk = mba.get_mblock(b)
        if not blk:
            continue
        it_idx = blk.predset.begin()
        while it_idx != blk.predset.end():
            preds[b].push_back(it_idx[0])
            inc(it_idx)

    # Seed worklist with all blocks
    for b in range(nb):
        worklist.push_back(b)

    # Main worklist loop
    while not worklist.empty():
        b = worklist.back()
        worklist.pop_back()

        blk = mba.get_mblock(b)
        if not blk:
            continue

        # MEET
        inm.clear()
        _meet_preds(b, preds, OUT_cpp, inm)

        if not _map_equals(inm, IN_cpp[b]):
            _map_assign(IN_cpp[b], inm)

        # TRANSFER
        outb.clear()
        _transfer_block(blk, IN_cpp[b], outb)

        if not _map_equals(outb, OUT_cpp[b]):
            _map_assign(OUT_cpp[b], outb)
            # Push all successors (simple; duplicates are filtered by later equality checks)
            it_idx = blk.succset.begin()
            while it_idx != blk.succset.end():
                worklist.push_back(it_idx[0])
                inc(it_idx)

    if debug_on:
        py_logger.debug("Converting C-level results back to Python dicts")

    # Convert C-level results back to Python dicts
    cdef list IN_py = [{} for _ in range(nb)]
    cdef list OUT_py = [{} for _ in range(nb)]
    cdef CppConstMap.iterator it
    cdef qstring k
    cdef const_val_t v

    for b in range(nb):
        it = IN_cpp[b].begin()
        while it != IN_cpp[b].end():
            k = deref(it).first
            v = deref(it).second
            IN_py[b][k.c_str().decode('utf-8')] = (v.first, v.second)
            inc(it)

        it = OUT_cpp[b].begin()
        while it != OUT_cpp[b].end():
            k = deref(it).first
            v = deref(it).second
            OUT_py[b][k.c_str().decode('utf-8')] = (v.first, v.second)
            inc(it)

    return IN_py, OUT_py

cpdef int cy_run_full_pass(object mba_py):
    """
    Performs the full dataflow and rewrite pass entirely in C-level code,
    minimizing Python-to-C transitions to a single call.
    """
    cdef:
        SwigPyObject* swig_obj = <SwigPyObject*>mba_py.this
        mba_t* mba = <mba_t*>swig_obj.ptr
        uint nb
        qvector[CppConstMap] IN_cpp
        qvector[CppConstMap] OUT_cpp
        qvector[intvec_t] preds
        intvec_t worklist
        mblock_t* curr_blk
        minsn_t* ins
        unsigned int b
        int total_changes = 0
        bint block_was_changed
        bint made_change_this_pass
        intvec_t.iterator it_idx
        CppConstMap inm, outb
        CppConstMap consts

    if not mba:
        return 0
    nb = mba.qty

    # --- Phase A: Dataflow Analysis ---
    # (This is the same logic as run_dataflow_cython)
    IN_cpp.resize_with_default(nb)
    OUT_cpp.resize_with_default(nb)
    preds.resize_with_default(nb)
    for b in range(nb):
        curr_blk = mba.get_mblock(b)
        if not curr_blk: continue
        it_idx = curr_blk.predset.begin()
        while it_idx != curr_blk.predset.end():
            preds[b].push_back(deref(it_idx))
            inc(it_idx)
        worklist.push_back(b)

    while not worklist.empty():
        b = worklist.back()
        worklist.pop_back()
        curr_blk = mba.get_mblock(b)
        if not curr_blk:
            continue

        _meet_preds(b, preds, OUT_cpp, inm)
        if not _map_equals(inm, IN_cpp[b]):
            _map_assign(IN_cpp[b], inm)
        _transfer_block(curr_blk, IN_cpp[b], outb)
        if not _map_equals(outb, OUT_cpp[b]):
            _map_assign(OUT_cpp[b], outb)
            it_idx = curr_blk.succset.begin()
            while it_idx != curr_blk.succset.end():
                worklist.push_back(deref(it_idx))
                inc(it_idx)

    # --- Phase B: Rewrite Loop ---
    curr_blk = mba.get_mblock(0)
    while curr_blk != NULL:
        block_was_changed = <bint>False
        while True:
            consts = IN_cpp[curr_blk.serial]
            ins = curr_blk.head
            made_change_this_pass = <bint>False
            # while ins != NULL:
            #     if _rewrite_instruction_c(ins, consts):
            #         total_changes += 1
            #         made_change_this_pass = <bint>True
            #         block_was_changed = <bint>True
            #         break
            #     _transfer_block(curr_blk, consts, consts) # Re-transfer on the modified map
            #     ins = ins.next
            while ins != NULL:
                if _rewrite_instruction_c(ins, consts):
                    total_changes += 1
                    made_change_this_pass = <bint>True
                    block_was_changed = <bint>True
                    ins.optimize_solo(0)
                    # keep scanning; env already reflects rewrites

                _transfer_insn(curr_blk, ins, consts)  # advance env by 1 insn
                ins = ins.next
            if not made_change_this_pass:
                break

        if block_was_changed:
            curr_blk.mark_lists_dirty()
        curr_blk = curr_blk.nextb

    if total_changes > 0:
        mba.mark_chains_dirty()
        mba.optimize_local(LOCOPT_FLAGS.LOCOPT_ALL)

    return total_changes
 # distutils: language = c++
import cython
from libcpp cimport bool
from libc.stdint cimport uintptr_t
# ===========================================================================
# C++ Definitions from hexrays.hpp
# ===========================================================================

# Import enums and constants first
cdef extern from "hexrays.hpp":
    ctypedef enum mopt_t:
        mop_z, mop_r, mop_n, mop_str, mop_d, mop_S, mop_v, mop_b,
        mop_f, mop_l, mop_a, mop_h, mop_c, mop_fn, mop_p, mop_sc

    ctypedef enum mcode_t:
        m_nop, m_stx, m_ldx, m_mov # Add others as needed

# Forward declare classes to resolve dependencies
cdef extern from "hexrays.hpp":
    cdef cppclass mop_t:
        mopt_t t
        int size
        void make_number(unsigned long long, int, long long, int) nogil
        void assign(const mop_t&) nogil

    cdef cppclass stkvar_ref_t:
        long long off

    cdef cppclass minsn_t:
        mcode_t opcode
        mop_t l, r, d
        void optimize_solo() nogil

# ===========================================================================
# Python Imports
# ===========================================================================
import ida_hexrays

# We still need Python helpers for name resolution & masking
from d810.hexrays.cfg_utils import get_stack_var_name, extract_base_and_offset
from d810.hexrays.hexrays_helpers import AND_TABLE
# Compile-time alias for SWIG proxy; runtime type is ida_hexrays.mop_t
ctypedef object MopProxy
# ===========================================================================
# Cython Implementation
# ===========================================================================


# … existing imports …

cdef inline mop_t* _borrow_mop_ptr(object py_mop):
    """
    Return the underlying C++ mop_t* from a SWIG proxy.

    We cast through uintptr_t to silence Cython's safety check.
    """
    # Expect a SWIG ida_hexrays.mop_t proxy that carries the raw C++ pointer in its
    # attribute "this" (exposed as a Python int).
    cdef uintptr_t raw
    try:
        raw = <uintptr_t> py_mop.this  # type: ignore[attr-defined]
    except AttributeError:
        raise TypeError("expected ida_hexrays.mop_t proxy")
    return <mop_t*> raw

# This is the public function called from Python.
# It takes Python objects and casts them to C++ pointers.
def process_operand_cy(op_py_obj, consts):
    """Public entry: *op_py_obj* is the ida_hexrays.mop_t proxy."""
    return _process_operand_impl(op_py_obj, consts)


cdef bool _process_operand_impl(object root_py_mop, object consts):
    """Iterative operand traversal working with Python proxy objects.

    We maintain Python lists (`worklist`, `post_order`) containing mop_t
    proxies.  The real C++ pointer is borrowed only when we need to access
    struct fields, avoiding conversions back-and-forth.
    """
    cdef list worklist = [root_py_mop]
    cdef list post_order = []
    cdef MopProxy py_mop
    cdef mop_t* op

    cdef bool changed_anything = False
    cdef bool current_op_changed
    cdef str name
    cdef unsigned long long val
    cdef int op_size
    cdef mop_t tmp  # reusable temporary instance

    # 1. Build post-order list ------------------------------------------------
    while worklist:
        py_mop = worklist.pop()
        post_order.append(py_mop)
        op = _borrow_mop_ptr(py_mop)
        if op.t == mop_d and py_mop.d is not None:
            # children are themselves proxies accessible via attributes
            worklist.append(py_mop.d.l)
            worklist.append(py_mop.d.r)

    # 2. Walk in reverse post-order ------------------------------------------
    for py_mop in reversed(post_order):
        op = _borrow_mop_ptr(py_mop)
        current_op_changed = False

        if op.t == mop_S or op.t == mop_r:
            name = get_stack_var_name(py_mop)
            if name is not None and name in consts:
                val, _ = consts[name]
                op_size = op.size
                tmp.make_number(val & AND_TABLE[op_size], op_size, 0, 0)
                op.assign(tmp)
                current_op_changed = True

        elif op.t == mop_d and py_mop.d is not None:
            if py_mop.d.opcode == m_ldx:
                addr_py = py_mop.d.r  # proxy for address operand
                addr = _borrow_mop_ptr(addr_py)
                const_info = None
                if addr.t == mop_S:
                    name = get_stack_var_name(addr_py)
                    if name is not None and name in consts:
                        const_info = consts[name]
                else:
                    base_py, off = extract_base_and_offset(addr_py)
                    if base_py is not None:
                        base_name = get_stack_var_name(base_py)
                        name = f"{base_name}+{off:X}" if off else base_name
                        if name in consts:
                            const_info = consts[name]
                if const_info is not None:
                    val, _ = const_info
                    op_size = op.size
                    tmp.make_number(val & AND_TABLE[op_size], op_size, 0, 0)
                    op.assign(tmp)
                    current_op_changed = True
            if changed_anything:
                py_mop.d.optimize_solo()

        if current_op_changed:
            changed_anything = True

    return changed_anything

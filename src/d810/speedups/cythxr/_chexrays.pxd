# cython: language_level=3, embedsignature=True
# distutils: language=c++
# distutils: define_macros=__EA64__=1
#
# Hex-Rays Microcode API bindings for Cython.
#
# This file imports basic types from SDK-generated pxd files but defines
# complex classes directly because SDK stubs are incomplete (missing methods,
# wrong signatures, missing fields).
#
# SDK imports: Basic typedefs (ea_t, uint64, etc.)
# Local defs:  qvector, _qstring, mop_t, minsn_t, mba_t, mcallinfo_t, etc.
#

from libc.stdint cimport uintptr_t, int64_t
from libc.stddef cimport size_t
from libcpp.pair cimport pair
from libcpp.map cimport map
from libcpp.unordered_map cimport unordered_map
from libcpp.memory cimport shared_ptr
from cpython cimport PyObject, PyObject_GetAttrString
from cython.operator cimport dereference as deref

# =============================================================================
# SDK imports - only basic typedefs that are correct in SDK
# =============================================================================
from .sdk.pro cimport (
    uchar, ushort, uint, uint8, int8, uint16, int16, uint32, int32, uint64, int64,
    ea_t, sel_t, asize_t, adiff_t, uval_t, sval_t, ea32_t, ea64_t, error_t,
    op_dtype_t, inode_t, flags_t, flags64_t, tid_t, bgcolor_t,
)

# =============================================================================
# Full template class definitions (SDK has stubs only)
# =============================================================================

cdef extern from "pro.h":
    ctypedef long long ssize_t

    # Full qvector definition
    cdef cppclass qvector[T]:
        ctypedef T value_type
        qvector() except +
        qvector_from_copy "qvector"(const qvector[T]& x) except +
        void push_back(const T& x) except +
        void push_back_move "push_back"(T&& x) except +
        T& push_back_and_get_ref "push_back"(const T& x) except +
        void pop_back() except +
        size_t size() const
        bint empty() const
        size_t capacity() const
        void reserve(size_t cnt) except +
        void truncate() except +
        const T& const_op_getitem "operator[]"(size_t _idx) const
        T& operator[](size_t _idx)
        const T& const_at "at"(size_t _idx) const
        T& at(size_t _idx)
        const T& const_front "front"() const
        T& front()
        const T& const_back "back"() const
        T& back()
        void qclear() except +
        void clear() except +
        qvector[T]& assign_from_copy "operator="(const qvector[T]& x) except +
        void resize(size_t _newsize, const T& x) except +
        void resize_with_default "resize"(size_t _newsize) except +
        void resize_noinit(size_t _newsize) except +
        void grow(const T& x) except +
        void swap(qvector[T]& r) except +
        T* extract() except +
        void inject(T* s, size_t len) except +
        bint operator==(const qvector[T]& r) const
        bint operator!=(const qvector[T]& r) const
        ctypedef T* iterator
        ctypedef const T* const_iterator
        iterator begin()
        const_iterator const_begin "begin"() const
        iterator end()
        const_iterator const_end "end"() const
        iterator insert_copy "insert"(iterator it, const T& x) except +
        iterator insert_move "insert"(iterator it, T&& x) except +
        iterator erase_at "erase"(iterator it) except +
        iterator erase_range "erase"(iterator first, iterator last) except +

    # Full _qstring definition
    cdef cppclass _qstring[T]:
        _qstring() except +
        _qstring(const T *ptr) except +
        _qstring(const T *ptr, size_t len) except +
        _qstring(size_t count, T ch) except +
        void swap(_qstring[T] &r) except +
        size_t length() const
        size_t size() const
        size_t capacity() const
        void resize(size_t s, T c) except +
        void resize_no_fill "resize"(size_t s) except +
        void remove_last(int cnt=1) except +
        void reserve(size_t cnt) except +
        void clear() except +
        void qclear() except +
        bint empty() const
        const T *c_str() const
        ctypedef T *iterator
        ctypedef const T *const_iterator
        iterator begin()
        const_iterator const_begin "begin"() const
        iterator end()
        const_iterator const_end "end"() const
        _qstring[T]& operator=(const T *str) except +
        _qstring[T]& assign_from_qstring "operator="(const _qstring[T] &qstr) except +
        _qstring[T]& operator_iadd_char "operator+="(T c) except +
        _qstring[T]& operator_iadd_qstring "operator+="(const _qstring[T] &r) except +
        _qstring[T] operator+(const _qstring[T] &r) const
        bint operator==(const _qstring[T]& r) const
        bint operator!=(const _qstring[T]& r) const
        bint operator<(const _qstring[T]& r) const
        bint operator>(const _qstring[T]& r) const
        bint operator<=(const _qstring[T]& r) const
        bint operator>=(const _qstring[T]& r) const
        bint operator_eq_ptr "operator=="(const T *r) const
        bint operator_ne_ptr "operator!=" (const T *r) const
        bint operator_lt_ptr "operator<"(const T *r) const
        bint starts_with_qstring "starts_with"(const _qstring[T] &str) const
        bint starts_with_ptr "starts_with"(const T *ptr, ssize_t len) const
        bint ends_with_qstring "ends_with"(const _qstring[T] &str) const
        bint ends_with_ptr "ends_with"(const T *ptr, ssize_t len) const
        const T& const_op_getitem "operator[]"(size_t idx) const
        T& operator[](size_t idx)
        const T& const_at "at"(size_t idx) const
        T& at(size_t idx) except +
        T last() const
        T *extract() except +
        void inject(T *s, size_t len) except +
        void inject_ptr "inject"(T *s) except +
        size_t find_ptr "find"(const T *str, size_t pos=0) const
        size_t find_qstring "find"(const _qstring[T] &str, size_t pos=0) const
        size_t find_char "find"(T c, size_t pos=0) const
        bint replace(const T *what, const T *with_this) except +
        size_t rfind(T c, size_t pos=0) const
        _qstring[T] substr(size_t pos, size_t n) const
        _qstring[T]& remove(size_t idx, size_t cnt) except +
        _qstring[T]& insert_char_at "insert"(size_t idx, T c) except +
        _qstring[T]& insert_substring_at "insert"(size_t idx, const T *str, size_t addlen) except +
        _qstring[T]& insert_string_at "insert"(size_t idx, const T *str) except +
        _qstring[T]& insert_qstring_at "insert"(size_t idx, const _qstring[T] &qstr) except +
        _qstring[T]& insert_char "insert"(T c) except +
        _qstring[T]& insert_string "insert"(const T *str) except +
        _qstring[T]& insert_qstring "insert"(const _qstring[T] &qstr) except +
        _qstring[T]& append(T c) except +
        _qstring[T]& append_substring "append"(const T *str, size_t addlen) except +
        _qstring[T]& append_string "append"(const T *str) except +
        _qstring[T]& append_qstring "append"(const _qstring[T] &qstr) except +
        _qstring[T]& cat_vsprnt(const char *format, ...) except +
        _qstring[T]& vsprnt(const char *format, ...) except +
        _qstring[T]& cat_sprnt(const char *format, ...) except +
        _qstring[T]& sprnt(const char *format, ...) except +
        _qstring[T]& nowarn_sprnt(const char *format, ...) except +
        _qstring[T]& fill(size_t pos, T c, size_t len) except +
        _qstring[T]& fill_all "fill"(T c, size_t len) except +
        _qstring[T]& ltrim(T blank) except +
        _qstring[T]& rtrim(T blank, size_t minlen = 0) except +
        _qstring[T]& rtrim_whitespace "rtrim"() except +
        _qstring[T]& trim2(T blank) except +

    # Common typedefs
    ctypedef _qstring[char] qstring
    ctypedef qvector[qstring] qstrvec_t
    ctypedef qvector[int] intvec_t
    ctypedef qvector[bint] boolvec_t
    ctypedef qvector[size_t] sizevec_t
    ctypedef qvector[uchar] bytevec_t


# =============================================================================
# Hex-Rays specific types
# =============================================================================

cdef extern from "hexrays.hpp":
    ctypedef int mreg_t
    ctypedef uint8 mopt_t

    # mcode_t enum - microcode opcodes
    cdef enum mcode_t:
        m_nop = 0x00
        m_stx = 0x01
        m_ldx = 0x02
        m_ldc = 0x03
        m_mov = 0x04
        m_neg = 0x05
        m_lnot = 0x06
        m_bnot = 0x07
        m_xds = 0x08
        m_xdu = 0x09
        m_low = 0x0A
        m_high = 0x0B
        m_add = 0x0C
        m_sub = 0x0D
        m_mul = 0x0E
        m_udiv = 0x0F
        m_sdiv = 0x10
        m_umod = 0x11
        m_smod = 0x12
        m_or = 0x13
        m_and = 0x14
        m_xor = 0x15
        m_shl = 0x16
        m_shr = 0x17
        m_sar = 0x18
        m_cfadd = 0x19
        m_ofadd = 0x1A
        m_cfshl = 0x1B
        m_cfshr = 0x1C
        m_sets = 0x1D
        m_seto = 0x1E
        m_setp = 0x1F
        m_setnz = 0x20
        m_setz = 0x21
        m_setae = 0x22
        m_setb = 0x23
        m_seta = 0x24
        m_setbe = 0x25
        m_setg = 0x26
        m_setge = 0x27
        m_setl = 0x28
        m_setle = 0x29
        m_jcnd = 0x2A
        m_jnz = 0x2B
        m_jz = 0x2C
        m_jae = 0x2D
        m_jb = 0x2E
        m_ja = 0x2F
        m_jbe = 0x30
        m_jg = 0x31
        m_jge = 0x32
        m_jl = 0x33
        m_jle = 0x34
        m_jtbl = 0x35
        m_ijmp = 0x36
        m_goto = 0x37
        m_call = 0x38
        m_icall = 0x39
        m_ret = 0x3A
        m_push = 0x3B
        m_pop = 0x3C
        m_und = 0x3D
        m_ext = 0x3E
        m_f2i = 0x3F
        m_f2u = 0x40
        m_i2f = 0x41
        m_u2f = 0x42
        m_f2f = 0x43
        m_fneg = 0x44
        m_fadd = 0x45
        m_fsub = 0x46
        m_fmul = 0x47
        m_fdiv = 0x48

    # Forward declarations
    cdef cppclass minsn_t
    cdef cppclass mblock_t
    cdef cppclass mba_t
    cdef cppclass mcallinfo_t
    cdef cppclass mop_addr_t
    cdef cppclass mop_pair_t
    cdef cppclass mcases_t
    cdef cppclass mnumber_t
    cdef cppclass fnumber_t
    cdef cppclass lvar_ref_t
    cdef cppclass stkvar_ref_t
    cdef cppclass scif_t

    # mop_t with correct make_number signature (2 args with defaults)
    cdef cppclass mop_t:
        mop_t() except +
        mopt_t t
        uint8 oprops
        uint16 valnum
        int size
        mreg_t r
        mnumber_t *nnn
        minsn_t *d
        stkvar_ref_t *s
        ea_t g
        int b
        mcallinfo_t *f
        lvar_ref_t *l
        mop_addr_t *a
        char *helper
        char *cstr
        mcases_t *c
        fnumber_t *fpc
        mop_pair_t *pair
        scif_t *scif
        const char *dstr() const
        void make_number(uint64 val, int size)  # simplified signature
        void assign(const mop_t& other)

    cdef cppclass mop_addr_t(mop_t):
        int insize
        int outsize

    cdef cppclass mop_pair_t:
        mop_t lop
        mop_t hop

    cdef cppclass mcallarg_t(mop_t):
        ea_t ea

    ctypedef qvector[mcallarg_t] mcallargs_t
    ctypedef qvector[mop_t] mopvec_t

    cdef cppclass mlist_t:
        pass

    cdef cppclass ivlset_t:
        pass

    # mcallinfo_t with args field
    cdef cppclass mcallinfo_t:
        ea_t callee
        int solid_args
        int call_spd
        int stkargs_top
        mcallargs_t args  # This field is missing in SDK
        mopvec_t retregs
        mlist_t return_regs
        mlist_t spoiled
        mlist_t pass_regs
        ivlset_t visible_memory
        mlist_t dead_regs
        int flags

    cdef cppclass mcases_t:
        pass

    cdef cppclass mnumber_t:
        uint64 value

    cdef cppclass fnumber_t:
        pass

    cdef cppclass lvar_ref_t:
        int idx
        sval_t off

    cdef cppclass stkvar_ref_t:
        mba_t *mba
        sval_t off

    cdef cppclass scif_t:
        pass

    cdef cppclass minsn_t:
        minsn_t *next
        minsn_t *prev
        ea_t ea
        int opcode
        int iprops
        mop_t l
        mop_t r
        mop_t d
        const char *dstr() const
        void optimize_solo(int optflags)
        bint has_side_effects(bint include_ldx_stx) const
        bint is_unknown_call() const

    cdef cppclass mblock_t:
        mblock_t *nextb
        mblock_t *prevb
        uint32 flags
        ea_t start
        ea_t end
        minsn_t *head
        minsn_t *tail
        mba_t *mba
        int serial
        int type
        intvec_t predset
        intvec_t succset
        int npred() const
        int nsucc() const
        int pred(int n) const
        int succ(int n) const
        void mark_lists_dirty()

    cdef cppclass mba_t:
        int qty
        mblock_t **natural
        ea_t entry_ea
        int frsize
        int inargoff
        sval_t stacksize
        sval_t minstkref
        sval_t fullsize
        bint use_frame() const
        sval_t stkoff_vd2ida(sval_t off) const
        mblock_t* get_mblock(int n) const
        void mark_chains_dirty()
        int optimize_local(int locopt_flags)

    # get_mreg_name function
    int get_mreg_name(qstring *out, mreg_t reg, int width, void *ud)


# =============================================================================
# Custom helpers
# =============================================================================

cdef extern from "stdarg.h":
    ctypedef struct va_list:
        pass

cdef extern from "swigpyobject.h":
    ctypedef struct SwigPyObject:
        void *ptr
    T swigtocpp[T](PyObject *obj)

ctypedef SwigPyObject* SwigPyObjectPtr

cdef inline void* _swig_ptr(object obj):
    addr = PyObject_GetAttrString(obj, "this")
    return (<SwigPyObjectPtr>addr).ptr


# =============================================================================
# Custom enums
# =============================================================================

cdef enum OPERAND_PROPERTIES:
    OPROP_IMPDONE = 0x01
    OPROP_UDT     = 0x02
    OPROP_FLOAT   = 0x04
    OPROP_CCFLAGS = 0x08
    OPROP_UDEFVAL = 0x10
    OPROP_LOWADDR = 0x20

cdef enum MOPT:
    ZERO          =  0
    REGISTER      =  1
    NUMBER        =  2
    STRING        =  3
    DEST_RESULT   =  4
    STACK         =  5
    GLOBAL        =  6
    MBLOCK        =  7
    ARGUMENT_LIST =  8
    LOCAL         =  9
    ADDRESS       = 10
    HELPER        = 11
    CASES         = 12
    FLOAT         = 13
    PAIR          = 14
    SCATTERED     = 15

cdef enum LOCOPT_FLAGS:
    LOCOPT_ALL     = 0x0001
    LOCOPT_REFINE  = 0x0002
    LOCOPT_REFINE2 = 0x0004


# =============================================================================
# Convenience typedefs
# =============================================================================
ctypedef mop_t* mop_t_ptr
ctypedef shared_ptr[mop_t] shared_mop_t_ptr
ctypedef pair[mop_t_ptr, uint64] mop_off_pair_t
ctypedef pair[uint64, int] const_val_t
ctypedef map[qstring, const_val_t] CppConstMap

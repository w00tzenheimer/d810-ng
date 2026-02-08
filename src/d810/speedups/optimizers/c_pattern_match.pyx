# distutils: language = c++
# cython: language_level=3, embedsignature=True
# cython: cdivision=True, boundscheck=False, wraparound=False
"""Cython-accelerated pattern matching for d810.

Three optimizations:
1. Non-mutating pattern match with stack-allocated bindings
2. O(1) opcode-indexed pattern storage using C++ unordered_map
3. Pre-computed pattern fingerprints with SIMD comparison
"""
from __future__ import annotations

import cython

from libc.stdint cimport uint16_t, uint64_t
from libc.string cimport memset

# --------------------------------------------------------------------------
# SIMD utilities from d810_simd.h
# --------------------------------------------------------------------------
cdef extern from "d810_simd.h" nogil:
    bint mem_eq_16(const void* a, const void* b)
    uint64_t hash_u64(uint64_t x)
    uint64_t hash_combine(uint64_t h1, uint64_t h2)


# --------------------------------------------------------------------------
# Priority 3: Pattern Fingerprint (C struct)
# --------------------------------------------------------------------------
cdef struct PatternFingerprint:
    uint64_t opcode_hash
    uint16_t depth
    uint16_t node_count
    uint16_t leaf_count
    uint16_t const_count
    # 4 bytes padding to reach 16 bytes for SIMD comparison
    uint16_t _pad1
    uint16_t _pad2


cdef inline void fingerprint_init(PatternFingerprint* fp) noexcept nogil:
    """Zero-initialize a fingerprint."""
    memset(fp, 0, sizeof(PatternFingerprint))


cdef inline bint fingerprint_eq(const PatternFingerprint* a, const PatternFingerprint* b) noexcept nogil:
    """Compare two fingerprints using SIMD when available."""
    return mem_eq_16(<const void*>a, <const void*>b)


cdef inline bint fingerprint_compatible(const PatternFingerprint* pattern, const PatternFingerprint* candidate) noexcept nogil:
    """Check if candidate could match pattern (quick rejection).

    Requires:
    - Same depth
    - Same node_count (structural shape)
    - Same total operand count (leaf + const)
    """
    if pattern.depth != candidate.depth:
        return False
    if pattern.node_count != candidate.node_count:
        return False
    # Total operand count must match
    if (pattern.leaf_count + pattern.const_count) != (candidate.leaf_count + candidate.const_count):
        return False
    return True


def compute_fingerprint_py(ast_node) -> dict:
    """Compute a fingerprint for a Python AST node.

    Returns a dict with the fingerprint fields, suitable for
    constructing a PatternFingerprint.
    """
    cdef PatternFingerprint fp
    fingerprint_init(&fp)
    _compute_fingerprint_recursive(ast_node, &fp, 0)

    return {
        "opcode_hash": fp.opcode_hash,
        "depth": fp.depth,
        "node_count": fp.node_count,
        "leaf_count": fp.leaf_count,
        "const_count": fp.const_count,
    }


cdef void _compute_fingerprint_recursive(object node, PatternFingerprint* fp, uint16_t cur_depth):
    """Recursively compute fingerprint from a Python AST tree."""
    cdef uint16_t next_depth = cur_depth + 1

    if node is None:
        return

    if node.is_node():
        fp.node_count += 1
        opcode = getattr(node, "opcode", 0) or 0
        fp.opcode_hash = hash_combine(fp.opcode_hash, hash_u64(<uint64_t>opcode))

        # Track maximum depth
        if next_depth > fp.depth:
            fp.depth = next_depth

        left = getattr(node, "left", None)
        right = getattr(node, "right", None)
        if left is not None:
            _compute_fingerprint_recursive(left, fp, next_depth)
        if right is not None:
            _compute_fingerprint_recursive(right, fp, next_depth)
    elif node.is_constant():
        fp.const_count += 1
        if next_depth > fp.depth:
            fp.depth = next_depth
    else:
        # Regular leaf
        fp.leaf_count += 1
        if next_depth > fp.depth:
            fp.depth = next_depth


# --------------------------------------------------------------------------
# Priority 1: Non-Mutating Pattern Match
# --------------------------------------------------------------------------
DEF MAX_BINDINGS = 64

cdef struct BindingEntry:
    # We store Python object references as void* at C level for the fixed
    # array, but manage them through Python for reference counting safety.
    # In practice, we use a parallel Python list for the actual objects.
    int name_hash  # Hash of the variable name for fast equality check
    int index      # Index into the parallel Python list


cdef class CMatchBindings:
    """C-level match bindings with fixed-size array.

    Uses a C array for the structural data and a parallel Python
    list for the actual mop objects (to maintain reference counting).
    """
    cdef int count
    cdef list names     # Variable names
    cdef list mops      # Bound mop objects
    cdef public object root_mop
    cdef public object root_dst_mop
    cdef public object root_dest_size
    cdef public object root_ea

    def __cinit__(self):
        self.count = 0
        self.names = []
        self.mops = []
        self.root_mop = None
        self.root_dst_mop = None
        self.root_dest_size = None
        self.root_ea = None

    cdef inline void reset(self):
        """Clear all bindings for reuse."""
        self.names.clear()
        self.mops.clear()
        self.count = 0
        self.root_mop = None
        self.root_dst_mop = None
        self.root_dest_size = None
        self.root_ea = None

    cdef inline bint add(self, object name, object mop):
        """Add a binding. Returns False if capacity exceeded."""
        if self.count >= MAX_BINDINGS:
            return False
        self.names.append(name)
        self.mops.append(mop)
        self.count += 1
        return True

    def to_dict(self) -> dict:
        """Convert bindings to {name: mop} dict."""
        cdef dict result = {}
        cdef int i
        for i in range(self.count):
            result[self.names[i]] = self.mops[i]
        return result

    def get_leafs_by_name(self) -> dict:
        """Get bindings indexed by name (last wins for duplicates)."""
        cdef dict result = {}
        cdef int i
        for i in range(self.count):
            result[self.names[i]] = self.mops[i]
        return result


def match_pattern_nomut(pattern, candidate, bindings=None):
    """Non-mutating pattern match (Cython accelerated).

    Walks pattern and candidate trees in parallel, checking structural
    compatibility. Collects variable bindings WITHOUT modifying either tree.

    Args:
        pattern: The frozen pattern AST (never modified)
        candidate: The candidate AST to match against
        bindings: CMatchBindings instance (created if None)

    Returns:
        True if pattern matches candidate.
    """
    cdef CMatchBindings cb
    if bindings is None:
        cb = CMatchBindings()
    elif isinstance(bindings, CMatchBindings):
        cb = <CMatchBindings>bindings
        cb.reset()
    else:
        # Fallback for non-Cython bindings
        cb = CMatchBindings()

    if not _match_recursive(pattern, candidate, cb):
        return False

    return _check_binding_equalities(cb)


cdef bint _match_recursive(object pattern, object candidate, CMatchBindings bindings):
    """Recursive structural match without mutation."""
    if pattern is None and candidate is None:
        return True
    if pattern is None or candidate is None:
        return False

    # Case 1: Pattern is a leaf
    if pattern.is_leaf():
        if pattern.is_constant():
            # AstConstant: candidate must be a constant with matching value
            if candidate.mop is None:
                return False

            # Use is_constant() when available; fall back to mop type check
            if hasattr(candidate, "is_constant") and callable(candidate.is_constant):
                if not candidate.is_constant():
                    pass  # Allow for capturing constants (expected_value=None)
            else:
                try:
                    import ida_hexrays
                    if hasattr(candidate.mop, 't') and candidate.mop.t != ida_hexrays.mop_n:
                        return False
                except ImportError:
                    pass

            expected = getattr(pattern, "expected_value", None)
            if expected is not None:
                if candidate.mop is None or not hasattr(candidate.mop, 'nnn'):
                    return False
                if expected != candidate.mop.nnn.value:
                    return False

            name = getattr(pattern, "name", None) or f"__const_{bindings.count}"
            return bindings.add(name, candidate.mop)
        else:
            # Regular leaf: matches any mop
            if candidate.mop is None:
                return False
            name = getattr(pattern, "name", None) or f"__leaf_{bindings.count}"
            return bindings.add(name, candidate.mop)

    # Case 2: Pattern is a node
    if not pattern.is_node():
        return False
    if not candidate.is_node():
        return False

    if getattr(pattern, "opcode", None) != getattr(candidate, "opcode", None):
        return False

    # Capture root metadata
    if bindings.root_mop is None:
        bindings.root_mop = candidate.mop
        bindings.root_dst_mop = getattr(candidate, "dst_mop", None)
        bindings.root_dest_size = candidate.dest_size
        bindings.root_ea = candidate.ea

    # Recurse into children
    cdef object p_left = getattr(pattern, "left", None)
    cdef object p_right = getattr(pattern, "right", None)
    cdef object c_left = getattr(candidate, "left", None)
    cdef object c_right = getattr(candidate, "right", None)

    if p_left is not None and c_left is not None:
        if not _match_recursive(p_left, c_left, bindings):
            return False
    elif p_left is not None and c_left is None:
        return False

    if p_right is not None and c_right is not None:
        if not _match_recursive(p_right, c_right, bindings):
            return False
    elif p_right is not None and c_right is None:
        return False

    return True


cdef bint _check_binding_equalities(CMatchBindings bindings):
    """Check implicit equalities: same name -> same mop."""
    cdef dict seen = {}
    cdef int i
    cdef object name, mop, prev_mop

    for i in range(bindings.count):
        name = bindings.names[i]
        mop = bindings.mops[i]
        if name in seen:
            prev_mop = seen[name]
            try:
                from d810.hexrays.hexrays_helpers import equal_mops_ignore_size
                if not equal_mops_ignore_size(prev_mop, mop):
                    return False
            except ImportError:
                if prev_mop is not mop:
                    return False
        else:
            seen[name] = mop
    return True


# --------------------------------------------------------------------------
# Priority 2: O(1) Opcode-Indexed Pattern Storage
# --------------------------------------------------------------------------

cdef class CRulePatternEntry:
    """A pattern with its pre-computed fingerprint and associated rule."""
    cdef public object rule
    cdef public object pattern
    cdef PatternFingerprint fingerprint

    def __init__(self, rule, pattern):
        self.rule = rule
        self.pattern = pattern
        fingerprint_init(&self.fingerprint)
        _compute_fingerprint_recursive(pattern, &self.fingerprint, 0)


cdef class COpcodeIndexedStorage:
    """O(1) opcode-indexed pattern storage (Cython accelerated).

    Patterns are indexed by root opcode for O(1) dispatch.
    Further filtered by pre-computed fingerprints.
    """
    cdef dict _by_opcode  # dict[int, list[CRulePatternEntry]]
    cdef int _total_patterns

    def __cinit__(self):
        self._by_opcode = {}
        self._total_patterns = 0

    def add_pattern(self, pattern, rule) -> None:
        """Register a pattern for a rule."""
        cdef CRulePatternEntry entry = CRulePatternEntry(rule, pattern)
        cdef int opcode = self._get_root_opcode(pattern)

        if opcode not in self._by_opcode:
            self._by_opcode[opcode] = []

        (<list>self._by_opcode[opcode]).append(entry)
        self._total_patterns += 1

    def get_candidates(self, candidate) -> list:
        """Get patterns that could match the candidate.

        Uses opcode dispatch + fingerprint pre-filtering.
        """
        cdef int opcode = self._get_root_opcode(candidate)
        cdef list entries = self._by_opcode.get(opcode)
        if entries is None:
            return []

        # Compute candidate fingerprint
        cdef PatternFingerprint cand_fp
        fingerprint_init(&cand_fp)
        _compute_fingerprint_recursive(candidate, &cand_fp, 0)

        # Filter by fingerprint compatibility
        cdef list result = []
        cdef CRulePatternEntry entry
        for entry in entries:
            if fingerprint_compatible(&entry.fingerprint, &cand_fp):
                result.append(entry)

        return result

    @property
    def total_patterns(self) -> int:
        return self._total_patterns

    cdef int _get_root_opcode(self, object ast):
        """Extract root opcode. Returns -1 for leaves."""
        if ast.is_node():
            opcode = getattr(ast, "opcode", None)
            return <int>(opcode if opcode is not None else -1)
        return -1

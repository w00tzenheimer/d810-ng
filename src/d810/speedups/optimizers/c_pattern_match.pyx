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
from d810.core.native_perf import register_provider as _register_native_perf_provider

# --------------------------------------------------------------------------
# SIMD utilities from d810_simd.h
# --------------------------------------------------------------------------
cdef extern from "d810_simd.h" nogil:
    bint mem_eq_16(const void* a, const void* b)
    uint64_t hash_u64(uint64_t x)
    uint64_t hash_combine(uint64_t h1, uint64_t h2)

cdef extern from "d810_perf.h" nogil:
    uint64_t d810_perf_now_ns() noexcept


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


cdef struct PatternPerfCounters:
    uint64_t clock_reads
    uint64_t fingerprint_calls
    uint64_t fingerprint_time_ns
    uint64_t bucket_lookups
    uint64_t bucket_hits
    uint64_t bucket_misses
    uint64_t entries_scanned
    uint64_t entries_accepted
    uint64_t match_calls
    uint64_t match_time_ns
    uint64_t match_nodes
    uint64_t binding_additions
    uint64_t repeated_binding_checks
    uint64_t repeated_binding_time_ns
    uint64_t result_list_materializations
    uint64_t result_list_items
    uint64_t to_dict_calls
    uint64_t to_dict_items


cdef bint _native_perf_enabled = False
cdef PatternPerfCounters _native_perf_counters


cdef inline uint64_t _perf_now() noexcept nogil:
    _native_perf_counters.clock_reads += 1
    return d810_perf_now_ns()


cdef inline uint64_t _perf_start() noexcept nogil:
    return _perf_now()


cdef inline void _perf_record_fingerprint(uint64_t started) noexcept nogil:
    if _native_perf_enabled:
        _native_perf_counters.fingerprint_calls += 1
        _native_perf_counters.fingerprint_time_ns += _perf_now() - started


cdef inline void _compute_fingerprint(
    object node, PatternFingerprint* fp
):
    cdef uint64_t started = 0
    if _native_perf_enabled:
        started = _perf_start()
    _compute_fingerprint_recursive(node, fp, 0)
    if _native_perf_enabled:
        _perf_record_fingerprint(started)


cdef inline void fingerprint_init(PatternFingerprint* fp) noexcept nogil:
    """Zero-initialize a fingerprint."""
    memset(fp, 0, sizeof(PatternFingerprint))


cdef inline bint fingerprint_eq(const PatternFingerprint* a, const PatternFingerprint* b) noexcept nogil:
    """Compare two fingerprints using SIMD when available."""
    return mem_eq_16(<const void*>a, <const void*>b)


cdef inline bint fingerprint_compatible(const PatternFingerprint* pattern, const PatternFingerprint* candidate) noexcept nogil:
    """Check if candidate could match pattern (quick rejection).

    Requires:
    - Same opcode_hash (sub-tree opcode structure)
    - Same depth
    - Same node_count (structural shape)
    - Same total operand count (leaf + const)
    - Pattern const_count <= candidate const_count (directional constraint)
    """
    if pattern.opcode_hash != candidate.opcode_hash:
        return False
    if pattern.depth != candidate.depth:
        return False
    if pattern.node_count != candidate.node_count:
        return False
    # Total operand count must match
    if (pattern.leaf_count + pattern.const_count) != (candidate.leaf_count + candidate.const_count):
        return False
    # A pattern with constants at specific positions can only match
    # candidates that have at least as many constants (directional constraint).
    if pattern.const_count > candidate.const_count:
        return False
    return True


def compute_fingerprint_py(ast_node) -> dict:
    """Compute a fingerprint for a Python AST node.

    Returns a dict with the fingerprint fields, suitable for
    constructing a PatternFingerprint.
    """
    cdef PatternFingerprint fp
    fingerprint_init(&fp)
    _compute_fingerprint(ast_node, &fp)

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
        if _native_perf_enabled:
            _native_perf_counters.binding_additions += 1
        return True

    def to_dict(self) -> dict:
        """Convert bindings to {name: mop} dict."""
        cdef dict result = {}
        cdef int i
        if _native_perf_enabled:
            _native_perf_counters.to_dict_calls += 1
            _native_perf_counters.to_dict_items += self.count
        for i in range(self.count):
            result[self.names[i]] = self.mops[i]
        return result

    def get_leafs_by_name(self) -> dict:
        """Get bindings indexed by name (last wins for duplicates)."""
        cdef dict result = {}
        cdef int i
        if _native_perf_enabled:
            _native_perf_counters.result_list_materializations += 1
            _native_perf_counters.result_list_items += self.count
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
    cdef uint64_t started = 0
    if _native_perf_enabled:
        _native_perf_counters.match_calls += 1
        started = _perf_start()
    if bindings is None:
        cb = CMatchBindings()
    elif isinstance(bindings, CMatchBindings):
        cb = <CMatchBindings>bindings
        cb.reset()
    else:
        # Fallback for non-Cython bindings
        cb = CMatchBindings()

    if not _match_recursive(pattern, candidate, cb):
        if _native_perf_enabled:
            _native_perf_counters.match_time_ns += _perf_now() - started
        return False

    result = _check_binding_equalities(cb)
    if _native_perf_enabled:
        _native_perf_counters.match_time_ns += _perf_now() - started
    return result


cdef bint _match_recursive(object pattern, object candidate, CMatchBindings bindings):
    """Recursive structural match without mutation."""
    if _native_perf_enabled:
        _native_perf_counters.match_nodes += 1
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
                nnn = candidate.mop.nnn
                if nnn is None or not hasattr(nnn, "value"):
                    return False
                if expected != nnn.value:
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
    cdef uint64_t equality_started

    for i in range(bindings.count):
        name = bindings.names[i]
        mop = bindings.mops[i]
        if name in seen:
            prev_mop = seen[name]
            if _native_perf_enabled:
                _native_perf_counters.repeated_binding_checks += 1
                equality_started = _perf_start()
            try:
                from d810.hexrays.utils.hexrays_helpers import equal_mops_ignore_size
                if not equal_mops_ignore_size(prev_mop, mop):
                    if _native_perf_enabled:
                        _native_perf_counters.repeated_binding_time_ns += (
                            _perf_now() - equality_started
                        )
                    return False
            except ImportError:
                if prev_mop is not mop:
                    if _native_perf_enabled:
                        _native_perf_counters.repeated_binding_time_ns += (
                            _perf_now() - equality_started
                        )
                    return False
            if _native_perf_enabled:
                _native_perf_counters.repeated_binding_time_ns += (
                    _perf_now() - equality_started
                )
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
        _compute_fingerprint(pattern, &self.fingerprint)


cdef class COpcodeIndexedStorage:
    """O(1) opcode-indexed pattern storage (Cython accelerated).

    Patterns are indexed by root opcode for O(1) dispatch.
    Further filtered by pre-computed fingerprints.
    """
    cdef dict _by_opcode  # dict[int, list[CRulePatternEntry]]
    cdef dict _by_shape  # dict[shape tuple, list[CRulePatternEntry]]
    cdef int _total_patterns

    def __cinit__(self):
        self._by_opcode = {}
        self._by_shape = {}
        self._total_patterns = 0

    def add_pattern(self, pattern, rule) -> None:
        """Register a pattern for a rule."""
        cdef CRulePatternEntry entry = CRulePatternEntry(rule, pattern)
        cdef int opcode = self._get_root_opcode(pattern)

        if opcode not in self._by_opcode:
            self._by_opcode[opcode] = []

        (<list>self._by_opcode[opcode]).append(entry)
        cdef tuple shape_key = (
            opcode,
            entry.fingerprint.opcode_hash,
            entry.fingerprint.depth,
            entry.fingerprint.node_count,
            entry.fingerprint.leaf_count + entry.fingerprint.const_count,
        )
        if shape_key not in self._by_shape:
            self._by_shape[shape_key] = []
        (<list>self._by_shape[shape_key]).append(entry)
        self._total_patterns += 1

    def get_candidates(self, candidate) -> list:
        """Get patterns that could match the candidate.

        Uses opcode dispatch + fingerprint pre-filtering.
        """
        cdef int opcode = self._get_root_opcode(candidate)

        # Compute the candidate fingerprint once, then index by every exact
        # compatibility field except the directional constant count.
        cdef PatternFingerprint cand_fp
        fingerprint_init(&cand_fp)
        _compute_fingerprint(candidate, &cand_fp)
        cdef tuple shape_key = (
            opcode,
            cand_fp.opcode_hash,
            cand_fp.depth,
            cand_fp.node_count,
            cand_fp.leaf_count + cand_fp.const_count,
        )
        cdef list entries = self._by_shape.get(shape_key)
        if _native_perf_enabled:
            _native_perf_counters.bucket_lookups += 1
        if entries is None:
            if _native_perf_enabled:
                _native_perf_counters.bucket_misses += 1
                _native_perf_counters.result_list_materializations += 1
            return []
        if _native_perf_enabled:
            _native_perf_counters.bucket_hits += 1

        # Only the directional constant-count constraint remains after the
        # exact structural lookup.
        cdef list result = []
        cdef CRulePatternEntry entry
        for entry in entries:
            if _native_perf_enabled:
                _native_perf_counters.entries_scanned += 1
            if fingerprint_compatible(&entry.fingerprint, &cand_fp):
                result.append(entry)
                if _native_perf_enabled:
                    _native_perf_counters.entries_accepted += 1

        if _native_perf_enabled:
            _native_perf_counters.result_list_materializations += 1
            _native_perf_counters.result_list_items += len(result)

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


def _native_perf_configure(enabled):
    """Configure the C-level counters without allocating hot-path objects."""
    global _native_perf_enabled
    _native_perf_enabled = bool(enabled)


def _native_perf_reset():
    """Reset all C-level counters at a manager session boundary."""
    memset(&_native_perf_counters, 0, sizeof(PatternPerfCounters))


def _native_perf_snapshot() -> dict:
    """Materialize the C counters for the opt-in lifecycle receipt."""
    cdef PatternPerfCounters counters = _native_perf_counters
    return {
        "backend": "cython",
        "counter_domain": "native",
        "provider_version": 1,
        "coverage": "indexed matcher only; legacy PatternStorage is not instrumented",
        "timing_model": "inclusive steady-clock spans around top-level calls",
        "counters": {
            "clock_reads": int(counters.clock_reads),
            "fingerprint_calls": int(counters.fingerprint_calls),
            "fingerprint_time_ns": int(counters.fingerprint_time_ns),
            "bucket_lookups": int(counters.bucket_lookups),
            "bucket_hits": int(counters.bucket_hits),
            "bucket_misses": int(counters.bucket_misses),
            "entries_scanned": int(counters.entries_scanned),
            "entries_accepted": int(counters.entries_accepted),
            "match_calls": int(counters.match_calls),
            "match_time_ns": int(counters.match_time_ns),
            "match_nodes": int(counters.match_nodes),
            "binding_additions": int(counters.binding_additions),
            "repeated_binding_checks": int(counters.repeated_binding_checks),
            "repeated_binding_time_ns": int(counters.repeated_binding_time_ns),
            "result_list_materializations": int(
                counters.result_list_materializations
            ),
            "result_list_items": int(counters.result_list_items),
            "to_dict_calls": int(counters.to_dict_calls),
            "to_dict_items": int(counters.to_dict_items),
        },
    }


def register_native_perf_provider():
    """Select the Cython provider when this backend is active."""
    _register_native_perf_provider(
        "pattern_match",
        snapshot=_native_perf_snapshot,
        configure=_native_perf_configure,
        reset=_native_perf_reset,
    )


register_native_perf_provider()

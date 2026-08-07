# cython: language_level=3
# distutils: language = c++
"""In-process binding to cobra::Simplify.

Replaces the cobra-cli subprocess.  Three reasons it is not merely faster:

* **No text round-trip.**  Input is a signature (a list of ints); output is a
  real ``Expr`` tree.  Neither end goes through cobra-cli's undocumented infix
  syntax.
* **Shifts are reachable.**  cobra-cli's tokenizer has no shift operator, so
  ``Expr::Kind::kShr`` can never come back through it.
* **The GIL is released** across the solve.  ``Simplify`` runs for seconds on
  large inputs; holding the GIL would stall every other thread in IDA.

This module includes CoBRA headers and **no IDA headers**, which is not a
style choice: the IDA SDK does not compile as C++23 (``pro.h`` uses
``std::is_pod``, removed in C++23) and CoBRA requires C++23 (``Result.h`` uses
``std::expected``).  They can never share a translation unit.  All IDA contact
stays on the Python side in ``detect.py`` / ``convert.py``.
"""

from libc.stdint cimport int32_t, uint32_t, uint64_t
from libc.stdlib cimport free, malloc

cdef extern from "cobra_shim.h" nogil:
    ctypedef struct cobra_node_t:
        int32_t kind
        uint64_t constant_val
        uint32_t var_index
        int32_t child0
        int32_t child1

    int cobra_shim_simplify(const uint64_t *sig, size_t sig_len, uint32_t nvars,
                            uint32_t bitwidth, uint32_t max_vars,
                            const cobra_node_t *in_nodes, size_t in_len,
                            int32_t in_root, cobra_node_t *out_nodes,
                            size_t out_cap, size_t *out_len, int32_t *out_root,
                            char *err, size_t err_cap)

    int COBRA_OK
    int COBRA_UNCHANGED
    int COBRA_ERROR
    int COBRA_TOO_SMALL
    int COBRA_EXCEPTION

    int COBRA_NODE_CONSTANT
    int COBRA_NODE_VARIABLE
    int COBRA_NODE_ADD
    int COBRA_NODE_MUL
    int COBRA_NODE_AND
    int COBRA_NODE_OR
    int COBRA_NODE_XOR
    int COBRA_NODE_NOT
    int COBRA_NODE_NEG
    int COBRA_NODE_SHR


class CobraSolverError(Exception):
    """The solver reported an error, or the binding could not marshal a result."""


#: Node kinds mapped onto the tree vocabulary used by ``expr.py``.
_BINARY_OPS = {
    COBRA_NODE_ADD: "+",
    COBRA_NODE_MUL: "*",
    COBRA_NODE_AND: "&",
    COBRA_NODE_OR: "|",
    COBRA_NODE_XOR: "^",
}
_UNARY_OPS = {COBRA_NODE_NOT: "~", COBRA_NODE_NEG: "-"}

#: Start big enough for anything seen in practice (largest observed rebuild was
#: 571 nodes) and grow once if the solver returns something larger.
_INITIAL_CAPACITY = 4096
_ERROR_CAPACITY = 512


#: Tree operator -> flat node kind, for the INPUT direction.
_OP_TO_KIND = {
    "+": COBRA_NODE_ADD,
    "*": COBRA_NODE_MUL,
    "&": COBRA_NODE_AND,
    "|": COBRA_NODE_OR,
    "^": COBRA_NODE_XOR,
}


def _flatten(tree, index_of, out):
    """Append *tree* to *out* in the flat encoding, returning its index.

    CoBRA's Expr has no subtract node, so ``a - b`` is emitted the way its own
    microcode converter does it: ``Add(a, Negate(b))``.
    """
    kind = tree["kind"]

    if kind == "const":
        out.append((COBRA_NODE_CONSTANT, tree["value"], 0, -1, -1))
        return len(out) - 1

    if kind == "var":
        name = tree["name"]
        if name not in index_of:
            raise CobraSolverError(f"leaf {name!r} is not in the declared leaves")
        out.append((COBRA_NODE_VARIABLE, 0, index_of[name], -1, -1))
        return len(out) - 1

    if kind == "un":
        child = _flatten(tree["a"], index_of, out)
        node_kind = COBRA_NODE_NOT if tree["op"] == "~" else COBRA_NODE_NEG
        out.append((node_kind, 0, 0, child, -1))
        return len(out) - 1

    if kind == "bin":
        op = tree["op"]
        left = _flatten(tree["a"], index_of, out)
        right = _flatten(tree["b"], index_of, out)
        if op == "-":
            out.append((COBRA_NODE_NEG, 0, 0, right, -1))
            right = len(out) - 1
            op = "+"
        node_kind = _OP_TO_KIND.get(op)
        if node_kind is None:
            raise CobraSolverError(f"cannot encode operator {op!r}")
        out.append((node_kind, 0, 0, left, right))
        return len(out) - 1

    raise CobraSolverError(f"cannot encode node kind {kind!r}")


cdef object _build(cobra_node_t *nodes, int32_t index, list varnames):
    """Rebuild one node (and its children) as the dict form used by expr.py."""
    cdef cobra_node_t node = nodes[index]
    cdef int32_t kind = node.kind

    if kind == COBRA_NODE_CONSTANT:
        return {"kind": "const", "value": int(node.constant_val)}

    if kind == COBRA_NODE_VARIABLE:
        if node.var_index >= <uint32_t>len(varnames):
            raise CobraSolverError(
                f"solver referenced x{node.var_index} but only "
                f"{len(varnames)} leaves were supplied"
            )
        return {"kind": "var", "name": varnames[node.var_index]}

    if kind in _UNARY_OPS:
        return {
            "kind": "un",
            "op": _UNARY_OPS[kind],
            "a": _build(nodes, node.child0, varnames),
        }

    if kind in _BINARY_OPS:
        return {
            "kind": "bin",
            "op": _BINARY_OPS[kind],
            "a": _build(nodes, node.child0, varnames),
            "b": _build(nodes, node.child1, varnames),
        }

    if kind == COBRA_NODE_SHR:
        # Reachable only through this binding; cobra-cli cannot emit a shift.
        # expr.py has no shift node, so refuse rather than silently mis-model.
        raise CobraSolverError("solver returned a shift; not yet representable")

    raise CobraSolverError(f"unknown node kind {kind}")


def simplify(signature, varnames, unsigned int bitwidth, tree,
             unsigned int max_vars=16):
    """Return the simplest expression CoBRA finds for *signature*.

    ``signature`` must hold ``1 << len(varnames)`` entries: the expression
    evaluated at every 0/1 assignment of its leaves.

    Returns ``None`` only when CoBRA reports ``kUnchangedUnsupported`` -- that
    is, it could not handle the input at all.

    **A returned tree is not necessarily different from the caller's original.**
    The solver is given a *signature*, not an expression, so "unchanged" is not
    a judgement it can make: it has nothing to compare against. Feeding it the
    signature of ``x`` returns ``Variable(0)``, which is both correct and
    identical to the input. Deciding whether a result is an improvement is the
    caller's job -- see ``expr.accept_rewrite``.
    """
    cdef list names = list(varnames)
    cdef uint32_t nvars = <uint32_t>len(names)
    cdef size_t sig_len = len(signature)

    if sig_len != (<size_t>1 << nvars):
        raise ValueError(
            f"signature has {sig_len} entries, expected {1 << nvars} "
            f"for {nvars} leaves"
        )
    if bitwidth not in (8, 16, 32, 64):
        raise ValueError(f"unsupported bitwidth {bitwidth}")

    # Flatten the ORIGINAL expression: without it Simplify loses its
    # evaluator, its cost baseline and the XOR fallback (see cobra_shim.h).
    cdef list flat = []
    _flatten(tree, {n: i for i, n in enumerate(names)}, flat)
    cdef size_t in_len = len(flat)
    cdef int32_t in_root = <int32_t>(in_len - 1)
    cdef cobra_node_t *in_nodes = <cobra_node_t *>malloc(
        in_len * sizeof(cobra_node_t))

    cdef uint64_t *sig = <uint64_t *>malloc(sig_len * sizeof(uint64_t))
    cdef cobra_node_t *nodes = NULL
    cdef char *err = <char *>malloc(_ERROR_CAPACITY)
    cdef size_t capacity = _INITIAL_CAPACITY
    # Hoisted into C locals: a nogil block cannot touch Python globals.
    cdef size_t err_cap = _ERROR_CAPACITY
    cdef size_t produced = 0
    cdef int32_t root = -1
    cdef int status
    cdef size_t i

    if sig == NULL or err == NULL or in_nodes == NULL:
        free(sig)
        free(err)
        free(in_nodes)
        raise MemoryError("could not allocate solver buffers")

    try:
        for i in range(sig_len):
            sig[i] = <uint64_t>(signature[i])
        for i in range(in_len):
            in_nodes[i].kind = <int32_t>flat[i][0]
            in_nodes[i].constant_val = <uint64_t>flat[i][1]
            in_nodes[i].var_index = <uint32_t>flat[i][2]
            in_nodes[i].child0 = <int32_t>flat[i][3]
            in_nodes[i].child1 = <int32_t>flat[i][4]
        err[0] = 0

        nodes = <cobra_node_t *>malloc(capacity * sizeof(cobra_node_t))
        if nodes == NULL:
            raise MemoryError("could not allocate node buffer")

        # The solve is the expensive part and touches no Python state.
        with nogil:
            status = cobra_shim_simplify(sig, sig_len, nvars, bitwidth,
                                         max_vars, in_nodes, in_len, in_root,
                                         nodes, capacity, &produced, &root,
                                         err, err_cap)

        if status == COBRA_TOO_SMALL:
            # Grow once to exactly what the solver asked for and retry.
            capacity = produced
            free(nodes)
            nodes = <cobra_node_t *>malloc(capacity * sizeof(cobra_node_t))
            if nodes == NULL:
                raise MemoryError("could not allocate node buffer")
            with nogil:
                status = cobra_shim_simplify(sig, sig_len, nvars, bitwidth,
                                             max_vars, in_nodes, in_len,
                                             in_root, nodes, capacity,
                                             &produced, &root, err, err_cap)

        if status == COBRA_UNCHANGED:
            return None
        if status != COBRA_OK:
            raise CobraSolverError(
                (err.decode("utf-8", "replace") or "solver failed")
                if err[0] != 0 else f"solver failed with status {status}"
            )
        if root < 0 or <size_t>root >= produced:
            raise CobraSolverError("solver returned an invalid root index")

        return _build(nodes, root, names)
    finally:
        free(sig)
        free(nodes)
        free(err)
        free(in_nodes)

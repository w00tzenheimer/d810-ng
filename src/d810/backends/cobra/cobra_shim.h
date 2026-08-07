/* Flat C surface over cobra::Simplify, so Cython never sees C++23 types.
 *
 * Three things make a direct binding impractical:
 *   - Result<T> is std::expected (C++23), which Cython cannot model;
 *   - Expr owns vector<unique_ptr<Expr>>, move-only by design;
 *   - the whole call must run without the GIL, so nothing here may touch the
 *     Python API.
 *
 * So the tree comes back as a flat array of nodes with integer child indices,
 * and the caller rebuilds whatever representation it wants.
 */

#ifndef D810_COBRA_SHIM_H
#define D810_COBRA_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Mirrors cobra::Expr::Kind. Kept as plain ints so the ABI is stable. */
enum {
  COBRA_NODE_CONSTANT = 0,
  COBRA_NODE_VARIABLE = 1,
  COBRA_NODE_ADD = 2,
  COBRA_NODE_MUL = 3,
  COBRA_NODE_AND = 4,
  COBRA_NODE_OR = 5,
  COBRA_NODE_XOR = 6,
  COBRA_NODE_NOT = 7,
  COBRA_NODE_NEG = 8,
  COBRA_NODE_SHR = 9
};

/* Return codes. */
enum {
  COBRA_OK = 0,          /* simplified; out_nodes/out_root are valid */
  COBRA_UNCHANGED = 1,   /* solver returned no reduction */
  COBRA_ERROR = 2,       /* solver reported an error; see err */
  COBRA_TOO_SMALL = 3,   /* out_cap too small; out_len holds the need */
  COBRA_EXCEPTION = 4    /* a C++ exception escaped; see err */
};

typedef struct {
  int32_t kind;          /* one of COBRA_NODE_* */
  uint64_t constant_val; /* kConstant only */
  uint32_t var_index;    /* kVariable only */
  int32_t child0;        /* index into the node array, -1 when absent */
  int32_t child1;
} cobra_node_t;

/* Simplify the function described by *sig*, seeded with the input expression.
 *
 * sig       : truth vector, sig_len == (1 << nvars) entries
 * nvars     : leaf count; variables are named x0..x{nvars-1}
 * bitwidth  : 8, 16, 32 or 64
 * in_nodes  : the ORIGINAL expression, same flat encoding as the output
 * in_root   : index of its root node
 *
 * The input expression is NOT optional in practice.  cobra::Simplify accepts a
 * null input_expr, but that path silently loses three things
 * (Orchestrator.cpp:1009, 1030):
 *
 *   - opts.evaluator stays unset, so candidates are never checked against the
 *     real function in the original space;
 *   - input_cost is nullopt, disabling the blow-up gate;
 *   - the XOR exhaustion fallback is skipped.
 *
 * Measured cost of passing null: 49 of 54 results were refuted by an
 * independent Z3 check, versus 0 when the expression is supplied.  A signature
 * over {0,1}^n under-determines the function once constants are involved
 * (`(a^b)^97` is the case that exposed it).
 *
 * Safe to call without the GIL: touches no Python API and never calls back
 * into the interpreter.
 */
int cobra_shim_simplify(const uint64_t *sig, size_t sig_len, uint32_t nvars,
                        uint32_t bitwidth, uint32_t max_vars,
                        const cobra_node_t *in_nodes, size_t in_len,
                        int32_t in_root, cobra_node_t *out_nodes,
                        size_t out_cap, size_t *out_len, int32_t *out_root,
                        char *err, size_t err_cap);

#ifdef __cplusplus
}
#endif

#endif /* D810_COBRA_SHIM_H */

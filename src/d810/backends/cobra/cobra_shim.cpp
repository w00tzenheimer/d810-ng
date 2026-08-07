/* Implementation of the flat C surface over cobra::Simplify.
 *
 * Everything here must stay callable without the GIL: no Python API, no
 * callbacks into the interpreter, and every C++ exception caught at the
 * boundary (letting one escape into Cython's nogil frame would terminate the
 * process).
 */

#include "cobra_shim.h"

#include <cobra/core/Expr.h>
#include <cobra/core/Result.h>
#include <cobra/core/SimplifyOutcome.h>
#include <cobra/core/Simplifier.h>

#include <cstring>
#include <string>
#include <vector>

namespace {

int32_t map_kind(cobra::Expr::Kind kind) {
  switch (kind) {
  case cobra::Expr::Kind::kConstant:
    return COBRA_NODE_CONSTANT;
  case cobra::Expr::Kind::kVariable:
    return COBRA_NODE_VARIABLE;
  case cobra::Expr::Kind::kAdd:
    return COBRA_NODE_ADD;
  case cobra::Expr::Kind::kMul:
    return COBRA_NODE_MUL;
  case cobra::Expr::Kind::kAnd:
    return COBRA_NODE_AND;
  case cobra::Expr::Kind::kOr:
    return COBRA_NODE_OR;
  case cobra::Expr::Kind::kXor:
    return COBRA_NODE_XOR;
  case cobra::Expr::Kind::kNot:
    return COBRA_NODE_NOT;
  case cobra::Expr::Kind::kNeg:
    return COBRA_NODE_NEG;
  case cobra::Expr::Kind::kShr:
    return COBRA_NODE_SHR;
  }
  return -1;
}

/* Flatten into `out`, returning this node's index (or -1 if it does not fit).
 * Children are emitted first so an index is always already assigned. */
int32_t flatten(const cobra::Expr &expr, std::vector<cobra_node_t> &out) {
  int32_t child0 = -1;
  int32_t child1 = -1;

  if (!expr.children.empty() && expr.children[0]) {
    child0 = flatten(*expr.children[0], out);
    if (child0 < 0) {
      return -1;
    }
  }
  if (expr.children.size() > 1 && expr.children[1]) {
    child1 = flatten(*expr.children[1], out);
    if (child1 < 0) {
      return -1;
    }
  }

  const int32_t kind = map_kind(expr.kind);
  if (kind < 0) {
    return -1;
  }

  cobra_node_t node;
  node.kind = kind;
  node.constant_val = expr.constant_val;
  node.var_index = expr.var_index;
  node.child0 = child0;
  node.child1 = child1;
  out.push_back(node);
  return static_cast<int32_t>(out.size() - 1);
}

/* Rebuild a cobra::Expr from the flat encoding. Returns nullptr on a malformed
 * node array (bad index, unknown kind, or a cycle deeper than the array). */
std::unique_ptr<cobra::Expr> unflatten(const cobra_node_t *nodes, size_t len,
                                       int32_t index, size_t depth) {
  if (index < 0 || static_cast<size_t>(index) >= len || depth > len) {
    return nullptr;
  }
  const cobra_node_t &node = nodes[index];

  switch (node.kind) {
  case COBRA_NODE_CONSTANT:
    return cobra::Expr::Constant(node.constant_val);
  case COBRA_NODE_VARIABLE:
    return cobra::Expr::Variable(node.var_index);
  default:
    break;
  }

  auto lhs = unflatten(nodes, len, node.child0, depth + 1);
  if (!lhs) {
    return nullptr;
  }

  if (node.kind == COBRA_NODE_NOT) {
    return cobra::Expr::BitwiseNot(std::move(lhs));
  }
  if (node.kind == COBRA_NODE_NEG) {
    return cobra::Expr::Negate(std::move(lhs));
  }
  if (node.kind == COBRA_NODE_SHR) {
    return cobra::Expr::LogicalShr(std::move(lhs), node.constant_val);
  }

  auto rhs = unflatten(nodes, len, node.child1, depth + 1);
  if (!rhs) {
    return nullptr;
  }

  switch (node.kind) {
  case COBRA_NODE_ADD:
    return cobra::Expr::Add(std::move(lhs), std::move(rhs));
  case COBRA_NODE_MUL:
    return cobra::Expr::Mul(std::move(lhs), std::move(rhs));
  case COBRA_NODE_AND:
    return cobra::Expr::BitwiseAnd(std::move(lhs), std::move(rhs));
  case COBRA_NODE_OR:
    return cobra::Expr::BitwiseOr(std::move(lhs), std::move(rhs));
  case COBRA_NODE_XOR:
    return cobra::Expr::BitwiseXor(std::move(lhs), std::move(rhs));
  default:
    return nullptr;
  }
}

void copy_error(char *err, size_t err_cap, const std::string &message) {
  if (err == nullptr || err_cap == 0) {
    return;
  }
  const size_t n = message.size() < (err_cap - 1) ? message.size() : (err_cap - 1);
  std::memcpy(err, message.data(), n);
  err[n] = '\0';
}

} // namespace

int cobra_shim_simplify(const uint64_t *sig, size_t sig_len, uint32_t nvars,
                        uint32_t bitwidth, uint32_t max_vars,
                        const cobra_node_t *in_nodes, size_t in_len,
                        int32_t in_root, cobra_node_t *out_nodes,
                        size_t out_cap, size_t *out_len, int32_t *out_root,
                        char *err, size_t err_cap) {
  try {
    if (sig == nullptr || out_len == nullptr || out_root == nullptr) {
      copy_error(err, err_cap, "null argument");
      return COBRA_ERROR;
    }
    if (in_nodes == nullptr || in_len == 0) {
      copy_error(err, err_cap, "input expression is required");
      return COBRA_ERROR;
    }
    if (sig_len != (size_t{1} << nvars)) {
      copy_error(err, err_cap, "signature length must be 1 << nvars");
      return COBRA_ERROR;
    }

    std::vector<uint64_t> signature(sig, sig + sig_len);

    std::vector<std::string> vars;
    vars.reserve(nvars);
    for (uint32_t i = 0; i < nvars; ++i) {
      vars.push_back("x" + std::to_string(i));
    }

    cobra::Options options;
    options.bitwidth = bitwidth;
    options.max_vars = max_vars;

    /* The input expression is what gives Simplify an evaluator, a cost
     * baseline and the XOR fallback. Passing nullptr compiles and runs, but
     * produces results that do not survive an independent equivalence check. */
    auto input = unflatten(in_nodes, in_len, in_root, 0);
    if (!input) {
      copy_error(err, err_cap, "malformed input expression");
      return COBRA_ERROR;
    }

    auto result = cobra::Simplify(signature, vars, input.get(), options);
    if (!result.has_value()) {
      copy_error(err, err_cap, result.error().message);
      return COBRA_ERROR;
    }

    const cobra::SimplifyOutcome &outcome = result.value();
    if (outcome.kind != cobra::SimplifyOutcome::Kind::kSimplified ||
        outcome.expr == nullptr) {
      return COBRA_UNCHANGED;
    }

    std::vector<cobra_node_t> nodes;
    const int32_t root = flatten(*outcome.expr, nodes);
    if (root < 0) {
      copy_error(err, err_cap, "unrepresentable node kind");
      return COBRA_ERROR;
    }

    *out_len = nodes.size();
    if (nodes.size() > out_cap || out_nodes == nullptr) {
      return COBRA_TOO_SMALL;
    }

    std::memcpy(out_nodes, nodes.data(), nodes.size() * sizeof(cobra_node_t));
    *out_root = root;
    return COBRA_OK;
  } catch (const std::exception &exc) {
    copy_error(err, err_cap, exc.what());
    return COBRA_EXCEPTION;
  } catch (...) {
    copy_error(err, err_cap, "unknown C++ exception");
    return COBRA_EXCEPTION;
  }
}

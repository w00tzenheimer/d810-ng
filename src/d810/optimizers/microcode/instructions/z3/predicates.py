import ida_hexrays

from d810.hexrays.expr.ast import AstConstant, AstLeaf, AstNode
from d810.backends.ast.z3 import Z3MopProver
from d810.backends.ast.z3_proof_policy import Z3ProofStatus
from d810.optimizers.microcode.instructions.z3.handler import Z3Rule
from d810.hexrays.ir.number_operand import safe_make_number


class Z3setzRuleGeneric(Z3Rule):
    DESCRIPTION = "Check with Z3 if a m_setz check is always True or False"
    PROOF_TRANSFORM_ID = "z-3-setz-generic"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(ida_hexrays.m_setz, AstLeaf("x_0"), AstLeaf("x_1"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("val_res"))

    def check_candidate(self, candidate):
        # setz result is a boolean (0 or 1), get size from destination operand
        # The destination size (e.g., %var_365.1 is 1 byte) determines result size,
        # NOT the operand sizes (e.g., x_0 may be 4 bytes)
        res_size = candidate.dst_mop.size if candidate.dst_mop else 1
        x0_mop = candidate["x_0"].mop
        x1_mop = candidate["x_1"].mop

        equal_result = Z3MopProver(policy=self.z3_proof_policy).prove_equal(
            x0_mop, x1_mop
        )
        if self.observe_z3_proof("prove_equal", equal_result) and (
            equal_result.status is Z3ProofStatus.PROVED
        ):
            candidate.add_constant_leaf("val_res", 1, res_size)
            return True
        unequal_result = Z3MopProver(policy=self.z3_proof_policy).prove_unequal(
            x0_mop, x1_mop
        )
        if self.observe_z3_proof("prove_unequal", unequal_result) and (
            unequal_result.status is Z3ProofStatus.PROVED
        ):
            candidate.add_constant_leaf("val_res", 0, res_size)
            return True

        # Check if comparing expression against constant 0
        # This handles opaque predicates like setz((x * (x-1)) & 1, 0)
        if (
            x1_mop is not None
            and x1_mop.t == ida_hexrays.mop_n
            and x1_mop.nnn.value == 0
        ):
            # setz(expr, 0) - check if expr is always 0 or always nonzero
            # Pass block/instruction context for backward tracking of register definitions
            zero_result = Z3MopProver(
                blk=self._current_blk,
                ins=self._current_ins,
                policy=self.z3_proof_policy,
            ).prove_always_zero(x0_mop)
            if self.observe_z3_proof("prove_always_zero", zero_result) and (
                zero_result.status is Z3ProofStatus.PROVED
            ):
                # expr is always 0, so setz(0, 0) = 1
                candidate.add_constant_leaf("val_res", 1, res_size)
                return True
            nonzero_result = Z3MopProver(
                blk=self._current_blk,
                ins=self._current_ins,
                policy=self.z3_proof_policy,
            ).prove_always_nonzero(x0_mop)
            if self.observe_z3_proof("prove_always_nonzero", nonzero_result) and (
                nonzero_result.status is Z3ProofStatus.PROVED
            ):
                # expr is always nonzero, so setz(nonzero, 0) = 0
                candidate.add_constant_leaf("val_res", 0, res_size)
                return True

        return False


class Z3setnzRuleGeneric(Z3Rule):
    DESCRIPTION = "Check with Z3 if a m_setnz check is always True or False"
    PROOF_TRANSFORM_ID = "z-3-setnz-generic"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(ida_hexrays.m_setnz, AstLeaf("x_0"), AstLeaf("x_1"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("val_res"))

    def check_candidate(self, candidate):
        # setnz result is a boolean (0 or 1), get size from destination operand
        # The destination size (e.g., %var_365.1 is 1 byte) determines result size,
        # NOT the operand sizes (e.g., x_0 may be 4 bytes)
        res_size = candidate.dst_mop.size if candidate.dst_mop else 1
        x0_mop = candidate["x_0"].mop
        x1_mop = candidate["x_1"].mop

        equal_result = Z3MopProver(policy=self.z3_proof_policy).prove_equal(
            x0_mop, x1_mop
        )
        if self.observe_z3_proof("prove_equal", equal_result) and (
            equal_result.status is Z3ProofStatus.PROVED
        ):
            candidate.add_constant_leaf("val_res", 0, res_size)
            return True
        unequal_result = Z3MopProver(policy=self.z3_proof_policy).prove_unequal(
            x0_mop, x1_mop
        )
        if self.observe_z3_proof("prove_unequal", unequal_result) and (
            unequal_result.status is Z3ProofStatus.PROVED
        ):
            candidate.add_constant_leaf("val_res", 1, res_size)
            return True

        # Check if comparing expression against constant 0
        # This handles opaque predicates like setnz((x * (x-1)) & 1, 0)
        if (
            x1_mop is not None
            and x1_mop.t == ida_hexrays.mop_n
            and x1_mop.nnn.value == 0
        ):
            # setnz(expr, 0) - check if expr is always 0 or always nonzero
            # Pass block/instruction context for backward tracking of register definitions
            zero_result = Z3MopProver(
                blk=self._current_blk,
                ins=self._current_ins,
                policy=self.z3_proof_policy,
            ).prove_always_zero(x0_mop)
            if self.observe_z3_proof("prove_always_zero", zero_result) and (
                zero_result.status is Z3ProofStatus.PROVED
            ):
                # expr is always 0, so setnz(0, 0) = 0
                candidate.add_constant_leaf("val_res", 0, res_size)
                return True
            nonzero_result = Z3MopProver(
                blk=self._current_blk,
                ins=self._current_ins,
                policy=self.z3_proof_policy,
            ).prove_always_nonzero(x0_mop)
            if self.observe_z3_proof("prove_always_nonzero", nonzero_result) and (
                nonzero_result.status is Z3ProofStatus.PROVED
            ):
                # expr is always nonzero, so setnz(nonzero, 0) = 1
                candidate.add_constant_leaf("val_res", 1, res_size)
                return True

        return False


class Z3lnotRuleGeneric(Z3Rule):
    DESCRIPTION = "Check with Z3 if a m_lnot check is always True or False"
    PROOF_TRANSFORM_ID = "z-3-lnot-generic"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(ida_hexrays.m_lnot, AstLeaf("x_0"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("val_res"))

    def check_candidate(self, candidate):
        # lnot result is a boolean (0 or 1), get size from destination operand
        res_size = candidate.dst_mop.size if candidate.dst_mop else 1
        prover = Z3MopProver(
            blk=self._current_blk,
            ins=self._current_ins,
            policy=self.z3_proof_policy,
        )
        # Resolve the operand through the current CFG context. Pair proving
        # treats a reaching register definition as an unconstrained variable;
        # the single-operand queries expand that definition before asking Z3.
        zero_result = prover.prove_always_zero(
            candidate["x_0"].mop
        )
        if self.observe_z3_proof("prove_always_zero", zero_result) and (
            zero_result.status is Z3ProofStatus.PROVED
        ):
            candidate.add_constant_leaf("val_res", 1, res_size)
            return True
        nonzero_result = prover.prove_always_nonzero(
            candidate["x_0"].mop
        )
        if self.observe_z3_proof("prove_always_nonzero", nonzero_result) and (
            nonzero_result.status is Z3ProofStatus.PROVED
        ):
            candidate.add_constant_leaf("val_res", 0, res_size)
            return True
        return False


class Z3SmodRuleGeneric(Z3Rule):
    DESCRIPTION = "Check with Z3 if a m_setz check is always True or False"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(ida_hexrays.m_smod, AstLeaf("x_0"), AstConstant("2", 2))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("val_res"))

    def check_candidate(self, candidate):
        # smod result size should match destination operand size
        res_size = candidate.dst_mop.size if candidate.dst_mop else 1
        cst_0_mop = ida_hexrays.mop_t()
        safe_make_number(cst_0_mop, 0, res_size)
        if Z3MopProver().are_equal(candidate.mop, cst_0_mop):
            candidate.add_leaf("val_res", cst_0_mop)
            return True
        cst_1_mop = ida_hexrays.mop_t()
        safe_make_number(cst_1_mop, 1, res_size)
        if Z3MopProver().are_equal(candidate.mop, cst_1_mop):
            candidate.add_leaf("val_res", cst_1_mop)
            return True
        return False

from functools import reduce

import ida_hexrays

from d810.core import getLogger
from d810.hexrays.hexrays_formatters import format_minsn_t
from d810.core.bits import AND_TABLE, SUB_TABLE
from d810.hexrays.hexrays_helpers import (
    equal_bnot_mop,
    equal_mops_ignore_size,
)
from d810.optimizers.microcode.instructions.chain.handler import ChainSimplificationRule

rules_chain_logger = getLogger("D810.rules.chain")


class ChainSimplification(object):
    def __init__(self, opcode, func_entry_ea: int = 0):
        self.opcode = opcode
        self.formatted_ins = ""
        self.non_cst_mop_list = []
        self.cst_mop_list = []
        self._is_instruction_simplified = False
        self.func_entry_ea = func_entry_ea

    def add_mop(self, mop):
        if (mop.t == ida_hexrays.mop_d) and (mop.d.opcode == self.opcode):
            self.add_mop(mop.d.l)
            self.add_mop(mop.d.r)
        else:
            if mop.t == ida_hexrays.mop_n:
                self.cst_mop_list.append(mop)
            else:
                self.non_cst_mop_list.append(mop)

    def do_simplification(self):
        final_mop_list = self.get_simplified_non_constant()
        final_mop_list += self.get_simplified_constant()
        return final_mop_list

    def get_simplified_constant(self):
        if len(self.cst_mop_list) == 0:
            return []
        elif len(self.cst_mop_list) == 1:
            return self.cst_mop_list
        else:
            cst_size_list = [c.size for c in self.cst_mop_list]
            cst_value_list = [c.nnn.value for c in self.cst_mop_list]
            final_cst_size = max(cst_size_list)
            rules_chain_logger.debug(
                "Doing cst simplification: {0}".format(cst_value_list)
            )
            self._is_instruction_simplified = True
            if self.opcode == ida_hexrays.m_xor:
                final_cst = reduce(lambda x, y: x ^ y, cst_value_list)
            elif self.opcode == ida_hexrays.m_and:
                final_cst = reduce(lambda x, y: x & y, cst_value_list)
            elif self.opcode == ida_hexrays.m_or:
                final_cst = reduce(lambda x, y: x | y, cst_value_list)
            elif self.opcode == ida_hexrays.m_add:
                final_cst = reduce(lambda x, y: x + y, cst_value_list)
            else:
                raise NotImplementedError("Euh")
            final_cst = final_cst & AND_TABLE[final_cst_size]
            rules_chain_logger.debug("Final cst: {0}".format(final_cst))
            final_cst_mop = ida_hexrays.mop_t()
            final_cst_mop.make_number(final_cst, max(cst_size_list))
            return [final_cst_mop]

    def get_simplified_non_constant(self):
        # Fast path
        if len(self.non_cst_mop_list) == 0:
            return []
        if len(self.non_cst_mop_list) == 1:
            return self.non_cst_mop_list

        # Local memo for equality to avoid recomputing within one instruction
        eq_memo: dict[tuple[int, int], bool] = {}

        def _eq(a, b) -> bool:
            ka, kb = id(a), id(b)
            key = (ka, kb) if ka <= kb else (kb, ka)
            cached = eq_memo.get(key)
            if cached is not None:
                return cached
            res = equal_mops_ignore_size(a, b)
            eq_memo[key] = res
            return res

        from d810.hexrays.hexrays_helpers import structural_mop_hash

        # Bucket first by structural hash and build per-bucket unique reps
        buckets: dict[int, list[ida_hexrays.mop_t]] = {}
        bucket_reps: dict[int, list[ida_hexrays.mop_t]] = {}
        unique: list[ida_hexrays.mop_t] = []

        for m in self.non_cst_mop_list:
            try:
                k = structural_mop_hash(m, self.func_entry_ea)
            except Exception:
                k = m.t
            reps = bucket_reps.setdefault(k, [])
            for rep in reps:
                if _eq(m, rep):
                    break
            else:
                reps.append(m)
                unique.append(m)
            buckets.setdefault(k, []).append(m)

        # Index mapping for removals over the flattened unique list
        idx_of = {id(m): i for i, m in enumerate(unique)}
        index_removed: set[int] = set()
        is_always_0 = False

        # Within-bucket reduction without O(n^2): group by equality
        for key, members in bucket_reps.items():
            if len(members) < 2:
                continue
            # Map representative id -> all indices in 'unique' that are equal to it
            groups: list[ida_hexrays.mop_t] = []
            group_indices: dict[int, list[int]] = {}

            # For each original member occurrence in this bucket, assign to a group
            for m in buckets[key]:
                # Find representative for this member
                for rep in members:
                    if _eq(m, rep):
                        rid = id(rep)
                        groups.append(rep) if rid not in group_indices else None
                        group_indices.setdefault(rid, []).append(idx_of[id(m)])
                        break

            # Now apply opcode-specific consolidation
            if self.opcode == ida_hexrays.m_xor:
                for rid, idxs in group_indices.items():
                    if len(idxs) % 2 == 0:
                        index_removed.update(idxs)
                    else:
                        # keep one, drop the rest
                        index_removed.update(idxs[1:])
            elif self.opcode in (ida_hexrays.m_and, ida_hexrays.m_or):
                for rid, idxs in group_indices.items():
                    # keep first occurrence only
                    index_removed.update(idxs[1:])

        # Cross-bucket bnot only when needed for AND → zero
        if self.opcode == ida_hexrays.m_and and not is_always_0:
            keys = list(bucket_reps.keys())
            for i in range(len(keys)):
                for j in range(i + 1, len(keys)):
                    for mi in bucket_reps[keys[i]]:
                        ii = idx_of[id(mi)]
                        if ii in index_removed:
                            continue
                        for mj in bucket_reps[keys[j]]:
                            jj = idx_of[id(mj)]
                            if jj in index_removed:
                                continue
                            if equal_bnot_mop(mi, mj):
                                is_always_0 = True
                                break
                        if is_always_0:
                            break
                if is_always_0:
                    break

        if len(index_removed) == 0 and not is_always_0:
            return unique

        final_mop_list: list[ida_hexrays.mop_t] = []
        self._is_instruction_simplified = True
        if is_always_0:
            final_mop_list.append(self.create_cst_mop(0, self.res_mop_size))
            return final_mop_list
        for idx, mop in enumerate(unique):
            if idx not in index_removed:
                final_mop_list.append(mop)
        return final_mop_list

    def simplify(self, ins):
        self.res_mop_size = ins.d.size
        if ins.opcode != self.opcode:
            return None

        self.formatted_ins = format_minsn_t(ins)
        self.non_cst_mop_list = []
        self.cst_mop_list = []
        self.add_mop(ins.l)
        self.add_mop(ins.r)

        self._is_instruction_simplified = False
        final_mop_list = self.do_simplification()
        if not self._is_instruction_simplified:
            return None

        return self.create_new_chain(ins, final_mop_list)

    def create_new_chain(self, original_ins, mop_list):
        new_ins = ida_hexrays.minsn_t(original_ins.ea)
        new_ins.opcode = self.opcode
        if len(mop_list) == 0:
            mop_list.append(self.create_cst_mop(0, original_ins.d.size))
        if len(mop_list) == 1:
            mop_list.append(self.create_cst_mop(0, original_ins.d.size))
        new_ins.l = self._create_mop_chain(
            original_ins, mop_list[:-1], original_ins.d.size
        )
        new_ins.r = mop_list[-1]
        if new_ins.r.t == ida_hexrays.mop_n:
            new_ins.r.size = original_ins.d.size
        new_ins.d = original_ins.d
        return new_ins

    def create_cst_mop(self, value, size):
        cst_mop = ida_hexrays.mop_t()
        cst_mop.make_number(value, size)
        return cst_mop

    def _create_mop_chain(self, ea, mop_list, size):
        if len(mop_list) == 1:
            return mop_list[0]
        new_ins = ida_hexrays.minsn_t(ea)
        new_ins.opcode = self.opcode
        new_ins.l = self._create_mop_chain(ea, mop_list[:-1], size)
        new_ins.r = mop_list[-1]
        new_ins.d = ida_hexrays.mop_t()
        new_ins.d.size = size
        mop = ida_hexrays.mop_t()
        mop.create_from_insn(new_ins)
        return mop


class ArithmeticChainSimplification(object):
    def __init__(self):
        self.formatted_ins = ""
        self.add_non_cst_mop_list = []
        self.add_cst_mop_list = []
        self.sub_non_cst_mop_list = []
        self.sub_cst_mop_list = []
        self.add_other_cst_list = []
        self.sub_other_cst_list = []
        self._is_instruction_simplified = False

    def add_mop(self, sign, mop):
        # sign is 0 if +, 1 is minus => minus minus = 1 ^ 1 = 0 so add
        if (mop.t == ida_hexrays.mop_d) and (mop.d.opcode in [ida_hexrays.m_add, ida_hexrays.m_sub]):

            self.add_mop(sign, mop.d.l)
            if mop.d.opcode == ida_hexrays.m_add:
                self.add_mop(sign, mop.d.r)
            else:
                self.add_mop(sign ^ 1, mop.d.r)
        elif (mop.t == ida_hexrays.mop_d) and (mop.d.opcode == ida_hexrays.m_neg):
            self.add_mop(sign ^ 1, mop.d.l)
        else:
            if mop.t == ida_hexrays.mop_n:
                if sign == 0:
                    self.add_cst_mop_list.append(mop)
                else:
                    self.sub_cst_mop_list.append(mop)
            else:
                if sign == 0:
                    self.add_non_cst_mop_list.append(mop)
                else:
                    self.sub_non_cst_mop_list.append(mop)

    def do_simplification(self):
        final_add_cst_list, final_sub_cst_list = self.get_simplified_constant()
        final_add_list, final_sub_list, final_add_cst_mop = (
            self.get_simplified_non_constant()
        )
        if final_add_cst_mop.nnn.value != 0:
            final_add_cst_list.append(final_add_cst_mop)
        return final_add_list, final_sub_list, final_add_cst_list, final_sub_cst_list

    def get_simplified_constant(self):
        if len(self.add_cst_mop_list) == 0 and len(self.sub_cst_mop_list) == 0:
            return [[], []]
        if len(self.add_cst_mop_list) == 1 and len(self.sub_cst_mop_list) == 0:
            return self.add_cst_mop_list, []
        if len(self.add_cst_mop_list) == 0 and len(self.sub_cst_mop_list) == 1:
            return [], self.sub_cst_mop_list
        add_cst_size_list = [c.size for c in self.add_cst_mop_list]
        add_cst_value_list = [c.nnn.value for c in self.add_cst_mop_list]
        sub_cst_size_list = [c.size for c in self.sub_cst_mop_list]
        sub_cst_value_list = [
            SUB_TABLE[c.size] - c.nnn.value for c in self.sub_cst_mop_list
        ]
        self._is_instruction_simplified = True

        final_cst_size = max(add_cst_size_list + sub_cst_size_list)
        rules_chain_logger.debug(
            "Doing arithmetic cst simplification: {0} {1}".format(
                add_cst_value_list, sub_cst_value_list
            )
        )
        final_cst = reduce(lambda x, y: x + y, add_cst_value_list + sub_cst_value_list)
        final_cst = final_cst & AND_TABLE[final_cst_size]
        rules_chain_logger.debug("Final cst: {0}".format(final_cst))
        final_cst_mop = ida_hexrays.mop_t()
        final_cst_mop.make_number(final_cst, final_cst_size)
        return [final_cst_mop], []

    def get_simplified_non_constant(self):
        if len(self.add_non_cst_mop_list) == 0 and len(self.sub_non_cst_mop_list) == 0:
            # Return an explicit zero-constant mop so callers can safely inspect .nnn
            zero = ida_hexrays.mop_t()
            zero.make_number(0, 1)
            return [], [], zero
        final_add_list = self.add_non_cst_mop_list
        final_sub_list = self.sub_non_cst_mop_list
        index_add_removed = []
        index_sub_removed = []
        for i, add_mop in enumerate(self.add_non_cst_mop_list):
            for j, sub_mop in enumerate(self.sub_non_cst_mop_list):
                if (i not in index_add_removed) and (j not in index_sub_removed):
                    if equal_mops_ignore_size(add_mop, sub_mop):
                        index_add_removed.append(i)
                        index_sub_removed.append(j)

        if len(index_add_removed) > 0:
            self._is_instruction_simplified = True
            final_add_list = []
            for i in range(len(self.add_non_cst_mop_list)):
                if i not in index_add_removed:
                    final_add_list.append(self.add_non_cst_mop_list[i])
            final_sub_list = []
            for i in range(len(self.sub_non_cst_mop_list)):
                if i not in index_sub_removed:
                    final_sub_list.append(self.sub_non_cst_mop_list[i])

        final_add_list, final_sub_list, final_add_cst_mop = self.check_bnot_mop(
            final_add_list, final_sub_list
        )
        return final_add_list, final_sub_list, final_add_cst_mop

    def check_bnot_mop(self, add_non_cst_mop_list, sub_non_cst_mop_list):
        add_index_removed = []
        sub_index_removed = []
        cst_value = 0
        final_add_non_cst_mop_list = add_non_cst_mop_list
        final_sub_non_cst_mop_list = sub_non_cst_mop_list
        add_size_list = [c.size for c in add_non_cst_mop_list]
        sub_size_list = [c.size for c in sub_non_cst_mop_list]
        final_cst_size = max(add_size_list + sub_size_list)

        for i in range(len(add_non_cst_mop_list)):
            for j in range(i + 1, len(add_non_cst_mop_list)):
                if (i not in add_index_removed) and (j not in add_index_removed):
                    if equal_bnot_mop(add_non_cst_mop_list[i], add_non_cst_mop_list[j]):
                        cst_value += AND_TABLE[add_non_cst_mop_list[i].size]
                        add_index_removed += [i, j]

        for i in range(len(sub_non_cst_mop_list)):
            for j in range(i + 1, len(sub_non_cst_mop_list)):
                if (i not in sub_index_removed) and (j not in sub_index_removed):
                    if equal_bnot_mop(sub_non_cst_mop_list[i], sub_non_cst_mop_list[j]):
                        cst_value += 1
                        sub_index_removed += [i, j]

        final_add_cst_mop = ida_hexrays.mop_t()
        final_add_cst_mop.make_number(
            cst_value & AND_TABLE[final_cst_size], final_cst_size
        )

        if len(add_index_removed) > 0:
            final_add_non_cst_mop_list = []
            self._is_instruction_simplified = True
            for i in range(len(add_non_cst_mop_list)):
                if i not in add_index_removed:
                    final_add_non_cst_mop_list.append(add_non_cst_mop_list[i])
        if len(sub_index_removed) > 0:
            final_sub_non_cst_mop_list = []
            self._is_instruction_simplified = True
            for i in range(len(sub_non_cst_mop_list)):
                if i not in sub_index_removed:
                    final_sub_non_cst_mop_list.append(sub_non_cst_mop_list[i])
        return final_add_non_cst_mop_list, final_sub_non_cst_mop_list, final_add_cst_mop

    def simplify(self, ins):
        if ins.opcode not in [ida_hexrays.m_add, ida_hexrays.m_sub]:
            return None
        self.formatted_ins = format_minsn_t(ins)
        self.add_non_cst_mop_list = []
        self.add_cst_mop_list = []
        self.sub_non_cst_mop_list = []
        self.sub_cst_mop_list = []
        self.add_mop(0, ins.l)
        if ins.opcode == ida_hexrays.m_add:
            self.add_mop(0, ins.r)
        else:
            self.add_mop(1, ins.r)

        self._is_instruction_simplified = False
        final_add_list, final_sub_list, final_add_cst_list, final_sub_cst_list = (
            self.do_simplification()
        )
        if not self._is_instruction_simplified:
            return None

        simplified_ins = self.create_new_chain(
            ins, final_add_list, final_sub_list, final_add_cst_list, final_sub_cst_list
        )

        return simplified_ins

    def create_new_chain(
        self,
        original_ins,
        final_add_list,
        final_sub_list,
        final_add_cst_list,
        final_sub_cst_list,
    ):
        mod_add = self._create_mop_add_chain(
            original_ins.ea, final_add_list + final_add_cst_list, original_ins.d.size
        )
        mod_sub = self._create_mop_add_chain(
            original_ins.ea, final_sub_list + final_sub_cst_list, original_ins.d.size
        )
        new_ins = ida_hexrays.minsn_t(original_ins.ea)
        new_ins.opcode = ida_hexrays.m_sub
        new_ins.l = mod_add
        new_ins.r = mod_sub
        new_ins.d = original_ins.d
        return new_ins

    def _create_mop_add_chain(self, ea, mop_list, size):
        if len(mop_list) == 0:
            res = ida_hexrays.mop_t()
            res.make_number(0, size)
            return res
        elif len(mop_list) == 1:
            return mop_list[0]
        new_ins = ida_hexrays.minsn_t(ea)
        new_ins.opcode = ida_hexrays.m_add
        new_ins.l = self._create_mop_add_chain(ea, mop_list[:-1], size)
        new_ins.r = mop_list[-1]
        new_ins.d = ida_hexrays.mop_t()
        new_ins.d.size = size
        mop = ida_hexrays.mop_t()
        mop.create_from_insn(new_ins)
        return mop


class XorChain(ChainSimplificationRule):
    DESCRIPTION = (
        "Remove XOR chains with common terms. E.g. x ^ 4 ^ y ^ 6 ^ 5 ^ x ==> y ^ 7"
    )

    def check_and_replace(self, blk, ins):
        func_ea = getattr(getattr(blk, "mba", None), "entry_ea", 0)
        xor_simplifier = ChainSimplification(ida_hexrays.m_xor, func_entry_ea=func_ea)
        new_ins = xor_simplifier.simplify(ins)
        return new_ins


class AndChain(ChainSimplificationRule):
    DESCRIPTION = (
        "Remove AND chains with common terms. E.g. x & 4 & y & 6 & 5 & x ==> x & y & 4"
    )

    def check_and_replace(self, blk, ins):
        func_ea = getattr(getattr(blk, "mba", None), "entry_ea", 0)
        and_simplifier = ChainSimplification(ida_hexrays.m_and, func_entry_ea=func_ea)
        new_ins = and_simplifier.simplify(ins)
        return new_ins


class OrChain(ChainSimplificationRule):
    DESCRIPTION = (
        "Remove OR chains with common terms. E.g. x | 4 | y | 6 | 5 | x ==> x | y | 7"
    )

    def check_and_replace(self, blk, ins):
        func_ea = getattr(getattr(blk, "mba", None), "entry_ea", 0)
        or_simplifier = ChainSimplification(ida_hexrays.m_or, func_entry_ea=func_ea)
        new_ins = or_simplifier.simplify(ins)
        return new_ins


class ArithmeticChain(ChainSimplificationRule):
    DESCRIPTION = "Remove arithmetic chains with common terms. E.g. x + 4 + y - (6 + x - 5) ==>  y + 3"

    def check_and_replace(self, blk, ins):
        arithmetic_simplifier = ArithmeticChainSimplification()
        new_ins = arithmetic_simplifier.simplify(ins)
        return new_ins

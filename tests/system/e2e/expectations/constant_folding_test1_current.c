// constant_folding_test1 - CURRENT OUTPUT (FIXED!)
// Address: 0x182c
// Generated: 2024-11-30
//
// STATUS: FULLY FOLDED
// After fixing FoldReadonlyDataRule to handle mop_v operands inside xdu/xds,
// the entire expression folds to a constant.
//
// The fix added handling for direct global variable references ($unk_CAEB.1)
// in addition to memory operands (mop_b), allowing the rule to fold:
//   xdu.8($unk_CAEB.1) -> 0x0C
//   xdu.4($unk_CAEC.1) -> 0x04
//   xdu.4($unk_CAF7.1) -> 0x02
//
// This enabled complete constant folding of the 59-line expression.

__int64 constant_folding_test1()
{
    return 1;
}

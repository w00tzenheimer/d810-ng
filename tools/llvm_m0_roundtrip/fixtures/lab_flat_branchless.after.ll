; ModuleID = 'lab_flat_branchless.before.ll'
source_filename = "lab_flat_branchless.m0"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "x86_64-pc-windows-msvc"

@state_sink = external global i32
@value_sink = external global i32

define i32 @lab_flat_branchless_m0(i32 %token) {
entry:
  %low = and i32 %token, 1
  %mask = sub nsw i32 0, %low
  %not_mask = add nsw i32 %low, -1
  %state_true = and i32 %mask, -1188804898
  %state_false = and i32 %not_mask, 1015636137
  %state = or i32 %state_false, %state_true
  store volatile i32 %state, ptr @state_sink, align 4
  %base = add i32 %token, 17
  %true_value = xor i32 %base, 34
  %false_value = add i32 %token, -34
  %true_part = and i32 %true_value, %mask
  %false_part = and i32 %not_mask, %false_value
  %value = or i32 %true_part, %false_part
  store volatile i32 %value, ptr @value_sink, align 4
  ret i32 %value
}

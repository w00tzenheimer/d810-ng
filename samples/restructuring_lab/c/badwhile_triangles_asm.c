/*
 * Restructuring-lab: BadWhileLoop triangle fixtures (hand-authored x64 asm).
 *
 * Ported VERBATIM from samples/src/c/hexrays_structuring_lab.c so the badwhile
 * registry cases can move off the retired hexrays_structuring_lab.dll onto this
 * lab's restructuring_lab.dll. The asm is byte-for-byte the same as the
 * previously compiled-CFG-validated form: every instruction keeps its length
 * (RIP-relative data displacements change value, not size), so block offsets,
 * opcodes, and edges are identical -> the recorded cfg_validation still holds.
 *
 * These are AT&T/GNU module-level asm blocks (not ml64 MASM): the C compiler
 * intentionally lowers the equivalent C conditional-goto arms through one-way
 * handoff blocks at -O0, which would erase the exact direct/trampoline edges
 * under test. Keeping the raw asm preserves them. If a future revision wants the
 * IDA-export MASM dialect (masm/), that is a re-authoring that must be
 * re-validated through the validate-cfg gate.
 *
 * g_hexrays_lab_sink is the shared volatile observable the arms store through;
 * it is defined here because these fixtures are this DLL's only users of it.
 */

volatile int g_hexrays_lab_sink = 0;

#if defined(_WIN64) || defined(__MINGW32__) || defined(__MINGW64__)
__asm__(
".text\n"
".att_syntax prefix\n"
".globl hexrays_lab_badwhile_direct_triangle_case_asm\n"
".def hexrays_lab_badwhile_direct_triangle_case_asm; .scl 2; .type 32; .endef\n"
"hexrays_lab_badwhile_direct_triangle_case_asm:\n"
"  leal 3(%ecx), %eax\n"
"  movl %ecx, %r8d\n"
"  andl $3, %r8d\n"
".Lbadwhile_direct_father:\n"
"  xorl $0x1111, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  testl $4, %r9d\n"
"  jne .Lbadwhile_direct_case_cond\n"
".Lbadwhile_direct_dispatcher:\n"
"  cmpl $1, %r8d\n"
"  je .Lbadwhile_direct_case_cond\n"
".Lbadwhile_direct_dispatcher_fallback:\n"
"  subl $0x17, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  jmp .Lbadwhile_direct_done\n"
".Lbadwhile_direct_case_cond:\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  addl %r8d, %r9d\n"
"  cmpl $0x4101, %r9d\n"
"  je .Lbadwhile_direct_case_true\n"
".Lbadwhile_direct_case_false:\n"
"  xorl $0x2424, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  jmp .Lbadwhile_direct_done\n"
".Lbadwhile_direct_case_true:\n"
"  addl $0x31, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
".Lbadwhile_direct_done:\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  retq\n"
);

__asm__(
".text\n"
".att_syntax prefix\n"
".globl hexrays_lab_badwhile_trampoline_triangle_case_asm\n"
".def hexrays_lab_badwhile_trampoline_triangle_case_asm; .scl 2; .type 32; .endef\n"
"hexrays_lab_badwhile_trampoline_triangle_case_asm:\n"
"  leal 5(%ecx), %eax\n"
"  movl %ecx, %r8d\n"
"  andl $7, %r8d\n"
".Lbadwhile_trampoline_father:\n"
"  xorl $0x2222, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  testl $8, %r9d\n"
"  je .Lbadwhile_trampoline_dispatcher\n"
".Lbadwhile_tri_trampoline:\n"
"  jmp .Lbadwhile_trampoline_case_cond\n"
".Lbadwhile_trampoline_dispatcher:\n"
"  cmpl $2, %r8d\n"
"  je .Lbadwhile_trampoline_case_cond\n"
".Lbadwhile_trampoline_dispatcher_fallback:\n"
"  subl $0x19, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  jmp .Lbadwhile_trampoline_done\n"
".Lbadwhile_trampoline_case_cond:\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  xorl %r8d, %r9d\n"
"  cmpl $0x4202, %r9d\n"
"  je .Lbadwhile_trampoline_case_true\n"
".Lbadwhile_trampoline_case_false:\n"
"  xorl $0x3535, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  jmp .Lbadwhile_trampoline_done\n"
".Lbadwhile_trampoline_case_true:\n"
"  addl $0x43, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
".Lbadwhile_trampoline_done:\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  retq\n"
);

__asm__(
".text\n"
".att_syntax prefix\n"
".globl hexrays_lab_badwhile_duplicate_group_triangle_asm\n"
".def hexrays_lab_badwhile_duplicate_group_triangle_asm; .scl 2; .type 32; .endef\n"
"hexrays_lab_badwhile_duplicate_group_triangle_asm:\n"
"  leal 7(%ecx), %eax\n"
"  movl %ecx, %r8d\n"
"  andl $15, %r8d\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  testl $1, %r9d\n"
"  jne .Lbadwhile_dup_pred_a\n"
"  jmp .Lbadwhile_dup_pred_b\n"
".Lbadwhile_dup_pred_a:\n"
"  addl $0x0A, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  testl $2, %r9d\n"
"  jne .Lbadwhile_dup_case_cond\n"
".Lbadwhile_dup_shared:\n"
"  xorl $0x5151, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  jmp .Lbadwhile_dup_dispatcher\n"
".Lbadwhile_dup_dispatcher:\n"
"  cmpl $3, %r8d\n"
"  je .Lbadwhile_dup_case_cond\n"
".Lbadwhile_dup_dispatcher_fallback:\n"
"  subl $0x1D, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  jmp .Lbadwhile_dup_done\n"
".Lbadwhile_dup_pred_b:\n"
"  subl $0x0B, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  testl $4, %r9d\n"
"  je .Lbadwhile_dup_shared\n"
".Lbadwhile_dup_case_cond:\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  subl %r8d, %r9d\n"
"  cmpl $0x4303, %r9d\n"
"  je .Lbadwhile_dup_case_true\n"
".Lbadwhile_dup_case_false:\n"
"  xorl $0x4646, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  jmp .Lbadwhile_dup_done\n"
".Lbadwhile_dup_case_true:\n"
"  addl $0x59, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
".Lbadwhile_dup_done:\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  retq\n"
);
#endif

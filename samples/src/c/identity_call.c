/**
 * identity_call.c - Test cases for Hikari-style identity call obfuscation
 *
 * Simulates Hikari's identity function obfuscation pattern where direct calls
 * are replaced with identity(off_XXX)() chains. The identity function simply
 * returns its first argument, and off_XXX global pointers hold target addresses.
 *
 * Pattern:
 *   // Original:  func(a, b)
 *   // Hikari:    identity_func(off_XXX)(a, b)  where off_XXX = &func
 *
 * At -O0, the identity function compiles to:
 *   x86-64 Windows: mov rax, rcx; ret   (rcx is first arg, rax is return)
 *   x86-64 SysV:    mov rax, rdi; ret   (rdi is first arg, rax is return)
 *
 * This is what arch_utils.is_identity_function() detects.
 *
 * Patterns created:
 * - Basic identity call with global pointer
 * - Trampoline chain (identity -> wrapper -> final target)
 * - Dual-entry table (both entries resolve to same target)
 * - Self-reference pattern (negative test)
 *
 * Target optimizer: IdentityCallResolver
 *
 * Compiled with: -O0 -g -fno-inline -fno-builtin
 */

#include "platform.h"
#include <stddef.h>
#include <stdint.h>

/* Prevent dead-code elimination */
volatile int g_identity_sink = 0;

/* ============================================================================
 * The Identity Function - Returns first argument unchanged
 *
 * At -O0, this compiles to a simple register move + return:
 *   Windows x64:  mov rax, rcx; ret   (RCX = arg1, RAX = return)
 *   SysV x64:     mov rax, rdi; ret   (RDI = arg1, RAX = return)
 *
 * This is the core pattern arch_utils.is_identity_function() detects.
 * ============================================================================ */
__attribute__((noinline))
static void* identity_func(void* arg) {
    return arg;
}

/* ============================================================================
 * Helper functions that identity calls resolve to
 * ============================================================================ */
__attribute__((noinline))
static int identity_helper_add(int a, int b) {
    int r = a + b;
    g_identity_sink = r;
    return r;
}

__attribute__((noinline))
static int identity_helper_sub(int a, int b) {
    int r = a - b;
    g_identity_sink = r;
    return r;
}

__attribute__((noinline))
static int identity_helper_mul(int a, int b) {
    int r = a * b;
    g_identity_sink = r;
    return r;
}

__attribute__((noinline))
static int identity_helper_xor(int a, int b) {
    int r = a ^ b;
    g_identity_sink = r;
    return r;
}

/* Function pointer type for binary operations */
typedef int (*binary_op_t)(int, int);

/* ============================================================================
 * Pattern 1: Basic identity call
 *
 * Hikari pattern: global pointer -> identity call -> indirect call to result
 *
 * Microcode sequence:
 *   1. m_ldx: Load global pointer into register
 *   2. m_call: Call identity_func with pointer as argument
 *   3. m_icall: Indirect call via returned pointer
 *
 * Expected resolution:
 *   - identity_func detected as identity (mov rax, rcx; ret)
 *   - Global pointer resolved to actual target address
 *   - Indirect call replaced with direct call
 * ============================================================================ */

/* Global pointers simulating Hikari's off_XXX relocations */
static void* g_identity_target_add = NULL;
static void* g_identity_target_sub = NULL;

EXPORT int identity_call_simple(int index, int a, int b)
{
    /* Runtime init (prevents compiler from optimizing away) */
    if (!g_identity_target_add) {
        g_identity_target_add = (void*)&identity_helper_add;
        g_identity_target_sub = (void*)&identity_helper_sub;
    }

    /* Select pointer based on index */
    void* ptr = (index & 1) ? g_identity_target_sub : g_identity_target_add;

    /* Hikari pattern: call identity with global ptr, then call result */
    binary_op_t resolved = (binary_op_t)identity_func(ptr);
    int result = resolved(a, b);

    g_identity_sink = result;
    return result;
}

/* ============================================================================
 * Pattern 2: Trampoline chain
 *
 * Two levels of indirection:
 *   1. Global pointer -> trampoline wrapper function
 *   2. Trampoline wrapper calls identity with ANOTHER global pointer
 *   3. Final target is the result of the second identity call
 *
 * Chain: caller -> identity(g_trampoline_ptr) -> trampoline_wrapper()
 *                -> identity(g_final_target) -> identity_helper_mul()
 *
 * Expected resolution:
 *   - Follow chain to final target
 *   - Depth tracking (max_trampoline_depth)
 *   - Cache results
 * ============================================================================ */

/* Second identity function (trampoline) */
__attribute__((noinline))
static void* trampoline_identity(void* arg) {
    return arg;
}

/* Global pointers for the chain */
static void* g_trampoline_ptr = NULL;  /* points to trampoline_wrapper */
static void* g_final_target = NULL;    /* points to identity_helper_mul */

/* Trampoline wrapper: calls identity with the REAL target */
__attribute__((noinline))
static int trampoline_wrapper(int a, int b) {
    binary_op_t resolved = (binary_op_t)trampoline_identity(g_final_target);
    int result = resolved(a, b);
    g_identity_sink = result;
    return result;
}

EXPORT int identity_call_trampoline_chain(int a, int b)
{
    if (!g_trampoline_ptr) {
        g_trampoline_ptr = (void*)&trampoline_wrapper;
        g_final_target = (void*)&identity_helper_mul;
    }

    /* First level: identity call resolves to trampoline_wrapper */
    binary_op_t first_hop = (binary_op_t)identity_func(g_trampoline_ptr);
    int result = first_hop(a, b);

    g_identity_sink = result;
    return result;
}

/* ============================================================================
 * Pattern 3: Dual-entry table
 *
 * Uses a table of global pointers where both entries resolve to the same
 * target. This simulates Hikari's table-based dispatch where multiple paths
 * lead to the same code.
 *
 * Expected resolution:
 *   - Table base detection (LEA instruction)
 *   - Resolve both table[0] and table[1]
 *   - Detect that both_same = true
 *   - Use single target for optimization
 * ============================================================================ */

static void* g_dual_table[2] = { NULL, NULL };

EXPORT int identity_call_dual_entry_table(int index, int a, int b)
{
    if (!g_dual_table[0]) {
        /* Both entries resolve to the same target (Hikari pattern) */
        g_dual_table[0] = (void*)&identity_helper_xor;
        g_dual_table[1] = (void*)&identity_helper_xor;
    }

    /* Index into table */
    index = index & 1;

    /* Identity call with table entry */
    binary_op_t resolved = (binary_op_t)identity_func(g_dual_table[index]);
    int result = resolved(a, b);

    g_identity_sink = result;
    return result;
}

/* ============================================================================
 * Pattern 4: Self-reference (negative test)
 *
 * The global pointer points back to the containing function itself. This
 * would cause infinite recursion if not detected.
 *
 * Expected behavior:
 *   - is_cff_dispatcher = true (both entries self-ref)
 *   - Pattern should be skipped (not transformed)
 *   - No crash/hang during analysis
 * ============================================================================ */

static void* g_self_ref_ptr = NULL;

EXPORT int identity_call_self_reference(int a, int b)
{
    if (!g_self_ref_ptr) {
        /* Self-reference: points to this function itself */
        g_self_ref_ptr = (void*)&identity_call_self_reference;
    }

    binary_op_t resolved = (binary_op_t)identity_func(g_self_ref_ptr);

    /* This would cause infinite recursion, but the resolver should
     * detect the self-reference and skip transformation */
    int result = resolved(a, b);

    g_identity_sink = result;
    return result;
}

/* ============================================================================
 * Pattern 5: Indirect jump pattern (Hikari assembly style)
 *
 * Instead of an indirect call, this uses an indirect jump after the identity
 * call. This is the classic Hikari pattern at assembly level:
 *   mov rdi, cs:off_XXX    ; Load pointer into arg1
 *   call identity_func     ; Call identity
 *   jmp rax                ; Jump to returned address
 *
 * We simulate this by making the identity call return control flow to the
 * caller, which then "jumps" by calling the result.
 * ============================================================================ */

static void* g_ijmp_target = NULL;

__attribute__((noinline))
static int ijmp_helper_shl(int a, int b) {
    int r = a << (b & 31);
    g_identity_sink = r;
    return r;
}

EXPORT int identity_call_indirect_jump(int a, int b)
{
    if (!g_ijmp_target) {
        g_ijmp_target = (void*)&ijmp_helper_shl;
    }

    /* Load pointer, call identity, use result (simulates jmp pattern) */
    binary_op_t resolved = (binary_op_t)identity_func(g_ijmp_target);
    int result = resolved(a, b);

    g_identity_sink = result;
    return result;
}

/* ============================================================================
 * Pattern 6: Conditional table dispatch
 *
 * Uses conditional logic to select between two different global pointers,
 * each going through identity call. This creates a more complex CFG.
 *
 * Expected resolution:
 *   - Both branches detected
 *   - Both pointers resolved
 *   - entry0_target != entry1_target (conditional dispatch)
 * ============================================================================ */

static void* g_cond_ptr_a = NULL;
static void* g_cond_ptr_b = NULL;

__attribute__((noinline))
static int cond_helper_and(int a, int b) {
    int r = a & b;
    g_identity_sink = r;
    return r;
}

__attribute__((noinline))
static int cond_helper_or(int a, int b) {
    int r = a | b;
    g_identity_sink = r;
    return r;
}

EXPORT int identity_call_conditional_dispatch(int index, int a, int b)
{
    if (!g_cond_ptr_a) {
        g_cond_ptr_a = (void*)&cond_helper_and;
        g_cond_ptr_b = (void*)&cond_helper_or;
    }

    /* Conditional selection */
    void* selected = (index < 5) ? g_cond_ptr_a : g_cond_ptr_b;

    /* Identity call with selected pointer */
    binary_op_t resolved = (binary_op_t)identity_func(selected);
    int result = resolved(a, b);

    g_identity_sink = result;
    return result;
}

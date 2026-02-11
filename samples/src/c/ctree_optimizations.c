/*
 * CTree Deobfuscation Test Cases for D810-ng
 *
 * This file consolidates all ctree-level optimization test patterns into
 * a single compilation unit. It covers four categories of patterns that
 * appear after microcode optimization when HexRays lifts obfuscated code
 * into its ctree AST:
 *
 *   1. Switch Folding  -- HIDWORD/LODWORD/PAIR64 constant dispatch
 *   2. Constant Folding -- XOR with known globals from the IDB
 *   3. Indirect Calls   -- Dispatch tables with additive/XOR offsets
 *   4. Combined         -- Realistic Hikari/OLLVM patterns mixing all three
 *
 * Compile: clang -O0 -c ctree_optimizations.c
 */

#include <stdint.h>


/* === SHARED: IDA/HexRays helper macros === */

#define HIDWORD(x)  ((uint32_t)((uint64_t)(x) >> 32))
#define LODWORD(x)  ((uint32_t)(x))
#define __PAIR64__(high, low) (((uint64_t)(uint32_t)(high) << 32) | (uint32_t)(low))


/* === SHARED: Volatile sinks (one per test category) === */

volatile int g_switch_input = 0;
volatile int g_switch_sink = 0;
volatile uint64_t g_const_fold_sink = 0;
volatile int g_indirect_sink = 0;
volatile int g_combined_sink = 0;
volatile uint64_t g_combined_sink64 = 0;


/* ========================================================================
 * ========================================================================
 *
 *                    SECTION: Switch Folding
 *
 * Simulates control-flow flattening (CFF) patterns where the switch
 * expression evaluates to a known constant at ctree level. These patterns
 * appear after microcode optimization when HexRays lifts flattened code
 * into its ctree AST.
 *
 * Key patterns tested:
 *
 * 1. HIDWORD encoding: switch(HIDWORD(combined_state))
 *    The obfuscator packs the real state into the upper 32 bits of a 64-bit
 *    variable via (STATE << 32) | junk. A ctree pass should recognize that
 *    HIDWORD(combined_state) is always a known constant and fold the switch.
 *
 * 2. OR-shift state encoding: combined = (STATE << 32) | noise
 *    The lower 32 bits carry junk/opaque data; only the upper half matters
 *    for dispatch. The ctree optimizer should see through the shift+or.
 *
 * 3. Direct constant switch: switch(known_const) where const is assigned
 *    unconditionally before the switch.
 *
 * Expected ctree optimization:
 *   - Recognize that the switch expression is constant
 *   - Replace switch with the body of the matching case
 *   - Eliminate dead cases
 *
 * ========================================================================
 * ======================================================================== */


/* ============================================================================
 * Pattern 1: HIDWORD switch with constant upper 32 bits
 *
 * After decompilation, HexRays produces code like:
 *   combined_state = (0x3u << 32) | some_runtime_value;
 *   switch (HIDWORD(combined_state)) { case 3: ... }
 *
 * The HIDWORD always evaluates to the constant 0x3, so the switch can be
 * folded to the body of case 3.
 * ============================================================================ */
__attribute__((noinline))
int ctree_hidword_switch_simple(int input)
{
    uint64_t combined_state;
    int result = 0;

    /* The upper 32 bits are always 0x00000003.
     * The lower 32 bits come from input (opaque junk). */
    combined_state = ((uint64_t)0x3 << 32) | (uint32_t)input;

    /* HIDWORD(combined_state) == 3 always.
     * A ctree pass should fold this switch to case 3. */
    switch (HIDWORD(combined_state))
    {
    case 0:
        result = input + 100;   /* dead */
        break;
    case 1:
        result = input * 2;    /* dead */
        break;
    case 2:
        result = input - 50;   /* dead */
        break;
    case 3:
        result = input ^ 0xDEAD; /* only reachable case */
        break;
    case 4:
        result = input + 999;   /* dead */
        break;
    default:
        result = -1;            /* dead */
        break;
    }

    g_switch_sink = result;
    return result;
}


/* ============================================================================
 * Pattern 2: HIDWORD switch with OR-shift encoding and multiple transitions
 *
 * A state machine where each state packs its successor into the upper 32 bits.
 * Each transition is:  combined = (NEXT_STATE << 32) | runtime_junk
 *
 * HexRays shows: switch(HIDWORD(combined)) for each iteration.
 * Since each assignment before the switch is to a known constant STATE,
 * each switch can be individually folded.
 * ============================================================================ */
__attribute__((noinline))
int ctree_hidword_switch_statemachine(int input)
{
    uint64_t combined;
    int result = input;
    int iteration;

    /* Initial state: upper 32 bits = 0xA */
    combined = ((uint64_t)0xA << 32) | (uint32_t)(input & 0xFFFF);

    for (iteration = 0; iteration < 4; iteration++)
    {
        /* HIDWORD(combined) is constant within each iteration.
         * Iteration 0: HIDWORD = 0xA -> case 0xA
         * Iteration 1: HIDWORD = 0xB -> case 0xB
         * Iteration 2: HIDWORD = 0xC -> case 0xC
         * Iteration 3: HIDWORD = 0xD -> case 0xD */
        switch (HIDWORD(combined))
        {
        case 0xA:
            result += 10;
            /* Transition to state 0xB, keep junk in low bits */
            combined = ((uint64_t)0xB << 32) | (uint32_t)(result * 3);
            break;

        case 0xB:
            result ^= 0xFF;
            /* Transition to state 0xC */
            combined = ((uint64_t)0xC << 32) | (uint32_t)(result + 7);
            break;

        case 0xC:
            result = (result << 1) | 1;
            /* Transition to state 0xD */
            combined = ((uint64_t)0xD << 32) | (uint32_t)(result);
            break;

        case 0xD:
            result -= 5;
            /* Transition back to 0xA for next loop */
            combined = ((uint64_t)0xA << 32) | (uint32_t)(result ^ 0x1234);
            break;

        default:
            result = -1; /* dead */
            break;
        }
    }

    g_switch_sink = result;
    return result;
}


/* ============================================================================
 * Pattern 3: __PAIR64__ encoding with HIDWORD dispatch
 *
 * Some obfuscators use IDA's __PAIR64__ macro to combine two 32-bit values:
 *   __PAIR64__(STATE_CONST, runtime_val)
 * which expands to ((uint64_t)STATE_CONST << 32) | (uint32_t)runtime_val.
 *
 * The ctree should recognize HIDWORD(__PAIR64__(C, x)) == C.
 * ============================================================================ */
__attribute__((noinline))
int ctree_pair64_hidword_dispatch(int a, int b)
{
    uint64_t packed;
    int result = a + b;

    /* State encoded via __PAIR64__ -- HIDWORD is always 0x42 */
    packed = __PAIR64__(0x42, result);

    switch (HIDWORD(packed))
    {
    case 0x40:
        result = a * b;         /* dead */
        break;
    case 0x41:
        result = a - b;         /* dead */
        break;
    case 0x42:
        result = (a ^ b) + 1;  /* only reachable */
        break;
    case 0x43:
        result = a | b;         /* dead */
        break;
    default:
        result = 0;             /* dead */
        break;
    }

    /* Second dispatch: re-pack with new state 0x43 */
    packed = __PAIR64__(0x43, result);

    switch (HIDWORD(packed))
    {
    case 0x42:
        result += 100;          /* dead */
        break;
    case 0x43:
        result = result * 2 + 3; /* only reachable */
        break;
    default:
        result = -1;            /* dead */
        break;
    }

    g_switch_sink = result;
    return result;
}


/* ============================================================================
 * Pattern 4: Direct constant switch (simplest case)
 *
 * The state variable is assigned a known constant, then immediately used
 * in a switch. No 64-bit packing -- just a plain constant propagation
 * opportunity at ctree level.
 *
 * This tests the baseline: if the ctree optimizer cannot handle this,
 * it certainly cannot handle the HIDWORD patterns.
 * ============================================================================ */
__attribute__((noinline))
int ctree_direct_const_switch(int input)
{
    volatile int state;
    int result = 0;

    /* State is always 7 -- volatile prevents compile-time folding,
     * but a ctree-level pass in IDA should still fold it. */
    state = 7;

    switch (state)
    {
    case 0:
        result = input + 1;
        break;
    case 3:
        result = input * 3;
        break;
    case 7:
        result = input ^ 0xBEEF;  /* only reachable */
        break;
    case 15:
        result = input >> 2;
        break;
    default:
        result = -1;
        break;
    }

    g_switch_sink = result;
    return result;
}


/* ============================================================================
 * Pattern 5: Nested HIDWORD dispatch (two-level state machine)
 *
 * Outer switch on HIDWORD selects a group, inner switch on LODWORD
 * selects the operation. Both are constants.
 * ============================================================================ */
__attribute__((noinline))
int ctree_nested_hidword_dispatch(int input)
{
    uint64_t combined;
    int result = input;

    /* Outer state = 2, inner state = 5 */
    combined = ((uint64_t)0x2 << 32) | (uint32_t)0x5;

    /* Outer dispatch: HIDWORD = 2 */
    switch (HIDWORD(combined))
    {
    case 0:
        result = input + 1;
        break;

    case 1:
        result = input - 1;
        break;

    case 2:
        /* Inner dispatch: LODWORD = 5 */
        switch (LODWORD(combined))
        {
        case 0:
            result = input * 10;
            break;
        case 5:
            result = input ^ 0xCAFE;  /* only reachable */
            break;
        case 10:
            result = input + 100;
            break;
        default:
            result = -1;
            break;
        }
        break;

    case 3:
        result = input << 3;
        break;

    default:
        result = -1;
        break;
    }

    g_switch_sink = result;
    return result;
}


/* ========================================================================
 * ========================================================================
 *
 *                    SECTION: Constant Folding
 *
 * Simulates XOR operations on global constants that survive into the
 * ctree level after microcode optimization. Obfuscators often store
 * encrypted data in global arrays and decrypt at runtime via XOR with
 * an immediate. When the global values are known (from the IDB), the
 * ctree optimizer can fold: known_global_value ^ IMMEDIATE = result.
 *
 * Key patterns tested:
 *
 * 1. Byte-level XOR: global_byte_array[i] ^ IMM8
 * 2. Word/dword/qword XOR: global_dword ^ IMM32, etc.
 * 3. Nested patterns: *(type*)&global ^ constant
 * 4. Chained XOR folding
 * 5. Function pointer decryption
 *
 * Expected ctree optimization:
 *   - Evaluate global[index] ^ constant at analysis time
 *   - Replace the expression with the resulting constant
 *   - Propagate the folded constant through uses
 *
 * ========================================================================
 * ======================================================================== */


/* ============================================================================
 * Global arrays with "known" values (in a real binary, these would be
 * read from the IDB's data segments).
 *
 * The XOR keys and expected results are documented for each test.
 * ============================================================================ */

/* 1-byte array: XOR key 0x5A -> plaintext "Hello!!!" */
uint8_t g_encrypted_bytes[8] = {
    0x12, 0x3F, 0x36, 0x36, 0x35, 0x6B, 0x6B, 0x6B
    /* 0x12^0x5A='H', 0x3F^0x5A='e', 0x36^0x5A='l', 0x36^0x5A='l',
     * 0x35^0x5A='o', 0x6B^0x5A='!', 0x6B^0x5A='!', 0x6B^0x5A='!' */
};

/* 2-byte (uint16_t) array: XOR key 0xBEEF */
uint16_t g_encrypted_words[4] = {
    0xBEEF ^ 0x0001,   /* = 0xBEEE, decrypts to 0x0001 */
    0xBEEF ^ 0x0002,   /* = 0xBEED, decrypts to 0x0002 */
    0xBEEF ^ 0x1234,   /* = 0xACDB, decrypts to 0x1234 */
    0xBEEF ^ 0xFFFF    /* = 0x4110, decrypts to 0xFFFF */
};

/* 4-byte (uint32_t) array: XOR key 0xDEADBEEF */
uint32_t g_encrypted_dwords[4] = {
    0xDEADBEEF ^ 0x00000000,  /* = 0xDEADBEEF, decrypts to 0 */
    0xDEADBEEF ^ 0x12345678,  /* = 0xCC99E897, decrypts to 0x12345678 */
    0xDEADBEEF ^ 0xCAFEBABE,  /* = 0x14530451, decrypts to 0xCAFEBABE */
    0xDEADBEEF ^ 0xFFFFFFFF   /* = 0x21524110, decrypts to 0xFFFFFFFF */
};

/* 8-byte (uint64_t) value: XOR key 0x0123456789ABCDEF */
uint64_t g_encrypted_qword = (uint64_t)0x0123456789ABCDEF ^ (uint64_t)0xDEADDEADDEADDEAD;
/* = 0xDF8E9BCA5706134A, decrypts to 0xDEADDEADDEADDEAD */

/* Single dword for pointer-cast pattern */
uint32_t g_encrypted_single = 0xA5A5A5A5;
/* XOR with 0x5A5A5A5A -> 0xFFFFFFFF (-1 signed) */


/* ============================================================================
 * Pattern 1: Byte-level XOR folding
 *
 * Simulates: decrypted[i] = g_encrypted_bytes[i] ^ 0x5A
 * Each byte is a known global; the XOR should fold to a constant.
 * ============================================================================ */
__attribute__((noinline))
int ctree_xor_fold_bytes(void)
{
    uint8_t decrypted[8];
    int i;

    /* Each of these XOR operations involves a known global and
     * a constant immediate. A ctree pass should fold each to the
     * plaintext byte. */
    for (i = 0; i < 8; i++)
    {
        decrypted[i] = g_encrypted_bytes[i] ^ 0x5A;
    }

    /* Use the result to prevent elimination */
    g_const_fold_sink = decrypted[0] | ((uint64_t)decrypted[4] << 32);
    return (int)decrypted[0];
}


/* ============================================================================
 * Pattern 2: Multi-size XOR folding (2-byte, 4-byte, 8-byte)
 *
 * Tests that the optimizer handles different operand widths correctly.
 * Each XOR involves a global with known value and a constant key.
 * ============================================================================ */
__attribute__((noinline))
uint64_t ctree_xor_fold_multisz(void)
{
    uint16_t w;
    uint32_t d;
    uint64_t q;

    /* 2-byte XOR: g_encrypted_words[2] (0xACDB) ^ 0xBEEF = 0x1234 */
    w = g_encrypted_words[2] ^ 0xBEEF;

    /* 4-byte XOR: g_encrypted_dwords[1] (0xCC99E897) ^ 0xDEADBEEF = 0x12345678 */
    d = g_encrypted_dwords[1] ^ 0xDEADBEEF;

    /* 8-byte XOR: g_encrypted_qword ^ key = 0xDEADDEADDEADDEAD */
    q = g_encrypted_qword ^ (uint64_t)0x0123456789ABCDEF;

    g_const_fold_sink = (uint64_t)w + (uint64_t)d + q;
    return (uint64_t)w + (uint64_t)d + q;
}


/* ============================================================================
 * Pattern 3: Pointer-to-global XOR with cast
 *
 * HexRays sometimes produces code like:
 *   *(uint32_t*)&g_encrypted_single ^ 0x5A5A5A5A
 * or with a cast:
 *   (uint16_t)g_encrypted_dwords[0] ^ 0xBEEF
 *
 * The optimizer must handle the pointer dereference / cast and still
 * recognize the global value.
 * ============================================================================ */
__attribute__((noinline))
int ctree_xor_fold_ptr_cast(void)
{
    uint32_t via_ptr;
    uint16_t via_cast;
    uint32_t via_lobyte;
    int result;

    /* Pattern A: dereference pointer to known global, then XOR.
     * *(uint32_t*)&g_encrypted_single = 0xA5A5A5A5
     * 0xA5A5A5A5 ^ 0x5A5A5A5A = 0xFFFFFFFF */
    via_ptr = *(uint32_t *)&g_encrypted_single ^ 0x5A5A5A5A;

    /* Pattern B: truncating cast of a dword global, then XOR.
     * (uint16_t)g_encrypted_dwords[0] = (uint16_t)0xDEADBEEF = 0xBEEF
     * 0xBEEF ^ 0xBEEF = 0x0000 */
    via_cast = (uint16_t)g_encrypted_dwords[0] ^ 0xBEEF;

    /* Pattern C: extract low byte of known global, then XOR.
     * (uint8_t)g_encrypted_dwords[2] = (uint8_t)0x14530451 = 0x51
     * 0x51 ^ 0x51 = 0x00 */
    via_lobyte = (uint8_t)g_encrypted_dwords[2] ^ 0x51;

    result = (int)via_ptr + (int)via_cast + (int)via_lobyte;
    g_const_fold_sink = result;
    return result;
}


/* ============================================================================
 * Pattern 4: Chained XOR folding
 *
 * Multiple sequential XOR operations where each intermediate result
 * is also foldable:
 *   temp1 = global_a ^ KEY1
 *   temp2 = temp1 ^ KEY2
 *   result = temp2 ^ KEY3
 *
 * If global_a is known, all three XORs can be folded into a single
 * constant: global_a ^ KEY1 ^ KEY2 ^ KEY3
 * ============================================================================ */
__attribute__((noinline))
uint32_t ctree_xor_fold_chained(void)
{
    uint32_t temp1, temp2, result;

    /* g_encrypted_dwords[3] = 0x21524110
     * temp1 = 0x21524110 ^ 0x11111111 = 0x30435001
     * temp2 = 0x30435001 ^ 0x22222222 = 0x12617223
     * result = 0x12617223 ^ 0x33333333 = 0x21524110 (back to original)
     *
     * Net effect: XOR with (0x11111111 ^ 0x22222222 ^ 0x33333333) = 0x00000000
     * So result == g_encrypted_dwords[3] */
    temp1 = g_encrypted_dwords[3] ^ 0x11111111;
    temp2 = temp1 ^ 0x22222222;
    result = temp2 ^ 0x33333333;

    g_const_fold_sink = result;
    return result;
}


/* ============================================================================
 * Pattern 5: XOR folding used as function pointer decryption
 *
 * A common obfuscation pattern: function addresses are stored XOR'd
 * with a key. At call time:
 *   real_addr = encrypted_addr ^ KEY
 *   ((fn_t)real_addr)(args)
 *
 * At ctree level, if encrypted_addr is a known global, the XOR folds
 * to reveal the true target address.
 * ============================================================================ */

typedef int (*simple_fn_t)(int);

/* Simulate an encrypted function pointer.
 * In real obfuscation, this would hold: real_func_addr ^ 0xDEADC0DE */
uint32_t g_encrypted_func_ptr = 0x12345678 ^ 0xDEADC0DE;
/* = 0xCC8996A6 -- XOR with key gives back 0x12345678 */

__attribute__((noinline))
uint32_t ctree_xor_fold_func_ptr(int arg)
{
    uint32_t decrypted_addr;

    /* Decrypt the function pointer: known global ^ constant key.
     * A ctree pass should fold this to the constant 0x12345678. */
    decrypted_addr = g_encrypted_func_ptr ^ 0xDEADC0DE;

    /* In a real binary, the next line would be:
     *   return ((simple_fn_t)decrypted_addr)(arg);
     * We just return the address to avoid calling into garbage. */
    g_const_fold_sink = decrypted_addr;
    return decrypted_addr + (uint32_t)arg;
}


/* ========================================================================
 * ========================================================================
 *
 *                    SECTION: Indirect Call Resolution
 *
 * Simulates indirect calls through obfuscated dispatch tables.
 * Obfuscators store function pointers with an additive or XOR offset to
 * hide the real targets. At the call site, the offset is subtracted (or
 * XORed) to recover the true address:
 *
 *   ((func_t)(table[index] - OFFSET))(args)
 *
 * After microcode optimization, HexRays lifts these into ctree nodes like:
 *   cot_call -> cot_cast -> cot_sub(cot_idx(table, index), cot_num(OFFSET))
 *
 * A ctree pass should:
 *   1. Recognize the table[index] - OFFSET pattern
 *   2. Look up table[index] from the IDB
 *   3. Compute the real address: table[index] - OFFSET
 *   4. Replace the indirect call with a direct call
 *
 * NOTE: In a real binary, the dispatch tables contain raw addresses from
 * the IDB data segment. We simulate this with hardcoded numeric addresses.
 * The tables are populated at runtime via init functions to make this
 * compilable.
 *
 * ========================================================================
 * ======================================================================== */


/* Target function implementations for indirect call tests */
__attribute__((noinline))
int target_add(int a, int b) { return a + b; }

__attribute__((noinline))
int target_sub(int a, int b) { return a - b; }

__attribute__((noinline))
int target_mul(int a, int b) { return a * b; }

__attribute__((noinline))
int target_div(int a, int b) { return b != 0 ? a / b : 0; }

__attribute__((noinline))
int target_xor(int a, int b) { return a ^ b; }

__attribute__((noinline))
int target_and(int a, int b) { return a & b; }

/* Function pointer type for binary operations */
typedef int (*binop_fn_t)(int, int);


/* ============================================================================
 * Obfuscation offset constants
 *
 * In real obfuscated binaries, the table entries are:
 *   obfuscated_ptr = real_func_addr + OFFSET
 * At call time:
 *   real_func_addr = obfuscated_ptr - OFFSET
 * ============================================================================ */

#define TABLE1_OFFSET    0x10000
#define TABLE2_OFFSET    0xDEAD0000u
#define TABLE3_OFFSET    0x42424242u
#define XOR_DISPATCH_KEY 0xCAFEBABEu
#define INLINE_OFFSET    0x1000


/* ============================================================================
 * Simulated IDB addresses for target functions.
 *
 * In an actual IDA database, the function addresses would be known values
 * like 0x00401000. We simulate this: the dispatch table holds these fake
 * addresses + OFFSET. After subtracting the offset, the ctree optimizer
 * recovers the real address and can match it against known functions.
 * ============================================================================ */

#define ADDR_TARGET_ADD  0x00401000u
#define ADDR_TARGET_SUB  0x00401100u
#define ADDR_TARGET_MUL  0x00401200u
#define ADDR_TARGET_DIV  0x00401300u
#define ADDR_TARGET_XOR  0x00401400u
#define ADDR_TARGET_AND  0x00401500u


/* ============================================================================
 * Pattern 1: Simple dispatch table with additive offset
 *
 * Table stores: real_addr + TABLE1_OFFSET
 * Call pattern: ((fn_t)(table[i] - TABLE1_OFFSET))(a, b)
 *
 * The ctree optimizer should:
 *   - Read table[i] from the data segment (e.g., 0x00411000)
 *   - Subtract TABLE1_OFFSET (0x10000)
 *   - Resolve to the real function address (0x00401000 = target_add)
 *
 * In the compiled test, we use runtime-initialized tables and real
 * function pointers so the code actually runs correctly.
 * ============================================================================ */

static uint64_t g_dispatch_table1[4];

__attribute__((noinline))
void init_dispatch_table1(void)
{
    g_dispatch_table1[0] = (uint64_t)(unsigned long)&target_add + TABLE1_OFFSET;
    g_dispatch_table1[1] = (uint64_t)(unsigned long)&target_sub + TABLE1_OFFSET;
    g_dispatch_table1[2] = (uint64_t)(unsigned long)&target_mul + TABLE1_OFFSET;
    g_dispatch_table1[3] = (uint64_t)(unsigned long)&target_div + TABLE1_OFFSET;
}

__attribute__((noinline))
int ctree_indirect_call_simple(int index, int a, int b)
{
    binop_fn_t fn;
    int result;

    /* Clamp index to valid range */
    index = index & 0x3;

    /* Deobfuscate: subtract offset to recover real function pointer.
     * In the ctree, this appears as:
     *   (binop_fn_t)(g_dispatch_table1[index] - 0x10000) */
    fn = (binop_fn_t)(unsigned long)(g_dispatch_table1[index] - TABLE1_OFFSET);

    result = fn(a, b);
    g_indirect_sink = result;
    return result;
}


/* ============================================================================
 * Pattern 2: XOR-obfuscated dispatch table
 *
 * Instead of addition, the table entries are XORed with a key:
 *   obfuscated_ptr = real_addr ^ XOR_KEY
 *   real_addr = obfuscated_ptr ^ XOR_KEY
 *
 * This pattern tests XOR-based deobfuscation at ctree level.
 * ============================================================================ */

static uint64_t g_dispatch_table_xor[4];

__attribute__((noinline))
void init_dispatch_table_xor(void)
{
    g_dispatch_table_xor[0] = (uint64_t)(unsigned long)&target_add ^ XOR_DISPATCH_KEY;
    g_dispatch_table_xor[1] = (uint64_t)(unsigned long)&target_sub ^ XOR_DISPATCH_KEY;
    g_dispatch_table_xor[2] = (uint64_t)(unsigned long)&target_mul ^ XOR_DISPATCH_KEY;
    g_dispatch_table_xor[3] = (uint64_t)(unsigned long)&target_xor ^ XOR_DISPATCH_KEY;
}

__attribute__((noinline))
int ctree_indirect_call_xor(int index, int a, int b)
{
    binop_fn_t fn;
    int result;

    index = index & 0x3;

    /* XOR deobfuscation at call site.
     * ctree: (binop_fn_t)(g_dispatch_table_xor[index] ^ 0xCAFEBABE) */
    fn = (binop_fn_t)(unsigned long)(g_dispatch_table_xor[index] ^ XOR_DISPATCH_KEY);

    result = fn(a, b);
    g_indirect_sink = result;
    return result;
}


/* ============================================================================
 * Pattern 3: Large table with different offset and stride
 *
 * A 6-entry table with a large offset (0xDEAD0000).
 * Tests that the optimizer handles larger tables and different offsets.
 * ============================================================================ */

static uint64_t g_dispatch_table_large[6];

__attribute__((noinline))
void init_dispatch_table_large(void)
{
    g_dispatch_table_large[0] = (uint64_t)(unsigned long)&target_add + TABLE2_OFFSET;
    g_dispatch_table_large[1] = (uint64_t)(unsigned long)&target_sub + TABLE2_OFFSET;
    g_dispatch_table_large[2] = (uint64_t)(unsigned long)&target_mul + TABLE2_OFFSET;
    g_dispatch_table_large[3] = (uint64_t)(unsigned long)&target_div + TABLE2_OFFSET;
    g_dispatch_table_large[4] = (uint64_t)(unsigned long)&target_xor + TABLE2_OFFSET;
    g_dispatch_table_large[5] = (uint64_t)(unsigned long)&target_and + TABLE2_OFFSET;
}

__attribute__((noinline))
int ctree_indirect_call_large_table(int index, int a, int b)
{
    binop_fn_t fn;

    /* Clamp to 6 entries */
    if (index < 0 || index >= 6)
        index = 0;

    /* Subtract large offset */
    fn = (binop_fn_t)(unsigned long)(g_dispatch_table_large[index] - TABLE2_OFFSET);

    g_indirect_sink = fn(a, b);
    return g_indirect_sink;
}


/* ============================================================================
 * Pattern 4: Chained dispatch (dispatcher calls another dispatcher)
 *
 * First-level dispatcher selects a second-level table based on opcode.
 * Second-level table provides the actual function pointer.
 *
 * ctree pattern:
 *   level2_table = (table_t*)(g_level1[opcode] - OFFSET1)
 *   fn = (fn_t)(level2_table[subop] - OFFSET2)
 *   fn(a, b)
 * ============================================================================ */

/* Second-level tables (one per opcode group) */
static uint64_t g_level2_arith[2];
static uint64_t g_level2_bitwise[2];

/* First-level table: points to second-level tables (with offset) */
static uint64_t g_level1_dispatch[2];

__attribute__((noinline))
void init_dispatch_chained(void)
{
    /* Level 2: actual function pointers + offset */
    g_level2_arith[0]   = (uint64_t)(unsigned long)&target_add + TABLE3_OFFSET;
    g_level2_arith[1]   = (uint64_t)(unsigned long)&target_sub + TABLE3_OFFSET;
    g_level2_bitwise[0] = (uint64_t)(unsigned long)&target_xor + TABLE3_OFFSET;
    g_level2_bitwise[1] = (uint64_t)(unsigned long)&target_and + TABLE3_OFFSET;

    /* Level 1: pointers to level-2 tables + offset */
    g_level1_dispatch[0] = (uint64_t)(unsigned long)g_level2_arith   + TABLE1_OFFSET;
    g_level1_dispatch[1] = (uint64_t)(unsigned long)g_level2_bitwise + TABLE1_OFFSET;
}

__attribute__((noinline))
int ctree_indirect_call_chained(int opcode, int subop, int a, int b)
{
    uint64_t *level2;
    binop_fn_t fn;

    /* Clamp indices */
    opcode = opcode & 0x1;
    subop  = subop & 0x1;

    /* First level: get pointer to second-level table.
     * g_level1_dispatch[opcode] - TABLE1_OFFSET = &g_level2_xxx */
    level2 = (uint64_t *)(unsigned long)(g_level1_dispatch[opcode] - TABLE1_OFFSET);

    /* Second level: get actual function pointer.
     * level2[subop] - TABLE3_OFFSET = real function address */
    fn = (binop_fn_t)(unsigned long)(level2[subop] - TABLE3_OFFSET);

    g_indirect_sink = fn(a, b);
    return g_indirect_sink;
}


/* ============================================================================
 * Pattern 5: Indirect call with inline offset computation
 *
 * Some obfuscators compute the offset inline rather than using a simple
 * subtraction. For example:
 *   fn = (fn_t)(table[i] + (~OFFSET + 1))   // equivalent to - OFFSET
 *   fn = (fn_t)((table[i] ^ MASK) - EXTRA)  // XOR then subtract
 *
 * These test more complex deobfuscation at ctree level.
 * ============================================================================ */

static uint64_t g_dispatch_inline[3];

__attribute__((noinline))
void init_dispatch_inline(void)
{
    g_dispatch_inline[0] = (uint64_t)(unsigned long)&target_add + INLINE_OFFSET;
    g_dispatch_inline[1] = (uint64_t)(unsigned long)&target_mul + INLINE_OFFSET;
    g_dispatch_inline[2] = (uint64_t)(unsigned long)&target_xor + INLINE_OFFSET;
}

__attribute__((noinline))
int ctree_indirect_call_inline_arith(int index, int a, int b)
{
    binop_fn_t fn;

    index = index % 3;
    if (index < 0) index = 0;

    /* Offset subtracted via two's complement: + (~0x1000 + 1) = - 0x1000
     * The ctree should recognize this as equivalent to a simple subtraction. */
    fn = (binop_fn_t)(unsigned long)(g_dispatch_inline[index] + (uint64_t)(~(uint64_t)INLINE_OFFSET + 1));

    g_indirect_sink = fn(a, b);
    return g_indirect_sink;
}


/* ============================================================================
 * Initialization entry point for indirect call tables
 *
 * Calls all table init functions. In a real binary, these tables would
 * be pre-populated in the data segment; the init functions exist only
 * to make this test compilable.
 * ============================================================================ */
__attribute__((noinline))
void ctree_indirect_init_all(void)
{
    init_dispatch_table1();
    init_dispatch_table_xor();
    init_dispatch_table_large();
    init_dispatch_chained();
    init_dispatch_inline();
}


/* ========================================================================
 * ========================================================================
 *
 *                    SECTION: Combined Patterns
 *
 * Simulates a realistic scenario combining multiple ctree-level
 * obfuscation patterns in single functions. Represents what a real
 * Hikari/OLLVM-obfuscated binary looks like after microcode-level passes
 * have already simplified the low-level patterns, leaving higher-level
 * obfuscation artifacts for the ctree optimizer to clean up.
 *
 * Patterns combined:
 *   - HIDWORD switch folding (CFF state machine)
 *   - XOR-encrypted global constants
 *   - Indirect calls through offset-obfuscated dispatch tables
 *   - Opaque predicates surviving to ctree level
 *
 * Each function increases in complexity:
 *   1. hikari_string_decrypt: XOR decryption + HIDWORD state machine
 *   2. hikari_dispatch_engine: State machine + indirect call dispatch
 *   3. hikari_full_pipeline: All patterns in a single function
 *   4. hikari_nested_vm: VM-like nested dispatch with encrypted operands
 *
 * ========================================================================
 * ======================================================================== */


/* Encrypted string "PASS" (XOR key 0x37) */
uint8_t g_enc_str[4] = {
    'P' ^ 0x37,  /* 0x67 */
    'A' ^ 0x37,  /* 0x76 */
    'S' ^ 0x37,  /* 0x64 */
    'S' ^ 0x37   /* 0x64 */
};

/* Encrypted operation constants (XOR key 0xDEADBEEF) */
uint32_t g_enc_add_key  = 0x0000002A ^ 0xDEADBEEF;  /* 42 ^ key */
uint32_t g_enc_mul_key  = 0x00000003 ^ 0xDEADBEEF;  /* 3 ^ key  */
uint32_t g_enc_xor_mask = 0x0000FF00 ^ 0xDEADBEEF;  /* 0xFF00 ^ key */
uint32_t g_enc_sentinel = 0xCAFEBABE ^ 0xDEADBEEF;  /* sentinel ^ key */

/* Target functions for combined indirect calls */
__attribute__((noinline))
int combined_op_add(int val, int key)
{
    return val + key;
}

__attribute__((noinline))
int combined_op_mul(int val, int key)
{
    return val * key;
}

__attribute__((noinline))
int combined_op_xor(int val, int key)
{
    return val ^ key;
}

__attribute__((noinline))
int combined_op_sub(int val, int key)
{
    return val - key;
}

typedef int (*combined_op_fn)(int, int);

/* Dispatch table with additive obfuscation offset */
#define COMBINED_TABLE_OFFSET 0x7F000000u

static uint64_t g_combined_dispatch[4];

__attribute__((noinline))
void init_combined_dispatch(void)
{
    g_combined_dispatch[0] = (uint64_t)(unsigned long)&combined_op_add + COMBINED_TABLE_OFFSET;
    g_combined_dispatch[1] = (uint64_t)(unsigned long)&combined_op_mul + COMBINED_TABLE_OFFSET;
    g_combined_dispatch[2] = (uint64_t)(unsigned long)&combined_op_xor + COMBINED_TABLE_OFFSET;
    g_combined_dispatch[3] = (uint64_t)(unsigned long)&combined_op_sub + COMBINED_TABLE_OFFSET;
}


/* ============================================================================
 * Function 1: XOR decryption + HIDWORD state machine
 *
 * Simulates a Hikari-obfuscated string decryption routine. The function:
 *   1. Uses HIDWORD switch to control the decryption state machine
 *   2. XORs encrypted globals with a key to recover plaintext bytes
 *   3. Each state processes one byte, then transitions to the next state
 *
 * After ctree optimization, this should simplify to a linear sequence
 * of XOR operations producing the plaintext string.
 * ============================================================================ */
__attribute__((noinline))
uint32_t hikari_string_decrypt(int seed)
{
    uint64_t state_combined;
    uint32_t plaintext = 0;
    uint8_t byte_val;

    /* State 1: decrypt first byte */
    state_combined = ((uint64_t)0x1 << 32) | (uint32_t)seed;

    switch (HIDWORD(state_combined))
    {
    case 0:  /* dead */
        plaintext = 0xFFFFFFFF;
        break;

    case 1:  /* HIDWORD is always 1 here */
        /* XOR fold: g_enc_str[0] (0x67) ^ 0x37 = 0x50 = 'P' */
        byte_val = g_enc_str[0] ^ 0x37;
        plaintext = (uint32_t)byte_val;
        /* Transition to state 2 */
        state_combined = ((uint64_t)0x2 << 32) | (uint32_t)(seed ^ 0xFF);
        break;

    default:
        plaintext = 0;
        break;
    }

    /* State 2: decrypt second byte */
    switch (HIDWORD(state_combined))
    {
    case 1:  /* dead */
        plaintext |= 0xFF00;
        break;

    case 2:  /* HIDWORD is always 2 here */
        byte_val = g_enc_str[1] ^ 0x37;  /* 0x76 ^ 0x37 = 0x41 = 'A' */
        plaintext |= ((uint32_t)byte_val << 8);
        state_combined = ((uint64_t)0x3 << 32) | (uint32_t)(seed + 1);
        break;

    default:
        break;
    }

    /* State 3: decrypt third byte */
    switch (HIDWORD(state_combined))
    {
    case 2:  /* dead */
        break;

    case 3:  /* HIDWORD is always 3 here */
        byte_val = g_enc_str[2] ^ 0x37;  /* 0x64 ^ 0x37 = 0x53 = 'S' */
        plaintext |= ((uint32_t)byte_val << 16);
        state_combined = ((uint64_t)0x4 << 32) | (uint32_t)(seed - 1);
        break;

    default:
        break;
    }

    /* State 4: decrypt fourth byte */
    switch (HIDWORD(state_combined))
    {
    case 3:  /* dead */
        break;

    case 4:  /* HIDWORD is always 4 here */
        byte_val = g_enc_str[3] ^ 0x37;  /* 0x64 ^ 0x37 = 0x53 = 'S' */
        plaintext |= ((uint32_t)byte_val << 24);
        break;

    default:
        break;
    }

    g_combined_sink = (int)plaintext;
    return plaintext;  /* Should be 0x53534150 = "PASS" (little-endian) */
}


/* ============================================================================
 * Function 2: State machine + indirect call dispatch
 *
 * A Hikari-style function that:
 *   1. Uses HIDWORD to select which operation to perform
 *   2. Dispatches via an offset-obfuscated function pointer table
 *   3. Decrypts the operand via XOR before passing to the function
 *
 * Combines: HIDWORD folding + indirect call resolution + const XOR fold
 * ============================================================================ */
__attribute__((noinline))
int hikari_dispatch_engine(int input)
{
    uint64_t state;
    int result = input;
    combined_op_fn fn;
    uint32_t operand;

    /* State 0x10: add operation */
    state = ((uint64_t)0x10 << 32) | (uint32_t)result;

    switch (HIDWORD(state))
    {
    case 0x10:
        /* Decrypt operand: g_enc_add_key ^ 0xDEADBEEF -> 42 */
        operand = g_enc_add_key ^ 0xDEADBEEF;

        /* Indirect call via obfuscated table: entry 0 = combined_op_add */
        fn = (combined_op_fn)(unsigned long)(g_combined_dispatch[0] - COMBINED_TABLE_OFFSET);
        result = fn(result, (int)operand);

        /* Transition to state 0x20 */
        state = ((uint64_t)0x20 << 32) | (uint32_t)result;
        break;

    default:
        break;
    }

    /* State 0x20: multiply operation */
    switch (HIDWORD(state))
    {
    case 0x20:
        /* Decrypt operand: g_enc_mul_key ^ 0xDEADBEEF -> 3 */
        operand = g_enc_mul_key ^ 0xDEADBEEF;

        /* Indirect call: entry 1 = combined_op_mul */
        fn = (combined_op_fn)(unsigned long)(g_combined_dispatch[1] - COMBINED_TABLE_OFFSET);
        result = fn(result, (int)operand);

        /* Transition to state 0x30 */
        state = ((uint64_t)0x30 << 32) | (uint32_t)result;
        break;

    default:
        break;
    }

    /* State 0x30: XOR operation */
    switch (HIDWORD(state))
    {
    case 0x30:
        /* Decrypt operand: g_enc_xor_mask ^ 0xDEADBEEF -> 0xFF00 */
        operand = g_enc_xor_mask ^ 0xDEADBEEF;

        /* Indirect call: entry 2 = combined_op_xor */
        fn = (combined_op_fn)(unsigned long)(g_combined_dispatch[2] - COMBINED_TABLE_OFFSET);
        result = fn(result, (int)operand);
        break;

    default:
        break;
    }

    g_combined_sink = result;
    return result;
    /* Expected: ((input + 42) * 3) ^ 0xFF00 */
}


/* ============================================================================
 * Function 3: Full pipeline with opaque predicates
 *
 * The most realistic simulation. Combines:
 *   - HIDWORD state machine (4 states)
 *   - XOR-encrypted constants for each operation
 *   - Indirect calls through obfuscated dispatch table
 *   - Opaque predicates that are always true/false at ctree level
 *
 * After full ctree optimization, this should reduce to:
 *   result = combined_op_sub(
 *              combined_op_xor(
 *                combined_op_mul(
 *                  combined_op_add(input, 42),
 *                  3),
 *                0xFF00),
 *              sentinel)
 * ============================================================================ */
__attribute__((noinline))
int hikari_full_pipeline(int input)
{
    uint64_t state;
    int result = input;
    combined_op_fn fn;
    uint32_t operand;

    /* Opaque predicate: (x * (x - 1)) is always even -> & 1 == 0 -> always true.
     * This survives to ctree level in OLLVM-obfuscated binaries. */
    volatile int opaque_x = 42;
    int opaque_pred = ((opaque_x * (opaque_x - 1)) & 1) == 0;  /* always 1 */

    /* === State 0xAA: Add === */
    state = ((uint64_t)0xAA << 32) | (uint32_t)result;

    if (opaque_pred)  /* always true */
    {
        switch (HIDWORD(state))
        {
        case 0xAA:
            operand = g_enc_add_key ^ 0xDEADBEEF;  /* -> 42 */
            fn = (combined_op_fn)(unsigned long)(g_combined_dispatch[0] - COMBINED_TABLE_OFFSET);
            result = fn(result, (int)operand);
            state = ((uint64_t)0xBB << 32) | (uint32_t)result;
            break;
        default:
            result = -1;  /* dead */
            break;
        }
    }
    else  /* dead branch -- opaque predicate is always true */
    {
        result = 0;
    }

    /* === State 0xBB: Multiply === */
    switch (HIDWORD(state))
    {
    case 0xBB:
        operand = g_enc_mul_key ^ 0xDEADBEEF;  /* -> 3 */
        fn = (combined_op_fn)(unsigned long)(g_combined_dispatch[1] - COMBINED_TABLE_OFFSET);
        result = fn(result, (int)operand);
        state = ((uint64_t)0xCC << 32) | (uint32_t)result;
        break;
    default:
        break;
    }

    /* === State 0xCC: XOR === */
    switch (HIDWORD(state))
    {
    case 0xCC:
        operand = g_enc_xor_mask ^ 0xDEADBEEF;  /* -> 0xFF00 */
        fn = (combined_op_fn)(unsigned long)(g_combined_dispatch[2] - COMBINED_TABLE_OFFSET);
        result = fn(result, (int)operand);
        state = ((uint64_t)0xDD << 32) | (uint32_t)result;
        break;
    default:
        break;
    }

    /* === State 0xDD: Subtract sentinel === */
    switch (HIDWORD(state))
    {
    case 0xDD:
        operand = g_enc_sentinel ^ 0xDEADBEEF;  /* -> 0xCAFEBABE */
        fn = (combined_op_fn)(unsigned long)(g_combined_dispatch[3] - COMBINED_TABLE_OFFSET);
        result = fn(result, (int)operand);
        break;
    default:
        break;
    }

    g_combined_sink = result;
    return result;
}


/* ============================================================================
 * Function 4: VM-like nested dispatch with encrypted operands
 *
 * Simulates a simple virtual machine interpreter that appears in heavily
 * obfuscated code. The VM:
 *   - Has a bytecode array (encrypted with XOR)
 *   - Uses HIDWORD for the "opcode fetch" state machine
 *   - Dispatches each opcode via an indirect call through the table
 *   - Operands are fetched from encrypted globals
 *
 * This is the most complex combined pattern, exercising all three
 * optimization passes simultaneously across multiple loop iterations.
 * ============================================================================ */

/* Encrypted "bytecode": opcode indices into the dispatch table.
 * XOR key: 0xAA
 * Plaintext: { 0, 1, 2, 0 } -> { add, mul, xor, add } */
uint8_t g_enc_bytecode[4] = {
    0 ^ 0xAA,   /* 0xAA */
    1 ^ 0xAA,   /* 0xAB */
    2 ^ 0xAA,   /* 0xA8 */
    0 ^ 0xAA    /* 0xAA */
};

/* Encrypted operand values for each bytecode.
 * XOR key: 0xDEADBEEF
 * Plaintext: { 10, 2, 0x00FF, 5 } */
uint32_t g_enc_operands[4] = {
    10     ^ 0xDEADBEEF,
    2      ^ 0xDEADBEEF,
    0x00FF ^ 0xDEADBEEF,
    5      ^ 0xDEADBEEF
};

__attribute__((noinline))
int hikari_nested_vm(int input)
{
    uint64_t vm_state;
    int accumulator = input;
    int pc;
    uint8_t opcode;
    uint32_t operand;
    combined_op_fn fn;

    for (pc = 0; pc < 4; pc++)
    {
        /* === Fetch phase: decrypt opcode === */
        /* Pack state: HIDWORD = 0xF0 (fetch state), LODWORD = pc */
        vm_state = ((uint64_t)0xF0 << 32) | (uint32_t)pc;

        switch (HIDWORD(vm_state))
        {
        case 0xF0:
            /* Decrypt opcode: g_enc_bytecode[pc] ^ 0xAA */
            opcode = g_enc_bytecode[pc] ^ 0xAA;

            /* Transition to execute state */
            vm_state = ((uint64_t)0xF1 << 32) | (uint32_t)opcode;
            break;

        default:
            opcode = 0; /* dead */
            break;
        }

        /* === Execute phase: dispatch via table === */
        switch (HIDWORD(vm_state))
        {
        case 0xF1:
            /* Decrypt operand for this instruction */
            operand = g_enc_operands[pc] ^ 0xDEADBEEF;

            /* Clamp opcode to table size */
            opcode = LODWORD(vm_state) & 0x3;

            /* Indirect call: deobfuscate function pointer from table */
            fn = (combined_op_fn)(unsigned long)(g_combined_dispatch[opcode] - COMBINED_TABLE_OFFSET);
            accumulator = fn(accumulator, (int)operand);
            break;

        default:
            break;
        }
    }

    g_combined_sink = accumulator;
    return accumulator;
    /* Expected: xor(mul(add(input, 10), 2), 0xFF) + 5
     *         = combined_op_add(combined_op_xor(combined_op_mul(
     *               combined_op_add(input, 10), 2), 0xFF), 5) */
}

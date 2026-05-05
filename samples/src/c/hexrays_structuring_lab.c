/**
 * Hex-Rays structuring lab fixtures.
 *
 * These functions are intentionally small and shape-focused. The lab does not
 * trust C source shape directly; every fixture must pass compiled-CFG validation
 * before its decompiler output is treated as evidence.
 */

#include "platform.h"
#include <stdint.h>

volatile int g_hexrays_lab_sink = 0;

#if defined(_MSC_VER)
#define HEXRAYS_LAB_NOINLINE __declspec(noinline)
#elif defined(__clang__) || defined(__GNUC__)
#define HEXRAYS_LAB_NOINLINE __attribute__((noinline))
#else
#define HEXRAYS_LAB_NOINLINE
#endif

/*
 * Intended CFG:
 *   entry -> step1 -> step2 -> step3 -> done
 *
 * The labels are deliberately laid out out of execution order so at least one
 * edge requires an explicit jump even at -O0. Validation must prove the final
 * compiled microcode still contains the single-pred/single-succ chain.
 */
EXPORT HEXRAYS_LAB_NOINLINE
int hexrays_lab_single_pred_chain_merge(int x)
{
    int result = x + 1;

    goto step1;

done:
    g_hexrays_lab_sink = result;
    return result;

step3:
    result = result - 7;
    g_hexrays_lab_sink = result;
    goto done;

step1:
    result = result * 3;
    g_hexrays_lab_sink = result;
    goto step2;

step2:
    result = result ^ 0x55AA;
    g_hexrays_lab_sink = result;
    goto step3;
}

/*
 * Restructuring-lab L6: a flattened dispatcher with DENSE state keys (0..4) that
 * clang lowers to an `m_jtbl` JUMP TABLE rather than a `jz` if-chain.
 *
 * Hypothesis: >=4 dense small keys compile to a jump table even at -O0; the
 * jtbl-reading routing extractor reads the `mcases_t` case/target pairs directly,
 * and redirecting each state-writer to its routed handler DRAINS the switch ->
 * a clean linear render with no jtbl / switch / state var.
 *
 * True CFG: entry -> H0 -> H1 -> H2 -> H3 -> H4 -> return (a linear chain the
 * flattener hid behind a jump-table dispatcher).
 *
 * NOTE: unlike the other lab fixtures this uses SMALL dense keys (0..5) on
 * purpose -- large sparse 32-bit states stay a `jz` chain (no table). The L6
 * extractor keys on the jtbl's own case values, not the MIN_STATE_CONSTANT floor.
 */
#include "platform.h"
#include <stdint.h>

extern volatile int g_hexrays_lab_sink;   /* defined in badwhile_triangles_asm.c */

EXPORT D810_NOINLINE int lab_flat_jtbl(int token)
{
    int state = 0;          /* dense keys force m_jtbl */
    int r = token;
    for (;;) {
        switch (state) {
        case 0: r += 0x11; g_hexrays_lab_sink = r; state = 1; break;  /* H0 */
        case 1: r ^= 0x22; g_hexrays_lab_sink = r; state = 2; break;  /* H1 */
        case 2: r -= 0x33; g_hexrays_lab_sink = r; state = 3; break;  /* H2 */
        case 3: r += 0x44; g_hexrays_lab_sink = r; state = 4; break;  /* H3 */
        case 4: r ^= 0x55; g_hexrays_lab_sink = r; state = 5; break;  /* H4 -> terminal */
        default: return r;   /* state == 5 (out of table range) -> return */
        }
    }
}

/*
 * Restructuring-lab: minimal flattened host for insert-based unflattening (Phase 1).
 *
 * 3 linear handlers behind a large-const state dispatcher. True CFG is
 * entry -> H0 -> H1 -> H2 -> return; compiled CFG funnels every handler through
 * the dispatcher. Large 32-bit states avoid the MIN_STATE_CONSTANT floor.
 * See specs/2026-06-06-insert-unflatten-phase1.md.
 */
#include "platform.h"
#include <stdint.h>

extern volatile int g_hexrays_lab_sink;   /* defined in badwhile_triangles_asm.c */

EXPORT D810_NOINLINE int lab_flat_mini(int token)
{
    unsigned int state = 0xC6685257u;            /* K0 */
    int r = token;
    for (;;) {
        switch (state) {
        case 0xC6685257u: r += 0x11; g_hexrays_lab_sink = r; state = 0xB92456DEu; break; /* H0 */
        case 0xB92456DEu: r ^= 0x22; g_hexrays_lab_sink = r; state = 0x3C8960A9u; break; /* H1 */
        case 0x3C8960A9u: r -= 0x33; g_hexrays_lab_sink = r; state = 0x1A2B3C4Du; break; /* H2 */
        default:          return r;                                                       /* terminal */
        }
    }
}

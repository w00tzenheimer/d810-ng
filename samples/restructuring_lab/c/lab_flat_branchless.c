/*
 * Restructuring-lab L8: a flattened CONDITIONAL transition encoded BRANCHLESSLY
 * (no `jcc` to preserve). H0 selects the next state via mask arithmetic:
 *     mask  = -(token & 1);                  // 0xFFFFFFFF if odd, else 0
 *     state = (K1 & mask) | (K2 & ~mask);    // K1 if token odd, K2 if even
 *
 * Hypothesis: there is no compiler branch at the transition (cf. lab_flat_cond's
 * P2a, where the handler keeps a real jcc). Reconstruction must RECOVER the
 * predicate (token & 1) from the branchless select and SYNTHESIZE the if/else via
 * BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT / LowerConditionalStateTransition.
 *
 * True CFG: entry -> H0 -> (token&1 ? H1 : H2) -> return.
 * Large 32-bit states clear the MIN_STATE_CONSTANT floor.
 */
#include "platform.h"
#include <stdint.h>

extern volatile int g_hexrays_lab_sink;   /* defined in badwhile_triangles_asm.c */

EXPORT D810_NOINLINE int lab_flat_branchless(int token)
{
    unsigned int state = 0xC6685257u;            /* K0 */
    int r = token;
    for (;;) {
        switch (state) {
        case 0xC6685257u: {                       /* H0: BRANCHLESS next-state */
            r += 0x11;
            g_hexrays_lab_sink = r;
            unsigned int mask = -(unsigned int)(token & 1);
            state = (0xB92456DEu & mask) | (0x3C8960A9u & ~mask);
            break;
        }
        case 0xB92456DEu:                         /* H1 (token odd) */
            r ^= 0x22; g_hexrays_lab_sink = r; state = 0x1A2B3C4Du; break;
        case 0x3C8960A9u:                         /* H2 (token even) */
            r -= 0x33; g_hexrays_lab_sink = r; state = 0x1A2B3C4Du; break;
        default:                                  /* KT terminal */
            return r;
        }
    }
}

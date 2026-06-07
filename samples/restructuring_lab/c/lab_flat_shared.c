/*
 * Restructuring-lab Phase 3: a flattened host with a SHARED block reached by
 * two predecessors (the de-share / capture-then-insert case).
 *
 * Entry picks path A or B; both run their own work, set state=KS, and converge
 * on the SHARED handler (case KS), which does shared work and terminates.
 * True CFG:  entry -> (token&1 ? A : B) -> SHARED -> return.
 * Compiled (flattened): A and B both write KS and loop to the dispatcher, which
 * routes KS to the single SHARED block (2 logical preds).
 *
 * Phase 3 de-shares SHARED into two private copies (one per path) emitted
 * STATE-FREE (the captured payload excludes the state-transition write), proving
 * the copies carry no state var by construction rather than relying on DCE.
 * Large 32-bit states clear the MIN_STATE_CONSTANT floor.
 */
#include "platform.h"
#include <stdint.h>

extern volatile int g_hexrays_lab_sink;   /* defined in badwhile_triangles_asm.c */

EXPORT D810_NOINLINE int lab_flat_shared(int token)
{
    unsigned int state = (token & 1) ? 0xC6685257u : 0xB92456DEu;  /* A : B */
    int r = token;
    for (;;) {
        switch (state) {
        case 0xC6685257u:                         /* path A */
            r += 0x11; g_hexrays_lab_sink = r; state = 0x3C8960A9u; break;  /* -> SHARED */
        case 0xB92456DEu:                         /* path B */
            r ^= 0x22; g_hexrays_lab_sink = r; state = 0x3C8960A9u; break;  /* -> SHARED */
        case 0x3C8960A9u:                         /* SHARED (preds: A and B) */
            r -= 0x33; g_hexrays_lab_sink = r; state = 0x1A2B3C4Du; break;  /* -> terminal */
        default:                                  /* KT terminal */
            return r;
        }
    }
}

/*
 * Restructuring-lab Phase 2: minimal flattened host with a CONDITIONAL
 * state transition (the "new branch" case).
 *
 * H0 conditionally transitions to H1 (taken) or H2 (fallthrough) based on a
 * runtime predicate, both of which terminate. True CFG:
 *     entry -> H0 -> (token&1 ? H1 : H2) -> return
 * Compiled (flattened): H0 evaluates the predicate, writes the next state in
 * each arm, and loops to the dispatcher, which routes by state. Phase 2
 * reconstructs the if/else branch by inserting a (cloned) conditional block via
 * queue_create_conditional_redirect, plus the two terminal inserts.
 * Large 32-bit states clear the MIN_STATE_CONSTANT floor.
 */
#include "platform.h"
#include <stdint.h>

extern volatile int g_hexrays_lab_sink;   /* defined in badwhile_triangles_asm.c */

EXPORT D810_NOINLINE int lab_flat_cond(int token)
{
    unsigned int state = 0xC6685257u;            /* K0 */
    int r = token;
    for (;;) {
        switch (state) {
        case 0xC6685257u:                         /* H0: conditional transition */
            r += 0x11;
            g_hexrays_lab_sink = r;
            if (token & 1)
                state = 0xB92456DEu;              /* -> H1 (taken) */
            else
                state = 0x3C8960A9u;              /* -> H2 (fallthrough) */
            break;
        case 0xB92456DEu:                         /* H1 */
            r ^= 0x22; g_hexrays_lab_sink = r; state = 0x1A2B3C4Du; break;
        case 0x3C8960A9u:                         /* H2 */
            r -= 0x33; g_hexrays_lab_sink = r; state = 0x1A2B3C4Du; break;
        default:                                  /* KT terminal */
            return r;
        }
    }
}

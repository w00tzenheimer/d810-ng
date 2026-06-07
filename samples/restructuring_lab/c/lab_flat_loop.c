/*
 * Restructuring-lab L1: a flattened host whose TRUE CFG contains a LOOP.
 *
 * The body handler conditionally transitions back to ITSELF (a back-edge) until
 * a counter hits zero, then to the exit handler. True CFG:
 *     entry -> init -> body (loop on counter) -> exit -> return
 * Compiled (flattened): init/body/exit write the next state and loop to the
 * dispatcher; the body's back-transition (state = KBODY) is a self-edge.
 *
 * L1 reconstructs it with the GENERAL rule -- redirect every state-writer to its
 * routed handler -- so the body's back-write becomes a real back-edge and the
 * render is a do/while on the counter (not the dispatcher loop, not the state).
 * Large 32-bit states clear the MIN_STATE_CONSTANT floor.
 */
#include "platform.h"
#include <stdint.h>

extern volatile int g_hexrays_lab_sink;   /* defined in badwhile_triangles_asm.c */

EXPORT D810_NOINLINE int lab_flat_loop(int token)
{
    unsigned int state = 0xC6685257u;            /* K0 = init */
    int r = token;
    int counter = 3;
    for (;;) {
        switch (state) {
        case 0xC6685257u:                         /* init */
            r += 0x11; state = 0xB92456DEu; break;            /* -> body */
        case 0xB92456DEu:                         /* body */
            r ^= 0x22; g_hexrays_lab_sink = r; counter -= 1;
            if (counter != 0) state = 0xB92456DEu;            /* back-edge -> body */
            else              state = 0x3C8960A9u;            /* -> exit */
            break;
        case 0x3C8960A9u:                         /* exit */
            r -= 0x33; g_hexrays_lab_sink = r; state = 0x1A2B3C4Du; break;  /* -> terminal */
        default:                                  /* KT terminal */
            return r;
        }
    }
}

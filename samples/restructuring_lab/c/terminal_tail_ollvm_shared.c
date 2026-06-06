/*
 * Restructuring-lab: OLLVM-realistic terminal-tail shared convergence.
 *
 * Ported from samples/src/c/hexrays_structuring_lab.c (was unregistered, lived
 * only in the retired hexrays_structuring_lab.dll). Same "D810-like bad shape"
 * as terminal_tail_shared_convergence (N terminals route through one shared
 * dispatcher -> one shared `return result`), but tuned so d810's OLLVM-aware
 * detection actually engages -- the two gaps the tiny-state fixtures exposed:
 *   - large 32-bit state constants (>= MIN_STATE_CONSTANT 0x01000000) so
 *     recover_dispatcher does not reject them on the `value > min_const` floor;
 *   - plain `state == K` (mop_S) compares so _detect_stkoff finds the state var
 *     (no MBA mop_d at the dispatcher -- the cursor return-check lives inside
 *     each handler instead).
 *
 * Hypothesis: d810 detects + recovers + de-converges this into a per-terminal
 * return cascade (returns=7, whiles=0) rather than collapsing it (returns~=2).
 */
#include "platform.h"
#include <stdint.h>

EXPORT D810_NOINLINE
int hexrays_lab_terminal_tail_ollvm_shared(volatile uint8_t *base, int token)
{
    unsigned int state = 0xC6685257u;   /* OLLVM-style large initial state */
    int cursor = token;
    int result = 7;

dispatcher:
    if (state == 0xC6685257u) goto byte0;
    if (state == 0xB92456DEu) goto byte1;
    if (state == 0x3C8960A9u) goto byte2;
    if (state == 0xEC031199u) goto byte3;
    if (state == 0x87A0CA6Eu) goto byte4;
    if (state == 0x5D1F4A2Bu) goto byte5;
    if (state == 0x2E7B9C30u) goto byte6;
    return result;                       /* state == 0x1A2B3C4D terminal -> shared return */

byte0:
    base[0] = (uint8_t)(cursor + 0x10); cursor += 1;
    if (cursor == 0x7010) { result = 0; state = 0x1A2B3C4Du; goto dispatcher; }
    state = 0xB92456DEu; goto dispatcher;
byte1:
    base[1] = (uint8_t)(cursor + 0x21); cursor += 3;
    if (cursor == 0x7021) { result = 1; state = 0x1A2B3C4Du; goto dispatcher; }
    state = 0x3C8960A9u; goto dispatcher;
byte2:
    base[2] = (uint8_t)(cursor + 0x32); cursor += 5;
    if (cursor == 0x7032) { result = 2; state = 0x1A2B3C4Du; goto dispatcher; }
    state = 0xEC031199u; goto dispatcher;
byte3:
    base[3] = (uint8_t)(cursor + 0x43); cursor += 7;
    if (cursor == 0x7043) { result = 3; state = 0x1A2B3C4Du; goto dispatcher; }
    state = 0x87A0CA6Eu; goto dispatcher;
byte4:
    base[4] = (uint8_t)(cursor + 0x54); cursor += 11;
    if (cursor == 0x7054) { result = 4; state = 0x1A2B3C4Du; goto dispatcher; }
    state = 0x5D1F4A2Bu; goto dispatcher;
byte5:
    base[5] = (uint8_t)(cursor + 0x65); cursor += 13;
    if (cursor == 0x7065) { result = 5; state = 0x1A2B3C4Du; goto dispatcher; }
    state = 0x2E7B9C30u; goto dispatcher;
byte6:
    base[6] = (uint8_t)(cursor + 0x76);
    result = 7; state = 0x1A2B3C4Du; goto dispatcher;
}

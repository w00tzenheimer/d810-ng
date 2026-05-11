/* mock.c — trace buffers, callee stubs, and MEM() dispatch shared by both sides. */
#include "mock.h"
#include <signal.h>

CallEvent ref_trace[TRACE_CAP];
int       ref_idx = 0;
CallEvent our_trace[TRACE_CAP];
int       our_idx = 0;
int       g_active_side = 0;

/* Iteration-cap watchdog state (see mock.h:EVENT_CAP_PER_SIDE). */
int g_overrun = 0;
int g_event_count_ref = 0;
int g_event_count_our = 0;

/* When the per-side event cap is exceeded inside record(), raise SIGALRM
 * to drop into the harness's existing siglongjmp-based abort path.  The
 * harness disambiguates overrun vs time-watchdog by inspecting g_overrun
 * after the longjmp returns. */
void _trigger_overrun_abort(void) {
    raise(SIGALRM);
}

const char         D810_ZERO_OWORD[16] = {0};
const unsigned char unk_180018E95[16]  = {0};

__int64 sub_7FFD32FF8F30(_QWORD a, _QWORD b, _QWORD c, _QWORD d) {
    record(KIND_FF8F30, a, b, c, d);
    /* Return value in [2,0x20] in even steps of 2 — keeps `v144 = v57 & 0x3E`
     * non-zero and the do-while terminating; still exercises clamp branch. */
    uint64_t r = det_return(a, b, c, d);
    /* even values 2..0x20 (16 distinct), then occasionally >0x20 for clamp. */
    uint64_t low = ((r & 0xF) + 1) * 2;            /* 2..32 even */
    if (((r >> 8) & 7) == 0) low = 0x40;           /* 1/8 chance: >0x20 */
    return (__int64)low;
}

__int64 sub_7FFD33050180(_QWORD a, _QWORD b, _QWORD c, _QWORD d) {
    record(KIND_050180, a, b, c, d);
    /* memcpy-like — record only. Return small int (used in `if v60 < v41`). */
    return (__int64)(det_return(a, b, c, d) & 0xFF);
}

__int64 *sub_7FFD333B4500(int a, __int64 b, __int64 c, __int64 *d) {
    record(KIND_3B4500, (uint64_t)(uint32_t)a, (uint64_t)b, (uint64_t)c,
           (uint64_t)(uintptr_t)d);
    return d;
}

__int64 sub_1800164E0(__int64 dst, __int64 src, __int64 n) {
    /* Equivalent to STORE_OWORD_N when src is a known zero-blob and n=16:
     * canonical recording shape is (dst, n, 0, 0). Otherwise records as
     * KIND_MEMCPY with the unnormalized src. */
    uint64_t nsrc = _normalize_zero_src((const void *)(uintptr_t)src);
    int kind = (nsrc == 0 && (uint64_t)n == 16) ? KIND_STORE16 : KIND_MEMCPY;
    record(kind, (uint64_t)dst, (uint64_t)n, nsrc, 0);
    return 0;
}

__int64 sub_180016770(__int64 dst, __int64 src, __int64 n) {
    /* Same canonical recording as sub_1800164E0 / STORE_OWORD_N. */
    uint64_t nsrc = _normalize_zero_src((const void *)(uintptr_t)src);
    int kind = (nsrc == 0 && (uint64_t)n == 16) ? KIND_STORE16 : KIND_MEMCPY;
    record(kind, (uint64_t)dst, (uint64_t)n, nsrc, 0);
    if ((uint64_t)n == 16) memset((void *)(uintptr_t)dst, 0, 16);
    return 0;
}

uint64_t MEM(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    int kind;
    /* Heuristic dispatch keyed on the constants the reference uses for the
     * second argument: 0x4D / 0x5D → FF8F30 (parser-style), 0x55 / 0x62 / 0x44 /
     * 0x2E → 050180 (memcpy-style), 0x11 / 0x2C / 0x27 → 3B4500 (sink). */
    if      (b == 0x4D || b == 0x5D)                              kind = KIND_FF8F30;
    else if (b == 0x55 || b == 0x62 || b == 0x44 || b == 0x2E ||
             a == 0x55 || a == 0x62 || a == 0x44 || a == 0x2E)    kind = KIND_050180;
    else if (b == 0x11 || b == 0x2C || b == 0x27 ||
             a == 0x11 || a == 0x2C || a == 0x27)                 kind = KIND_3B4500;
    else                                                          kind = 0;
    record(kind, a, b, c, d);
    return det_return(a, b, c, d);
}

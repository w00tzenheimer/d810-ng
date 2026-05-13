/* mock.h — shared types and trace recording for ref/ours equivalence harness. */
#ifndef D810_EQ_MOCK_H
#define D810_EQ_MOCK_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* IDA-style typedefs so reference pseudocode compiles unchanged. */
typedef uint64_t            _QWORD;
typedef uint32_t            _DWORD;
typedef uint16_t            _WORD;
typedef unsigned char       _BYTE;
/* IDA's __intN are not typedefs but pseudo-keywords that combine with
 * `unsigned`. Use macros so `unsigned __int8` parses as `unsigned char`. */
#define __int64 long long
#define __int32 int
#define __int16 short
#define __int8  char

/* Strip IDA-only attributes when compiling on host. */
#define __fastcall
#define EXPORT
#define D810_NOINLINE __attribute__((noinline))

/* CallEvent: kind = synthetic callee identity (low bits of callee address)
 * plus a tag for memory-mutating helpers. */
typedef struct {
    int      kind;
    uint64_t a, b, c, d;
} CallEvent;

#define TRACE_CAP 8192

/* Two independent trace buffers — one per side. The harness selects which
 * is active via a function-pointer record() set before each call. */
extern CallEvent ref_trace[TRACE_CAP];
extern int       ref_idx;
extern CallEvent our_trace[TRACE_CAP];
extern int       our_idx;

extern int g_active_side; /* 0 = ref, 1 = ours */

/* Iteration-cap watchdog: when one side records more than EVENT_CAP_PER_SIDE
 * events in a single trial, treat it as a runaway loop and abort cleanly via
 * SIGALRM (the same path the time-based watchdog uses).  This converts
 * non-progressing do-while loops in either ref.c or ours.c into a structured
 * OVERRUN classification with the partial trace intact, instead of a black-box
 * "hang".  The cap is a hard upper bound on call events, deliberately well
 * below TRACE_CAP=8192 so we leave headroom for legitimate long traces. */
#define EVENT_CAP_PER_SIDE 4096
extern int g_overrun;          /* 1 if last trial overran the event cap */
extern int g_event_count_ref;  /* events recorded by REF this trial */
extern int g_event_count_our;  /* events recorded by OUR this trial */

#include <signal.h>
extern void _trigger_overrun_abort(void);

static inline void record(int kind, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    if (g_active_side == 0) {
        if (ref_idx < TRACE_CAP) {
            ref_trace[ref_idx].kind = kind;
            ref_trace[ref_idx].a = a;
            ref_trace[ref_idx].b = b;
            ref_trace[ref_idx].c = c;
            ref_trace[ref_idx].d = d;
            ref_idx++;
        }
        g_event_count_ref++;
        if (g_event_count_ref > EVENT_CAP_PER_SIDE && !g_overrun) {
            g_overrun = 1;
            _trigger_overrun_abort();
        }
    } else {
        if (our_idx < TRACE_CAP) {
            our_trace[our_idx].kind = kind;
            our_trace[our_idx].a = a;
            our_trace[our_idx].b = b;
            our_trace[our_idx].c = c;
            our_trace[our_idx].d = d;
            our_idx++;
        }
        g_event_count_our++;
        if (g_event_count_our > EVENT_CAP_PER_SIDE && !g_overrun) {
            g_overrun = 1;
            _trigger_overrun_abort();
        }
    }
}

/* Deterministic content-derived stub return so both sides observe the
 * same behavior given identical args. */
static inline uint64_t det_return(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return ((a ^ b) * 0x9E3779B97F4A7C15ULL ^ c) ^ (d << 11);
}

/* Synthetic callee kinds (the low bits of the original IDA addresses). */
#define KIND_FF8F30  0x32FF8F30
#define KIND_050180  0x33050180
#define KIND_3B4500  0x333B4500
#define KIND_MEMCPY  0x800164E0
#define KIND_STORE16 0x57108E16  /* tag for STORE_OWORD_N memset side-effect */

/* Real callee stubs (used by reference). */
__int64 sub_7FFD32FF8F30(_QWORD a, _QWORD b, _QWORD c, _QWORD d);
__int64 sub_7FFD33050180(_QWORD a, _QWORD b, _QWORD c, _QWORD d);
__int64 *sub_7FFD333B4500(int a, __int64 b, __int64 c, __int64 *d);
__int64 sub_1800164E0(__int64 dst, __int64 src, __int64 n);

/* Zero/sink helper used by current AFTER. Argument shape matches
 * sub_1800164E0 (dst, src, n). Records KIND_STORE16 with the
 * normalized (dst, n, 0, 0) shape so it canonicalizes to STORE_OWORD_N
 * when src is a 16-byte zero blob. */
__int64 sub_180016770(__int64 dst, __int64 src, __int64 n);

/* Heuristic dispatch wrapper used by ours.c (substitute for
 * MEMORY[0x180000000] indirect calls). */
uint64_t MEM(uint64_t a, uint64_t b, uint64_t c, uint64_t d);

/* STORE_OWORD_N(base, n, src) — write 16 bytes at base + 16*n.
 * In reference D810_ZERO_OWORD is a 16-byte zero blob; we record + memset.
 * Recording shape is (dst_absolute, 16, 0, 0) -- ``src`` is normalized to
 * 0 when it is a known zero-blob (D810_ZERO_OWORD or unk_180018E95) so
 * the reference's STORE_OWORD_N and OUR's sub_180016770(dst, src, 16)
 * compare equal under "zero-blob memcpy vs STORE_OWORD_N". */
extern const char D810_ZERO_OWORD[16];
extern const unsigned char unk_180018E95[16];

static inline uint64_t _normalize_zero_src(const void *src) {
    return (src == (const void *)D810_ZERO_OWORD ||
            src == (const void *)unk_180018E95) ? 0 :
           (uint64_t)(uintptr_t)src;
}

static inline void STORE_OWORD_N(uintptr_t base, int n, const void *src) {
    uintptr_t dst = base + (uintptr_t)16 * (uintptr_t)n;
    record(KIND_STORE16, (uint64_t)dst, 16, _normalize_zero_src(src), 0);
    memset((char *)dst, 0, 16);
}

/* Function-under-test signatures (same shape both sides). */
__int64 sub_7FFD3338C040_REF(_QWORD a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5);
__int64 sub_7FFD3338C040_OUR(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5);

#endif /* D810_EQ_MOCK_H */

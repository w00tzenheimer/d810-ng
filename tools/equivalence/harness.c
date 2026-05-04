/* harness.c — fuzz harness comparing ref vs ours by call trace + memory hash. */
#include "mock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/time.h>

static sigjmp_buf g_jmp;
static volatile int g_last_sig = 0;

static void on_signal(int sig) {
    g_last_sig = sig;
    siglongjmp(g_jmp, 1);
}

static void arm_watchdog_ms(int ms) {
    struct itimerval it = {0};
    it.it_value.tv_sec  = ms / 1000;
    it.it_value.tv_usec = (ms % 1000) * 1000;
    setitimer(ITIMER_REAL, &it, NULL);
}
static void disarm_watchdog(void) {
    struct itimerval it = {0};
    setitimer(ITIMER_REAL, &it, NULL);
}

#define A5_SIZE  0x4000
#define A3_SIZE  0x400

/* xorshift64 — deterministic per-seed. */
static uint64_t xs_state;
static uint64_t xs64(void) {
    uint64_t x = xs_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    xs_state = x;
    return x;
}

static uint64_t hash_buf(const void *p, size_t n) {
    const unsigned char *b = (const unsigned char *)p;
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 0x100000001b3ULL; }
    return h;
}

static int trace_diff(int *first_idx) {
    if (ref_idx != our_idx) {
        *first_idx = (ref_idx < our_idx ? ref_idx : our_idx);
        return 1;
    }
    for (int i = 0; i < ref_idx; i++) {
        if (ref_trace[i].kind != our_trace[i].kind ||
            ref_trace[i].a    != our_trace[i].a    ||
            ref_trace[i].b    != our_trace[i].b    ||
            ref_trace[i].c    != our_trace[i].c    ||
            ref_trace[i].d    != our_trace[i].d) {
            *first_idx = i;
            return 1;
        }
    }
    return 0;
}

static void print_event(const char *side, const CallEvent *e) {
    printf("    %s kind=0x%08x a=0x%016lx b=0x%016lx c=0x%016lx d=0x%016lx\n",
           side, e->kind, (unsigned long)e->a, (unsigned long)e->b,
           (unsigned long)e->c, (unsigned long)e->d);
}

int main(int argc, char **argv) {
    int K = (argc > 1) ? atoi(argv[1]) : 1000;
    uint64_t seed = (argc > 2) ? strtoull(argv[2], NULL, 0) : 42;

    int pass = 0, fail = 0;
    int first_fail_seed = -1;
    int first_fail_idx = -1;
    int rv_diffs = 0, mem_diffs = 0, trace_diffs = 0;
    int ref_hangs = 0, our_hangs = 0;
    int ref_crashes = 0, our_crashes = 0;

    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);

    unsigned char a3_buf[A3_SIZE];
    unsigned char a5_ref[A5_SIZE];
    unsigned char a5_our[A5_SIZE];

    setbuf(stdout, NULL); /* unbuffered, so partial output survives crash */
    int verbose = (getenv("EQ_VERBOSE") != NULL);
    for (int trial = 0; trial < K; trial++) {
        if (verbose) fprintf(stderr, "[trial=%d] ", trial);
        xs_state = seed + (uint64_t)trial * 0x9E3779B97F4A7C15ULL + 1;
        for (int i = 0; i < A3_SIZE; i++) a3_buf[i] = (unsigned char)(xs64() & 0xFF);

        memset(a5_ref, 0, A5_SIZE);
        memset(a5_our, 0, A5_SIZE);
        /* Seed *(a5+0xD0) (== v49) so the function takes varied paths.
         * Use low byte from RNG, mask to keep it interesting. */
        uint64_t init_v49 = xs64() & 0xFF;
        memcpy(a5_ref + 0xD0, &init_v49, 8);
        memcpy(a5_our + 0xD0, &init_v49, 8);

        ref_idx = 0; our_idx = 0;
        long long rv_ref = 0, rv_our = 0;
        int ref_hung = 0, our_hung = 0;
        int ref_crashed = 0, our_crashed = 0;

        g_active_side = 0;
        g_last_sig = 0;
        if (verbose) fprintf(stderr, "REF ");
        if (sigsetjmp(g_jmp, 1) == 0) {
            arm_watchdog_ms(50);
            rv_ref = sub_7FFD3338C040_REF(
                0, 0, (long long)(uintptr_t)a3_buf, 0,
                (long long)(uintptr_t)a5_ref);
            disarm_watchdog();
        } else {
            disarm_watchdog();
            if (g_last_sig == SIGALRM) ref_hung = 1;
            else                       ref_crashed = 1;
        }

        g_active_side = 1;
        g_last_sig = 0;
        if (verbose) fprintf(stderr, "OUR ");
        if (sigsetjmp(g_jmp, 1) == 0) {
            arm_watchdog_ms(50);
            rv_our = sub_7FFD3338C040_OUR(
                0, 0, a3_buf, 0, (long long)(uintptr_t)a5_our);
            disarm_watchdog();
        } else {
            disarm_watchdog();
            if (g_last_sig == SIGALRM) our_hung = 1;
            else                       our_crashed = 1;
        }
        if (verbose) fprintf(stderr, "done\n");
        if (ref_hung)    ref_hangs++;
        if (our_hung)    our_hangs++;
        if (ref_crashed) ref_crashes++;
        if (our_crashed) our_crashes++;
        if (ref_hung || our_hung || ref_crashed || our_crashed) {
            fail++;
            if (first_fail_seed == -1) {
                first_fail_seed = trial;
                printf("ABNORMAL trial=%d ref_hung=%d our_hung=%d "
                       "ref_crash=%d our_crash=%d init_v49=0x%lx\n",
                       trial, ref_hung, our_hung,
                       ref_crashed, our_crashed, (unsigned long)init_v49);
            }
            continue;
        }

        int t_first = -1;
        int t_diff = trace_diff(&t_first);
        int rv_diff = (rv_ref != rv_our);
        int m_diff  = (memcmp(a5_ref, a5_our, A5_SIZE) != 0);
        uint64_t href = hash_buf(a5_ref, A5_SIZE);
        uint64_t hour = hash_buf(a5_our, A5_SIZE);

        if (t_diff || rv_diff || m_diff) {
            fail++;
            if (rv_diff)  rv_diffs++;
            if (m_diff)   mem_diffs++;
            if (t_diff)   trace_diffs++;
            int dump_all = (getenv("EQ_DUMP_ALL") != NULL);
            if (first_fail_seed == -1 || (dump_all && fail <= 8)) {
                if (first_fail_seed == -1) {
                    first_fail_seed = trial;
                    first_fail_idx = t_first;
                }
                printf("FAIL trial=%d (seed=%lu+%d) init_v49=0x%lx\n",
                       trial, (unsigned long)seed, trial, (unsigned long)init_v49);
                printf("  rv_ref=0x%lx rv_our=0x%lx %s\n",
                       (unsigned long)rv_ref, (unsigned long)rv_our,
                       rv_diff ? "(DIFF)" : "");
                printf("  memhash_ref=0x%016lx memhash_our=0x%016lx %s\n",
                       (unsigned long)href, (unsigned long)hour,
                       m_diff ? "(DIFF)" : "");
                printf("  ref_idx=%d our_idx=%d\n", ref_idx, our_idx);
                if (t_diff && t_first >= 0) {
                    printf("  first divergent event index=%d\n", t_first);
                    if (t_first < ref_idx) print_event("REF", &ref_trace[t_first]);
                    if (t_first < our_idx) print_event("OUR", &our_trace[t_first]);
                }
            }
        } else {
            pass++;
        }
    }

    printf("\n=== fuzz summary ===\n");
    printf("trials      : %d\n", K);
    printf("pass        : %d\n", pass);
    printf("fail        : %d\n", fail);
    printf("  rv_diffs    : %d\n", rv_diffs);
    printf("  mem_diffs   : %d\n", mem_diffs);
    printf("  trace_diffs : %d\n", trace_diffs);
    printf("  ref_hangs   : %d\n", ref_hangs);
    printf("  our_hangs   : %d\n", our_hangs);
    printf("  ref_crashes : %d\n", ref_crashes);
    printf("  our_crashes : %d\n", our_crashes);
    if (first_fail_seed >= 0) {
        printf("first_fail  : trial=%d trace_idx=%d\n",
               first_fail_seed, first_fail_idx);
    }
    return (fail == 0) ? 0 : 1;
}

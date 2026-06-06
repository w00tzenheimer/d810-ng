/*
 * Restructuring-lab seed C fixture.
 *
 * Hypothesis: a source-level if/else diamond (two arms joining at a single
 * return) compiles to a clean diamond CFG and decompiles back to if/else --
 * i.e. Hex-Rays preserves the join rather than duplicating the tail.
 *
 * This is intentionally tiny; it exists to prove the C half of the lab build
 * (MinGW clang -> isolated DLL). Real fixtures get one hypothesis each too.
 */
#include "polyfill.h"
#include "platform.h"

EXPORT D810_NOINLINE int lab_if_diamond(int x, int y)
{
    int r;
    if (x > y)
        r = x - y;
    else
        r = y - x;
    return r + x;
}

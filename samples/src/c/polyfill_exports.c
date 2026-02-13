#define NT_CURRENT_TEB_DEFINED
#include "polyfill.h"
#include "platform.h"

/*
 * Export an external NtCurrentTeb symbol for Windows test binaries while
 * keeping the existing header-only inline helper for internal call sites.
 */
EXPORT TEB *NtCurrentTeb(void)
{
    static TEB fake_teb = {0};
    static uint64 fake_fiber_data = 0x123456789ABCDEF0LL;
    fake_teb.NtTib.FiberData = &fake_fiber_data;
    return &fake_teb;
}

#include "polyfill.h"
#include "platform.h"

const uint64 qword_1802D2C33 = 0x736006A871C63D9ALL;

// Does not fold ok
EXPORT uint64 while_switch_flattened(void)
{
    int v2 = 0;
    int rval = 0x272BCB9A;
    int v3 = 0;
    int v4 = 0;
    int v5 = 0;
    uint64 a3 = 0;
    uint64 globalConstant = __ROL8__(
        (__ROL8__(
             __ROL8__(0x736006A871C63D9ALL, 0x28) - 0x43401825757A7203LL,
             0x2B) +
         0x789F447F89C06931LL) ^
            0x43B6AE2CD812A432LL,
        0x2F);
    while (1)
    {
        switch (v2)
        {
        case 0:
            v3 = *(_QWORD *)NtCurrentTeb()->NtTib.FiberData;
            v2 = 1;
            break;

        case 1:
            v4 = __ROL8__(globalConstant, 0x11);
            v2 = 2;
            break;

        case 2:
            a3 = __ROL8__(
                     (*(__int64 *)((char *)&qword_1802D2C33 + 3) ^ v4 ^ 0xCD455C5FB8140C43uLL) - 0x789F447F89C06931LL,
                     0x15) +
                 0x507AF58A6E5A51E3LL;
            v2 = 3;
            break;

        case 3:
            v5 = __ROL8__(a3 - 0xD3ADD64F8DFDFE0LL, 0x18);
            v2 = 4;
            break;

        case 4:
            rval = v3 == v5;
            return rval;

        default:
            continue;
        }
    }
}

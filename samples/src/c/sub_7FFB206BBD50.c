/**
 * Function: sub_7FFB206BBD50
 * Address: 0x7ffb206bbd50
 *
 * User metadata:
 *   herpa
 *
 * Compilation flags (recommended):
 *   -O0 -g -fno-inline -fno-builtin
 */

#include "polyfill.h"
#include "platform.h"

// Referenced globals
volatile unsigned __int8 byte_7FFB208A6E40 = 0x48u;
volatile unsigned __int8 byte_7FFB208A6E41 = 0x92u;
volatile unsigned __int8 byte_7FFB208A6E48 = 0x8Bu;
volatile unsigned __int8 byte_7FFB208A6E49 = 0x2Eu;
volatile unsigned __int8 byte_7FFB208A6E68 = 0x0Fu;
volatile unsigned __int8 byte_7FFB208C0070 = 0x01u;
volatile unsigned __int32 dword_7FFB208A6E30 = 0xDE74B21Eu;
volatile unsigned __int32 dword_7FFB208A6E44 = 0x38683879u;
volatile unsigned __int32 dword_7FFB208A6E58 = 0xC6A09573u;
volatile unsigned __int32 dword_7FFB208A6E5C = 0x59FF23F2u;
volatile unsigned __int32 dword_7FFB208A6E60 = 0x9DF622EFu;
volatile unsigned __int32 dword_7FFB208A6E64 = 0x63552538u;
volatile unsigned __int32 dword_7FFB208A6E6C = 0xC91C1891u;
volatile unsigned __int32 dword_7FFB208A6E78 = 0xC2DC289Fu;
volatile unsigned __int32 dword_7FFB208C0038 = 0x8F913167u;
volatile HANDLE hThread = (HANDLE)0x00000000000002C4uLL;
volatile unsigned __int64 qword_7FFB208A6E38 = 0x6BAD9027C4BC0D2DuLL;
volatile unsigned __int64 qword_7FFB208A6E50 = 0x107ED29DD86DCA8DuLL;
volatile unsigned __int64 qword_7FFB208A6E70 = 0xFC9D15172942BBFFuLL;
volatile unsigned __int64 qword_7FFB208C0040 = 0x364AE8F6459BF55FuLL;
volatile unsigned __int64 qword_7FFB208C0050 = 0x000000C7598AE000uLL;
volatile HANDLE qword_7FFB208C0058 = (HANDLE)(ULONG_PTR)(0x00000000000002C0uLL);
volatile unsigned __int64 qword_7FFB208C0060 = 0x0000000000000000uLL;
volatile unsigned __int64 unk_7FFB208C0068 = 0x0000000000000000uLL;
static volatile const _OWORD xmmword_7FFB2084A716 = D810_XMMWORD("90708D8A9D04E7A19D273081BA1B2423");
static volatile const _OWORD xmmword_7FFB2084A726 = D810_XMMWORD("33E919F4343E7A0985500402EEC8F9F4");
static volatile const _OWORD xmmword_7FFB2084A736 = D810_XMMWORD("9A5BC3C2D1CDC6822CCC81A6D1D635D1");

// Forward declarations
extern __int64 __fastcall sub_7FFB2033FAF0(_QWORD, _QWORD, _QWORD, _QWORD);
extern __int64 __fastcall sub_7FFB2037CA90(_QWORD, _QWORD, _QWORD, _QWORD);
extern __int64 __fastcall sub_7FFB205841B0(_QWORD, _QWORD, _QWORD, _QWORD);
extern __int64 __fastcall sub_7FFB207233E0(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
extern void __stdcall sub_7FFB207ADFE0(LPVOID lpFiberParameter);
extern __int64 __fastcall sub_7FFB208350D0(_QWORD, _QWORD, _QWORD);
extern __int64 __fastcall sub_7FFB20835490(_QWORD, _QWORD, _QWORD);

// Imported / external function pointers
extern LPVOID (__stdcall *ConvertThreadToFiber)(LPVOID lpParameter);
extern LPVOID (__stdcall *CreateFiber)(SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter);
extern BOOL (__stdcall *GetThreadContext)(HANDLE hThread, LPCONTEXT lpContext);
extern BOOL (__stdcall *IsThreadAFiber)(void);
extern void (__stdcall *RtlAcquireSRWLockExclusive)(void *SRWLock);
extern void (__stdcall *RtlReleaseSRWLockExclusive)(void *SRWLock);
extern BOOL (__stdcall *SetThreadContext)(HANDLE hThread, const CONTEXT *lpContext);
extern void (__stdcall *SwitchToFiber)(LPVOID lpFiber);
extern LPVOID (__stdcall *TlsGetValue)(DWORD dwTlsIndex);
extern BOOL (__stdcall *TlsSetValue)(DWORD dwTlsIndex, LPVOID lpTlsValue);

// Sink variable to prevent optimization
volatile int g_sub_7FFB206BBD50_sink = 0;

// Function: sub_7FFB206BBD50 at 0x7ffb206bbd50
EXPORT D810_NOINLINE __int64 __fastcall sub_7FFB206BBD50(unsigned int **a1)
{
    int v2; // eax
    unsigned int v3; // ebx
    char *Value; // rdi
    __int64 v5; // rdx
    unsigned __int64 v6; // r8
    char v7; // r8
    char v8; // dl
    char v9; // r10
    char v10; // r10
    char v11; // r10
    char v12; // r11
    char v13; // bp
    char v14; // r14
    char v15; // bl
    char v16; // r14
    char v17; // r11
    int v18; // eax
    unsigned int v19; // ecx
    char v20; // r9
    char v21; // r8
    char v22; // bl
    unsigned int v23; // ecx
    struct _TEB *v24; // rax
    __int64 v25; // rcx
    int v26; // edx
    unsigned int v27; // ecx
    int *v28; // rax
    __int64 v30; // [rsp+0h] [rbp-A18h] BYREF
    CONTEXT v31; // [rsp+30h] [rbp-9E8h] BYREF
    CONTEXT Context; // [rsp+500h] [rbp-518h] BYREF
    __int64 v33; // [rsp+9D0h] [rbp-48h]

    v2 = **a1;
    v3 = 0;
    if ( v2 > 0x40010005 )
    {
        if ( v2 == 0x40010006 || v2 == 0x4001000A )
            goto LABEL_xE627;
    }

    else if ( v2 == 0xC00000E5 || v2 == 0xC00000FD )
    {
        goto LABEL_xE627;
    }

    if ( IsThreadAFiber() == (((~(dword_7FFB208A6E30 + 0x36A0C2DA) & 0x67B7E766)
                             + ((dword_7FFB208A6E30 + 0x36A0C2DA) & 0x98481899)
                             + 2 * (~(dword_7FFB208A6E30 + 0x36A0C2DA) & 0x18481899)
                             - 2 * ~(dword_7FFB208A6E30 + 0x36A0C2DA)
                             - 0x3C4120B8)
                            ^ 0x4781C92C)
                           - dword_7FFB208A6E30
                           - 0x5828F3D8 )
        ConvertThreadToFiber((LPVOID)(qword_7FFB208C0040 ^ 0x364AEAB0583CE76FLL));

    Value = (char *)TlsGetValue(dword_7FFB208C0038 ^ 0x8F91316A);
    if ( !Value )
    {
        v5 = (qword_7FFB208A6E38 - 0x54CE28FB019E5516LL) ^ 0x436CC0358FBDA6D6LL;
        v6 = 0xFFFFFFFFFFFFFFF5uLL * ((v5 - 0x5CF7144FBE477511LL) & 0xD25917447C57B156uLL)
           + ((v5 - 0x5CF7144FBE477511LL) & 0x2DA6E8BB83A84EA9LL)
           + ((v5 - 0x5CF7144FBE477511LL) | 0xD25917447C57B156uLL)
           - 0xB * (~(v5 - 0x5CF7144FBE477511LL) & 0xD25917447C57B156uLL)
           + qword_7FFB208A6E38
           + ~(v5 - 0x5CF7144FBE477511LL)
           + v5
           - (qword_7FFB208A6E38
            - 0x54CE28FB019E5516LL)
           + 0x176E1336740F662LL;
        Value = (char *)sub_7FFB2033FAF0(
                            0x52,
                            0x3E,
                            8 * (v6 & ~(qword_7FFB208A6E38 - 0x38B7C70C1485F119LL))
                          - 2 * ((qword_7FFB208A6E38 - 0x38B7C70C1485F119LL) & v6)
                          - 7 * ((qword_7FFB208A6E38 - 0x38B7C70C1485F119LL) ^ v6)
                          + 4 * ~((qword_7FFB208A6E38 - 0x38B7C70C1485F119LL) ^ v6)
                          - 4 * ~((qword_7FFB208A6E38 - 0x38B7C70C1485F119LL) | v6)
                          + 8 * ~(~(qword_7FFB208A6E38 - 0x38B7C70C1485F119LL) | v6),
                            7);
        STORE_OWORD_N(Value, 0, &xmmword_7FFB2084A716);
        STORE_OWORD_N(Value, 1, &xmmword_7FFB2084A726);
        STORE_OWORD_N(Value, 2, &D810_ZERO_OWORD);
        Value[0x30] = 0;
        *(_QWORD *)(Value + 0x31) = (_QWORD)(0xC69686BF50840F8DuLL);
        Value[0x39] = 0xCE;
        v7 = ((byte_7FFB208A6E40 - 0x70) | 0xB5)
           + 6 * (~(byte_7FFB208A6E40 - 0x70) & 0x35)
           + 0xFD * ((byte_7FFB208A6E40 - 0x70) & 0x4A)
           + 3 * (byte_7FFB208A6E40 - 0x70)
           + 4 * ((byte_7FFB208A6E40 - 0x70) & 0x35);
        v8 = v7 - 0x3D;
        v7 -= 0x22;
        v9 = 3 * (~(byte_7FFB208A6E40 + 0x20) & 0x41)
           - ((byte_7FFB208A6E40 + 0x20) & 0x41)
           + (~(byte_7FFB208A6E40 + 0x20) | 0x41)
           + 3 * (~(byte_7FFB208A6E40 + 0x20) & 0xBE)
           - 3 * ~(byte_7FFB208A6E40 + 0x20)
           + 0x42;
        v10 = 6 * (v7 & 5)
            + 8 * (v7 & 0x1A)
            - 5 * (v7 | 5)
            - 3 * (v7 ^ 5)
            + ~(v7 | 5)
            + 8 * (~v7 & 5)
            + 3 * ~(~v7 | v9)
            + 5 * ~(v7 | v9)
            + 8 * (~v7 & v9)
            - 2 * (v9 ^ v7)
            - 5 * ~v7
            - (byte_7FFB208A6E40
             - 0x70);
        Value[0x3A] = byte_7FFB208A6E40
                    + 0xB * (v8 | v10)
                    + 0xF5 * (v8 & v10)
                    - 9 * (v10 & ~v8)
                    - (v8 ^ v10)
                    - 0xB * ~(~v8 | v10);
        v11 = 8
            * (~(0xF9
               - (7
                * ~((2 * (byte_7FFB208A6E41 + 0x5A)
                   - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                   + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                   + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                   + 0x48)
                  ^ 0x4C
                  | 0xB2)
                + 6
                * ((2 * (byte_7FFB208A6E41 + 0x5A)
                  - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                  + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                  + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                  + 0x48)
                 ^ 0x4C
                 | 0xB2)
                + (((2 * (byte_7FFB208A6E41 + 0x5A)
                   - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                   + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                   + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                   + 0x48)
                  ^ 0x4C)
                 & 0xB2)))
             & 0x19);
        v12 = 4
            * (~(0xF9
               - (7
                * ~((2 * (byte_7FFB208A6E41 + 0x5A)
                   - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                   + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                   + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                   + 0x48)
                  ^ 0x4C
                  | 0xB2)
                + 6
                * ((2 * (byte_7FFB208A6E41 + 0x5A)
                  - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                  + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                  + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                  + 0x48)
                 ^ 0x4C
                 | 0xB2)
                + (((2 * (byte_7FFB208A6E41 + 0x5A)
                   - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                   + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                   + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                   + 0x48)
                  ^ 0x4C)
                 & 0xB2)))
             & 0x26);
        v13 = 4
            * ((0xF9
              - (7
               * ~((2 * (byte_7FFB208A6E41 + 0x5A)
                  - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                  + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                  + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                  + 0x48)
                 ^ 0x4C
                 | 0xB2)
               + 6
               * ((2 * (byte_7FFB208A6E41 + 0x5A)
                 - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                 + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                 + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                 + 0x48)
                ^ 0x4C
                | 0xB2)
               + (((2 * (byte_7FFB208A6E41 + 0x5A)
                  - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                  + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                  + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                  + 0x48)
                 ^ 0x4C)
                & 0xB2)))
             ^ 0x26);
        v14 = 7
            * ((0xF9
              - (7
               * ~((2 * (byte_7FFB208A6E41 + 0x5A)
                  - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                  + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                  + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                  + 0x48)
                 ^ 0x4C
                 | 0xB2)
               + 6
               * ((2 * (byte_7FFB208A6E41 + 0x5A)
                 - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                 + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                 + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                 + 0x48)
                ^ 0x4C
                | 0xB2)
               + (((2 * (byte_7FFB208A6E41 + 0x5A)
                  - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                  + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                  + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                  + 0x48)
                 ^ 0x4C)
                & 0xB2)))
             ^ 0xD9);
        v15 = v11
            + v13
            + 8
            * ((0xF9
              - (7
               * ~((2 * (byte_7FFB208A6E41 + 0x5A)
                  - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                  + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                  + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                  + 0x48)
                 ^ 0x4C
                 | 0xB2)
               + 6
               * ((2 * (byte_7FFB208A6E41 + 0x5A)
                 - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                 + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                 + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                 + 0x48)
                ^ 0x4C
                | 0xB2)
               + (((2 * (byte_7FFB208A6E41 + 0x5A)
                  - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                  + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                  + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                  + 0x48)
                 ^ 0x4C)
                & 0xB2)))
             & 6)
            - 2
            * ((0xF9
              - (7
               * ~((2 * (byte_7FFB208A6E41 + 0x5A)
                  - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                  + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                  + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                  + 0x48)
                 ^ 0x4C
                 | 0xB2)
               + 6
               * ((2 * (byte_7FFB208A6E41 + 0x5A)
                 - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                 + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                 + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                 + 0x48)
                ^ 0x4C
                | 0xB2)
               + (((2 * (byte_7FFB208A6E41 + 0x5A)
                  - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                  + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                  + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                  + 0x48)
                 ^ 0x4C)
                & 0xB2)))
             & 0x59)
            - v14
            - v12;
        v16 = 0xB * ~((v15 ^ 0x24) & 0x36)
            + 0xB * (v15 ^ 0x24 | 0x36)
            + 0xF7 * ((v15 ^ 0x24) & 0x36)
            - 0x15 * ((v15 ^ 0x24) & 0xC9)
            - 0xB * ~(v15 ^ 0x24 | 0x36)
            - 0x15 * ((v15 ^ 0x12) & 0x36);
        v17 = (v15 ^ 0x24)
            + (v16 | 0xE4)
            + 2 * (~v16 & 0x64)
            + 3 * (v16 & 0xE4)
            - (0xF9
             - (7
              * ~((2 * (byte_7FFB208A6E41 + 0x5A)
                 - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                 + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                 + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                 + 0x48)
                ^ 0x4C
                | 0xB2)
              + 6
              * ((2 * (byte_7FFB208A6E41 + 0x5A)
                - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                + 0x48)
               ^ 0x4C
               | 0xB2)
              + (((2 * (byte_7FFB208A6E41 + 0x5A)
                 - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                 + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                 + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                 + 0x48)
                ^ 0x4C)
               & 0xB2)))
            - ((2 * (byte_7FFB208A6E41 + 0x5A)
              - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
              + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
              + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
              + 0x48)
             ^ 0x4C)
            - (byte_7FFB208A6E41
             + 0x5A)
            + 0x38;
        Value[0x3B] = 3 * (v17 & ~byte_7FFB208A6E41)
                    + 3 * (byte_7FFB208A6E41 & v17)
                    - 2 * v17
                    + 2 * (byte_7FFB208A6E41 + 0x5A)
                    - 2 * ((byte_7FFB208A6E41 + 0x5A) & 0x46)
                    + ((byte_7FFB208A6E41 + 0x5A) | 0xB9)
                    + (~(byte_7FFB208A6E41 + 0x5A) & 0xB9)
                    + 0x48
                    + ~(~byte_7FFB208A6E41 | v17)
                    + (byte_7FFB208A6E41 | v17)
                    + (v17 ^ ~byte_7FFB208A6E41)
                    + 1;
        STORE_OWORD_N(Value, 3, &xmmword_7FFB2084A736);
        *(_DWORD *)(Value + 0x4B) = 0x66A46E9A;
        *((_QWORD *)Value + 0xA) = (_QWORD)(0);
        *((_QWORD *)Value + 0xB) = (_QWORD)(0x28D7E786C7B33EEALL);
        *((_DWORD *)Value + 0x18) = 0x6E20978E;
        Value[0x64] = 0x1A;
        Value[0x65] = 0x7D;
        v18 = ((2 * (dword_7FFB208A6E44 ^ 0x2B3C5B2B)) | 0x7C1C6C5E)
            - (dword_7FFB208A6E44 ^ 0x15326D04)
            - 2 * ((dword_7FFB208A6E44 ^ 0x2B3C5B2B) & 0x3E0E362F);
        v19 = (dword_7FFB208A6E44 ^ 0xD4C3A4D4)
            - ((v18 - 0x471756AE) ^ 0x3F5A18DB)
            + dword_7FFB208A6E44
            - 0x7955448F;
        *((_DWORD *)Value + 0x1A) = ~(v19 & ~v18)
                                  - (2 * (v19 & ~v18)
                                   + 2 * (v19 & v18))
                                  - 4 * ~(v18 | v19)
                                  - 3 * ~(~v18 | v19)
                                  - 3;
        *(_QWORD *)(Value + 0x6C) = (_QWORD)(0x7F5E16D4FF33CF9ALL);
        *((_DWORD *)Value + 0x1D) = 0xAA405E6D;
        Value[0x78] = 0x2F;
        LOBYTE(v19) = (byte_7FFB208A6E48 - 0xF) ^ 0x60;
        Value[0x79] = byte_7FFB208A6E48
                    + ((v19 - 0x76)
                     ^ (6
                      * ((6 * (~(v19 - 0x76) & 0xD)
                        + ((v19 - 0x76) ^ 0x72)
                        + 6 * ((v19 - 0x76) & 0xD)
                        + 6 * ((v19 - 0x76) & 0x72)
                        - 6 * ((v19 - 0x76) | 0xD))
                       & 0x6B)
                      + ((6 * (~(v19 - 0x76) & 0xD)
                        + ((v19 - 0x76) ^ 0x72)
                        + 6 * ((v19 - 0x76) & 0xD)
                        + 6 * ((v19 - 0x76) & 0x72)
                        - 6 * ((v19 - 0x76) | 0xD))
                       & 0x94)
                      - 5
                      * ((6 * (~(v19 - 0x76) & 0xD)
                        + ((v19 - 0x76) ^ 0x72)
                        + 6 * ((v19 - 0x76) & 0xD)
                        + 6 * ((v19 - 0x76) & 0x72)
                        - 6 * ((v19 - 0x76) | 0xD))
                       ^ 0x94)
                      + 7
                      * (~(6 * (~(v19 - 0x76) & 0xD)
                         + ((v19 - 0x76) ^ 0x72)
                         + 6 * ((v19 - 0x76) & 0xD)
                         + 6 * ((v19 - 0x76) & 0x72)
                         - 6 * ((v19 - 0x76) | 0xD))
                       & 0x94)
                      + ((byte_7FFB208A6E48 - 0xF)
                       ^ (6 * (~(v19 - 0x76) & 0xD)
                        + ((v19 - 0x76) ^ 0x72)
                        + 6 * ((v19 - 0x76) & 0xD)
                        + 6 * ((v19 - 0x76) & 0x72)
                        - 6 * ((v19 - 0x76) | 0xD))
                       ^ 0xEB)
                      - v19
                      - 0x6E));
        v20 = (byte_7FFB208A6E49 + 0x59) ^ 0x49;
        LOBYTE(v18) = (v20 - 0x13) ^ 0xB8;
        v21 = 0xFD * (v18 & 0xB8)
            + 3 * v18
            + 4 * (v18 & 7)
            + (v18 | 0x47)
            + 6 * (~(v20 - 0x13) & 0x47);
        v22 = ((v21 + 0x18) ^ (0xE0 - v20)) - v20 - 5;
        Value[0x7A] = v21
                    + ((v20 - 0x13)
                     ^ ((~byte_7FFB208A6E49 | v22)
                      + 6 * ~(byte_7FFB208A6E49 | v22)
                      + 0xFD * (v22 & byte_7FFB208A6E49)
                      + 3 * v22
                      + 4 * (v22 & ~byte_7FFB208A6E49)
                      - 6 * ~byte_7FFB208A6E49
                      + 1))
                    - v18
                    + 0x57;
        *((_QWORD *)Value + 4) = (_QWORD)(CreateFiber(
                                     (qword_7FFB208A6E50 + 0x407FE788560D2F17LL)
                                   ^ (qword_7FFB208A6E50 + 0x7DB57E93A7643614LL)
                                   ^ (qword_7FFB208A6E50 - 0x77514C1427772917LL)
                                   ^ (qword_7FFB208A6E50 - 0x89275A8A1CBA69CLL)
                                   ^ 0x400B316BD7FC7B82LL,
                                     sub_7FFB207ADFE0,
                                     Value));
        v23 = ((dword_7FFB208A6E58 - 0x6C414818) ^ 0x7C6BBFE0)
            + ((dword_7FFB208A6E58 - 0x6C414818)
             ^ (((dword_7FFB208A6E58 - 0x6C414818) ^ 0x8F683FEE)
              - (((dword_7FFB208A6E58 - 0x6C414818) ^ 0xFF68D9CB)
               + 0x259FE959)
              - 0x54FA7CEA)
             ^ 0xDCF0A43A)
            - (dword_7FFB208A6E58
             - 0x6C414818)
            - ((dword_7FFB208A6E58 - 0x6C414818) ^ 0xFF68D9CB)
            - (((dword_7FFB208A6E58 - 0x6C414818) ^ 0xFF68D9CB)
             + 0x259FE959);
        TlsSetValue(
            ~(~v23 | dword_7FFB208C0038)
          + 6 * (dword_7FFB208C0038 & ~v23)
          + 8 * (dword_7FFB208C0038 & v23)
          - 5 * (~v23 | dword_7FFB208C0038)
          - 3 * (dword_7FFB208C0038 ^ ~v23)
          + 8 * ~(v23 | dword_7FFB208C0038),
            Value);
    }

    if ( *((_QWORD *)Value + 5) )
    {
        v3 = 0xFFFFFFFF;
        if ( (unsigned int)sub_7FFB205841B0((_QWORD)(a1), 0x2E, 0x52, 5) == (dword_7FFB208A6E5C ^ 0xC34883B5)
                                                                + dword_7FFB208A6E5C
                                                                - (dword_7FFB208A6E5C ^ 0x4D91B498)
                                                                + 0x1FB7D330 )
            goto LABEL_xE627;

        RtlAcquireSRWLockExclusive(&unk_7FFB208C0068);
        if ( qword_7FFB208C0060 )
            MEMORY[0x2461D6A0400]();

        qword_7FFB208C0060 = (__int64)NtCurrentTeb()->NtTib.FiberData;
        sub_7FFB20835490((_QWORD)(&Context), (_QWORD)(a1[1]), 0x4D0);
        Context.ContextFlags = ((dword_7FFB208A6E60 - 0x121AD1A1) ^ 0x71D2010B)
                             - ((dword_7FFB208A6E60 - 0x121AD1A1) ^ 0x9EDC1DE7)
                             + 0x1B0DFC6F;
        SetThreadContext(qword_7FFB208C0058, &Context);
        v24 = NtCurrentTeb();
        v25 = qword_7FFB208C0050;
        *(_QWORD *)(qword_7FFB208C0050 + 8) = (_QWORD)(v24->NtTib.StackBase);
        *(_QWORD *)(v25 + 0x10) = (_QWORD)(v24->NtTib.StackLimit);
        *(_QWORD *)(v25 + 0x20) = (_QWORD)(v24->NtTib.FiberData);
        *(_DWORD *)(v25 + 0x1748) = v24->GuaranteedStackBytes;
        *(_QWORD *)(v25 + 0x1478) = (_QWORD)(v24->DeallocationStack);
        *(_QWORD *)(v25 + 0x2C8) = (_QWORD)(v24->ActivationContextStackPointer);
        sub_7FFB208350D0((_QWORD)(&v31), 0, 0x4D0);
        v26 = (dword_7FFB208A6E64 - 0x152CB370) ^ 0xEBA43E0;
        v27 = 0xFFFFFFF9
            - (7 * ~((v26 - 0x224D2CB8) | dword_7FFB208A6E64 ^ v26 ^ 0xFA1CB9C7)
             + ((v26 - 0x224D2CB8) & (dword_7FFB208A6E64 ^ v26 ^ 0xFA1CB9C7))
             + 6 * ((v26 - 0x224D2CB8) | dword_7FFB208A6E64 ^ v26 ^ 0xFA1CB9C7));
        v31.ContextFlags = 2 * (((v26 - 0x224D2CB8) ^ 0xD9CBAEEC) & v27)
                         - 3 * (v27 & ((v26 - 0x224D2CB8) ^ 0x26345113))
                         + 4 * ~(((v26 - 0x224D2CB8) ^ 0xD9CBAEEC) & v27)
                         - 2 * ~(v27 & ((v26 - 0x224D2CB8) ^ 0x26345113))
                         - 2 * ~((v26 - 0x224D2CB8) ^ 0xD9CBAEEC | v27)
                         - 3 * ~((v26 - 0x224D2CB8) ^ 0x26345113 | v27);
        GetThreadContext(qword_7FFB208C0058, &v31);
        v31.Rax = 0xE1D0E1D0LL;
        v28 = (int *)*a1;
        v31.Rbx = **a1;
        v31.Rcx = *((_QWORD *)v28 + 2);
        v31.Rdx = (unsigned int)v28[6];
        v31.Rdi = *((_QWORD *)v28 + 4);
        v31.Rsi = *((_QWORD *)v28 + 5);
        SetThreadContext(qword_7FFB208C0058, &v31);
        Value[0x30] = byte_7FFB208A6E68
                    + (byte_7FFB208A6E68
                     ^ (0xC1 - (((byte_7FFB208A6E68 ^ 0xE7) + 0x62) ^ 0x27))
                     ^ ((byte_7FFB208A6E68 ^ 0xE7) + 0x62)
                     ^ ((((byte_7FFB208A6E68 ^ 0xE7) + 0x62) ^ 0x27) + 0x14)
                     ^ 0x62);
        SwitchToFiber(*((LPVOID *)Value + 0xA));
    }

    *((_QWORD *)Value + 5) = (_QWORD)(a1);
    *((_QWORD *)Value + 0xA) = (_QWORD)(NtCurrentTeb()->NtTib.FiberData);
    SwitchToFiber(*((LPVOID *)Value + 4));
    *((_QWORD *)Value + 5) = (_QWORD)(0);
    if ( Value[0x30] )
    {
        v3 = 0;
        TlsSetValue(
            9 * (dword_7FFB208C0038 & (dword_7FFB208A6E6C ^ 0x468D29FB))
          + 4 * (dword_7FFB208C0038 & (dword_7FFB208A6E6C ^ 0xB972D604))
          - 3 * (dword_7FFB208A6E6C ^ 0x468D29FB | dword_7FFB208C0038)
          - 6 * (dword_7FFB208A6E6C ^ 0x468D29FB)
          + 0xA * ~(dword_7FFB208A6E6C ^ 0xB972D604 | dword_7FFB208C0038),
            0);
        RtlReleaseSRWLockExclusive(&unk_7FFB208C0068);
        sub_7FFB207233E0(
            0x23,
            0x26,
            (_QWORD)(Value),
            (((qword_7FFB208A6E70 - 0xC5ECB6A52740A5BLL) ^ 0x8D5B133EEE16DB3FuLL)
           + (qword_7FFB208A6E70 ^ (0xA5A7B6F34C88E4EBuLL - qword_7FFB208A6E70)))
          ^ (qword_7FFB208A6E70 - 0xC5ECB6A52740A5BLL)
          ^ 0x22C346F194124C8ALL,
            0xA);
    }
    else
    {
        v3 = *((_DWORD *)Value + 0x1A);
        if ( !byte_7FFB208C0070
          && v3 == (((dword_7FFB208A6E78 ^ 0xB001F5EA) + 0x6A39C690)
                  ^ dword_7FFB208A6E78
                  ^ (0x37D11FD6 - dword_7FFB208A6E78)
                  ^ 0x6B3F7BAD) )
        {
            sub_7FFB2037CA90((_QWORD)(5), 0x4D, 0x14, *((_QWORD *)a1[1] + 0x1F));
            v3 = 0;
        }
    }

LABEL_xE627:
    if ( ((unsigned __int64)&v30 ^ v33) != __security_cookie )
        JUMPOUT(0x7FFB206BE656LL);

    return v3;
}

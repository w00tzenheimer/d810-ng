; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: sub_7FF85A5CB920  @ 0x7ff85a5cb920
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN CreateFileMappingW:PROC
EXTERN MapViewOfFile:PROC
EXTERN MapViewOfFileEx:PROC
EXTERN UnmapViewOfFile:PROC
EXTERN VirtualProtect:PROC
EXTERN _invalid_parameter_noinfo_noreturn:PROC
EXTERN sub_7FF858F328E0:PROC
EXTERN sub_7FF85923CE60:PROC
EXTERN sub_7FF85925C110:PROC
EXTERN sub_7FF8599FA090:PROC
EXTERN sub_7FF859EF52F0:PROC
EXTERN sub_7FF859F29900:PROC
EXTERN sub_7FF85A074F40:PROC
EXTERN sub_7FF85A433DC0:PROC
EXTERN sub_7FF85A5E6830:PROC
EXTERN sub_7FF85A639760:PROC
EXTERN sub_7FF85A9D88B0:PROC
EXTERN sub_7FF85AA0FF60:PROC

CONST SEGMENT
qword_7FF85AAE4450 dq 536410DF5043B9C9h
dword_7FF85AAE4458 dd 0FF125B4h
dword_7FF85AAE445C dd 0BAFBB7E9h
dword_7FF85AAE4460 dd 40D65729h
dword_7FF85AAE4464 dd 6AC5E922h
dword_7FF85AAE4468 dd 259220Bh
dword_7FF85AAE446C dd 0E05713E3h
dword_7FF85AAE4470 dd 0A2EDFFD9h
dword_7FF85AAE4474 dd 9B1794F3h
dword_7FF85AAE4478 dd 6778F82Ch
dword_7FF85AAE447C dd 2606EC5h
dword_7FF85AAE4480 dd 7D0908C4h
dword_7FF85AAE4484 dd 0C1E4826Ch
dword_7FF85AAE4488 dd 0E97C7DD9h
qword_7FF85AAE4490 dq -5BE16CA6C6090D36h
qword_7FF85AAE4498 dq -7D186A39BD52FA8Ah
qword_7FF85AAE44A0 dq -663EC31D4900F084h
qword_7FF85AAE44A8 dq 6DFDFC26DC1F32D7h
dword_7FF85AAE44B0 dd 3833BADAh
dword_7FF85AB5E54C dd 3D983A4Bh
dword_7FF85AB5E550 dd 69C5C96Bh
dword_7FF85AB5E554 dd 9B5B4A7Ah
dword_7FF85AB5E558 dd 565F3486h
dword_7FF85AB5E55C dd 85A05235h
dword_7FF85AB5E560 dd 55075A31h
dword_7FF85AB5E564 dd 688BAF08h
dword_7FF85AB5E568 dd 418E2162h
dword_7FF85AB5E56C dd 0FBED8D4Dh
dword_7FF85AB5E570 dd 94E81F87h
dword_7FF85AB5E574 dd 11FFDC92h
dword_7FF85AB5E578 dd 0DB1A4ADh
dword_7FF85AB5E57C dd 443AD638h
dword_7FF85AB5E580 dd 3E5E955h
dword_7FF85AB5E584 dd 0DA256318h
dword_7FF85AB5E588 dd 0C0F55C1Ch
dword_7FF85AB5E58C dd 21EC158Ah
dword_7FF85AB5E590 dd 6C030D3Ch
dword_7FF85AB5E594 dd 2D4CA7F4h
dword_7FF85AB5E598 dd 12EA0E9Eh
dword_7FF85AB5E59C dd 0CF3F88C9h
dword_7FF85AB5E5A0 dd 0E80ECEFCh
dword_7FF85AB5E5A4 dd 0A07460F9h
dword_7FF85AB5E5A8 dd 2B4145F0h
dword_7FF85AB5E5AC dd 8839481Fh
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC sub_7FF85A5CB920
sub_7FF85A5CB920:
    push rbp
    push r15
    push r14
    push r13
    push r12
    push rsi
    push rdi
    push rbx
    sub rsp, 138h
    lea rbp, [rsp+80h]
    mov qword ptr [rbp+0B0h], -2
    mov qword ptr [rbp+10h], rdx
    mov rsi, rcx
    mov eax, dword ptr [dword_7FF85AB5E54C]
    mov ecx, 6F4DE42Ch
    sub ecx, eax
    xor eax, -2D89EB45h
    lea edx, [rax-14C999F4h]
    mov r8d, edx
    xor r8d, 547B6953h
    xor ecx, eax
    xor ecx, r8d
    add r8d, 6DFDFC26h
    sub ecx, edx
    xor r8d, edx
    xor r8d, ecx
    xor r8d, 0E3F4E81h
    mov dword ptr [rbp+0ACh], r8d
    mov rbx, 1B405FE20ACE9FDAh
    jmp loc_7FF85A5CB9C6
    loc_7FF85A5CB99D:
    mov rax, qword ptr [rbp+8]
    mov qword ptr [rbp+40h], rax
    mov eax, dword ptr [dword_7FF85AB5E564]
    mov ecx, -2EDC81h
    xor eax, ecx
    add eax, -1E000396h
    nop word ptr [rax+rax+00000000h]
    loc_7FF85A5CB9C0:
    mov dword ptr [rbp+0ACh], eax
    loc_7FF85A5CB9C6:
    mov eax, dword ptr [rbp+0ACh]
    cmp eax, 37E2E8EEh
    jle loc_7FF85A5CBA10
    cmp eax, 5A2B1718h
    jg loc_7FF85A5CBBC0
    cmp eax, 4D6EB34Fh
    jle loc_7FF85A5CBC8F
    cmp eax, 578842BFh
    jle loc_7FF85A5CC359
    cmp eax, 578842C0h
    jz loc_7FF85A5CBD54
    jmp loc_7FF85A5CC593
    loc_7FF85A5CBA10:
    cmp eax, 2BEE72F4h
    jle loc_7FF85A5CBC10
    cmp eax, 36145CD6h
    jg loc_7FF85A5CBC60
    cmp eax, 2BEE72F5h
    jz loc_7FF85A5CCC91
    cmp eax, 31796C2Ah
    jnz loc_7FF85A5CC04C
    mov rax, qword ptr [rbp+90h]
    mov rax, qword ptr [rax]
    mov rcx, qword ptr [rbp+70h]
    mov qword ptr [rsi], rcx
    mov qword ptr [rsi+8], rax
    cmp qword ptr [rbp+98h], 0
    jz loc_7FF85A5CCA19
    mov rax, qword ptr [rbp-10h]
    mov rcx, qword ptr [rbp+98h]
    sub rax, rcx
    mov qword ptr [rbp+50h], rax
    cmp rax, 0FFFh
    jbe loc_7FF85A5CCA47
    mov rax, qword ptr [rbp+98h]
    mov rax, qword ptr [rax-8]
    mov qword ptr [rbp], rax
    mov r8, qword ptr [qword_7FF85AAE4490]
    mov rdx, -293D8D9121ACFF90h
    add rdx, r8
    mov r9, -48B47F571716C1E8h
    xor rdx, r9
    mov r9, 303ABBD3733CDC4Bh
    add r9, r8
    sub rdx, r9
    mov r10, 76F6A64151583FCAh
    add rdx, r10
    xor rdx, r9
    mov r9, r8
    not r9
    mov r10, rdx
    or r10, r9
    not r10
    lea r10, [r10+r10*2]
    mov r11, rdx
    or r11, r8
    not r11
    add r11, r11
    and r9, rdx
    lea rdi, [r9+r9*2]
    not r9
    add r9, r9
    and rdx, r8
    mov r8, rdx
    not r8
    add rdx, rdx
    sub rdx, rdi
    lea rdx, [rdx+r8*4]
    sub rdx, r9
    sub rdx, r11
    sub rdx, r10
    mov r8, rcx
    not r8
    lea r8, [r8+r8*2]
    mov r9, rdx
    not r9
    mov r10, rcx
    or r10, r9
    not r10
    lea r10, [r10+r10*2]
    mov r11, rcx
    or r11, rdx
    not r11
    lea r11, [r11+r11*2]
    mov rdi, rcx
    xor rdi, rdx
    lea r14, [rdi*8]
    sub r14, rdi
    add r14, r11
    and r9, rcx
    add r9, r9
    lea r9, [r9+r9*2]
    and rdx, rcx
    add rdx, rdx
    sub rdx, r9
    add rdx, r14
    sub rdx, r10
    sub rdx, r8
    sub rdx, rax
    cmp rdx, 20h
    jnb loc_7FF85A5CCE94
    mov eax, dword ptr [dword_7FF85AB5E558]
    lea ecx, [rax+14CF8E04h]
    lea edx, [rax-14467482h]
    lea r8d, [rax-15380065h]
    lea r9d, [rax+166ABA63h]
    xor r9d, edx
    lea edx, [rax+5B2E8CEFh]
    xor edx, ecx
    xor edx, r9d
    xor edx, -22D3E5E0h
    add eax, edx
    add eax, -9B362CFh
    xor eax, r8d
    jmp loc_7FF85A5CB9C0
    loc_7FF85A5CBBC0:
    cmp eax, 75F14240h
    jg loc_7FF85A5CBE46
    cmp eax, 5A2B1719h
    jz loc_7FF85A5CC38B
    cmp eax, 5D99C66Ah
    jz loc_7FF85A5CC16A
    mov eax, dword ptr [dword_7FF85AB5E57C]
    mov ecx, eax
    xor ecx, 5CAC4E4Bh
    lea edx, [rcx+319C8BE1h]
    xor ecx, eax
    xor ecx, edx
    xor ecx, 4E463F86h
    mov dword ptr [rbp+0ACh], ecx
    jmp loc_7FF85A5CB9C6
    loc_7FF85A5CBC10:
    cmp eax, 1E928A3Ah
    jle loc_7FF85A5CBE96
    cmp eax, 1E928A3Bh
    jz loc_7FF85A5CB99D
    cmp eax, 1FC69F30h
    jnz loc_7FF85A5CC41A
    mov rax, qword ptr [rbp+0A0h]
    mov rcx, qword ptr [rbp+48h]
    mov qword ptr [rbp+20h], rcx
    mov qword ptr [rbp+18h], rax
    mov eax, dword ptr [dword_7FF85AB5E594]
    mov ecx, 60E18E87h
    add eax, ecx
    xor eax, 27E84BB0h
    add eax, 56FCB087h
    jmp loc_7FF85A5CB9C0
    loc_7FF85A5CBC60:
    cmp eax, 36145CD7h
    jz loc_7FF85A5CC9AB
    cmp eax, 36CCCAC9h
    jz loc_7FF85A5CC49D
    mov rax, qword ptr [rbp+50h]
    add rax, 27h
    mov rcx, qword ptr [rbp]
    mov qword ptr [rbp+30h], rax
    mov qword ptr [rbp+28h], rcx
    jmp loc_7FF85A5CCA5A
    loc_7FF85A5CBC8F:
    cmp eax, 37E2E8EFh
    jz loc_7FF85A5CC16A
    cmp eax, 399666A7h
    jz loc_7FF85A5CCA67
    mov ecx, dword ptr [dword_7FF85AAE4478]
    lea edx, [rcx+171E5EDBh]
    mov eax, edx
    xor eax, -3D9924E8h
    mov r9d, edx
    xor r9d, 3D9924E7h
    mov r8d, r9d
    and r8d, 60F3E7Bh
    add r8d, r8d
    add r9d, r9d
    or r9d, 0C1E7CF6h
    mov r10d, edx
    xor r10d, 3B961A9Ch
    sub r9d, r10d
    sub r9d, r8d
    mov r8d, edx
    not r8d
    lea r10d, [r8+r8*4]
    mov r11d, edx
    and r11d, 19C3A29Dh
    lea r11d, [r11+r11*2]
    mov edi, r8d
    and edi, 19C3A29Dh
    lea edi, [rdi+rdi*4]
    add edi, r11d
    xor edx, 663C5D62h
    add edx, edx
    and r8d, 63C5D62h
    shl r8d, 3
    sub r8d, edx
    add r8d, edi
    sub r8d, r10d
    lea edx, [rcx+r8]
    add edx, -619BDAFBh
    xor r9d, ecx
    xor r9d, edx
    sub r9d, eax
    mov ecx, 5Ah
    mov edx, 37h
    mov r8d, 3Eh
    call sub_7FF858F328E0
    loc_7FF85A5CBD54:
    mov rax, qword ptr [rbp+80h]
    mov rcx, qword ptr [rbp+90h]
    mov r10, qword ptr [rcx]
    mov ecx, dword ptr [dword_7FF85AAE447C]
    lea edx, [rcx-6220EB9Ch]
    mov r8d, edx
    xor r8d, 5720C9A9h
    lea r9d, [r8-13809CD9h]
    sub ecx, r9d
    xor r9d, 49331A14h
    sub ecx, edx
    add ecx, -5E6EF75Eh
    xor ecx, r9d
    lea edx, [r9+rcx]
    add edx, -3E4D5E35h
    xor edx, r8d
    mov r8d, dword ptr [dword_7FF85AAE4480]
    lea ecx, [r8+1FAFB49h]
    xor ecx, 2895957Fh
    sub ecx, r8d
    add r8d, 5D7F7FEAh
    xor r8d, ecx
    mov r9d, dword ptr [dword_7FF85AAE4484]
    mov ecx, 3E1B7D94h
    add r9d, ecx
    mov rcx, qword ptr [rbp+78h]
    mov qword ptr [rsp+28h], rax
    mov qword ptr [rsp+20h], r10
    call qword ptr [MapViewOfFileEx]
    test rax, rax
    jz loc_7FF85A5CC51B
    mov eax, dword ptr [dword_7FF85AB5E588]
    lea ecx, [rax-7B388614h]
    xor ecx, 549BD1C9h
    lea edx, [rcx+3A08E0DCh]
    mov r8d, edx
    xor r8d, 5B02CD2Eh
    lea r9d, [r8-7ABA5B0Dh]
    xor edx, ecx
    xor edx, -172B6DADh
    sub edx, r8d
    add edx, 176BF676h
    xor edx, r9d
    add ecx, edx
    add ecx, 60F11377h
    xor ecx, r8d
    add ecx, eax
    mov dword ptr [rbp+0ACh], ecx
    jmp loc_7FF85A5CB9C6
    loc_7FF85A5CBE46:
    cmp eax, 75F14241h
    jz loc_7FF85A5CC647
    cmp eax, 7664D179h
    jnz loc_7FF85A5CC396
    mov eax, dword ptr [dword_7FF85AB5E568]
    lea ecx, [rax+36F1E1A3h]
    lea edx, [rax+4432700Bh]
    xor edx, -204CB8CDh
    mov r8d, 15E849Eh
    sub r8d, eax
    xor r8d, ecx
    sub r8d, edx
    add r8d, 914B866h
    mov dword ptr [rbp+0ACh], r8d
    jmp loc_7FF85A5CB9C6
    loc_7FF85A5CBE96:
    cmp eax, 5009DC0h
    jz loc_7FF85A5CC04C
    cmp eax, 18760792h
    jnz loc_7FF85A5CCE70
    mov ecx, 3
    mov edx, 10h
    mov r8d, 31h
    call sub_7FF85923CE60
    mov ecx, 54h
    mov edx, 5Fh
    mov r8d, 4Fh
    call sub_7FF85925C110
    mov ecx, 2Ch
    mov edx, 57h
    mov r8d, 41h
    call sub_7FF85A074F40
    mov ecx, 44h
    mov edx, 35h
    mov r8d, 2
    call sub_7FF85A5E6830
    mov ecx, 6
    mov edx, 2
    mov r8d, 22h
    call sub_7FF85A433DC0
    mov qword ptr [rsp+20h], 4Ch
    mov ecx, 4Eh
    mov edx, 42h
    mov r8, qword ptr [rbp+10h]
    lea r9, [rbp+80h]
    call sub_7FF8599FA090
    movups xmm0, xmmword ptr [rbp+80h]
    movaps xmmword ptr [rbp-50h], xmm0
    lea rcx, [rbp-38h]
    lea rdx, [rbp-50h]
    call sub_7FF859EF52F0
    lea rax, [rbp+88h]
    mov qword ptr [rbp+90h], rax
    mov eax, dword ptr [rbp+88h]
    mov ecx, dword ptr [dword_7FF85AAE4458]
    lea r11d, [rcx-1E906A1Fh]
    lea r10d, [rcx-114306BDh]
    mov r9d, r11d
    not r9d
    mov edx, r10d
    or edx, r9d
    not edx
    lea r8d, [rdx+rdx*4]
    lea edx, [rdx+r8*4]
    mov edi, r10d
    or edi, r11d
    lea r8d, [rdi+rdi*4]
    lea r8d, [rdi+r8*2]
    not edi
    lea r14d, [rdi+rdi*4]
    lea edi, [rdi+r14*2]
    and r11d, r10d
    lea r14d, [r11+r11*8]
    not r11d
    lea r15d, [r11+r11*4]
    lea r11d, [r11+r15*2]
    and r9d, r10d
    lea r10d, [r9+r9*4]
    lea r9d, [r9+r10*4]
    add r14d, r9d
    sub r8d, r14d
    add r8d, r11d
    sub r8d, edi
    sub r8d, edx
    add r8d, ecx
    mov ecx, dword ptr [dword_7FF85AAE445C]
    mov edx, ecx
    xor edx, 535770F2h
    mov r9d, ecx
    xor r9d, 526EF1BEh
    add r9d, ecx
    sub r9d, edx
    xor r9d, ecx
    xor r9d, 31F80CCh
    mov dword ptr [rsp+20h], eax
    mov qword ptr [rsp+28h], 0
    mov rcx, -1
    xor edx, edx
    call qword ptr [CreateFileMappingW]
    mov qword ptr [rbp+78h], rax
    test rax, rax
    jz loc_7FF85A5CC5C8
    mov eax, dword ptr [dword_7FF85AB5E560]
    lea ecx, [rax+70A072ABh]
    add eax, -4EE8D3ABh
    mov edx, eax
    xor edx, -6F276393h
    sub edx, eax
    add edx, 231B8940h
    jmp loc_7FF85A5CCA3A
    loc_7FF85A5CC04C:
    mov edx, 14h
    mov r8d, 0Dh
    mov r9d, 52h
    lea rcx, [rbp-20h]
    call sub_7FF859F29900
    loc_7FF85A5CC066:
    mov rcx, qword ptr [rbp+80h]
    call qword ptr [UnmapViewOfFile]
    mov ecx, dword ptr [dword_7FF85AAE4474]
    mov edx, ecx
    not edx
    and edx, 481B4ADCh
    add edx, edx
    lea edx, [rdx+rdx*4]
    mov r8d, ecx
    or r8d, -37E4B524h
    lea r9d, [r8+r8*4]
    lea r8d, [r8+r9*2]
    mov r9d, ecx
    xor r9d, 481B4ADCh
    add r9d, r9d
    mov r10d, ecx
    and r10d, 17E4B523h
    shl r10d, 3
    mov r11d, ecx
    and r11d, -37E4B524h
    imul r11d, 0F5h
    sub r11d, r10d
    sub r11d, r9d
    add r11d, r8d
    sub r11d, edx
    mov edx, r11d
    xor edx, -7CF678D7h
    lea r8d, [rdx-0DEA721Eh]
    add ecx, -558B225Ch
    xor ecx, edx
    add ecx, r11d
    mov edx, ecx
    or edx, r8d
    lea r9d, [rcx+rcx]
    mov r10d, r8d
    not r10d
    and r10d, ecx
    and ecx, r8d
    xor r8d, -29CB5293h
    add r8d, -66BE916Dh
    lea ecx, [rcx+rcx*2]
    lea ecx, [rcx+r10*2]
    sub ecx, r9d
    add ecx, edx
    xor ecx, r8d
    cmp eax, ecx
    jnz loc_7FF85A5CC3FE
    mov eax, dword ptr [dword_7FF85AB5E5A0]
    lea ecx, [rax-35FC0A8Ah]
    lea edx, [rax+16511AFEh]
    xor edx, 0C4E3B50h
    lea r8d, [rdx+5AE1DB2Ch]
    xor r8d, 6109CE55h
    sub r8d, edx
    add r8d, edx
    add r8d, 5AE1DB2Ch
    sub r8d, eax
    lea eax, [r8+rdx]
    add eax, 60A292FDh
    xor eax, ecx
    jmp loc_7FF85A5CB9C0
    loc_7FF85A5CC16A:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    pushfq
    pop rax
    mov rcx, qword ptr [qword_7FF85AAE4450]
    mov r8, rcx
    mov rdx, 187DFDB968F9CA77h
    xor r8, rdx
    mov rdx, rcx
    mov r9, -187DFDB968F9CA78h
    xor rdx, r9
    mov r9, rdx
    and r9, rbx
    lea r10, [r9+r9*4]
    lea r9, [r9+r10*2]
    mov r10, r8
    or r10, rbx
    mov r11, r8
    mov rdi, -1B405FE20ACE9FDBh
    and r11, rdi
    add r11, r10
    mov r10, r8
    and r10, rbx
    imul rdi, r10, 0F5h
    add rdi, r11
    sub rdi, r9
    add rdi, rdx
    mov r9, 2BC41EB676E0DE5Fh
    add r9, rdi
    mov r10, 38143676982D0ECEh
    add rdi, r10
    mov r10, rdi
    mov r11, 326466F70A963525h
    xor r10, r11
    mov r11, 76281BB1EDF6DA6Ch
    add r10, r11
    xor r10, rdi
    mov r11, r10
    or r11, rdx
    not r11
    lea rdi, [r11+r11*4]
    lea r11, [r11+rdi*2]
    lea rdi, [r8+r8*4]
    lea rdi, [r8+rdi*2]
    and rdx, r10
    add rdx, rdi
    mov rdi, r10
    or rdi, r8
    add rdx, rdi
    and r8, r10
    imul r8, 0F5h
    add r8, rdx
    sub r8, r11
    sub r8, r10
    sub r8, r9
    sub r8, r9
    mov rdx, 5A0964E1E870B3F0h
    add rcx, rdx
    add rcx, r8
    cmp rax, rcx
    jnz loc_7FF85A5CC450
    mov eax, dword ptr [dword_7FF85AB5E5AC]
    lea ecx, [rax-49337992h]
    lea edx, [rax+2F17A557h]
    lea r8d, [rax-55330A7Ch]
    xor r8d, edx
    lea edx, 0FFFFFFFFBD204580h[rax*2]
    add eax, edx
    add eax, 44E4DD37h
    xor eax, r8d
    xor eax, ecx
    jmp loc_7FF85A5CB9C0
    loc_7FF85A5CC359:
    cmp eax, 4FB06FEBh
    jnz loc_7FF85A5CCE7D
    mov eax, dword ptr [dword_7FF85AB5E574]
    lea ecx, [rax-4AA605D4h]
    lea edx, [rax+619B90D9h]
    xor edx, ecx
    xor edx, -6FF1AA1Eh
    add edx, eax
    mov dword ptr [rbp+0ACh], edx
    jmp loc_7FF85A5CB9C6
    loc_7FF85A5CC38B:
    mov rax, qword ptr [rbp+0A0h]
    mov qword ptr [rbp+40h], rax
    loc_7FF85A5CC396:
    mov rax, qword ptr [rbp+40h]
    mov qword ptr [rbp+60h], rax
    cmp dword ptr [rax+10h], 1
    jnz loc_7FF85A5CC47F
    mov eax, dword ptr [dword_7FF85AB5E5A4]
    mov ecx, eax
    xor ecx, -6B403425h
    lea edx, [rcx-71C7E391h]
    lea r8d, [rcx-2804CAF9h]
    mov r9d, r8d
    xor r9d, -6304DB9Eh
    lea r10d, [r9-6F7AF076h]
    lea r11d, [r9-3FE86294h]
    sub r9d, r8d
    sub r9d, ecx
    add r9d, 0DA541E1h
    xor edx, eax
    xor edx, r10d
    xor edx, r11d
    xor edx, r9d
    mov dword ptr [rbp+0ACh], edx
    jmp loc_7FF85A5CB9C6
    loc_7FF85A5CC3FE:
    mov eax, dword ptr [dword_7FF85AB5E584]
    mov ecx, eax
    xor ecx, 74A8BE03h
    add ecx, ecx
    add eax, ecx
    add eax, 20472572h
    jmp loc_7FF85A5CB9C0
    loc_7FF85A5CC41A:
    mov eax, dword ptr [dword_7FF85AB5E554]
    lea ecx, [rax-74D87F48h]
    xor ecx, -2688EC97h
    lea edx, [rcx+71904286h]
    lea r8d, 49100C9h[rcx*2]
    xor r8d, edx
    add r8d, eax
    sub r8d, ecx
    add eax, r8d
    add eax, -74D87F48h
    jmp loc_7FF85A5CB9C0
    loc_7FF85A5CC450:
    mov eax, dword ptr [dword_7FF85AB5E55C]
    mov ecx, eax
    xor ecx, -2CED2E30h
    lea edx, [rcx-1E0BA1A8h]
    xor edx, -56F9200Bh
    add ecx, edx
    add ecx, -4A7C6C06h
    xor ecx, eax
    mov dword ptr [rbp+0ACh], ecx
    jmp loc_7FF85A5CB9C6
    loc_7FF85A5CC47F:
    mov rax, qword ptr [rbp+60h]
    mov rdx, qword ptr [rax]
    mov r8, qword ptr [rax+8]
    mov rcx, rdx
    sub rcx, qword ptr [rbp+80h]
    add rcx, qword ptr [rbp+70h]
    call sub_7FF85AA0FF60
    loc_7FF85A5CC49D:
    mov rax, qword ptr [rbp+60h]
    add rax, 18h
    mov qword ptr [rbp+8], rax
    cmp rax, qword ptr [rbp+68h]
    jz loc_7FF85A5CC4EC
    mov eax, dword ptr [dword_7FF85AB5E578]
    lea ecx, [rax+5817BC21h]
    mov edx, ecx
    xor edx, -338991DAh
    xor ecx, 318A094Ah
    add ecx, edx
    add ecx, 70A3E784h
    add edx, 2CC69255h
    xor ecx, edx
    sub ecx, eax
    add ecx, 7420301Bh
    mov dword ptr [rbp+0ACh], ecx
    jmp loc_7FF85A5CB9C6
    loc_7FF85A5CC4EC:
    mov eax, dword ptr [dword_7FF85AB5E580]
    mov ecx, eax
    xor ecx, -3BCE6E6Fh
    lea edx, [rcx+8B247C9h]
    add eax, ecx
    add eax, -4307C210h
    add ecx, -4C2C55AEh
    xor eax, ecx
    xor eax, edx
    add eax, 11D943C3h
    jmp loc_7FF85A5CB9C0
    loc_7FF85A5CC51B:
    mov ecx, dword ptr [dword_7FF85AAE4488]
    mov eax, 4ED0E438h
    add ecx, eax
    mov eax, ecx
    xor eax, 516314B3h
    mov edx, ecx
    not edx
    mov r8d, edx
    and r8d, 516312B1h
    lea r8d, [r8+r8*2]
    lea r9d, [rdx+rdx]
    or r9d, 5D39DA9Ch
    lea r9d, [r9+r9*2]
    mov r10d, ecx
    xor r10d, -516312B2h
    and edx, 2E9CED4Eh
    lea edx, [rdx+rdx*2]
    add edx, edx
    and ecx, 2E9CED4Eh
    lea ecx, [rcx+rcx*2]
    lea ecx, [rdx+rcx*2]
    add ecx, r10d
    sub ecx, r9d
    lea r9d, [rcx+r8*2]
    add r9d, eax
    mov ecx, 28h
    mov edx, 33h
    mov r8d, 0Dh
    call sub_7FF858F328E0
    loc_7FF85A5CC593:
    mov rdx, qword ptr [rbp-20h]
    mov rcx, qword ptr [rbp-18h]
    mov qword ptr [rbp+98h], rdx
    mov qword ptr [rsp+20h], 5
    mov r8d, 46h
    mov r9d, 35h
    call sub_7FF85A639760
    mov rax, qword ptr [rbp+0A0h]
    jmp loc_7FF85A5CCC30
    loc_7FF85A5CC5C8:
    mov edx, dword ptr [dword_7FF85AAE4460]
    lea ecx, [rdx+34DDF4D0h]
    lea eax, [rdx-7AE115FBh]
    xor eax, -0D97FFCh
    lea r8d, [rax+7E6BB6E3h]
    mov r9d, edx
    xor r9d, -42DC6A03h
    add edx, r9d
    add edx, -7AE115FBh
    add edx, eax
    xor edx, r8d
    xor edx, -6B88F5DFh
    mov r8d, edx
    or r8d, ecx
    lea r9d, [r8+r8*2]
    not r8d
    lea r10d, [r8*8]
    sub r10d, r8d
    and edx, ecx
    lea ecx, [rdx+r9*2]
    add ecx, r10d
    neg ecx
    lea r9d, [rax+rcx]
    add r9d, 1EE947D6h
    mov ecx, 64h
    mov edx, 2Dh
    mov r8d, 4
    call sub_7FF858F328E0
    loc_7FF85A5CC647:
    mov rax, qword ptr [rbp+90h]
    mov rax, qword ptr [rax]
    mov r8d, dword ptr [dword_7FF85AAE4464]
    lea ecx, [r8-225A557h]
    mov r9d, ecx
    or r9d, 68AF93F4h
    mov edx, ecx
    or edx, -68AF93F5h
    mov r10d, ecx
    xor r10d, 68AF93F4h
    add r10d, edx
    lea r11d, 0FFFFFFFFFBB4B552h[r8*2]
    mov edx, ecx
    and edx, 68AF93F4h
    lea r12d, [rdx+rdx*2]
    mov edx, ecx
    and edx, -68AF93F5h
    lea edx, [rdx+rdx*2]
    add edx, r12d
    sub edx, r11d
    add edx, r10d
    sub edx, r9d
    mov r9d, edx
    xor r9d, -5079C013h
    lea r12d, [r9-389A6E53h]
    lea r13d, [r9-22D0E3A2h]
    xor r13d, -61EA385Ch
    add r13d, r8d
    mov r10d, r12d
    not r10d
    lea r11d, [r10+r10]
    lea r11d, [r11+r11*2]
    mov r15d, r13d
    or r15d, r10d
    mov edi, r13d
    or edi, r12d
    not edi
    lea edi, [rdi+rdi*2]
    lea r14d, [r13+r13*2+0]
    and r10d, r13d
    shl r10d, 2
    and r13d, r12d
    lea r12d, [r13+r13*2+0]
    sub r10d, r12d
    add r10d, r14d
    lea r10d, [r10+rdi*2]
    add r10d, r15d
    sub r10d, r11d
    sub r10d, r8d
    sub r10d, r9d
    add r10d, 1D51DADAh
    mov r8d, edx
    not r8d
    mov r9d, r10d
    or r9d, r8d
    mov r11d, r10d
    or r11d, edx
    and edx, r10d
    and r8d, r10d
    not r10d
    lea edi, [r10*8]
    sub edi, r10d
    not r9d
    lea r9d, [r9+r9*8]
    not r11d
    add r11d, r11d
    lea r10d, [r11+r11*4]
    mov r11d, edx
    not r11d
    lea r11d, [r11+r11*2]
    add r8d, r8d
    add edx, edx
    sub edx, r8d
    add edx, r11d
    sub edx, r10d
    sub edx, r9d
    add edx, edi
    xor edx, ecx
    mov r8d, dword ptr [dword_7FF85AAE4468]
    lea ecx, [r8+796AD814h]
    add r8d, 36664CEAh
    xor r8d, ecx
    xor r8d, -55488F47h
    add r8d, 16341BADh
    mov ecx, dword ptr [dword_7FF85AAE446C]
    mov r9d, ecx
    xor r9d, -2222F48Ch
    mov r10d, ecx
    xor r10d, 22024409h
    and r10d, -1DB8B0D7h
    lea r11d, [r10+r10*4]
    lea r10d, [r10+r11*2]
    mov r11d, r9d
    or r11d, -1DB8B0D7h
    lea edi, [r11+r11*4]
    lea edi, [r11+rdi*2]
    mov r14d, ecx
    xor r14d, 3F9A445Dh
    mov r11d, r9d
    and r11d, 1DB8B0D6h
    lea r15d, [r11+r11*8]
    mov r11d, r9d
    and r11d, -1DB8B0D7h
    imul r11d, 0F5h
    sub r11d, r15d
    sub r11d, r14d
    add r11d, edi
    sub r11d, r10d
    lea r12d, [r11+1C1402B5h]
    mov r10d, r12d
    not r10d
    and r10d, 372B3767h
    add r10d, r10d
    lea edi, [r10+r10*4]
    mov r10d, r12d
    or r10d, 372B3767h
    lea r14d, [r10+r10*4]
    lea r14d, [r10+r14*2]
    mov r15d, r12d
    xor r15d, 372B3767h
    add r15d, r15d
    mov r13d, r12d
    and r13d, 8D4C898h
    shl r13d, 3
    mov r10d, r12d
    and r10d, 372B3767h
    imul r10d, 0F5h
    sub r10d, r13d
    sub r10d, r15d
    add r10d, r14d
    sub r10d, edi
    mov edi, r10d
    sub edi, r11d
    sub edi, r12d
    sub edi, r9d
    add edi, 7074A0CBh
    mov r9d, ecx
    not r9d
    mov r11d, edi
    or r11d, r9d
    not r11d
    mov r14d, edi
    or r14d, ecx
    add r14d, r14d
    mov r15d, edi
    xor r15d, ecx
    and r9d, edi
    shl r9d, 2
    and edi, ecx
    lea ecx, [r9+rdi*2]
    sub ecx, r15d
    sub ecx, r14d
    lea r9d, [rcx+r11*4]
    xor r9d, r10d
    mov rcx, qword ptr [rbp+78h]
    mov qword ptr [rsp+20h], rax
    call qword ptr [MapViewOfFile]
    mov qword ptr [rbp+70h], rax
    test rax, rax
    jz loc_7FF85A5CC8F7
    mov eax, dword ptr [dword_7FF85AB5E550]
    mov ecx, -638F9D1Ah
    xor eax, ecx
    lea ecx, [rax-19683F5Ah]
    mov edx, 46C505CCh
    sub edx, eax
    xor edx, ecx
    sub edx, eax
    add edx, -61782DA8h
    mov dword ptr [rbp+0ACh], edx
    jmp loc_7FF85A5CB9C6
    loc_7FF85A5CC8F7:
    mov eax, dword ptr [dword_7FF85AAE4470]
    mov edx, eax
    xor edx, -69B87B3Bh
    lea r8d, [rdx-1E4C987Ch]
    mov ecx, r8d
    xor ecx, -522041A0h
    mov r9d, r8d
    not r9d
    mov r10d, r9d
    or r10d, 40E157D4h
    lea r11d, [r10+r10*4]
    lea r11d, [r10+r11*2]
    not r10d
    lea edi, [r10*8]
    sub edi, r10d
    mov r10d, r9d
    and r10d, -40E157D5h
    mov r14d, r10d
    shl r14d, 4
    add r14d, r10d
    add r14d, edi
    and r9d, 40E157D4h
    lea r10d, [r9+r9*2]
    not r9d
    add r9d, r9d
    lea edi, [r9+r9*2]
    and r8d, 40E157D4h
    lea r9d, [r8+r8*8]
    lea r8d, [r8+r9*2]
    lea r9d, [r8+r10*4]
    sub r9d, r11d
    sub r9d, edi
    add r9d, r14d
    sub r9d, ecx
    sub r9d, edx
    add r9d, eax
    xor r9d, ecx
    xor r9d, -4E7DC74Eh
    mov ecx, 36h
    mov edx, 58h
    mov r8d, 25h
    call sub_7FF858F328E0
    loc_7FF85A5CC9AB:
    mov rax, qword ptr [rbp-38h]
    mov rcx, qword ptr [rbp-30h]
    mov qword ptr [rbp+0A0h], rax
    mov qword ptr [rbp+68h], rcx
    cmp rax, rcx
    jz loc_7FF85A5CC9F7
    mov eax, dword ptr [dword_7FF85AB5E570]
    lea ecx, [rax-1CC2D612h]
    xor ecx, -0B80C469h
    lea edx, [rcx-34701A9Fh]
    add eax, ecx
    add eax, -16131345h
    xor eax, edx
    xor eax, ecx
    xor eax, 585CF594h
    add eax, ecx
    add eax, 450D0426h
    jmp loc_7FF85A5CB9C0
    loc_7FF85A5CC9F7:
    mov eax, dword ptr [dword_7FF85AB5E5A8]
    mov ecx, eax
    xor ecx, -7F5F57BDh
    add eax, ecx
    add eax, -353F2136h
    add ecx, -6FD5E06h
    xor eax, ecx
    jmp loc_7FF85A5CB9C0
    loc_7FF85A5CCA19:
    mov eax, dword ptr [dword_7FF85AB5E59C]
    lea ecx, [rax-503F88D7h]
    add eax, -5D93B515h
    mov edx, eax
    xor edx, -2441BEB3h
    sub edx, eax
    add edx, 0EFFDA10h
    loc_7FF85A5CCA3A:
    xor edx, ecx
    mov dword ptr [rbp+0ACh], edx
    jmp loc_7FF85A5CB9C6
    loc_7FF85A5CCA47:
    mov rax, qword ptr [rbp+98h]
    mov rcx, qword ptr [rbp+50h]
    mov qword ptr [rbp+30h], rcx
    mov qword ptr [rbp+28h], rax
    loc_7FF85A5CCA5A:
    mov rcx, qword ptr [rbp+28h]
    mov rdx, qword ptr [rbp+30h]
    call sub_7FF85A9D88B0
    loc_7FF85A5CCA67:
    cmp qword ptr [rbp+0A0h], 0
    jz loc_7FF85A5CCBC9
    mov rdx, qword ptr [rbp-28h]
    mov rax, qword ptr [rbp+0A0h]
    mov r8, rax
    not r8
    mov rcx, rdx
    or rcx, r8
    mov r9, rdx
    or r9, rax
    not r9
    add r9, rcx
    lea rcx, [rdx+rdx]
    and rdx, rax
    add rdx, rdx
    sub rcx, rdx
    add rcx, r9
    sub rcx, r8
    mov rdx, qword ptr [qword_7FF85AAE4498]
    mov r8, 18B2E59BD009C7D3h
    lea r9, [rdx+r8]
    mov r8, r9
    mov r10, -587BD3D2856D90E7h
    xor r8, r10
    mov r10, -6C7C0480F70D9337h
    add r10, r8
    mov r11, r10
    mov r15, -37A6F7992E5579FCh
    or r11, r15
    lea rdi, [r11+r11*2]
    not r11
    lea r14, [r11*8]
    sub r14, r11
    and r10, r15
    lea r10, [r10+rdi*2]
    add r10, r14
    mov r11, -7
    sub r11, r10
    mov r10, 6D8BBAA996AB4B85h
    add r10, r8
    add r8, r9
    mov r9, 27B6DF7C736C378Bh
    add r9, rdx
    xor r11, r10
    add r8, r11
    xor r9, r10
    mov r10, -7D9EF7DD337F1C4h
    xor r9, r10
    xor r9, r8
    mov r10, rdx
    not r10
    mov r8, r9
    or r8, r10
    mov r11, r9
    or r11, rdx
    and r10, r9
    and r9, rdx
    mov rdx, r10
    add r10, r10
    lea r9, [r10+r9*2]
    not rdx
    sub rdx, r9
    not r11
    shl r11, 2
    sub rdx, r11
    not r8
    lea r8, [r8+r8*2]
    sub rdx, r8
    inc rcx
    mov qword ptr [rbp+48h], rcx
    add rdx, -3
    cmp rcx, rdx
    ja loc_7FF85A5CCCC4
    mov eax, dword ptr [dword_7FF85AB5E56C]
    lea ecx, [rax-7D13A560h]
    xor ecx, 25957190h
    add ecx, eax
    add ecx, -7D13A560h
    add ecx, eax
    add ecx, eax
    add ecx, 0AF1DD53h
    add eax, ecx
    add eax, 46E59B8Ch
    jmp loc_7FF85A5CB9C0
    loc_7FF85A5CCBC9:
    mov eax, dword ptr [dword_7FF85AB5E598]
    mov ecx, eax
    xor ecx, -73FEE9D5h
    lea edx, [rcx-72BC72FFh]
    xor edx, 4ED162CAh
    xor eax, 3696C89h
    sub eax, edx
    add eax, ecx
    jmp loc_7FF85A5CB9C0
    loc_7FF85A5CCBF1:
    mov eax, dword ptr [dword_7FF85AB5E58C]
    lea ecx, [rax-7DB92B4Bh]
    lea edx, [rax+3BB2CA3Dh]
    mov r8d, edx
    xor r8d, 5BDCF28Bh
    xor ecx, eax
    xor ecx, -0A0F7FADh
    add ecx, r8d
    xor ecx, edx
    mov dword ptr [rbp+0ACh], ecx
    jmp loc_7FF85A5CB9C6
    loc_7FF85A5CCC30:
    mov qword ptr [rbp+38h], rax
    mov rax, qword ptr [rbp+38h]
    mov qword ptr [rbp+58h], rax
    cmp rax, qword ptr [rbp+68h]
    jz loc_7FF85A5CCC9B
    mov rax, qword ptr [rbp+58h]
    mov r8d, dword ptr [rax+10h]
    mov rcx, qword ptr [rax]
    mov rdx, qword ptr [rax+8]
    lea r9, [rbp-4]
    call qword ptr [VirtualProtect]
    test eax, eax
    jnz loc_7FF85A5CCBF1
    mov r9d, dword ptr [dword_7FF85AAE44B0]
    mov eax, -66AA1159h
    add r9d, eax
    xor r9d, -245E5C04h
    add r9d, -0A280478h
    mov ecx, 0Ah
    mov edx, 2Ah
    mov r8d, 1Ah
    call sub_7FF858F328E0
    loc_7FF85A5CCC91:
    mov rax, qword ptr [rbp+58h]
    add rax, 18h
    jmp loc_7FF85A5CCC30
    loc_7FF85A5CCC9B:
    mov eax, dword ptr [dword_7FF85AB5E590]
    lea ecx, [rax+497D32ADh]
    mov edx, ecx
    xor edx, 2642292Dh
    add edx, eax
    sub edx, ecx
    add edx, -18CB77EDh
    mov dword ptr [rbp+0ACh], edx
    jmp loc_7FF85A5CB9C6
    loc_7FF85A5CCCC4:
    mov rcx, qword ptr [rbp+0A0h]
    mov rcx, qword ptr [rcx-8]
    mov rdx, qword ptr [qword_7FF85AAE44A0]
    mov r9, -678F83C07DDF7CB5h
    add r9, rdx
    mov r10, -3BB14714A94B4B17h
    add r10, rdx
    mov r11, 5F8695E646E11162h
    xor r11, r10
    mov r8, 696337F47ADF3DE6h
    add r8, r11
    mov rdi, -42D6EC8BA418A06h
    xor rdi, r10
    sub rdi, rdx
    mov rdx, 349F9C88C8E6542Bh
    add rdx, rdi
    xor r8, r11
    xor r8, rdx
    sub r8, r10
    xor r8, r9
    mov r9, r8
    not r9
    mov rdx, rax
    or rdx, r9
    not rdx
    lea r10, [rdx+rdx*2]
    mov r11, rax
    or r11, r8
    not r11
    shl r11, 2
    and r9, rax
    mov rdx, r9
    not rdx
    add r9, r9
    and r8, rax
    lea rax, [r9+r8*2]
    sub rdx, rax
    sub rdx, r11
    sub rdx, r10
    sub rdx, rcx
    add rdx, -3
    mov r9, qword ptr [qword_7FF85AAE44A8]
    mov rax, 3B150C79B471BC10h
    xor rax, r9
    mov r8, 6DAB6DC272133E7Fh
    add r8, rax
    mov r10, 704AFA93EA119B87h
    xor r10, r8
    mov rax, -73CFFADFEF99BBA0h
    xor rax, r8
    mov r11, 0C30052010664460h
    xor r11, r8
    mov rdi, 385004C05882018h
    xor rdi, r8
    mov rbx, 3C5F8CC4F883299h
    and rdi, rbx
    lea rdi, [rdi+rdi*2]
    mov r14, 3C3A0733B077CD66h
    and r14, r11
    shl r14, 2
    or rax, rbx
    sub rax, r10
    sub rax, r10
    sub rax, r14
    sub rax, rdi
    add rax, -3
    mov r11, 5A5C5AC74DEACD28h
    add r11, r9
    add r11, r10
    mov r9, r8
    not r9
    mov r10, r11
    or r10, r9
    not r10
    lea r10, [r10+r10*2]
    mov rdi, r11
    or rdi, r8
    not rdi
    add rdi, rdi
    and r9, r11
    lea rbx, [r9+r9*2]
    not r9
    add r9, r9
    and r11, r8
    mov r8, r11
    not r8
    add r11, r11
    sub r11, rbx
    lea r8, [r11+r8*4]
    sub r8, r9
    sub r8, rdi
    sub r8, r10
    xor r8, rax
    cmp rdx, r8
    jnb loc_7FF85A5CCE94
    mov rax, qword ptr [rbp+48h]
    add rax, 27h
    mov qword ptr [rbp+20h], rax
    mov qword ptr [rbp+18h], rcx
    loc_7FF85A5CCE70:
    mov rcx, qword ptr [rbp+18h]
    mov rdx, qword ptr [rbp+20h]
    call sub_7FF85A9D88B0
    loc_7FF85A5CCE7D:
    mov rax, rsi
    add rsp, 138h
    pop rbx
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    pop rbp
    ret
    loc_7FF85A5CCE94:
    call _invalid_parameter_noinfo_noreturn
_TEXT ENDS
END

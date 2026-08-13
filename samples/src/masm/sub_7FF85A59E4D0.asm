; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: sub_7FF85A59E4D0  @ 0x7ff85a59e4d0
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN __security_check_cookie:PROC
EXTERN memset:PROC
EXTERN sub_7FF858E45D30:PROC
EXTERN sub_7FF85A3BE8A0:PROC

CONST SEGMENT
__security_cookie dq 0C6DD3C173A62h
dword_7FF85AAE40A4 dd 5447DE18h
dword_7FF85AB5D568 dd 613C8454h
dword_7FF85AB5D56C dd 7E9A8D29h
dword_7FF85AB5D570 dd 6A997E33h
dword_7FF85AB5D574 dd 265F6A6Ah
dword_7FF85AB5D578 dd 112C4743h
dword_7FF85AB5D57C dd 10056539h
dword_7FF85AB5D580 dd 79CC5851h
dword_7FF85AB5D584 dd 0C37E60BBh
dword_7FF85AB5D588 dd 3EAD9570h
dword_7FF85AB5D58C dd 0AC4E07CAh
dword_7FF85AB5D590 dd 9DE586BBh
dword_7FF85AB5D594 dd 8028DA60h
dword_7FF85AB5D598 dd 937A764Bh
dword_7FF85AB5D59C dd 7332C07Eh
dword_7FF85AB5D5A0 dd 0D9DF5203h
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC sub_7FF85A59E4D0
sub_7FF85A59E4D0:
    push r15
    push r14
    push rsi
    push rdi
    push rbp
    push rbx
    sub rsp, 0D8h
    movaps xmmword ptr [rsp+0C0h], xmm6
    mov rsi, r9
    mov rdi, rdx
    mov rax, qword ptr [__security_cookie]
    xor rax, rsp
    mov qword ptr [rsp+0B8h], rax
    mov eax, -6BF54EE9h
    add eax, dword ptr [dword_7FF85AB5D568]
    mov rbx, rcx
    mov ecx, eax
    xor ecx, -5CDEB7EDh
    sub ecx, eax
    xor eax, -15D7C6B5h
    lea edx, [rax+278B09AFh]
    add ecx, -48D0CB9Bh
    xor ecx, edx
    add ecx, eax
    add eax, ecx
    add eax, -7EC78B1Eh
    mov dword ptr [rsp+2Ch], eax
    xorps xmm6, xmm6
    lea r15, [rsp+60h]
    lea r14, [rsp+88h]
    mov ebp, 171BD219h
    jmp loc_7FF85A59E560
    loc_7FF85A59E54E:
    mov eax, -4027AC0Bh
    sub eax, dword ptr [dword_7FF85AB5D580]
    mov dword ptr [rsp+2Ch], eax
    nop dword ptr [rax]
    loc_7FF85A59E560:
    mov eax, dword ptr [rsp+2Ch]
    cmp eax, 47E69B9Dh
    jle loc_7FF85A59E620
    cmp eax, 5DFD5E34h
    jg loc_7FF85A59E6A0
    cmp eax, 53DA3C54h
    jle loc_7FF85A59E7AE
    cmp eax, 53DA3C55h
    jnz loc_7FF85A59E9AE
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
    mov qword ptr [rsp+98h], rdi
    mov eax, dword ptr [dword_7FF85AB5D57C]
    lea ecx, [rax+2B93F67Ch]
    mov edx, ecx
    xor edx, 1D53AA2h
    xor ecx, -615E58F2h
    add ecx, 6D3B0542h
    lea r8d, [rax-4BCEAFB7h]
    xor r8d, ecx
    sub r8d, eax
    add r8d, edx
    mov dword ptr [rsp+2Ch], r8d
    jmp loc_7FF85A59E560
    loc_7FF85A59E620:
    cmp eax, 2B72582Ah
    jle loc_7FF85A59E720
    cmp eax, 434A850Eh
    jle loc_7FF85A59E76B
    cmp eax, 434A850Fh
    jnz loc_7FF85A59E906
    mov eax, dword ptr [rsp+58h]
    xor eax, dword ptr [rsp+4Ch]
    sub eax, dword ptr [rsp+50h]
    xor eax, dword ptr [rsp+40h]
    add eax, dword ptr [rsp+44h]
    cmp dword ptr [rsp+38h], eax
    jle loc_7FF85A59EA7F
    mov eax, dword ptr [dword_7FF85AB5D59C]
    lea ecx, [rax-4201D6FEh]
    mov edx, ecx
    xor edx, 0BAAC58Eh
    lea r8d, [rdx+21806F48h]
    add edx, -3148FE8h
    xor edx, ecx
    xor r8d, eax
    xor r8d, edx
    xor r8d, 75575691h
    mov dword ptr [rsp+2Ch], r8d
    jmp loc_7FF85A59E560
    loc_7FF85A59E6A0:
    cmp eax, 67674E7Ch
    jle loc_7FF85A59E80A
    cmp eax, 67674E7Dh
    jnz loc_7FF85A59EA3B
    mov eax, dword ptr [rsp+54h]
    sub eax, dword ptr [rsp+48h]
    mov dword ptr [rsp+58h], eax
    mov eax, dword ptr [dword_7FF85AB5D594]
    lea ecx, [rax+6EDF1ADEh]
    lea edx, [rax+66D5EDFAh]
    mov r8d, edx
    xor r8d, -34AC076Eh
    lea r9d, [r8+67D381Ah]
    mov r10d, r9d
    xor r10d, 1EBE8885h
    xor r9d, -7471753Ch
    add r10d, 2E3E2F0Eh
    xor r10d, edx
    sub r10d, r9d
    xor r10d, eax
    add r10d, r8d
    xor r10d, ecx
    mov dword ptr [rsp+2Ch], r10d
    jmp loc_7FF85A59E560
    loc_7FF85A59E720:
    cmp eax, 89B05Dh
    jz loc_7FF85A59E54E
    cmp eax, 18D18222h
    jnz loc_7FF85A59E94E
    movups xmmword ptr [rsp+0A8h], xmm6
    mov qword ptr [rsp+88h], rbx
    mov eax, dword ptr [dword_7FF85AB5D574]
    lea ecx, [rax+8C64654h]
    lea edx, [rax+277A590Bh]
    xor edx, ecx
    xor edx, 18C5D574h
    sub edx, eax
    mov dword ptr [rsp+2Ch], edx
    jmp loc_7FF85A59E560
    loc_7FF85A59E76B:
    cmp eax, 3CC3FEA8h
    jnz loc_7FF85A59EAE1
    mov eax, dword ptr [rsp+38h]
    mov dword ptr [rsp+34h], eax
    mov eax, dword ptr [dword_7FF85AB5D584]
    mov ecx, eax
    xor ecx, -4E605608h
    lea edx, [rcx+4DC3FBBBh]
    mov r8d, -51A960C7h
    sub r8d, ecx
    xor r8d, edx
    sub r8d, ecx
    add r8d, eax
    mov dword ptr [rsp+2Ch], r8d
    jmp loc_7FF85A59E560
    loc_7FF85A59E7AE:
    cmp eax, 47E69B9Eh
    jnz loc_7FF85A59EB51
    movaps xmmword ptr [rsp+70h], xmm6
    movaps xmmword ptr [rsp+60h], xmm6
    mov qword ptr [rsp+90h], r15
    mov r8d, 148h
    mov rcx, rsi
    xor edx, edx
    call memset
    mov eax, dword ptr [rbx]
    mov dword ptr [rsi], eax
    movzx ecx, byte ptr [rbx+4]
    mov eax, 10h
    shl eax, cl
    mov byte ptr [rsp+33h], al
    mov eax, dword ptr [dword_7FF85AB5D578]
    lea ecx, [rax+0DA18DCDh]
    add eax, 5AEB50EBh
    xor eax, ecx
    mov dword ptr [rsp+2Ch], eax
    jmp loc_7FF85A59E560
    loc_7FF85A59E80A:
    cmp eax, 63596D43h
    jnz loc_7FF85A59EAEE
    mov qword ptr [rsp+20h], 5Eh
    mov ecx, 46h
    mov edx, 48h
    mov r8, r14
    mov r9, rsi
    call sub_7FF858E45D30
    mov dword ptr [rsp+38h], eax
    mov eax, dword ptr [dword_7FF85AAE40A4]
    mov dword ptr [rsp+40h], eax
    lea ecx, [rax+65B395B3h]
    mov dword ptr [rsp+44h], ecx
    lea ecx, [rax+70B2D663h]
    mov dword ptr [rsp+48h], ecx
    lea ecx, [rax+612D2249h]
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
    xor ecx, 613C8454h
    mov dword ptr [rsp+4Ch], ecx
    add ecx, -6BF54EE9h
    mov dword ptr [rsp+50h], ecx
    mov ecx, -37DF6A20h
    sub ecx, eax
    mov dword ptr [rsp+54h], ecx
    mov eax, dword ptr [dword_7FF85AB5D590]
    lea ecx, [rax+64AF198Ah]
    mov edx, ecx
    xor edx, -85B5DADh
    lea r8d, [rdx-2B08C490h]
    mov r9d, r8d
    xor r9d, 48E50C25h
    sub ecx, r9d
    sub ecx, r8d
    sub ecx, edx
    add ecx, r9d
    sub ecx, eax
    add ecx, -3DF08B71h
    mov dword ptr [rsp+2Ch], ecx
    jmp loc_7FF85A59E560
    loc_7FF85A59E906:
    mov qword ptr [rsp+0A0h], 0Fh
    mov byte ptr [rsp+0B4h], 0FFh
    mov eax, dword ptr [dword_7FF85AB5D56C]
    mov ecx, eax
    xor ecx, -53CFBEA5h
    lea edx, [rcx+219083F2h]
    mov r8d, edx
    xor r8d, 74395CC8h
    xor edx, 6FDFE53Fh
    add edx, r8d
    xor edx, ecx
    add edx, eax
    mov dword ptr [rsp+2Ch], edx
    jmp loc_7FF85A59E560
    loc_7FF85A59E94E:
    test rdi, rdi
    jz loc_7FF85A59EABC
    mov eax, dword ptr [dword_7FF85AB5D570]
    mov ecx, eax
    xor ecx, -47FF2499h
    mov edx, eax
    xor edx, -6710C875h
    mov r8d, 39DA173Ch
    sub r8d, edx
    xor r8d, eax
    lea r9d, [rdx-56B83BCBh]
    xor r9d, -47F23F2Bh
    xor r8d, -77296C3Eh
    add edx, r8d
    add edx, -56B83BCBh
    sub edx, r9d
    xor edx, eax
    xor eax, -19257670h
    sub edx, eax
    sub edx, ecx
    mov dword ptr [rsp+2Ch], edx
    jmp loc_7FF85A59E560
    loc_7FF85A59E9AE:
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
    mov eax, dword ptr [rsi+0Ch]
    mov dword ptr [rsp+5Ch], eax
    mov eax, dword ptr [dword_7FF85AB5D588]
    mov ecx, eax
    xor ecx, 2B5DCF5Bh
    lea edx, [rcx+7D6337C5h]
    xor edx, eax
    xor eax, 71CA5C65h
    lea r8d, [rcx+6AF9D43Ah]
    xor edx, -35E5601Fh
    sub edx, ecx
    sub edx, eax
    xor edx, r8d
    sub edx, ecx
    add edx, -0E789DE4h
    mov dword ptr [rsp+2Ch], edx
    jmp loc_7FF85A59E560
    loc_7FF85A59EA3B:
    movzx eax, byte ptr [rsp+33h]
    mov byte ptr [rsi+15h], al
    mov qword ptr [rsp+20h], 35h
    mov ecx, 19h
    mov edx, 1Bh
    mov r8, rsi
    mov r9, r14
    call sub_7FF85A3BE8A0
    test eax, eax
    js loc_7FF85A59EB4D
    mov eax, dword ptr [dword_7FF85AB5D58C]
    add eax, ebp
    xor eax, -5FCF4B60h
    mov dword ptr [rsp+2Ch], eax
    jmp loc_7FF85A59E560
    loc_7FF85A59EA7F:
    mov eax, dword ptr [dword_7FF85AB5D598]
    lea ecx, [rax+33A429D7h]
    mov edx, ecx
    xor edx, -397EF5C7h
    xor ecx, -221217E7h
    lea r8d, [rcx+81B9AD8h]
    add edx, -5A485FA0h
    xor edx, r8d
    xor edx, ecx
    sub edx, eax
    add edx, 319393A0h
    mov dword ptr [rsp+2Ch], edx
    jmp loc_7FF85A59E560
    loc_7FF85A59EABC:
    mov eax, dword ptr [dword_7FF85AB5D5A0]
    lea ecx, [rax+2FF641A1h]
    lea edx, [rax-1F6D2A1Ch]
    xor edx, ecx
    xor edx, -1DCB4D95h
    add edx, eax
    mov dword ptr [rsp+2Ch], edx
    jmp loc_7FF85A59E560
    loc_7FF85A59EAE1:
    mov dword ptr [rsp+3Ch], -7FEFFFFCh
    jmp loc_7FF85A59EBCB
    loc_7FF85A59EAEE:
    mov eax, dword ptr [rsp+5Ch]
    mov dword ptr [rsi+0ECh], eax
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
    mov dword ptr [rsp+34h], 100000h
    jmp loc_7FF85A59EB51
    loc_7FF85A59EB4D:
    mov dword ptr [rsp+34h], eax
    loc_7FF85A59EB51:
    mov eax, dword ptr [rsp+34h]
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
    mov dword ptr [rsp+3Ch], eax
    loc_7FF85A59EBCB:
    mov eax, dword ptr [rsp+3Ch]
    mov rcx, qword ptr [rsp+0B8h]
    xor rcx, rsp
    cmp rcx, qword ptr [__security_cookie]
    jnz loc_7FF85A59EBFB
    movaps xmm6, xmmword ptr [rsp+0C0h]
    add rsp, 0D8h
    pop rbx
    pop rbp
    pop rdi
    pop rsi
    pop r14
    pop r15
    ret
    loc_7FF85A59EBFB:
    call __security_check_cookie
_TEXT ENDS
END

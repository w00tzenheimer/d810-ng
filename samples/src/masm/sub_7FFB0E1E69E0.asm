; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: sub_7FFB0E1E69E0  @ 0x7ffb0e1e69e0
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN loc_7FFB0E1F202D:PROC
EXTERN loc_7FFB0E1F6014:PROC
EXTERN loc_7FFB0E1FC675:PROC

CONST SEGMENT
jpt_7FFB0E1E6A88 dd 0FE397B34h
dd 0FE397A98h
dd 0FE397B47h
dd 0FE397AE3h
dword_7FFB0FEDDE00 dd 8659220h
dword_7FFB0FEDDE04 dd 81E5DD72h
dword_7FFB0FEDDE08 dd 0F469A7Dh
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC sub_7FFB0E1E69E0
sub_7FFB0E1E69E0:
    push rsi
    push rdi
    push rax
    mov rax, qword ptr [rsp+48h]
    mov edx, dword ptr [dword_7FFB0FEDDE04]
    lea r9d, [rdx+370BB2B7h]
    lea r10d, [rdx-5DEFF8D7h]
    add edx, -679C3C08h
    xor r10d, edx
    xor edx, 35A884D3h
    lea r11d, [rdx+424385DFh]
    xor r11d, r10d
    xor r11d, -7C65AE64h
    add r11d, 319B65C5h
    xor edx, r9d
    xor edx, r11d
    mov dword ptr [rsp+4], edx
    dec ecx
    lea rdx, jpt_7FFB0E1E6A88
    jmp loc_7FFB0E1E6A6E
    loc_7FFB0E1E6A40:
    mov r9d, dword ptr [dword_7FFB0FEDDE00]
    lea r10d, [r9+3D79666Bh]
    lea r11d, [r9+70408ACh]
    xor r11d, r10d
    add r9d, 2891552Fh
    xor r9d, r11d
    xor r9d, 63DBFCBFh
    mov dword ptr [rsp+4], r9d
    loc_7FFB0E1E6A6E:
    mov r9d, dword ptr [rsp+4]
    cmp r9d, 6E8E902Ah
    jnz loc_7FFB0E1E6AD3
    cmp ecx, 3
    ja def_7FFB0E1E6A88
    movsxd r9, dword ptr (jpt_7FFB0E1E6A88 - 7FFB0FE4EFA8h)[rdx+rcx*4]
    add r9, rdx
    jmp r9
    loc_7FFB0E1E6A8B:
    mov r9d, r8d
    lock xadd dword ptr [rax], r9d
    mov dword ptr [rsp], r9d
    loc_7FFB0E1E6A97:
    mov r9d, dword ptr [dword_7FFB0FEDDE08]
    lea r10d, [r9-67C1101Dh]
    xor r10d, 592B8320h
    lea r11d, [r10-1F45273Dh]
    lea esi, [r10-4ADE714Ah]
    mov edi, 5B76C4E7h
    sub edi, r9d
    xor edi, r9d
    xor edi, esi
    xor edi, r11d
    add edi, r10d
    mov dword ptr [rsp+4], edi
    jmp loc_7FFB0E1E6A6E
    loc_7FFB0E1E6AD3:
    cmp r9d, 199A79B7h
    jnz loc_7FFB0E1E6AE5
    def_7FFB0E1E6A88:
    lock seto byte ptr [rax+24048990h]
    loc_7FFB0E1E6AE5:
    mov eax, dword ptr [rsp]
    add rsp, 8
    pop rdi
    pop rsi
    ret
    loc_7FFB0E1E6AEF:
    lock xadd dword ptr [rax], r8d
    nop
    nop
    nop
    nop
    nop
    pop rsi
    jb loc_7FFB0E1E6A97+3
    push 51h
    mov ebx, -1E8F8D45h
    sub edi, 5D800254h
    push rdi
    rdtsc
    jbe loc_7FFB0E1F202D+2
    mov ebx, -62CCD674h
    add dh, 0B7h
    js loc_7FFB0E1F6014
    add ebx, 3Eh
    jnz loc_7FFB0E1FC675
    sub bl, 7Fh
    add ebp, 5
    sub ch, 64h
    mov ebx, -10EF9ED3h
    add ebp, -5B79C21Ah
    loc_7FFB0E1E6B40:
    sbb bh, byte ptr [rbx-33336215h]
_TEXT ENDS
END

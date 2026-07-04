; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: sub_1815C8C30  @ 0x1815c8c30
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN sub_18010A890:PROC

CONST SEGMENT
qword_1820FB868 dq -6F17D3B815F9C620h
qword_1820FB870 dq 52F4D8FC2BDB37D0h
byte_1820FB887 db 1Dh
dword_1820FB888 dd 6C0DDC73h
dword_1820FB88C dd 0C98B8047h
off_18210A360 dq -64E2C540BC1DB16h
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC sub_1815C8C30
sub_1815C8C30:
    push r15
    push r14
    push r13
    push r12
    push rsi
    push rdi
    push rbp
    push rbx
    sub rsp, 38h
    mov rsi, -22E00FA40B9ABBA4h
    mov rax, -7CB745852DE36BEBh
    mov qword ptr [rsp+20h], rax
    lea r14, sub_18010A890
    lea r15, [rsp+2Ch]
    lea rdi, [rsp+30h]
    lea r13, [rsp+20h]
    mov rbp, 0E82C47E0AC934AEh
    nop dword ptr [rax]
    loc_1815C8C80:
    mov rax, qword ptr [off_18210A360]
    mov rcx, 64E2C558D421136h
    add rax, rcx
    mov rcx, -7CB745852DE36BEBh
    cmp qword ptr [rsp+20h], rcx
    cmovnz rax, r14
    mov r12, rdi
    cmovz r12, r15
    mov rbx, rdi
    cmovz rbx, r13
    call rax
    mov ecx, eax
    mov rdx, qword ptr [qword_1820FB868]
    mov r8, qword ptr [qword_1820FB870]
    shrd r8, rdx, 3Ch
    xor r8, rbp
    imul r8, rcx
    movzx ecx, byte ptr [byte_1820FB887]
    xor cl, 3Ch
    shr r8, cl
    mov ecx, r8d
    mov edx, dword ptr [dword_1820FB888]
    mov r8d, dword ptr [dword_1820FB88C]
    shrd r8d, edx, 1Bh
    xor r8d, -7E447186h
    imul r8d, ecx
    sub eax, r8d
    mov dword ptr [r12], eax
    mov qword ptr [rbx], rsi
    cmp rsi, qword ptr [rsp+20h]
    jnz loc_1815C8C80
    mov eax, dword ptr [rsp+2Ch]
    add rsp, 38h
    pop rbx
    pop rbp
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    ret
_TEXT ENDS
END

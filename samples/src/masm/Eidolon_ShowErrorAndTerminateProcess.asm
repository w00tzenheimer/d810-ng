; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: Eidolon_ShowErrorAndTerminateProcess  @ 0x7ff855576b50
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN GetCurrentProcess:PROC
EXTERN MessageBoxA:PROC
EXTERN TerminateProcess:PROC

CONST SEGMENT
byte_7FF8571AD970 db 0E6h
byte_7FF8571AD971 db 4Dh
byte_7FF8571AD972 db 8
dword_7FF8571AD974 dd 42CA954Dh
dword_7FF8571AD978 dd 526C45A5h
dword_7FF8571ECA44 dd 60215DDEh
dword_7FF8571ECA48 dd 4C3DA91Dh
dword_7FF8571ECA4C dd 17AC8396h
dword_7FF8571ECA50 dd 1EB6EF04h
dword_7FF8571ECA54 dd 89FC7994h
dword_7FF8571ECA58 dd 9C1BA52h
dword_7FF8571ECA5C dd 9A311B7Dh
dword_7FF8571ECA60 dd 34374BA3h
Caption db 0FFh
byte_7FF85726196A db 0FFh
byte_7FF85726196B db 0FFh
byte_7FF85726196C db 0FFh
byte_7FF85726196D db 0FFh
byte_7FF85726196E db 0FFh
byte_7FF85726196F db 0FFh
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC Eidolon_ShowErrorAndTerminateProcess
Eidolon_ShowErrorAndTerminateProcess:
    push rbp
    push r14
    push rsi
    push rdi
    push rbx
    sub rsp, 30h
    lea rbp, [rsp+30h]
    mov rdx, rcx
    mov eax, dword ptr [dword_7FF8571ECA44]
    lea ecx, [rax+42CA954Dh]
    mov r8d, ecx
    xor r8d, 60A029C0h
    lea r9d, [r8-2BD932E6h]
    add eax, -4263AFA2h
    xor eax, r9d
    sub eax, ecx
    add eax, r8d
    lea ecx, [r8-35F9B16Eh]
    add eax, r8d
    add eax, -35F9B16Eh
    add eax, r8d
    add eax, ecx
    add eax, -6F74B5F5h
    jmp loc_7FF855576BE4
    loc_7FF855576BB0:
    mov eax, dword ptr [dword_7FF8571ECA58]
    mov ecx, eax
    xor ecx, 4927437Eh
    add eax, ecx
    lea r8d, [rcx+78A8C41Fh]
    xor r8d, -2C7963F4h
    add r8d, eax
    neg r8d
    lea eax, [rcx+r8]
    add eax, 78A8C41Fh
    add eax, 55014994h
    xor eax, ecx
    loc_7FF855576BE4:
    mov dword ptr [rbp-4], eax
    loc_7FF855576BE7:
    mov eax, dword ptr [rbp-4]
    cmp eax, 1888937Dh
    jle loc_7FF855576C60
    cmp eax, 1BABC1DBh
    jle loc_7FF855576D90
    cmp eax, 1BABC1DCh
    jz loc_7FF855576BB0
    cmp eax, 3F71D85Bh
    jnz loc_7FF855576E9C
    mov eax, dword ptr [dword_7FF8571ECA48]
    lea ecx, [rax-6748B13h]
    mov r8d, ecx
    xor r8d, 7E69B8E3h
    lea r9d, [r8-3E9AB65Bh]
    lea r10d, [r8-394A5CEAh]
    xor r10d, 2AF54EAEh
    lea r11d, [r8+330AED4Ah]
    xor r11d, ecx
    sub r11d, eax
    sub r11d, r10d
    add r8d, r8d
    sub r11d, r8d
    add r11d, -41AF04ADh
    xor r11d, r9d
    mov dword ptr [rbp-4], r11d
    jmp loc_7FF855576BE7
    loc_7FF855576C60:
    cmp eax, 9477C2h
    jz loc_7FF855576C72
    cmp eax, 79323F9h
    jz loc_7FF855576E00
    loc_7FF855576C72:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    test rax, rax
    jz loc_7FF855576E35
    movzx eax, byte ptr [byte_7FF8571AD970]
    xor al, 9
    add al, 0CFh
    xor al, 0BEh
    cmp byte ptr [rdx], al
    jz loc_7FF855576E59
    mov eax, dword ptr [dword_7FF8571ECA50]
    lea ecx, [rax+4EB75175h]
    mov r8d, ecx
    xor r8d, -753C82BEh
    add r8d, 7C182B16h
    xor ecx, -62380AD1h
    add ecx, eax
    xor ecx, r8d
    add ecx, -541D388Dh
    mov dword ptr [rbp-4], ecx
    jmp loc_7FF855576BE7
    loc_7FF855576D90:
    cmp eax, 1888937Eh
    jnz loc_7FF855576FDA
    cmp byte ptr [byte_7FF85726196F], 0
    jz loc_7FF855576EA7
    mov eax, dword ptr [dword_7FF8571ECA5C]
    lea ecx, [rax-2C5583A1h]
    mov r8d, ecx
    xor r8d, -2687FCA4h
    mov r9d, ecx
    xor r9d, 21A57205h
    lea r10d, [r9-33392E16h]
    lea r11d, [r9-0AC32C3Ch]
    sub eax, r8d
    sub eax, r11d
    add eax, -60807B95h
    xor eax, r10d
    sub eax, ecx
    xor ecx, 59693C0Bh
    sub eax, ecx
    add eax, r9d
    add eax, 17A639AEh
    jmp loc_7FF855576BE4
    loc_7FF855576E00:
    mov eax, dword ptr [dword_7FF8571ECA54]
    lea ecx, [rax+539FF1DCh]
    mov r8d, ecx
    xor r8d, -253B6935h
    xor ecx, -3802AA6Bh
    add ecx, r8d
    add ecx, eax
    add ecx, eax
    add ecx, 539FF1DCh
    add eax, ecx
    add eax, 59A87B89h
    jmp loc_7FF855576BE4
    loc_7FF855576E35:
    mov eax, dword ptr [dword_7FF8571ECA4C]
    lea ecx, [rax-55F84D29h]
    add ecx, eax
    add ecx, -55F84D29h
    add ecx, eax
    neg ecx
    add eax, ecx
    add eax, -3D25BACBh
    jmp loc_7FF855576BE4
    loc_7FF855576E59:
    mov eax, dword ptr [dword_7FF8571ECA60]
    lea ecx, [rax+75442537h]
    lea r8d, [rax-596E10DFh]
    lea r9d, [rax+2657B61h]
    xor r9d, r8d
    lea r8d, [rax+4B2B7B6Fh]
    xor r8d, eax
    sub r8d, eax
    add r8d, -3AD4C1E0h
    xor r8d, r9d
    add eax, r8d
    add eax, 4A948492h
    xor eax, ecx
    jmp loc_7FF855576BE4
    loc_7FF855576E9C:
    add rsp, 30h
    pop rbx
    pop rdi
    pop rsi
    pop r14
    pop rbp
    ret
    loc_7FF855576EA7:
    movzx eax, byte ptr [byte_7FF8571AD971]
    lea ecx, [rax+71h]
    mov r9d, ecx
    not r9b
    mov r10d, r9d
    and r10b, 5Ch
    add r10b, r10b
    mov r11d, r9d
    and r11b, 0A3h
    or r9b, 0A3h
    lea r8d, [rcx+rcx]
    add r8b, r9b
    add r8b, r11b
    add r8b, r10b
    lea r10d, [r8-6Ah]
    lea r9d, [r8+52h]
    mov r11d, r9d
    not r11b
    and r11b, 16h
    movzx r11d, r11b
    lea esi, [r11+r11*4]
    lea r11d, [r11+rsi*2]
    mov ebx, r9d
    or bl, 16h
    movzx esi, bl
    lea edi, [rsi+rsi*4]
    lea esi, [rsi+rdi*2]
    mov ebx, r9d
    xor bl, 16h
    mov edi, r9d
    and dil, 0E9h
    movzx edi, dil
    lea edi, [rdi+rdi*8]
    mov r14d, r9d
    and r14b, 16h
    movzx r14d, r14b
    imul r14d, 0F5h
    sub r14b, dil
    sub r14b, bl
    add r14b, sil
    sub r14b, r11b
    add al, 3Fh
    xor al, r10b
    sub al, r8b
    add al, 0FEh
    xor al, cl
    xor al, r14b
    xor r14b, 5Fh
    sub al, r14b
    xor al, r9b
    mov byte ptr [rbp-0Ah], al
    mov byte ptr [rbp-9], 72h
    mov byte ptr [rbp-8], 72h
    mov byte ptr [rbp-7], 6Fh
    mov byte ptr [rbp-6], 72h
    movzx eax, byte ptr [byte_7FF8571AD972]
    mov ecx, eax
    xor cl, 37h
    lea r8d, [rcx+7Dh]
    mov r9d, r8d
    xor r9b, 3Eh
    mov r10d, r8d
    xor r10b, 9Ch
    sub al, r9b
    add r10b, cl
    add r10b, al
    add r10b, 0F2h
    xor r10b, r8b
    xor r10b, 6Bh
    mov byte ptr [rbp-5], r10b
    movzx eax, byte ptr [rbp-0Ah]
    mov byte ptr [Caption], al
    movzx eax, byte ptr [rbp-9]
    mov byte ptr [byte_7FF85726196A], al
    movzx eax, byte ptr [rbp-8]
    mov byte ptr [byte_7FF85726196B], al
    movzx eax, byte ptr [rbp-7]
    mov byte ptr [byte_7FF85726196C], al
    movzx eax, byte ptr [rbp-6]
    mov byte ptr [byte_7FF85726196D], al
    movzx eax, byte ptr [rbp-5]
    mov byte ptr [byte_7FF85726196E], al
    mov byte ptr [byte_7FF85726196F], 1
    loc_7FF855576FDA:
    mov r9d, 60A029C0h
    xor r9d, dword ptr [dword_7FF8571AD974]
    add r9d, -226AAC7Dh
    lea r8, Caption
    xor ecx, ecx
    call qword ptr [MessageBoxA]
    call qword ptr [GetCurrentProcess]
    mov ecx, dword ptr [dword_7FF8571AD978]
    lea r8d, [rcx+797BFD35h]
    mov r9d, r8d
    not r9d
    lea edx, [r9*8]
    sub edx, r9d
    mov r10d, r9d
    and r10d, -469C5E99h
    lea r10d, [r10+r10*8]
    and r9d, 469C5E98h
    add r9d, r9d
    lea r9d, [r9+r9*4]
    mov r11d, r8d
    and r11d, -469C5E99h
    mov esi, r11d
    not esi
    lea esi, [rsi+rsi*2]
    and r8d, 469C5E98h
    add r8d, r8d
    add r11d, r11d
    sub r11d, r8d
    add r11d, esi
    sub r11d, r9d
    sub r11d, r10d
    lea r8d, [r11+rdx]
    add r8d, 1A4BDC3Dh
    mov r9d, r11d
    add r9d, edx
    lea edx, [rcx+5ADC2B3Dh]
    xor edx, r8d
    add edx, ecx
    xor edx, r9d
    mov rcx, rax
    add rsp, 30h
    pop rbx
    pop rdi
    pop rsi
    pop r14
    pop rbp
    jmp qword ptr [TerminateProcess]
_TEXT ENDS
END

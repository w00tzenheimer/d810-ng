; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: Eidolon_RunFiberWorker13  @ 0x7ff8564adc40
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN Eidolon_CreateOneShotWaitableTimerMilliseconds:PROC
EXTERN Eidolon_QueueHandleForCurrentFiber:PROC
EXTERN Eidolon_TestAndUpdateSharedState13:PROC

CONST SEGMENT
dword_7FF8571C669C dd 36FF109Ah
dword_7FF85722BEFC dd 3EF7DCFAh
dword_7FF85722BF00 dd 9D5415C8h
dword_7FF85722BF04 dd 0F213A7AFh
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC Eidolon_RunFiberWorker13
Eidolon_RunFiberWorker13:
    push rbp
    sub rsp, 30h
    lea rbp, [rsp+30h]
    mov eax, 140E14B3h
    xor eax, dword ptr [dword_7FF85722BF00]
    lea ecx, [rax-61DA159Ch]
    xor ecx, eax
    sub ecx, eax
    add ecx, 22F7DE60h
    mov dword ptr [rbp-4], ecx
    jmp loc_7FF8564ADCB1
    loc_7FF8564ADC70:
    mov eax, dword ptr [dword_7FF85722BEFC]
    mov ecx, eax
    xor ecx, 38AB768Fh
    mov edx, eax
    xor edx, -1BE1E2B6h
    lea r8d, [rdx+9365A10h]
    mov r9d, r8d
    xor r9d, 6E875407h
    xor r8d, 0F4FDE95h
    add edx, ecx
    add edx, r8d
    sub edx, eax
    sub edx, r9d
    add edx, 76621E69h
    mov dword ptr [rbp-4], edx
    loc_7FF8564ADCB1:
    mov eax, dword ptr [rbp-4]
    cmp eax, 47C3C789h
    jz loc_7FF8564ADCC6
    cmp eax, 79792322h
    jnz loc_7FF8564ADDC0
    loc_7FF8564ADCC6:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    jz loc_7FF8564ADC70
    mov eax, dword ptr [dword_7FF85722BF04]
    lea ecx, [rax+2405999Ch]
    lea edx, [rax+68C9FFD5h]
    xor edx, ecx
    xor ecx, 6B11AF7Dh
    xor edx, eax
    add edx, ecx
    mov dword ptr [rbp-4], edx
    jmp loc_7FF8564ADCB1
    loc_7FF8564ADDC0:
    mov ecx, 32h
    mov edx, 1Ah
    mov r8d, 62h
    call Eidolon_TestAndUpdateSharedState13
    mov eax, dword ptr [dword_7FF8571C669C]
    mov ecx, eax
    not ecx
    lea edx, [rcx+rcx]
    mov r8d, ecx
    and r8d, 0EE6AB45h
    and ecx, 711954BAh
    mov r9d, eax
    and r9d, -0EE6AB46h
    lea ecx, [r9+rcx*2]
    add ecx, r8d
    sub ecx, edx
    lea edx, [rcx+rax]
    add edx, 6FC59907h
    mov eax, ecx
    xor eax, 138315B6h
    add eax, -6CBE46FDh
    xor edx, eax
    mov ecx, 3Eh
    mov r8d, 59h
    mov r9d, 27h
    call Eidolon_CreateOneShotWaitableTimerMilliseconds
    mov edx, 47h
    mov r8d, 2Bh
    mov r9d, 4Fh
    mov rcx, rax
    call Eidolon_QueueHandleForCurrentFiber
    jmp loc_7FF8564ADDC0
_TEXT ENDS
END

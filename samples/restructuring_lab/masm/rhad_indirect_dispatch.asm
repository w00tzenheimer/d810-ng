; Restructuring-lab MASM fixture: rhad_indirect_dispatch.
;
; Hypothesis: a CFF state machine whose dispatcher is a chain of 2-way COMPUTED
; branches of the form `cmovcc ptr; mov rax,[ptr]; add rax,KEY; jmp rax` (a
; cmov-selected POINTER dereference plus additive key -- NOT an indexed jump
; table). IDA's switch recogniser needs an indexed table, so it cannot resolve
; `jmp rax`: the handler blocks stay OUT of the function graph and Hex-Rays
; returns a truncated/None decompile. This is the exact shape of the real
; Rhadamanthys loader sub_40A560 (e.g. block 0x40adf2:
;   mov eax,edx / lea edi,tableA / cmovl eax,edi / mov eax,[eax] / add eax,KEY / jmp eax).
;
; An earlier indexed-table version (`mov rax,[tbl+idx*8]; add rax,KEY; jmp rax`)
; was REJECTED because IDA cracked it as a switch (the +KEY read as an elbase).
;
; Real loader is 32-bit dword[table]+key; the lab is x86_64-only (llvm-ml64), so
; this is the x64 shape analog (qword cell + additive key). C cannot emit this.
;
; Exercises Track 1 (resolve the computed jmp reg via d810's concolic / microcode
; evaluator + materialize the orphaned handlers so the CFG forms) AND Track 2
; (unflatten the ebx state machine; map_rows adapter). State consts are all
; > MIN_STATE_CONSTANT (0x01000000) so the CFF gate does not silently reject them.

OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

KEY   EQU 011223344h        ; non-zero additive key (fits sign-extended imm32)
S1    EQU 03B9ACA00h
S2    EQU 077359400h
S3    EQU 0B2D05E00h
SEND  EQU 0EE6B2800h

CONST SEGMENT READONLY ALIGN(16) 'CONST'   ; -> PE .rdata
; each dispatcher node cmov-selects between two of these cells (target - KEY);
; runtime adds KEY back to recover the real target.
c_h1  QWORD h_s1   - KEY
c_n2  QWORD n2     - KEY
c_h2  QWORD h_s2   - KEY
c_n3  QWORD n3     - KEY
c_h3  QWORD h_s3   - KEY
c_hd  QWORD h_done - KEY
CONST ENDS

_DATA SEGMENT ALIGN(16) 'DATA'             ; -> PE .data (observable side effect)
lab_rhad_sink QWORD 0
_DATA ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC lab_rhad_indirect
lab_rhad_indirect:
    push    rbx
    mov     ebx, S1                          ; initial state
; --- dispatcher: chain of 2-way computed branches on ebx ---
n1:                                          ; ebx==S1 ? h_s1 : n2
    lea     rcx, c_h1
    lea     rdx, c_n2
    cmp     ebx, S1
    cmovne  rcx, rdx
    mov     rax, QWORD PTR [rcx]             ; target - KEY
    add     rax, KEY                          ; + KEY -> real target
    jmp     rax                               ; computed goto (IDA cannot resolve)
    int     3                                 ; filler: keep targets off jmp+len (like real dispatchers)
n2:                                          ; ebx==S2 ? h_s2 : n3
    lea     rcx, c_h2
    lea     rdx, c_n3
    cmp     ebx, S2
    cmovne  rcx, rdx
    mov     rax, QWORD PTR [rcx]
    add     rax, KEY
    jmp     rax
    int     3
n3:                                          ; ebx==S3 ? h_s3 : h_done
    lea     rcx, c_h3
    lea     rdx, c_hd
    cmp     ebx, S3
    cmovne  rcx, rdx
    mov     rax, QWORD PTR [rcx]
    add     rax, KEY
    jmp     rax
    int     3
; --- handlers: do work, advance state, loop back to dispatcher head ---
h_s1:
    add     QWORD PTR [lab_rhad_sink], 011h
    mov     ebx, S2
    jmp     n1
h_s2:
    add     QWORD PTR [lab_rhad_sink], 022h
    mov     ebx, S3
    jmp     n1
h_s3:
    add     QWORD PTR [lab_rhad_sink], 033h
    mov     ebx, SEND                         ; matches nothing -> h_done
    jmp     n1
h_done:
    mov     rax, QWORD PTR [lab_rhad_sink]
    pop     rbx
    ret
_TEXT ENDS
END

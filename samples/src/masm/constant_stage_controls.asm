; Purpose-built x64 MASM acceptance fixture for the constant-simplification
; stage contract.  Each export isolates one lifecycle/operator shape.  The
; source is intentionally small and deterministic so the system test can use
; rendered pseudocode plus the typed schedule/receipt surfaces as its oracle.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

CONST SEGMENT READONLY
csc_prepare_value DD 012345678h
csc_forward_value DD 02468ACEh
CONST ENDS

CSC_CONST SEGMENT READONLY
; D810_EXPORT csc_bounded_table
PUBLIC csc_bounded_table
csc_bounded_table DQ 010h, 020h, 030h, 040h, 124 DUP(0)
PUBLIC csc_bounded_table_ptr
csc_bounded_table_ptr DQ csc_bounded_table
CSC_CONST ENDS

.data
csc_bounded_sink DQ 0
csc_readonly_value DD 013579BDFh
csc_subtree_value DD 013579BDFh

_TEXT SEGMENT ALIGN(16) 'CODE'

; The MASM build exports the source basename by convention.  Keep that primary
; object export at its own address so IDA can retain names for all eight actual
; cases exposed through explicit D810_EXPORT directives below.
PUBLIC constant_stage_controls
constant_stage_controls:
    ret

; D810_EXPORT const_prepare_without_fold
PUBLIC const_prepare_without_fold
const_prepare_without_fold:
    mov eax, DWORD PTR [csc_prepare_value]
    ret

; D810_EXPORT readonly_fold_without_prepare
PUBLIC readonly_fold_without_prepare
readonly_fold_without_prepare:
    mov eax, DWORD PTR [csc_readonly_value]
    ret

; D810_EXPORT readonly_then_subtree
PUBLIC readonly_then_subtree
readonly_then_subtree:
    mov eax, DWORD PTR [csc_subtree_value]
    rol eax, 0Dh
    xor eax, ecx
    ret

; D810_EXPORT state_rotate_rol4
PUBLIC state_rotate_rol4
state_rotate_rol4:
    mov eax, ecx
    rol eax, 0Dh
    ret

; D810_EXPORT state_rotate_ror8
PUBLIC state_rotate_ror8
state_rotate_ror8:
    mov rax, rcx
    ror rax, 11h
    ret

; D810_EXPORT forward_selected_maturity
PUBLIC forward_selected_maturity
forward_selected_maturity:
    sub rsp, 20h
    mov DWORD PTR [rsp+1Ch], 02468ACEh
    test ecx, ecx
    jz short forward_const_alt
    lea edx, DWORD PTR [ecx+1]
    jmp short forward_const_join
forward_const_alt:
    lea edx, DWORD PTR [ecx+2]
forward_const_join:
    mov eax, DWORD PTR [rsp+1Ch]
    xor eax, edx
    add rsp, 20h
    ret

; D810_EXPORT bounded_table_next_round
PUBLIC bounded_table_next_round
bounded_table_next_round:
    mov eax, ecx
    and eax, 7Fh
    test eax, eax
    jz short bounded_table_index_ready
bounded_table_index_ready:
    mov rdx, QWORD PTR [csc_bounded_table_ptr]
    mov r8, QWORD PTR [rdx+rax*8]
    mov QWORD PTR [csc_bounded_sink], r8
    mov rax, r8
    ret

; The following three functions intentionally leave a non-trivial symbolic
; value on the setcc/lnot input.  The identity
; 2 * (x & C) + (x ^ C) - x == C is exact in a 32-bit bit-vector domain, but
; deliberately remains a compare-against-constant rather than a native
; boolean.  It therefore leaves a real predicate for the bounded Z3 rules.
; D810_EXPORT bounded_setz
PUBLIC bounded_setz
bounded_setz:
    mov eax, ecx
    xor eax, 055AA55AAh
    mov edx, ecx
    and edx, 055AA55AAh
    imul edx, edx, 2
    add eax, edx
    sub eax, ecx
    cmp eax, 055AA55AAh
    setz al
    movzx eax, al
    ret

; D810_EXPORT bounded_setnz
PUBLIC bounded_setnz
bounded_setnz:
    mov eax, ecx
    xor eax, 033CC33CCh
    mov edx, ecx
    and edx, 033CC33CCh
    imul edx, edx, 2
    add eax, edx
    sub eax, ecx
    cmp eax, 033CC33CCh
    setnz al
    movzx eax, al
    ret

; D810_EXPORT bounded_lnot
PUBLIC bounded_lnot
bounded_lnot:
    mov eax, ecx
    xor eax, 00F0F3C3Ch
    mov edx, ecx
    and edx, 00F0F3C3Ch
    imul edx, edx, 2
    add eax, edx
    mov r8d, ecx
    add r8d, 00F0F3C3Ch
    cmp eax, r8d
    ; Both 32-bit expressions are x + 0F0F3C3Ch. Keep the impossible JNZ as a
    ; branch so its nested m_lnot predicate reaches z-3-lnot-generic.
    jnz short bounded_lnot_impossible
    mov eax, 1
    ret
bounded_lnot_impossible:
    xor eax, eax
    ret

_TEXT ENDS
END

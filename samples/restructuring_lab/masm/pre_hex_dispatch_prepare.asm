; Pre-Hex-Rays preparation witness.  The selected function's entry chunk jumps
; across a separate exported function into a dispatcher tail chunk.  Rewriting
; the first conditional dispatcher edge therefore proves that a preparation
; transaction is function-anchored without being entry-range-confined.

OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_DATA SEGMENT ALIGN(16) 'DATA'
PUBLIC lab_pre_hex_inherited_patch_byte
lab_pre_hex_inherited_patch_byte BYTE 05Ah
_DATA ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC lab_pre_hex_dispatch_prepare
lab_pre_hex_dispatch_prepare:
    mov     r8d, ecx
    jmp     pre_hex_dispatch

PUBLIC lab_pre_hex_spacer
lab_pre_hex_spacer:
    lea     eax, DWORD PTR [rcx+7]
    ret

pre_hex_dispatch:
    cmp     r8d, 0
    je      pre_hex_case_zero
    cmp     r8d, 1
    je      pre_hex_case_one
    mov     eax, 033h
    ret

pre_hex_case_zero:
    mov     eax, 011h
    ret

pre_hex_case_one:
    mov     eax, 022h
    ret
_TEXT ENDS
END

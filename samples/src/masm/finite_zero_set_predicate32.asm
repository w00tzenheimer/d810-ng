; Purpose-built x64 MASM fixture for finite-zero-set-predicate recovery.
; The arithmetic has two 32-bit roots. It includes the mixed-width source
; form zext((~low8(x)) & 70h), rather than a pre-normalized 32-bit term.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC finite_zero_set_predicate32
finite_zero_set_predicate32:
    mov r8d, ecx
    not r8d

    mov r9d, r8d
    imul r9d, r9d, 11

    mov r10d, r8d
    or r10d, 70h
    imul r10d, r10d, 7
    sub r9d, r10d

    mov r10d, ecx
    and r10d, 70h
    imul r10d, r10d, 6
    sub r9d, r10d

    mov r10d, r8d
    and r10d, 0FFFFFF8Fh
    imul r10d, r10d, 12h
    sub r9d, r10d

    movzx eax, cl
    not al
    and al, 70h
    movzx eax, al
    imul eax, eax, 12h
    sub r9d, eax

    test r9d, r9d
    setnz al
    movzx eax, al
    ret
_TEXT ENDS
END

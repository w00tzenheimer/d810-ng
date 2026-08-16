; Purpose-built x64 MASM fixture for modular-product-nonzero recovery.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC modular_product_nonzero32
modular_product_nonzero32:
    test ecx, ecx
    jz short modular_product_zero
    mov r8d, ecx
    not r8d
    mov r9d, 11
    imul r9d, r8d
    mov r10d, r8d
    or r10d, 70h
    imul r9d, r10d
    movzx eax, cl
    and eax, 70h
    imul r9d, eax
    mov r10d, r8d
    and r10d, 0FFFFFF8Fh
    imul r9d, r10d
    movzx eax, cl
    not al
    and eax, 70h
    imul r9d, eax
    imul r9d, r9d, 7
    imul r9d, r9d, 6
    imul r9d, r9d, 12h
    imul r9d, r9d, 12h
    test r9d, r9d
    setnz al
    movzx eax, al
    ret
modular_product_zero:
    xor eax, eax
    ret
_TEXT ENDS
END

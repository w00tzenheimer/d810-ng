; Purpose-built x64 MASM fixture for JmpRuleAffineEq.
; The two independent products force Hex-Rays to retain:
;   604 * x == 604 * x - 768
; which is always false. The target is intentionally side-effect free so the
; generic discarded-corridor guard does not veto this valid fold.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC affine_opaque_jz_false
affine_opaque_jz_false:
    mov rax, rcx
    imul rax, rax, 604
    mov rdx, rcx
    imul rdx, rdx, 604
    sub rdx, 768
    cmp rax, rdx
    jz affine_opaque_jz_false_taken
    mov eax, 1
    ret

affine_opaque_jz_false_taken:
    mov eax, 2
    ret
_TEXT ENDS
END

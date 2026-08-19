; Focused native fixture for the generalized Hodur complementary-mask MBA.
; This lives in a dedicated MASM-only image so its linker layout cannot change
; unrelated libobfuscated.dll Hex-Rays baselines.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC Hodur_ComplementMaskResidual
Hodur_ComplementMaskResidual:
    mov r10, 060657A1106CA3013h
    mov r11, 09F9A85EEF935CFECh

    mov rax, rcx
    and rax, r10
    not rax
    imul rax, rax, 4

    mov rdx, rcx
    and rdx, r10
    imul rdx, rdx, 2
    mov r8, rcx
    and r8, r11
    imul r8, r8, 3
    sub rdx, r8
    add rax, rdx

    mov rdx, rcx
    and rdx, r11
    not rdx
    imul rdx, rdx, 2
    sub rax, rdx

    mov rdx, rcx
    or rdx, r10
    not rdx
    imul rdx, rdx, 2
    sub rax, rdx

    or rcx, r11
    not rcx
    imul rcx, rcx, 3
    sub rax, rcx
    ret
_TEXT ENDS
END

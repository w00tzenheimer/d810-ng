; Narrow MurmurHash3 x64_128 inner-rotate fixture.
; Deliberately uses multiply/shift/OR rather than CPU rotate instructions so
; rotate-idiom-recovery must recognize the exact shared-base construction.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC Eidolon_ComputeTwoQwordBufferHash
Eidolon_ComputeTwoQwordBufferHash:
    ; Keep a real CFG split so Hex-Rays enters its final global-optimization
    ; maturity, where this profile's semantic-lifting stage is scheduled.
    test rcx, rcx
    jz short hash_zero

    ; c2 * ROL64(c1 * k1, 31)
    mov rax, 087C37B91114253D5h
    imul rax, rcx
    mov r8, 088A129EA80000000h       ; (c1 << 31) mod 2^64
    imul r8, rcx
    shr rax, 21h
    or rax, r8
    mov r9, 04CF5AD432745937Fh
    imul rax, r9

    ; c1 * ROL64(c2 * k2, 33)
    mov r8, 04CF5AD432745937Fh
    imul r8, rdx
    mov r10, 04E8B26FE00000000h      ; (c2 << 33) mod 2^64
    imul r10, rdx
    shr r8, 1Fh
    or r8, r10
    mov r9, 087C37B91114253D5h
    imul r8, r9
    xor rax, r8
    ret
hash_zero:
    xor eax, eax
    ret
_TEXT ENDS
END

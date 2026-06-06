; Restructuring-lab seed MASM fixture (compilable ml64 / llvm-ml64).
;
; Hypothesis: a hand-written direct two-arm branch (no compiler-inserted handoff
; blocks) gives Hex-Rays clean if/else microcode edges -- the asm path exists
; precisely to force block/edge shapes the C compiler normalizes away.
;
; Windows x64 fastcall: arg0=ecx, arg1=edx, return in eax. No data, no CRT.
; Proves the MASM half of the lab build (llvm-ml64 -> isolated DLL).
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC lab_asm_branch
lab_asm_branch:
    cmp     ecx, edx
    jle     lab_asm_branch_le
    mov     eax, ecx
    sub     eax, edx
    ret
lab_asm_branch_le:
    mov     eax, edx
    sub     eax, ecx
    ret
_TEXT ENDS
END

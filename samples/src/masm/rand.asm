; Dependency-free `rand` stub for the sub_1815C8C30 fixture (dac.dll issue #48).
;
; sub_1815C8C30's obfuscated indirect call computes `[off_18210A360] + const`,
; and that data slot is a relocation `rand - const`, so after linking the target
; folds to &rand.  This stub is that `rand`: a leaf function with NO external
; dependencies (unlike the CRT rand, which drags in security-cookie / kernel32
; imports that get /FORCE'd to __ImageBase).  It is auto-discovered + /EXPORT'd by
; the Makefile so IDA names it `rand` and d810 renders `rand()`.  The body is
; irrelevant -- the fixture is analyzed, never run.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC rand
rand:
    xor eax, eax
    ret
_TEXT ENDS
END

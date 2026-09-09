; Dependency-selected exact original v85 instructions; not whole-state equivalence.
; x=r9d (v77), y=r8d AFTER original table add2832F (v84); output eax.
; The table read and interleaved round-key work are outside this pure-value contract.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE
_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC warden_v85_value_mba
warden_v85_value_mba:
 push rsi
 mov r9d, ecx
 mov r8d, edx
 db 044h,089h,0C8h ; 0x18f5572832a mov     eax, r9d
 db 0F7h,0D0h ; 0x18f5572832d not     eax
 db 044h,08Dh,014h,080h ; 0x18f55728337 lea     r10d, [rax+rax*4]
 db 044h,089h,0C1h ; 0x18f5572833b mov     ecx, r8d
 db 009h,0C1h ; 0x18f5572833e or      ecx, eax
 db 0F7h,0D1h ; 0x18f55728340 not     ecx
 db 044h,089h,0C2h ; 0x18f55728394 mov     edx, r8d
 db 044h,009h,0CAh ; 0x18f55728397 or      edx, r9d
 db 08Dh,034h,049h ; 0x18f5572839a lea     esi, [rcx+rcx*2]
 db 0F7h,0D2h ; 0x18f5572839d not     edx
 db 045h,031h,0C1h ; 0x18f5572839f xor     r9d, r8d
 db 045h,001h,0C9h ; 0x18f557283a2 add     r9d, r9d
 db 08Dh,00Ch,092h ; 0x18f557283a5 lea     ecx, [rdx+rdx*4]
 db 044h,021h,0C0h ; 0x18f557283a8 and     eax, r8d
 db 0C1h,0E0h,003h ; 0x18f557283ab shl     eax, 3
 db 044h,029h,0C8h ; 0x18f557283b5 sub     eax, r9d
 db 001h,0C8h ; 0x18f557283c3 add     eax, ecx
 db 001h,0F0h ; 0x18f557283e1 add     eax, esi
 db 044h,029h,0D0h ; 0x18f557283e8 sub     eax, r10d
 pop rsi
 ret
_TEXT ENDS
END

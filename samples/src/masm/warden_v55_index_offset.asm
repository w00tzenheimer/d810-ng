; Genuine source arithmetic2647C..26550; EBX=masked x, EDX=contextual mask.
; MaskFF gives low-byte offset. Lookup adds original+C00 byte displacement.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE
_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC warden_v55_index_offset
warden_v55_index_offset:
    push rbx
    push rsi
    mov ebx, ecx
    db 041h,089h,0D2h ; 0x18f5572647c mov     r10d, edx
    db 041h,0F7h,0D2h ; 0x18f5572647f not     r10d
    db 041h,089h,0D9h ; 0x18f55726482 mov     r9d, ebx
    db 090h ; 0x18f55726485 nop
    db 090h ; 0x18f55726486 nop
    db 090h ; 0x18f55726487 nop
    db 090h ; 0x18f55726488 nop
    db 090h ; 0x18f55726489 nop
    db 090h ; 0x18f5572648a nop
    db 090h ; 0x18f5572648b nop
    db 090h ; 0x18f5572648c nop
    db 090h ; 0x18f5572648d nop
    db 090h ; 0x18f5572648e nop
    db 090h ; 0x18f5572648f nop
    db 090h ; 0x18f55726490 nop
    db 090h ; 0x18f55726491 nop
    db 090h ; 0x18f55726492 nop
    db 090h ; 0x18f55726493 nop
    db 090h ; 0x18f55726494 nop
    db 090h ; 0x18f55726495 nop
    db 090h ; 0x18f55726496 nop
    db 090h ; 0x18f55726497 nop
    db 090h ; 0x18f55726498 nop
    db 090h ; 0x18f55726499 nop
    db 090h ; 0x18f5572649a nop
    db 090h ; 0x18f5572649b nop
    db 090h ; 0x18f5572649c nop
    db 090h ; 0x18f5572649d nop
    db 090h ; 0x18f5572649e nop
    db 090h ; 0x18f5572649f nop
    db 090h ; 0x18f557264a0 nop
    db 090h ; 0x18f557264a1 nop
    db 090h ; 0x18f557264a2 nop
    db 090h ; 0x18f557264a3 nop
    db 090h ; 0x18f557264a4 nop
    db 090h ; 0x18f557264a5 nop
    db 090h ; 0x18f557264a6 nop
    db 090h ; 0x18f557264a7 nop
    db 090h ; 0x18f557264a8 nop
    db 090h ; 0x18f557264a9 nop
    db 090h ; 0x18f557264aa nop
    db 090h ; 0x18f557264ab nop
    db 090h ; 0x18f557264ac nop
    db 090h ; 0x18f557264ad nop
    db 090h ; 0x18f557264ae nop
    db 090h ; 0x18f557264af nop
    db 090h ; 0x18f557264b0 nop
    db 090h ; 0x18f557264b1 nop
    db 090h ; 0x18f557264b2 nop
    db 090h ; 0x18f557264b3 nop
    db 090h ; 0x18f557264b4 nop
    db 090h ; 0x18f557264b5 nop
    db 090h ; 0x18f557264b6 nop
    db 090h ; 0x18f557264b7 nop
    db 090h ; 0x18f557264b8 nop
    db 090h ; 0x18f557264b9 nop
    db 090h ; 0x18f557264ba nop
    db 090h ; 0x18f557264bb nop
    db 090h ; 0x18f557264bc nop
    db 090h ; 0x18f557264bd nop
    db 090h ; 0x18f557264be nop
    db 090h ; 0x18f557264bf nop
    db 090h ; 0x18f557264c0 nop
    db 090h ; 0x18f557264c1 nop
    db 090h ; 0x18f557264c2 nop
    db 090h ; 0x18f557264c3 nop
    db 090h ; 0x18f557264c4 nop
    db 090h ; 0x18f557264c5 nop
    db 090h ; 0x18f557264c6 nop
    db 090h ; 0x18f557264c7 nop
    db 090h ; 0x18f557264c8 nop
    db 090h ; 0x18f557264c9 nop
    db 090h ; 0x18f557264ca nop
    db 090h ; 0x18f557264cb nop
    db 090h ; 0x18f557264cc nop
    db 041h,089h,0DBh ; 0x18f557264cd mov     r11d, ebx
    db 045h,009h,0D1h ; 0x18f557264d0 or      r9d, r10d
    db 041h,009h,0D3h ; 0x18f557264d3 or      r11d, edx
    db 044h,089h,0DEh ; 0x18f557264d6 mov     esi, r11d
    db 090h ; 0x18f557264d9 nop
    db 090h ; 0x18f557264da nop
    db 090h ; 0x18f557264db nop
    db 090h ; 0x18f557264dc nop
    db 090h ; 0x18f557264dd nop
    db 090h ; 0x18f557264de nop
    db 090h ; 0x18f557264df nop
    db 090h ; 0x18f557264e0 nop
    db 090h ; 0x18f557264e1 nop
    db 090h ; 0x18f557264e2 nop
    db 090h ; 0x18f557264e3 nop
    db 090h ; 0x18f557264e4 nop
    db 090h ; 0x18f557264e5 nop
    db 090h ; 0x18f557264e6 nop
    db 090h ; 0x18f557264e7 nop
    db 090h ; 0x18f557264e8 nop
    db 090h ; 0x18f557264e9 nop
    db 090h ; 0x18f557264ea nop
    db 090h ; 0x18f557264eb nop
    db 090h ; 0x18f557264ec nop
    db 090h ; 0x18f557264ed nop
    db 090h ; 0x18f557264ee nop
    db 090h ; 0x18f557264ef nop
    db 090h ; 0x18f557264f0 nop
    db 090h ; 0x18f557264f1 nop
    db 090h ; 0x18f557264f2 nop
    db 090h ; 0x18f557264f3 nop
    db 090h ; 0x18f557264f4 nop
    db 090h ; 0x18f557264f5 nop
    db 090h ; 0x18f557264f6 nop
    db 090h ; 0x18f557264f7 nop
    db 090h ; 0x18f557264f8 nop
    db 090h ; 0x18f557264f9 nop
    db 090h ; 0x18f557264fa nop
    db 090h ; 0x18f557264fb nop
    db 090h ; 0x18f557264fc nop
    db 090h ; 0x18f557264fd nop
    db 090h ; 0x18f557264fe nop
    db 090h ; 0x18f557264ff nop
    db 090h ; 0x18f55726500 nop
    db 090h ; 0x18f55726501 nop
    db 090h ; 0x18f55726502 nop
    db 090h ; 0x18f55726503 nop
    db 090h ; 0x18f55726504 nop
    db 090h ; 0x18f55726505 nop
    db 090h ; 0x18f55726506 nop
    db 090h ; 0x18f55726507 nop
    db 090h ; 0x18f55726508 nop
    db 090h ; 0x18f55726509 nop
    db 090h ; 0x18f5572650a nop
    db 090h ; 0x18f5572650b nop
    db 090h ; 0x18f5572650c nop
    db 090h ; 0x18f5572650d nop
    db 090h ; 0x18f5572650e nop
    db 090h ; 0x18f5572650f nop
    db 090h ; 0x18f55726510 nop
    db 090h ; 0x18f55726511 nop
    db 090h ; 0x18f55726512 nop
    db 090h ; 0x18f55726513 nop
    db 090h ; 0x18f55726514 nop
    db 090h ; 0x18f55726515 nop
    db 090h ; 0x18f55726516 nop
    db 090h ; 0x18f55726517 nop
    db 090h ; 0x18f55726518 nop
    db 090h ; 0x18f55726519 nop
    db 090h ; 0x18f5572651a nop
    db 090h ; 0x18f5572651b nop
    db 090h ; 0x18f5572651c nop
    db 090h ; 0x18f5572651d nop
    db 090h ; 0x18f5572651e nop
    db 090h ; 0x18f5572651f nop
    db 090h ; 0x18f55726520 nop
    db 090h ; 0x18f55726521 nop
    db 090h ; 0x18f55726522 nop
    db 090h ; 0x18f55726523 nop
    db 090h ; 0x18f55726524 nop
    db 090h ; 0x18f55726525 nop
    db 090h ; 0x18f55726526 nop
    db 090h ; 0x18f55726527 nop
    db 090h ; 0x18f55726528 nop
    db 090h ; 0x18f55726529 nop
    db 0F7h,0D6h ; 0x18f5572652a not     esi
    db 045h,001h,0DBh ; 0x18f5572652c add     r11d, r11d
    db 047h,08Dh,01Ch,05Bh ; 0x18f5572652f lea     r11d, [r11+r11*2]
    db 041h,021h,0DAh ; 0x18f55726533 and     r10d, ebx
    db 041h,0F7h,0D1h ; 0x18f55726536 not     r9d
    db 021h,0D3h ; 0x18f55726539 and     ebx, edx
    db 08Dh,014h,09Bh ; 0x18f5572653b lea     edx, [rbx+rbx*4]
    db 042h,08Dh,014h,092h ; 0x18f5572653e lea     edx, [rdx+r10*4]
    db 001h,0F6h ; 0x18f55726542 add     esi, esi
    db 044h,029h,0DAh ; 0x18f55726544 sub     edx, r11d
    db 029h,0F2h ; 0x18f55726547 sub     edx, esi
    db 042h,08Dh,014h,08Ah ; 0x18f55726549 lea     edx, [rdx+r9*4]
    db 083h,0C2h,0FEh ; 0x18f5572654d add     edx, 0FFFFFFFEh
    mov eax, edx
    pop rsi
    pop rbx
    ret
_TEXT ENDS
END

; Genuine source instruction slice 0x18F5572660F..0x18F55726690.
; ABI wrapper only: x -> r8d, y -> ecx; return r9d. Preserve RSI.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE
_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC warden_v57_value_mba
warden_v57_value_mba:
    push rsi
    mov r8d, ecx
    mov ecx, edx
    db 044h,089h,0C2h ; 0x18f5572660f mov     edx, r8d
    db 0F7h,0D2h ; 0x18f55726612 not     edx
    db 090h ; 0x18f55726614 nop
    db 090h ; 0x18f55726615 nop
    db 090h ; 0x18f55726616 nop
    db 090h ; 0x18f55726617 nop
    db 090h ; 0x18f55726618 nop
    db 090h ; 0x18f55726619 nop
    db 090h ; 0x18f5572661a nop
    db 090h ; 0x18f5572661b nop
    db 090h ; 0x18f5572661c nop
    db 090h ; 0x18f5572661d nop
    db 090h ; 0x18f5572661e nop
    db 090h ; 0x18f5572661f nop
    db 090h ; 0x18f55726620 nop
    db 090h ; 0x18f55726621 nop
    db 090h ; 0x18f55726622 nop
    db 090h ; 0x18f55726623 nop
    db 090h ; 0x18f55726624 nop
    db 090h ; 0x18f55726625 nop
    db 090h ; 0x18f55726626 nop
    db 090h ; 0x18f55726627 nop
    db 090h ; 0x18f55726628 nop
    db 090h ; 0x18f55726629 nop
    db 090h ; 0x18f5572662a nop
    db 090h ; 0x18f5572662b nop
    db 090h ; 0x18f5572662c nop
    db 090h ; 0x18f5572662d nop
    db 090h ; 0x18f5572662e nop
    db 090h ; 0x18f5572662f nop
    db 090h ; 0x18f55726630 nop
    db 090h ; 0x18f55726631 nop
    db 090h ; 0x18f55726632 nop
    db 090h ; 0x18f55726633 nop
    db 090h ; 0x18f55726634 nop
    db 090h ; 0x18f55726635 nop
    db 090h ; 0x18f55726636 nop
    db 090h ; 0x18f55726637 nop
    db 090h ; 0x18f55726638 nop
    db 090h ; 0x18f55726639 nop
    db 090h ; 0x18f5572663a nop
    db 090h ; 0x18f5572663b nop
    db 090h ; 0x18f5572663c nop
    db 090h ; 0x18f5572663d nop
    db 090h ; 0x18f5572663e nop
    db 090h ; 0x18f5572663f nop
    db 090h ; 0x18f55726640 nop
    db 090h ; 0x18f55726641 nop
    db 090h ; 0x18f55726642 nop
    db 090h ; 0x18f55726643 nop
    db 090h ; 0x18f55726644 nop
    db 090h ; 0x18f55726645 nop
    db 090h ; 0x18f55726646 nop
    db 090h ; 0x18f55726647 nop
    db 090h ; 0x18f55726648 nop
    db 090h ; 0x18f55726649 nop
    db 090h ; 0x18f5572664a nop
    db 090h ; 0x18f5572664b nop
    db 090h ; 0x18f5572664c nop
    db 090h ; 0x18f5572664d nop
    db 090h ; 0x18f5572664e nop
    db 090h ; 0x18f5572664f nop
    db 090h ; 0x18f55726650 nop
    db 090h ; 0x18f55726651 nop
    db 090h ; 0x18f55726652 nop
    db 090h ; 0x18f55726653 nop
    db 090h ; 0x18f55726654 nop
    db 090h ; 0x18f55726655 nop
    db 090h ; 0x18f55726656 nop
    db 090h ; 0x18f55726657 nop
    db 090h ; 0x18f55726658 nop
    db 090h ; 0x18f55726659 nop
    db 090h ; 0x18f5572665a nop
    db 090h ; 0x18f5572665b nop
    db 090h ; 0x18f5572665c nop
    db 041h,089h,0CAh ; 0x18f5572665d mov     r10d, ecx
    db 041h,009h,0D2h ; 0x18f55726660 or      r10d, edx
    db 041h,089h,0C9h ; 0x18f55726663 mov     r9d, ecx
    db 041h,0F7h,0D2h ; 0x18f55726666 not     r10d
    db 045h,031h,0C1h ; 0x18f55726669 xor     r9d, r8d
    db 047h,08Dh,01Ch,089h ; 0x18f5572666c lea     r11d, [r9+r9*4]
    db 021h,0CAh ; 0x18f55726670 and     edx, ecx
    db 042h,08Dh,034h,0D5h,000h,000h,000h,000h ; 0x18f55726672 lea     esi, ds:0[r10*8]
    db 08Dh,014h,052h ; 0x18f5572667a lea     edx, [rdx+rdx*2]
    db 044h,021h,0C1h ; 0x18f5572667d and     ecx, r8d
    db 044h,08Dh,00Ch,051h ; 0x18f55726680 lea     r9d, [rcx+rdx*2]
    db 044h,029h,0D6h ; 0x18f55726684 sub     esi, r10d
    db 045h,029h,0D9h ; 0x18f55726687 sub     r9d, r11d
    db 045h,029h,0C1h ; 0x18f5572668a sub     r9d, r8d
    db 041h,001h,0F1h ; 0x18f5572668d add     r9d, esi
    mov eax, r9d
    pop rsi
    ret
_TEXT ENDS
END

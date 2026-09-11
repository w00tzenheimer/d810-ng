; Exact original mixed-width source bytes. Live-in R8 is zero-extended by source34D05.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE
_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC warden_mixed_source
warden_mixed_source:
    push rdi
    mov r8d, ecx
    db 04Ch,089h,0C0h ; 0x18f55734d13 mov     rax, r8
    db 048h,0F7h,0D0h ; 0x18f55734d16 not     rax
    db 090h ; 0x18f55734d19 nop
    db 090h ; 0x18f55734d1a nop
    db 090h ; 0x18f55734d1b nop
    db 090h ; 0x18f55734d1c nop
    db 090h ; 0x18f55734d1d nop
    db 090h ; 0x18f55734d1e nop
    db 090h ; 0x18f55734d1f nop
    db 090h ; 0x18f55734d20 nop
    db 090h ; 0x18f55734d21 nop
    db 090h ; 0x18f55734d22 nop
    db 090h ; 0x18f55734d23 nop
    db 090h ; 0x18f55734d24 nop
    db 090h ; 0x18f55734d25 nop
    db 090h ; 0x18f55734d26 nop
    db 090h ; 0x18f55734d27 nop
    db 090h ; 0x18f55734d28 nop
    db 090h ; 0x18f55734d29 nop
    db 090h ; 0x18f55734d2a nop
    db 090h ; 0x18f55734d2b nop
    db 090h ; 0x18f55734d2c nop
    db 090h ; 0x18f55734d2d nop
    db 090h ; 0x18f55734d2e nop
    db 090h ; 0x18f55734d2f nop
    db 090h ; 0x18f55734d30 nop
    db 090h ; 0x18f55734d31 nop
    db 090h ; 0x18f55734d32 nop
    db 090h ; 0x18f55734d33 nop
    db 090h ; 0x18f55734d34 nop
    db 090h ; 0x18f55734d35 nop
    db 090h ; 0x18f55734d36 nop
    db 090h ; 0x18f55734d37 nop
    db 090h ; 0x18f55734d38 nop
    db 090h ; 0x18f55734d39 nop
    db 090h ; 0x18f55734d3a nop
    db 090h ; 0x18f55734d3b nop
    db 090h ; 0x18f55734d3c nop
    db 090h ; 0x18f55734d3d nop
    db 090h ; 0x18f55734d3e nop
    db 090h ; 0x18f55734d3f nop
    db 090h ; 0x18f55734d40 nop
    db 090h ; 0x18f55734d41 nop
    db 090h ; 0x18f55734d42 nop
    db 090h ; 0x18f55734d43 nop
    db 090h ; 0x18f55734d44 nop
    db 090h ; 0x18f55734d45 nop
    db 090h ; 0x18f55734d46 nop
    db 090h ; 0x18f55734d47 nop
    db 090h ; 0x18f55734d48 nop
    db 090h ; 0x18f55734d49 nop
    db 090h ; 0x18f55734d4a nop
    db 090h ; 0x18f55734d4b nop
    db 090h ; 0x18f55734d4c nop
    db 090h ; 0x18f55734d4d nop
    db 090h ; 0x18f55734d4e nop
    db 090h ; 0x18f55734d4f nop
    db 090h ; 0x18f55734d50 nop
    db 090h ; 0x18f55734d51 nop
    db 090h ; 0x18f55734d52 nop
    db 090h ; 0x18f55734d53 nop
    db 090h ; 0x18f55734d54 nop
    db 090h ; 0x18f55734d55 nop
    db 090h ; 0x18f55734d56 nop
    db 090h ; 0x18f55734d57 nop
    db 090h ; 0x18f55734d58 nop
    db 090h ; 0x18f55734d59 nop
    db 090h ; 0x18f55734d5a nop
    db 090h ; 0x18f55734d5b nop
    db 090h ; 0x18f55734d5c nop
    db 090h ; 0x18f55734d5d nop
    db 090h ; 0x18f55734d5e nop
    db 090h ; 0x18f55734d5f nop
    db 090h ; 0x18f55734d60 nop
    db 090h ; 0x18f55734d61 nop
    db 090h ; 0x18f55734d62 nop
    db 090h ; 0x18f55734d63 nop
    db 090h ; 0x18f55734d64 nop
    db 090h ; 0x18f55734d65 nop
    db 090h ; 0x18f55734d66 nop
    db 090h ; 0x18f55734d67 nop
    db 090h ; 0x18f55734d68 nop
    db 090h ; 0x18f55734d69 nop
    db 090h ; 0x18f55734d6a nop
    db 090h ; 0x18f55734d6b nop
    db 090h ; 0x18f55734d6c nop
    db 090h ; 0x18f55734d6d nop
    db 090h ; 0x18f55734d6e nop
    db 090h ; 0x18f55734d6f nop
    db 090h ; 0x18f55734d70 nop
    db 090h ; 0x18f55734d71 nop
    db 04Ch,089h,0C2h ; 0x18f55734d72 mov     rdx, r8
    db 048h,083h,0CAh,0F3h ; 0x18f55734d75 or      rdx, 0FFFFFFFFFFFFFFF3h
    db 04Ch,08Dh,00Ch,092h ; 0x18f55734d79 lea     r9, [rdx+rdx*4]
    db 04Eh,08Dh,00Ch,04Ah ; 0x18f55734d7d lea     r9, [rdx+r9*2]
    db 048h,0F7h,0D2h ; 0x18f55734d81 not     rdx
    db 04Ch,08Dh,014h,0D5h,000h,000h,000h,000h ; 0x18f55734d84 lea     r10, ds:0[rdx*8]
    db 049h,029h,0D2h ; 0x18f55734d8c sub     r10, rdx
    db 048h,083h,0E0h,0F3h ; 0x18f55734d8f and     rax, 0FFFFFFFFFFFFFFF3h
    db 048h,089h,0C2h ; 0x18f55734d93 mov     rdx, rax
    db 048h,0C1h,0E2h,004h ; 0x18f55734d96 shl     rdx, 4
    db 048h,001h,0C2h ; 0x18f55734d9a add     rdx, rax
    db 044h,089h,0C0h ; 0x18f55734d9d mov     eax, r8d
    db 083h,0E0h,0F3h ; 0x18f55734da0 and     eax, 0FFFFFFF3h
    db 04Ch,08Dh,01Ch,040h ; 0x18f55734da3 lea     r11, [rax+rax*2]
    db 048h,0F7h,0D0h ; 0x18f55734da7 not     rax
    db 048h,001h,0C0h ; 0x18f55734daa add     rax, rax
    db 048h,08Dh,004h,040h ; 0x18f55734dad lea     rax, [rax+rax*2]
    db 090h ; 0x18f55734db1 nop
    db 090h ; 0x18f55734db2 nop
    db 090h ; 0x18f55734db3 nop
    db 090h ; 0x18f55734db4 nop
    db 090h ; 0x18f55734db5 nop
    db 090h ; 0x18f55734db6 nop
    db 090h ; 0x18f55734db7 nop
    db 090h ; 0x18f55734db8 nop
    db 090h ; 0x18f55734db9 nop
    db 090h ; 0x18f55734dba nop
    db 090h ; 0x18f55734dbb nop
    db 090h ; 0x18f55734dbc nop
    db 090h ; 0x18f55734dbd nop
    db 090h ; 0x18f55734dbe nop
    db 090h ; 0x18f55734dbf nop
    db 090h ; 0x18f55734dc0 nop
    db 090h ; 0x18f55734dc1 nop
    db 090h ; 0x18f55734dc2 nop
    db 090h ; 0x18f55734dc3 nop
    db 090h ; 0x18f55734dc4 nop
    db 090h ; 0x18f55734dc5 nop
    db 090h ; 0x18f55734dc6 nop
    db 090h ; 0x18f55734dc7 nop
    db 090h ; 0x18f55734dc8 nop
    db 090h ; 0x18f55734dc9 nop
    db 090h ; 0x18f55734dca nop
    db 090h ; 0x18f55734dcb nop
    db 090h ; 0x18f55734dcc nop
    db 090h ; 0x18f55734dcd nop
    db 090h ; 0x18f55734dce nop
    db 090h ; 0x18f55734dcf nop
    db 090h ; 0x18f55734dd0 nop
    db 090h ; 0x18f55734dd1 nop
    db 090h ; 0x18f55734dd2 nop
    db 090h ; 0x18f55734dd3 nop
    db 090h ; 0x18f55734dd4 nop
    db 090h ; 0x18f55734dd5 nop
    db 090h ; 0x18f55734dd6 nop
    db 090h ; 0x18f55734dd7 nop
    db 090h ; 0x18f55734dd8 nop
    db 090h ; 0x18f55734dd9 nop
    db 090h ; 0x18f55734dda nop
    db 090h ; 0x18f55734ddb nop
    db 090h ; 0x18f55734ddc nop
    db 090h ; 0x18f55734ddd nop
    db 090h ; 0x18f55734dde nop
    db 090h ; 0x18f55734ddf nop
    db 090h ; 0x18f55734de0 nop
    db 090h ; 0x18f55734de1 nop
    db 090h ; 0x18f55734de2 nop
    db 090h ; 0x18f55734de3 nop
    db 090h ; 0x18f55734de4 nop
    db 090h ; 0x18f55734de5 nop
    db 090h ; 0x18f55734de6 nop
    db 090h ; 0x18f55734de7 nop
    db 090h ; 0x18f55734de8 nop
    db 090h ; 0x18f55734de9 nop
    db 090h ; 0x18f55734dea nop
    db 090h ; 0x18f55734deb nop
    db 090h ; 0x18f55734dec nop
    db 090h ; 0x18f55734ded nop
    db 090h ; 0x18f55734dee nop
    db 090h ; 0x18f55734def nop
    db 090h ; 0x18f55734df0 nop
    db 090h ; 0x18f55734df1 nop
    db 090h ; 0x18f55734df2 nop
    db 090h ; 0x18f55734df3 nop
    db 090h ; 0x18f55734df4 nop
    db 090h ; 0x18f55734df5 nop
    db 090h ; 0x18f55734df6 nop
    db 090h ; 0x18f55734df7 nop
    db 090h ; 0x18f55734df8 nop
    db 090h ; 0x18f55734df9 nop
    db 090h ; 0x18f55734dfa nop
    db 090h ; 0x18f55734dfb nop
    db 090h ; 0x18f55734dfc nop
    db 090h ; 0x18f55734dfd nop
    db 090h ; 0x18f55734dfe nop
    db 090h ; 0x18f55734dff nop
    db 090h ; 0x18f55734e00 nop
    db 090h ; 0x18f55734e01 nop
    db 090h ; 0x18f55734e02 nop
    db 090h ; 0x18f55734e03 nop
    db 090h ; 0x18f55734e04 nop
    db 090h ; 0x18f55734e05 nop
    db 090h ; 0x18f55734e06 nop
    db 090h ; 0x18f55734e07 nop
    db 090h ; 0x18f55734e08 nop
    db 090h ; 0x18f55734e09 nop
    db 090h ; 0x18f55734e0a nop
    db 090h ; 0x18f55734e0b nop
    db 090h ; 0x18f55734e0c nop
    db 090h ; 0x18f55734e0d nop
    db 090h ; 0x18f55734e0e nop
    db 090h ; 0x18f55734e0f nop
    db 090h ; 0x18f55734e10 nop
    db 090h ; 0x18f55734e11 nop
    db 090h ; 0x18f55734e12 nop
    db 090h ; 0x18f55734e13 nop
    db 090h ; 0x18f55734e14 nop
    db 090h ; 0x18f55734e15 nop
    db 090h ; 0x18f55734e16 nop
    db 090h ; 0x18f55734e17 nop
    db 041h,083h,0E0h,00Ch ; 0x18f55734e18 and     r8d, 0Ch
    db 04Bh,08Dh,03Ch,0C0h ; 0x18f55734e1c lea     rdi, [r8+r8*8]
    db 04Dh,08Dh,004h,078h ; 0x18f55734e20 lea     r8, [r8+rdi*2]
    db 04Fh,08Dh,004h,098h ; 0x18f55734e24 lea     r8, [r8+r11*4]
    db 090h ; 0x18f55734e28 nop
    db 090h ; 0x18f55734e29 nop
    db 090h ; 0x18f55734e2a nop
    db 090h ; 0x18f55734e2b nop
    db 090h ; 0x18f55734e2c nop
    db 090h ; 0x18f55734e2d nop
    db 090h ; 0x18f55734e2e nop
    db 090h ; 0x18f55734e2f nop
    db 090h ; 0x18f55734e30 nop
    db 090h ; 0x18f55734e31 nop
    db 090h ; 0x18f55734e32 nop
    db 090h ; 0x18f55734e33 nop
    db 090h ; 0x18f55734e34 nop
    db 090h ; 0x18f55734e35 nop
    db 090h ; 0x18f55734e36 nop
    db 090h ; 0x18f55734e37 nop
    db 090h ; 0x18f55734e38 nop
    db 090h ; 0x18f55734e39 nop
    db 090h ; 0x18f55734e3a nop
    db 090h ; 0x18f55734e3b nop
    db 090h ; 0x18f55734e3c nop
    db 090h ; 0x18f55734e3d nop
    db 090h ; 0x18f55734e3e nop
    db 090h ; 0x18f55734e3f nop
    db 090h ; 0x18f55734e40 nop
    db 090h ; 0x18f55734e41 nop
    db 090h ; 0x18f55734e42 nop
    db 090h ; 0x18f55734e43 nop
    db 090h ; 0x18f55734e44 nop
    db 090h ; 0x18f55734e45 nop
    db 090h ; 0x18f55734e46 nop
    db 090h ; 0x18f55734e47 nop
    db 090h ; 0x18f55734e48 nop
    db 090h ; 0x18f55734e49 nop
    db 090h ; 0x18f55734e4a nop
    db 090h ; 0x18f55734e4b nop
    db 090h ; 0x18f55734e4c nop
    db 090h ; 0x18f55734e4d nop
    db 090h ; 0x18f55734e4e nop
    db 090h ; 0x18f55734e4f nop
    db 090h ; 0x18f55734e50 nop
    db 090h ; 0x18f55734e51 nop
    db 090h ; 0x18f55734e52 nop
    db 090h ; 0x18f55734e53 nop
    db 090h ; 0x18f55734e54 nop
    db 090h ; 0x18f55734e55 nop
    db 090h ; 0x18f55734e56 nop
    db 090h ; 0x18f55734e57 nop
    db 090h ; 0x18f55734e58 nop
    db 090h ; 0x18f55734e59 nop
    db 090h ; 0x18f55734e5a nop
    db 090h ; 0x18f55734e5b nop
    db 090h ; 0x18f55734e5c nop
    db 090h ; 0x18f55734e5d nop
    db 090h ; 0x18f55734e5e nop
    db 090h ; 0x18f55734e5f nop
    db 090h ; 0x18f55734e60 nop
    db 090h ; 0x18f55734e61 nop
    db 090h ; 0x18f55734e62 nop
    db 090h ; 0x18f55734e63 nop
    db 090h ; 0x18f55734e64 nop
    db 090h ; 0x18f55734e65 nop
    db 090h ; 0x18f55734e66 nop
    db 090h ; 0x18f55734e67 nop
    db 04Dh,029h,0C8h ; 0x18f55734e68 sub     r8, r9
    db 049h,029h,0C0h ; 0x18f55734e6b sub     r8, rax
    db 04Ch,001h,0D2h ; 0x18f55734e6e add     rdx, r10
    db 04Ch,001h,0C2h ; 0x18f55734e71 add     rdx, r8; length
    mov rax, rdx
    pop rdi
    ret
; D810_EXPORT warden_mixed64_negative_precondition
PUBLIC warden_mixed64_negative_precondition
warden_mixed64_negative_precondition:
    push rdi
    mov r8, rcx
    db 04Ch,089h,0C0h ; 0x18f55734d13 mov     rax, r8
    db 048h,0F7h,0D0h ; 0x18f55734d16 not     rax
    db 090h ; 0x18f55734d19 nop
    db 090h ; 0x18f55734d1a nop
    db 090h ; 0x18f55734d1b nop
    db 090h ; 0x18f55734d1c nop
    db 090h ; 0x18f55734d1d nop
    db 090h ; 0x18f55734d1e nop
    db 090h ; 0x18f55734d1f nop
    db 090h ; 0x18f55734d20 nop
    db 090h ; 0x18f55734d21 nop
    db 090h ; 0x18f55734d22 nop
    db 090h ; 0x18f55734d23 nop
    db 090h ; 0x18f55734d24 nop
    db 090h ; 0x18f55734d25 nop
    db 090h ; 0x18f55734d26 nop
    db 090h ; 0x18f55734d27 nop
    db 090h ; 0x18f55734d28 nop
    db 090h ; 0x18f55734d29 nop
    db 090h ; 0x18f55734d2a nop
    db 090h ; 0x18f55734d2b nop
    db 090h ; 0x18f55734d2c nop
    db 090h ; 0x18f55734d2d nop
    db 090h ; 0x18f55734d2e nop
    db 090h ; 0x18f55734d2f nop
    db 090h ; 0x18f55734d30 nop
    db 090h ; 0x18f55734d31 nop
    db 090h ; 0x18f55734d32 nop
    db 090h ; 0x18f55734d33 nop
    db 090h ; 0x18f55734d34 nop
    db 090h ; 0x18f55734d35 nop
    db 090h ; 0x18f55734d36 nop
    db 090h ; 0x18f55734d37 nop
    db 090h ; 0x18f55734d38 nop
    db 090h ; 0x18f55734d39 nop
    db 090h ; 0x18f55734d3a nop
    db 090h ; 0x18f55734d3b nop
    db 090h ; 0x18f55734d3c nop
    db 090h ; 0x18f55734d3d nop
    db 090h ; 0x18f55734d3e nop
    db 090h ; 0x18f55734d3f nop
    db 090h ; 0x18f55734d40 nop
    db 090h ; 0x18f55734d41 nop
    db 090h ; 0x18f55734d42 nop
    db 090h ; 0x18f55734d43 nop
    db 090h ; 0x18f55734d44 nop
    db 090h ; 0x18f55734d45 nop
    db 090h ; 0x18f55734d46 nop
    db 090h ; 0x18f55734d47 nop
    db 090h ; 0x18f55734d48 nop
    db 090h ; 0x18f55734d49 nop
    db 090h ; 0x18f55734d4a nop
    db 090h ; 0x18f55734d4b nop
    db 090h ; 0x18f55734d4c nop
    db 090h ; 0x18f55734d4d nop
    db 090h ; 0x18f55734d4e nop
    db 090h ; 0x18f55734d4f nop
    db 090h ; 0x18f55734d50 nop
    db 090h ; 0x18f55734d51 nop
    db 090h ; 0x18f55734d52 nop
    db 090h ; 0x18f55734d53 nop
    db 090h ; 0x18f55734d54 nop
    db 090h ; 0x18f55734d55 nop
    db 090h ; 0x18f55734d56 nop
    db 090h ; 0x18f55734d57 nop
    db 090h ; 0x18f55734d58 nop
    db 090h ; 0x18f55734d59 nop
    db 090h ; 0x18f55734d5a nop
    db 090h ; 0x18f55734d5b nop
    db 090h ; 0x18f55734d5c nop
    db 090h ; 0x18f55734d5d nop
    db 090h ; 0x18f55734d5e nop
    db 090h ; 0x18f55734d5f nop
    db 090h ; 0x18f55734d60 nop
    db 090h ; 0x18f55734d61 nop
    db 090h ; 0x18f55734d62 nop
    db 090h ; 0x18f55734d63 nop
    db 090h ; 0x18f55734d64 nop
    db 090h ; 0x18f55734d65 nop
    db 090h ; 0x18f55734d66 nop
    db 090h ; 0x18f55734d67 nop
    db 090h ; 0x18f55734d68 nop
    db 090h ; 0x18f55734d69 nop
    db 090h ; 0x18f55734d6a nop
    db 090h ; 0x18f55734d6b nop
    db 090h ; 0x18f55734d6c nop
    db 090h ; 0x18f55734d6d nop
    db 090h ; 0x18f55734d6e nop
    db 090h ; 0x18f55734d6f nop
    db 090h ; 0x18f55734d70 nop
    db 090h ; 0x18f55734d71 nop
    db 04Ch,089h,0C2h ; 0x18f55734d72 mov     rdx, r8
    db 048h,083h,0CAh,0F3h ; 0x18f55734d75 or      rdx, 0FFFFFFFFFFFFFFF3h
    db 04Ch,08Dh,00Ch,092h ; 0x18f55734d79 lea     r9, [rdx+rdx*4]
    db 04Eh,08Dh,00Ch,04Ah ; 0x18f55734d7d lea     r9, [rdx+r9*2]
    db 048h,0F7h,0D2h ; 0x18f55734d81 not     rdx
    db 04Ch,08Dh,014h,0D5h,000h,000h,000h,000h ; 0x18f55734d84 lea     r10, ds:0[rdx*8]
    db 049h,029h,0D2h ; 0x18f55734d8c sub     r10, rdx
    db 048h,083h,0E0h,0F3h ; 0x18f55734d8f and     rax, 0FFFFFFFFFFFFFFF3h
    db 048h,089h,0C2h ; 0x18f55734d93 mov     rdx, rax
    db 048h,0C1h,0E2h,004h ; 0x18f55734d96 shl     rdx, 4
    db 048h,001h,0C2h ; 0x18f55734d9a add     rdx, rax
    db 044h,089h,0C0h ; 0x18f55734d9d mov     eax, r8d
    db 083h,0E0h,0F3h ; 0x18f55734da0 and     eax, 0FFFFFFF3h
    db 04Ch,08Dh,01Ch,040h ; 0x18f55734da3 lea     r11, [rax+rax*2]
    db 048h,0F7h,0D0h ; 0x18f55734da7 not     rax
    db 048h,001h,0C0h ; 0x18f55734daa add     rax, rax
    db 048h,08Dh,004h,040h ; 0x18f55734dad lea     rax, [rax+rax*2]
    db 090h ; 0x18f55734db1 nop
    db 090h ; 0x18f55734db2 nop
    db 090h ; 0x18f55734db3 nop
    db 090h ; 0x18f55734db4 nop
    db 090h ; 0x18f55734db5 nop
    db 090h ; 0x18f55734db6 nop
    db 090h ; 0x18f55734db7 nop
    db 090h ; 0x18f55734db8 nop
    db 090h ; 0x18f55734db9 nop
    db 090h ; 0x18f55734dba nop
    db 090h ; 0x18f55734dbb nop
    db 090h ; 0x18f55734dbc nop
    db 090h ; 0x18f55734dbd nop
    db 090h ; 0x18f55734dbe nop
    db 090h ; 0x18f55734dbf nop
    db 090h ; 0x18f55734dc0 nop
    db 090h ; 0x18f55734dc1 nop
    db 090h ; 0x18f55734dc2 nop
    db 090h ; 0x18f55734dc3 nop
    db 090h ; 0x18f55734dc4 nop
    db 090h ; 0x18f55734dc5 nop
    db 090h ; 0x18f55734dc6 nop
    db 090h ; 0x18f55734dc7 nop
    db 090h ; 0x18f55734dc8 nop
    db 090h ; 0x18f55734dc9 nop
    db 090h ; 0x18f55734dca nop
    db 090h ; 0x18f55734dcb nop
    db 090h ; 0x18f55734dcc nop
    db 090h ; 0x18f55734dcd nop
    db 090h ; 0x18f55734dce nop
    db 090h ; 0x18f55734dcf nop
    db 090h ; 0x18f55734dd0 nop
    db 090h ; 0x18f55734dd1 nop
    db 090h ; 0x18f55734dd2 nop
    db 090h ; 0x18f55734dd3 nop
    db 090h ; 0x18f55734dd4 nop
    db 090h ; 0x18f55734dd5 nop
    db 090h ; 0x18f55734dd6 nop
    db 090h ; 0x18f55734dd7 nop
    db 090h ; 0x18f55734dd8 nop
    db 090h ; 0x18f55734dd9 nop
    db 090h ; 0x18f55734dda nop
    db 090h ; 0x18f55734ddb nop
    db 090h ; 0x18f55734ddc nop
    db 090h ; 0x18f55734ddd nop
    db 090h ; 0x18f55734dde nop
    db 090h ; 0x18f55734ddf nop
    db 090h ; 0x18f55734de0 nop
    db 090h ; 0x18f55734de1 nop
    db 090h ; 0x18f55734de2 nop
    db 090h ; 0x18f55734de3 nop
    db 090h ; 0x18f55734de4 nop
    db 090h ; 0x18f55734de5 nop
    db 090h ; 0x18f55734de6 nop
    db 090h ; 0x18f55734de7 nop
    db 090h ; 0x18f55734de8 nop
    db 090h ; 0x18f55734de9 nop
    db 090h ; 0x18f55734dea nop
    db 090h ; 0x18f55734deb nop
    db 090h ; 0x18f55734dec nop
    db 090h ; 0x18f55734ded nop
    db 090h ; 0x18f55734dee nop
    db 090h ; 0x18f55734def nop
    db 090h ; 0x18f55734df0 nop
    db 090h ; 0x18f55734df1 nop
    db 090h ; 0x18f55734df2 nop
    db 090h ; 0x18f55734df3 nop
    db 090h ; 0x18f55734df4 nop
    db 090h ; 0x18f55734df5 nop
    db 090h ; 0x18f55734df6 nop
    db 090h ; 0x18f55734df7 nop
    db 090h ; 0x18f55734df8 nop
    db 090h ; 0x18f55734df9 nop
    db 090h ; 0x18f55734dfa nop
    db 090h ; 0x18f55734dfb nop
    db 090h ; 0x18f55734dfc nop
    db 090h ; 0x18f55734dfd nop
    db 090h ; 0x18f55734dfe nop
    db 090h ; 0x18f55734dff nop
    db 090h ; 0x18f55734e00 nop
    db 090h ; 0x18f55734e01 nop
    db 090h ; 0x18f55734e02 nop
    db 090h ; 0x18f55734e03 nop
    db 090h ; 0x18f55734e04 nop
    db 090h ; 0x18f55734e05 nop
    db 090h ; 0x18f55734e06 nop
    db 090h ; 0x18f55734e07 nop
    db 090h ; 0x18f55734e08 nop
    db 090h ; 0x18f55734e09 nop
    db 090h ; 0x18f55734e0a nop
    db 090h ; 0x18f55734e0b nop
    db 090h ; 0x18f55734e0c nop
    db 090h ; 0x18f55734e0d nop
    db 090h ; 0x18f55734e0e nop
    db 090h ; 0x18f55734e0f nop
    db 090h ; 0x18f55734e10 nop
    db 090h ; 0x18f55734e11 nop
    db 090h ; 0x18f55734e12 nop
    db 090h ; 0x18f55734e13 nop
    db 090h ; 0x18f55734e14 nop
    db 090h ; 0x18f55734e15 nop
    db 090h ; 0x18f55734e16 nop
    db 090h ; 0x18f55734e17 nop
    db 041h,083h,0E0h,00Ch ; 0x18f55734e18 and     r8d, 0Ch
    db 04Bh,08Dh,03Ch,0C0h ; 0x18f55734e1c lea     rdi, [r8+r8*8]
    db 04Dh,08Dh,004h,078h ; 0x18f55734e20 lea     r8, [r8+rdi*2]
    db 04Fh,08Dh,004h,098h ; 0x18f55734e24 lea     r8, [r8+r11*4]
    db 090h ; 0x18f55734e28 nop
    db 090h ; 0x18f55734e29 nop
    db 090h ; 0x18f55734e2a nop
    db 090h ; 0x18f55734e2b nop
    db 090h ; 0x18f55734e2c nop
    db 090h ; 0x18f55734e2d nop
    db 090h ; 0x18f55734e2e nop
    db 090h ; 0x18f55734e2f nop
    db 090h ; 0x18f55734e30 nop
    db 090h ; 0x18f55734e31 nop
    db 090h ; 0x18f55734e32 nop
    db 090h ; 0x18f55734e33 nop
    db 090h ; 0x18f55734e34 nop
    db 090h ; 0x18f55734e35 nop
    db 090h ; 0x18f55734e36 nop
    db 090h ; 0x18f55734e37 nop
    db 090h ; 0x18f55734e38 nop
    db 090h ; 0x18f55734e39 nop
    db 090h ; 0x18f55734e3a nop
    db 090h ; 0x18f55734e3b nop
    db 090h ; 0x18f55734e3c nop
    db 090h ; 0x18f55734e3d nop
    db 090h ; 0x18f55734e3e nop
    db 090h ; 0x18f55734e3f nop
    db 090h ; 0x18f55734e40 nop
    db 090h ; 0x18f55734e41 nop
    db 090h ; 0x18f55734e42 nop
    db 090h ; 0x18f55734e43 nop
    db 090h ; 0x18f55734e44 nop
    db 090h ; 0x18f55734e45 nop
    db 090h ; 0x18f55734e46 nop
    db 090h ; 0x18f55734e47 nop
    db 090h ; 0x18f55734e48 nop
    db 090h ; 0x18f55734e49 nop
    db 090h ; 0x18f55734e4a nop
    db 090h ; 0x18f55734e4b nop
    db 090h ; 0x18f55734e4c nop
    db 090h ; 0x18f55734e4d nop
    db 090h ; 0x18f55734e4e nop
    db 090h ; 0x18f55734e4f nop
    db 090h ; 0x18f55734e50 nop
    db 090h ; 0x18f55734e51 nop
    db 090h ; 0x18f55734e52 nop
    db 090h ; 0x18f55734e53 nop
    db 090h ; 0x18f55734e54 nop
    db 090h ; 0x18f55734e55 nop
    db 090h ; 0x18f55734e56 nop
    db 090h ; 0x18f55734e57 nop
    db 090h ; 0x18f55734e58 nop
    db 090h ; 0x18f55734e59 nop
    db 090h ; 0x18f55734e5a nop
    db 090h ; 0x18f55734e5b nop
    db 090h ; 0x18f55734e5c nop
    db 090h ; 0x18f55734e5d nop
    db 090h ; 0x18f55734e5e nop
    db 090h ; 0x18f55734e5f nop
    db 090h ; 0x18f55734e60 nop
    db 090h ; 0x18f55734e61 nop
    db 090h ; 0x18f55734e62 nop
    db 090h ; 0x18f55734e63 nop
    db 090h ; 0x18f55734e64 nop
    db 090h ; 0x18f55734e65 nop
    db 090h ; 0x18f55734e66 nop
    db 090h ; 0x18f55734e67 nop
    db 04Dh,029h,0C8h ; 0x18f55734e68 sub     r8, r9
    db 049h,029h,0C0h ; 0x18f55734e6b sub     r8, rax
    db 04Ch,001h,0D2h ; 0x18f55734e6e add     rdx, r10
    db 04Ch,001h,0C2h ; 0x18f55734e71 add     rdx, r8; length
    mov rax, rdx
    pop rdi
    ret
_TEXT ENDS
END

; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: sub_7FF856533A20  @ 0x7ff856533a20
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE
OPTION NOSCOPED

; These values model mutable image globals from the captured function.  Keep
; them in a writable section: modern ml64/link.exe maps CONST to .rdata, which
; lets Hex-Rays fold the initial dispatcher seed and erase the fixture.
_DATA SEGMENT
dword_7FF8571C7520 dd 8D9EE5B3h
qword_7FF8571C7528 dq -3D95E0CAC2DAED5Ch
dword_7FF8571C7530 dd 0C107FF85h
dword_7FF8571C7534 dd 22749ECCh
byte_7FF8571C7538 db 54h
qword_7FF8571C7540 dq 2AC66B40788E43F6h
dword_7FF8571C7548 dd 16A3B0BFh
qword_7FF8571C7550 dq 3E628D2F9F1A0FAh
dword_7FF8571C7558 dd 2D66127Bh
dword_7FF8571C755C dd 8EB841DBh
qword_7FF8571C7560 dq 3B4645CAFC79D1EBh
dword_7FF8571C7568 dd 3BCCB145h
byte_7FF8571C756C db 5
qword_7FF8571C7570 dq 9C32F1FED91F947h
dword_7FF8571C7578 dd 275E794Fh
qword_7FF8571C7580 dq 557C03EC708E8A38h
qword_7FF8571C7588 dq 56328A507D760C9h
qword_7FF8571C7590 dq 3D939A90804FB23Bh
qword_7FF8571C7598 dq 3DC09C5BF2A19273h
qword_7FF8571C75A0 dq -757EBE5CE752ABD7h
qword_7FF8571C75A8 dq 4010924CDB580C47h
qword_7FF8571C75B0 dq -4A7259C5E15CF0C2h
qword_7FF8571C75B8 dq -7072EC5BC7E75F49h
qword_7FF8571C75C0 dq 4B042930BE238483h
qword_7FF8571C75C8 dq -4B0706013377D1DFh
qword_7FF8571C75D0 dq -4344DCA8E2A983Ch
qword_7FF8571C75D8 dq -176E541B48AAB187h
qword_7FF8571C75E0 dq -6DD12A6ACDC56406h
dword_7FF85722E300 dd 0C2E4AC12h
dword_7FF85722E304 dd 8485DCB5h
dword_7FF85722E308 dd 0A82F0880h
dword_7FF85722E30C dd 4F776100h
dword_7FF85722E310 dd 33FFA28Fh
dword_7FF85722E314 dd 0B26DD018h
dword_7FF85722E318 dd 0B66CBA1Bh
dword_7FF85722E31C dd 0C68EE796h
dword_7FF85722E320 dd 73956EABh
dword_7FF85722E324 dd 46E43F44h
dword_7FF85722E328 dd 0DE63C301h
dword_7FF85722E32C dd 5F745F4h
dword_7FF85722E330 dd 4B046DDDh
dword_7FF85722E334 dd 536925D2h
dword_7FF85722E338 dd 656C925Dh
dword_7FF85722E33C dd 7E25C866h
dword_7FF85722E340 dd 37E420D3h
dword_7FF85722E344 dd 8A76BB8Ch
dword_7FF85722E348 dd 3A7FC870h
dword_7FF85722E34C dd 0F05896A8h
dword_7FF85722E350 dd 0AB0775F1h
dword_7FF85722E354 dd 5DAE1352h
dword_7FF85722E358 dd 72A281EDh
dword_7FF85722E35C dd 0AE4464E4h
dword_7FF85722E360 dd 0A8A7F74Bh
dword_7FF85722E364 dd 23C0EC47h
dword_7FF85722E368 dd 551966EFh
dword_7FF85722E36C dd 54CDD2Bh
dword_7FF85722E370 dd 3C83AE13h
dword_7FF85722E374 dd 0E1529Ch
dword_7FF85722E378 dd 6A91091h
dword_7FF85722E37C dd 208CF572h
dword_7FF85722E380 dd 0B9638B1Ah
dword_7FF85722E384 dd 4C38D4F7h
xmmword_7FF857262FF0 db 0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh
_DATA ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
; Keep the relative table in the same section as its destinations.  Microsoft
; ml64 resolves these assembly-time differences with OPTION NOSCOPED, without
; image-relative relocations or a post-link byte patch.
; D810_EXPORT d810_relative_jpt_sub_7FF856533A20
PUBLIC d810_relative_jpt_sub_7FF856533A20
d810_relative_jpt_sub_7FF856533A20:
jpt_7FF856535804:
    dd loc_7FF856535806 - jpt_7FF856535804
    dd loc_7FF856536157 - jpt_7FF856535804
    dd loc_7FF856535E26 - jpt_7FF856535804
    dd loc_7FF856535E98 - jpt_7FF856535804
    dd loc_7FF856535BC9 - jpt_7FF856535804
    dd loc_7FF856536316 - jpt_7FF856535804
    dd loc_7FF856536898 - jpt_7FF856535804
    dd loc_7FF856536100 - jpt_7FF856535804
    dd loc_7FF856536E10 - jpt_7FF856535804
    dd loc_7FF856535BFB - jpt_7FF856535804
    dd loc_7FF856536BAE - jpt_7FF856535804
    dd loc_7FF856535BA8 - jpt_7FF856535804
    dd loc_7FF856535BED - jpt_7FF856535804
    dd loc_7FF8565364D6 - jpt_7FF856535804
    dd loc_7FF856535AC4 - jpt_7FF856535804
    dd loc_7FF856535E47 - jpt_7FF856535804
    dd loc_7FF856535A3D - jpt_7FF856535804
    dd loc_7FF8565362E7 - jpt_7FF856535804
    dd loc_7FF856536972 - jpt_7FF856535804
    dd loc_7FF856537141 - jpt_7FF856535804
    dd loc_7FF856537CB3 - jpt_7FF856535804
    dd loc_7FF85653646B - jpt_7FF856535804
    dd loc_7FF856536EA3 - jpt_7FF856535804
    dd loc_7FF856537732 - jpt_7FF856535804
    dd loc_7FF856535D0B - jpt_7FF856535804
    dd loc_7FF856535C1C - jpt_7FF856535804
    dd loc_7FF856537A65 - jpt_7FF856535804
    dd loc_7FF856535A1B - jpt_7FF856535804
    dd loc_7FF8565377B0 - jpt_7FF856535804
    dd loc_7FF8565378B5 - jpt_7FF856535804
    dd loc_7FF856536E31 - jpt_7FF856535804
    dd loc_7FF856536269 - jpt_7FF856535804
    dd loc_7FF856536E45 - jpt_7FF856535804
    dd loc_7FF856535B94 - jpt_7FF856535804
    dd loc_7FF856535A2F - jpt_7FF856535804
    dd loc_7FF856535929 - jpt_7FF856535804
    dd loc_7FF856535993 - jpt_7FF856535804
    dd loc_7FF856535908 - jpt_7FF856535804
    dd loc_7FF8565379B7 - jpt_7FF856535804
    dd loc_7FF856536EC4 - jpt_7FF856535804
    dd loc_7FF856535827 - jpt_7FF856535804
    dd loc_7FF856536308 - jpt_7FF856535804
    dd loc_7FF85653723F - jpt_7FF856535804
    dd loc_7FF8565352FE - jpt_7FF856535804
    dd loc_7FF856535A4B - jpt_7FF856535804

PUBLIC sub_7FF856533A20
sub_7FF856533A20 PROC FRAME
    push r15
    .pushreg r15
    push r14
    .pushreg r14
    push r13
    .pushreg r13
    push r12
    .pushreg r12
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    sub rsp, 148h
    .allocstack 148h
    .endprolog
    mov r13, rcx
    mov r15, -5379EA1CB64DBB60h
    mov eax, dword ptr [dword_7FF85722E310]
    mov ecx, eax
    xor ecx, 6EE21611h
    lea edx, [rcx+rcx]
    lea r8d, [rcx-6AA82EFh]
    xor r8d, -1A17421Ch
    sub edx, r8d
    mov r12, -5409039D789AF9B3h
    add edx, eax
    sub edx, ecx
    add edx, -72D30455h
    mov dword ptr [rsp+0Ch], edx
    lea rdi, jpt_7FF856535804
    mov rbp, 4301042C122F606Ah
    mov r14, 5E76CF28E3C6132Fh
    mov rax, 165DD20E288AA5C7h
    mov qword ptr [rsp+0B8h], r13
    jmp near ptr loc_7FF856533AF0
    loc_7FF856533AA9:
    mov ecx, dword ptr [dword_7FF85722E318]
    mov edx, 49D9C8C0h
    xor ecx, edx
    lea edx, [rcx+1832BABCh]
    xor edx, 117D515Ah
    lea r8d, [rdx+72E78A6Eh]
    mov r9d, r8d
    xor r9d, 0FDE1329h
    add r9d, 0D266DC1h
    xor r8d, ecx
    xor r8d, r9d
    add r8d, edx
    add ecx, r8d
    add ecx, 1832BABCh
    mov dword ptr [rsp+0Ch], ecx
    loc_7FF856533AF0:
    mov ecx, dword ptr [rsp+0Ch]
    cmp ecx, 3BEDBE32h
    jle loc_7FF856533B40
    cmp ecx, 64EF2D85h
    jle loc_7FF856533C50
    cmp ecx, 6AAEC68Ch
    jle loc_7FF856533FA7
    cmp ecx, 71FEC9DDh
    jle loc_7FF8565345A9
    cmp ecx, 71FEC9DEh
    jz loc_7FF856534A74
    cmp ecx, 7651F374h
    jnz loc_7FF856534FD0
    jmp loc_7FF856536B5F
    loc_7FF856533B40:
    cmp ecx, 20A48CDAh
    jle loc_7FF856533BE0
    cmp ecx, 2DAFE7C3h
    jg loc_7FF856533FF9
    cmp ecx, 26D8380Fh
    jle loc_7FF856534705
    cmp ecx, 26D83810h
    jz loc_7FF856534D0D
    cmp ecx, 2A36DDE6h
    jnz loc_7FF856537E4B
    mov ecx, dword ptr [rsp+50h]
    movzx edx, byte ptr [rsp+3Ch]
    mov dword ptr [rsp+0A0h], ecx
    mov byte ptr [rsp+26h], dl
    mov ecx, dword ptr [dword_7FF85722E378]
    mov edx, -22D14AFAh
    xor ecx, edx
    lea edx, [rcx-0CCDA42Eh]
    mov r8d, edx
    xor r8d, -3D9B839h
    mov r9d, edx
    xor r9d, 5E014E9Dh
    xor edx, 146BB46h
    sub edx, r8d
    add edx, r9d
    add ecx, edx
    add ecx, 35417BB7h
    mov dword ptr [rsp+0Ch], ecx
    jmp loc_7FF856533AF0
    loc_7FF856533BE0:
    cmp ecx, 107536C9h
    jg loc_7FF856533FD8
    cmp ecx, 0DED38C5h
    jg loc_7FF856534185
    cmp ecx, 0B0ED265h
    jnz loc_7FF856534C12
    mov ecx, dword ptr [rsp+4Ch]
    movzx edx, byte ptr [rsp+39h]
    mov dword ptr [rsp+94h], ecx
    mov byte ptr [rsp+25h], dl
    mov ecx, dword ptr [dword_7FF85722E364]
    mov edx, 7393A4C8h
    add ecx, edx
    mov edx, ecx
    xor edx, 0CF85ED2h
    xor ecx, -6467C132h
    add ecx, edx
    add ecx, -781FC81Eh
    mov dword ptr [rsp+0Ch], ecx
    jmp loc_7FF856533AF0
    loc_7FF856533C50:
    cmp ecx, 4A07738Fh
    jg loc_7FF85653401A
    cmp ecx, 41C1BAEFh
    jg loc_7FF856534682
    cmp ecx, 3BEDBE33h
    jnz loc_7FF856537331
    mov ecx, dword ptr [rsp+50h]
    mov dword ptr [rsp+0A4h], ecx
    loc_7FF856533C7F:
    mov rcx, qword ptr [qword_7FF8571C7550]
    mov rdx, -0E5DEC32290965DEh
    add rcx, rdx
    mov rdx, rcx
    mov r11, -4A8C2FF7A81AF542h
    or rdx, r11
    lea r8, [rdx+rdx*4]
    lea r8, [rdx+r8*2]
    not rdx
    lea r9, [rdx*8]
    sub r9, rdx
    mov r10, rcx
    mov rsi, 4A8C2FF7A81AF541h
    or r10, rsi
    not r10
    mov rdx, r10
    shl rdx, 4
    add rdx, r10
    mov r10, rcx
    and r10, r11
    mov r11, rcx
    and r11, rsi
    lea rsi, [r11+r11*8]
    lea r11, [r11+rsi*2]
    lea rsi, [r10+r10*2]
    lea r11, [r11+rsi*4]
    sub r11, r8
    not r10
    add r10, r10
    lea r8, [r10+r10*2]
    sub r11, r8
    add rdx, r9
    add rdx, r11
    mov r8, -484B16AFAE5CDF0Ch
    lea r9, [rdx+r8]
    mov r8, r9
    mov rsi, 6DED88F5063CAEC1h
    and r8, rsi
    mov r10, r9
    mov r11, -6DED88F5063CAEC2h
    and r10, r11
    sub r10, r8
    mov r8, r9
    xor r8, r11
    lea r8, [r8+r8*2]
    add r10, r8
    add rdx, rcx
    mov rcx, r9
    add rdx, r9
    or r9, rsi
    or rcx, r11
    not rcx
    sub r10, r9
    add r10, rcx
    not r9
    shl r9, 2
    sub r10, r9
    add rdx, r10
    mov rcx, 28D4BE759931BC20h
    sub rcx, rdx
    mov edx, dword ptr [rsp+0A4h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov dword ptr [rsp+0A8h], edx
    xor rcx, qword ptr [rsp+10h]
    jmp loc_7FF8565376A8
    loc_7FF856533FA7:
    cmp ecx, 686E6C3Ch
    jg loc_7FF856534163
    cmp ecx, 64EF2D86h
    jnz loc_7FF856534631
    nop
    loc_7FF856533FC0:
    mov ecx, dword ptr [rsp+78h]
    mov rdx, qword ptr [rsp+0E0h]
    xor rdx, r14
    mov dword ptr [rsp+8], ecx
    jmp loc_7FF856537A20
    loc_7FF856533FD8:
    cmp ecx, 1AEA4347h
    jg loc_7FF85653457F
    cmp ecx, 107536CAh
    jnz loc_7FF856534C33
    mov ecx, dword ptr [rsp+60h]
    jmp loc_7FF856534A78
    loc_7FF856533FF9:
    cmp ecx, 34D3F3AAh
    jg loc_7FF8565345FE
    cmp ecx, 2DAFE7C4h
    jnz loc_7FF856536A25
    mov ecx, dword ptr [rsp+44h]
    jmp loc_7FF856534FA1
    loc_7FF85653401A:
    cmp ecx, 5AF1E859h
    jg loc_7FF8565346CA
    cmp ecx, 4A077390h
    jz loc_7FF856534AA7
    movzx ecx, byte ptr [byte_7FF8571C7538]
    lea edx, [rcx+3Ah]
    mov r8d, edx
    not r8b
    and r8b, 9Bh
    movzx r8d, r8b
    lea r9d, [r8+r8*4]
    lea r8d, [r8+r9*2]
    mov r9d, edx
    or r9b, 9Bh
    movzx r9d, r9b
    lea r10d, [r9+r9*4]
    lea r10d, [r9+r10*2]
    mov r11d, edx
    xor r11b, 9Bh
    mov r9d, edx
    and r9b, 64h
    movzx r9d, r9b
    lea esi, [r9+r9*8]
    and dl, 9Bh
    movzx edx, dl
    imul r9d, edx, 0F5h
    sub r9b, sil
    sub r9b, r11b
    add r9b, r10b
    sub r9b, r8b
    lea r8d, [r9+1Ch]
    mov r10d, r8d
    or r10b, 80h
    mov edx, r8d
    and dl, 80h
    movzx edx, dl
    lea edx, [rdx+rdx*2]
    add dl, r10b
    mov r10d, edx
    xor r10b, 12h
    lea r11d, [r10+2Bh]
    xor dl, cl
    xor dl, r8b
    xor dl, r11b
    xor dl, 8
    mov ecx, r9d
    not cl
    mov r8d, edx
    or r8b, cl
    not r8b
    shl r8b, 2
    mov ebx, edx
    or bl, r9b
    add bl, bl
    mov esi, edx
    xor sil, r9b
    and cl, dl
    shl cl, 2
    and dl, r9b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add dl, dl
    add dl, cl
    sub dl, sil
    sub dl, bl
    add dl, r8b
    xor dl, r10b
    add dl, r11b
    add dl, byte ptr [rsp+3Bh]
    add dl, 0BFh
    mov byte ptr [rsp+3Ch], dl
    cmp dl, byte ptr [rsp+3Ah]
    jnz loc_7FF85653524B
    mov ecx, dword ptr [dword_7FF85722E380]
    mov edx, -7D75CCE7h
    add ecx, edx
    mov dword ptr [rsp+0Ch], ecx
    jmp loc_7FF856533AF0
    loc_7FF856534163:
    cmp ecx, 686E6C3Dh
    jnz loc_7FF856534C09
    mov ecx, dword ptr [rsp+54h]
    movzx edx, byte ptr [rsp+3Fh]
    mov dword ptr [rsp+0ACh], ecx
    mov byte ptr [rsp+27h], dl
    jmp loc_7FF8565341A1
    loc_7FF856534185:
    cmp ecx, 0DED38C6h
    jnz loc_7FF856537A25
    mov ecx, dword ptr [rsp+68h]
    mov dword ptr [rsp+0ACh], ecx
    mov byte ptr [rsp+27h], 0
    loc_7FF8565341A1:
    movzx edx, byte ptr [rsp+27h]
    mov ecx, dword ptr [rsp+0ACh]
    mov byte ptr [rsp+3Eh], dl
    mov r9, qword ptr [rsp+28h]
    mov r8, qword ptr [qword_7FF8571C7528]
    mov rdx, -3F14838278EC2C8Bh
    add r8, rdx
    mov r10, r8
    mov rdx, r8
    mov rsi, -7424F7A3FF7F2562h
    and rdx, rsi
    lea rdx, [rdx+rdx*2]
    mov r11, r8
    mov rbx, 7424F7A3FF7F2561h
    and r11, rbx
    sub rdx, r11
    add rdx, r8
    or r8, rsi
    or r10, rbx
    not r10
    lea r10, [r10+r10*2]
    add r10, r8
    add rdx, r10
    mov r8, 779AA0A802349611h
    add r8, rdx
    mov r10, -248969252554F5B1h
    add r10, rdx
    mov r11, r10
    sub r11, r8
    not rdx
    mov rsi, 62D11CB55DE2CF45h
    add rdx, rsi
    add rdx, r11
    mov r11, rdx
    or r11, r8
    not r11
    lea r11, [r11+r11*2]
    mov rsi, r8
    not rsi
    mov rbx, rdx
    or rbx, rsi
    add rbx, rbx
    lea rbx, [rbx+rbx*2]
    mov r14, rdx
    xor r14, r8
    and rsi, rdx
    lea rsi, [rsi+rsi*2]
    add rsi, rsi
    and rdx, r8
    lea rdx, [rdx+rdx*2]
    lea rdx, [rsi+rdx*2]
    add rdx, r14
    sub rdx, rbx
    lea rdx, [rdx+r11*2]
    sub rdx, r10
    xor rdx, qword ptr [r9+rcx]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9d, dword ptr [dword_7FF8571C7530]
    mov r10d, r9d
    xor r10d, 0C1C2E42h
    mov esi, r9d
    xor esi, 2043D125h
    mov r11d, r9d
    xor r11d, 13A00098h
    and r11d, 1BBC08D8h
    and esi, 2443F727h
    shl esi, 2
    mov r8d, r9d
    xor r8d, 57A0269Ah
    mov ebx, r10d
    and ebx, 443F727h
    shl ebx, 3
    mov ebp, r10d
    and ebp, 5BBC08D8h
    add ebp, ebp
    sub ebx, ebp
    lea ebp, [r8*8]
    sub r8d, ebp
    mov r14d, r9d
    xor r14d, 285FD965h
    add r8d, ebx
    lea r8d, [r8+r14*4]
    sub r8d, esi
    lea r11d, [r8+r11*8]
    mov r8d, r11d
    not r8d
    lea esi, [r8+r8*2]
    mov ebx, r8d
    or ebx, -59E2FACCh
    mov r14d, r8d
    and r14d, 59E2FACBh
    lea ebp, [r14+r14*2]
    add ebp, ebx
    and r8d, -59E2FACCh
    lea r8d, [r8+r8*2]
    mov ebx, r11d
    and ebx, -59E2FACCh
    sub r8d, ebx
    add r8d, ebp
    sub r8d, esi
    add r8d, -59E2FACBh
    xor r8d, r10d
    sub r8d, r9d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8d, r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8d, ecx
    add r8d, -182ED664h
    mov r9, qword ptr [rsp+28h]
    mov r9d, dword ptr [r9+r8]
    add ecx, 0Ch
    mov dword ptr [rsp+54h], ecx
    mov rcx, qword ptr [rsp+140h]
    cmp rcx, rdx
    jb loc_7FF856534BC4
    add rdx, r9
    cmp rcx, rdx
    jnb loc_7FF856534BC4
    mov rcx, qword ptr [rsp+10h]
    mov edx, dword ptr [rsp+54h]
    mov dword ptr [rsp+0B4h], edx
    mov qword ptr [rsp+108h], rcx
    mov rbp, 4301042C122F606Ah
    mov r14, 5E76CF28E3C6132Fh
    jmp loc_7FF856534C66
    loc_7FF85653457F:
    cmp ecx, 1AEA4348h
    jnz loc_7FF856534CB9
    movzx ecx, byte ptr [rsp+3Eh]
    inc cl
    mov byte ptr [rsp+3Fh], cl
    cmp cl, byte ptr [rsp+3Dh]
    jnz loc_7FF856535219
    mov ecx, dword ptr [rsp+54h]
    jmp loc_7FF856534C37
    loc_7FF8565345A9:
    cmp ecx, 6AAEC68Dh
    jnz loc_7FF856534D20
    mov rcx, qword ptr [xmmword_7FF857262FF0]
    mov qword ptr [rsp+28h], rcx
    mov rdx, qword ptr [xmmword_7FF857262FF0+8]
    sub rdx, rcx
    mov qword ptr [rsp+110h], rdx
    jz loc_7FF856537E43
    mov ecx, dword ptr [dword_7FF85722E320]
    lea edx, [rcx-3CB65904h]
    xor edx, 3970D74Eh
    sub edx, ecx
    sub edx, ecx
    add edx, -1D301EC9h
    mov dword ptr [rsp+0Ch], edx
    jmp loc_7FF856533AF0
    loc_7FF8565345FE:
    cmp ecx, 34D3F3ABh
    jnz loc_7FF856534F9D
    mov rcx, qword ptr [rsp+188h]
    movsxd rdx, dword ptr [rcx-4]
    add rdx, rcx
    mov qword ptr [rsp+128h], rdx
    mov ecx, dword ptr [rsp+60h]
    mov dword ptr [rsp+88h], ecx
    mov byte ptr [rsp+24h], 0
    loc_7FF856534631:
    movzx ecx, byte ptr [rsp+24h]
    mov edx, dword ptr [rsp+88h]
    mov byte ptr [rsp+36h], cl
    mov rcx, qword ptr [rsp+28h]
    mov rcx, qword ptr [rcx+rdx]
    mov r8, 5379EA1CB64DBB5Fh
    xor rcx, r8
    add edx, 8
    mov dword ptr [rsp+48h], edx
    cmp qword ptr [rsp+128h], rcx
    jz loc_7FF8565350AE
    mov ecx, dword ptr [dword_7FF85722E358]
    mov edx, 3AC22161h
    xor ecx, edx
    mov dword ptr [rsp+0Ch], ecx
    jmp loc_7FF856533AF0
    loc_7FF856534682:
    cmp ecx, 41C1BAF0h
    jz loc_7FF8565347D3
    movzx ecx, byte ptr [rsp+36h]
    inc cl
    mov byte ptr [rsp+37h], cl
    cmp cl, byte ptr [rsp+35h]
    jnz loc_7FF8565352A7
    mov ecx, dword ptr [dword_7FF85722E35C]
    mov edx, ecx
    xor edx, -5FE9236Fh
    mov r8d, -23C4D1FEh
    sub r8d, edx
    xor r8d, ecx
    add r8d, edx
    mov dword ptr [rsp+0Ch], r8d
    jmp loc_7FF856533AF0
    loc_7FF8565346CA:
    cmp ecx, 5AF1E85Ah
    jnz loc_7FF856534FF5
    mov ecx, dword ptr [rsp+40h]
    loc_7FF8565346DA:
    mov dword ptr [rsp+74h], ecx
    mov ecx, dword ptr [rsp+74h]
    mov rdx, qword ptr [rsp+10h]
    mov r8, 27F31DC5B8200547h
    xor rdx, r8
    mov dword ptr [rsp+78h], ecx
    mov qword ptr [rsp+0E0h], rdx
    jmp loc_7FF856533FC0
    loc_7FF856534705:
    cmp ecx, 20A48CDBh
    jnz loc_7FF85653505D
    mov rcx, qword ptr [rsp+188h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movsxd rdx, dword ptr [rcx-4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rdx, rcx
    mov qword ptr [rsp+118h], rdx
    mov ecx, dword ptr [rsp+58h]
    mov dword ptr [rsp+70h], ecx
    mov byte ptr [rsp+22h], 0
    loc_7FF8565347D3:
    movzx ecx, byte ptr [rsp+22h]
    mov edx, dword ptr [rsp+70h]
    mov r9, qword ptr [rsp+28h]
    mov r9, qword ptr [r9+rdx]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r10, r9
    mov r8, 5379EA1CB64DBB5Fh
    or r10, r8
    not r10
    lea r10, [r10+r10*2]
    mov r11, r9
    or r11, r15
    add r11, r11
    lea r11, [r11+r11*2]
    mov rsi, r9
    xor rsi, r8
    mov rbx, r9
    and rbx, r15
    lea rbx, [rbx+rbx*2]
    add rbx, rbx
    and r9, r8
    lea r9, [r9+r9*2]
    lea r9, [rbx+r9*2]
    add r9, rsi
    sub r9, r11
    lea r9, [r9+r10*2]
    add edx, 8
    mov dword ptr [rsp+40h], edx
    cmp qword ptr [rsp+118h], r9
    jz loc_7FF856535160
    mov edx, ecx
    not dl
    movzx r8d, dl
    lea edx, [r8+r8*2]
    mov r9d, r8d
    and r9b, 1
    movzx r9d, r9b
    lea r9d, [r9+r9*2]
    and r8b, 0FEh
    movzx r8d, r8b
    lea r8d, [r8+r8*2]
    mov r10d, ecx
    xor r10b, 1
    movzx r11d, r10b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r10d, [r11*8]
    sub r10d, r11d
    mov r11d, ecx
    and r11b, 7Eh
    movzx r11d, r11b
    add r11d, r11d
    lea r11d, [r11+r11*2]
    and cl, 1
    add cl, cl
    sub cl, r11b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r10b, r8b
    add r10b, cl
    sub r10b, r9b
    sub r10b, dl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp r10b, byte ptr [rsp+32h]
    jnz loc_7FF8565351BE
    mov ecx, dword ptr [dword_7FF85722E300]
    lea edx, [rcx+7C89AE8Ch]
    lea r8d, 0FFFFFFFF80E81012h[rcx*2]
    xor r8d, edx
    sub r8d, ecx
    add r8d, -1C089E3Ch
    mov dword ptr [rsp+0Ch], r8d
    jmp loc_7FF856533AF0
    loc_7FF856534A74:
    mov ecx, dword ptr [rsp+48h]
    loc_7FF856534A78:
    mov dword ptr [rsp+8Ch], ecx
    mov ecx, dword ptr [rsp+8Ch]
    mov rdx, qword ptr [rsp+10h]
    mov r8, 71A7EB2DF7C173A2h
    xor rdx, r8
    mov dword ptr [rsp+90h], ecx
    mov qword ptr [rsp+0F0h], rdx
    loc_7FF856534AA7:
    mov rcx, qword ptr [qword_7FF8571C7560]
    mov rdx, -519CA3B3565B4776h
    xor rcx, rdx
    mov rdx, 39DB0370F0AB2F76h
    add rdx, rcx
    add rcx, rcx
    add rcx, rdx
    mov r8, -4749436377513F6Ch
    xor rdx, r8
    mov r8, rdx
    or r8, r12
    lea r9, [r8+r8*4]
    lea r9, [r8+r9*2]
    not r8
    lea r10, [r8+r8*4]
    lea r8, [r8+r10*2]
    mov r10, rdx
    and r10, r12
    lea r11, [r10+r10*8]
    not r10
    lea rsi, [r10+r10*4]
    lea r10, [r10+rsi*2]
    mov rsi, rdx
    mov r14, 5409039D789AF9B2h
    and rsi, r14
    lea rbx, [rsi+rsi*4]
    lea rsi, [rsi+rbx*4]
    add rsi, r11
    sub r9, rsi
    add r9, r10
    sub r9, r8
    add r9, rdx
    or rdx, r14
    mov r14, 5E76CF28E3C6132Fh
    not rdx
    lea r8, [rdx+rdx*4]
    lea rdx, [rdx+r8*4]
    sub rdx, r9
    mov r8, 684128237C616A9h
    add rcx, r8
    add rcx, rdx
    xor rcx, qword ptr [rsp+0F0h]
    mov edx, dword ptr [rsp+90h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov dword ptr [rsp+8], edx
    mov qword ptr [rsp+18h], rcx
    jmp loc_7FF856537A25
    loc_7FF856534BC4:
    mov ecx, dword ptr [dword_7FF85722E314]
    mov edx, ecx
    mov r8d, ecx
    xor r8d, 552940ADh
    lea r9d, [r8+7DB66F46h]
    xor r9d, ecx
    xor ecx, -23C57F47h
    xor edx, 79080349h
    sub r9d, ecx
    add r8d, edx
    add r8d, r9d
    mov dword ptr [rsp+0Ch], r8d
    loc_7FF856534BFA:
    mov rbp, 4301042C122F606Ah
    jmp loc_7FF856535151
    loc_7FF856534C09:
    mov ecx, dword ptr [rsp+64h]
    jmp loc_7FF856536B30
    loc_7FF856534C12:
    mov qword ptr [rsp+0C8h], 0
    mov qword ptr [rsp+0D0h], r13
    mov dword ptr [rsp+6Ch], 0
    jmp loc_7FF85653575A
    loc_7FF856534C33:
    mov ecx, dword ptr [rsp+68h]
    loc_7FF856534C37:
    mov dword ptr [rsp+0B0h], ecx
    mov ecx, dword ptr [rsp+0B0h]
    mov rdx, qword ptr [rsp+10h]
    mov r8, -3BA07BE5E4AF6847h
    xor rdx, r8
    mov dword ptr [rsp+0B4h], ecx
    mov qword ptr [rsp+108h], rdx
    loc_7FF856534C66:
    mov rcx, qword ptr [rsp+108h]
    mov edx, dword ptr [rsp+0B4h]
    mov r8, rcx
    mov r11, 4922B7D69DAF4324h
    or r8, r11
    lea r9, [r8+r8*2]
    not r8
    lea r10, [r8*8]
    sub r10, r8
    and rcx, r11
    lea rcx, [rcx+r9*2]
    add rcx, r10
    mov r8, -7
    sub r8, rcx
    mov dword ptr [rsp+8], edx
    mov qword ptr [rsp+18h], r8
    jmp loc_7FF856537A25
    loc_7FF856534CB9:
    mov rcx, qword ptr [rsp+10h]
    mov edx, dword ptr [rsp+40h]
    mov dword ptr [rsp+78h], edx
    mov qword ptr [rsp+0E0h], rcx
    mov ecx, dword ptr [dword_7FF85722E334]
    lea edx, [rcx+0B6E7C03h]
    xor edx, 291BBC4Ch
    lea r8d, 7789C3D2h[rdx*2]
    add r8d, ecx
    add edx, r8d
    add edx, 7789C3D2h
    add edx, ecx
    add edx, 6ADFD406h
    add ecx, -46A3F833h
    xor edx, ecx
    mov dword ptr [rsp+0Ch], edx
    jmp loc_7FF856533AF0
    loc_7FF856534D0D:
    mov ecx, dword ptr [rsp+44h]
    movzx edx, byte ptr [rsp+34h]
    mov dword ptr [rsp+7Ch], ecx
    mov byte ptr [rsp+23h], dl
    jmp loc_7FF856534D44
    loc_7FF856534D20:
    mov rcx, qword ptr [rsp+188h]
    movsxd rdx, dword ptr [rcx-4]
    add rdx, rcx
    mov qword ptr [rsp+120h], rdx
    mov ecx, dword ptr [rsp+5Ch]
    mov dword ptr [rsp+7Ch], ecx
    mov byte ptr [rsp+23h], 0
    loc_7FF856534D44:
    movzx ecx, byte ptr [rsp+23h]
    mov edx, dword ptr [rsp+7Ch]
    mov r8, qword ptr [rsp+28h]
    mov r10, qword ptr [qword_7FF8571C7570]
    mov r11, r10
    mov r9, 2BA30EACCB73F633h
    xor r11, r9
    mov r9, 793D725DA5C0EF7Dh
    add r11, r9
    mov r9, r10
    mov rsi, -2417FE0C16773A52h
    xor r9, rsi
    xor r9, r11
    add r9, r10
    xor r9, qword ptr [r8+rdx]
    mov r10d, dword ptr [dword_7FF8571C7578]
    lea esi, [r10+36E824BCh]
    mov ebx, esi
    not ebx
    mov r8d, ebx
    and r8d, -6C250B9h
    lea r11d, [r8+r8*8]
    add r11d, ebx
    mov r8d, ebx
    and r8d, 6C250B8h
    lea r8d, [r8+r8*4]
    mov ebx, esi
    and ebx, 6C250B8h
    and esi, -6C250B9h
    lea r14d, [rsi+rsi*4]
    lea esi, [rsi+r14*2]
    add esi, ebx
    not ebx
    lea r14d, [rbx+rbx*4]
    lea ebx, [rbx+r14*2]
    sub esi, ebx
    lea r8d, [rsi+r8*2]
    add r11d, r8d
    lea r8d, [r10+2C7507D7h]
    xor r8d, r11d
    add r8d, r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8d, r10d
    add r8d, 7A679D88h
    mov r10d, r8d
    not r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11d, edx
    or r11d, r10d
    or r8d, edx
    not r8d
    shl r8d, 2
    and edx, r10d
    mov esi, edx
    not esi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add esi, esi
    sub esi, edx
    sub esi, r8d
    add esi, r11d
    lea edx, [rsi+r10*2]
    inc edx
    mov dword ptr [rsp+44h], edx
    cmp qword ptr [rsp+120h], r9
    jz loc_7FF856535117
    inc cl
    mov byte ptr [rsp+34h], cl
    cmp cl, byte ptr [rsp+33h]
    mov r14, 5E76CF28E3C6132Fh
    jnz loc_7FF85653518A
    mov ecx, dword ptr [dword_7FF85722E344]
    lea edx, [rcx+0B0080E0h]
    lea r8d, [rcx-5182B3C5h]
    mov r9d, r8d
    xor r9d, 47DDAA3Fh
    lea r10d, [rcx+99EA28h]
    xor r10d, edx
    add r10d, r9d
    sub r10d, ecx
    add r10d, 24153BFh
    jmp loc_7FF856535050
    loc_7FF856534F9D:
    mov ecx, dword ptr [rsp+5Ch]
    loc_7FF856534FA1:
    mov dword ptr [rsp+80h], ecx
    mov ecx, dword ptr [rsp+80h]
    mov rdx, qword ptr [rsp+10h]
    mov r8, 40ADCC0630FC5E7Bh
    xor rdx, r8
    mov dword ptr [rsp+84h], ecx
    mov qword ptr [rsp+0E8h], rdx
    loc_7FF856534FD0:
    mov ecx, dword ptr [rsp+84h]
    mov rdx, qword ptr [rsp+0E8h]
    mov r8, 218B5C213E8D2143h
    xor rdx, r8
    mov dword ptr [rsp+8], ecx
    jmp loc_7FF856537A20
    loc_7FF856534FF5:
    mov ecx, dword ptr [rsp+48h]
    movzx edx, byte ptr [rsp+37h]
    mov dword ptr [rsp+88h], ecx
    mov byte ptr [rsp+24h], dl
    mov ecx, dword ptr [dword_7FF85722E340]
    mov edx, ecx
    xor edx, -0E52085Dh
    lea r8d, [rdx-7D4ECE71h]
    mov r9d, r8d
    xor r9d, -28FE8822h
    lea r10d, [r9+0E379AC8h]
    xor r10d, 4FE89647h
    sub r10d, edx
    sub r10d, r9d
    add r10d, -62C5F9E9h
    xor r10d, ecx
    sub r10d, edx
    add r10d, -3920410Fh
    loc_7FF856535050:
    xor r10d, r8d
    mov dword ptr [rsp+0Ch], r10d
    jmp loc_7FF856533AF0
    loc_7FF85653505D:
    mov rcx, qword ptr [rsp+0C0h]
    mov qword ptr [rsp+0D8h], rcx
    mov ecx, dword ptr [dword_7FF85722E308]
    mov edx, -7DCABE5Ah
    add ecx, edx
    mov edx, ecx
    xor edx, 59B009AFh
    lea r8d, 0FFFFFFFFEF4C74A4h[rdx*2]
    add edx, -10B38B5Ch
    sub r8d, ecx
    add r8d, 2961AF30h
    xor r8d, edx
    xor r8d, -6E7E6578h
    mov dword ptr [rsp+0Ch], r8d
    jmp loc_7FF856533AF0
    loc_7FF8565350AE:
    mov rcx, qword ptr [rsp+10h]
    mov edx, dword ptr [rsp+48h]
    mov dword ptr [rsp+90h], edx
    mov qword ptr [rsp+0F0h], rcx
    mov ecx, dword ptr [dword_7FF85722E30C]
    lea edx, [rcx-31E877F9h]
    xor edx, 821FD7Fh
    lea r8d, [rdx+6428F644h]
    mov r9d, r8d
    xor r9d, 61BD0EDFh
    lea ecx, 0FFFFFFFFCE178807h[rcx*2]
    sub ecx, r9d
    add r9d, 62472F7h
    add ecx, 7B75091Bh
    xor ecx, r8d
    sub ecx, edx
    add ecx, -3F912AC1h
    loc_7FF85653510B:
    xor ecx, r9d
    mov dword ptr [rsp+0Ch], ecx
    jmp loc_7FF856533AF0
    loc_7FF856535117:
    mov rcx, qword ptr [rsp+10h]
    mov edx, dword ptr [rsp+44h]
    mov dword ptr [rsp+84h], edx
    mov qword ptr [rsp+0E8h], rcx
    mov ecx, dword ptr [dword_7FF85722E348]
    mov edx, ecx
    xor edx, 72655F3Eh
    add edx, ecx
    xor ecx, -6BFED3B0h
    sub edx, ecx
    add edx, -5496587Ch
    mov dword ptr [rsp+0Ch], edx
    loc_7FF856535151:
    mov r14, 5E76CF28E3C6132Fh
    jmp loc_7FF856533AF0
    loc_7FF856535160:
    mov ecx, dword ptr [dword_7FF85722E338]
    lea edx, [rcx-73142FF3h]
    mov r8d, -7A2CE890h
    sub r8d, ecx
    xor r8d, edx
    add ecx, r8d
    add ecx, -1B1475D7h
    mov dword ptr [rsp+0Ch], ecx
    jmp loc_7FF856533AF0
    loc_7FF85653518A:
    mov ecx, dword ptr [dword_7FF85722E31C]
    mov edx, -644903DAh
    xor ecx, edx
    lea edx, [rcx-1A303E87h]
    mov r8d, edx
    xor r8d, -455E51D5h
    add r8d, -6EFEB1B9h
    xor r8d, edx
    add r8d, ecx
    mov dword ptr [rsp+0Ch], r8d
    jmp loc_7FF856533AF0
    loc_7FF8565351BE:
    mov ecx, dword ptr [rsp+40h]
    mov dword ptr [rsp+70h], ecx
    mov byte ptr [rsp+22h], r10b
    mov ecx, dword ptr [dword_7FF85722E324]
    lea edx, [rcx-2797B8C2h]
    mov r8d, edx
    xor r8d, 1AE8F458h
    lea r9d, [r8-2E8A3526h]
    lea r10d, [r8+4994922h]
    lea r11d, [rcx-1C2BE6Bh]
    xor r11d, r8d
    xor r11d, r9d
    sub r11d, ecx
    xor r11d, r10d
    sub r11d, edx
    sub r11d, r8d
    add r11d, 0C2C88BDh
    mov dword ptr [rsp+0Ch], r11d
    jmp loc_7FF856533AF0
    loc_7FF856535219:
    mov ecx, dword ptr [dword_7FF85722E304]
    mov edx, ecx
    xor edx, -74C2B877h
    lea r9d, [rdx-2BC179D4h]
    xor r9d, 35881F5h
    add edx, ecx
    sub r9d, edx
    add r9d, 1BFD4391h
    mov dword ptr [rsp+0Ch], r9d
    jmp loc_7FF856533AF0
    loc_7FF85653524B:
    mov ecx, dword ptr [dword_7FF85722E374]
    lea edx, [rcx+0E10110h]
    mov r8d, edx
    xor r8d, 3992F124h
    lea r9d, [r8-5683CF44h]
    lea r10d, [r8-5E3FC97Ah]
    xor r9d, edx
    xor r9d, 1FD33459h
    sub r9d, ecx
    add r9d, r8d
    lea ecx, [r8+r10]
    add ecx, -5E3FC97Ah
    sub r9d, ecx
    add r9d, -72BD762Ah
    xor r9d, edx
    xor r9d, 3B99521Dh
    mov dword ptr [rsp+0Ch], r9d
    jmp loc_7FF856533AF0
    loc_7FF8565352A7:
    mov ecx, dword ptr [dword_7FF85722E354]
    lea edx, [rcx+2468815Bh]
    xor edx, -4A9D5DC0h
    lea r8d, [rdx-2FA265C6h]
    lea r9d, [rdx-3076F007h]
    xor r9d, -59ED9260h
    lea r10d, [rdx+3698A505h]
    xor r10d, edx
    add r10d, ecx
    add r10d, 2468815Bh
    xor r10d, r8d
    add r9d, ecx
    add r9d, r10d
    lea ecx, [rdx+r9]
    add ecx, 4BC687D8h
    mov dword ptr [rsp+0Ch], ecx
    jmp loc_7FF856533AF0
    loc_7FF8565352FE:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r14d, dword ptr [dword_7FF8571C7568]
    mov ebx, r14d
    xor ebx, -1D598908h
    lea edx, [rbx+48207F58h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11d, edx
    xor r11d, -7E5FF7FFh
    mov r10d, edx
    xor r10d, 465FE73Eh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, r10d
    or r8d, -7A1416C9h
    lea esi, [r8+r8*4]
    lea esi, [r8+rsi*2]
    not r8d
    lea r15d, [r8*8]
    sub r15d, r8d
    and r11d, -7A1416C9h
    mov r8d, r11d
    shl r8d, 4
    add r8d, r11d
    mov r11d, r10d
    and r11d, -7A1416C9h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r12d, [r11+r11*2]
    not r11d
    add r11d, r11d
    lea r11d, [r11+r11*2]
    and r10d, 7A1416C8h
    lea ebp, [r10+r10*8]
    lea r10d, [r10+rbp*2]
    lea r12d, [r12]
    sub r12d, esi
    sub r12d, r11d
    add r12d, r8d
    lea r11d, [r12]
    add r11d, 4DA07FFh
    lea r10d, [r12]
    add r10d, 3C8A9750h
    mov esi, r12d
    add esi, r15d
    mov r12d, r10d
    not r12d
    mov r8d, r12d
    and r8d, 4CDF90B3h
    lea r15d, [r8+r8*8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r15d, r12d
    mov r8d, r12d
    and r8d, 33206F4Ch
    lea r8d, [r8+r8*4]
    mov ebp, r10d
    and ebp, -4CDF90B4h
    mov r12d, r10d
    and r12d, 4CDF90B3h
    lea r13d, [r12]
    lea r12d, [r12+r13*2]
    add r12d, ebp
    mov r13d, ebp
    not r13d
    lea ebp, [r13+r13*4+0]
    lea ebp, [r13+rbp*2+0]
    sub r12d, ebp
    lea r8d, [r12+r8*2]
    add r15d, r8d
    mov r8d, r14d
    xor r8d, 8500102h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ebp, ebx
    and ebp, 150FAAA5h
    shl ebp, 2
    lea r13d, [rbx+rbx]
    mov r12d, ebx
    or r12d, -550FAAA6h
    lea r12d, [r12]
    and r8d, 2AF0555Ah
    and ebx, -550FAAA6h
    lea ebx, [rbx+rbx*2]
    lea r8d, [rbx+r8*4]
    sub r12d, r8d
    sub r12d, r13d
    sub r12d, ebp
    xor r12d, r14d
    xor r12d, r11d
    add r12d, esi
    add r12d, r15d
    xor r12d, r10d
    mov r8d, r12d
    or r8d, edx
    lea r10d, [r12]
    mov r11d, edx
    not r11d
    and r11d, r12d
    and r12d, edx
    lea edx, [r12]
    lea edx, [rdx+r11*2]
    not r10d
    add r10d, r8d
    add r10d, edx
    lea edx, [r9+r10]
    inc edx
    mov dword ptr [rsp+5Ch], edx
    mov ecx, ecx
    mov rdx, qword ptr [rsp+28h]
    movzx ecx, byte ptr [rdx+rcx]
    mov byte ptr [rsp+33h], cl
    mov dl, 5
    sub dl, byte ptr [byte_7FF8571C756C]
    cmp cl, dl
    jnz loc_7FF8565356EA
    mov ecx, dword ptr [dword_7FF85722E350]
    lea edx, [rcx-4302FD0Fh]
    xor edx, -5BB48B2Bh
    lea r8d, [rdx-23924755h]
    xor r8d, ecx
    sub r8d, edx
    mov dword ptr [rsp+0Ch], r8d
    jmp loc_7FF856535739
    loc_7FF8565356EA:
    mov ecx, dword ptr [dword_7FF85722E33C]
    lea edx, [rcx+33C51873h]
    lea r9d, [rcx-5B8F8C9Eh]
    xor r9d, edx
    lea edx, [rcx-59EB0ED6h]
    xor edx, 25435A6h
    lea r10d, [rdx-604EB98Dh]
    mov r11d, -0FCA9F7Eh
    sub r11d, edx
    xor edx, r9d
    xor edx, r11d
    add edx, ecx
    add edx, -59EB0ED6h
    xor edx, r10d
    sub edx, ecx
    add edx, -7B288637h
    mov dword ptr [rsp+0Ch], edx
    loc_7FF856535739:
    mov r13, qword ptr [rsp+0B8h]
    mov r15, -5379EA1CB64DBB60h
    mov r12, -5409039D789AF9B3h
    jmp loc_7FF856534BFA
    loc_7FF85653575A:
    mov r9d, dword ptr [rsp+6Ch]
    mov rcx, qword ptr [rsp+0D0h]
    mov rdx, qword ptr [rsp+0C8h]
    mov qword ptr [rsp+10h], rcx
    mov rcx, qword ptr [rsp+28h]
    movzx edx, word ptr [rcx+rdx]
    mov r8d, dword ptr [dword_7FF8571C7520]
    mov r10d, r8d
    xor r10d, 72AA6EA7h
    mov ecx, r8d
    xor ecx, -61748596h
    lea r11d, [rcx+264BBE71h]
    add ecx, -5C0A9B02h
    xor ecx, r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add ecx, r10d
    xor ecx, r8d
    add ecx, r9d
    cmp rdx, 2Ch
    ja def_7FF856535804
    lea rdi, jpt_7FF856535804
    movsxd rdx, dword ptr [rdi+rdx*4]
    add rdx, rdi
    jmp rdx
    loc_7FF856535806:
    mov rdx, qword ptr [$+67h]
    mov r8, qword ptr [rsp+10h]
    xor r8, qword ptr [rdx+18h]
    mov rdx, 5CE520BE3D2D8567h
    jmp loc_7FF856537A0D
    loc_7FF856535827:
    mov rdx, qword ptr [rsp+188h]
    mov qword ptr [rsp+140h], rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9d, 3
    mov dword ptr [rsp+68h], r9d
    mov ecx, ecx
    mov rdx, qword ptr [rsp+28h]
    movzx ecx, byte ptr [rdx+rcx]
    mov byte ptr [rsp+3Dh], cl
    test cl, cl
    jz loc_7FF856537D7D
    mov ecx, dword ptr [dword_7FF85722E384]
    lea edx, [rcx-19ECE915h]
    mov r8d, edx
    xor r8d, 55C8D8F4h
    lea r9d, [r8-4F8BFF42h]
    sub r8d, edx
    add ecx, r8d
    add ecx, -67561119h
    jmp loc_7FF85653510B
    def_7FF856535804:
    mov rdx, qword ptr [rsp+10h]
    mov dword ptr [rsp+8], ecx
    mov qword ptr [rsp+18h], rdx
    mov ecx, dword ptr [dword_7FF85722E32C]
    lea edx, [rcx-3814515Dh]
    add ecx, -784B8D9h
    xor ecx, edx
    xor edx, 1431DBD3h
    add ecx, edx
    add ecx, edx
    add ecx, 2871DA9Ah
    mov dword ptr [rsp+0Ch], ecx
    jmp loc_7FF856533AF0
    loc_7FF856535908:
    mov rdx, qword ptr [$+37h]
    mov r8, qword ptr [rsp+10h]
    xor r8, qword ptr [rdx+40h]
    mov rdx, 6CB86866F281046Eh
    jmp loc_7FF856537A0D
    loc_7FF856535929:
    mov rdx, qword ptr [$+67h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, qword ptr [rsp+10h]
    xor r8, qword ptr [rdx+110h]
    mov rdx, 602B3F342EA0422Eh
    jmp loc_7FF856537A0D
    loc_7FF856535993:
    mov r8, qword ptr [qword_7FF8571C7588]
    mov rdx, -422A23F4B73A0829h
    add rdx, r8
    mov r9, -17294802BF40CD03h
    xor r9, rdx
    mov r10, 4A7895D64C90EB75h
    add r10, r9
    mov r11, 55F37DB59157B0F6h
    xor r11, r10
    mov rsi, -7235AF322C6E274Fh
    xor rsi, r10
    add r11, r9
    add r8, rsi
    add r8, r11
    mov r9, -53BB7FAEF0F59815h
    sub r9, r8
    xor r9, r10
    sub r9, rsi
    mov r8, -653F46E5A4C8DF11h
    add r8, r9
    xor r8, rdx
    xor r8, qword ptr [rsp+10h]
    mov rdx, 551D33442551A115h
    jmp loc_7FF856537A0D
    loc_7FF856535A1B:
    mov rdx, -27546C50550BBAE0h
    add rdx, qword ptr [rsp+10h]
    jmp loc_7FF856537A10
    loc_7FF856535A2F:
    mov rdx, qword ptr [rsp+10h]
    rol rdx, 29h
    jmp loc_7FF856537A10
    loc_7FF856535A3D:
    mov rdx, qword ptr [rsp+10h]
    rol rdx, 2Eh
    jmp loc_7FF856537A10
    loc_7FF856535A4B:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rsp+10h]
    rol rdx, 15h
    jmp loc_7FF856537A10
    loc_7FF856535AC4:
    mov rdx, qword ptr [$+67h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rdx+30h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor rdx, qword ptr [rsp+10h]
    mov r8, 456D703DD65DA3D3h
    jmp loc_7FF856537CA2
    loc_7FF856535B94:
    mov rdx, 7BA89702F651AE55h
    add rdx, qword ptr [rsp+10h]
    jmp loc_7FF856537A10
    loc_7FF856535BA8:
    mov rdx, qword ptr [$+67h]
    mov r8, qword ptr [rsp+10h]
    xor r8, qword ptr [rdx+20h]
    mov rdx, 30E377F107E1838Ah
    jmp loc_7FF856537A0D
    loc_7FF856535BC9:
    mov rdx, qword ptr [$+67h]
    mov r8, qword ptr [rsp+10h]
    xor r8, qword ptr [rdx+110h]
    mov rdx, 6F55913DA1B59C50h
    jmp loc_7FF856537A0D
    loc_7FF856535BED:
    mov rdx, qword ptr [rsp+10h]
    rol rdx, 2Bh
    jmp loc_7FF856537A10
    loc_7FF856535BFB:
    mov rdx, qword ptr [$+37h]
    mov r8, qword ptr [rsp+10h]
    xor r8, qword ptr [rdx+40h]
    mov rdx, -659A96220EF759D3h
    jmp loc_7FF856537A0D
    loc_7FF856535C1C:
    mov r8, qword ptr [qword_7FF8571C75D8]
    mov rdx, 4FC616E5A93EC920h
    xor rdx, r8
    mov r11, -10FAED02E20DFC73h
    add r11, rdx
    mov r9, -0FA22E6AA95E6C53h
    add r9, rdx
    mov r10, -3C2383D37581DC9h
    xor r10, r9
    mov r9, 5A13E3ABBB2DD17Ah
    add r9, rdx
    xor r9, r11
    mov r11, -4FC616E5A93EC921h
    xor r11, r8
    mov r8, r9
    or r8, r11
    mov rsi, r9
    mov rbx, r9
    xor rbx, rdx
    lea rbx, [rbx+rbx*2]
    and r11, r9
    and r9, rdx
    sub r9, r11
    add r9, rbx
    sub r9, r8
    not r8
    shl r8, 2
    or rsi, rdx
    not rsi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9, rsi
    sub r9, r8
    sub r9, r10
    add r9, qword ptr [rsp+10h]
    jmp loc_7FF856537133
    loc_7FF856535D0B:
    mov rdx, qword ptr [$+67h]
    mov rdx, qword ptr [rdx+30h]
    mov r8, rdx
    not r8
    mov r9, qword ptr [rsp+10h]
    mov r10, r9
    or r10, r8
    not r10
    or r9, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9, r9
    mov r11, qword ptr [rsp+10h]
    mov rsi, r11
    xor rsi, rdx
    and r8, r11
    shl r8, 2
    and r11, rdx
    lea rdx, [r8+r11*2]
    sub rdx, rsi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rdx, r9
    lea rdx, [rdx+r10*4]
    mov r8, -0D928AD39AE5F1DCh
    jmp loc_7FF856537CA2
    loc_7FF856535E26:
    mov rdx, qword ptr [$+67h]
    mov r8, qword ptr [rsp+10h]
    xor r8, qword ptr [rdx+38h]
    mov rdx, -50E355DCB40B9ECEh
    jmp loc_7FF856537A0D
    loc_7FF856535E47:
    mov rdx, qword ptr [$+67h]
    xor rdx, qword ptr [rsp+10h]
    mov r8, -37DA2B2F8AE6DE6Eh
    add r8, qword ptr [qword_7FF8571C75B8]
    mov r9, 562683A6659FB99Ah
    xor r9, r8
    mov r10, 20E7567B138FD732h
    add r10, r9
    xor r8, rdx
    mov rdx, 5C734D91A503062Fh
    xor rdx, r8
    xor rdx, r10
    jmp loc_7FF856537A10
    loc_7FF856535E98:
    mov rdx, qword ptr [$+67h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rdx+10h]
    test al, 0D2h
    shl ch, 0
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor rdx, qword ptr [rsp+10h]
    mov r9, qword ptr [qword_7FF8571C7598]
    mov r10, 42A7CF43A2DE85EDh
    xor r10, r9
    mov r8, r10
    mov rbx, -122356F547CB1B05h
    or r8, rbx
    mov r11, r10
    mov r14, 122356F547CB1B04h
    xor r11, r14
    lea r11, [r11+r11*2]
    mov rsi, r10
    and rsi, rbx
    mov rbx, r10
    and rbx, r14
    sub rbx, rsi
    add rbx, r11
    sub rbx, r8
    not r8
    shl r8, 2
    mov r11, r10
    or r11, r14
    mov r14, 5E76CF28E3C6132Fh
    not r11
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rbx, r11
    sub rbx, r8
    mov r8, 6D0695A22916C93Dh
    xor r8, rbx
    mov r11, 38C7ADF564B8294Ch
    add r11, r8
    mov r8, 7D0F238E22DEA692h
    sub r8, rbx
    xor r8, r10
    add r8, r9
    mov r9, r11
    not r9
    mov r10, r8
    or r10, r9
    not r10
    mov rsi, r8
    or rsi, r11
    add rsi, rsi
    mov rbx, r8
    xor rbx, r11
    and r9, r8
    shl r9, 2
    and r8, r11
    lea r8, [r9+r8*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r8, rbx
    sub r8, rsi
    lea r8, [r8+r10*4]
    jmp loc_7FF856537CA2
    loc_7FF856536100:
    mov rdx, qword ptr [rsp+10h]
    mov r8, rdx
    mov rsi, -54874EEB7B1A1019h
    or r8, rsi
    mov r9, rdx
    mov rbx, 54874EEB7B1A1018h
    or r9, rbx
    mov r10, rdx
    xor r10, rbx
    not r10
    add r10, r9
    lea r9, [rdx+rdx]
    mov r11, rdx
    and r11, rsi
    lea r11, [r11+r11*2]
    and rdx, rbx
    lea rdx, [rdx+rdx*2]
    add rdx, r11
    sub rdx, r9
    add rdx, r10
    sub rdx, r8
    jmp loc_7FF856537A10
    loc_7FF856536157:
    mov r8, qword ptr [qword_7FF8571C7580]
    mov rdx, 0D536415E175EBE1h
    xor rdx, r8
    mov r10, -0D536415E175EBE2h
    xor r10, r8
    mov r8, rdx
    mov rbx, 2189DC799899DA63h
    or r8, rbx
    not r8
    lea r9, [r8+r8*4]
    lea r8, [r8+r9*2]
    mov r9, rdx
    mov rsi, -2189DC799899DA64h
    or r9, rsi
    mov r11, rdx
    and r11, rbx
    add r11, r9
    mov r9, rdx
    and r9, rsi
    imul r9, 0F5h
    add r9, r11
    sub r9, r8
    add r9, r10
    mov r8, -2022B4DE5D5F7CC1h
    add r8, r9
    mov r10, 2EDF80DE6F55D999h
    add r10, r9
    mov r11, r10
    mov rsi, r10
    or rsi, r8
    lea rbx, [r10+r10]
    and r10, r8
    not r8
    or r11, r8
    not rsi
    add rsi, r11
    add r10, r10
    sub rbx, r10
    add rbx, rsi
    sub rbx, r8
    inc rbx
    xor rbx, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, -22E7478A4F850BECh
    add rdx, r9
    add rdx, rbx
    xor rdx, qword ptr [rsp+10h]
    jmp loc_7FF856537A10
    loc_7FF856536269:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [$+67h]
    mov r8, qword ptr [rsp+10h]
    xor r8, qword ptr [rdx+38h]
    mov rdx, 0F3D2C7B39D4C1C5h
    jmp loc_7FF856537A0D
    loc_7FF8565362E7:
    mov rdx, qword ptr [$+37h]
    mov r8, qword ptr [rsp+10h]
    xor r8, qword ptr [rdx+40h]
    mov rdx, 115C8D77640A4951h
    jmp loc_7FF856537A0D
    loc_7FF856536308:
    mov rdx, qword ptr [rsp+10h]
    rol rdx, 17h
    jmp loc_7FF856537A10
    loc_7FF856536316:
    mov r8, qword ptr [$+67h]
    mov rdx, r8
    not rdx
    mov r9, qword ptr [rsp+10h]
    mov r10, r9
    or r10, rdx
    not r10
    lea r11, [r10*8]
    sub r11, r10
    mov r10, r9
    xor r10, r8
    lea r10, [r10+r10*4]
    and rdx, r9
    lea rdx, [rdx+rdx*2]
    and r9, r8
    lea rdx, [r9+rdx*2]
    sub rdx, r10
    sub rdx, r8
    add rdx, r11
    mov r9, qword ptr [qword_7FF8571C75C0]
    mov r8, 63DB047466DBB476h
    add r8, r9
    mov r10, -5FC100A91437FF3h
    add r10, r9
    mov r11, 4D648724785B7AAAh
    xor r11, r10
    mov rsi, 29313851A1C27459h
    add rsi, r11
    mov rbx, 13B29E826BA0CDDh
    xor rbx, rsi
    mov rsi, -2633DAC49B7C272Dh
    sub rsi, r11
    xor rsi, r8
    mov r8, rsi
    or r8, r11
    not r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8, r8
    mov r14, rsi
    and r14, r11
    not r14
    add r14, r14
    xor rsi, r11
    sub r14, rsi
    sub r14, r8
    xor r14, r10
    sub r14, rbx
    sub r14, r9
    mov r8, -660C843C4671D97Eh
    add r8, r14
    mov r14, 5E76CF28E3C6132Fh
    jmp loc_7FF856537CA2
    loc_7FF85653646B:
    add r9d, 3
    mov dword ptr [rsp+58h], r9d
    mov ecx, ecx
    mov rdx, qword ptr [rsp+28h]
    movzx ecx, byte ptr [rdx+rcx]
    mov byte ptr [rsp+32h], cl
    test cl, cl
    jz loc_7FF856537DF0
    mov ecx, 3FCAE232h
    add ecx, dword ptr [dword_7FF85722E328]
    mov edx, ecx
    xor edx, 288369B2h
    lea r8d, [rdx-275B087Fh]
    lea r9d, 180A385Ah[rdx*2]
    lea r10d, [rdx+3F6540D9h]
    xor r10d, r8d
    add r9d, edx
    mov edx, 6EE0D206h
    sub edx, r9d
    xor edx, r10d
    xor edx, -0AA03081h
    sub edx, ecx
    mov dword ptr [rsp+0Ch], edx
    jmp loc_7FF856533AF0
    loc_7FF8565364D6:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [qword_7FF8571C75D0]
    mov r8, rdx
    mov r11, 35E47638DBAE2395h
    or r8, r11
    not r8
    lea r10, [r8*8]
    sub r10, r8
    mov r8, rdx
    mov rsi, -35E47638DBAE2396h
    xor r8, rsi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r8, [r8+r8*4]
    mov r9, rdx
    and r9, r11
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r9, [r9+r9*2]
    mov r11, rdx
    and r11, rsi
    lea r11, [r11+r9*2]
    sub r11, r8
    sub r11, rsi
    mov r9, -430DAC2D2F27CC24h
    add r9, r10
    add r9, r11
    mov r10, 6EA24A2C05DF13A1h
    xor r10, r9
    mov r11, r10
    mov r12, 1F6551363A0F320Ah
    or r11, r12
    not r11
    mov r8, r10
    mov rbp, -1F6551363A0F320Bh
    or r8, rbp
    not r8
    shl r8, 2
    mov rsi, r10
    xor rsi, rbp
    mov rbx, rsi
    not rbx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r14, [rsi*8]
    mov r15, r10
    and r15, r12
    shl r15, 3
    mov r12, r10
    and r12, rbp
    mov rbp, 4301042C122F606Ah
    add r12, r12
    sub r15, r12
    mov r12, -5409039D789AF9B3h
    sub rsi, r14
    mov r14, 5E76CF28E3C6132Fh
    add rsi, r15
    mov r15, -5379EA1CB64DBB60h
    lea rsi, [rsi+rbx*4]
    sub rsi, r8
    lea r8, [rsi+r11*8]
    mov r11, -2FAE7003F8540FEDh
    add r11, r8
    mov rsi, -751DEA4EBF24EF09h
    xor rsi, r11
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r9, r11
    add r9, r8
    add rdx, rsi
    add rdx, r9
    mov r8, 771E7B18EF500D4Bh
    add r8, rdx
    xor r8, r10
    sub r8, rsi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8, qword ptr [rsp+10h]
    mov rdx, -664339A9DB7048B5h
    add rdx, r8
    jmp loc_7FF856537A10
    loc_7FF856536898:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, 69789AFF591FF775h
    add rdx, qword ptr [qword_7FF8571C75E0]
    mov r8, -7E589BF142136DBCh
    xor r8, rdx
    mov r9, 77EAB0A93E6DD516h
    add r9, r8
    mov r8, -294156ECDFD7935Fh
    xor r8, rdx
    mov r10, r8
    or r10, r9
    not r10
    add r10, r10
    mov r11, r8
    and r11, r9
    not r11
    add r11, r11
    xor r8, r9
    sub r11, r8
    sub r11, r10
    xor r11, rdx
    add r11, qword ptr [rsp+10h]
    mov dword ptr [rsp+8], ecx
    mov qword ptr [rsp+18h], r11
    jmp loc_7FF856537A25
    loc_7FF856536972:
    mov rdx, qword ptr [rsp+188h]
    mov qword ptr [rsp+130h], rdx
    mov edx, dword ptr [dword_7FF8571C7558]
    lea r8d, [rdx+1083C730h]
    mov r10d, r8d
    xor r10d, -51A72F10h
    mov r11d, r8d
    xor r11d, 51820001h
    and r11d, -26653F1Fh
    lea esi, [r11*8]
    sub esi, r11d
    xor r8d, 77C21011h
    lea r8d, [r8+r8*4]
    mov r11d, r10d
    xor edx, 1726CA95h
    sub edx, r10d
    and r10d, 26653F1Eh
    lea r10d, [r10+r10*2]
    and r11d, -26653F1Fh
    lea r10d, [r11+r10*2]
    sub r10d, r8d
    add r10d, esi
    xor edx, -135BF9D2h
    sub edx, r10d
    add edx, r9d
    add edx, -26653F1Fh
    mov dword ptr [rsp+64h], edx
    mov ecx, ecx
    mov rdx, qword ptr [rsp+28h]
    movzx ecx, byte ptr [rdx+rcx]
    mov byte ptr [rsp+38h], cl
    test cl, cl
    jz loc_7FF856537DA3
    mov ecx, dword ptr [rsp+64h]
    mov dword ptr [rsp+94h], ecx
    mov byte ptr [rsp+25h], 0
    loc_7FF856536A25:
    movzx ecx, byte ptr [rsp+25h]
    mov r8d, dword ptr [rsp+94h]
    mov r9, qword ptr [rsp+28h]
    mov rdx, qword ptr [r9+r8]
    mov r10, -54814BEDE87B468Dh
    xor rdx, r10
    lea r10d, [r8+8]
    mov r9d, dword ptr [r9+r10]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8d, 0Ch
    mov dword ptr [rsp+4Ch], r8d
    mov r10, qword ptr [rsp+130h]
    cmp r10, rdx
    jb loc_7FF856536B20
    nop word ptr [rax+rax+00000000h]
    add rdx, r9
    cmp r10, rdx
    jnb loc_7FF856536B20
    mov rcx, qword ptr [rsp+10h]
    mov edx, dword ptr [rsp+4Ch]
    mov dword ptr [rsp+9Ch], edx
    mov qword ptr [rsp+0F8h], rcx
    mov ecx, dword ptr [dword_7FF85722E370]
    mov edx, 63557A2Bh
    sub edx, ecx
    xor edx, ecx
    add ecx, edx
    add ecx, 1F7BE356h
    mov dword ptr [rsp+0Ch], ecx
    jmp loc_7FF856533AF0
    loc_7FF856536B20:
    inc cl
    mov byte ptr [rsp+39h], cl
    cmp cl, byte ptr [rsp+38h]
    jnz loc_7FF856536B7A
    mov ecx, dword ptr [rsp+4Ch]
    loc_7FF856536B30:
    mov dword ptr [rsp+98h], ecx
    mov ecx, dword ptr [rsp+98h]
    mov rdx, qword ptr [rsp+10h]
    mov r8, 565DD1B2080F3138h
    xor rdx, r8
    mov dword ptr [rsp+9Ch], ecx
    mov qword ptr [rsp+0F8h], rdx
    loc_7FF856536B5F:
    mov ecx, dword ptr [rsp+9Ch]
    mov rdx, qword ptr [rsp+0F8h]
    xor rdx, rbp
    mov dword ptr [rsp+8], ecx
    jmp loc_7FF856537A20
    loc_7FF856536B7A:
    mov ecx, dword ptr [dword_7FF85722E36C]
    lea edx, [rcx+41CB1E2Fh]
    lea r8d, [rcx-2A6781FBh]
    lea r9d, [rcx-4203B3FCh]
    xor r9d, edx
    xor r9d, r8d
    xor r9d, 4EE026D5h
    sub r9d, ecx
    mov dword ptr [rsp+0Ch], r9d
    jmp loc_7FF856533AF0
    loc_7FF856536BAE:
    mov r9, qword ptr [$+67h]
    mov rdx, qword ptr [rsp+10h]
    xor rdx, qword ptr [r9+30h]
    mov r9, qword ptr [qword_7FF8571C75A8]
    mov r10, 618E6170A9D29F43h
    add r10, r9
    mov r11, r10
    mov r8, -353E55C41AE40556h
    or r11, r8
    not r11
    mov rsi, r10
    mov r14, 353E55C41AE40555h
    or rsi, r14
    not rsi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rbx, r10
    and rbx, r14
    and r10, r8
    add r10, r10
    lea r10, [r10+rbx*2]
    not rbx
    add rbx, rsi
    add r10, rbx
    lea rsi, [r10+r11*2]
    add rsi, 2
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11, -7A90A08A56DF82ADh
    xor r11, rsi
    mov rbx, 1438F3952557B93Fh
    add rbx, r11
    mov r10, 48C719BC38D1D329h
    add r10, r11
    mov r14, rbx
    not r14
    mov rbp, -23CCF0B6E6EF121Bh
    mov r15, rbp
    or r15, r14
    not r15
    lea r15, [r15+r15*2]
    mov r12, rbp
    or r12, rbx
    not r12
    add r12, r12
    and r14, rbp
    lea r8, [r14+r14*2]
    not r14
    add r14, r14
    and rbx, rbp
    mov rbp, rbx
    not rbp
    add rbx, rbx
    sub rbx, r8
    lea r8, [rbx+rbp*4]
    mov rbp, 4301042C122F606Ah
    sub r8, r14
    mov r14, 5E76CF28E3C6132Fh
    sub r8, r12
    mov r12, -5409039D789AF9B3h
    sub r8, r15
    mov r15, -5379EA1CB64DBB60h
    sub r8, rsi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r8, r9
    add r8, r11
    mov r9, r10
    not r9
    mov r11, r8
    or r11, r9
    not r11
    shl r11, 2
    lea rsi, [r10+r10]
    mov rbx, r8
    or rbx, r10
    lea rbx, [rbx+rbx*4]
    and r9, r8
    and r8, r10
    lea r8, [r8+r8*2]
    lea r8, [r8+r9*4]
    sub rbx, r8
    sub rbx, rsi
    sub rbx, r11
    xor rbx, rdx
    mov dword ptr [rsp+8], ecx
    mov qword ptr [rsp+18h], rbx
    jmp loc_7FF856537A25
    loc_7FF856536E10:
    mov rdx, qword ptr [$+67h]
    mov r8, qword ptr [rsp+10h]
    xor r8, qword ptr [rdx+18h]
    mov rdx, 20794943D4CF7338h
    jmp loc_7FF856537A0D
    loc_7FF856536E31:
    mov rdx, -1BC115FD5E5EEF36h
    xor rdx, qword ptr [rsp+10h]
    jmp loc_7FF856537A10
    loc_7FF856536E45:
    mov rdx, qword ptr [$+67h]
    mov r8, qword ptr [rsp+10h]
    xor r8, qword ptr [rdx+20h]
    mov rdx, r8
    mov r11, -2720BB92238B91DFh
    or rdx, r11
    not rdx
    mov r9, r8
    mov rsi, 2720BB92238B91DEh
    or r9, rsi
    not r9
    mov r10, r8
    and r10, rsi
    and r8, r11
    add r8, r8
    lea r8, [r8+r10*2]
    not r10
    add r10, r9
    add r8, r10
    lea rdx, [r8+rdx*2]
    add rdx, 2
    jmp loc_7FF856537A10
    loc_7FF856536EA3:
    mov rdx, qword ptr [$+67h]
    mov r8, qword ptr [rsp+10h]
    xor r8, qword ptr [rdx+20h]
    mov rdx, -164E4A4B37D1E5CCh
    jmp loc_7FF856537A0D
    loc_7FF856536EC4:
    mov rdx, qword ptr [$+67h]
    mov r10, qword ptr [qword_7FF8571C75C8]
    mov r9, 4840F7E6B09D6710h
    add r9, r10
    mov r8, r9
    mov r12, -27BA4F1401C37691h
    or r8, r12
    not r8
    lea r11, [r8+r8*4]
    lea r14, [r8+r11*4]
    mov r8, r9
    mov rbx, 27BA4F1401C37690h
    or r8, rbx
    lea r11, [r8+r8*4]
    lea r11, [r8+r11*2]
    not r8
    lea rsi, [r8+r8*4]
    lea r8, [r8+rsi*2]
    mov rsi, r9
    and rsi, rbx
    lea rbx, [rsi+rsi*8]
    not rsi
    lea r15, [rsi+rsi*4]
    lea r15, [rsi+r15*2]
    mov rsi, r9
    and rsi, r12
    lea r12, [rsi+rsi*4]
    lea r12, [rsp]
    add r12, rbx
    mov rsi, -13F93B1AA0673BC5h
    add rsi, r10
    sub r11, r12
    mov rbx, -57A1924E0A352CA2h
    add rbx, r10
    add r11, r15
    sub r11, r8
    sub r11, r14
    mov r8, r10
    not r8
    mov rbp, -6ADEC36F30A5D9A1h
    mov r14, rbp
    or r14, r10
    mov r15, r8
    xor r15, rbp
    and r10, rbp
    lea r12, [r10+r10*2]
    add r12, r15
    mov r15, -5379EA1CB64DBB60h
    mov r10, rbp
    or r10, r8
    and r8, rbp
    mov rbp, 4301042C122F606Ah
    lea r8, [r8+r8*2]
    add r12, r8
    not r10
    add r14, r10
    mov r10, -481E2EF397E1A5E6h
    add r10, r11
    add r14, r12
    mov r12, -5409039D789AF9B3h
    sub r14, r11
    mov r11, -2A4279219EB44CBDh
    add r11, r14
    xor r11, rsi
    mov r8, r11
    not r8
    mov rsi, r10
    not rsi
    mov r14, r11
    or r14, rsi
    not r14
    lea r14, [r14+r14*8]
    add r14, r8
    mov r8, r11
    or r8, r10
    and rsi, r11
    and r11, r10
    lea r10, [r11+r11*4]
    lea r10, [r11+r10*2]
    add r10, rsi
    not rsi
    lea r11, [rsi+rsi*4]
    lea r11, [rsi+r11*2]
    sub r10, r11
    not r8
    lea r8, [r8+r8*4]
    lea r8, [r10+r8*2]
    add r8, r14
    mov r14, 5E76CF28E3C6132Fh
    xor rdx, qword ptr [rsp+10h]
    xor r9, rbx
    xor r9, rdx
    xor r9, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and al, 0FFh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FF856537133:
    mov dword ptr [rsp+8], ecx
    mov qword ptr [rsp+18h], r9
    jmp loc_7FF856537A25
    loc_7FF856537141:
    mov rdx, qword ptr [$+67h]
    mov r8, qword ptr [rsp+10h]
    xor r8, qword ptr [rdx+18h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, -3D6B43F8ED97EA0Dh
    xor rdx, r8
    and dh, 0FFh
    xchg bl, bl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jmp loc_7FF856537A10
    loc_7FF85653723F:
    mov rdx, qword ptr [rsp+188h]
    mov qword ptr [rsp+138h], rdx
    mov r10d, dword ptr [dword_7FF8571C7534]
    lea edx, [r10+5C51D971h]
    mov r11d, edx
    xor r11d, -3CC0EA9h
    mov r8d, edx
    xor r8d, 3CC0EA8h
    lea esi, [r8+r8*2]
    mov ebx, r8d
    and ebx, 4B673609h
    lea ebx, [rbx+rbx*2]
    and r8d, -4B67360Ah
    lea r8d, [r8+r8*2]
    mov r14d, edx
    xor r14d, -48AB38A2h
    lea ebp, [r14*8]
    sub ebp, r14d
    add ebp, r8d
    mov r8d, r11d
    and r8d, 3498C9F6h
    add r8d, r8d
    lea r8d, [r8+r8*2]
    mov r14d, r11d
    and r14d, 4B673609h
    add r14d, r14d
    sub r14d, r8d
    add r14d, ebp
    sub r14d, ebx
    sub r14d, esi
    mov r8d, r14d
    xor r8d, -2B6A9A87h
    xor r14d, -108E1C89h
    add r14d, r11d
    lea r11d, [r8+r14]
    add r11d, -78718280h
    xor edx, r10d
    xor edx, r8d
    xor edx, r11d
    add r9d, edx
    mov ecx, ecx
    mov rdx, qword ptr [rsp+28h]
    movzx ecx, byte ptr [rdx+rcx]
    mov byte ptr [rsp+3Ah], cl
    test cl, cl
    jz loc_7FF856537DF9
    mov dword ptr [rsp+0A0h], r9d
    mov byte ptr [rsp+26h], 0
    mov rbp, 4301042C122F606Ah
    mov r14, 5E76CF28E3C6132Fh
    loc_7FF856537331:
    mov rcx, qword ptr [qword_7FF8571C7540]
    mov rdx, rcx
    mov rsi, -6651F47D02281005h
    or rdx, rsi
    mov r8, rcx
    mov rbx, 6651F47D02281004h
    or r8, rbx
    not r8
    mov r9, rcx
    xor r9, rbx
    not r9
    lea r9, [r9+r9*2]
    lea r10, [rdx+rdx*4]
    not rdx
    mov r11, rcx
    and r11, rsi
    lea r11, [r11+r11*2]
    add r11, r11
    and rcx, rbx
    lea rcx, [r11+rcx*8]
    sub rcx, r10
    sub rcx, r9
    lea rcx, [rcx+r8*8]
    add rcx, rdx
    mov r11, rcx
    mov rdx, -76407DA45892DB89h
    xor r11, rdx
    mov rdx, 5EE9C4384C280BFCh
    lea r9, [r11+rdx]
    mov rdx, -486A5F70AE965FACh
    add rdx, r11
    mov r8, 48FD89449F0D4623h
    lea r10, [r11+r8]
    xor r10, rdx
    mov rdx, r9
    mov r8, -255A1F83C4D31ECCh
    xor rdx, r8
    mov r8, rcx
    mov rsi, 76407DA45892DB88h
    xor r8, rsi
    mov rsi, rdx
    or rsi, r8
    not rsi
    lea rbx, [rsi+rsi*4]
    lea rsi, [rsi+rbx*2]
    lea rbx, [r11+r11*4]
    lea rbx, [r11+rbx*2]
    and r8, rdx
    add r8, rbx
    mov rbx, rdx
    or rbx, r11
    add r8, rbx
    movzx ebx, byte ptr [rsp+26h]
    mov byte ptr [rsp+3Bh], bl
    and rdx, r11
    imul rbx, rdx, 0F5h
    add rbx, r8
    mov edx, dword ptr [rsp+0A0h]
    mov r8, 52BAF5A5225C633Bh
    add r11, r8
    mov r8, 255A1F83C4D31ECBh
    xor r9, r8
    sub rbx, rsi
    lea r8, [rbx+r9]
    inc r8
    xor r8, r10
    mov r9, r11
    not r9
    mov r10, r8
    or r10, r9
    mov rsi, r8
    or rsi, r11
    and r11, r8
    and r9, r8
    mov r8, qword ptr [rsp+28h]
    not r10
    not rsi
    add r9, r9
    lea r9, [r9+r11*2]
    not r11
    add r11, rsi
    add r9, r11
    lea r9, [r9+r10*2]
    add rcx, r9
    add rcx, 2
    xor rcx, qword ptr [r8+rdx]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r8d, [rdx+8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9, qword ptr [rsp+28h]
    mov r9d, dword ptr [r9+r8]
    mov r8d, dword ptr [dword_7FF8571C7548]
    lea r10d, [r8+7BB71D38h]
    mov r11d, r10d
    xor r10d, -36CD6D08h
    lea esi, [r10+6AF31C6Ch]
    xor esi, 3DE96297h
    sub esi, r8d
    xor r11d, 1BFCC7E5h
    sub esi, r11d
    sub esi, r10d
    add esi, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov dword ptr [rsp+50h], esi
    mov rdx, qword ptr [rsp+138h]
    cmp rdx, rcx
    jb loc_7FF856537713
    nop dword ptr [rax]
    add rcx, r9
    cmp rdx, rcx
    jnb loc_7FF856537713
    mov rcx, qword ptr [rsp+10h]
    mov edx, dword ptr [rsp+50h]
    mov dword ptr [rsp+0A8h], edx
    loc_7FF8565376A8:
    mov qword ptr [rsp+100h], rcx
    mov ecx, dword ptr [rsp+0A8h]
    mov rdx, qword ptr [rsp+100h]
    xor rdx, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov dword ptr [rsp+8], ecx
    jmp loc_7FF856537A20
    loc_7FF856537713:
    mov ecx, dword ptr [dword_7FF85722E37C]
    mov edx, ecx
    xor edx, 422FAB80h
    sub edx, ecx
    add edx, 129035C3h
    mov dword ptr [rsp+0Ch], edx
    jmp loc_7FF856533AF0
    loc_7FF856537732:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rsp+10h]
    rol rdx, 12h
    jmp loc_7FF856537A10
    loc_7FF8565377B0:
    mov r8, qword ptr [$+67h]
    mov rdx, qword ptr [rsp+10h]
    xor rdx, qword ptr [r8+110h]
    mov r8, rdx
    mov r14, 79AB5D3B2580FD9Fh
    or r8, r14
    lea r9, [r8+r8*4]
    not r8
    mov r10, rdx
    mov rbx, -79AB5D3B2580FDA0h
    or r10, rbx
    not r10
    mov r11, rdx
    xor r11, rbx
    not r11
    lea r11, [r11+r11*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rsi, rdx
    and rsi, r14
    mov r14, 5E76CF28E3C6132Fh
    lea rsi, [rsi+rsi*2]
    add rsi, rsi
    and rdx, rbx
    lea rdx, [rsi+rdx*8]
    sub rdx, r9
    sub rdx, r11
    lea rdx, [rdx+r10*8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rdx, r8
    jmp loc_7FF856537A10
    loc_7FF8565378B5:
    mov r8, qword ptr [$+67h]
    mov rdx, qword ptr [rsp+10h]
    xor rdx, qword ptr [r8+10h]
    mov r9, qword ptr [qword_7FF8571C7590]
    mov r10, 7647E4CC1CD56D3Dh
    add r10, r9
    mov r8, 70932810C86F5BCFh
    xor r8, r10
    mov r11, 0B090FF3CC2D09F5h
    xor r11, r10
    sub r11, r8
    mov r8, -5172310864AF137Ch
    add r8, r11
    mov r11, r10
    not r11
    mov rsi, r8
    or rsi, r11
    not rsi
    lea rbx, [rsi+rsi*4]
    lea rsi, [rsi+rbx*2]
    mov rbx, r8
    or rbx, r10
    lea r14, [rbx+rbx*4]
    lea rbx, [rbx+r14*2]
    mov r14, r8
    xor r14, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r11, r8
    lea r11, [r11+r11*8]
    and r8, r10
    imul r8, 0F5h
    sub r8, r11
    sub r8, r14
    mov r14, 5E76CF28E3C6132Fh
    add r8, rbx
    sub r8, rsi
    add r8, r9
    jmp loc_7FF856537CA2
    loc_7FF8565379B7:
    mov rdx, qword ptr [$+67h]
    mov r8, qword ptr [rsp+10h]
    xor r8, qword ptr [rdx+38h]
    mov rdx, qword ptr [qword_7FF8571C75B0]
    mov r9, -391AD518E1550575h
    add r9, rdx
    mov r10, 2753ADD3E51D0201h
    xor r10, r9
    mov r11, -33C2BD946C45A767h
    add r11, rdx
    add r11, r10
    mov rdx, 4C2F4DF6D2327C36h
    xor rdx, r9
    xor rdx, r11
    sub rdx, r9
    loc_7FF856537A0D:
    xor rdx, r8
    loc_7FF856537A10:
    mov dword ptr [rsp+8], ecx
    nop word ptr [rax+rax+00000000h]
    loc_7FF856537A20:
    mov qword ptr [rsp+18h], rdx
    loc_7FF856537A25:
    mov rdx, qword ptr [rsp+18h]
    mov ecx, dword ptr [rsp+8]
    mov qword ptr [rsp+0C0h], rdx
    cmp qword ptr [rsp+110h], rcx
    jbe loc_7FF856533AA9
    mov rdx, qword ptr [rsp+0C0h]
    mov qword ptr [rsp+0C8h], rcx
    mov qword ptr [rsp+0D0h], rdx
    mov dword ptr [rsp+6Ch], ecx
    jmp loc_7FF85653575A
    loc_7FF856537A65:
    mov r8, qword ptr [$+67h]
    mov rdx, qword ptr [rsp+10h]
    xor rdx, qword ptr [r8+10h]
    mov r9, qword ptr [qword_7FF8571C75A0]
    mov r11, -4F0F8565860E7309h
    add r11, r9
    mov r8, 324C6C07F2ECE387h
    add r8, r9
    mov r10, 788B7B51A43C8592h
    add r10, r9
    mov rsi, -581DBF060CD21ADCh
    xor rsi, r10
    mov r10, 3D7A49613A5D8B36h
    add r10, rsi
    mov rbx, r8
    not rbx
    lea r14, [rbx+rbx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rbp, -787F036F7FB8E447h
    mov r15, rbp
    or r15, rbx
    mov r12, rbp
    or r12, r8
    not r12
    lea r12, [r12]
    and rbx, rbp
    lea rbx, [rbx+rbx*2]
    and r8, rbp
    sub rbx, r8
    add r12, rbp
    mov rbp, 4301042C122F606Ah
    add r12, rbx
    add r12, r15
    mov r15, -5379EA1CB64DBB60h
    sub r12, r14
    mov r14, 5E76CF28E3C6132Fh
    inc r12
    xor r10, rsi
    xor r10, r11
    xor r10, r12
    mov r12, -5409039D789AF9B3h
    mov r8, r10
    or r8, r9
    lea r11, [r10+r10]
    mov rsi, r9
    not rsi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and rsi, r10
    and r10, r9
    lea r9, [r10+r10*2]
    lea r9, [r9+rsi*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not r11
    add r11, r9
    add r8, r11
    inc r8
    loc_7FF856537CA2:
    xor r8, rdx
    mov dword ptr [rsp+8], ecx
    mov qword ptr [rsp+18h], r8
    jmp loc_7FF856537A25
    loc_7FF856537CB3:
    mov edx, 38E78E4Ch
    xor edx, dword ptr [dword_7FF8571C755C]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add edx, -5E670408h
    xor edx, 57F8CB8Ch
    add r9d, edx
    mov dword ptr [rsp+60h], r9d
    mov ecx, ecx
    mov rdx, qword ptr [rsp+28h]
    movzx ecx, byte ptr [rdx+rcx]
    mov byte ptr [rsp+35h], cl
    test cl, cl
    jz loc_7FF856537E1A
    mov ecx, dword ptr [dword_7FF85722E34C]
    lea edx, [rcx+29BC33E2h]
    xor edx, 0C12D8DEh
    lea r9d, [rdx-0DE4E620h]
    mov r10d, ecx
    sub r10d, edx
    add r10d, 5A8582EDh
    xor r10d, edx
    add ecx, r10d
    add ecx, 29BC33E2h
    jmp loc_7FF85653510B
    loc_7FF856537D7D:
    mov ecx, dword ptr [dword_7FF85722E330]
    mov edx, ecx
    xor edx, 5E8C7F1Dh
    add ecx, edx
    mov r8d, 6F9E483Bh
    sub r8d, ecx
    xor r8d, edx
    mov dword ptr [rsp+0Ch], r8d
    jmp loc_7FF856533AF0
    loc_7FF856537DA3:
    mov ecx, dword ptr [dword_7FF85722E368]
    mov edx, ecx
    xor edx, 426C7185h
    lea r8d, [rdx-4E1EA086h]
    xor r8d, 629F0A28h
    lea r9d, [r8-2DBE9CCEh]
    xor r9d, -0E287546h
    add ecx, r8d
    add ecx, -2DBE9CCEh
    add r8d, edx
    add r8d, ecx
    add r8d, r9d
    mov ecx, -6F71D0BAh
    sub ecx, r8d
    mov dword ptr [rsp+0Ch], ecx
    jmp loc_7FF856533AF0
    loc_7FF856537DF0:
    mov ecx, dword ptr [rsp+58h]
    jmp loc_7FF8565346DA
    loc_7FF856537DF9:
    mov dword ptr [rsp+0A4h], r9d
    mov rbp, 4301042C122F606Ah
    mov r14, 5E76CF28E3C6132Fh
    jmp loc_7FF856533C7F
    loc_7FF856537E1A:
    mov ecx, dword ptr [dword_7FF85722E360]
    lea edx, 0FFFFFFFF900C7636h[rcx*2]
    add ecx, -6FF389CAh
    mov r8d, 0A1DC017h
    sub r8d, edx
    xor r8d, ecx
    mov dword ptr [rsp+0Ch], r8d
    jmp loc_7FF856533AF0
    loc_7FF856537E43:
    mov qword ptr [rsp+0D8h], r13
    loc_7FF856537E4B:
    mov rax, qword ptr [rsp+0D8h]
    add rsp, 148h
    pop rbx
    pop rbp
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    ret
sub_7FF856533A20 ENDP
_TEXT ENDS
END

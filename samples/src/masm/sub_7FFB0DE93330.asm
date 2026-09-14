; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Regression fixture: d81-vp29, source function SHA-256
; bf50dd35d372bb927fe87b43193798816eb48eeda93e63a59d8cc900247056c3
; Function: sub_7FFB0DE93330  @ 0x7ffb0de93330
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE


CONST SEGMENT
dword_7FFB0FE99084 dd 2038C9A9h
dword_7FFB0FE99088 dd 78CB1E8Fh
byte_7FFB0FE9908C db 0F5h
byte_7FFB0FE9908D db 47h
dword_7FFB0FED01A4 dd 809D176Eh
dword_7FFB0FED01A8 dd 0EC46EEA6h
dword_7FFB0FED01AC dd 2F80661Ah
dword_7FFB0FED01B0 dd 13588D27h
dword_7FFB0FED01B4 dd 0E972B0CAh
dword_7FFB0FED01B8 dd 87F7E368h
dword_7FFB0FED01BC dd 9B8CC2D5h
dword_7FFB0FED01C0 dd 71BEE006h
dword_7FFB0FED01C4 dd 0B766F7A3h
dword_7FFB0FED01C8 dd 4E951F66h
dword_7FFB0FED01CC dd 5D1DA492h
dword_7FFB0FED01D0 dd 5CC526D6h
dword_7FFB0FED01D4 dd 89A004B5h
dword_7FFB0FED01D8 dd 8F366499h
dword_7FFB0FED01DC dd 88F3935Dh
dword_7FFB0FED01E0 dd 38865FE9h
dword_7FFB0FED01E4 dd 66B1E20Bh
dword_7FFB0FED01E8 dd 7AE7E349h
dword_7FFB0FED01EC dd 0D9D1736h
dword_7FFB0FED01F0 dd 0B40121F1h
dword_7FFB0FED01F4 dd 0B24E49F9h
dword_7FFB0FED01F8 dd 675C2320h
dword_7FFB0FED01FC dd 17335C37h
dword_7FFB0FED0200 dd 0B00B9AFBh
dword_7FFB0FED0204 dd 0A51E1B3Ch
dword_7FFB0FED0208 dd 960A262Dh
dword_7FFB0FED020C dd 0E9567184h
dword_7FFB0FED0210 dd 84A8E658h
dword_7FFB0FED0214 dd 0BE363B61h
dword_7FFB0FED0218 dd 0EAE646A8h
dword_7FFB0FED021C dd 0AC57749Eh
dword_7FFB0FED0220 dd 9B48C112h
dword_7FFB0FED0224 dd 0A4ACF84Ch
dword_7FFB0FED0228 dd 0D2C7C96Eh
dword_7FFB0FED022C dd 0BC89F967h
dword_7FFB0FED0230 dd 0A0BF255Ah
dword_7FFB0FED0234 dd 0E2468A3Ah
dword_7FFB0FED0238 dd 0B3639116h
dword_7FFB0FED023C dd 95240277h
dword_7FFB0FED0240 dd 53598ECAh
dword_7FFB0FED0244 dd 3DE8F76h
dword_7FFB0FED0248 dd 723312B9h
dword_7FFB0FED024C dd 7B01D42Dh
dword_7FFB0FED0250 dd 0F0D69AC3h
dword_7FFB0FED0254 dd 0FA0A1E0Ch
dword_7FFB0FED0258 dd 0A9D6F93Eh
dword_7FFB0FED025C dd 0E20DB19Fh
dword_7FFB0FED0260 dd 900B58C7h
dword_7FFB0FED0264 dd 0FB8BEE90h
dword_7FFB0FED0268 dd 0B7AA1BA9h
dword_7FFB0FED026C dd 81F1EA36h
dword_7FFB0FED0270 dd 3E331985h
dword_7FFB0FED0274 dd 98B3897Eh
dword_7FFB0FED0278 dd 0C81FB33Bh
dword_7FFB0FED027C dd 0DD34AEB7h
dword_7FFB0FED0280 dd 8D4B7EF9h
dword_7FFB0FED0284 dd 6E6BCF75h
dword_7FFB0FED0288 dd 0A789468Ch
dword_7FFB0FED028C dd 0E8093806h
dword_7FFB0FED0290 dd 1235AB8Bh
dword_7FFB0FED0294 dd 0E8B5E6AFh
dword_7FFB0FED0298 dd 1B8FBA03h
dword_7FFB0FED029C dd 0E01E0B1Bh
dword_7FFB0FED02A0 dd 0FADF26C1h
dword_7FFB0FED02A4 dd 0FB51369Ch
dword_7FFB0FED02A8 dd 2E0A4594h
dword_7FFB0FED02AC dd 4522F22Fh
dword_7FFB0FED02B0 dd 0FD1F0F66h
dword_7FFB0FED02B4 dd 0A95EF694h
dword_7FFB0FED02B8 dd 0FDC79A05h
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
; The source table stored target deltas from an unrelated image-base anchor.
; Keep the relocatable fixture table beside its code targets and express every
; entry symbolically so branch relaxation cannot stale the deltas.
jpt_7FFB0DE95647 dd loc_7FFB0DE9564A - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd loc_7FFB0DE9564A - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd loc_7FFB0DE9638A - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd def_7FFB0DE95647 - jpt_7FFB0DE95647
dd loc_7FFB0DE9564A - jpt_7FFB0DE95647
PUBLIC sub_7FFB0DE93330
sub_7FFB0DE93330:
    push r15
    push r14
    push r13
    push r12
    push rsi
    push rdi
    push rbp
    push rbx
    sub rsp, 288h
    mov eax, dword ptr [dword_7FFB0FED01B8]
    mov r8d, eax
    xor r8d, -4C3A5B93h
    add r8d, eax
    xor eax, -7A4DC22Ch
    add eax, r8d
    add eax, -4350ADF6h
    mov dword ptr [rsp+4], eax
    lea r14, [rsp+1A8h]
    lea r15, [rsp+1A0h]
    mov r12d, 71506C3Bh
    mov r13d, 1BACFD70h
    mov eax, -57935AE3h
    lea r9, jpt_7FFB0DE95647
    mov r10d, -3D93FA33h
    jmp loc_7FFB0DE93405
    loc_7FFB0DE93397:
    movzx r8d, byte ptr [rsp+30h]
    xor r11d, r11d
    sub r11b, r8b
    mov byte ptr [rsp+31h], r11b
    mov r8d, dword ptr [dword_7FFB0FED0224]
    lea r11d, [r8-67B6E722h]
    xor r11d, -445A99BBh
    lea esi, [r11+53E52592h]
    xor esi, -5734E8A1h
    lea edi, [rsi-0C97632h]
    add r8d, esi
    add r8d, -68805D54h
    mov ebx, 7AC033CBh
    sub ebx, r8d
    xor ebx, edi
    add ebx, r11d
    lea r8d, [r11+rbx]
    add r8d, 53E52592h
    xor r8d, esi
    nop word ptr [rax+rax+00000000h]
    loc_7FFB0DE93400:
    mov dword ptr [rsp+4], r8d
    loc_7FFB0DE93405:
    mov edi, dword ptr [rsp+4]
    cmp edi, 381CC2A9h
    jg loc_7FFB0DE93530
    cmp edi, 1C6BE034h
    jle loc_7FFB0DE935E0
    cmp edi, 2A45BF97h
    jle loc_7FFB0DE9377B
    cmp edi, 319EFB35h
    jle loc_7FFB0DE9396E
    cmp edi, 3298408Ch
    jle loc_7FFB0DE9421F
    cmp edi, 3298408Dh
    jz loc_7FFB0DE94964
    cmp edi, 33ACEF14h
    jnz loc_7FFB0DE94C41
    mov r8d, dword ptr [rsp+160h]
    lea r11d, [r8+r8*4]
    lea r8d, [r8+r11*2]
    mov dword ptr [rsp+164h], r8d
    mov r8d, dword ptr [rsp+0A0h]
    or r8d, dword ptr [rsp+64h]
    mov dword ptr [rsp+168h], r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, dword ptr [dword_7FFB0FED022C]
    lea r11d, [r8+69F01715h]
    mov esi, r11d
    xor esi, -2B9E931Ah
    lea edi, [rsi+7937B599h]
    xor edi, -25A9994Ch
    mov ebx, 1A985128h
    sub ebx, esi
    xor ebx, r8d
    add ebx, edi
    xor ebx, r11d
    mov dword ptr [rsp+4], ebx
    jmp loc_7FFB0DE93405
    loc_7FFB0DE93530:
    cmp edi, 6380920Bh
    jle loc_7FFB0DE93680
    cmp edi, 6EE1AF74h
    jg loc_7FFB0DE9380E
    cmp edi, 6932E80Dh
    jg loc_7FFB0DE93C75
    cmp edi, 6669CE67h
    jle loc_7FFB0DE94710
    cmp edi, 6669CE68h
    jz loc_7FFB0DE9585E
    cmp edi, 68EF40B1h
    jnz loc_7FFB0DE963DD
    movzx r8d, byte ptr [rsp+0Ch]
    mov r11d, r8d
    add r11d, r11d
    lea r11d, [r11+r11*2]
    mov byte ptr [rsp+38h], r11b
    movzx r11d, byte ptr [rsp+0Ah]
    or r11b, r8b
    movzx r11d, r11b
    lea r11d, [r11+r11*2]
    mov byte ptr [rsp+39h], r11b
    not r8b
    mov byte ptr [rsp+3Ah], r8b
    mov r8d, dword ptr [dword_7FFB0FED0210]
    mov r11d, r8d
    xor r11d, 1B1392ACh
    lea esi, [r11-66FDE2B3h]
    add r11d, r8d
    mov r8d, -7CC7488Bh
    sub r8d, r11d
    jmp loc_7FFB0DE9393D
    loc_7FFB0DE935E0:
    cmp edi, 0E003A2Ch
    jg loc_7FFB0DE93896
    cmp edi, 6EC86CBh
    jg loc_7FFB0DE939F6
    cmp edi, 2DF4490h
    jle loc_7FFB0DE945A2
    cmp edi, 2DF4491h
    jz loc_7FFB0DE95484
    cmp edi, 5B2C9B1h
    jnz loc_7FFB0DE96391
    mov r8d, dword ptr [rsp+54h]
    lea r11d, [r8+r8*2]
    mov dword ptr [rsp+100h], r11d
    and r8d, 17935AE2h
    shl r8d, 2
    mov dword ptr [rsp+104h], r8d
    mov r8d, dword ptr [dword_7FFB0FED0288]
    mov r11d, 562F0C1Ah
    add r8d, r11d
    mov r11d, r8d
    xor r11d, -7AFA6CDDh
    lea esi, [r11+212C34AFh]
    xor esi, r8d
    xor esi, -67FAF15Dh
    add esi, r11d
    mov dword ptr [rsp+4], esi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE93680:
    cmp edi, 500CF653h
    jle loc_7FFB0DE93945
    cmp edi, 5D6C617Dh
    jg loc_7FFB0DE93F68
    cmp edi, 574E3E72h
    jle loc_7FFB0DE94913
    cmp edi, 5BE53D1Ah
    jz loc_7FFB0DE95B98
    cmp edi, 5CD7812Fh
    jnz loc_7FFB0DE9638A
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, dword ptr [rsp+198h]
    sub r8d, dword ptr [rsp+18Ch]
    mov dword ptr [rsp+19Ch], r8d
    mov r8d, dword ptr [dword_7FFB0FED02B4]
    lea r11d, [r8+0C8718A2h]
    xor r11d, -49038B33h
    lea esi, [r11-420C6A1Ch]
    xor esi, 29E17313h
    lea edi, [rsi-7CB93CEh]
    xor edi, r8d
    xor edi, -258BCB3Fh
    add r8d, edi
    add r8d, 0C8718A2h
    sub r8d, r11d
    sub r8d, esi
    jmp loc_7FFB0DE93400
    loc_7FFB0DE9377B:
    cmp edi, 1FBB7D3Dh
    jle loc_7FFB0DE93A96
    cmp edi, 24829C7Ch
    jg loc_7FFB0DE946B4
    cmp edi, 1FBB7D3Eh
    jz loc_7FFB0DE95667
    cmp edi, 242102F7h
    jnz loc_7FFB0DE96400
    movzx r8d, byte ptr [rsp+3Ch]
    lea r8d, [r8+r8*8]
    add r8b, byte ptr [rsp+3Bh]
    sub r8b, byte ptr [rsp+39h]
    sub r8b, byte ptr [rsp+38h]
    mov byte ptr [rsp+3Dh], r8b
    mov r8d, dword ptr [dword_7FFB0FED0244]
    lea r11d, [r8+211170D4h]
    mov esi, r11d
    xor esi, -0B5D4F39h
    mov edi, esi
    add edi, 5F5971EAh
    xor edi, r11d
    xor r11d, 7C144ADAh
    add r8d, r8d
    add r8d, r11d
    add r8d, esi
    add r8d, 3EFD4176h
    xor edi, r8d
    mov dword ptr [rsp+4], edi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE9380E:
    cmp edi, 7AAFDB39h
    jg loc_7FFB0DE93D6F
    cmp edi, 7701FB03h
    jg loc_7FFB0DE947B5
    cmp edi, 6FE5A497h
    jz loc_7FFB0DE958FD
    cmp edi, 75126BB6h
    jnz loc_7FFB0DE963A3
    mov r8d, dword ptr [rsp+54h]
    and r8d, eax
    lea r8d, [r8+r8*2]
    mov r11d, dword ptr [rsp+104h]
    sub r11d, r8d
    mov dword ptr [rsp+108h], r11d
    mov r8d, dword ptr [dword_7FFB0FED0240]
    mov r11d, r8d
    xor r11d, -44B03204h
    lea esi, [r11-2149D5Eh]
    lea edi, [r11-17693661h]
    xor edi, esi
    xor edi, -35D2A16Ch
    sub edi, r11d
    add r8d, edi
    add r8d, -3305E8ACh
    jmp loc_7FFB0DE93400
    loc_7FFB0DE93896:
    cmp edi, 15F65A97h
    jg loc_7FFB0DE93AFF
    cmp edi, 1333380Fh
    jg loc_7FFB0DE94357
    cmp edi, 0E003A2Dh
    jnz loc_7FFB0DE95FF1
    movzx r8d, byte ptr [rsp+2Ch]
    sub r8b, byte ptr [rsp+0Fh]
    sub r8b, byte ptr [rsp+0Eh]
    cmp byte ptr [rsp+1Dh], r8b
    jnz loc_7FFB0DE95D7A
    mov r8, qword ptr [rsp+0D0h]
    lea r11, [r8+1]
    mov qword ptr [rsp+1A0h], r11
    cmp byte ptr [r8+1], 22h
    setz byte ptr [rsp+10h]
    mov r8d, dword ptr [dword_7FFB0FED0204]
    mov r11d, r8d
    xor r11d, -4C31D011h
    lea esi, [r11-283E1220h]
    add r11d, -72E446EDh
    mov edi, r11d
    xor edi, 152B45A5h
    xor r11d, -657DE7C6h
    lea ebx, [r11+r8]
    xor r8d, 60173DCDh
    sub r8d, edi
    add r8d, ebx
    add r8d, r11d
    add r8d, 7F740C92h
    loc_7FFB0DE9393D:
    xor r8d, esi
    jmp loc_7FFB0DE93400
    loc_7FFB0DE93945:
    cmp edi, 4B3CB086h
    jg loc_7FFB0DE93FC2
    cmp edi, 425F710Fh
    jg loc_7FFB0DE94861
    cmp edi, 381CC2AAh
    jnz loc_7FFB0DE94097
    jmp loc_7FFB0DE940D2
    loc_7FFB0DE9396E:
    cmp edi, 2EFA08A9h
    jg loc_7FFB0DE94058
    cmp edi, 2A45BF98h
    jnz loc_7FFB0DE949F6
    mov r8, qword ptr [rsp+70h]
    movzx r11d, byte ptr [rsp+1Ch]
    mov byte ptr [r8], r11b
    inc r8
    mov r11, qword ptr [rsp+268h]
    movzx r11d, byte ptr [r11]
    test r11d, r11d
    jz loc_7FFB0DE95F7C
    cmp r11d, 3Dh
    jnz loc_7FFB0DE96038
    mov r11, qword ptr [rsp+40h]
    mov qword ptr [rsp+218h], r11
    mov qword ptr [rsp+220h], r8
    mov r8d, dword ptr [dword_7FFB0FED0280]
    lea r11d, [r8-235FB89Eh]
    mov esi, r11d
    xor esi, -6DADB723h
    add esi, r8d
    mov r8d, -626F8016h
    sub r8d, esi
    xor r8d, r11d
    jmp loc_7FFB0DE93400
    loc_7FFB0DE939F6:
    cmp edi, 0B62CC81h
    jg loc_7FFB0DE9414C
    cmp edi, 6EC86CCh
    jnz loc_7FFB0DE94A3E
    mov r8d, dword ptr [rsp+154h]
    sub r8d, dword ptr [rsp+150h]
    sub r8d, dword ptr [rsp+14Ch]
    add r8d, dword ptr [rsp+148h]
    add r8d, dword ptr [rsp+140h]
    mov dword ptr [rsp+158h], r8d
    mov r8d, 89204C5h
    sub r8d, dword ptr [rsp+5Ch]
    mov dword ptr [rsp+15Ch], r8d
    mov r8d, dword ptr [dword_7FFB0FED01F0]
    lea r11d, [r8+270E5787h]
    mov esi, r11d
    xor esi, -182148DAh
    mov edi, r11d
    xor edi, -4AB55CDDh
    add edi, esi
    add edi, 4A4EDC9Bh
    xor edi, r11d
    lea r11d, [rsi+rdi]
    add r11d, 4F0CE498h
    xor esi, r8d
    xor esi, r11d
    mov dword ptr [rsp+4], esi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE93A96:
    cmp edi, 1F40B8B4h
    jg loc_7FFB0DE9427C
    cmp edi, 1C6BE035h
    jnz loc_7FFB0DE94E48
    mov r8, qword ptr [rsp+270h]
    movzx r8d, byte ptr [r8]
    test r8d, r8d
    jz loc_7FFB0DE93AC9
    cmp r8d, 3Dh
    jnz loc_7FFB0DE96097
    loc_7FFB0DE93AC9:
    mov r8, qword ptr [rsp+40h]
    mov r11, qword ptr [rsp+0D8h]
    mov qword ptr [rsp+228h], r8
    mov qword ptr [rsp+230h], r11
    mov r8, qword ptr [rsp+230h]
    mov r11, qword ptr [rsp+228h]
    add r11, 2
    jmp loc_7FFB0DE95FE4
    loc_7FFB0DE93AFF:
    cmp edi, 16B08F68h
    jg loc_7FFB0DE943BA
    cmp edi, 15F65A98h
    jnz loc_7FFB0DE94EE6
    movzx r8d, byte ptr [rsp+11h]
    lea r11d, [r8-44h]
    mov byte ptr [rsp+12h], r11b
    add r8b, 0E2h
    mov byte ptr [rsp+13h], r8b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx r8d, byte ptr [rsp+13h]
    add r8b, 83h
    mov byte ptr [rsp+9], r8b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx r8d, byte ptr [rsp+9]
    xor r8b, 0ACh
    mov byte ptr [rsp+0Ch], r8b
    movzx r8d, byte ptr [rsp+12h]
    mov r11d, r8d
    and r11b, 30h
    mov byte ptr [rsp+2Dh], r11b
    or r8b, 0CFh
    mov byte ptr [rsp+2Eh], r8b
    mov r8d, dword ptr [dword_7FFB0FED0218]
    lea r11d, [r8+r8]
    lea esi, [r8-7F1E2391h]
    lea edi, [r8-6DF22C89h]
    mov ebx, edi
    xor ebx, -509E39B9h
    sub r11d, ebx
    xor edi, -0FAAA197h
    add r11d, 0FC9DA18h
    xor r11d, esi
    add r11d, edi
    add r11d, r8d
    add r11d, -6DF22C89h
    jmp loc_7FFB0DE95D6D
    loc_7FFB0DE93C75:
    cmp edi, 6A0A20B7h
    jg loc_7FFB0DE94451
    cmp edi, 6932E80Eh
    jnz loc_7FFB0DE9517A
    movzx r8d, byte ptr [rsp+32h]
    add r8b, byte ptr [rsp+2Dh]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r8b, byte ptr [rsp+11h]
    add r8b, 0A0h
    mov byte ptr [rsp+14h], r8b
    movzx r8d, byte ptr [rsp+9]
    not r8b
    movzx r8d, r8b
    lea r8d, [r8+r8*4]
    mov byte ptr [rsp+33h], r8b
    mov r8d, dword ptr [dword_7FFB0FED01E8]
    lea r11d, [r8-2DF174EFh]
    mov esi, r11d
    xor esi, 37306FD5h
    lea edi, [rsi+532057CFh]
    xor edi, -7CF74CB9h
    lea ebx, [rdi-4C5A6C2Bh]
    xor ebx, 189213DEh
    xor r11d, ebx
    xor r11d, 771B9AB1h
    sub r11d, r8d
    sub r11d, esi
    lea r8d, [r11+rdi]
    add r8d, -4C5A6C2Bh
    add ebx, edi
    sub r8d, ebx
    add r8d, -64E0678Ah
    jmp loc_7FFB0DE93400
    loc_7FFB0DE93D6F:
    cmp edi, 7C603C6Ah
    jg loc_7FFB0DE9454D
    cmp edi, 7AAFDB3Ah
    jnz loc_7FFB0DE95232
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, dword ptr [rsp+58h]
    or r8d, dword ptr [rsp+118h]
    not r8d
    lea r8d, [r8+r8*8]
    mov dword ptr [rsp+11Ch], r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, dword ptr [rsp+50h]
    mov r11d, dword ptr [rsp+58h]
    or r11d, r8d
    not r11d
    add r11d, r11d
    lea r11d, [r11+r11*4]
    mov dword ptr [rsp+120h], r11d
    not r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11d, dword ptr [rsp+58h]
    and r8d, r11d
    not r8d
    lea esi, [r8+r8*4]
    lea r8d, [r8+rsi*2]
    mov dword ptr [rsp+124h], r8d
    mov r8d, dword ptr [rsp+50h]
    not r8d
    and r8d, r11d
    mov dword ptr [rsp+128h], r8d
    mov r8d, dword ptr [dword_7FFB0FED0290]
    xor r8d, r10d
    lea r11d, [r8-4DDF469Ch]
    xor r11d, 7F0D2D52h
    lea esi, 1405B059h[r11*2]
    lea edi, [r11+1405B059h]
    xor edi, 3E3DFF7Eh
    add esi, r8d
    add esi, -3819CE3h
    xor esi, r11d
    add esi, edi
    sub esi, r11d
    add esi, -63A9A450h
    jmp loc_7FFB0DE957FD
    loc_7FFB0DE93F68:
    cmp edi, 621053D2h
    jg loc_7FFB0DE9465A
    cmp edi, 5D6C617Eh
    jnz loc_7FFB0DE953BB
    mov r8d, dword ptr [rsp+17Ch]
    add r8d, dword ptr [rsp+16Ch]
    mov dword ptr [rsp+180h], r8d
    mov r8d, dword ptr [dword_7FFB0FED024C]
    lea r11d, [r8+6DD20AEDh]
    lea esi, [r8+5CCD33C4h]
    xor esi, 1838C6F3h
    xor r11d, -7C8A5CDCh
    sub r11d, esi
    jmp loc_7FFB0DE95477
    loc_7FFB0DE93FC2:
    cmp edi, 4E6E550Dh
    jg loc_7FFB0DE948D4
    cmp edi, 4B3CB087h
    jnz loc_7FFB0DE956C1
    mov r8, qword ptr [rsp+0D0h]
    add r8, 2
    mov qword ptr [rsp+1A8h], r8
    cmp byte ptr [rsp+10h], 0
    mov r8, r15
    cmovnz r8, r14
    mov r8, qword ptr [r8]
    mov qword ptr [rsp+250h], r8
    movzx r8d, byte ptr [r8]
    mov byte ptr [rsp+0Bh], r8b
    movzx r8d, byte ptr [byte_7FFB0FE9908D]
    mov byte ptr [rsp+11h], r8b
    mov r8d, dword ptr [dword_7FFB0FED0214]
    xor r8d, r12d
    lea r11d, [r8-43B2F93Ch]
    xor r11d, 1A8C86Ch
    lea esi, [r11-4CE47AC2h]
    xor esi, 3B4A235h
    add esi, r8d
    mov r8d, r11d
    sub r8d, esi
    add r8d, r11d
    add r8d, 0FA93E93h
    jmp loc_7FFB0DE93400
    loc_7FFB0DE94058:
    cmp edi, 2EFA08AAh
    jnz loc_7FFB0DE93397
    mov r8, qword ptr [rsp+1A8h]
    movzx r11d, byte ptr [rsp+0Bh]
    mov byte ptr [rsp+19h], r11b
    mov byte ptr [rsp+1Ah], 0
    mov dword ptr [rsp+0ACh], 3FFh
    mov qword ptr [rsp+1F8h], r8
    mov qword ptr [rsp+200h], rcx
    loc_7FFB0DE94097:
    mov r8, qword ptr [rsp+200h]
    mov rdi, qword ptr [rsp+1F8h]
    mov r11d, dword ptr [rsp+0ACh]
    movzx ebx, byte ptr [rsp+1Ah]
    sub r11d, 1
    jnb loc_7FFB0DE95045
    mov qword ptr [rsp+208h], r8
    mov qword ptr [rsp+210h], rdi
    mov byte ptr [rsp+1Bh], bl
    loc_7FFB0DE940D2:
    mov r8, qword ptr [rsp+210h]
    mov r11, qword ptr [rsp+208h]
    mov qword ptr [rsp+260h], r8
    mov qword ptr [rsp+258h], r11
    test byte ptr [rsp+1Bh], 1
    jz loc_7FFB0DE954AF
    mov byte ptr [rsp+8], 0
    mov r8d, dword ptr [dword_7FFB0FED01F8]
    mov r11d, r8d
    xor r11d, -4A9478BDh
    mov esi, 4EED7C75h
    sub esi, r11d
    xor esi, r8d
    lea r8d, [r11+0E1A3045h]
    lea edi, [r11-39CB0404h]
    lea ebx, [r11+311D9EBCh]
    xor ebx, edi
    xor ebx, r8d
    xor esi, -6C8D5AF8h
    add esi, r11d
    xor esi, ebx
    mov dword ptr [rsp+4], esi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE9414C:
    cmp edi, 0B62CC82h
    jnz loc_7FFB0DE94A8C
    movzx r8d, byte ptr [rsp+17h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    test r8b, r8b
    jz loc_7FFB0DE95F4B
    mov r8d, dword ptr [dword_7FFB0FED0270]
    lea r11d, [r8+33F72077h]
    xor r11d, 687B85FBh
    lea esi, [r11-47B39107h]
    mov edi, esi
    xor edi, -621EE4CAh
    xor esi, -3D4CA3EBh
    add edi, r8d
    add edi, esi
    lea esi, [r11+rdi]
    add esi, -47B39107h
    neg esi
    add r8d, esi
    add r8d, 33F72077h
    add r8d, r11d
    add r8d, 474CED47h
    jmp loc_7FFB0DE93400
    loc_7FFB0DE9421F:
    cmp edi, 319EFB36h
    jnz loc_7FFB0DE94DE8
    imul r8d, dword ptr [rsp+178h], 0F5h
    sub r8d, dword ptr [rsp+174h]
    sub r8d, dword ptr [rsp+170h]
    mov dword ptr [rsp+17Ch], r8d
    mov r8d, dword ptr [dword_7FFB0FED0278]
    lea r11d, [r8+421DC736h]
    xor r11d, -7531D579h
    add r11d, r8d
    add r11d, 421DC736h
    add r11d, r8d
    mov r8d, -4F431FE0h
    sub r8d, r11d
    jmp loc_7FFB0DE93400
    loc_7FFB0DE9427C:
    cmp edi, 1F40B8B5h
    jnz loc_7FFB0DE94E9C
    mov r8d, dword ptr [rsp+9Ch]
    mov r11d, r8d
    or r11d, 7BE66373h
    lea esi, [r11+r11*4]
    lea r11d, [r11+rsi*2]
    mov dword ptr [rsp+150h], r11d
    mov r11d, r8d
    and r11d, 3BE66373h
    lea r11d, [r11+r11*2]
    and r8d, -7BE66374h
    lea esi, [r8+r8*8]
    lea r8d, [r8+rsi*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r8d, [r8+r11*4]
    mov dword ptr [rsp+154h], r8d
    mov r8d, dword ptr [dword_7FFB0FED029C]
    lea r11d, [r8+1938DE7Ah]
    lea esi, [r8-6E0C9685h]
    xor esi, -441863E4h
    mov edi, 89E3598h
    sub edi, r8d
    xor edi, r11d
    xor edi, esi
    add esi, 3533D1FBh
    xor esi, edi
    jmp loc_7FFB0DE95409
    loc_7FFB0DE94357:
    cmp edi, 13333810h
    jnz loc_7FFB0DE94FBF
    mov r8, qword ptr [rsp+1C8h]
    movzx r11d, byte ptr [rsp+16h]
    mov rsi, qword ptr [rsp+1D0h]
    mov qword ptr [rsp+208h], r8
    mov qword ptr [rsp+210h], rsi
    mov byte ptr [rsp+1Bh], r11b
    mov r8d, dword ptr [dword_7FFB0FED01A4]
    lea r11d, [r8-2FD247CDh]
    sub r8d, r11d
    xor r11d, -3D3E13EAh
    sub r8d, r11d
    add r8d, -65AA616Ch
    mov dword ptr [rsp+4], r8d
    jmp loc_7FFB0DE93405
    loc_7FFB0DE943BA:
    cmp edi, 16B08F69h
    jnz loc_7FFB0DE95008
    mov r8d, dword ptr [rsp+180h]
    sub r8d, dword ptr [rsp+164h]
    mov dword ptr [rsp+68h], r8d
    mov r8d, dword ptr [rsp+4Ch]
    not r8d
    lea r11d, [r8*8]
    sub r11d, r8d
    mov dword ptr [rsp+184h], r11d
    mov r8d, dword ptr [dword_7FFB0FED02A4]
    lea r11d, [r8+453AF919h]
    xor r11d, 29B7E8D3h
    lea esi, [r11+21F09547h]
    mov edi, esi
    xor edi, -746CBE39h
    mov ebx, esi
    xor ebx, 33EF354Fh
    add edi, ebx
    mov ebp, -2C0E7447h
    sub ebp, edi
    xor ebp, ebx
    xor ebp, 526D3D76h
    lea edi, [r8+rbp]
    add edi, 453AF919h
    xor edi, esi
    add r8d, edi
    add r8d, 4D7ED53Fh
    xor r8d, r11d
    jmp loc_7FFB0DE93400
    loc_7FFB0DE94451:
    cmp edi, 6A0A20B8h
    jnz loc_7FFB0DE952B0
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, dword ptr [rsp+68h]
    mov r11d, r8d
    not r11d
    mov esi, dword ptr [rsp+4Ch]
    or r11d, esi
    not r11d
    lea r11d, [r11+r11*8]
    mov dword ptr [rsp+188h], r11d
    mov r11d, esi
    or r11d, r8d
    not r11d
    add r11d, r11d
    lea r11d, [r11+r11*4]
    mov dword ptr [rsp+18Ch], r11d
    and esi, r8d
    not esi
    lea r8d, [rsi+rsi*2]
    mov dword ptr [rsp+190h], r8d
    mov r8d, dword ptr [dword_7FFB0FED02A8]
    lea r11d, [r8-65F11AA0h]
    lea esi, [r8-267B2EE1h]
    mov edi, esi
    xor edi, -320018FFh
    lea ebx, [rdi+70685EE2h]
    xor esi, r11d
    xor esi, 784D6671h
    sub esi, r8d
    sub esi, r8d
    add esi, 8F826EAh
    xor esi, ebx
    sub esi, edi
    sub esi, edi
    add esi, 55C185E6h
    mov dword ptr [rsp+4], esi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE9454D:
    cmp edi, 7C603C6Bh
    jnz loc_7FFB0DE95F91
    mov r8, qword ptr [rsp+40h]
    inc r8
    mov qword ptr [rsp+268h], r8
    mov r8d, dword ptr [dword_7FFB0FED01F4]
    mov r11d, r8d
    xor r11d, 3609846Ah
    lea esi, [r11+1FFCBF5h]
    add r11d, 288ACBBEh
    xor r11d, r8d
    xor r11d, esi
    xor r11d, 28561000h
    sub r11d, esi
    mov dword ptr [rsp+4], r11d
    jmp loc_7FFB0DE93405
    loc_7FFB0DE945A2:
    cmp edi, 1DF4154h
    jnz loc_7FFB0DE95362
    mov r8, qword ptr [rsp+248h]
    mov byte ptr [r8], 0
    mov r8, qword ptr [rsp+0D0h]
    movzx r8d, byte ptr [r8]
    mov byte ptr [rsp+1Dh], r8b
    movzx r8d, byte ptr [byte_7FFB0FE9908C]
    mov byte ptr [rsp+0Eh], r8b
    mov r11d, r8d
    not r11b
    and r11b, 0BFh
    movzx r11d, r11b
    lea esi, [r11*8]
    sub esi, r11d
    mov byte ptr [rsp+1Eh], sil
    mov r11d, r8d
    xor r11b, 0BFh
    movzx r11d, r11b
    lea r11d, [r11+r11*4]
    mov byte ptr [rsp+1Fh], r11b
    and r8b, 40h
    mov byte ptr [rsp+20h], r8b
    mov r8d, dword ptr [dword_7FFB0FED01CC]
    lea r11d, [r8+4DE3F5E9h]
    lea esi, [r8-2C660E54h]
    mov edi, esi
    xor edi, -6052D970h
    xor esi, 2F8A68E1h
    mov ebx, r8d
    sub ebx, edi
    sub ebx, esi
    sub ebx, esi
    add ebx, -1DDFD9C3h
    xor ebx, r11d
    add ebx, r8d
    add r8d, ebx
    add r8d, -64D4D8E8h
    jmp loc_7FFB0DE93400
    loc_7FFB0DE9465A:
    cmp edi, 621053D3h
    jnz loc_7FFB0DE95415
    movzx r8d, byte ptr [rsp+28h]
    sub r8b, byte ptr [rsp+27h]
    mov byte ptr [rsp+29h], r8b
    mov r8d, dword ptr [dword_7FFB0FED01AC]
    mov r11d, r8d
    xor r11d, 3F448EA0h
    lea esi, [r11-1AF60F0Ch]
    mov edi, esi
    xor edi, -70BFAE81h
    xor r11d, esi
    xor esi, 77B5A672h
    xor r8d, 2C9F4F26h
    sub r8d, esi
    add r8d, edi
    xor r8d, r11d
    jmp loc_7FFB0DE93400
    loc_7FFB0DE946B4:
    cmp edi, 24829C7Dh
    jnz loc_7FFB0DE954F4
    mov r8d, dword ptr [rsp+58h]
    and r8d, dword ptr [rsp+50h]
    lea r11d, [r8+r8*4]
    lea r8d, [r8+r11*2]
    mov dword ptr [rsp+12Ch], r8d
    mov r8d, dword ptr [dword_7FFB0FED01C4]
    mov r11d, r8d
    xor r11d, 4CEC461Bh
    lea esi, [r11+3EF15B0Bh]
    lea edi, [r11-4DB266D7h]
    xor edi, -59E4B75Ah
    add edi, r8d
    xor esi, r11d
    xor esi, edi
    mov dword ptr [rsp+4], esi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE94710:
    cmp edi, 6380920Ch
    jnz loc_7FFB0DE955E9
    mov r8d, dword ptr [rsp+168h]
    lea r11d, [r8+r8*4]
    lea r8d, [r8+r11*2]
    mov dword ptr [rsp+16Ch], r8d
    mov r8d, dword ptr [rsp+64h]
    mov r11d, dword ptr [rsp+0A0h]
    mov esi, r11d
    xor esi, r8d
    mov dword ptr [rsp+170h], esi
    mov esi, r8d
    not esi
    and esi, r11d
    lea esi, [rsi+rsi*8]
    mov dword ptr [rsp+174h], esi
    and r11d, r8d
    mov dword ptr [rsp+178h], r11d
    mov r8d, dword ptr [dword_7FFB0FED027C]
    lea r11d, [r8-35A9B0E8h]
    lea esi, [r8-6D8CDBE1h]
    xor esi, r11d
    lea r11d, [r8+49671A6Fh]
    xor esi, r11d
    xor r11d, 5E1FFB80h
    lea edi, [r11-561EF370h]
    lea ebx, [r11+28718F2Ah]
    xor ebx, esi
    xor ebx, r11d
    add ebx, r8d
    xor ebx, edi
    mov dword ptr [rsp+4], ebx
    jmp loc_7FFB0DE93405
    loc_7FFB0DE947B5:
    cmp edi, 7701FB04h
    jnz loc_7FFB0DE9562C
    movzx r8d, byte ptr [rsp+35h]
    sub r8b, byte ptr [rsp+13h]
    mov byte ptr [rsp+0Ah], r8b
    movzx r8d, byte ptr [rsp+0Ch]
    not r8b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or r8b, byte ptr [rsp+0Ah]
    mov byte ptr [rsp+36h], r8b
    mov r8d, dword ptr [dword_7FFB0FED0230]
    mov r11d, r8d
    xor r11d, -2B02626Ch
    mov esi, r8d
    xor esi, -473980C2h
    add esi, r11d
    xor r8d, 42BBCD59h
    mov r11d, r8d
    sub r11d, esi
    add r8d, r11d
    add r8d, 0B11B43Ch
    jmp loc_7FFB0DE93400
    loc_7FFB0DE94861:
    cmp edi, 425F7110h
    jnz loc_7FFB0DE95740
    movzx r8d, byte ptr [rsp+36h]
    not r8b
    movzx r8d, r8b
    add r8d, r8d
    lea r8d, [r8+r8*4]
    mov byte ptr [rsp+37h], r8b
    mov r8d, dword ptr [dword_7FFB0FED0234]
    lea r11d, [r8+0C04BE67h]
    mov esi, r11d
    xor esi, -60A2F939h
    lea edi, [rsi-522A155Bh]
    xor edi, 2147A9A8h
    lea ebx, [rdi+762ABD6Dh]
    xor ebx, -44E1A9CBh
    sub r8d, esi
    sub r8d, ebx
    add r8d, edi
    add r8d, 16FBE461h
    xor edi, r11d
    xor edi, r8d
    mov dword ptr [rsp+4], edi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE948D4:
    cmp edi, 4E6E550Eh
    jnz loc_7FFB0DE95809
    mov r8, qword ptr [rsp+1A0h]
    movzx r11d, byte ptr [rsp+0Bh]
    mov byte ptr [rsp+18h], r11b
    mov dword ptr [rsp+0A8h], 3FFh
    mov qword ptr [rsp+1E8h], r8
    mov qword ptr [rsp+1F0h], rcx
    jmp loc_7FFB0DE9552D
    loc_7FFB0DE94913:
    cmp edi, 500CF654h
    jnz loc_7FFB0DE95943
    movzx r8d, byte ptr [rsp+20h]
    add r8d, r8d
    lea r8d, [r8+r8*2]
    mov byte ptr [rsp+21h], r8b
    mov r8d, dword ptr [dword_7FFB0FED01D4]
    lea r11d, [r8-6032FABEh]
    lea esi, [r8-64CE5397h]
    lea edi, [r8+21161331h]
    xor edi, esi
    xor r11d, r8d
    xor r11d, edi
    add r8d, r11d
    add r8d, -7060AF5Ah
    jmp loc_7FFB0DE93400
    loc_7FFB0DE94964:
    mov r8d, dword ptr [rsp+15Ch]
    add r8d, dword ptr [rsp+134h]
    xor r8d, dword ptr [rsp+138h]
    sub r8d, dword ptr [rsp+158h]
    mov dword ptr [rsp+0A0h], r8d
    mov r11d, dword ptr [rsp+64h]
    not r11d
    or r11d, r8d
    not r11d
    mov dword ptr [rsp+160h], r11d
    mov r8d, dword ptr [dword_7FFB0FED02A0]
    lea r11d, [r8-48B64EA9h]
    mov esi, r11d
    xor esi, -345D7285h
    mov edi, r11d
    xor edi, -4D66256Eh
    mov ebx, r11d
    xor ebx, -3BDAFEBCh
    add edi, ebx
    add edi, ebx
    mov ebx, -316704B6h
    sub ebx, edi
    xor ebx, r11d
    xor ebx, 19E1A8BEh
    add ebx, r8d
    sub ebx, esi
    xor ebx, r11d
    xor ebx, 4ADE3F00h
    mov dword ptr [rsp+4], ebx
    jmp loc_7FFB0DE93405
    loc_7FFB0DE949F6:
    movzx r8d, byte ptr [rsp+2Ah]
    sub r8b, byte ptr [rsp+2Bh]
    add r8b, 42h
    mov byte ptr [rsp+2Ch], r8b
    mov r8d, dword ptr [dword_7FFB0FED01E4]
    lea r11d, [r8+0FBC49F4h]
    mov esi, -637994B6h
    sub esi, r8d
    xor esi, r11d
    xor esi, 715C4A19h
    sub esi, r8d
    sub esi, r8d
    add r8d, esi
    add r8d, 41CB335Fh
    jmp loc_7FFB0DE93400
    loc_7FFB0DE94A3E:
    mov r8, qword ptr [rsp+258h]
    mov r11, qword ptr [rsp+260h]
    mov qword ptr [rsp+0C0h], r11
    mov qword ptr [rsp+0C8h], r8
    mov r8d, dword ptr [dword_7FFB0FED0260]
    lea r11d, [r8-3BD41F4Ah]
    lea esi, [r8+474DBADh]
    xor r11d, 28C30A6Ah
    sub r11d, r8d
    add r11d, 751C4C81h
    xor esi, r8d
    jmp loc_7FFB0DE94EDA
    loc_7FFB0DE94A8C:
    mov r8d, dword ptr [rsp+110h]
    lea r8d, [r8+r8*4]
    mov r11d, dword ptr [rsp+94h]
    mov esi, r11d
    and esi, 7E840BB9h
    lea esi, [rsi+rsi*2]
    and r11d, -7E840BBAh
    lea r11d, [r11+rsi*2]
    sub r11d, r8d
    mov esi, dword ptr [rsp+10Ch]
    lea r8d, [r11+rsi]
    add r8d, -777BD4CDh
    add r11d, esi
    add r11d, -6A1CE51Ah
    mov dword ptr [rsp+98h], r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11d, dword ptr [rsp+98h]
    mov esi, r11d
    xor esi, 8806040h
    xor r11d, -2892E1C6h
    lea edi, [r11+r11]
    lea edi, [rdi+rdi*2]
    mov ebx, r11d
    or ebx, -31729D86h
    mov ebp, r11d
    and ebp, 31729D85h
    lea ebp, [rbp+rbp*2+0]
    and r11d, 0E8D627Ah
    shl r11d, 2
    and esi, -31729D86h
    lea esi, [rsi+rsi*2]
    sub r11d, esi
    lea r11d, [r11+rbp*2]
    add r11d, ebx
    sub r11d, edi
    add r11d, 6BA8276Fh
    xor r11d, r8d
    mov dword ptr [rsp+58h], r11d
    not r11d
    mov dword ptr [rsp+114h], r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, dword ptr [rsp+50h]
    not r8d
    mov dword ptr [rsp+118h], r8d
    mov r8d, dword ptr [dword_7FFB0FED025C]
    mov r11d, r8d
    add r11d, -5F4392C9h
    add r8d, r11d
    add r8d, -6C720A89h
    xor r8d, r11d
    jmp loc_7FFB0DE93400
    loc_7FFB0DE94C41:
    mov r8d, dword ptr [rsp+108h]
    add r8d, dword ptr [rsp+100h]
    add r8d, dword ptr [rsp+0FCh]
    sub r8d, dword ptr [rsp+0F8h]
    add r8d, -0D74214Ch
    mov dword ptr [rsp+90h], r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edi, dword ptr [rsp+90h]
    mov r8d, 5EBC805Eh
    add edi, r8d
    mov dword ptr [rsp+50h], edi
    not edi
    and edi, -6B5012A9h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, dword ptr [rsp+50h]
    mov r11d, r8d
    not r11d
    and r11d, 0B5012A8h
    mov esi, r8d
    xor esi, 6B5012A8h
    lea esi, [rsi+rsi*2]
    mov ebx, r8d
    or ebx, 6B5012A8h
    lea ebx, [rbx+rbx*4]
    mov ebp, r8d
    and ebp, 6B5012A8h
    lea ebp, [rbp+rbp*2+0]
    add ebp, ebp
    and r8d, 14AFED57h
    lea r8d, [rbp+r8*8+0]
    sub r8d, ebx
    sub r8d, esi
    lea r8d, [r8+r11*8]
    add r8d, edi
    mov dword ptr [rsp+94h], r8d
    mov r11d, r8d
    not r11d
    and r11d, -7E840BBAh
    lea esi, [r11*8]
    sub esi, r11d
    mov dword ptr [rsp+10Ch], esi
    xor r8d, -7E840BBAh
    mov dword ptr [rsp+110h], r8d
    mov r8d, dword ptr [dword_7FFB0FED028C]
    mov r11d, r8d
    xor r11d, -54C220CBh
    lea esi, [r11+643212C7h]
    xor esi, 6719835Bh
    add r11d, esi
    add r11d, 22741C7Fh
    xor r11d, r8d
    sub r11d, esi
    mov dword ptr [rsp+4], r11d
    jmp loc_7FFB0DE93405
    loc_7FFB0DE94DE8:
    mov r8d, dword ptr [rsp+144h]
    mov r11d, r8d
    shl r11d, 4
    add r11d, r8d
    mov dword ptr [rsp+148h], r11d
    mov r8d, dword ptr [dword_7FFB0FED0238]
    lea r11d, [r8+624ABE60h]
    lea esi, [r8-7B3CD840h]
    lea edi, [r8-7C755DB0h]
    xor edi, r11d
    lea r11d, [r8-3F9EDBE1h]
    lea ebx, [r8-2F3DAD3Fh]
    xor ebx, r11d
    xor esi, r8d
    xor esi, edi
    xor esi, ebx
    xor esi, 44C56FCAh
    mov dword ptr [rsp+4], esi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE94E48:
    movzx r8d, byte ptr [rsp+29h]
    add r8b, byte ptr [rsp+26h]
    add r8b, byte ptr [rsp+25h]
    sub r8b, byte ptr [rsp+23h]
    sub r8b, byte ptr [rsp+22h]
    add r8b, 0F7h
    mov byte ptr [rsp+2Ah], r8b
    xor r8b, 3Eh
    mov byte ptr [rsp+2Bh], r8b
    mov r8d, dword ptr [dword_7FFB0FED01A8]
    lea r11d, [r8+284A5B6Ch]
    mov esi, -641BA25Ch
    sub esi, r8d
    xor esi, r11d
    add r8d, esi
    add r8d, -7D013515h
    jmp loc_7FFB0DE93400
    loc_7FFB0DE94E9C:
    mov r8d, dword ptr [rsp+68h]
    not r8d
    and r8d, dword ptr [rsp+4Ch]
    mov dword ptr [rsp+194h], r8d
    mov r8d, dword ptr [dword_7FFB0FED02AC]
    lea r11d, [r8-588ED041h]
    mov esi, r8d
    add esi, 6446CE6Ah
    add r8d, esi
    add r8d, 6446CE6Ah
    mov esi, 4602DE02h
    sub esi, r8d
    loc_7FFB0DE94EDA:
    xor esi, r11d
    mov dword ptr [rsp+4], esi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE94EE6:
    movzx r8d, byte ptr [rsp+34h]
    not r8b
    movzx r8d, r8b
    lea r8d, [r8+r8*2]
    movzx r11d, byte ptr [rsp+9]
    movzx ebx, byte ptr [rsp+14h]
    mov esi, ebx
    or sil, r11b
    not sil
    movzx esi, sil
    lea esi, [rsi+rsi*4]
    mov edi, ebx
    xor dil, r11b
    add dil, dil
    not r11b
    and r11b, bl
    shl r11b, 3
    sub r11b, dil
    add r11b, sil
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r11b, r8b
    sub r11b, byte ptr [rsp+33h]
    mov byte ptr [rsp+35h], r11b
    mov r8d, dword ptr [dword_7FFB0FED01D0]
    mov r11d, -15C8CE05h
    add r8d, r11d
    mov r11d, r8d
    xor r11d, -11801517h
    mov esi, r8d
    xor esi, 4FD67EDCh
    sub r11d, r8d
    add r11d, esi
    add r11d, 171878BDh
    xor r11d, r8d
    xor r11d, -4FCBA41Ch
    mov dword ptr [rsp+4], r11d
    jmp loc_7FFB0DE93405
    loc_7FFB0DE94FBF:
    cmp byte ptr [rsp+10h], 0
    jz loc_7FFB0DE95DC8
    mov r8d, dword ptr [dword_7FFB0FED0264]
    lea r11d, [r8-7816DD87h]
    mov esi, r11d
    xor esi, 3726E6C5h
    mov edi, esi
    add edi, -6389D603h
    add r8d, esi
    add r8d, -7BD07951h
    xor r8d, edi
    sub r8d, r11d
    add r8d, esi
    add r8d, -66AA2ADBh
    jmp loc_7FFB0DE93400
    loc_7FFB0DE95008:
    mov r8d, dword ptr [rsp+9Ch]
    not r8d
    add r8d, r8d
    or r8d, 8333918h
    lea r8d, [r8+r8*2]
    mov dword ptr [rsp+14Ch], r8d
    mov r8d, dword ptr [dword_7FFB0FED021C]
    lea r11d, [r8+r8]
    add r11d, r8d
    mov r8d, 2447168Fh
    sub r8d, r11d
    jmp loc_7FFB0DE93400
    loc_7FFB0DE95045:
    movzx esi, byte ptr [rsp+19h]
    test bl, 1
    jz loc_7FFB0DE95E22
    loc_7FFB0DE95053:
    lea rbx, [r8+1]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov byte ptr [r8], sil
    mov qword ptr [rsp+0E0h], rbx
    mov dword ptr [rsp+6Ch], r11d
    mov byte ptr [rsp+0Dh], 0
    loc_7FFB0DE950C0:
    movzx r8d, byte ptr [rsp+0Dh]
    mov r11d, dword ptr [rsp+6Ch]
    mov rsi, qword ptr [rsp+0E0h]
    mov byte ptr [rsp+16h], r8b
    mov dword ptr [rsp+0F4h], r11d
    mov qword ptr [rsp+1C8h], rsi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r8, [rdi+1]
    mov qword ptr [rsp+1D0h], r8
    movzx r8d, byte ptr [rdi+1]
    mov byte ptr [rsp+17h], r8b
    mov r8d, dword ptr [dword_7FFB0FED026C]
    mov r11d, r8d
    xor r11d, 160CFEDAh
    lea esi, [r11-48785C2h]
    mov edi, esi
    xor edi, 17AE0539h
    sub edi, esi
    xor esi, 29FF8940h
    add esi, edi
    add r8d, esi
    add r8d, 6EBDECE5h
    xor r8d, r11d
    jmp loc_7FFB0DE93400
    loc_7FFB0DE9517A:
    movzx r8d, byte ptr [rsp+2Eh]
    not r8b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8b, r8b
    mov byte ptr [rsp+2Fh], r8b
    movzx r8d, byte ptr [rsp+12h]
    and r8b, 0CFh
    mov byte ptr [rsp+30h], r8b
    mov r8d, dword ptr [dword_7FFB0FED0200]
    lea r11d, [r8+4825FD6Eh]
    mov esi, r11d
    xor esi, 1AD79C3h
    lea edi, [rsi+256A9266h]
    xor r8d, edi
    xor edi, -3DAB2B79h
    add edi, -505BC696h
    xor edi, r11d
    xor edi, -78EFE9B0h
    add edi, -3667AA30h
    xor edi, r8d
    sub edi, esi
    add edi, 16860CD5h
    mov dword ptr [rsp+4], edi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE95232:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, qword ptr [rsp+2F0h]
    mov qword ptr [rsp+1D8h], r8
    mov qword ptr [rsp+1E0h], rdx
    mov dword ptr [rsp+0A4h], 0FFh
    jmp loc_7FFB0DE95C3C
    loc_7FFB0DE952B0:
    movzx r8d, byte ptr [rsp+24h]
    not r8b
    movzx r8d, r8b
    lea r8d, [r8+r8*2]
    mov byte ptr [rsp+25h], r8b
    movzx r8d, byte ptr [rsp+0Fh]
    mov r11d, r8d
    xor r11b, 0BBh
    movzx r11d, r11b
    lea esi, [r11*8]
    sub esi, r11d
    mov byte ptr [rsp+26h], sil
    mov r11d, r8d
    and r11b, 44h
    movzx r11d, r11b
    add r11d, r11d
    lea r11d, [r11+r11*2]
    mov byte ptr [rsp+27h], r11b
    and r8b, 3Bh
    add r8b, r8b
    mov byte ptr [rsp+28h], r8b
    mov r8d, dword ptr [dword_7FFB0FED01D8]
    lea r11d, [r8+11E7F8F1h]
    xor r11d, -5B808138h
    lea esi, [r11-38513A73h]
    xor esi, 1E1C0D5h
    lea edi, [rsi-5EF1D116h]
    add r11d, r8d
    add r11d, r8d
    add r11d, 11E7F8F1h
    sub r8d, r11d
    sub r8d, esi
    sub r8d, edi
    xor edi, 69332048h
    sub r8d, edi
    add r8d, 4849CB09h
    mov dword ptr [rsp+4], r8d
    jmp loc_7FFB0DE93405
    loc_7FFB0DE95362:
    mov r8d, dword ptr [rsp+130h]
    add r8d, dword ptr [rsp+54h]
    add r8d, dword ptr [rsp+94h]
    add r8d, dword ptr [rsp+98h]
    mov r11, qword ptr [rsp+40h]
    mov qword ptr [rsp+278h], r11
    mov r11, qword ptr [rsp+0B0h]
    mov qword ptr [rsp+280h], r11
    cmp dword ptr [rsp+4Ch], r8d
    jnz loc_7FFB0DE95E51
    mov r8d, dword ptr [dword_7FFB0FED02B8]
    lea r8d, 53D2A2ABh[r8*2]
    jmp loc_7FFB0DE93400
    loc_7FFB0DE953BB:
    movzx r8d, byte ptr [rsp+9]
    not r8b
    or r8b, byte ptr [rsp+14h]
    mov byte ptr [rsp+34h], r8b
    mov r8d, dword ptr [dword_7FFB0FED0220]
    lea r11d, [r8-71F0DC28h]
    mov esi, r11d
    xor esi, -482F9BF8h
    mov edi, r11d
    xor edi, -1365AA35h
    add esi, edi
    add esi, edi
    add esi, -714239B6h
    add edi, -714239B6h
    add esi, edi
    add esi, -74C5FAB1h
    xor esi, r11d
    loc_7FFB0DE95409:
    sub esi, r8d
    mov dword ptr [rsp+4], esi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE95415:
    mov r8, qword ptr [rsp+1C8h]
    mov r11d, dword ptr [rsp+0F4h]
    movzx ebx, byte ptr [rsp+16h]
    mov rsi, qword ptr [rsp+1D0h]
    movzx edi, byte ptr [rsp+17h]
    mov byte ptr [rsp+19h], dil
    mov byte ptr [rsp+1Ah], bl
    mov dword ptr [rsp+0ACh], r11d
    mov qword ptr [rsp+1F8h], rsi
    mov qword ptr [rsp+200h], r8
    mov r8d, dword ptr [dword_7FFB0FED0268]
    lea r11d, [r8-1B008400h]
    xor r8d, 406E9426h
    sub r8d, r11d
    xor r11d, 7DE3A8D2h
    loc_7FFB0DE95477:
    add r11d, r8d
    mov dword ptr [rsp+4], r11d
    jmp loc_7FFB0DE93405
    loc_7FFB0DE95484:
    mov r8d, dword ptr [dword_7FFB0FED0294]
    mov r11d, -33DA9209h
    xor r8d, r11d
    lea r11d, [r8+17727B9Dh]
    xor r11d, r8d
    xor r11d, 557B1F23h
    mov dword ptr [rsp+4], r11d
    jmp loc_7FFB0DE93405
    loc_7FFB0DE954AF:
    mov r8d, dword ptr [dword_7FFB0FED01FC]
    lea r11d, [r8+70086277h]
    mov esi, r11d
    xor esi, -6786273Dh
    lea edi, [rsi-51DD8593h]
    xor edi, 61B475Ah
    add edi, r8d
    xor edi, r11d
    xor edi, -677DCF8Ah
    lea r8d, [rsi+rdi]
    add r8d, 525367DCh
    xor r8d, r11d
    add r8d, esi
    jmp loc_7FFB0DE93400
    loc_7FFB0DE954F4:
    mov r8, qword ptr [rsp+1B8h]
    mov r11d, dword ptr [rsp+0F0h]
    mov rsi, qword ptr [rsp+1C0h]
    movzx ebx, byte ptr [rsp+3Eh]
    mov byte ptr [rsp+18h], bl
    mov dword ptr [rsp+0A8h], r11d
    mov qword ptr [rsp+1E8h], rsi
    mov qword ptr [rsp+1F0h], r8
    loc_7FFB0DE9552D:
    mov r8, qword ptr [rsp+1F0h]
    mov r11, qword ptr [rsp+1E8h]
    mov esi, dword ptr [rsp+0A8h]
    movzx ebx, byte ptr [rsp+18h]
    mov qword ptr [rsp+88h], r8
    mov qword ptr [rsp+1B0h], r11
    mov byte ptr [rsp+15h], bl
    sub esi, 1
    mov dword ptr [rsp+0ECh], esi
    jnb loc_7FFB0DE955AA
    mov r8d, dword ptr [dword_7FFB0FED01B0]
    lea r11d, [r8+5CE188EAh]
    lea esi, [r8-4CFDB569h]
    xor r11d, 9B91B9Fh
    sub r11d, r8d
    add r11d, r8d
    add r11d, 4775715h
    xor esi, r8d
    xor esi, r11d
    sub esi, r8d
    add esi, 6F89F5CAh
    mov dword ptr [rsp+4], esi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE955AA:
    mov r8d, dword ptr [dword_7FFB0FED0258]
    mov r11d, r8d
    xor r11d, -1A9E633Eh
    lea esi, [r11-16E720D2h]
    mov edi, esi
    xor edi, -7F1044EEh
    lea ebx, [rdi-70A3E303h]
    xor ebx, 4C5AA374h
    sub ebx, esi
    sub ebx, r11d
    xor ebx, r8d
    sub ebx, edi
    mov dword ptr [rsp+4], ebx
    jmp loc_7FFB0DE93405
    loc_7FFB0DE955E9:
    movzx r8d, byte ptr [rsp+3Dh]
    add r8b, byte ptr [rsp+37h]
    cmp byte ptr [rsp+0Bh], r8b
    jnz loc_7FFB0DE95EF7
    mov r8d, dword ptr [dword_7FFB0FED0208]
    mov r11d, r8d
    xor r11d, 5017DE81h
    lea esi, [r11+0DF222EAh]
    xor esi, r8d
    xor esi, 76E5959Ah
    sub esi, r11d
    mov dword ptr [rsp+4], esi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE9562C:
    movzx r8d, byte ptr [rsp+15h]
    add r8d, -0Ah
    cmp r8d, 22h
    ja def_7FFB0DE95647
    movsxd r8, dword ptr [r9+r8*4]
    add r8, r9
    jmp r8
    loc_7FFB0DE9564A:
    mov r8, qword ptr [rsp+88h]
    mov qword ptr [rsp+0B8h], r8
    mov dword ptr [rsp+60h], 0
    jmp loc_7FFB0DE96130
    loc_7FFB0DE95667:
    mov r8d, dword ptr [rsp+194h]
    add r8d, r8d
    mov r11d, dword ptr [rsp+4Ch]
    and r11d, dword ptr [rsp+68h]
    add r11d, r11d
    sub r11d, r8d
    add r11d, dword ptr [rsp+190h]
    mov dword ptr [rsp+198h], r11d
    mov r8d, dword ptr [dword_7FFB0FED02B0]
    mov r11d, r8d
    xor r11d, 34BD90D4h
    sub r11d, r8d
    xor r8d, 539E27C9h
    add r8d, -1E2D174Ch
    xor r11d, r8d
    mov dword ptr [rsp+4], r11d
    jmp loc_7FFB0DE93405
    loc_7FFB0DE956C1:
    mov r8d, dword ptr [rsp+12Ch]
    add r8d, dword ptr [rsp+128h]
    sub r8d, dword ptr [rsp+124h]
    add r8d, dword ptr [rsp+120h]
    add r8d, dword ptr [rsp+11Ch]
    add r8d, dword ptr [rsp+114h]
    sub r8d, dword ptr [rsp+90h]
    mov dword ptr [rsp+130h], r8d
    mov r8d, dword ptr [dword_7FFB0FED01C0]
    lea r11d, [r8-36C982B3h]
    mov esi, r11d
    xor esi, -623FC3E7h
    mov edi, r11d
    xor edi, -14D81E67h
    xor r11d, -7EEEAC90h
    add r11d, edi
    add r11d, r8d
    sub esi, r11d
    add r8d, esi
    add r8d, -173E1D26h
    jmp loc_7FFB0DE93400
    loc_7FFB0DE95740:
    movzx r8d, byte ptr [rsp+0Eh]
    and r8b, 0BFh
    add r8b, byte ptr [rsp+21h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r8b, byte ptr [rsp+1Fh]
    add r8b, byte ptr [rsp+1Eh]
    add r8b, 41h
    mov byte ptr [rsp+0Fh], r8b
    mov r11d, r8d
    not r11b
    movzx r11d, r11b
    lea esi, [r11+r11*2]
    mov byte ptr [rsp+22h], sil
    and r11b, 0BBh
    movzx r11d, r11b
    lea r11d, [r11+r11*2]
    mov byte ptr [rsp+23h], r11b
    or r8b, 0BBh
    mov byte ptr [rsp+24h], r8b
    mov r8d, dword ptr [dword_7FFB0FED01DC]
    lea r11d, [r8-6D853E60h]
    mov esi, 6CBF8DE5h
    sub esi, r8d
    xor esi, r11d
    add esi, -1291C14Bh
    loc_7FFB0DE957FD:
    xor esi, r8d
    mov dword ptr [rsp+4], esi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE95809:
    mov r8, qword ptr [rsp+280h]
    mov r11, qword ptr [rsp+278h]
    add r11, 3
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jmp loc_7FFB0DE95FE4
    loc_7FFB0DE9585E:
    movzx r8d, byte ptr [rsp+0Ah]
    and r8b, byte ptr [rsp+3Ah]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    shl r8b, 2
    mov byte ptr [rsp+3Bh], r8b
    movzx r8d, byte ptr [rsp+0Ah]
    and r8b, byte ptr [rsp+0Ch]
    mov byte ptr [rsp+3Ch], r8b
    mov r8d, dword ptr [dword_7FFB0FED023C]
    mov r11d, r8d
    xor r11d, 34704A22h
    lea esi, [r11-3D7DEF6Bh]
    xor esi, r8d
    sub esi, r11d
    sub esi, r11d
    add esi, 6FD73904h
    mov dword ptr [rsp+4], esi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE958FD:
    movzx r8d, byte ptr [rsp+31h]
    add r8b, byte ptr [rsp+2Fh]
    add r8b, 0CFh
    mov byte ptr [rsp+32h], r8b
    mov r8d, dword ptr [dword_7FFB0FED0228]
    mov r11d, r8d
    xor r11d, -48289618h
    xor r8d, r11d
    add r11d, -35A9EECBh
    xor r11d, r11d
    xor r11d, r8d
    xor r11d, -211A7E1Ah
    mov dword ptr [rsp+4], r11d
    jmp loc_7FFB0DE93405
    loc_7FFB0DE95943:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, dword ptr [rsp+13Ch]
    not r8d
    lea r11d, [r8+r8*4]
    lea r8d, [r8+r11*2]
    mov r11d, dword ptr [rsp+5Ch]
    or r11d, r13d
    lea esi, [r11+r11*4]
    lea r11d, [r11+rsi*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov esi, dword ptr [rsp+5Ch]
    mov edi, esi
    xor edi, 1BACFD70h
    mov ebx, esi
    and ebx, -1BACFD71h
    lea ebx, [rbx+rbx*8]
    and esi, 1BACFD70h
    imul esi, 0F5h
    sub esi, ebx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub esi, edi
    add esi, r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub esi, r8d
    mov dword ptr [rsp+9Ch], esi
    not esi
    mov r8d, esi
    and r8d, -7BE66374h
    lea r11d, [r8*8]
    sub r11d, r8d
    mov dword ptr [rsp+140h], r11d
    and esi, 7BE66373h
    mov dword ptr [rsp+144h], esi
    mov r8d, dword ptr [dword_7FFB0FED020C]
    mov r11d, r8d
    xor r11d, -664346D8h
    xor r8d, r11d
    add r11d, 37632A0Eh
    xor r8d, r11d
    xor r8d, 4791E760h
    sub r8d, r11d
    add r8d, 63AA3D73h
    jmp loc_7FFB0DE93400
    loc_7FFB0DE95B98:
    mov r8d, dword ptr [rsp+19Ch]
    sub r8d, dword ptr [rsp+188h]
    add r8d, dword ptr [rsp+184h]
    mov r11, qword ptr [rsp+40h]
    add r11, 4
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rsi, qword ptr [rsp+70h]
    add rsi, 4
    mov rdi, qword ptr [rsp+0B0h]
    movzx ebx, byte ptr [rsp+3Fh]
    mov byte ptr [rdi], bl
    mov qword ptr [rsp+1D8h], rsi
    mov qword ptr [rsp+1E0h], r11
    mov dword ptr [rsp+0A4h], r8d
    loc_7FFB0DE95C3C:
    mov r8d, dword ptr [rsp+0A4h]
    mov r11, qword ptr [rsp+1E0h]
    mov rsi, qword ptr [rsp+1D8h]
    mov dword ptr [rsp+4Ch], r8d
    mov qword ptr [rsp+40h], r11
    mov qword ptr [rsp+70h], rsi
    movzx r8d, byte ptr [r11]
    mov byte ptr [rsp+1Ch], r8b
    test r8d, r8d
    jz loc_7FFB0DE95CC2
    cmp r8d, 3Dh
    jnz loc_7FFB0DE95CD1
    mov r8, qword ptr [rsp+70h]
    mov r11, qword ptr [rsp+40h]
    mov qword ptr [rsp+78h], r8
    mov qword ptr [rsp+80h], r11
    mov r8d, dword ptr [dword_7FFB0FED01BC]
    lea r11d, [r8-6B193125h]
    add r8d, 29FC3671h
    mov esi, r8d
    xor esi, 4941B3B8h
    add esi, 588CA86Dh
    xor r8d, r11d
    xor r8d, esi
    mov dword ptr [rsp+4], r8d
    jmp loc_7FFB0DE93405
    loc_7FFB0DE95CC2:
    mov r8, qword ptr [rsp+70h]
    mov r11, qword ptr [rsp+40h]
    jmp loc_7FFB0DE95FE4
    loc_7FFB0DE95CD1:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, dword ptr [dword_7FFB0FED0274]
    lea r11d, [r8+245852C3h]
    xor r11d, 470183AAh
    add r11d, r8d
    add r11d, 245852C3h
    add r11d, r8d
    add r11d, -6AF61095h
    loc_7FFB0DE95D6D:
    xor r11d, r8d
    mov dword ptr [rsp+4], r11d
    jmp loc_7FFB0DE93405
    loc_7FFB0DE95D7A:
    mov r8d, dword ptr [dword_7FFB0FED01EC]
    lea r11d, [r8-0BF233D9h]
    mov esi, r11d
    xor esi, -7BD482B3h
    mov edi, r11d
    xor edi, 7B61D398h
    lea ebx, [rdi-0CAEB967h]
    mov ebp, 1BD68CF1h
    sub ebp, edi
    xor ebp, ebx
    xor ebp, 306F786Fh
    sub ebp, edi
    add esi, r8d
    add esi, ebp
    sub esi, r11d
    add esi, 412D4A32h
    mov dword ptr [rsp+4], esi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE95DC8:
    mov r8d, dword ptr [dword_7FFB0FED0248]
    mov r11d, -32C6F8DBh
    xor r8d, r11d
    lea r11d, [r8-1F11A683h]
    lea esi, [r8-776D7A7Ah]
    mov edi, esi
    xor edi, -65D7024Dh
    mov ebx, esi
    xor ebx, -2D97ED04h
    mov ebp, esi
    xor ebp, 22019941h
    xor esi, -75622673h
    sub esi, edi
    sub esi, r8d
    add esi, ebp
    add esi, -2F47EE58h
    xor esi, r11d
    add ebx, r8d
    add ebx, esi
    mov dword ptr [rsp+4], ebx
    jmp loc_7FFB0DE93405
    loc_7FFB0DE95E22:
    movzx ebp, sil
    cmp ebp, 5Bh
    jg loc_7FFB0DE961BA
    cmp ebp, 22h
    jnz loc_7FFB0DE9637C
    mov qword ptr [rsp+0E0h], r8
    mov dword ptr [rsp+6Ch], 0
    mov byte ptr [rsp+0Dh], bl
    jmp loc_7FFB0DE950C0
    loc_7FFB0DE95E51:
    mov r8d, dword ptr [dword_7FFB0FE99088]
    mov dword ptr [rsp+134h], r8d
    lea r11d, [r8+68F0761Ah]
    mov dword ptr [rsp+64h], r11d
    add r8d, 2AAE3842h
    mov dword ptr [rsp+138h], r8d
    xor r8d, -31A1A760h
    mov dword ptr [rsp+5Ch], r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, dword ptr [rsp+5Ch]
    mov r11d, -1BACFD71h
    or r8d, r11d
    mov dword ptr [rsp+13Ch], r8d
    mov r8d, dword ptr [dword_7FFB0FED0298]
    mov r11d, 49D9DD4Eh
    xor r8d, r11d
    jmp loc_7FFB0DE93400
    loc_7FFB0DE95EF7:
    mov r8d, dword ptr [dword_7FFB0FED0250]
    mov r11d, r8d
    xor r11d, 250112B4h
    add r11d, -4E696DEAh
    mov esi, r11d
    xor esi, 30D44D75h
    lea edi, [rsi+5C4FC882h]
    mov ebx, edi
    xor ebx, 0D6DEF45h
    lea ebp, [rbx+3817334Fh]
    add ebx, 4E3DFA44h
    xor r11d, r8d
    xor r11d, ebx
    sub r11d, edi
    sub r11d, esi
    xor r11d, ebp
    mov dword ptr [rsp+4], r11d
    jmp loc_7FFB0DE93405
    loc_7FFB0DE95F4B:
    mov r8d, dword ptr [dword_7FFB0FED0254]
    lea r11d, [r8-1E485D56h]
    xor r11d, 36086A72h
    add r11d, 53B6BB70h
    xor r11d, r8d
    add r11d, r8d
    add r8d, r11d
    add r8d, 639483C0h
    jmp loc_7FFB0DE93400
    loc_7FFB0DE95F7C:
    mov r11, qword ptr [rsp+40h]
    mov qword ptr [rsp+218h], r11
    mov qword ptr [rsp+220h], r8
    loc_7FFB0DE95F91:
    mov r8, qword ptr [rsp+220h]
    mov r11, qword ptr [rsp+218h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc r11
    loc_7FFB0DE95FE4:
    mov qword ptr [rsp+78h], r8
    mov qword ptr [rsp+80h], r11
    loc_7FFB0DE95FF1:
    mov r8, qword ptr [rsp+80h]
    mov r11, qword ptr [rsp+78h]
    mov qword ptr [rsp+0D0h], r8
    mov qword ptr [rsp+248h], r11
    mov r8d, dword ptr [dword_7FFB0FED01C8]
    lea r11d, [r8-0D8CAC4Bh]
    lea esi, [r8+0FEA6B8Eh]
    xor esi, r11d
    xor esi, r8d
    xor esi, 503DA7DDh
    mov dword ptr [rsp+4], esi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE96038:
    mov rsi, qword ptr [rsp+40h]
    add rsi, 2
    mov qword ptr [rsp+270h], rsi
    mov rsi, qword ptr [rsp+70h]
    add rsi, 2
    mov qword ptr [rsp+0D8h], rsi
    mov byte ptr [r8], r11b
    mov r8d, dword ptr [dword_7FFB0FED0284]
    lea r11d, [r8+47DBFEE5h]
    mov esi, r11d
    xor esi, -74BCDB8Eh
    mov edi, r11d
    xor edi, -257E8BA5h
    sub esi, r8d
    add esi, edi
    add esi, -2317F61Ah
    xor esi, r11d
    add esi, r8d
    mov dword ptr [rsp+4], esi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE96097:
    mov r11, qword ptr [rsp+40h]
    mov rsi, qword ptr [rsp+70h]
    add rsi, 3
    mov qword ptr [rsp+0B0h], rsi
    mov rsi, qword ptr [rsp+0D8h]
    mov byte ptr [rsi], r8b
    movzx r8d, byte ptr [r11+3]
    mov byte ptr [rsp+3Fh], r8b
    test r8d, r8d
    jz loc_7FFB0DE960D1
    cmp r8d, 3Dh
    jnz loc_7FFB0DE961DA
    loc_7FFB0DE960D1:
    mov r8, qword ptr [rsp+40h]
    mov r11, qword ptr [rsp+0B0h]
    mov qword ptr [rsp+238h], r8
    mov qword ptr [rsp+240h], r11
    mov r8, qword ptr [rsp+240h]
    mov r11, qword ptr [rsp+238h]
    add r11, 3
    jmp loc_7FFB0DE95FE4
    def_7FFB0DE95647:
    mov r8, qword ptr [rsp+88h]
    movzx r11d, byte ptr [rsp+15h]
    mov byte ptr [r8], r11b
    inc r8
    mov r11d, dword ptr [rsp+0ECh]
    mov qword ptr [rsp+0B8h], r8
    mov dword ptr [rsp+60h], r11d
    loc_7FFB0DE96130:
    mov r8d, dword ptr [rsp+60h]
    mov r11, qword ptr [rsp+0B8h]
    mov dword ptr [rsp+0F0h], r8d
    mov qword ptr [rsp+1B8h], r11
    mov r8, qword ptr [rsp+1B0h]
    lea r11, [r8+1]
    mov qword ptr [rsp+1C0h], r11
    movzx r8d, byte ptr [r8+1]
    mov byte ptr [rsp+3Eh], r8b
    test r8b, r8b
    jz loc_7FFB0DE963BD
    mov r8d, dword ptr [dword_7FFB0FED01B4]
    mov r11d, r8d
    xor r11d, 0D6DFFC8h
    lea esi, [r11+72E8DFD8h]
    xor esi, -0CBEE569h
    lea edi, [rsi-2BD3F851h]
    mov ebx, esi
    sub ebx, edi
    sub ebx, r11d
    add esi, ebx
    add esi, -2BD3F851h
    sub esi, r8d
    lea r8d, [rsi+r11]
    add r8d, 6D149619h
    jmp loc_7FFB0DE93400
    loc_7FFB0DE961BA:
    cmp ebp, 5Ch
    jnz loc_7FFB0DE95053
    mov qword ptr [rsp+0E0h], r8
    mov dword ptr [rsp+6Ch], r11d
    mov byte ptr [rsp+0Dh], 1
    jmp loc_7FFB0DE950C0
    loc_7FFB0DE961DA:
    mov r8d, dword ptr [dword_7FFB0FE99084]
    mov dword ptr [rsp+54h], r8d
    not r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r8d, -57935AE3h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov dword ptr [rsp+0F8h], r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, dword ptr [rsp+54h]
    not r8d
    and r8d, 57935AE2h
    add r8d, r8d
    lea r8d, [r8+r8*2]
    mov dword ptr [rsp+0FCh], r8d
    mov r8d, dword ptr [dword_7FFB0FED01E0]
    mov r11d, r8d
    xor r11d, -5F32F798h
    lea esi, [r11-7457989h]
    lea edi, [r11-315B7B14h]
    mov ebx, edi
    xor ebx, -1DFEC3C9h
    xor edi, -59835FCCh
    add edi, ebx
    sub edi, r8d
    xor edi, esi
    sub edi, r11d
    mov dword ptr [rsp+4], edi
    jmp loc_7FFB0DE93405
    loc_7FFB0DE9637C:
    cmp ebp, 0Ah
    jz loc_7FFB0DE9638A
    cmp ebp, 0Dh
    jnz loc_7FFB0DE95053
    loc_7FFB0DE9638A:
    mov byte ptr [rsp+8], 0
    jmp loc_7FFB0DE96400
    loc_7FFB0DE96391:
    mov rax, qword ptr [rsp+1B0h]
    mov rcx, qword ptr [rsp+88h]
    jmp loc_7FFB0DE963AB
    loc_7FFB0DE963A3:
    mov rax, qword ptr [rsp+250h]
    loc_7FFB0DE963AB:
    mov qword ptr [rsp+0C0h], rax
    mov qword ptr [rsp+0C8h], rcx
    jmp loc_7FFB0DE963DD
    loc_7FFB0DE963BD:
    mov rax, qword ptr [rsp+1B8h]
    mov rcx, qword ptr [rsp+1C0h]
    mov qword ptr [rsp+0C0h], rcx
    mov qword ptr [rsp+0C8h], rax
    loc_7FFB0DE963DD:
    mov rax, qword ptr [rsp+0C8h]
    mov rcx, qword ptr [rsp+0C0h]
    mov byte ptr [rax], 0
    mov rax, qword ptr [rsp+300h]
    mov qword ptr [rax], rcx
    mov byte ptr [rsp+8], 1
    loc_7FFB0DE96400:
    movzx eax, byte ptr [rsp+8]
    add rsp, 288h
    pop rbx
    pop rbp
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    ret
_TEXT ENDS
END

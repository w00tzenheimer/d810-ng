; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: sub_7FFB0DE51120  @ 0x7ffb0de51120
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN __security_check_cookie:PROC
EXTERN sub_7FFB0FA84070:PROC
EXTERN sub_7FFB0FC70C30:PROC
EXTERN sub_7FFB0FDD3740:PROC

CONST SEGMENT
xmmword_7FFB0FE4E280 db 5Bh,44h,6Fh,48h,5Dh,20h,41h,41h,41h,41h,3Ah,20h,0,0,0,0
xmmword_7FFB0FE4E290 db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
xmmword_7FFB0FE4E2A0 db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
xmmword_7FFB0FE4E2B0 db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
xmmword_7FFB0FE4E2C0 db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
xmmword_7FFB0FE4E2D0 db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
xmmword_7FFB0FE4E2E0 db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
xmmword_7FFB0FE4E2F0 db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
MultiByteStr db 0
db 0
__security_cookie dq 77104A6308CEh
qword_7FFB0FE98B48 dq -0CEDE2D63561DE02h
qword_7FFB0FE98B50 dq 37CCD2ABDB93B870h
qword_7FFB0FE98B58 dq -5E592013862A3BF0h
dword_7FFB0FE98B60 dd 706117E6h
dword_7FFB0FE98B64 dd 11468021h
qword_7FFB0FE98B68 dq 4AD33598860FB004h
qword_7FFB0FE98B70 dq -4C7E27F7045642EBh
qword_7FFB0FE98B78 dq -2D69C80D1797B4F8h
qword_7FFB0FE98B80 dq -2AA87045399DDE99h
qword_7FFB0FE98B88 dq -1706ACC7F795DC65h
qword_7FFB0FE98B90 dq 2C0D6C3C9F79F330h
qword_7FFB0FE98B98 dq -3B5F466B52B5DA4Ch
qword_7FFB0FE98BA0 dq 419B4CFE1025BA99h
qword_7FFB0FE98BA8 dq 2AEB23E0B4A95C21h
qword_7FFB0FE98BB0 dq 7C1B18C29AFE2F96h
qword_7FFB0FE98BB8 dq -2C4EAFBA054FBF9Eh
qword_7FFB0FE98BC0 dq -0D3992D4350DCD6Eh
qword_7FFB0FE98BC8 dq 2486DA7B43857C7Ch
qword_7FFB0FE98BD0 dq -59CA341F0E27390Eh
qword_7FFB0FE98BD8 dq 17E52473B6F1337Ch
qword_7FFB0FE98BE0 dq -6F9E93EE7B7C4E88h
qword_7FFB0FE98BE8 dq 3CBF243EB2E9A26Ch
qword_7FFB0FE98BF0 dq -2DC54CAFE6FCEE92h
qword_7FFB0FE98BF8 dq 6C88ED98507CEDD3h
qword_7FFB0FE98C00 dq 2B4C23EF0BEE0601h
qword_7FFB0FE98C08 dq 3DFAEE0B9D09D370h
qword_7FFB0FE98C10 dq 1D514375DFD25018h
qword_7FFB0FE98C18 dq 2A54D056910D830Bh
qword_7FFB0FE98C20 dq 2F19FA80C8B4F91Ch
qword_7FFB0FE98C28 dq 5D6BD9E7A17B8E1Fh
qword_7FFB0FE98C30 dq 32A5D159C09480C8h
qword_7FFB0FE98C38 dq 4489351B4B0FC919h
dword_7FFB0FE98C40 dd 8ABDEAC2h
qword_7FFB0FE98C48 dq 7108C523FAA5660h
qword_7FFB0FE98C50 dq -7781339E1E949175h
qword_7FFB0FE98C58 dq -72C6B383818E85E6h
dword_7FFB0FECEBEC dd 0F942622Dh
dword_7FFB0FECEBF0 dd 22D6756Fh
dword_7FFB0FECEBF4 dd 0B83D2B0Bh
dword_7FFB0FECEBF8 dd 0A96059A8h
dword_7FFB0FECEBFC dd 3D3260ECh
dword_7FFB0FECEC00 dd 8F1F9CBCh
dword_7FFB0FECEC04 dd 1FA2A12Bh
dword_7FFB0FECEC08 dd 34D348B4h
dword_7FFB0FECEC0C dd 616E527Bh
dword_7FFB0FECEC10 dd 4D1B95B4h
dword_7FFB0FECEC14 dd 3F7D1F73h
dword_7FFB0FECEC18 dd 52148B3h
dword_7FFB0FECEC1C dd 0F8043573h
dword_7FFB0FECEC20 dd 733112C9h
dword_7FFB0FECEC24 dd 39ED6235h
dword_7FFB0FECEC28 dd 9B83FF4h
dword_7FFB0FECEC2C dd 0DB00F239h
dword_7FFB0FECEC30 dd 0D3F3E529h
dword_7FFB0FECEC34 dd 0E9421F2Ch
dword_7FFB0FECEC38 dd 4BA10612h
dword_7FFB0FECEC3C dd 39FC1EAFh
dword_7FFB0FECEC40 dd 4AE27477h
dword_7FFB0FECEC44 dd 0CDD8389Ah
dword_7FFB0FECEC48 dd 0C8295858h
dword_7FFB0FECEC4C dd 0C5B0FD75h
dword_7FFB0FECEC50 dd 72F3EF9Bh
dword_7FFB0FECEC54 dd 241CF93Ah
dword_7FFB0FECEC58 dd 97CCAF6Dh
dword_7FFB0FECEC5C dd 1A591E9Ah
dword_7FFB0FECEC60 dd 0B994AC46h
dword_7FFB0FECEC64 dd 0A136226Dh
dword_7FFB0FECEC68 dd 734AC1F3h
dword_7FFB0FECEC6C dd 0B302A962h
dword_7FFB0FECEC70 dd 0E8E5C791h
dword_7FFB0FECEC74 dd 0B5CDA7B0h
dword_7FFB0FECEC78 dd 0BF184BFEh
dword_7FFB0FECEC7C dd 0E54FC67Bh
dword_7FFB0FECEC80 dd 1654C1D9h
dword_7FFB0FECEC84 dd 9C40C463h
dword_7FFB0FECEC88 dd 7A610A31h
dword_7FFB0FECEC8C dd 206DFE96h
dword_7FFB0FECEC90 dd 36FD44C9h
dword_7FFB0FECEC94 dd 61146567h
dword_7FFB0FECEC98 dd 5294872Ch
dword_7FFB0FECEC9C dd 1E5D6554h
dword_7FFB0FECECA0 dd 0DBA8ACFCh
dword_7FFB0FECECA4 dd 490F1BA0h
dword_7FFB0FECECA8 dd 86E3DED5h
dword_7FFB0FECECAC dd 0E1083A87h
dword_7FFB0FECECB0 dd 2AB74418h
dword_7FFB0FECECB4 dd 0AE0C70EDh
dword_7FFB0FECECB8 dd 3E129BCEh
dword_7FFB0FECECBC dd 0F31AA1EFh
dword_7FFB0FECECC0 dd 1449EFB0h
dword_7FFB0FECECC4 dd 0F40B4A9Bh
dword_7FFB0FECECC8 dd 0CF3D863Fh
dword_7FFB0FECECCC dd 0FD3F9000h
dword_7FFB0FECECD0 dd 2C2BE5DEh
dword_7FFB0FECECD4 dd 2B2EDB8Bh
dword_7FFB0FECECD8 dd 0CF73CBDBh
dword_7FFB0FECECDC dd 3D649D67h
dword_7FFB0FECECE0 dd 1E03FA44h
dword_7FFB0FECECE4 dd 9AF331D7h
dword_7FFB0FECECE8 dd 0E63D4958h
dword_7FFB0FECECEC dd 4F30F8F9h
dword_7FFB0FECECF0 dd 13751A50h
dword_7FFB0FECECF4 dd 684586FBh
dword_7FFB0FECECF8 dd 0BE7D33B3h
dword_7FFB0FECECFC dd 572307A8h
dword_7FFB0FECED00 dd 1C7FAB6h
dword_7FFB0FECED04 dd 39827048h
dword_7FFB0FECED08 dd 87DBCFD9h
dword_7FFB0FECED0C dd 6A1D7D2Fh
qword_7FFB0FFA43D0 dq -1
qword_7FFB0FFA43D8 dq -1
qword_7FFB0FFA43E0 dq -1
qword_7FFB0FFA43F0 dq -1
qword_7FFB0FFA43F8 dq -1
qword_7FFB0FFA4400 dq -1
qword_7FFB0FFA4408 dq -1
qword_7FFB0FFA4410 dq -1
qword_7FFB0FFA4418 dq -1
qword_7FFB0FFA4420 dq -1
qword_7FFB0FFA4428 dq -1
qword_7FFB0FFA61C8 dq -1
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC sub_7FFB0DE51120
sub_7FFB0DE51120:
    push r15
    push r14
    push r13
    push r12
    push rsi
    push rdi
    push rbp
    push rbx
    sub rsp, 4C8h
    mov qword ptr [rsp+60h], r8
    mov rax, qword ptr [__security_cookie]
    xor rax, rsp
    mov qword ptr [rsp+4C0h], rax
    mov eax, dword ptr [dword_7FFB0FECEBEC]
    lea ecx, [rax+5E814315h]
    lea edx, [rax-5495AB03h]
    add eax, 788C5937h
    xor eax, edx
    xor eax, ecx
    xor eax, -7BC62DA1h
    mov dword ptr [rsp+30h], eax
    mov r15, 32654ACD41B700EEh
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE5117A:
    mov r8d, dword ptr [rsp+18Ch]
    mov rcx, qword ptr [rsp+530h]
    lea rdx, qword_7FFB0FFA43D0
    call sub_7FFB0FC70C30
    loc_7FFB0DE51196:
    mov eax, dword ptr [dword_7FFB0FECEC10]
    lea ecx, [rax+20DED57Bh]
    mov edx, eax
    xor edx, -60817E92h
    add edx, eax
    add edx, 5DD048A2h
    xor edx, ecx
    add edx, eax
    add eax, 5DD048A2h
    sub edx, eax
    add edx, 70BED990h
    nop word ptr [rax+rax+00000000h]
    loc_7FFB0DE511D0:
    mov dword ptr [rsp+30h], edx
    loc_7FFB0DE511D4:
    mov eax, dword ptr [rsp+30h]
    cmp eax, 49295B9Ch
    jg loc_7FFB0DE512C0
    cmp eax, 2399290Ch
    jg loc_7FFB0DE513C0
    cmp eax, 14A31705h
    jle loc_7FFB0DE515DB
    cmp eax, 1F82EDD2h
    jle loc_7FFB0DE51703
    cmp eax, 20FE0073h
    jle loc_7FFB0DE52AD7
    cmp eax, 20FE0074h
    jz loc_7FFB0DE53377
    cmp eax, 21FF5728h
    jnz loc_7FFB0DE5617E
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+330h]
    mov qword ptr [qword_7FFB0FFA4418], rax
    mov rcx, qword ptr [rsp+530h]
    lea rdx, qword_7FFB0FFA4418
    lea r8, [rsp+440h]
    call sub_7FFB0FC70C30
    jmp loc_7FFB0DE582A5
    loc_7FFB0DE512C0:
    cmp eax, 66683F75h
    jg loc_7FFB0DE51380
    cmp eax, 5705E593h
    jg loc_7FFB0DE51459
    cmp eax, 51800C83h
    jle loc_7FFB0DE5175E
    cmp eax, 557FF7A8h
    jle loc_7FFB0DE5267C
    cmp eax, 557FF7A9h
    jz loc_7FFB0DE53242
    cmp eax, 567B591Dh
    jnz loc_7FFB0DE5553A
    mov rax, qword ptr [rsp+328h]
    lea rax, [rax+rax*2]
    mov rcx, qword ptr [rsp+310h]
    and rcx, qword ptr [rsp+0B8h]
    lea rax, [rcx+rax*2]
    mov rcx, qword ptr [rsp+320h]
    sub rcx, rax
    sub rcx, qword ptr [rsp+318h]
    mov qword ptr [rsp+330h], rcx
    mov eax, dword ptr [dword_7FFB0FECECB4]
    mov ecx, eax
    xor ecx, -72CF7A06h
    lea edx, [rcx-7514DC6Eh]
    mov r8d, -51E73EBFh
    sub r8d, ecx
    xor r8d, eax
    sub r8d, ecx
    sub r8d, ecx
    add r8d, -4E868318h
    xor r8d, edx
    mov dword ptr [rsp+30h], r8d
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE51380:
    cmp eax, 712CC77Eh
    jg loc_7FFB0DE51557
    cmp eax, 6C3DA2F1h
    jle loc_7FFB0DE51944
    cmp eax, 6F0B7067h
    jle loc_7FFB0DE528CC
    cmp eax, 6F0B7068h
    jz loc_7FFB0DE52B89
    cmp eax, 6FC4ECF1h
    jz loc_7FFB0DE51196
    jmp loc_7FFB0DE535AD
    loc_7FFB0DE513C0:
    cmp eax, 389B1B11h
    jg loc_7FFB0DE51670
    cmp eax, 2E9048BDh
    jle loc_7FFB0DE51FEF
    cmp eax, 32800A72h
    jle loc_7FFB0DE52F38
    cmp eax, 32800A73h
    jz loc_7FFB0DE569B3
    cmp eax, 360DBB04h
    jz loc_7FFB0DE582E6
    mov rax, qword ptr [rsp+530h]
    add rax, 11E0h
    mov qword ptr [rsp+208h], rax
    mov rax, qword ptr [rsp+98h]
    cmp byte ptr [rax], 0
    jz loc_7FFB0DE58562
    mov eax, dword ptr [dword_7FFB0FECEC44]
    lea ecx, [rax+176F9742h]
    mov edx, ecx
    xor edx, -3E0DF7ACh
    xor ecx, -76641B80h
    add ecx, eax
    add ecx, 176F9742h
    mov r8d, -55A14D2Bh
    sub r8d, ecx
    xor r8d, eax
    sub r8d, edx
    mov dword ptr [rsp+30h], r8d
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE51459:
    cmp eax, 5EA2A1D8h
    jle loc_7FFB0DE51BE3
    cmp eax, 6183E6F1h
    jle loc_7FFB0DE52907
    cmp eax, 6183E6F2h
    jz loc_7FFB0DE5117A
    cmp eax, 625AD8EDh
    jnz loc_7FFB0DE556A9
    mov rax, qword ptr [rsp+3D8h]
    add rax, qword ptr [rsp+3B0h]
    add rax, qword ptr [rsp+3A8h]
    mov qword ptr [qword_7FFB0FFA43F8], rax
    mov rax, qword ptr [qword_7FFB0FE98B78]
    mov rcx, rax
    mov rdx, 375E88E891671369h
    xor rcx, rdx
    mov rdx, -5947219DDA405008h
    add rdx, rcx
    mov r8, rdx
    mov r9, -339E21628F3593E8h
    xor r8, r9
    mov r9, -32A7C65A718C181Fh
    add r9, r8
    mov r10, -7023CFF9575218A2h
    add r10, r8
    mov r11, 2C04313FD9E0F526h
    add rdx, r11
    add rdx, r10
    xor r9, rax
    xor r9, rdx
    xor r9, r8
    add r9, r10
    xor r9, rcx
    mov qword ptr [qword_7FFB0FFA4400], r9
    mov eax, dword ptr [rsp+178h]
    mov ecx, dword ptr [rsp+17Ch]
    mov r9d, dword ptr [rsp+180h]
    mov r8d, dword ptr [rsp+184h]
    mov dword ptr [rsp+28h], eax
    mov dword ptr [rsp+20h], ecx
    mov rcx, qword ptr [rsp+530h]
    lea rdx, qword_7FFB0FFA43F0
    call sub_7FFB0FC70C30
    jmp loc_7FFB0DE582E6
    loc_7FFB0DE51557:
    cmp eax, 783D72E0h
    jle loc_7FFB0DE51EFC
    cmp eax, 7BF40C04h
    jle loc_7FFB0DE5299F
    cmp eax, 7BF40C05h
    jz loc_7FFB0DE55C7C
    cmp eax, 7F8A42D7h
    jnz loc_7FFB0DE55739
    mov rax, qword ptr [rsp+398h]
    add rax, qword ptr [rsp+368h]
    add rax, qword ptr [rsp+340h]
    mov qword ptr [rsp+78h], rax
    mov rax, qword ptr [rsp+68h]
    not rax
    mov qword ptr [rsp+3A0h], rax
    mov eax, dword ptr [dword_7FFB0FECECDC]
    mov ecx, eax
    xor ecx, 1D4B8ECDh
    lea edx, [rcx-7F0ADDD0h]
    xor edx, 6AB27CF8h
    sub edx, ecx
    sub edx, eax
    sub edx, ecx
    add edx, 901CFB9h
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE515DB:
    cmp eax, 0EEF3EDAh
    jle loc_7FFB0DE51F31
    cmp eax, 0FDC4884h
    jle loc_7FFB0DE52A09
    cmp eax, 0FDC4885h
    jz loc_7FFB0DE53328
    cmp eax, 105D4019h
    jnz loc_7FFB0DE5320A
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FECEC40]
    lea ecx, [rax+12E1C789h]
    xor ecx, 2257592Ch
    add ecx, eax
    mov edx, 5ADBFB1Fh
    sub edx, ecx
    xor edx, eax
    add eax, edx
    add eax, 12E1C789h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE51670:
    cmp eax, 40A9060Bh
    jle loc_7FFB0DE522F4
    cmp eax, 44000D17h
    jle loc_7FFB0DE53154
    cmp eax, 44000D18h
    jz loc_7FFB0DE56A1B
    cmp eax, 45BA2E86h
    jnz loc_7FFB0DE57FCE
    mov rax, qword ptr [rsp+248h]
    xor rax, qword ptr [rsp+240h]
    mov qword ptr [qword_7FFB0FFA4420], rax
    mov rax, qword ptr [qword_7FFB0FE98C50]
    mov qword ptr [rsp+250h], rax
    mov rcx, -2D1E952B854E2BD3h
    xor rax, rcx
    mov qword ptr [rsp+1A8h], rax
    mov eax, dword ptr [dword_7FFB0FECEC6C]
    lea ecx, [rax-22CF68B5h]
    lea edx, [rax+760AD5Fh]
    add eax, 4FA11D52h
    xor edx, -1F6A2671h
    sub edx, eax
    add edx, 6E6618B5h
    xor eax, ecx
    jmp loc_7FFB0DE52468
    loc_7FFB0DE51703:
    cmp eax, 1A331801h
    jle loc_7FFB0DE52B3E
    cmp eax, 1A331802h
    jz loc_7FFB0DE56BB9
    cmp eax, 1D2DFAB0h
    jnz loc_7FFB0DE58562
    mov eax, dword ptr [dword_7FFB0FECECF4]
    lea ecx, [rax-6B31654Eh]
    lea edx, [rax-1E798B7Ah]
    lea r8d, [rax+1FCD6859h]
    xor r8d, 4DEF0AFAh
    sub r8d, eax
    add r8d, 55D8CE0Ch
    xor ecx, eax
    xor ecx, edx
    xor ecx, r8d
    mov dword ptr [rsp+30h], ecx
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE5175E:
    cmp eax, 4E6EACC1h
    jg loc_7FFB0DE523A3
    cmp eax, 49295B9Dh
    jnz loc_7FFB0DE53451
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+3E8h]
    add rax, qword ptr [rsp+418h]
    sub rax, qword ptr [rsp+1E0h]
    mov rcx, 6320E0DABB54AEEDh
    add rax, rcx
    mov qword ptr [rsp+420h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FECECA0]
    mov ecx, eax
    xor ecx, 8D6797Dh
    lea edx, [rcx+46294D90h]
    xor edx, -5850F9ABh
    lea r8d, [rdx+0CFF9EA5h]
    mov r9d, eax
    xor r9d, 3B0B3C3Fh
    add r9d, ecx
    add r9d, 46294D90h
    sub r9d, edx
    sub r9d, ecx
    add r9d, -0A39B372h
    xor r9d, r8d
    lea ecx, [rdx+r9]
    add ecx, 5B1FB893h
    xor ecx, eax
    xor ecx, 479902C4h
    mov dword ptr [rsp+30h], ecx
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE51944:
    cmp eax, 683077DFh
    jg loc_7FFB0DE5240F
    cmp eax, 66683F76h
    jnz loc_7FFB0DE534FA
    mov eax, dword ptr [rsp+44h]
    not eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or eax, -4956448Ah
    lea eax, [rax+rax*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [rsp+44h]
    not ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and ecx, 49564489h
    add ecx, ecx
    mov edx, dword ptr [rsp+44h]
    mov r8d, 49564489h
    and edx, r8d
    add edx, edx
    sub edx, ecx
    add edx, eax
    sub edx, dword ptr [rsp+158h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub edx, dword ptr [rsp+154h]
    add edx, -15BDFC6h
    mov dword ptr [rsp+58h], edx
    mov eax, dword ptr [rsp+48h]
    not eax
    or eax, edx
    not eax
    shl eax, 2
    mov dword ptr [rsp+15Ch], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+48h]
    mov ecx, dword ptr [rsp+58h]
    mov edx, ecx
    or edx, eax
    add edx, edx
    mov dword ptr [rsp+160h], edx
    xor ecx, eax
    mov dword ptr [rsp+164h], ecx
    mov eax, dword ptr [dword_7FFB0FECEC90]
    lea ecx, [rax+686F5288h]
    lea edx, [rax-70C78107h]
    xor ecx, eax
    sub eax, edx
    sub eax, edx
    add eax, 170FE733h
    jmp loc_7FFB0DE5829A
    loc_7FFB0DE51BE3:
    cmp eax, 5C35E1ADh
    jg loc_7FFB0DE52473
    cmp eax, 5705E594h
    jnz loc_7FFB0DE52581
    mov rax, qword ptr [rsp+230h]
    mov eax, dword ptr [rax+8]
    mov dword ptr [rsp+114h], eax
    mov eax, dword ptr [dword_7FFB0FE98C40]
    mov dword ptr [rsp+118h], eax
    add eax, 163DD125h
    mov dword ptr [rsp+11Ch], eax
    xor eax, -4137A324h
    mov dword ptr [rsp+90h], eax
    or eax, -2149035Fh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [rsp+90h]
    lea edx, [rcx+rcx]
    mov r8d, ecx
    and r8d, 2149035Eh
    and ecx, -2149035Fh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ecx, [rcx+rcx*2]
    lea ecx, [rcx+r8*2]
    not edx
    add edx, ecx
    lea ecx, [rax+rdx]
    inc ecx
    mov dword ptr [rsp+120h], ecx
    add eax, edx
    add eax, -63D6FB4Fh
    mov dword ptr [rsp+40h], eax
    not eax
    and eax, 1E62BC13h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+124h], eax
    mov eax, dword ptr [rsp+40h]
    not eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and eax, 619D43ECh
    add eax, eax
    mov dword ptr [rsp+128h], eax
    mov eax, dword ptr [rsp+40h]
    not eax
    add eax, eax
    or eax, 3CC57826h
    mov dword ptr [rsp+12Ch], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+40h]
    not eax
    or eax, -1E62BC14h
    mov dword ptr [rsp+130h], eax
    mov eax, dword ptr [dword_7FFB0FECEC58]
    lea ecx, [rax+1E1B727Fh]
    mov edx, ecx
    xor edx, 3AE4AC88h
    add edx, -12CBD1E6h
    xor edx, 8318C1Ah
    sub edx, ecx
    xor ecx, -469E901Bh
    sub edx, eax
    sub edx, ecx
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE51EFC:
    cmp eax, 71D527C1h
    jg loc_7FFB0DE52530
    cmp eax, 712CC77Fh
    jnz loc_7FFB0DE55048
    mov eax, dword ptr [rsp+110h]
    mov dword ptr [rsp+94h], eax
    mov qword ptr [rsp+1F0h], 0
    jmp loc_7FFB0DE534A8
    loc_7FFB0DE51F31:
    cmp eax, 6987B52h
    jg loc_7FFB0DE525DF
    cmp eax, 41156Fh
    jnz loc_7FFB0DE52581
    mov edx, dword ptr [rsp+0D4h]
    mov eax, edx
    not eax
    mov ecx, dword ptr [rsp+0DCh]
    mov r8d, ecx
    or r8d, eax
    not r8d
    lea r8d, [r8+r8*8]
    mov dword ptr [rsp+0E4h], r8d
    mov r8d, ecx
    or r8d, edx
    not r8d
    add r8d, r8d
    lea r8d, [r8+r8*4]
    mov dword ptr [rsp+0E8h], r8d
    and edx, ecx
    mov dword ptr [rsp+0F4h], edx
    not edx
    lea edx, [rdx+rdx*2]
    mov dword ptr [rsp+0ECh], edx
    and eax, ecx
    add eax, eax
    mov dword ptr [rsp+0F0h], eax
    mov eax, dword ptr [dword_7FFB0FECEC14]
    lea ecx, [rax+21A65547h]
    xor ecx, -617FE767h
    lea edx, [rcx-6A63CD64h]
    xor edx, 1C3751F4h
    lea r8d, [rdx+451C7CC1h]
    xor r8d, -1B435CD1h
    add r8d, ecx
    add r8d, -6A63CD64h
    sub r8d, edx
    xor r8d, ecx
    add r8d, eax
    mov dword ptr [rsp+30h], r8d
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE51FEF:
    cmp eax, 2580E5D4h
    jg loc_7FFB0DE52B7E
    cmp eax, 2399290Dh
    jnz loc_7FFB0DE56BF2
    mov rax, qword ptr [rsp+60h]
    add rax, 260h
    mov qword ptr [rsp+190h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+190h]
    mov eax, dword ptr [rax]
    mov dword ptr [rsp+0CCh], eax
    mov eax, dword ptr [dword_7FFB0FE98B60]
    lea ecx, [rax+4C96BCB6h]
    mov dword ptr [rsp+80h], ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [rsp+80h]
    mov edx, -6B5449EAh
    add ecx, edx
    mov edx, ecx
    or edx, 480821DEh
    lea r8d, [rdx+rdx*2]
    not edx
    lea r9d, [rdx*8]
    sub r9d, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and ecx, 480821DEh
    lea ecx, [rcx+r8*2]
    add ecx, r9d
    mov edx, -7
    sub edx, ecx
    mov dword ptr [rsp+0D0h], edx
    mov edx, 0F60FF69h
    sub edx, ecx
    mov dword ptr [rsp+4Ch], edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [rsp+4Ch]
    mov edx, 28979756h
    add ecx, edx
    mov dword ptr [rsp+0D4h], ecx
    xor ecx, 2C890339h
    mov dword ptr [rsp+0D8h], ecx
    mov ecx, eax
    or ecx, -4993452Fh
    mov edx, eax
    not edx
    and edx, 366CBAD1h
    and eax, -4993452Fh
    lea eax, [rax+rax*2]
    lea eax, [rax+rdx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add eax, ecx
    add eax, -6CD975A2h
    mov dword ptr [rsp+0DCh], eax
    not eax
    lea ecx, [rax*8]
    sub ecx, eax
    mov dword ptr [rsp+0E0h], ecx
    mov eax, dword ptr [dword_7FFB0FECEC24]
    mov ecx, eax
    xor ecx, -16A690CBh
    mov edx, eax
    xor edx, 715C2FF5h
    add edx, ecx
    sub edx, eax
    add edx, 20C91CE4h
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE522F4:
    cmp eax, 3FD7701Eh
    jg loc_7FFB0DE52EF3
    cmp eax, 389B1B12h
    jnz loc_7FFB0DE56C4F
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+208h]
    mov rax, qword ptr [rax]
    mov qword ptr [rsp+230h], rax
    test rax, rax
    jz loc_7FFB0DE5320A
    mov eax, dword ptr [dword_7FFB0FECEC0C]
    lea ecx, [rax+26C07159h]
    xor ecx, 57D0DBE8h
    add ecx, 608AF68Ch
    xor ecx, -0E2D5686h
    add eax, ecx
    add eax, 443BEB67h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE523A3:
    cmp eax, 4E6EACC2h
    jnz loc_7FFB0DE51196
    mov rax, qword ptr [rsp+0A0h]
    xor rax, qword ptr [rsp+70h]
    not rax
    add rax, rax
    mov qword ptr [rsp+380h], rax
    mov eax, dword ptr [dword_7FFB0FECECD0]
    mov ecx, eax
    xor ecx, 722A6159h
    lea edx, [rcx-7F8DAF9Bh]
    xor edx, 38486154h
    lea r8d, [rdx+71551112h]
    mov r9d, edx
    sub r9d, eax
    add r9d, -4C6096C2h
    xor r9d, r8d
    sub r9d, edx
    lea eax, [r9+rcx]
    add eax, 6D7D1F32h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE5240F:
    cmp eax, 683077E0h
    jnz loc_7FFB0DE55084
    mov eax, dword ptr [rsp+48h]
    not eax
    and eax, dword ptr [rsp+58h]
    mov dword ptr [rsp+168h], eax
    mov eax, dword ptr [dword_7FFB0FECEC20]
    lea ecx, [rax-27F8CEFh]
    xor ecx, -13F78C8Fh
    lea edx, [rcx+7C4C5331h]
    lea r8d, [rcx+5553F096h]
    xor r8d, -26A02773h
    add eax, -6F527D37h
    xor eax, r8d
    add eax, 4FA052CBh
    xor eax, ecx
    sub eax, r8d
    add eax, -468CDA57h
    loc_7FFB0DE52468:
    xor eax, edx
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE52473:
    cmp eax, 5C35E1AEh
    jz loc_7FFB0DE5816F
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FECEC74]
    lea ecx, [rax+58C3943Fh]
    mov edx, ecx
    xor edx, -49A668BFh
    add edx, 6CDD203Bh
    mov r8d, edx
    xor r8d, 4687A6C5h
    lea r9d, [r8-59FE3181h]
    xor r9d, 30A1ECBAh
    sub r9d, ecx
    add r9d, eax
    mov eax, edx
    xor eax, r8d
    xor eax, r9d
    xor eax, -5E362B6h
    add eax, r8d
    add eax, -59FE3181h
    jmp loc_7FFB0DE531FF
    loc_7FFB0DE52530:
    cmp eax, 71D527C2h
    jnz loc_7FFB0DE5539B
    mov rax, qword ptr [rsp+300h]
    mov qword ptr [rsp+1F8h], rax
    mov eax, dword ptr [dword_7FFB0FECEC78]
    lea ecx, [rax+21646FFBh]
    lea edx, [rax+3107B469h]
    lea r8d, [rax+1F67FA07h]
    xor r8d, edx
    lea edx, [rax+5902655Fh]
    xor edx, eax
    xor edx, ecx
    sub edx, eax
    add edx, -28C3EFB0h
    xor edx, r8d
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE52581:
    mov rax, qword ptr [rsp+38h]
    lea rcx, [rax+4]
    mov qword ptr [rsp+338h], rcx
    movzx ecx, byte ptr [rax+7]
    mov dword ptr [rsp+178h], ecx
    movzx eax, byte ptr [rax+6]
    mov byte ptr [rsp+37h], al
    mov eax, dword ptr [dword_7FFB0FECECC8]
    mov ecx, eax
    xor ecx, 249339E3h
    lea edx, [rcx+3C235034h]
    mov r8d, -7E8A4Dh
    sub r8d, ecx
    xor r8d, edx
    sub r8d, ecx
    add r8d, 331CC267h
    loc_7FFB0DE525CF:
    xor r8d, ecx
    add r8d, eax
    mov dword ptr [rsp+30h], r8d
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE525DF:
    cmp eax, 6987B53h
    jnz loc_7FFB0DE55466
    mov rcx, qword ptr [rsp+530h]
    lea rax, [rcx+953h]
    mov qword ptr [rsp+98h], rax
    cmp byte ptr [rcx+953h], 0
    jz loc_7FFB0DE583D7
    mov rax, qword ptr [rsp+530h]
    mov rax, qword ptr [rax+11E0h]
    mov qword ptr [rsp+3E0h], rax
    test rax, rax
    jz loc_7FFB0DE584D8
    mov eax, dword ptr [dword_7FFB0FECECEC]
    mov ecx, eax
    xor ecx, -65972999h
    mov edx, eax
    xor edx, 7FAD736Bh
    lea r8d, [rdx+rax]
    add r8d, -63C761AFh
    sub r8d, ecx
    add r8d, -75D0D44Fh
    xor r8d, eax
    add edx, -63C761AFh
    xor edx, -1E73A369h
    xor r8d, 0F8DE3F1h
    sub r8d, edx
    mov dword ptr [rsp+30h], r8d
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE5267C:
    cmp eax, 51800C84h
    jnz loc_7FFB0DE557D4
    mov rax, qword ptr [qword_7FFB0FE98C48]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, rax
    not rcx
    lea rcx, [rcx+rcx*2]
    mov rdx, rax
    mov rbx, 5E90FCF0FBAE2E4Dh
    or rdx, rbx
    not rdx
    lea rdx, [rdx+rdx*2]
    mov r8, rax
    mov r11, -5E90FCF0FBAE2E4Eh
    or r8, r11
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not r8
    lea r8, [r8+r8*2]
    mov r9, rax
    xor r9, r11
    lea r10, [r9*8]
    sub r10, r9
    add r10, r8
    mov r8, rax
    and r8, rbx
    add r8, r8
    lea r8, [r8+r8*2]
    mov r9, rax
    and r9, r11
    add r9, r9
    sub r9, r8
    add r9, r10
    sub r9, rdx
    sub r9, rcx
    mov rcx, 73BD50D549E9E274h
    add rcx, r9
    mov qword ptr [rsp+240h], rcx
    mov rcx, 2CA0DF082B5F8327h
    add rcx, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, -70545055CC5C9292h
    sub rdx, r9
    xor rdx, rcx
    add rdx, rax
    mov qword ptr [rsp+248h], rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FECEC68]
    mov ecx, eax
    xor ecx, -63177C1Fh
    add ecx, eax
    mov edx, 55570DD9h
    sub edx, ecx
    xor edx, eax
    xor edx, -3B65195Fh
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE528CC:
    cmp eax, 6C3DA2F2h
    jnz loc_7FFB0DE558DB
    mov eax, dword ptr [dword_7FFB0FECEC04]
    mov ecx, eax
    xor ecx, -454E6BA5h
    add ecx, -61A3EA72h
    xor ecx, eax
    xor eax, -67FCBD0Fh
    lea edx, [rax-46E3358Ch]
    xor edx, eax
    xor edx, ecx
    xor edx, -0BE9B550h
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE52907:
    cmp eax, 5EA2A1D9h
    jnz loc_7FFB0DE55D38
    mov rax, qword ptr [rsp+3B8h]
    not rax
    add rax, rax
    lea rax, [rax+rax*2]
    mov qword ptr [rsp+3C0h], rax
    mov rax, qword ptr [rsp+68h]
    not rax
    mov rcx, qword ptr [rsp+78h]
    or rcx, rax
    lea rdx, [rcx+rcx*4]
    lea rcx, [rcx+rdx*2]
    mov qword ptr [rsp+3C8h], rcx
    mov qword ptr [rsp+3D0h], rax
    mov eax, dword ptr [dword_7FFB0FECECE8]
    mov ecx, eax
    xor ecx, 3B61590Ch
    lea edx, [rcx+558C5643h]
    lea r8d, [rcx+2A126A1Ch]
    lea r9d, [rcx+rdx]
    add r9d, 5A9A6289h
    xor r9d, r8d
    xor r9d, 7AE60E93h
    sub r9d, eax
    xor eax, 27AEA1F5h
    sub r9d, eax
    xor r9d, ecx
    sub r9d, edx
    mov dword ptr [rsp+30h], r9d
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE5299F:
    cmp eax, 783D72E1h
    jnz loc_7FFB0DE55FA7
    mov eax, dword ptr [rsp+44h]
    not eax
    and eax, 36A9BB76h
    add eax, eax
    lea eax, [rax+rax*4]
    mov dword ptr [rsp+158h], eax
    mov eax, dword ptr [dword_7FFB0FECECBC]
    mov ecx, eax
    xor ecx, 190C090Ah
    lea edx, [rcx-5D577955h]
    lea r8d, [rcx-3B8325C7h]
    lea r9d, [rcx-7F822B0Eh]
    xor eax, -73F31EE9h
    add eax, ecx
    add eax, 1173B547h
    xor eax, r9d
    xor eax, edx
    add eax, ecx
    add eax, 4C1F9F47h
    xor eax, r8d
    add eax, ecx
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE52A09:
    cmp eax, 0EEF3EDBh
    jnz loc_7FFB0DE560CA
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+4Ch]
    mov ecx, eax
    not ecx
    mov edx, dword ptr [rsp+84h]
    and ecx, edx
    shl ecx, 3
    mov dword ptr [rsp+108h], ecx
    and edx, eax
    imul eax, edx, 0F5h
    mov dword ptr [rsp+10Ch], eax
    mov eax, dword ptr [dword_7FFB0FECEC34]
    lea ecx, [rax-251F1934h]
    mov edx, ecx
    xor edx, -6BECD1BBh
    xor ecx, 16AC661Fh
    add ecx, eax
    xor ecx, edx
    add edx, 3C2CE24Fh
    xor edx, ecx
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE52AD7:
    cmp eax, 1F82EDD3h
    jnz loc_7FFB0DE56297
    mov rax, qword ptr [rsp+0A0h]
    mov qword ptr [rsp+388h], rax
    mov rcx, qword ptr [rsp+70h]
    not rcx
    and rcx, rax
    mov qword ptr [rsp+390h], rcx
    mov eax, dword ptr [dword_7FFB0FECEC84]
    lea ecx, [rax+113CB1F3h]
    mov edx, ecx
    xor edx, 54B0FE12h
    lea r8d, [rdx-667A3D58h]
    xor r8d, -59A5CCA1h
    sub r8d, ecx
    sub r8d, edx
    add eax, r8d
    add eax, 497807B2h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE52B3E:
    cmp eax, 14A31706h
    jnz loc_7FFB0DE56ABF
    mov qword ptr [rsp+430h], 0
    mov eax, dword ptr [dword_7FFB0FECED04]
    lea ecx, [rax+455E5C2Ah]
    add eax, -6481EDAh
    xor ecx, eax
    xor ecx, 229D741Eh
    add eax, ecx
    add eax, -7F013EF8h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE52B7E:
    cmp eax, 2580E5D5h
    jnz loc_7FFB0DE56D2B
    loc_7FFB0DE52B89:
    mov rax, qword ptr [rsp+60h]
    mov eax, dword ptr [rax+264h]
    mov dword ptr [rsp+18Ch], eax
    mov rdx, qword ptr [qword_7FFB0FE98B48]
    mov rax, 464055CA699985C1h
    add rax, rdx
    mov rcx, -175DAB701849A743h
    add rdx, rcx
    mov rcx, rdx
    not rcx
    lea r8, [rcx*8]
    sub r8, rcx
    mov rcx, rdx
    mov r14, -3F7A508814AA4232h
    or rcx, r14
    not rcx
    lea r9, [rcx+rcx*8]
    mov rcx, rdx
    mov r11, 3F7A508814AA4231h
    or rcx, r11
    not rcx
    add rcx, rcx
    lea r10, [rcx+rcx*4]
    mov rcx, rdx
    and rcx, r11
    mov r11, rcx
    not r11
    lea r11, [r11+r11*2]
    mov rbx, rdx
    and rbx, r14
    add rbx, rbx
    add rcx, rcx
    sub rcx, rbx
    add rcx, r11
    sub rcx, r10
    sub rcx, r9
    add rcx, r8
    mov r8, rcx
    mov r11, 2D1BCAB88C604328h
    or r8, r11
    lea r9, [r8+r8*2]
    not r8
    lea r10, [r8*8]
    sub r10, r8
    mov r8, rcx
    and r8, r11
    lea r9, [r8+r9*2]
    add r9, r10
    mov r8, -7
    sub r8, r9
    mov r10, 7BD7F9AD89288F70h
    sub r10, r9
    mov r9, r10
    mov r11, -34E2AFEF247537A3h
    xor r9, r11
    mov r11, r10
    sub r11, rdx
    mov rdx, 39D5A5B58A18C22h
    add r11, rdx
    mov rdx, 34E2AFEF247537A2h
    xor r10, rdx
    lea rdx, [r10+r10*2]
    mov rbx, r11
    or rbx, r10
    mov r14, r11
    or r14, r9
    and r10, r11
    lea r10, [r10+r10*2]
    and r9, r11
    sub r10, r9
    add r10, r11
    not r14
    lea r9, [r14+r14*2]
    add r9, rbx
    add r9, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r9, rdx
    inc r9
    xor r8, rax
    xor r8, r9
    sub r8, rcx
    mov qword ptr [qword_7FFB0FFA43D0], r8
    mov rax, qword ptr [qword_7FFB0FE98B50]
    mov qword ptr [rsp+3E8h], rax
    mov rcx, 34273C0CC22A2E01h
    xor rax, rcx
    mov qword ptr [rsp+1E0h], rax
    mov rcx, rax
    or rcx, r15
    not rcx
    add rcx, rcx
    mov qword ptr [rsp+3F0h], rcx
    mov rcx, -32654ACD41B700EFh
    or rax, rcx
    not rax
    mov qword ptr [rsp+3F8h], rax
    mov eax, dword ptr [dword_7FFB0FECECF8]
    lea ecx, [rax-7A38EE3Bh]
    mov edx, ecx
    xor edx, -6562D7DEh
    mov r8d, ecx
    xor ecx, 11F0DFD4h
    lea r9d, [rcx-261E05E8h]
    add ecx, edx
    xor r9d, -3C546E3Ah
    add ecx, r9d
    xor r8d, -1373BB9Fh
    sub r8d, ecx
    add eax, r8d
    add eax, 480178E8h
    xor eax, -688EC9A6h
    mov dword ptr [rsp+30h], eax
    mov qword ptr [rsp+400h], 0
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE52EF3:
    cmp eax, 3FD7701Fh
    jnz loc_7FFB0DE57DE2
    mov rax, qword ptr [rsp+2A0h]
    mov qword ptr [qword_7FFB0FFA4428], rax
    mov r8, qword ptr [rsp+238h]
    mov rcx, qword ptr [rsp+530h]
    lea rdx, qword_7FFB0FFA4420
    call sub_7FFB0FC70C30
    mov rax, qword ptr [rsp+200h]
    mov eax, dword ptr [rax]
    jmp loc_7FFB0DE55C83
    loc_7FFB0DE52F38:
    cmp eax, 2E9048BEh
    jnz loc_7FFB0DE580D0
    mov rax, qword ptr [rsp+2F8h]
    sub rax, qword ptr [rsp+2F0h]
    sub rax, qword ptr [rsp+2E8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor rax, qword ptr [rsp+2E0h]
    mov rcx, qword ptr [rsp+1D0h]
    mov rdx, rcx
    not rdx
    or rdx, rax
    not rdx
    lea rdx, [rdx+rdx*2]
    or rcx, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not rcx
    shl rcx, 2
    mov r8, qword ptr [rsp+1D0h]
    mov r9, r8
    not r9
    and r9, rax
    mov r10, r9
    not r10
    add r9, r9
    and rax, r8
    lea rax, [r9+rax*2]
    sub r10, rax
    sub r10, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r10, rdx
    add r10, -3
    mov qword ptr [qword_7FFB0FFA61C8], r10
    mov rdx, qword ptr [rsp+2C0h]
    mov rcx, qword ptr [rsp+2C8h]
    mov eax, dword ptr [rsp+13Ch]
    mov r8d, dword ptr [rsp+140h]
    mov dword ptr [rsp+28h], eax
    mov dword ptr [rsp+20h], r8d
    lea r8, qword_7FFB0FFA4408
    lea r9, qword_7FFB0FFA61C8
    call sub_7FFB0FA84070
    mov rax, qword ptr [rsp+98h]
    cmp byte ptr [rax], 0
    jz loc_7FFB0DE582A5
    mov eax, dword ptr [dword_7FFB0FECECA8]
    lea ecx, [rax+0EAC02B5h]
    mov edx, ecx
    xor edx, -549D8C75h
    mov r8d, ecx
    xor r8d, 11AF256h
    sub edx, r8d
    sub edx, ecx
    sub edx, eax
    add edx, -4F683893h
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE53154:
    cmp eax, 40A9060Ch
    jnz loc_7FFB0DE5815D
    mov eax, dword ptr [rsp+174h]
    xor eax, dword ptr [rsp+148h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp dword ptr [rsp+144h], eax
    jle loc_7FFB0DE583FA
    mov eax, dword ptr [dword_7FFB0FECECC4]
    mov ecx, eax
    xor ecx, 38ABCA41h
    lea edx, [rcx+7C119716h]
    add eax, ecx
    add eax, 7C119716h
    add eax, ecx
    add eax, 6316BF81h
    xor eax, ecx
    loc_7FFB0DE531FF:
    sub eax, edx
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE5320A:
    mov rax, qword ptr [rsp+198h]
    shl rax, 5
    mov rcx, qword ptr [rsp+60h]
    mov rax, qword ptr [rcx+rax]
    mov qword ptr [rsp+238h], rax
    mov eax, dword ptr [dword_7FFB0FECEC64]
    mov ecx, 5D6979DEh
    add eax, ecx
    xor eax, -50E06F31h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE53242:
    mov rax, qword ptr [rsp+1A0h]
    mov rcx, 0C96D03FC4BF55BAh
    xor rax, rcx
    mov qword ptr [rsp+210h], rax
    mov rcx, 50D9DFE6704D6E71h
    add rax, rcx
    mov rcx, -727BDBC6E533532Dh
    xor rax, rcx
    mov rcx, -71104DF674119350h
    add rcx, rax
    mov qword ptr [rsp+218h], rcx
    mov rcx, 119063419EC1CED8h
    add rcx, rax
    mov rdx, -0DCCB19D4B9391BDh
    xor rcx, rdx
    mov rdx, 61C83F18ED8FA690h
    add rdx, rax
    mov qword ptr [rsp+220h], rdx
    add rcx, rax
    mov qword ptr [rsp+228h], rcx
    mov eax, dword ptr [dword_7FFB0FECEC54]
    mov ecx, eax
    xor ecx, 68633DFFh
    lea edx, [rcx-5D10C153h]
    lea r8d, [rcx-40F92D43h]
    mov r9d, r8d
    xor r9d, 7471F4Ah
    mov r10d, r8d
    xor r10d, -243882C9h
    mov r11d, r8d
    xor r11d, 43A91699h
    add r9d, -31CA85B5h
    xor r9d, edx
    add r9d, r11d
    sub r9d, r10d
    sub r9d, r8d
    add r9d, ecx
    add eax, r9d
    add eax, 386A9A87h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE53328:
    mov eax, dword ptr [rsp+170h]
    add eax, dword ptr [rsp+16Ch]
    sub eax, dword ptr [rsp+14Ch]
    xor eax, dword ptr [rsp+150h]
    mov dword ptr [rsp+174h], eax
    mov eax, dword ptr [dword_7FFB0FECEC30]
    mov ecx, eax
    xor ecx, -3A2E2AC2h
    lea edx, [rcx+4AF77613h]
    xor edx, eax
    xor eax, -7797CD7Ah
    sub edx, ecx
    add edx, 56670B5Eh
    xor edx, ecx
    add edx, eax
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE53377:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+2B0h]
    inc rax
    mov qword ptr [rsp+300h], rax
    mov rcx, qword ptr [rsp+190h]
    movsxd rcx, dword ptr [rcx]
    cmp rax, rcx
    jge loc_7FFB0DE54FC4
    mov eax, dword ptr [dword_7FFB0FECECA4]
    lea ecx, [rax+3FB7F10Dh]
    xor ecx, 69D358FAh
    lea edx, [rcx+0C8AD780h]
    xor edx, -50B07129h
    add edx, eax
    lea r8d, [rcx+27A78C27h]
    sub edx, ecx
    sub edx, ecx
    sub edx, r8d
    add edx, 20BAC3F7h
    xor edx, r8d
    add eax, edx
    add eax, 3FB7F10Dh
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE53451:
    mov rax, qword ptr [rsp+228h]
    sub rax, qword ptr [rsp+220h]
    sub rax, qword ptr [rsp+1A0h]
    xor rax, qword ptr [rsp+210h]
    add rax, qword ptr [rsp+218h]
    add rax, qword ptr [rsp+198h]
    movsxd rcx, dword ptr [rsp+8Ch]
    cmp rax, rcx
    jge loc_7FFB0DE58562
    mov ecx, dword ptr [rsp+8Ch]
    mov dword ptr [rsp+94h], ecx
    mov qword ptr [rsp+1F0h], rax
    loc_7FFB0DE534A8:
    mov rax, qword ptr [rsp+1F0h]
    mov ecx, dword ptr [rsp+94h]
    mov qword ptr [rsp+198h], rax
    mov dword ptr [rsp+88h], ecx
    mov rax, qword ptr [rsp+98h]
    cmp byte ptr [rax], 0
    jz loc_7FFB0DE5831C
    mov eax, dword ptr [dword_7FFB0FECEBF8]
    mov ecx, eax
    xor ecx, 11EAB16Ch
    lea edx, [rcx+2E2E2CDBh]
    xor edx, -5E83404Fh
    add edx, eax
    sub edx, ecx
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE534FA:
    mov eax, dword ptr [rsp+10Ch]
    sub eax, dword ptr [rsp+108h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub eax, dword ptr [rsp+104h]
    add eax, dword ptr [rsp+100h]
    sub eax, dword ptr [rsp+0FCh]
    xor eax, dword ptr [rsp+0D0h]
    add eax, dword ptr [rsp+0D8h]
    cmp dword ptr [rsp+0CCh], eax
    jle loc_7FFB0DE54FC4
    mov rax, qword ptr [rsp+60h]
    add rax, 80h
    mov qword ptr [rsp+2A8h], rax
    mov rax, qword ptr [rsp+530h]
    add rax, 11E0h
    mov qword ptr [rsp+1B0h], rax
    mov qword ptr [rsp+1F8h], 0
    loc_7FFB0DE535AD:
    mov rax, qword ptr [rsp+1F8h]
    mov qword ptr [rsp+2B0h], rax
    mov rcx, qword ptr [rsp+2A8h]
    lea rax, [rax+rax*4]
    lea rdx, [rcx+rax*4]
    mov qword ptr [rsp+38h], rdx
    mov eax, dword ptr [rcx+rax*4]
    cmp eax, 1
    jz loc_7FFB0DE58371
    cmp eax, 1Ch
    jnz loc_7FFB0DE582E6
    movaps xmm0, xmmword ptr [xmmword_7FFB0FE4E2F0]
    movaps xmmword ptr [rsp+4B0h], xmm0
    movaps xmm0, xmmword ptr [xmmword_7FFB0FE4E2E0]
    movaps xmmword ptr [rsp+4A0h], xmm0
    movaps xmm0, xmmword ptr [xmmword_7FFB0FE4E2D0]
    movaps xmmword ptr [rsp+490h], xmm0
    movaps xmm0, xmmword ptr [xmmword_7FFB0FE4E2C0]
    movaps xmmword ptr [rsp+480h], xmm0
    movaps xmm0, xmmword ptr [xmmword_7FFB0FE4E2B0]
    movaps xmmword ptr [rsp+470h], xmm0
    movaps xmm0, xmmword ptr [xmmword_7FFB0FE4E2A0]
    movaps xmmword ptr [rsp+460h], xmm0
    movaps xmm0, xmmword ptr [xmmword_7FFB0FE4E290]
    movaps xmmword ptr [rsp+450h], xmm0
    movaps xmm0, xmmword ptr [xmmword_7FFB0FE4E280]
    movaps xmmword ptr [rsp+440h], xmm0
    lea rcx, [rsp+440h]
    call sub_7FFB0FDD3740
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rsp+38h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [rdx+5]
    movzx edx, byte ptr [rdx+4]
    mov r8, qword ptr [qword_7FFB0FE98B80]
    mov r9, r8
    mov r10, 145565A093C474AAh
    xor r9, r10
    mov r10, r8
    mov r11, -7999309A1A2F6B78h
    xor r10, r11
    mov r11, 75453A1B13A1B1BDh
    add r10, r11
    sub r9, r10
    mov r11, -1B9361605DD47678h
    xor r10, r11
    mov r11, 131422AA64CEE483h
    add r11, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdi, -2455A3D84DB7F60h
    add r9, rdi
    xor r9, r8
    xor r11, r10
    xor r11, r9
    mov qword ptr [qword_7FFB0FFA4408], r11
    mov r9, qword ptr [qword_7FFB0FE98B88]
    mov r8, 3EB6D88BEF4BC8BEh
    add r8, r9
    mov r10, r8
    mov r14, 4111114D4821E026h
    and r10, r14
    shl r10, 2
    mov r11, r8
    mov rbx, -4111114D4821E027h
    and r11, rbx
    lea r11, [r11+r11*2]
    sub r10, r11
    lea r11, [r8+r8*2]
    add r10, r11
    mov r11, r8
    or r11, rbx
    not r11
    lea r11, [r11+r11*2]
    lea r10, [r10+r11*2]
    mov r11, r8
    or r11, r14
    add r11, r9
    add r11, r10
    sub r11, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, 4F8F33AAFEA9338Dh
    add r11, r8
    mov qword ptr [qword_7FFB0FFA4410], r11
    mov ebp, 80h
    sub rbp, rax
    lea r13, [rsp+rax+508h+var_508]
    add r13, 440h
    mov dword ptr [rsp+28h], ecx
    mov dword ptr [rsp+20h], edx
    mov rcx, r13
    mov rdx, rbp
    lea rsi, qword_7FFB0FFA4408
    mov r8, rsi
    lea r9, MultiByteStr
    call sub_7FFB0FA84070
    mov rcx, r13
    call sub_7FFB0FDD3740
    sub rbp, rax
    add r13, rax
    mov rax, qword ptr [rsp+38h]
    movzx eax, byte ptr [rax+7]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, qword ptr [qword_7FFB0FE98B90]
    mov rcx, 13C56CD1AA3B04A5h
    add rcx, r8
    mov rdx, 7A64E5916327C3BAh
    lea r9, [r8+rdx]
    mov rdx, r9
    not rdx
    mov rbx, -483C22B2B72807BAh
    mov r10, rbx
    or r10, rdx
    not r10
    shl r10, 2
    and rdx, rbx
    mov r11, rbx
    and r11, r9
    lea r11, [r11+r11*2]
    lea r11, [r11+rdx*4]
    mov rdx, rbx
    or rdx, r9
    lea rdx, [rdx+rdx*4]
    sub rdx, r11
    sub rdx, r9
    sub rdx, r9
    sub rdx, r10
    xor rdx, r8
    sub rdx, r9
    mov r8, 790D0BC6A2E3896Eh
    add rdx, r8
    mov r10, rcx
    not r10
    mov r8, rdx
    or r8, r10
    mov r9, rdx
    or r9, rcx
    mov r11, rdx
    and r11, r10
    xor r10, rdx
    and rdx, rcx
    mov rcx, qword ptr [rsp+38h]
    movzx ecx, byte ptr [rcx+6]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not r9
    lea r10, [r10+r10*2]
    lea r11, [r11+r11*2]
    add r11, r11
    lea rdx, [r11+rdx*8]
    lea r11, [r8+r8*4]
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
    sub rdx, r11
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rdx, r10
    lea rdx, [rdx+r9*8]
    add rdx, r8
    mov qword ptr [qword_7FFB0FFA4408], rdx
    mov rdx, qword ptr [qword_7FFB0FE98B98]
    mov r8, rdx
    not r8
    lea r9, [r8*8]
    sub r9, r8
    mov r8, rdx
    mov rbx, -16F640447E7A0000h
    and r8, rbx
    mov r10, r8
    mov r11, rdx
    mov r14, 16F640447E79FFFFh
    and r11, r14
    add r11, r11
    add r8, r8
    sub r8, r11
    not r10
    lea r10, [r10+r10*2]
    add r8, r10
    mov r10, rdx
    or r10, rbx
    not r10
    add r10, r10
    lea r10, [r10+r10*4]
    sub r8, r10
    mov r10, rdx
    or r10, r14
    not r10
    lea r10, [r10+r10*8]
    sub r8, r10
    add r8, r9
    mov r9, r8
    mov r11, 4F07E579D38FFA2Dh
    and r9, r11
    not r9
    add r9, r9
    mov r10, r8
    xor r10, r11
    sub r9, r10
    mov r10, r8
    or r10, r11
    not r10
    add r10, r10
    sub r9, r10
    mov r10, r9
    mov r11, 0EAD26D0F4582797h
    xor r10, r11
    add r10, r8
    sub r10, r9
    mov r8, 5F8D4CC65B1E9D84h
    xor r9, r8
    add r9, r9
    mov r8, -6C9E8069D9B064DDh
    add r9, r8
    add r9, r10
    xor r9, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [qword_7FFB0FFA4410], r9
    mov rdx, qword ptr [qword_7FFB0FE98BA0]
    mov r8, -312FEA56274CE658h
    add rdx, r8
    mov r8, -0C7FE9D32FFDE82Ch
    xor rdx, r8
    mov r8, 30C27C3197967289h
    add rdx, r8
    mov r8, -2143824E40C09B5Eh
    xor rdx, r8
    mov r8, 35EE72F290B1AD7Eh
    add rdx, r8
    mov qword ptr [qword_7FFB0FFA61C8], rdx
    mov dword ptr [rsp+28h], eax
    mov dword ptr [rsp+20h], ecx
    mov rcx, r13
    mov rdx, rbp
    mov r8, rsi
    lea rdi, qword_7FFB0FFA61C8
    mov r9, rdi
    call sub_7FFB0FA84070
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, r13
    call sub_7FFB0FDD3740
    sub rbp, rax
    add r13, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rsp+38h]
    movzx eax, byte ptr [rcx+9]
    movzx ecx, byte ptr [rcx+8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [qword_7FFB0FE98BA8]
    mov r8, 6DBE1E138A21484Eh
    add r8, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rdx, rdx
    add rdx, r8
    sub r8, rdx
    mov rdx, -7A04400C6687D499h
    add r8, rdx
    mov qword ptr [qword_7FFB0FFA4408], r8
    mov r8, qword ptr [qword_7FFB0FE98BB0]
    mov rdx, -7BBA1E13C7E83C31h
    add rdx, r8
    mov r9, rdx
    mov r10, -5383FF7FF46067B2h
    xor r9, r10
    mov r12, -2F98E7BD6E9E3016h
    mov r10, r12
    or r10, r9
    not r10
    lea r10, [r10+r10*2]
    mov r11, rdx
    mov rbx, 5383FF7FF46067B1h
    xor r11, rbx
    mov rbx, r12
    or rbx, r11
    add rbx, rbx
    lea rbx, [rbx+rbx*2]
    mov r14, r12
    xor r14, r9
    and r11, r12
    lea r11, [r11+r11*2]
    add r11, r11
    and r9, r12
    lea r9, [r9+r9*2]
    lea r9, [r11+r9*2]
    add r9, r14
    sub r9, rbx
    lea r11, [r9+r10*2]
    mov r9, r8
    not r9
    lea r10, [r9+r9*4]
    mov rbx, r11
    or rbx, r9
    mov r14, r11
    or r14, r8
    xor r8, r11
    and r9, r11
    add r8, r8
    shl r9, 3
    sub r9, r8
    not r14
    lea r8, [r14+r14*4]
    add r9, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not rbx
    lea r8, [rbx+rbx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9, r8
    sub r9, r10
    xor r9, rdx
    mov qword ptr [qword_7FFB0FFA4410], r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [qword_7FFB0FE98BB8]
    mov r8, -75453EEDDCABBDCCh
    add r8, rdx
    mov r9, r8
    mov r10, 6A1B4E605490FF42h
    xor r9, r10
    add r9, rdx
    mov r10, 2844BB9670D625E2h
    sub r10, r9
    xor r10, r8
    mov rdx, r8
    mov r8, 6C2BFC287AD717C1h
    xor rdx, r8
    mov r8, -6B3ED2A43A606C74h
    add r8, rdx
    add rdx, r8
    mov r9, -743C2148C0948448h
    xor r8, r9
    mov r9, 41D75D9DBF7FBFE5h
    add r9, r8
    mov r11, -61A9BFDEA453A2E1h
    add r8, r11
    xor r10, r8
    add rdx, r10
    mov r8, rdx
    or r8, r9
    mov r10, rdx
    and r10, r9
    xor rdx, r9
    not r10
    add r10, r10
    sub r10, rdx
    not r8
    add r8, r8
    sub r10, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [qword_7FFB0FFA61C8], r10
    mov dword ptr [rsp+28h], eax
    mov dword ptr [rsp+20h], ecx
    mov rcx, r13
    mov rdx, rbp
    mov r8, rsi
    mov r9, rdi
    call sub_7FFB0FA84070
    mov rcx, r13
    call sub_7FFB0FDD3740
    sub rbp, rax
    mov qword ptr [rsp+0A8h], rbp
    add r13, rax
    mov qword ptr [rsp+0B0h], r13
    mov rax, qword ptr [rsp+38h]
    movzx eax, byte ptr [rax+0Bh]
    mov dword ptr [rsp+0C8h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rsp+38h]
    movzx r8d, byte ptr [rcx+0Ah]
    mov r10, qword ptr [qword_7FFB0FE98BC0]
    mov rdx, r10
    mov rax, -2F1FA6190A9DC184h
    xor rdx, rax
    mov rax, 73EE2847D3277D1Dh
    lea rcx, [rdx+rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, 35778D24317C5971h
    lea r11, [rdx+rax]
    mov rax, 3EB6C1D3951E0CADh
    xor r11, rax
    mov rax, -0DE07F7C4B3EB2FCh
    lea r9, [rdx+rax]
    mov rax, -3C657F42FD4023A4h
    add r11, r9
    add r11, rax
    xor r11, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, 2F1FA6190A9DC183h
    xor r10, rax
    mov rbx, r11
    or rbx, r10
    not rbx
    lea r14, [rbx*8]
    sub r14, rbx
    mov rbx, r11
    xor rbx, rdx
    lea rbx, [rbx+rbx*4]
    and r10, r11
    lea r10, [r10+r10*2]
    and r11, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r10, [r11+r10*2]
    sub r10, rbx
    sub r10, rdx
    add r14, r9
    add r14, r10
    xor r14, rcx
    mov qword ptr [qword_7FFB0FFA4408], r14
    mov rcx, qword ptr [qword_7FFB0FE98BC8]
    mov rax, 5BBFEF4EDCAB5780h
    lea rdx, [rcx+rax]
    mov r9, rdx
    mov r15, 770049D1D3D52B66h
    or r9, r15
    not r9
    lea r10, [r9+r9*4]
    lea r10, [r9+r10*4]
    mov r11, rdx
    mov rax, -770049D1D3D52B67h
    or r11, rax
    lea r9, [r11+r11*4]
    lea r9, [r11+r9*2]
    not r11
    lea rbx, [r11+r11*4]
    lea rbx, [r11+rbx*2]
    mov r11, rdx
    and r11, rax
    lea r14, [r11+r11*8]
    not r11
    lea r12, [r11+r11*4]
    lea r12, [r12]
    mov r11, rdx
    and r11, r15
    lea r13, [r11+r11*4]
    lea r13, [r11+r13*4]
    mov rax, 5AEB7FC221F47491h
    lea r11, [rcx+rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r13, r14
    sub r9, r13
    add r9, r12
    sub r9, rbx
    sub r9, r10
    mov r10, r11
    not r10
    lea rbx, [r10+r10]
    lea rbx, [rbx+rbx*2]
    mov rax, 2CFE35FA9567514Ch
    mov r14, rax
    or r14, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r12, rax
    or r12, r11
    not r12
    lea r12, [r12]
    and r10, rax
    shl r10, 2
    and r11, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r11, [r11+r11*2]
    sub r10, r11
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r10, [r12]
    add r10, r14
    sub r10, rbx
    mov rax, -79055E103FCA0C1Bh
    add r10, rax
    xor r10, r9
    sub r10, rdx
    sub r10, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [qword_7FFB0FFA4410], r10
    mov rcx, qword ptr [qword_7FFB0FE98BD0]
    mov r9, rcx
    not r9
    lea r10, [r9+r9]
    mov r11, -510D0526C39C76B9h
    and r9, r11
    mov rdx, rcx
    or rdx, r11
    not rdx
    not r11
    and r11, rcx
    lea rdx, [r11+rdx*2]
    add rdx, r9
    sub rdx, r10
    mov rax, 7273EDA0F35D60EAh
    lea r11, [rdx+rax]
    mov r9, r11
    mov rax, -5E55DCBACCF0FB9Ah
    or r9, rax
    lea r10, [r9+r9*2]
    not r9
    lea rbx, [r9*8]
    sub rbx, r9
    mov r9, r11
    and r9, rax
    lea r9, [r9+r10*2]
    add r9, rbx
    mov r13, -7
    sub r13, r9
    mov rbp, 3F342C2AED3F7930h
    sub rbp, r9
    mov r10, rbp
    mov rax, -272AFDEBE50FCDEFh
    xor r10, rax
    mov rax, -4EE62A2744CAE9A6h
    lea r9, [r10+rax]
    mov rax, 272AFDEBE50FCDEEh
    xor rbp, rax
    mov r15, -18C3972BDADB9778h
    mov rbx, r15
    xor rbx, r10
    lea r14, [rbx*8]
    sub r14, rbx
    mov rbx, r15
    or rbx, r10
    not rbx
    lea rbx, [rbx+rbx*2]
    add r14, rbx
    mov rbx, r15
    or rbx, rbp
    and rbp, r15
    add rbp, rbp
    lea r12, [rbp*2]
    add r12, rbp
    and r10, r15
    mov r15, 32654ACD41B700EEh
    add r10, r10
    sub r10, r12
    add r10, r14
    not rbx
    lea rbx, [rbx+rbx*2]
    sub r10, rbx
    mov rax, -4A4AC5839092C665h
    add r10, rax
    xor r10, rcx
    sub r10, r11
    add r10, r9
    sub r10, r13
    sub r10, rdx
    mov rax, -37E1CD624EA3D0E4h
    add r10, rax
    mov rdx, r9
    not rdx
    mov rcx, r10
    or rcx, rdx
    mov r11, r10
    and rdx, r10
    and r10, r9
    lea r10, [r10+r10*8]
    lea rdx, [r10+rdx*4]
    or r11, r9
    lea r10, [r11+r11*2]
    sub rdx, r10
    add r9, r9
    lea r9, [r9+r9*2]
    sub rdx, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not rcx
    lea rcx, [rcx+rcx*4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rcx, [rdx+rcx*2]
    mov qword ptr [qword_7FFB0FFA61C8], rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rsp+0A8h]
    mov rcx, qword ptr [rsp+0B0h]
    mov eax, dword ptr [rsp+0C8h]
    mov dword ptr [rsp+28h], eax
    mov dword ptr [rsp+20h], r8d
    mov r8, rsi
    mov r9, rdi
    call sub_7FFB0FA84070
    mov rcx, qword ptr [rsp+0B0h]
    call sub_7FFB0FDD3740
    mov qword ptr [rsp+1B8h], rax
    not rax
    or rax, qword ptr [rsp+0A8h]
    not rax
    mov qword ptr [rsp+2B8h], rax
    mov eax, dword ptr [dword_7FFB0FECEC7C]
    lea ecx, [rax+1E9A0F22h]
    lea edx, [rax-7184EC65h]
    lea r8d, [rax+19039006h]
    xor r8d, ecx
    lea ecx, [rax-6D143746h]
    xor ecx, 66F701A1h
    mov r9d, -5F1D2C2Ah
    sub r9d, eax
    xor r9d, edx
    lea edx, [rcx+r9]
    add edx, 7049B347h
    xor edx, r8d
    sub edx, eax
    lea eax, [rdx+rcx]
    add eax, 46387AF0h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE54FC4:
    mov rcx, qword ptr [rsp+60h]
    lea rax, [rcx+268h]
    mov qword ptr [rsp+200h], rax
    mov eax, dword ptr [rcx+268h]
    mov dword ptr [rsp+110h], eax
    test eax, eax
    jle loc_7FFB0DE5842E
    mov eax, dword ptr [dword_7FFB0FECEC3C]
    lea ecx, [rax+5E2D1396h]
    lea edx, [rax-7033CDE0h]
    xor edx, -18526ACEh
    add edx, 49F2569Ah
    mov r8d, edx
    xor r8d, -9365CF4h
    add r8d, eax
    add r8d, -7033CDE0h
    mov r9d, -7AE98E2Ch
    sub r9d, r8d
    xor r9d, eax
    sub r9d, edx
    sub r9d, eax
    sub r9d, eax
    add r9d, 5F844C8Ch
    xor r9d, ecx
    mov dword ptr [rsp+30h], r9d
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE55048:
    mov rax, qword ptr [rsp+1D8h]
    and rax, qword ptr [rsp+358h]
    not rax
    mov qword ptr [rsp+360h], rax
    mov eax, dword ptr [dword_7FFB0FECECCC]
    lea ecx, [rax+557278A4h]
    lea edx, [rax-2D695F26h]
    xor edx, ecx
    xor edx, -149F6C00h
    sub edx, eax
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE55084:
    mov eax, dword ptr [rsp+168h]
    shl eax, 2
    mov ecx, dword ptr [rsp+58h]
    and ecx, dword ptr [rsp+48h]
    lea eax, [rax+rcx*2]
    sub eax, dword ptr [rsp+164h]
    sub eax, dword ptr [rsp+160h]
    add eax, dword ptr [rsp+15Ch]
    mov ecx, dword ptr [rsp+54h]
    not ecx
    or ecx, eax
    not ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add ecx, ecx
    lea ecx, [rcx+rcx*4]
    mov edx, dword ptr [rsp+54h]
    mov r8d, eax
    or r8d, edx
    lea r9d, [r8+r8*4]
    lea r8d, [r8+r9*2]
    mov r9d, eax
    xor r9d, edx
    add r9d, r9d
    not edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and edx, eax
    shl edx, 3
    and eax, dword ptr [rsp+54h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    imul eax, 0F5h
    sub eax, edx
    sub eax, r9d
    add eax, r8d
    sub eax, ecx
    mov ecx, dword ptr [rsp+50h]
    mov edx, ecx
    not edx
    or edx, eax
    not edx
    add edx, edx
    lea edx, [rdx+rdx*4]
    mov dword ptr [rsp+16Ch], edx
    lea edx, [rcx+rcx]
    lea edx, [rdx+rdx*2]
    or ecx, eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    and r8d, eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and eax, dword ptr [rsp+50h]
    lea eax, [rax+rax*8]
    lea eax, [rax+r8*4]
    sub eax, ecx
    sub eax, edx
    mov dword ptr [rsp+170h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FECECC0]
    mov ecx, eax
    xor ecx, -71FD29F2h
    add ecx, -248E6F67h
    xor ecx, -23614F6Eh
    sub ecx, eax
    add ecx, 7B03BD70h
    mov dword ptr [rsp+30h], ecx
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE5539B:
    mov rax, qword ptr [rsp+0A0h]
    and rax, qword ptr [rsp+70h]
    mov rcx, qword ptr [rsp+390h]
    lea rax, [rax+rcx*2]
    sub rax, qword ptr [rsp+388h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rax, qword ptr [rsp+380h]
    sub rax, qword ptr [rsp+378h]
    mov qword ptr [rsp+398h], rax
    mov eax, dword ptr [dword_7FFB0FECECD4]
    lea ecx, [rax+34432F09h]
    xor ecx, eax
    xor ecx, 0BD693C8h
    mov dword ptr [rsp+30h], ecx
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE55466:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+0F4h]
    add eax, eax
    sub eax, dword ptr [rsp+0F0h]
    add eax, dword ptr [rsp+0ECh]
    sub eax, dword ptr [rsp+0E8h]
    sub eax, dword ptr [rsp+0E4h]
    add eax, dword ptr [rsp+0E0h]
    xor eax, dword ptr [rsp+80h]
    mov dword ptr [rsp+84h], eax
    mov ecx, dword ptr [rsp+4Ch]
    not ecx
    or ecx, eax
    not ecx
    mov dword ptr [rsp+0F8h], ecx
    mov eax, dword ptr [dword_7FFB0FECEC28]
    mov ecx, -36C52602h
    xor eax, ecx
    add eax, 49C21E7Ch
    xor eax, 9B48A14h
    add eax, 216B7990h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE5553A:
    mov rax, qword ptr [rsp+78h]
    or rax, qword ptr [rsp+3A0h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not rax
    lea rcx, [rax*8]
    sub rcx, rax
    mov qword ptr [rsp+3A8h], rcx
    mov rax, qword ptr [rsp+78h]
    or rax, qword ptr [rsp+68h]
    not rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, rax
    shl rcx, 4
    add rcx, rax
    mov rax, qword ptr [rsp+68h]
    not rax
    and rax, qword ptr [rsp+78h]
    mov qword ptr [rsp+3B0h], rcx
    mov qword ptr [rsp+3B8h], rax
    mov eax, dword ptr [dword_7FFB0FECECE0]
    mov ecx, -1E309CB3h
    xor eax, ecx
    lea ecx, [rax-5E73A67Fh]
    xor ecx, 626E6E60h
    lea edx, [rax+rcx]
    add edx, -7A5ACF7Dh
    add ecx, 32AB2C4Fh
    xor edx, ecx
    add eax, edx
    add eax, -5E73A67Fh
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE556A9:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+3E0h]
    mov eax, dword ptr [rax+8]
    mov dword ptr [rsp+188h], eax
    mov eax, dword ptr [dword_7FFB0FECEC80]
    lea ecx, [rax-33C11537h]
    xor ecx, -0EBF0050h
    sub ecx, eax
    sub ecx, eax
    add ecx, 5CD63DB8h
    mov dword ptr [rsp+30h], ecx
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE55739:
    mov rax, qword ptr [rsp+78h]
    mov rcx, qword ptr [rsp+3D0h]
    and rcx, rax
    lea rcx, [rcx+rcx*2]
    and rax, qword ptr [rsp+68h]
    lea rdx, [rax+rax*8]
    lea rax, [rax+rdx*2]
    lea rax, [rax+rcx*4]
    sub rax, qword ptr [rsp+3C8h]
    sub rax, qword ptr [rsp+3C0h]
    mov qword ptr [rsp+3D8h], rax
    mov eax, dword ptr [dword_7FFB0FECEC2C]
    mov ecx, -0F1CBC0Ch
    xor eax, ecx
    lea ecx, [rax-10E6AD77h]
    xor ecx, 18435CB9h
    lea edx, [rcx-48AD2970h]
    mov r8d, edx
    xor r8d, -4B23C6B6h
    mov r9d, edx
    xor r9d, 3B13BFEEh
    lea r10d, [r9+rax]
    add r10d, -10E6AD77h
    add r8d, r10d
    add r8d, -34E66B3Dh
    xor r8d, eax
    add r8d, r9d
    xor r8d, edx
    sub r8d, ecx
    mov dword ptr [rsp+30h], r8d
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE557D4:
    mov rax, qword ptr [rsp+1A8h]
    mov rcx, -3598E7B7B644E50Bh
    xor rax, rcx
    mov rcx, -6D22FEDD1C3A2A8Ah
    add rcx, rax
    mov qword ptr [rsp+258h], rcx
    mov rcx, -0DBF1C1F20871DE9h
    add rax, rcx
    mov qword ptr [rsp+260h], rax
    mov rcx, rax
    mov rdx, -5AD369B46643E11Ah
    xor rcx, rdx
    mov qword ptr [rsp+268h], rcx
    mov rcx, qword ptr [rsp+250h]
    mov rdx, -53E7197E3A1D7B53h
    xor rcx, rdx
    mov qword ptr [rsp+270h], rcx
    mov rdx, rcx
    or rdx, rax
    not rax
    mov r8, rcx
    or r8, rax
    not r8
    mov qword ptr [rsp+278h], r8
    not rdx
    add rdx, rdx
    mov qword ptr [rsp+280h], rdx
    mov rdx, rax
    xor rdx, rcx
    add rdx, rdx
    mov qword ptr [rsp+288h], rdx
    mov qword ptr [rsp+290h], rcx
    and rax, rcx
    add rax, rax
    mov qword ptr [rsp+298h], rax
    mov eax, dword ptr [dword_7FFB0FECEBF4]
    lea ecx, [rax-728871C2h]
    lea edx, [rax-1691B6C5h]
    lea r8d, [rax+42D56991h]
    xor r8d, 40874FF7h
    add r8d, -39A440C7h
    xor ecx, eax
    xor ecx, r8d
    add ecx, 1CE3C120h
    xor ecx, edx
    add eax, ecx
    add eax, 551AE488h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE558DB:
    mov eax, dword ptr [rsp+138h]
    lea ecx, [rax+rax*2]
    mov eax, dword ptr [rsp+40h]
    mov edx, 1E62BC13h
    and eax, edx
    add eax, eax
    sub eax, ecx
    add eax, dword ptr [rsp+134h]
    sub eax, dword ptr [rsp+12Ch]
    sub eax, dword ptr [rsp+128h]
    sub eax, dword ptr [rsp+124h]
    mov ecx, eax
    not ecx
    and ecx, -212F824Eh
    lea edx, [rcx+rcx*4]
    lea ecx, [rcx+rdx*4]
    mov r8d, eax
    or r8d, -212F824Eh
    lea edx, [r8+r8*4]
    lea edx, [r8+rdx*2]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r9d, [r8+r8*4]
    lea r8d, [r8+r9*2]
    mov r9d, eax
    and r9d, -212F824Eh
    lea r10d, [r9+r9*8]
    not r9d
    lea r11d, [r9+r9*4]
    lea r9d, [r9+r11*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and eax, 212F824Dh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r11d, [rax+rax*4]
    lea eax, [rax+r11*4]
    add r10d, eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub edx, r10d
    add edx, r9d
    sub edx, r8d
    sub edx, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+11Ch]
    mov ecx, -3A5F38BFh
    add eax, ecx
    xor eax, dword ptr [rsp+118h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add eax, dword ptr [rsp+90h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add eax, edx
    sub eax, dword ptr [rsp+120h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add eax, dword ptr [rsp+40h]
    cmp dword ptr [rsp+114h], eax
    jle loc_7FFB0DE55C7C
    mov eax, dword ptr [dword_7FFB0FECEC60]
    lea ecx, [rax+5B7F5652h]
    lea edx, [rax+507E2B8h]
    xor edx, ecx
    xor edx, eax
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE55C7C:
    mov eax, dword ptr [rsp+88h]
    loc_7FFB0DE55C83:
    mov dword ptr [rsp+5Ch], eax
    mov eax, dword ptr [rsp+5Ch]
    mov dword ptr [rsp+8Ch], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [qword_7FFB0FE98C58]
    mov qword ptr [rsp+1A0h], rax
    mov eax, dword ptr [dword_7FFB0FECEC4C]
    lea ecx, [rax-0A9CC86Eh]
    xor ecx, -2A02EA80h
    add ecx, 49A96076h
    lea edx, [rax+62AC8CACh]
    xor edx, eax
    xor edx, ecx
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE55D38:
    movzx eax, byte ptr [rsp+37h]
    mov dword ptr [rsp+17Ch], eax
    mov rax, qword ptr [rsp+38h]
    movzx eax, byte ptr [rax+5]
    mov dword ptr [rsp+180h], eax
    mov rax, qword ptr [rsp+338h]
    movzx eax, byte ptr [rax]
    mov dword ptr [rsp+184h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [qword_7FFB0FE98B68]
    mov rcx, 4D81668FAA50F43Dh
    add rcx, rax
    mov rdx, -23026E1C50D97BB2h
    add rdx, rax
    mov r8, -4F1DFDFD19B5F977h
    xor rdx, r8
    mov r8, 6D331792EBAB7B81h
    add r8, rax
    xor r8, rcx
    sub r8, rdx
    xor r8, rax
    mov rax, -20E4E33E735DDB6Dh
    add rdx, rax
    add rdx, r8
    mov qword ptr [qword_7FFB0FFA43F0], rdx
    mov rcx, qword ptr [qword_7FFB0FE98B70]
    mov qword ptr [rsp+340h], rcx
    mov rax, -63A3F8DDD19376D6h
    add rcx, rax
    mov qword ptr [rsp+68h], rcx
    mov rax, rcx
    mov rdx, 203DAC84B56031A5h
    xor rax, rdx
    mov rdx, -2D10131C3239E341h
    xor rcx, rdx
    mov qword ptr [rsp+0C0h], rcx
    mov rdx, -6F51872598CCC573h
    add rcx, rdx
    mov qword ptr [rsp+70h], rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, -1924962ACD95455Bh
    add rax, rcx
    mov qword ptr [rsp+1D8h], rax
    mov rcx, qword ptr [rsp+0C0h]
    mov rdx, rcx
    not rdx
    or rdx, rax
    not rdx
    lea r8, [rdx*8]
    sub r8, rdx
    mov qword ptr [rsp+348h], r8
    or rax, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not rax
    mov rcx, rax
    shl rcx, 4
    add rcx, rax
    mov qword ptr [rsp+350h], rcx
    mov rax, qword ptr [rsp+0C0h]
    not rax
    mov qword ptr [rsp+358h], rax
    mov eax, dword ptr [dword_7FFB0FECEC9C]
    mov ecx, -10DF8E0Bh
    xor eax, ecx
    lea ecx, [rax+51BD98B7h]
    lea edx, [rax+31D018E2h]
    mov r8d, edx
    xor r8d, -77E4AC00h
    xor edx, -23C147C8h
    add r8d, eax
    add r8d, 31D018E2h
    add r8d, edx
    mov edx, -6E0CD0D4h
    sub edx, r8d
    xor ecx, eax
    xor ecx, edx
    mov dword ptr [rsp+30h], ecx
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE55FA7:
    mov rax, qword ptr [rsp+360h]
    add rax, rax
    lea rax, [rax+rax*2]
    mov rcx, qword ptr [rsp+0C0h]
    mov rdx, rcx
    not rdx
    mov r8, qword ptr [rsp+1D8h]
    mov r9, r8
    or r9, rdx
    lea r10, [r9+r9*4]
    lea r9, [r9+r10*2]
    and rdx, r8
    lea rdx, [rdx+rdx*2]
    and r8, rcx
    lea rcx, [r8+r8*8]
    lea rcx, [r8+rcx*2]
    lea rcx, [rcx+rdx*4]
    sub rcx, r9
    sub rcx, rax
    add rcx, qword ptr [rsp+350h]
    add rcx, qword ptr [rsp+348h]
    mov qword ptr [rsp+0A0h], rcx
    mov rax, qword ptr [rsp+70h]
    not rax
    or rax, rcx
    not rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rsp+0A0h]
    or rcx, qword ptr [rsp+70h]
    mov qword ptr [rsp+368h], rax
    mov qword ptr [rsp+370h], rcx
    mov eax, dword ptr [dword_7FFB0FECEBFC]
    mov ecx, eax
    xor ecx, -29BF01B4h
    lea edx, [rcx-6AD22E50h]
    xor edx, 4BEBA106h
    lea r8d, [rdx+7854FEEAh]
    xor r8d, 5454958Bh
    xor eax, -2DB10C6Ah
    add eax, edx
    add eax, 7854FEEAh
    xor eax, 5BFB978Bh
    sub eax, r8d
    add eax, edx
    sub eax, ecx
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE560CA:
    mov rax, qword ptr [rsp+410h]
    sub rax, qword ptr [rsp+408h]
    add rax, qword ptr [rsp+3F8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rax, qword ptr [rsp+3F0h]
    mov qword ptr [rsp+418h], rax
    mov rcx, 421831F3EA347232h
    or rax, rcx
    mov qword ptr [rsp+438h], rax
    mov eax, dword ptr [dword_7FFB0FECECF0]
    lea ecx, [rax+46E7277Dh]
    loc_7FFB0DE56173:
    xor ecx, eax
    mov dword ptr [rsp+30h], ecx
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE5617E:
    mov rax, qword ptr [rsp+430h]
    not rax
    lea rcx, [rax*8]
    sub rcx, rax
    mov rax, qword ptr [rsp+1E8h]
    mov rdx, rax
    mov r8, -797F6A13B6D76103h
    or rdx, r8
    lea rdx, [rdx+rdx*2]
    and rax, r8
    lea rax, [rax+rdx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rcx, rax
    sub rcx, qword ptr [rsp+428h]
    mov rax, 586ECAB105DD96BCh
    add rax, rcx
    mov rdx, -51581C9D2B30817h
    xor rax, rdx
    sub rax, rcx
    add rax, qword ptr [rsp+1E8h]
    mov qword ptr [qword_7FFB0FFA43E0], rax
    mov eax, dword ptr [dword_7FFB0FECED08]
    mov ecx, eax
    xor ecx, 11D59C2Ch
    lea edx, [rcx-2DEEF4DBh]
    mov r8d, edx
    xor r8d, 5B153797h
    xor edx, -766727A1h
    xor eax, 630957DFh
    add eax, ecx
    add eax, -2DEEF4DBh
    add eax, r8d
    add eax, edx
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE56297:
    mov rax, qword ptr [rsp+2D8h]
    lea rcx, [rax*8]
    sub rcx, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+1C8h]
    or rax, qword ptr [rsp+1C0h]
    lea rax, [rax+rax*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rsp+1C8h]
    and rdx, qword ptr [rsp+1C0h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rax, [rdx+rax*2]
    sub rcx, rax
    sub rcx, qword ptr [rsp+2D0h]
    mov qword ptr [qword_7FFB0FFA4408], rcx
    mov rcx, qword ptr [qword_7FFB0FE98C28]
    mov rax, -592F2247659894B1h
    add rax, rcx
    mov rdx, -0E4FFB42E56351B9h
    xor rax, rdx
    mov rdx, -38EF23ACE2505346h
    lea r9, [rax+rdx]
    mov r8, r9
    mov rdx, 6792B2B0C75B55F5h
    xor r8, rdx
    mov r10, r8
    mov rbx, -12AD94B9822C9007h
    or r10, rbx
    not r10
    add r10, r10
    mov rdx, r8
    and rdx, rbx
    not rdx
    add rdx, rdx
    mov r11, r8
    xor r11, rbx
    sub rdx, r11
    sub rdx, r10
    mov r10, 44FE93D9D1443C10h
    sub r10, rdx
    mov r11, r9
    not r11
    lea r13, [r11+r11]
    mov rbp, r10
    or rbp, r11
    mov rbx, r10
    lea r14, [r10+r10*2]
    and r11, r10
    shl r11, 2
    and r10, r9
    lea r10, [r10+r10*2]
    sub r11, r10
    lea r10, [r13*2]
    add r10, r13
    or rbx, r9
    not rbx
    lea rbx, [rbx+rbx*2]
    add r11, r14
    lea r11, [r11+rbx*2]
    add r11, rbp
    sub r11, r10
    lea r10, [r11+1]
    mov rbx, -6792B2B0C75B55F6h
    xor r9, rbx
    lea rbx, [r9+r9*2]
    mov r14, r10
    or r14, r9
    mov r13, r10
    or r13, r8
    and r9, r10
    and r8, r10
    lea r9, [r9+r9*2]
    sub r9, r8
    lea r8, [r9+r11]
    inc r8
    not r13
    lea r9, [r13*2]
    add r9, r13
    add r9, r14
    add r9, r8
    sub r9, rbx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, -1250595FB4A5449Dh
    add rdx, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc r9
    xor r9, rdx
    sub r9, rcx
    sub r9, rax
    mov qword ptr [qword_7FFB0FFA4410], r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [qword_7FFB0FE98C30]
    mov qword ptr [rsp+2E0h], rax
    mov rcx, rax
    mov rdx, -78D17185D9566A83h
    xor rcx, rdx
    mov rdx, 7E8F9B401E24C16Ah
    add rdx, rcx
    mov qword ptr [rsp+2E8h], rdx
    mov r8, -599E87FD041B9A6Eh
    xor rdx, r8
    mov qword ptr [rsp+2F0h], rdx
    mov r8, -21E158C695186B05h
    add rdx, r8
    mov qword ptr [rsp+1D0h], rdx
    mov rdx, -3910A0B4DDBD347h
    xor rax, rdx
    add rax, rcx
    mov qword ptr [rsp+2F8h], rax
    mov eax, dword ptr [dword_7FFB0FECEC94]
    mov ecx, 71BE6E99h
    sub ecx, eax
    xor eax, 60E6696Fh
    lea edx, [rax-4DD4EE9Bh]
    lea r8d, [rax-18FBEA92h]
    xor r8d, edx
    lea edx, [rax-24477C2h]
    xor ecx, edx
    xor ecx, r8d
    lea edx, [rax+37ACD37Bh]
    xor edx, eax
    xor edx, ecx
    sub edx, eax
    add edx, -5AFE1E1Eh
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE569B3:
    mov rax, qword ptr [rsp+420h]
    mov qword ptr [qword_7FFB0FFA43D8], rax
    mov rax, qword ptr [qword_7FFB0FE98B58]
    mov qword ptr [rsp+1E8h], rax
    mov rcx, -797F6A13B6D76103h
    or rax, rcx
    not rax
    lea rcx, [rax*8]
    sub rcx, rax
    mov qword ptr [rsp+428h], rcx
    mov eax, dword ptr [dword_7FFB0FECED00]
    lea ecx, [rax-1E7C4B9Fh]
    mov edx, ecx
    xor edx, 45B9168Ah
    xor ecx, 5A867AFAh
    sub ecx, edx
    add ecx, eax
    mov dword ptr [rsp+30h], ecx
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE56A1B:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp dword ptr [rsp+188h], 0
    jle loc_7FFB0DE58461
    mov eax, dword ptr [dword_7FFB0FECEC00]
    lea ecx, [rax+51DE1F06h]
    mov edx, ecx
    xor edx, -5CB2C753h
    lea r8d, [rdx-6F511232h]
    lea r9d, [rdx+66361474h]
    xor r8d, 736D504Fh
    sub r8d, ecx
    add r8d, eax
    xor r8d, r9d
    lea eax, [rdx+r8]
    add eax, -23351E4Eh
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE56ABF:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+400h]
    not rax
    add rax, rax
    mov qword ptr [rsp+408h], rax
    mov rax, qword ptr [rsp+1E0h]
    mov rcx, rax
    mov rdx, -32654ACD41B700EFh
    and rcx, rdx
    and rax, r15
    add rax, rax
    lea rax, [rax+rcx*2]
    not rcx
    add rcx, rax
    mov qword ptr [rsp+410h], rcx
    mov eax, dword ptr [dword_7FFB0FECECFC]
    mov ecx, eax
    xor ecx, -4C71FD51h
    add ecx, -0EC1672Ah
    xor ecx, 197DB49Bh
    mov edx, ecx
    add edx, -40DDD3A5h
    add ecx, edx
    add ecx, -40DDD3A5h
    add ecx, eax
    mov eax, 7E4F9B6Fh
    sub eax, ecx
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE56BB9:
    mov eax, dword ptr [rsp+130h]
    shl eax, 2
    mov dword ptr [rsp+134h], eax
    mov eax, dword ptr [rsp+40h]
    mov ecx, -1E62BC14h
    and eax, ecx
    mov dword ptr [rsp+138h], eax
    mov eax, dword ptr [dword_7FFB0FECEC5C]
    mov ecx, 52301238h
    add eax, ecx
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE56BF2:
    mov eax, dword ptr [rsp+0F8h]
    add eax, eax
    lea eax, [rax+rax*4]
    mov dword ptr [rsp+0FCh], eax
    mov eax, dword ptr [rsp+4Ch]
    mov ecx, dword ptr [rsp+84h]
    mov edx, ecx
    or edx, eax
    lea r8d, [rdx+rdx*4]
    lea edx, [rdx+r8*2]
    mov dword ptr [rsp+100h], edx
    xor ecx, eax
    add ecx, ecx
    mov dword ptr [rsp+104h], ecx
    mov eax, dword ptr [dword_7FFB0FECEC18]
    lea ecx, [rax+78E0E7ABh]
    lea edx, [rax+157688Bh]
    xor edx, ecx
    xor edx, eax
    xor edx, 73B4F708h
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE56C4F:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+1B0h]
    mov rax, qword ptr [rax]
    mov qword ptr [rsp+308h], rax
    test rax, rax
    jz loc_7FFB0DE584A1
    mov eax, dword ptr [dword_7FFB0FECECB0]
    lea ecx, [rax-23566041h]
    lea edx, [rax+1B100CCBh]
    mov r8d, edx
    xor r8d, -1B194624h
    add r8d, 3AC92395h
    mov r9d, r8d
    xor r9d, 0B9560E8h
    lea r10d, [r9+51D30D53h]
    xor r10d, 2648DC64h
    sub r10d, r8d
    xor r10d, ecx
    sub r10d, edx
    sub r10d, r9d
    add r10d, eax
    mov dword ptr [rsp+30h], r10d
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE56D2B:
    mov rax, qword ptr [rsp+2B8h]
    lea rcx, [rax+rax*4]
    lea rax, [rax+rcx*2]
    mov rcx, qword ptr [rsp+0A8h]
    mov rdx, qword ptr [rsp+1B8h]
    mov r8, rcx
    or r8, rdx
    lea r9, [r8+r8*4]
    lea r8, [r8+r9*2]
    mov r9, rcx
    xor r9, rdx
    mov r10, rdx
    not r10
    and r10, rcx
    lea r10, [r10+r10*8]
    and rcx, rdx
    imul rbp, rcx, 0F5h
    sub rbp, r10
    sub rbp, r9
    add rbp, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r13, qword ptr [rsp+0B0h]
    add r13, qword ptr [rsp+1B8h]
    sub rbp, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+38h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rax+0Dh]
    mov rcx, qword ptr [rsp+38h]
    movzx ecx, byte ptr [rcx+0Ch]
    mov rdx, qword ptr [qword_7FFB0FE98BD8]
    mov r8, 7B1AA60AE2A5E6DFh
    add r8, rdx
    mov r9, r8
    mov r10, 65C07ED4FFE5E8F3h
    xor r9, r10
    sub rdx, rdx
    sub rdx, r9
    sub rdx, r8
    mov r8, 515A4BC156618E90h
    add rdx, r8
    xor rdx, r9
    mov qword ptr [qword_7FFB0FFA4408], rdx
    mov rdx, qword ptr [qword_7FFB0FE98BE0]
    mov r8, rdx
    mov r15, 41577CA74FCD8906h
    or r8, r15
    not r8
    lea r9, [r8+r8*4]
    lea r8, [r8+r9*4]
    mov r9, rdx
    mov rbx, -41577CA74FCD8907h
    or r9, rbx
    lea r10, [r9+r9*4]
    lea r10, [r9+r10*2]
    not r9
    lea r11, [r9+r9*4]
    lea r9, [r9+r11*2]
    mov r11, rdx
    and r11, rbx
    lea rbx, [r11+r11*8]
    not r11
    lea r14, [r11+r11*4]
    lea r11, [r11+r14*2]
    mov r14, rdx
    and r14, r15
    lea r12, [r14+r14*4]
    lea r14, [r12]
    add r14, rbx
    sub r10, r14
    add r10, r11
    sub r10, r9
    sub r10, r8
    mov r8, 2094A48446C69E49h
    add rdx, r8
    add rdx, r10
    mov qword ptr [qword_7FFB0FFA4410], rdx
    mov r8, qword ptr [qword_7FFB0FE98BE8]
    mov r9, r8
    mov rdx, -6CE4B88622BA6D45h
    xor r9, rdx
    mov rdx, 6237752126A4B823h
    add rdx, r9
    mov r10, rdx
    mov rbx, -7B8F5B56AF79BDDAh
    or r10, rbx
    not r10
    mov r11, rdx
    and r11, rbx
    mov rbx, rdx
    mov r14, 7B8F5B56AF79BDD9h
    and rbx, r14
    add rbx, rbx
    lea rbx, [rbx+r11*2]
    not r11
    add r11, r10
    mov r10, r8
    mov rdi, 78CB1546CFCD6571h
    xor r10, rdi
    add rbx, r11
    mov r11, rdx
    or r11, r14
    not r11
    lea r11, [rbx+r11*2]
    add r11, 2
    mov rdi, -325158B56332A956h
    xor r11, rdi
    sub r11, r8
    mov rdi, 27C8C5C024D96C2h
    add r10, rdi
    add r10, r11
    mov r11, 6CE4B88622BA6D44h
    xor r8, r11
    mov r11, r10
    or r11, r8
    mov rbx, r10
    or rbx, r9
    and r8, r10
    and r10, r9
    mov r9, r8
    add r8, r8
    lea r8, [r8+r10*2]
    not r9
    sub r9, r8
    not rbx
    shl rbx, 2
    sub r9, rbx
    not r11
    lea r8, [r11+r11*2]
    sub r9, r8
    add r9, -3
    xor r9, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [qword_7FFB0FFA61C8], r9
    mov dword ptr [rsp+28h], eax
    mov dword ptr [rsp+20h], ecx
    mov rcx, r13
    mov rdx, rbp
    lea rdi, qword_7FFB0FFA4408
    mov r8, rdi
    lea rsi, qword_7FFB0FFA61C8
    mov r9, rsi
    call sub_7FFB0FA84070
    mov rcx, r13
    call sub_7FFB0FDD3740
    sub rbp, rax
    add r13, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+38h]
    movzx eax, byte ptr [rax+0Fh]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rsp+38h]
    movzx ecx, byte ptr [rcx+0Eh]
    mov r9, qword ptr [qword_7FFB0FE98BF0]
    mov rdx, -0D63244DACFF2C5Fh
    lea r10, [r9+rdx]
    mov rdx, 724F7C332EC094B8h
    add rdx, r9
    mov r8, rdx
    mov r11, -221436D9E29D5DBFh
    xor r8, r11
    mov r11, r8
    mov r12, 255373FD68097175h
    or r11, r12
    not r11
    add r11, r11
    lea r11, [r11+r11*4]
    mov rbx, r8
    mov r15, -255373FD68097176h
    or rbx, r15
    lea r14, [rbx+rbx*4]
    lea rbx, [rbx+r14*2]
    mov r14, r8
    and r14, r12
    shl r14, 3
    mov r12, r8
    and r12, r15
    imul r12, 0F5h
    sub r12, r14
    mov r14, r8
    xor r14, r15
    add r14, r14
    sub r12, r14
    add r12, rbx
    sub r11, r12
    xor r10, r9
    mov rbx, -5276884A0386D443h
    xor rdx, rbx
    xor rdx, r10
    add rdx, r9
    add rdx, r11
    sub rdx, r8
    mov r8, -49EC5E3A9A4C9DFFh
    add rdx, r8
    mov qword ptr [qword_7FFB0FFA4408], rdx
    mov r10, qword ptr [qword_7FFB0FE98BF8]
    mov rdx, 616EC2749CA7A785h
    xor r10, rdx
    mov rdx, 56D3270E2EDAC6EAh
    lea r8, [r10+rdx]
    mov rdx, r8
    mov r9, 45B972497587D31Ch
    xor rdx, r9
    mov r9, -746B242E70DBB110h
    lea r11, [rdx+r9]
    mov r9, -6C5DD49487C3610Fh
    add r9, r10
    mov rbx, r11
    not rbx
    mov r14, r9
    or r14, rbx
    mov r12, r9
    and rbx, r9
    and r9, r11
    lea r9, [r9+r9*2]
    lea rbx, [r9+rbx*4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or r12, r11
    lea r9, [r12]
    sub r9, rbx
    mov rbx, -574A83A2E5BC29AFh
    add rbx, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not r14
    shl r14, 2
    add r11, r11
    sub r9, r11
    sub r9, r14
    xor r9, r8
    sub r9, rbx
    sub r9, r10
    sub r9, rbx
    mov r10, -0FF8BECF4CE29535h
    add r9, r10
    mov r10, -45B972497587D31Dh
    xor r8, r10
    mov r10, r9
    or r10, r8
    lea r11, [r10+r10*4]
    lea r11, [r10+r11*2]
    not r10
    lea rbx, [r10*8]
    sub rbx, r10
    mov r10, r9
    or r10, rdx
    not r10
    mov r14, r10
    shl r14, 4
    add r14, r10
    and r8, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r10, [r8+r8*2]
    not r8
    add r8, r8
    lea r8, [r8+r8*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r9, rdx
    lea rdx, [r9+r9*8]
    lea rdx, [r9+rdx*2]
    lea rdx, [rdx+r10*4]
    sub rdx, r11
    sub rdx, r8
    add r14, rbx
    add r14, rdx
    mov qword ptr [qword_7FFB0FFA4410], r14
    mov rdx, qword ptr [qword_7FFB0FE98C00]
    mov r8, rdx
    mov r9, 2B314B5323A5CD43h
    xor r8, r9
    mov r9, 49B6DB4CC98ABD9Dh
    add r9, r8
    mov rbx, 6969D64902D8B43Ch
    mov r10, rbx
    or r10, r9
    not r10
    add r10, r10
    mov r11, rbx
    and r11, r9
    not r11
    add r11, r11
    xor r9, rbx
    sub r11, r9
    sub r11, r10
    mov r9, rdx
    mov r10, -86CD912D0ABF1E6h
    xor r9, r10
    xor r9, r11
    mov r10, -2B314B5323A5CD44h
    xor rdx, r10
    mov r10, r9
    or r10, rdx
    mov r11, r9
    or r11, r8
    lea rbx, [r9+r9]
    mov r14, r9
    and r14, rdx
    xor rdx, r9
    and r9, r8
    lea r8, [r14+r14*2]
    lea r9, [r9+r9*2]
    add r9, r8
    sub r9, rbx
    add rdx, r11
    add rdx, r9
    sub rdx, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [qword_7FFB0FFA61C8], rdx
    mov dword ptr [rsp+28h], eax
    mov dword ptr [rsp+20h], ecx
    mov rcx, r13
    mov rdx, rbp
    mov r8, rdi
    mov r9, rsi
    call sub_7FFB0FA84070
    mov rcx, r13
    call sub_7FFB0FDD3740
    mov rcx, rax
    not rcx
    mov rdx, rbp
    or rdx, rcx
    not rdx
    lea r8, [rdx+rdx*4]
    lea rdx, [rdx+r8*2]
    mov r8, rbp
    or r8, rax
    lea r9, [r8+r8*4]
    lea r8, [r8+r9*2]
    mov r9, rbp
    xor r9, rax
    and rcx, rbp
    lea rcx, [rcx+rcx*8]
    and rbp, rax
    imul rbp, 0F5h
    sub rbp, rcx
    sub rbp, r9
    add rbp, r8
    sub rbp, rdx
    add r13, rax
    mov rcx, qword ptr [rsp+38h]
    movzx eax, byte ptr [rcx+11h]
    movzx ecx, byte ptr [rcx+10h]
    mov rdx, qword ptr [qword_7FFB0FE98C08]
    mov r8, -5BAF0BECD9320A58h
    add r8, rdx
    mov r9, r8
    mov r15, 477259EFD7C8E9CAh
    or r9, r15
    mov r10, r8
    mov r14, -477259EFD7C8E9CBh
    or r10, r14
    not r10
    lea r10, [r10+r10*2]
    lea r11, [r8+r8*2]
    mov rbx, r8
    and rbx, r15
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    shl rbx, 2
    and r8, r14
    lea r8, [r8+r8*2]
    sub rbx, r8
    add rbx, r11
    lea r10, [rbx+r10*2]
    add r10, r9
    mov r8, 5351E460F14A8545h
    lea r9, [r10+r8]
    mov r8, 7734BE9DFD3335BBh
    add r10, r8
    mov r8, r10
    mov r11, -785D04C50AA4F34Fh
    xor r8, r11
    mov r11, 1682D562E165A79Fh
    add r11, r8
    lea rbx, [r11+r11]
    mov r14, r11
    add r8, r10
    mov r10, r11
    add r8, r11
    mov r15, -4C25B7B5807E730Eh
    or r11, r15
    mov r12, 4C25B7B5807E730Dh
    and r14, r12
    and r10, r15
    mov r15, 32654ACD41B700EEh
    lea r10, [r10+r10*2]
    lea r10, [r10+r14*2]
    not rbx
    add rbx, r10
    lea r10, [r11+rbx]
    inc r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11, r10
    mov rbx, -70EBBC390AE65E9Dh
    xor r11, rbx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rbx, 785D8DED8613064Bh
    add r8, rbx
    add r8, r11
    xor r8, r9
    sub r8, r10
    xor r8, rdx
    mov qword ptr [qword_7FFB0FFA4408], r8
    mov rdx, qword ptr [qword_7FFB0FE98C10]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, -670B6BAD88844C62h
    lea r9, [rdx+r8]
    mov r8, r9
    mov r10, 75DF10E6FE831467h
    xor r8, r10
    mov r10, r9
    mov r11, -369AA5042C2530D4h
    xor r10, r11
    mov r11, -204D72ADE5D6F35Dh
    add r10, r11
    mov r11, -6B3D545826DE87D2h
    xor r10, r11
    add r10, r10
    add rdx, r9
    mov r11, 5BE049ABE373D9EFh
    add rdx, r11
    add rdx, r10
    mov r10, rdx
    or r10, r8
    not r10
    lea r10, [r10+r10*2]
    mov r11, -75DF10E6FE831468h
    xor r9, r11
    mov r11, rdx
    or r11, r9
    add r11, r11
    lea r11, [r11+r11*2]
    mov rbx, rdx
    xor rbx, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r9, rdx
    lea r9, [r9+r9*2]
    add r9, r9
    and rdx, r8
    lea rdx, [rdx+rdx*2]
    lea rdx, [r9+rdx*2]
    add rdx, rbx
    sub rdx, r11
    lea rdx, [rdx+r10*2]
    mov qword ptr [qword_7FFB0FFA4410], rdx
    mov r9, qword ptr [qword_7FFB0FE98C18]
    mov rdx, 49364582CE6F64D9h
    lea r8, [r9+rdx]
    mov rdx, r8
    mov r10, 741909E50026F8EDh
    xor rdx, r10
    mov r10, 2D873A9149303237h
    add r10, rdx
    mov r11, r10
    mov r12, 0AA48C9441EB3DF5h
    or r11, r12
    lea rbx, [r11+r11*2]
    not r11
    lea r14, [r11*8]
    sub r14, r11
    mov r11, r10
    and r11, r12
    lea r11, [r11+rbx*2]
    add r11, r14
    mov rbx, -7
    sub rbx, r11
    mov r11, 608458BE353F0BF2h
    xor r8, r11
    mov r11, 76D19977CE8288CFh
    add r8, r11
    add r8, rbx
    xor r8, r10
    sub r8, r9
    xor rdx, r9
    xor rdx, rbx
    mov r9, 40484E952D96C2BEh
    add r8, r9
    xor rdx, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [qword_7FFB0FFA61C8], rdx
    mov dword ptr [rsp+28h], eax
    mov dword ptr [rsp+20h], ecx
    mov rcx, r13
    mov rdx, rbp
    mov r8, rdi
    mov r9, rsi
    call sub_7FFB0FA84070
    mov rcx, r13
    call sub_7FFB0FDD3740
    mov rcx, rax
    not rcx
    mov rdx, rbp
    or rdx, rcx
    not rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rdx, [rdx+rdx*2]
    mov r8, rbp
    or r8, rax
    not r8
    add r8, r8
    and rcx, rbp
    lea r9, [rcx+rcx*2]
    not rcx
    add rcx, rcx
    and rbp, rax
    mov r10, rbp
    not r10
    add rbp, rbp
    sub rbp, r9
    lea r9, [r10*4]
    add r9, rbp
    sub r9, rcx
    sub r9, r8
    sub r9, rdx
    mov qword ptr [rsp+2C0h], r9
    add r13, rax
    mov qword ptr [rsp+2C8h], r13
    mov rax, qword ptr [rsp+38h]
    movzx ecx, byte ptr [rax+13h]
    mov dword ptr [rsp+13Ch], ecx
    movzx eax, byte ptr [rax+12h]
    mov dword ptr [rsp+140h], eax
    mov rax, qword ptr [qword_7FFB0FE98C20]
    mov qword ptr [rsp+1C0h], rax
    mov rcx, -56167B69E4D17F15h
    add rcx, rax
    mov rdx, -6A974E53B79D775Bh
    xor rcx, rdx
    sub rcx, rax
    mov rdx, 1EAAE7915C490B3h
    add rcx, rdx
    mov qword ptr [rsp+1C8h], rcx
    or rcx, rax
    not rcx
    lea rax, [rcx*8]
    sub rax, rcx
    mov qword ptr [rsp+2D0h], rax
    mov qword ptr [rsp+2D8h], -1
    mov eax, dword ptr [dword_7FFB0FECEC8C]
    mov ecx, eax
    xor ecx, 32F861F8h
    add ecx, 3CD84342h
    xor ecx, 599CA5A6h
    mov edx, eax
    xor edx, -5840AD00h
    add ecx, edx
    add ecx, -5F1F33F6h
    jmp loc_7FFB0DE5829A
    loc_7FFB0DE57DE2:
    mov eax, dword ptr [rsp+44h]
    mov ecx, -740A16D2h
    add eax, ecx
    mov dword ptr [rsp+48h], eax
    mov ecx, eax
    not ecx
    and ecx, 1B2267FCh
    add ecx, ecx
    lea ecx, [rcx+rcx*4]
    mov edx, eax
    or edx, -64DD9804h
    lea r8d, [rdx+rdx*4]
    lea edx, [rdx+r8*2]
    mov r8d, eax
    xor r8d, 1B2267FCh
    add r8d, r8d
    and eax, 4DD9803h
    shl eax, 3
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9d, dword ptr [rsp+48h]
    mov r10d, -64DD9804h
    and r9d, r10d
    imul r9d, 0F5h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r9d, eax
    sub r9d, r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9d, edx
    sub r9d, ecx
    mov dword ptr [rsp+148h], r9d
    lea eax, [r9+25FA654Eh]
    mov dword ptr [rsp+50h], eax
    lea eax, [r9+233DCC7Fh]
    mov dword ptr [rsp+14Ch], eax
    add r9d, 41D3F7D1h
    mov dword ptr [rsp+54h], r9d
    xor r9d, -38470307h
    mov dword ptr [rsp+150h], r9d
    mov eax, dword ptr [rsp+44h]
    mov ecx, -4956448Ah
    and eax, ecx
    lea eax, [rax+rax*8]
    mov dword ptr [rsp+154h], eax
    mov eax, dword ptr [dword_7FFB0FECECB8]
    lea ecx, [rax-3BC610A5h]
    mov edx, ecx
    xor edx, -43972D73h
    add edx, eax
    add edx, 3C2F66C8h
    xor edx, ecx
    add edx, eax
    jmp loc_7FFB0DE511D0
    loc_7FFB0DE57FCE:
    mov rax, qword ptr [rsp+270h]
    and rax, qword ptr [rsp+260h]
    add rax, qword ptr [rsp+298h]
    sub rax, qword ptr [rsp+290h]
    add rax, qword ptr [rsp+288h]
    sub rax, qword ptr [rsp+280h]
    add rax, qword ptr [rsp+278h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rax, qword ptr [rsp+268h]
    add rax, qword ptr [rsp+1A8h]
    add rax, qword ptr [rsp+258h]
    mov qword ptr [rsp+2A0h], rax
    mov eax, dword ptr [dword_7FFB0FECEC70]
    mov ecx, -3C04F1EDh
    xor eax, ecx
    lea ecx, [rax-62A016C0h]
    lea edx, [rax-5C816FC3h]
    xor edx, 5AB79753h
    lea r8d, [rax+2F5F4780h]
    xor r8d, eax
    xor r8d, edx
    sub r8d, edx
    add r8d, 43295593h
    jmp loc_7FFB0DE5830F
    loc_7FFB0DE580D0:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+370h]
    not rax
    add rax, rax
    mov qword ptr [rsp+378h], rax
    mov eax, dword ptr [dword_7FFB0FECEC1C]
    lea ecx, [rax+54E5C19h]
    xor ecx, -57F5812Eh
    add eax, ecx
    add eax, 11187F1h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE5815D:
    mov rax, qword ptr [rsp+308h]
    cmp dword ptr [rax+8], 0
    jle loc_7FFB0DE582A5
    loc_7FFB0DE5816F:
    mov rax, qword ptr [qword_7FFB0FE98C38]
    mov qword ptr [rsp+0B8h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+0B8h]
    mov rcx, -5C82169EA603C57Dh
    add rcx, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, 2B9B46F7EE67050h
    add rax, rdx
    add rax, rax
    mov rdx, 3B13FE7D81F02C72h
    sub rdx, rax
    xor rdx, rcx
    mov qword ptr [rsp+310h], rdx
    or rdx, qword ptr [rsp+0B8h]
    mov qword ptr [rsp+328h], rdx
    not rdx
    lea rax, [rdx*8]
    sub rax, rdx
    mov qword ptr [rsp+318h], rax
    mov qword ptr [rsp+320h], -7
    mov eax, dword ptr [dword_7FFB0FECECAC]
    mov ecx, eax
    xor ecx, 5D0FF2E8h
    sub ecx, eax
    xor eax, -600205ACh
    add eax, 0D8F1422h
    loc_7FFB0DE5829A:
    xor ecx, eax
    mov dword ptr [rsp+30h], ecx
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE582A5:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FFB0DE582E6:
    mov eax, dword ptr [dword_7FFB0FECEBF0]
    lea ecx, [rax+4A52F6D1h]
    lea edx, [rax+7F858395h]
    mov r8d, edx
    xor r8d, -1421866Bh
    add r8d, -768F67EAh
    xor r8d, edx
    sub r8d, eax
    loc_7FFB0DE5830F:
    xor r8d, ecx
    mov dword ptr [rsp+30h], r8d
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE5831C:
    mov eax, dword ptr [dword_7FFB0FECEC48]
    mov ecx, eax
    xor ecx, 45610A84h
    lea edx, [rcx+35433D01h]
    lea r8d, [rcx+5D6C0B07h]
    lea r9d, [rcx+3225BF9Bh]
    lea r10d, [rcx-6CA9CA39h]
    xor r10d, 2E6A972h
    mov r11d, -639ADC15h
    sub r11d, ecx
    xor r11d, r8d
    add r11d, eax
    sub r11d, r10d
    xor r9d, ecx
    xor r9d, edx
    xor r9d, r11d
    mov dword ptr [rsp+30h], r9d
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE58371:
    mov rax, qword ptr [rsp+98h]
    cmp byte ptr [rax], 0
    jz loc_7FFB0DE582E6
    mov rax, qword ptr [rsp+1B0h]
    mov rax, qword ptr [rax]
    test rax, rax
    jz loc_7FFB0DE58530
    mov eax, dword ptr [rax+8]
    mov dword ptr [rsp+144h], eax
    mov eax, dword ptr [dword_7FFB0FE98B64]
    mov dword ptr [rsp+44h], eax
    mov eax, dword ptr [dword_7FFB0FECEC88]
    mov ecx, eax
    xor ecx, 30619915h
    lea edx, [rcx-47B9C7F6h]
    mov r8d, edx
    xor r8d, -4E308F51h
    sub r8d, edx
    add r8d, -253ABD79h
    jmp loc_7FFB0DE525CF
    loc_7FFB0DE583D7:
    mov eax, dword ptr [dword_7FFB0FECEC08]
    lea ecx, [rax-605D596Ah]
    xor ecx, eax
    xor ecx, 433811BAh
    add ecx, -53FC9E35h
    mov dword ptr [rsp+30h], ecx
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE583FA:
    mov eax, dword ptr [dword_7FFB0FECEC98]
    lea ecx, [rax-0E609DBAh]
    mov edx, ecx
    xor edx, 29DB44AAh
    sub ecx, edx
    add edx, 4B252BE0h
    add ecx, -1DE0A20Dh
    xor ecx, edx
    add eax, ecx
    add eax, -1DEE0C5Dh
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE5842E:
    mov eax, dword ptr [dword_7FFB0FECEC38]
    mov ecx, eax
    xor ecx, 5020EC4Fh
    lea edx, [rcx+784F9B82h]
    xor edx, 700B318Ah
    add eax, edx
    add eax, -29AC15BCh
    xor eax, edx
    add eax, ecx
    add eax, 1A0206AEh
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE58461:
    mov eax, dword ptr [dword_7FFB0FECECE4]
    lea ecx, [rax+67B40621h]
    xor ecx, 5ACDA35h
    lea edx, [rcx-7ED07F13h]
    mov r8d, -4BF1557Eh
    sub r8d, eax
    xor r8d, ecx
    add ecx, -3639D9E6h
    xor r8d, edx
    add eax, r8d
    add eax, -742F7C9Eh
    xor eax, ecx
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE584A1:
    mov eax, dword ptr [dword_7FFB0FECEC50]
    mov ecx, eax
    xor ecx, -6CED4649h
    lea edx, [rcx+2503DC68h]
    xor eax, edx
    xor eax, -0B8C8541h
    add eax, ecx
    add eax, 5665362Eh
    xor eax, edx
    xor eax, -7642225Bh
    add eax, 24410673h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE584D8:
    mov eax, dword ptr [dword_7FFB0FECED0C]
    mov ecx, eax
    xor ecx, 2A0C4BBBh
    lea edx, [rcx-1AD107D9h]
    xor edx, 4CC30838h
    lea r8d, [rdx-51B3E19Fh]
    mov r9d, ecx
    sub r9d, r8d
    lea r8d, [rcx+r9]
    add r8d, -1AD107D9h
    sub r8d, eax
    add r8d, 148DBDA8h
    xor r8d, ecx
    lea eax, [rdx+r8]
    add eax, -51B3E19Fh
    add eax, edx
    add eax, -13B4DC02h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0DE511D4
    loc_7FFB0DE58530:
    mov eax, dword ptr [dword_7FFB0FECECD8]
    lea ecx, [rax-4E0E2F9h]
    lea edx, [rax-639029D7h]
    xor edx, 7A088F88h
    neg edx
    add edx, eax
    add edx, -59E8F6DBh
    xor edx, ecx
    lea ecx, [rax+rdx]
    add ecx, 50EEFA33h
    jmp loc_7FFB0DE56173
    loc_7FFB0DE58562:
    mov rcx, qword ptr [rsp+4C0h]
    xor rcx, rsp
    cmp rcx, qword ptr [__security_cookie]
    jnz loc_7FFB0DE5858A
    add rsp, 4C8h
    pop rbx
    pop rbp
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    ret
    loc_7FFB0DE5858A:
    call __security_check_cookie
    int 3
_TEXT ENDS
END

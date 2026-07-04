; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: Java_dimension_DimensionAPI_getHuzpsbPY  @ 0x1815a1670
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN RtlRandom:PROC
EXTERN __alloca_probe:PROC
EXTERN _invalid_parameter_noinfo_noreturn:PROC
EXTERN memmove:PROC
EXTERN sub_1800C2C90:PROC
EXTERN sub_180146890:PROC
EXTERN sub_18053CC50:PROC
EXTERN sub_180550530:PROC
EXTERN sub_1817B7FB0:PROC

CONST SEGMENT
unk_181D58F92 db 8Eh
qword_181D5ABC0 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
qword_181D5ABE0 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
qword_181D5AC00 dq 1
dq 1
dq 1
dq 0
qword_181D5AC20 dq 0FFFh
dq 0FFFh
dq 0FFFh
dq 0
unk_181D5AC40 db 28h
unk_181D5AC60 db 28h
unk_181D5AC80 db 7
qword_181D5ACA0 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
unk_181D5ACC0 db 0Fh
qword_181D5ACE0 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
qword_181D5AD00 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
qword_181D5AD20 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
unk_181D5AD40 db 0Fh
qword_181D5AD60 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
qword_181D5AD80 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
unk_181D5ADA0 db 0Fh
unk_181D5ADC0 db 0Fh
unk_181D5ADE0 db 0Fh
qword_181D5AE00 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
qword_181D5AE20 dq 1
dq 1
dq 1
dq 0
qword_181D5AE40 dq 0FFFh
dq 0FFFh
dq 0FFFh
dq 0
unk_181D5AE60 db 28h
unk_181D5AE80 db 28h
unk_181D5AEA0 db 7
qword_181D5AEC0 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
qword_181D5AEE0 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
qword_181D5AF00 dq 1
dq 1
dq 1
dq 0
qword_181D5AF20 dq 0FFFh
dq 0FFFh
dq 0FFFh
dq 0
unk_181D5AF40 db 28h
unk_181D5AF60 db 28h
unk_181D5AF80 db 7
qword_181D5AFA0 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
qword_181D5AFC0 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
qword_181D5AFE0 dq 1
dq 1
dq 1
dq 0
qword_181D5B000 dq 0FFFh
dq 0FFFh
dq 0FFFh
dq 0
unk_181D5B020 db 28h
unk_181D5B040 db 28h
unk_181D5B060 db 7
qword_181D5B080 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
qword_181D5B0A0 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
unk_181D5B0C0 db 0Fh
qword_181D5B0E0 dq 1
dq 1
dq 1
dq 0
qword_181D5B100 dq 0FFFh
dq 0FFFh
dq 0FFFh
dq 0
unk_181D5B120 db 28h
unk_181D5B140 db 28h
unk_181D5B160 db 7
qword_181D5B180 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
qword_181D5B1A0 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
qword_181D5B1C0 dq 1
dq 1
dq 1
dq 0
qword_181D5B1E0 dq 0FFFh
dq 0FFFh
dq 0FFFh
dq 0
unk_181D5B200 db 28h
unk_181D5B220 db 28h
unk_181D5B240 db 7
qword_181D5B260 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
qword_181D5B280 dq 0Fh
dq 0Fh
dq 0Fh
dq 0
qword_181D5B2A0 dq 1
dq 1
dq 1
dq 0
qword_181D5B2C0 dq 0FFFh
dq 0FFFh
dq 0FFFh
dq 0
unk_181D5B2E0 db 28h
unk_181D5B300 db 28h
unk_181D5B320 db 7
dword_1820F8A00 dd 0E2E0BB39h
dword_1820F8A04 dd 6D225E71h
dword_1820F8A08 dd 9B5F3AF4h
dword_1820F8A0C dd 0B588B3C4h
dword_1820F8A10 dd 0C0E6E403h
dword_1820F8A14 dd 6E6A029Eh
dword_1820F8A18 dd 78C9E50Bh
dword_1820F8A1C dd 0CA41D382h
dword_1820F8A20 dd 914D2666h
dword_1820F8A24 dd 1AAB811Ch
dword_1820F8A28 dd 9B920365h
dword_1820F8A2C dd 53F20549h
dword_1820F8A30 dd 0FDF879D4h
dword_1820F8A34 dd 0FD273A02h
dword_1820F8A38 dd 0C0932A1Eh
dword_1820F8A3C dd 286A3022h
dword_1820F8A40 dd 9BD79DE1h
dword_1820F8A44 dd 16F50CB4h
dword_1820F8A48 dd 5B5D39Ch
dword_1820F8A4C dd 0E16FB9B7h
dword_1820F8A50 dd 784AAEA6h
dword_1820F8A54 dd 78953D28h
dword_1820F8A58 dd 252FBB12h
dword_1820F8A5C dd 0BB0813CDh
dword_1820F8A60 dd 38D31EEAh
dword_1820F8A64 dd 4D85D846h
dword_1820F8A68 dd 0C027406Dh
dword_1820F8A6C dd 0F4B6D2E6h
dword_1820F8A70 dd 3FA6E568h
dword_1820F8A74 dd 0C3769B6Fh
qword_1820F8A78 dq 0B1AC7E824CA4C15h
qword_1820F8A80 dq -64269C648ACE3C5h
byte_1820F8A88 db 0F9h
byte_1820F8A89 db 77h
dword_1820F8A8C dd 4F0D36Dh
dword_1820F8A90 dd 6AC346A0h
dword_1820F8A94 dd 8343A824h
dword_1820F8A98 dd 0E48E3674h
dword_1820F8A9C dd 17021031h
dword_1820F8AA0 dd 4BF239F8h
byte_1820F8AA4 db 0A6h
byte_1820F8AA5 db 0E1h
qword_1820F8AA8 dq 2E4245F399F8FF50h
qword_1820F8AB0 dq -59D71F66416938A1h
byte_1820F8AB8 db 5Ch
byte_1820F8AB9 db 6Eh
dword_1820F8ABC dd 1597CDFBh
dword_1820F8AC0 dd 0D965477Bh
dword_1820F8AC4 dd 73AB102Ch
dword_1820F8AC8 dd 987CD4B9h
dword_1820F8ACC dd 20B4AD59h
dword_1820F8AD0 dd 8FDE6632h
dword_1820F8AD4 dd 299348B9h
dword_1820F8AD8 dd 4A9D01C7h
byte_1820F8ADC db 72h
byte_1820F8ADD db 0D6h
dword_1820F8AE0 dd 9906E035h
dword_1820F8AE4 dd 580F4082h
dword_1820F8AE8 dd 7A75EFCh
dword_1820F8AEC dd 22AB9348h
qword_1820F8AF0 dq -116785A2E2203147h
qword_1820F8AF8 dq -19A4778F288A831Ah
qword_1820F8B00 dq 729D8A2B511186FAh
qword_1820F8B08 dq 33AC1CB1663535E1h
byte_1820F8B10 db 48h
byte_1820F8B11 db 0BCh
dword_1820F8B14 dd 0F2791454h
dword_1820F8B18 dd 0C3C3CEB8h
dword_1820F8B1C dd 20B2A29Dh
dword_1820F8B20 dd 0B5F74284h
dword_1820F8B24 dd 0FFDEB6C9h
dword_1820F8B28 dd 918215D2h
dword_1820F8B2C dd 0D3EB8DBh
dword_1820F8B30 dd 0C3B9300Ah
dword_1820F8B34 dd 91380812h
dword_1820F8B38 dd 0E062072h
dword_1820F8B3C dd 7F59EDAh
dword_1820F8B40 dd 5CD2FB1Dh
byte_1820F8B44 db 0DBh
byte_1820F8B45 db 0F7h
qword_1820F8B48 dq -67B59B1B82B78E29h
qword_1820F8B50 dq 78607C8E78A8B4B1h
byte_1820F8B58 db 0D1h
byte_1820F8B59 db 3
dword_1820F8B5C dd 0B476C6Ah
dword_1820F8B60 dd 9BC4EA65h
dword_1820F8B64 dd 33CE5BF7h
dword_1820F8B68 dd 0A227DBD7h
dword_1820F8B6C dd 0BD045132h
dword_1820F8B70 dd 892CE221h
dword_1820F8B74 dd 6CA44494h
dword_1820F8B78 dd 9F328926h
dword_1820F8B7C dd 0AA40954Fh
dword_1820F8B80 dd 0C613B3C4h
dword_1820F8B84 dd 0FE3EA7Bh
dword_1820F8B88 dd 0FA1967C0h
qword_1820F8B90 dq 71EB7E47BEC8D41h
qword_1820F8B98 dq -624C82C2CD61888Ah
byte_1820F8BA0 db 1Fh
byte_1820F8BA1 db 11h
dword_1820F8BA4 dd 8069D840h
dword_1820F8BA8 dd 0EFCAA821h
dword_1820F8BAC dd 4C30983h
dword_1820F8BB0 dd 0F152A24Ah
dword_1820F8BB4 dd 0A95DCD37h
dword_1820F8BB8 dd 6C3C07FBh
dword_1820F8BBC dd 991DA472h
dword_1820F8BC0 dd 0CED9FE86h
dword_1820F8BC4 dd 0FD91AA27h
dword_1820F8BC8 dd 29F4C5E0h
dword_1820F8BCC dd 847F32A6h
dword_1820F8BD0 dd 5C9CD3D3h
qword_1820F8BD8 dq 359C0A8AFC110F9Dh
qword_1820F8BE0 dq -2236068D1A5A3457h
byte_1820F8BE8 db 7
byte_1820F8BE9 db 9
dword_1820F8BEC dd 0A2B47E2Ch
dword_1820F8BF0 dd 50F3BDD5h
dword_1820F8BF4 dd 0B3FC63Ch
dword_1820F8BF8 dd 0C354F148h
dword_1820F8BFC dd 0EC150F33h
dword_1820F8C00 dd 0ECA8AC38h
dword_1820F8C04 dd 0F2D062F7h
dword_1820F8C08 dd 0F43E09CEh
dword_1820F8C0C dd 33DCB0CBh
dword_1820F8C10 dd 6DDB2780h
dword_1820F8C14 dd 0B2FA2B12h
dword_1820F8C18 dd 0A631851h
qword_1820F8C20 dq -3E9AFB06937450C6h
qword_1820F8C28 dq 1ED88A9DADD7925Ch
byte_1820F8C30 db 0F4h
byte_1820F8C31 db 1Ah
dword_1820F8C34 dd 0F56A69AFh
dword_1820F8C38 dd 0F9C876B5h
dword_1820F8C3C dd 185D5F3Dh
dword_1820F8C40 dd 1FEF09D4h
dword_1820F8C44 dd 29AFE43Bh
dword_1820F8C48 dd 0DD4EA1D7h
dword_1820F8C4C dd 0BD490383h
dword_1820F8C50 dd 9186686Ah
dword_1820F8C54 dd 6331554h
dword_1820F8C58 dd 5CEA2B3Bh
dword_1820F8C5C dd 0B3F57384h
dword_1820F8C60 dd 7D6EB462h
dword_1820F8C64 dd 8B41195Eh
dword_1820F8C68 dd 0BAF509C2h
dword_1820F8C6C dd 95820533h
dword_1820F8C70 dd 13439309h
qword_1820F8C78 dq 0BA235E9D6EC516Eh
qword_1820F8C80 dq 566FC40B483613F6h
byte_1820F8C88 db 9Fh
byte_1820F8C89 db 0DCh
dword_1820F8C8C dd 0B8F803F9h
dword_1820F8C90 dd 94A793A7h
dword_1820F8C94 dd 93F69E3Bh
dword_1820F8C98 dd 3B6BADFh
dword_1820F8C9C dd 51BE9157h
dword_1820F8CA0 dd 0A41313F0h
dword_1820F8CA4 dd 9DD30A3Ch
dword_1820F8CA8 dd 0A56924CCh
dword_1820F8CAC dd 0D0657D70h
dword_1820F8CB0 dd 59D0F05Ch
dword_1820F8CB4 dd 0BF1D6DD1h
dword_1820F8CB8 dd 7BEB9AC6h
qword_1820F8CC0 dq 120824175F1CC0DAh
qword_1820F8CC8 dq -33AB6030A756583Ch
byte_1820F8CD0 db 5Ch
byte_1820F8CD1 db 1Fh
dword_1820F8CD4 dd 0C049B8E2h
dword_1820F8CD8 dd 32A17208h
dword_1820F8CDC dd 0B6F5C487h
dword_1820F8CE0 dd 92E1519Fh
dword_1820F8CE4 dd 82EA9F61h
dword_1820F8CE8 dd 6BEC5031h
dword_1820F8CEC dd 0EFBF51FCh
dword_1820F8CF0 dd 6EFAF1ACh
dword_1820F8CF4 dd 20AC2A00h
dword_1820F8CF8 dd 0A8F74EF1h
dword_1820F8CFC dd 0F268DE68h
dword_1820F8D00 dd 0B36BDF82h
off_182108150 dq -203DD5BAF5CD885Bh
off_182108158 dq -203DD5BAF4C3862Bh
off_182108160 dq -203DD5BAF4C3851Bh
off_182108168 dq -203DD5BAF4C383EBh
off_182108170 dq -203DD5BAF4C382BBh
off_182108178 dq -203DD5BAF4C381BBh
off_182108180 dq -203DD5BAF4C380ABh
off_182108188 dq -203DD5BAF4C37FABh
off_182108198 dq -203DD5BAF4A23863h
off_1821081A8 dq -203DD5BAF4C37EABh
off_1821081B0 dq -203DD5BAF4C37DABh
off_1821081B8 dq -203DD5BAF4C37C9Bh
off_1821081C0 dq -203DD5BAF4C37B8Bh
off_1821081C8 dq -203DD5BAF4C37A8Bh
off_1821081D0 dq -203DD5BAF4BF9D2Bh
off_1821081D8 dq -203DD5BAF4C3797Bh
off_1821081E0 dq -203DD5BAF4C3785Bh
off_1821081E8 dq -203DD5BAF4C3772Bh
off_1821081F0 dq -203DD5BAF4C375FBh
off_1821081F8 dq -203DD5BAF49F3BDBh
off_182108200 dq -203DD5BAF4C374FBh
off_182108208 dq -203DD5BAF4C373EBh
off_182108210 dq -203DD5BAF4C372EBh
off_182108218 dq -203DD5BAF4C371BBh
off_182108220 dq -203DD5BAF4C3708Bh
off_182108228 dq -203DD5BAF4C36F5Bh
off_182108230 dq -203DD5BAF4C36E4Bh
off_182108238 dq -203DD5BAF4C36D2Bh
off_182108240 dq -203DD5BAF4C36C0Bh
off_182108248 dq -203DD5BAF4C36ADBh
off_182108250 dq -203DD5BAF4C369CBh
off_182108258 dq -203DD5BAF4C3689Bh
off_182108260 dq -203DD5BAF4C3676Bh
off_182108268 dq -203DD5BAF4C3665Bh
off_182108270 dq -203DD5BAF4C3652Bh
off_182108278 dq -203DD5BAF4C3641Bh
off_182108280 dq -203DD5BAF4C362EBh
off_182108288 dq -203DD5BAF4C361EBh
off_182108290 dq -203DD5BAF4C360BBh
off_182108298 dq -203DD5BAF4C35F8Bh
off_1821082A0 dq -203DD5BAF4C35E6Bh
off_1821082A8 dq -203DD5BAF4C35D6Bh
off_1821082B0 dq -203DD5BAF4C35C6Bh
off_1821082B8 dq -203DD5BAF4C35B6Bh
off_1821082C0 dq -203DD5BAF4C35A6Bh
off_1821082C8 dq -203DD5BAF4C3593Bh
off_1821082D0 dq -203DD5BAF4C3583Bh
off_1821082D8 dq -203DD5BAF4C3570Bh
off_1821082E0 dq -203DD5BAF4C355FBh
off_1821082E8 dq -203DD5BAF4C354EBh
off_1821082F0 dq -203DD5BAF4C353CBh
off_1821082F8 dq -203DD5BAF4C3529Bh
off_182108300 dq -203DD5BAF4C3516Bh
off_182108308 dq -203DD5BAF4C3505Bh
off_182108310 dq -203DD5BAF4C34F4Bh
off_182108318 dq -203DD5BAF4C34E1Bh
off_182108320 dq -203DD5BAF4C34D1Bh
off_182108328 dq -203DD5BAF4C34C0Bh
off_182108330 dq -203DD5BAF4C34AFBh
off_182108338 dq -203DD5BAF4C349CBh
off_182108340 dq -203DD5BAF4C3489Bh
off_182108348 dq -203DD5BAF4C3477Bh
off_182108350 dq -203DD5BAF4C3466Bh
off_182108358 dq -203DD5BAF4C3453Bh
off_182108360 dq -203DD5BAF4C3441Bh
off_182108368 dq -203DD5BAF4C3430Bh
off_182108370 dq -203DD5BAF4C3420Bh
off_182108378 dq -203DD5BAF4C340DBh
off_182108380 dq -203DD5BAF4C33FCBh
off_182108388 dq -203DD5BAF4C33E9Bh
off_182108390 dq -203DD5BAF4C33D8Bh
off_182108398 dq -203DD5BAF4C33C5Bh
off_1821083A0 dq -203DD5BAF4C33B4Bh
off_1821083A8 dq -203DD5BAF4C33A3Bh
off_1821083B0 dq -203DD5BAF4C3391Bh
off_1821083B8 dq -203DD5BAF4C3381Bh
off_1821083C0 dq -203DD5BAF4C336EBh
off_1821083C8 dq -203DD5BAF4C335BBh
off_1821083D0 dq -203DD5BAF4C3348Bh
off_1821083D8 dq -203DD5BAF4C3336Bh
off_1821083E0 dq -203DD5BAF4C3323Bh
off_1821083E8 dq -203DD5BAF4C3312Bh
off_1821083F0 dq -203DD5BAF4C3302Bh
off_1821083F8 dq -203DD5BAF4C32F2Bh
off_182108400 dq -203DD5BAF4C32DFBh
Seed dd 0FFFFFFFFh
qword_18215B1B8 dq -1
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC Java_dimension_DimensionAPI_getHuzpsbPY
Java_dimension_DimensionAPI_getHuzpsbPY:
    push rbp
    push r15
    push r14
    push r13
    push r12
    push rsi
    push rdi
    push rbx
    sub rsp, 78h
    lea rbp, [rsp+70h]
    movups xmmword ptr [rbp-10h], xmm6
    mov qword ptr [rbp-18h], -2
    mov rbx, rdx
    mov rdi, rcx
    mov eax, dword ptr [dword_1820F8A00]
    mov ecx, dword ptr [dword_1820F8A04]
    shrd ecx, eax, 1Ch
    xor ecx, 2E0BB397h
    mov eax, ecx
    shl rax, 5
    call __alloca_probe
    sub rsp, rax
    mov rcx, rsp
    mov eax, dword ptr [dword_1820F8A08]
    mov edx, dword ptr [dword_1820F8A0C]
    shrd edx, eax, 10h
    xor edx, 3AF4B589h
    mov eax, edx
    shl rax, 5
    call __alloca_probe
    sub rsp, rax
    mov rdx, rsp
    imul eax, dword ptr [dword_1820F8A10], 37AFC4FDh
    imul r9d, dword ptr [dword_1820F8A14], -10850EBFh
    add eax, r9d
    add eax, 7B83F4ECh
    shl rax, 5
    call __alloca_probe
    sub rsp, rax
    mov r15, rsp
    mov eax, dword ptr [dword_1820F8A18]
    mov r9d, dword ptr [dword_1820F8A1C]
    shrd r9d, eax, 1
    xor r9d, -1ADF1640h
    mov eax, r9d
    shl rax, 5
    call __alloca_probe
    sub rsp, rax
    mov r9, rsp
    imul eax, dword ptr [dword_1820F8A20], -3A33D4B9h
    imul r10d, dword ptr [dword_1820F8A24], -3B235AB6h
    add eax, r10d
    add eax, 304D99Fh
    shl rax, 5
    call __alloca_probe
    sub rsp, rax
    mov r10, rsp
    imul eax, dword ptr [dword_1820F8A28], -30AB5243h
    imul r11d, dword ptr [dword_1820F8A2C], 3AB7697Ah
    add eax, r11d
    add eax, 1A13C7A6h
    shl rax, 5
    call __alloca_probe
    sub rsp, rax
    mov r11, rsp
    mov eax, dword ptr [dword_1820F8A30]
    mov esi, dword ptr [dword_1820F8A34]
    shrd esi, eax, 1Bh
    xor esi, -40F0C562h
    mov eax, esi
    shl rax, 5
    call __alloca_probe
    sub rsp, rax
    mov rax, rsp
    mov r14, 203DD5BC762154ABh
    mov qword ptr [rbp-58h], r8
    test r8, r8
    mov qword ptr [rbp-48h], rdi
    jz loc_1815A375D
    mov qword ptr [rbp-60h], rbx
    mov rsi, rdx
    mov qword ptr [rbp-28h], r15
    mov qword ptr [rbp-30h], r9
    mov qword ptr [rbp-50h], r10
    mov qword ptr [rbp-20h], r11
    mov qword ptr [rbp-38h], rax
    mov qword ptr [rdx], 0
    mov rax, qword ptr [off_1821081A8]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov rax, -49767383605CBBC6h
    imul rax, qword ptr [qword_1820F8A78]
    mov rcx, 261DE4D663EB409Ch
    imul rcx, qword ptr [qword_1820F8A80]
    add rcx, rax
    mov rax, -38ECE821C746C4B6h
    add rax, rcx
    mov qword ptr [rsi+10h], rax
    mov rax, qword ptr [off_1821081B0]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, qword_181D5ACA0
    mov rax, qword ptr [rcx+rax*8]
    mov qword ptr [rsi+18h], rax
    mov rax, qword ptr [off_1821081B8]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    movzx eax, byte ptr [byte_1820F8A88]
    movzx ecx, byte ptr [byte_1820F8A89]
    shr cl, 4
    shl al, 4
    or al, cl
    xor al, 97h
    mov qword ptr [rbp-40h], rsi
    mov byte ptr [rsi], al
    lea rdi, unk_181D5ACC0
    lea rbx, qword_181D5ACE0
    xorps xmm6, xmm6
    lea r14, unk_181D58F92
    lea r15, qword_18215B1B8
    mov ecx, 62CE9A1Ch
    mov r13, qword ptr [rbp-40h]
    jmp loc_1815A18D5
    loc_1815A18D0:
    mov ecx, 0FCD789Fh
    loc_1815A18D5:
    cmp ecx, 0FCD789Fh
    jz loc_1815A1900
    mov eax, ecx
    cmp ecx, 62CE9A1Ch
    jz loc_1815A18D0
    mov ecx, eax
    cmp eax, -1602613Ch
    jnz loc_1815A18D5
    jmp loc_1815A1AC8
    loc_1815A1900:
    mov r12, qword ptr [r13]
    mov rsi, qword ptr [r13+18h]
    mov rax, qword ptr [off_1821081C0]
    mov rcx, 203DD5BC762154ABh
    add rax, rcx
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov ecx, dword ptr [dword_1820F8A8C]
    mov edx, dword ptr [dword_1820F8A90]
    shrd edx, ecx, 12h
    cdqe
    xor edx, 68B74FB3h
    mov ecx, dword ptr [dword_1820F8A94]
    mov r8d, dword ptr [dword_1820F8A98]
    shrd r8d, ecx, 1Fh
    xor r8d, -43AB0342h
    cmp rsi, qword ptr [rdi+rax*8]
    mov eax, r8d
    cmova eax, edx
    mov rcx, r13
    mov r8d, -18C65315h
    jmp loc_1815A1979
    loc_1815A1970:
    mov rcx, r12
    mov r8d, -452C5309h
    loc_1815A1979:
    mov edx, r8d
    mov r8d, eax
    cmp edx, -18C65315h
    jz loc_1815A1979
    cmp edx, 5C6C1503h
    jz loc_1815A1970
    mov rsi, rcx
    mov r8d, edx
    cmp edx, -452C5309h
    jnz loc_1815A1979
    mov rax, qword ptr [off_1821081C8]
    mov r12, 203DD5BC762154ABh
    add rax, r12
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov rax, qword ptr [rbx+rax*8]
    mov rcx, qword ptr [rbp-40h]
    mov qword ptr [rcx+10h], rax
    imul eax, dword ptr [dword_1820F8A9C], -3225E0EBh
    imul ecx, dword ptr [dword_1820F8AA0], -354E7C04h
    add eax, ecx
    add eax, 24B56950h
    mov r10, qword ptr [off_1821081D0]
    add r10, r12
    sub rsp, 110h
    mov dword ptr [rsp+100h], eax
    movups xmmword ptr [rsp+0F0h], xmm6
    movups xmmword ptr [rsp+0E0h], xmm6
    movups xmmword ptr [rsp+0D0h], xmm6
    movups xmmword ptr [rsp+0C0h], xmm6
    movups xmmword ptr [rsp+0B0h], xmm6
    movups xmmword ptr [rsp+0A0h], xmm6
    movups xmmword ptr [rsp+90h], xmm6
    movups xmmword ptr [rsp+80h], xmm6
    movups xmmword ptr [rsp+70h], xmm6
    movups xmmword ptr [rsp+60h], xmm6
    mov qword ptr [rsp+58h], r14
    mov qword ptr [rsp+50h], r15
    movups xmmword ptr [rsp+40h], xmm6
    movups xmmword ptr [rsp+30h], xmm6
    movups xmmword ptr [rsp+20h], xmm6
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    call r10
    add rsp, 110h
    mov rax, qword ptr [qword_18215B1B8]
    mov qword ptr [rsi], rax
    mov rax, qword ptr [qword_18215B1B8+7]
    mov qword ptr [rsi+7], rax
    mov rax, qword ptr [off_1821081D8]
    add rax, r12
    sub rsp, 20h
    call rax
    add rsp, 20h
    movzx eax, byte ptr [byte_1820F8AA4]
    movzx ecx, byte ptr [byte_1820F8AA5]
    mov edx, ecx
    shl ecx, 4
    sub edx, ecx
    mov ecx, edx
    shl al, 6
    sub cl, al
    add cl, 0AFh
    mov byte ptr [rsi+0Fh], cl
    mov ecx, -1602613Ch
    jmp loc_1815A18D5
    loc_1815A1AC8:
    nop
    loc_1815A1AC9:
    sub rsp, 20h
    lea rcx, Seed
    call qword ptr [RtlRandom]
    add rsp, 20h
    nop
    mov rbx, qword ptr [rbp-48h]
    mov rax, qword ptr [rbx]
    nop
    sub rsp, 20h
    mov rcx, rbx
    mov rdx, qword ptr [rbp-58h]
    xor r8d, r8d
    call qword ptr [rax+548h]
    add rsp, 20h
    nop
    loc_1815A1B00:
    mov r14, rax
    mov rdi, qword ptr [rbp-28h]
    mov qword ptr [rdi], 0
    mov rax, qword ptr [off_1821081E0]
    mov rsi, 203DD5BC762154ABh
    add rax, rsi
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov rax, -66BEF9EA9B7588A3h
    imul rax, qword ptr [qword_1820F8AA8]
    mov rcx, -611CA76DFBD910BDh
    imul rcx, qword ptr [qword_1820F8AB0]
    add rcx, rax
    mov rax, 1546F190B70B3113h
    add rax, rcx
    mov qword ptr [rdi+10h], rax
    mov rax, qword ptr [off_1821081E8]
    add rax, rsi
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, qword_181D5AD00
    mov rax, qword ptr [rcx+rax*8]
    mov qword ptr [rdi+18h], rax
    mov rax, qword ptr [off_1821081F0]
    add rax, rsi
    sub rsp, 20h
    call rax
    add rsp, 20h
    movzx eax, byte ptr [byte_1820F8AB8]
    movzx ecx, byte ptr [byte_1820F8AB9]
    shr cl, 1
    shl al, 7
    or al, cl
    xor al, 37h
    mov byte ptr [rdi], al
    mov rax, qword ptr [off_1821081F8]
    add rax, rsi
    sub rsp, 20h
    mov rcx, r14
    call rax
    add rsp, 20h
    mov r12, rax
    mov r15, rax
    mov rax, qword ptr [off_182108200]
    add rax, rsi
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    imul ecx, dword ptr [dword_1820F8ABC], -4B106617h
    lea rdx, qword_181D5AD20
    imul r8d, dword ptr [dword_1820F8AC0], -5BB15941h
    mov r9d, dword ptr [dword_1820F8AC4]
    mov r10d, dword ptr [dword_1820F8AC8]
    shrd r10d, r9d, 18h
    xor r10d, -5B22ABF9h
    cmp r12, qword ptr [rdx+rax*8]
    mov eax, r8d
    lea esi, [rcx+rax+406FCA5Eh]
    cmovbe esi, r10d
    lea rdi, unk_181D5AD40
    mov ecx, 62CE9A1Ch
    mov r13, qword ptr [rbp-28h]
    jmp loc_1815A1C79
    loc_1815A1C50:
    cmp eax, -2291A26Ah
    jnz loc_1815A1DA3
    nop
    loc_1815A1C5C:
    sub rsp, 20h
    mov rcx, qword ptr [rbp-28h]
    mov rdx, r15
    mov r9, r14
    call sub_1800C2C90
    add rsp, 20h
    nop
    loc_1815A1C74:
    mov ecx, -1602613Ch
    loc_1815A1C79:
    mov eax, ecx
    cmp ecx, 0FCD789Eh
    jle loc_1815A1C50
    mov ecx, esi
    cmp eax, 62CE9A1Ch
    jz loc_1815A1C79
    mov ecx, eax
    cmp eax, 0FCD789Fh
    jnz loc_1815A1C79
    mov rbx, qword ptr [r13]
    mov r12, qword ptr [r13+18h]
    mov rax, qword ptr [off_182108208]
    mov rcx, 203DD5BC762154ABh
    add rax, rcx
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8ACC]
    mov edx, dword ptr [dword_1820F8AD0]
    shrd edx, ecx, 8
    xor edx, 5E3CB65h
    imul ecx, dword ptr [dword_1820F8AD4], 77459B22h
    imul r8d, dword ptr [dword_1820F8AD8], 70998D3Bh
    cmp r12, qword ptr [rdi+rax*8]
    mov eax, r8d
    lea eax, [rcx+rax-5CBA0278h]
    cmova eax, edx
    mov rcx, r13
    mov r8d, -18C65315h
    jmp loc_1815A1D19
    loc_1815A1D10:
    mov rcx, rbx
    mov r8d, -452C5309h
    loc_1815A1D19:
    mov edx, r8d
    mov r8d, eax
    cmp edx, -18C65315h
    jz loc_1815A1D19
    cmp edx, 5C6C1503h
    jz loc_1815A1D10
    mov r12, rcx
    mov r8d, edx
    cmp edx, -452C5309h
    jnz loc_1815A1D19
    mov rax, qword ptr [rbp-28h]
    mov qword ptr [rax+10h], r15
    sub rsp, 20h
    mov rcx, r12
    mov rdx, r14
    mov r8, r15
    call memmove
    add rsp, 20h
    mov rax, qword ptr [off_182108210]
    mov rcx, 203DD5BC762154ABh
    add rax, rcx
    sub rsp, 20h
    call rax
    add rsp, 20h
    movzx eax, byte ptr [byte_1820F8ADC]
    movzx ecx, byte ptr [byte_1820F8ADD]
    shr cl, 4
    shl al, 4
    or al, cl
    xor al, 2Dh
    mov byte ptr [r12+r15], al
    mov ecx, -1602613Ch
    mov rbx, qword ptr [rbp-48h]
    jmp loc_1815A1C79
    loc_1815A1DA3:
    mov ecx, eax
    cmp eax, -1602613Ch
    jnz loc_1815A1C79
    mov rax, qword ptr [rbx]
    nop
    loc_1815A1DB4:
    sub rsp, 20h
    mov rcx, rbx
    mov rdx, qword ptr [rbp-58h]
    mov r8, r14
    call qword ptr [rax+550h]
    add rsp, 20h
    nop
    mov edx, dword ptr [Seed]
    nop
    sub rsp, 20h
    mov rcx, qword ptr [rbp-38h]
    call sub_18053CC50
    add rsp, 20h
    nop
    loc_1815A1DE6:
    mov rbx, qword ptr [rbp-28h]
    mov rsi, qword ptr [rbx]
    mov r14, qword ptr [rbx+10h]
    mov rdi, qword ptr [rbx+18h]
    mov rax, qword ptr [off_182108218]
    mov rcx, 203DD5BC762154ABh
    add rax, rcx
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8AE0]
    mov edx, dword ptr [dword_1820F8AE4]
    shrd edx, ecx, 1
    lea rcx, qword_181D5AD60
    xor edx, 6380004Ch
    mov r8d, dword ptr [dword_1820F8AE8]
    mov r9d, dword ptr [dword_1820F8AEC]
    shrd r9d, r8d, 1Bh
    xor r9d, 4818A20Ch
    cmp rdi, qword ptr [rcx+rax*8]
    mov eax, r9d
    cmova eax, edx
    mov rcx, rbx
    mov r9d, 1BD0B1Ah
    jmp loc_1815A1E79
    loc_1815A1E70:
    mov rcx, rsi
    mov r9d, -430C8278h
    loc_1815A1E79:
    cmp r9d, -30785FF3h
    jz loc_1815A1E70
    mov edx, r9d
    mov r8, rcx
    mov r9d, eax
    cmp edx, 1BD0B1Ah
    jz loc_1815A1E79
    mov rcx, r8
    mov r9d, edx
    cmp edx, -430C8278h
    jnz loc_1815A1E79
    mov rax, -740BFEF988546600h
    imul rax, qword ptr [qword_1820F8AF0]
    mov rcx, 3B4FAB41E121EA31h
    imul rcx, qword ptr [qword_1820F8AF8]
    add rcx, rax
    mov rdx, -0F7636C1983B6E06h
    add rdx, rcx
    nop
    loc_1815A1ED6:
    sub rsp, 20h
    mov rcx, qword ptr [rbp-38h]
    mov r9, r14
    call sub_180550530
    add rsp, 20h
    nop
    loc_1815A1EEB:
    mov rsi, rax
    movups xmm0, xmmword ptr [rax]
    movups xmm1, xmmword ptr [rax+10h]
    mov rax, qword ptr [rbp-20h]
    movups xmmword ptr [rax+10h], xmm1
    movups xmmword ptr [rax], xmm0
    mov rax, qword ptr [off_182108220]
    mov rbx, 203DD5BC762154ABh
    add rax, rbx
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov rax, qword ptr [qword_1820F8B00]
    mov rcx, qword ptr [qword_1820F8B08]
    shrd rcx, rax, 3Dh
    mov rax, -6B13AEA57773C82Fh
    xor rax, rcx
    mov qword ptr [rsi+10h], rax
    mov rax, qword ptr [off_182108228]
    add rax, rbx
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, qword_181D5AD80
    mov rax, qword ptr [rcx+rax*8]
    mov qword ptr [rsi+18h], rax
    mov rax, qword ptr [off_182108230]
    add rax, rbx
    sub rsp, 20h
    call rax
    add rsp, 20h
    movzx eax, byte ptr [byte_1820F8B10]
    movzx ecx, byte ptr [byte_1820F8B11]
    imul eax, 8Dh
    imul ecx, 4Eh
    add cl, al
    add cl, 10h
    mov byte ptr [rsi], cl
    mov r15, qword ptr [rbp-40h]
    mov rsi, qword ptr [r15]
    mov r14, qword ptr [r15+10h]
    mov rdi, qword ptr [r15+18h]
    mov rax, qword ptr [off_182108238]
    add rax, rbx
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8B14]
    mov edx, dword ptr [dword_1820F8B18]
    shrd edx, ecx, 7
    lea rcx, unk_181D5ADA0
    xor edx, 66002790h
    mov r8d, dword ptr [dword_1820F8B1C]
    mov r9d, dword ptr [dword_1820F8B20]
    shrd r9d, r8d, 1Fh
    xor r9d, -269C74Dh
    cmp rdi, qword ptr [rcx+rax*8]
    mov eax, r9d
    cmova eax, edx
    mov rcx, r15
    mov r8d, 1BD0B1Ah
    jmp loc_1815A2019
    loc_1815A2010:
    mov rcx, rsi
    mov r8d, -430C8278h
    loc_1815A2019:
    cmp r8d, -30785FF3h
    jz loc_1815A2010
    mov edx, r8d
    mov r15, rcx
    mov r8d, eax
    cmp edx, 1BD0B1Ah
    jz loc_1815A2019
    mov rcx, r15
    mov r8d, edx
    cmp edx, -430C8278h
    jnz loc_1815A2019
    mov rax, qword ptr [rbp-20h]
    mov rdi, qword ptr [rax+10h]
    mov rax, qword ptr [rax+18h]
    sub rax, rdi
    mov ecx, dword ptr [dword_1820F8B24]
    mov edx, dword ptr [dword_1820F8B28]
    shrd edx, ecx, 13h
    lea rcx, [rdi+r14]
    mov qword ptr [rbp-68h], rcx
    imul ecx, dword ptr [dword_1820F8B2C], -28EBF076h
    xor edx, 15993455h
    imul r8d, dword ptr [dword_1820F8B30], -6C0CA76Dh
    cmp rax, r14
    mov eax, r8d
    lea r13d, [rcx+rax-5D7A6E1Dh]
    cmovb r13d, edx
    mov edx, -0B06B7AEh
    jmp loc_1815A20CF
    loc_1815A20A0:
    cmp ecx, -3CBFF99Bh
    jnz loc_1815A2214
    nop
    loc_1815A20AD:
    sub rsp, 30h
    mov qword ptr [rsp+20h], r14
    mov rcx, qword ptr [rbp-20h]
    mov rdx, r14
    mov r9, r15
    call sub_180146890
    add rsp, 30h
    nop
    loc_1815A20CA:
    mov edx, -74487209h
    loc_1815A20CF:
    mov ecx, edx
    mov r12, rax
    cmp edx, -0B06B7AFh
    jle loc_1815A20A0
    cmp ecx, 349E12AFh
    jz loc_1815A2100
    mov rax, r12
    mov edx, ecx
    cmp ecx, -0B06B7AEh
    jnz loc_1815A20CF
    mov rax, r12
    mov edx, r13d
    jmp loc_1815A20CF
    loc_1815A2100:
    mov rbx, qword ptr [rbp-20h]
    mov rax, qword ptr [rbp-68h]
    mov qword ptr [rbx+10h], rax
    mov r12, qword ptr [rbx]
    mov rsi, qword ptr [rbx+18h]
    mov rax, qword ptr [off_182108240]
    mov rcx, 203DD5BC762154ABh
    add rax, rcx
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov ecx, dword ptr [dword_1820F8B34]
    mov edx, dword ptr [dword_1820F8B38]
    shrd edx, ecx, 0Ch
    cdqe
    xor edx, -22B30A9Fh
    mov ecx, dword ptr [dword_1820F8B3C]
    mov r8d, dword ptr [dword_1820F8B40]
    shrd r8d, ecx, 1Bh
    xor r8d, 446077BCh
    lea rcx, unk_181D5ADC0
    cmp rsi, qword ptr [rcx+rax*8]
    mov eax, r8d
    cmova eax, edx
    mov r9d, -18C65315h
    jmp loc_1815A2189
    loc_1815A2180:
    mov rbx, r12
    mov r9d, -452C5309h
    loc_1815A2189:
    mov r8d, r9d
    mov r9d, eax
    cmp r8d, -18C65315h
    jz loc_1815A2189
    cmp r8d, 5C6C1503h
    jz loc_1815A2180
    mov rcx, rbx
    mov r9d, r8d
    cmp r8d, -452C5309h
    jnz loc_1815A2189
    mov r12, rcx
    add r12, rdi
    sub rsp, 20h
    mov rcx, r12
    mov rdx, r15
    mov r8, r14
    call memmove
    add rsp, 20h
    mov rax, qword ptr [off_182108248]
    mov rcx, 203DD5BC762154ABh
    add rax, rcx
    sub rsp, 20h
    call rax
    add rsp, 20h
    movzx eax, byte ptr [byte_1820F8B44]
    movzx ecx, byte ptr [byte_1820F8B45]
    shr cl, 2
    shl al, 6
    or al, cl
    xor al, 0FDh
    mov byte ptr [r12], al
    mov rax, qword ptr [rbp-20h]
    mov edx, -74487209h
    jmp loc_1815A20CF
    loc_1815A2214:
    mov rax, r12
    mov edx, ecx
    cmp ecx, -74487209h
    jnz loc_1815A20CF
    mov rdi, qword ptr [rbp-50h]
    mov qword ptr [rdi], 0
    xorps xmm0, xmm0
    movups xmmword ptr [rdi+10h], xmm0
    movups xmm0, xmmword ptr [r12]
    movups xmm1, xmmword ptr [r12+10h]
    movups xmmword ptr [rdi+10h], xmm1
    movups xmmword ptr [rdi], xmm0
    mov rax, qword ptr [off_182108250]
    mov rsi, 203DD5BC762154ABh
    add rax, rsi
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov rax, -23C881339D450D70h
    imul rax, qword ptr [qword_1820F8B48]
    mov rcx, 17BADBCF4DC28C1Dh
    imul rcx, qword ptr [qword_1820F8B50]
    add rcx, rax
    mov rax, -320AC4F111A28AFDh
    add rax, rcx
    mov qword ptr [r12+10h], rax
    mov rax, qword ptr [off_182108258]
    add rax, rsi
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, unk_181D5ADE0
    mov rax, qword ptr [rcx+rax*8]
    mov qword ptr [r12+18h], rax
    mov rax, qword ptr [off_182108260]
    add rax, rsi
    sub rsp, 20h
    call rax
    add rsp, 20h
    movzx eax, byte ptr [byte_1820F8B58]
    movzx ecx, byte ptr [byte_1820F8B59]
    shr cl, 6
    shl al, 2
    or al, cl
    xor al, 44h
    mov byte ptr [r12], al
    nop
    loc_1815A22F7:
    sub rsp, 20h
    mov rcx, qword ptr [rbp-30h]
    mov rdx, rdi
    call sub_1817B7FB0
    add rsp, 20h
    nop
    loc_1815A230C:
    lea r15, qword_181D5AE20
    lea r13, qword_181D5AE40
    lea r12, qword_181D5AE00
    mov ecx, 73B79306h
    mov r14, 203DD5BC762154ABh
    jmp loc_1815A23A6
    loc_1815A2340:
    mov rax, qword ptr [rbp-50h]
    mov rsi, qword ptr [rax+18h]
    mov rax, qword ptr [off_182108268]
    mov rcx, 203DD5BC762154ABh
    add rax, rcx
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8B5C]
    mov edx, dword ptr [dword_1820F8B60]
    shrd edx, ecx, 5
    xor edx, 8C5E76Ch
    imul ecx, dword ptr [dword_1820F8B64], 63624FABh
    imul r8d, dword ptr [dword_1820F8B68], 522DFAADh
    cmp rsi, qword ptr [r12+rax*8]
    mov eax, r8d
    lea eax, [rcx+rax+4EE6E35h]
    cmova eax, edx
    mov ecx, eax
    loc_1815A23A6:
    cmp ecx, 5C1BC03Fh
    jz loc_1815A23D0
    mov eax, ecx
    cmp ecx, 73B79306h
    jz loc_1815A2340
    mov ecx, eax
    cmp eax, 0C1F9B7Dh
    jnz loc_1815A23A6
    jmp loc_1815A25CA
    loc_1815A23D0:
    mov rax, qword ptr [rbp-50h]
    mov rbx, qword ptr [rax]
    mov rsi, qword ptr [rax+18h]
    mov rax, qword ptr [off_182108270]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov rdi, qword ptr [r15+rax*8]
    add rdi, rsi
    mov rax, qword ptr [off_182108278]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    cmp rdi, qword ptr [r13+rax*8+0]
    jbe loc_1815A258D
    mov rax, qword ptr [off_182108280]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, unk_181D5AE60
    add rsi, qword ptr [rcx+rax*8]
    mov r12, qword ptr [rbx-8]
    sub rbx, r12
    mov rax, qword ptr [off_182108288]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    imul ecx, dword ptr [dword_1820F8B6C], 6C468A4h
    imul edx, dword ptr [dword_1820F8B70], -270DCC6Eh
    imul r8d, dword ptr [dword_1820F8B74], -7934DDBEh
    imul r9d, dword ptr [dword_1820F8B78], 5964BDF7h
    cdqe
    lea r10, unk_181D5AE80
    cmp rbx, qword ptr [r10+rax*8]
    mov eax, edx
    lea eax, [rcx+rax-2A50066h]
    mov ecx, r9d
    mov edx, r8d
    lea edi, [rdx+rcx-53CB523Ah]
    cmovb edi, eax
    mov rax, qword ptr [off_182108290]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8B7C]
    mov edx, dword ptr [dword_1820F8B80]
    shrd edx, ecx, 1Dh
    xor edx, -3660EE9Bh
    mov ecx, dword ptr [dword_1820F8B84]
    mov r8d, dword ptr [dword_1820F8B88]
    shrd r8d, ecx, 15h
    xor r8d, 15B2BA48h
    lea rcx, unk_181D5AEA0
    cmp rbx, qword ptr [rcx+rax*8]
    mov eax, r8d
    cmova eax, edx
    mov edx, -1A412436h
    jmp loc_1815A2510
    loc_1815A2502:
    mov edx, 139CD0CDh
    nop word ptr [rax+rax+00000000h]
    loc_1815A2510:
    mov ecx, edx
    cmp edx, -0CC5228Dh
    jle loc_1815A2540
    cmp ecx, 139CD0CCh
    jg loc_1815A2560
    cmp ecx, -0CC5228Ch
    jz loc_1815A2502
    mov edx, ecx
    cmp ecx, 0AE16598h
    jnz loc_1815A2510
    mov edx, 472A0F40h
    jmp loc_1815A2510
    loc_1815A2540:
    mov edx, edi
    cmp ecx, -646444E5h
    jz loc_1815A2510
    cmp ecx, -312C5882h
    jz loc_1815A256F
    mov edx, ecx
    cmp ecx, -1A412436h
    jnz loc_1815A2510
    mov edx, eax
    jmp loc_1815A2510
    loc_1815A2560:
    cmp ecx, 139CD0CDh
    jnz loc_1815A2576
    mov edx, 2D02E08Ch
    jmp loc_1815A2510
    loc_1815A256F:
    mov edx, 139CD0CDh
    jmp loc_1815A2510
    loc_1815A2576:
    cmp ecx, 2D02E08Ch
    jz loc_1815A2595
    mov edx, ecx
    cmp ecx, 472A0F40h
    jnz loc_1815A2510
    jmp loc_1815A3AFD
    loc_1815A258D:
    mov rdx, rdi
    mov rcx, rbx
    jmp loc_1815A25A2
    loc_1815A2595:
    mov rdx, rsi
    mov rcx, r12
    lea r12, qword_181D5AE00
    loc_1815A25A2:
    mov rax, qword ptr [off_182108198]
    mov r8, 203DD5BC762154ABh
    add rax, r8
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov ecx, 0C1F9B7Dh
    jmp loc_1815A23A6
    loc_1815A25CA:
    mov rax, qword ptr [off_182108298]
    mov rsi, 203DD5BC762154ABh
    add rax, rsi
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov rax, -8A5B4AB049F857Ch
    imul rax, qword ptr [qword_1820F8B90]
    mov rcx, 0D08BB2138B77CB4h
    imul rcx, qword ptr [qword_1820F8B98]
    add rcx, rax
    mov rax, -5F93A591E34CF67Ch
    add rax, rcx
    mov rdi, qword ptr [rbp-50h]
    mov qword ptr [rdi+10h], rax
    mov rax, qword ptr [off_1821082A0]
    add rax, rsi
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, qword_181D5AEC0
    mov rax, qword ptr [rcx+rax*8]
    mov qword ptr [rdi+18h], rax
    mov rax, qword ptr [off_1821082A8]
    add rax, rsi
    sub rsp, 20h
    call rax
    add rsp, 20h
    movzx eax, byte ptr [byte_1820F8BA0]
    movzx ecx, byte ptr [byte_1820F8BA1]
    shr cl, 6
    shl al, 2
    or al, cl
    xor al, 7Ch
    mov byte ptr [rdi], al
    lea r15, qword_181D5AF00
    lea rbx, qword_181D5AF20
    lea r13, qword_181D5AEE0
    mov ecx, 73B79306h
    mov r14, 203DD5BC762154ABh
    jmp loc_1815A2703
    loc_1815A26A0:
    mov rax, qword ptr [rbp-20h]
    mov rsi, qword ptr [rax+18h]
    mov rax, qword ptr [off_1821082B0]
    mov rcx, 203DD5BC762154ABh
    add rax, rcx
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8BA4]
    mov edx, dword ptr [dword_1820F8BA8]
    shrd edx, ecx, 14h
    xor edx, -3E60313Dh
    mov ecx, dword ptr [dword_1820F8BAC]
    mov r8d, dword ptr [dword_1820F8BB0]
    shrd r8d, ecx, 15h
    xor r8d, 145384F7h
    cmp rsi, qword ptr [r13+rax*8+0]
    cmova r8d, edx
    mov ecx, r8d
    loc_1815A2703:
    cmp ecx, 5C1BC03Fh
    jz loc_1815A2730
    mov eax, ecx
    cmp ecx, 73B79306h
    jz loc_1815A26A0
    mov ecx, eax
    cmp eax, 0C1F9B7Dh
    jnz loc_1815A2703
    jmp loc_1815A291B
    loc_1815A2730:
    mov rax, qword ptr [rbp-20h]
    mov rdi, qword ptr [rax]
    mov rsi, qword ptr [rax+18h]
    mov rax, qword ptr [off_1821082B8]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov r12, qword ptr [r15+rax*8]
    add r12, rsi
    mov rax, qword ptr [off_1821082C0]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    cmp r12, qword ptr [rbx+rax*8]
    jbe loc_1815A28DE
    mov rax, qword ptr [off_1821082C8]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, unk_181D5AF40
    add rsi, qword ptr [rcx+rax*8]
    mov r12, qword ptr [rdi-8]
    sub rdi, r12
    mov rax, qword ptr [off_1821082D0]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8BB4]
    mov edx, dword ptr [dword_1820F8BB8]
    shrd edx, ecx, 1Eh
    xor edx, 564DE9A9h
    imul ecx, dword ptr [dword_1820F8BBC], 4AC9D3F2h
    imul r8d, dword ptr [dword_1820F8BC0], 5D1DF237h
    lea r9, unk_181D5AF60
    cmp rdi, qword ptr [r9+rax*8]
    mov eax, r8d
    lea r13d, [rcx+rax-39CE5EF6h]
    cmovb r13d, edx
    mov rax, qword ptr [off_1821082D8]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8BC4]
    mov edx, dword ptr [dword_1820F8BC8]
    shrd edx, ecx, 1Ah
    xor edx, -0ECD2Fh
    mov ecx, dword ptr [dword_1820F8BCC]
    mov r8d, dword ptr [dword_1820F8BD0]
    shrd r8d, ecx, 1Eh
    xor r8d, 1B1DAF01h
    lea rcx, unk_181D5AF80
    cmp rdi, qword ptr [rcx+rax*8]
    mov eax, r8d
    cmova eax, edx
    mov edx, -1A412436h
    jmp loc_1815A2860
    loc_1815A2858:
    mov edx, 139CD0CDh
    nop dword ptr [rax]
    loc_1815A2860:
    mov ecx, edx
    cmp edx, -0CC5228Dh
    jle loc_1815A2890
    cmp ecx, 139CD0CCh
    jg loc_1815A28B1
    cmp ecx, -0CC5228Ch
    jz loc_1815A2858
    mov edx, ecx
    cmp ecx, 0AE16598h
    jnz loc_1815A2860
    mov edx, 472A0F40h
    jmp loc_1815A2860
    loc_1815A2890:
    mov edx, r13d
    cmp ecx, -646444E5h
    jz loc_1815A2860
    cmp ecx, -312C5882h
    jz loc_1815A28C0
    mov edx, ecx
    cmp ecx, -1A412436h
    jnz loc_1815A2860
    mov edx, eax
    jmp loc_1815A2860
    loc_1815A28B1:
    cmp ecx, 139CD0CDh
    jnz loc_1815A28C7
    mov edx, 2D02E08Ch
    jmp loc_1815A2860
    loc_1815A28C0:
    mov edx, 139CD0CDh
    jmp loc_1815A2860
    loc_1815A28C7:
    cmp ecx, 2D02E08Ch
    jz loc_1815A28E6
    mov edx, ecx
    cmp ecx, 472A0F40h
    jnz loc_1815A2860
    jmp loc_1815A3B0C
    loc_1815A28DE:
    mov rdx, r12
    mov rcx, rdi
    jmp loc_1815A28F3
    loc_1815A28E6:
    mov rdx, rsi
    mov rcx, r12
    lea r13, qword_181D5AEE0
    loc_1815A28F3:
    mov rax, qword ptr [off_182108198]
    mov r8, 203DD5BC762154ABh
    add rax, r8
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov ecx, 0C1F9B7Dh
    jmp loc_1815A2703
    loc_1815A291B:
    mov rax, qword ptr [off_1821082E0]
    mov rsi, 203DD5BC762154ABh
    add rax, rsi
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov rax, -599277D200BB0821h
    imul rax, qword ptr [qword_1820F8BD8]
    mov rcx, 7C68B80C4E1F8663h
    imul rcx, qword ptr [qword_1820F8BE0]
    add rcx, rax
    mov rax, 7263AB5AAF2FB2E2h
    add rax, rcx
    mov rdi, qword ptr [rbp-20h]
    mov qword ptr [rdi+10h], rax
    mov rax, qword ptr [off_1821082E8]
    add rax, rsi
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, qword_181D5AFA0
    mov rax, qword ptr [rcx+rax*8]
    mov qword ptr [rdi+18h], rax
    mov rax, qword ptr [off_1821082F0]
    add rax, rsi
    sub rsp, 20h
    call rax
    add rsp, 20h
    movzx eax, byte ptr [byte_1820F8BE8]
    movzx ecx, byte ptr [byte_1820F8BE9]
    imul eax, 0B5h
    mov edx, ecx
    shl edx, 5
    lea ecx, [rdx+rcx*2]
    add cl, al
    add cl, 0DBh
    mov byte ptr [rdi], cl
    lea r15, qword_181D5AFE0
    lea rbx, qword_181D5B000
    lea r13, qword_181D5AFC0
    mov ecx, 73B79306h
    mov r14, 203DD5BC762154ABh
    jmp loc_1815A2A70
    loc_1815A2A00:
    mov rax, qword ptr [rbp-38h]
    mov rsi, qword ptr [rax+18h]
    mov rax, qword ptr [off_1821082F8]
    mov rcx, 203DD5BC762154ABh
    add rax, rcx
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    imul ecx, dword ptr [dword_1820F8BEC], 47091810h
    imul edx, dword ptr [dword_1820F8BF0], -2B5E1688h
    imul r8d, dword ptr [dword_1820F8BF4], 13A5F4C5h
    imul r9d, dword ptr [dword_1820F8BF8], 0EFED4F4h
    cmp rsi, qword ptr [r13+rax*8+0]
    mov eax, edx
    lea eax, [rcx+rax+1076E4A7h]
    mov ecx, r9d
    mov edx, r8d
    lea ecx, [rdx+rcx-77C6B94Fh]
    cmova ecx, eax
    loc_1815A2A70:
    cmp ecx, 5C1BC03Fh
    jz loc_1815A2AA0
    mov eax, ecx
    cmp ecx, 73B79306h
    jz loc_1815A2A00
    mov ecx, eax
    cmp eax, 0C1F9B7Dh
    jnz loc_1815A2A70
    jmp loc_1815A2C8B
    loc_1815A2AA0:
    mov rax, qword ptr [rbp-38h]
    mov rdi, qword ptr [rax]
    mov rsi, qword ptr [rax+18h]
    mov rax, qword ptr [off_182108300]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov r12, qword ptr [r15+rax*8]
    add r12, rsi
    mov rax, qword ptr [off_182108308]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    cmp r12, qword ptr [rbx+rax*8]
    jbe loc_1815A2C4E
    mov rax, qword ptr [off_182108310]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, unk_181D5B020
    add rsi, qword ptr [rcx+rax*8]
    mov r12, qword ptr [rdi-8]
    sub rdi, r12
    mov rax, qword ptr [off_182108318]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov ecx, dword ptr [dword_1820F8BFC]
    mov edx, dword ptr [dword_1820F8C00]
    shrd edx, ecx, 9
    cdqe
    xor edx, 6ACC8922h
    mov ecx, dword ptr [dword_1820F8C04]
    mov r13d, dword ptr [dword_1820F8C08]
    shrd r13d, ecx, 16h
    xor r13d, 4B6ABA48h
    lea rcx, unk_181D5B040
    cmp rdi, qword ptr [rcx+rax*8]
    cmovb r13d, edx
    mov rax, qword ptr [off_182108320]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8C0C]
    mov edx, dword ptr [dword_1820F8C10]
    shrd edx, ecx, 1Eh
    xor edx, 54E97836h
    mov ecx, dword ptr [dword_1820F8C14]
    mov r8d, dword ptr [dword_1820F8C18]
    shrd r8d, ecx, 8
    xor r8d, 18EB0680h
    lea rcx, unk_181D5B060
    cmp rdi, qword ptr [rcx+rax*8]
    mov eax, r8d
    cmova eax, edx
    mov edx, -1A412436h
    jmp loc_1815A2BD0
    loc_1815A2BC1:
    mov edx, 139CD0CDh
    nop word ptr [rax+rax+00000000h]
    loc_1815A2BD0:
    mov ecx, edx
    cmp edx, -0CC5228Dh
    jle loc_1815A2C00
    cmp ecx, 139CD0CCh
    jg loc_1815A2C21
    cmp ecx, -0CC5228Ch
    jz loc_1815A2BC1
    mov edx, ecx
    cmp ecx, 0AE16598h
    jnz loc_1815A2BD0
    mov edx, 472A0F40h
    jmp loc_1815A2BD0
    loc_1815A2C00:
    mov edx, r13d
    cmp ecx, -646444E5h
    jz loc_1815A2BD0
    cmp ecx, -312C5882h
    jz loc_1815A2C30
    mov edx, ecx
    cmp ecx, -1A412436h
    jnz loc_1815A2BD0
    mov edx, eax
    jmp loc_1815A2BD0
    loc_1815A2C21:
    cmp ecx, 139CD0CDh
    jnz loc_1815A2C37
    mov edx, 2D02E08Ch
    jmp loc_1815A2BD0
    loc_1815A2C30:
    mov edx, 139CD0CDh
    jmp loc_1815A2BD0
    loc_1815A2C37:
    cmp ecx, 2D02E08Ch
    jz loc_1815A2C56
    mov edx, ecx
    cmp ecx, 472A0F40h
    jnz loc_1815A2BD0
    jmp loc_1815A3B1B
    loc_1815A2C4E:
    mov rdx, r12
    mov rcx, rdi
    jmp loc_1815A2C63
    loc_1815A2C56:
    mov rdx, rsi
    mov rcx, r12
    lea r13, qword_181D5AFC0
    loc_1815A2C63:
    mov rax, qword ptr [off_182108198]
    mov r8, 203DD5BC762154ABh
    add rax, r8
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov ecx, 0C1F9B7Dh
    jmp loc_1815A2A70
    loc_1815A2C8B:
    mov rax, qword ptr [off_182108328]
    mov r14, 203DD5BC762154ABh
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov rax, qword ptr [qword_1820F8C20]
    mov rcx, qword ptr [qword_1820F8C28]
    shrd rcx, rax, 10h
    mov rax, -50C5E12775625229h
    xor rax, rcx
    mov rsi, qword ptr [rbp-38h]
    mov qword ptr [rsi+10h], rax
    mov rax, qword ptr [off_182108330]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, qword_181D5B080
    mov rax, qword ptr [rcx+rax*8]
    mov qword ptr [rsi+18h], rax
    mov rax, qword ptr [off_182108338]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    movzx eax, byte ptr [byte_1820F8C30]
    movzx ecx, byte ptr [byte_1820F8C31]
    shr cl, 3
    shl al, 5
    or al, cl
    xor al, 83h
    mov byte ptr [rsi], al
    mov rax, qword ptr [rbp-48h]
    mov rax, qword ptr [rax]
    mov rsi, qword ptr [rax+538h]
    mov r15, qword ptr [rbp-30h]
    mov rdi, qword ptr [r15]
    mov rbx, qword ptr [r15+18h]
    mov rax, qword ptr [off_182108340]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8C34]
    mov edx, dword ptr [dword_1820F8C38]
    shrd edx, ecx, 1Eh
    lea rcx, qword_181D5B0A0
    xor edx, 1A2E06B2h
    mov r8d, dword ptr [dword_1820F8C3C]
    mov r9d, dword ptr [dword_1820F8C40]
    shrd r9d, r8d, 19h
    xor r9d, -6DA31CF9h
    cmp rbx, qword ptr [rcx+rax*8]
    mov eax, r9d
    cmova eax, edx
    mov rcx, r15
    mov r9d, 1BD0B1Ah
    mov rbx, qword ptr [rbp-60h]
    jmp loc_1815A2DB9
    loc_1815A2DB0:
    mov rcx, rdi
    mov r9d, -430C8278h
    loc_1815A2DB9:
    cmp r9d, -30785FF3h
    jz loc_1815A2DB0
    mov r8d, r9d
    mov rdx, rcx
    mov r9d, eax
    cmp r8d, 1BD0B1Ah
    jz loc_1815A2DB9
    mov rcx, rdx
    mov r9d, r8d
    cmp r8d, -430C8278h
    jnz loc_1815A2DB9
    nop
    loc_1815A2DE4:
    sub rsp, 20h
    mov rdi, qword ptr [rbp-48h]
    mov rcx, rdi
    call rsi
    add rsp, 20h
    nop
    mov r14, rax
    mov rax, qword ptr [rdi]
    nop
    sub rsp, 20h
    mov rcx, rdi
    mov rdx, qword ptr [rbp-58h]
    call qword ptr [rax+0B8h]
    add rsp, 20h
    nop
    mov rax, qword ptr [rdi]
    nop
    sub rsp, 20h
    mov rcx, rdi
    mov rdx, rbx
    call qword ptr [rax+0B8h]
    add rsp, 20h
    nop
    loc_1815A2E2C:
    mov qword ptr [rbp-20h], r14
    lea rsi, qword_181D5B0E0
    lea rdi, qword_181D5B100
    lea r13, unk_181D5B0C0
    mov ecx, 73B79306h
    mov r15, 203DD5BC762154ABh
    jmp loc_1815A2EB9
    loc_1815A2E60:
    mov rax, qword ptr [rbp-30h]
    mov rbx, qword ptr [rax+18h]
    mov rax, qword ptr [off_182108348]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8C44]
    mov edx, dword ptr [dword_1820F8C48]
    shrd edx, ecx, 10h
    xor edx, -47DFE28Fh
    mov ecx, dword ptr [dword_1820F8C4C]
    mov r8d, dword ptr [dword_1820F8C50]
    shrd r8d, ecx, 12h
    xor r8d, 4CFF7F1Ch
    cmp rbx, qword ptr [r13+rax*8+0]
    cmova r8d, edx
    mov ecx, r8d
    loc_1815A2EB9:
    cmp ecx, 5C1BC03Fh
    jz loc_1815A2EE0
    mov eax, ecx
    cmp ecx, 73B79306h
    jz loc_1815A2E60
    mov ecx, eax
    cmp eax, 0C1F9B7Dh
    jnz loc_1815A2EB9
    jmp loc_1815A30D4
    loc_1815A2EE0:
    mov rax, qword ptr [rbp-30h]
    mov r12, qword ptr [rax]
    mov r14, qword ptr [rax+18h]
    mov rax, qword ptr [off_182108350]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov rbx, qword ptr [rsi+rax*8]
    add rbx, r14
    mov rax, qword ptr [off_182108358]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    cmp rbx, qword ptr [rdi+rax*8]
    jbe loc_1815A309E
    mov rax, qword ptr [off_182108360]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, unk_181D5B120
    add r14, qword ptr [rcx+rax*8]
    mov rbx, qword ptr [r12-8]
    sub r12, rbx
    mov rax, qword ptr [off_182108368]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8C54]
    mov edx, dword ptr [dword_1820F8C58]
    shrd edx, ecx, 1Dh
    xor edx, -3D5D882Ah
    imul ecx, dword ptr [dword_1820F8C5C], 10FEC24h
    imul r8d, dword ptr [dword_1820F8C60], 20D80768h
    lea r9, unk_181D5B140
    cmp r12, qword ptr [r9+rax*8]
    mov eax, r8d
    mov r8, r15
    lea r15d, [rcx+rax-41747EC8h]
    cmovb r15d, edx
    mov rax, qword ptr [off_182108370]
    add rax, r8
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8C64]
    mov edx, dword ptr [dword_1820F8C68]
    shrd edx, ecx, 6
    xor edx, -1E8F90C4h
    imul ecx, dword ptr [dword_1820F8C6C], -4EE9DAFh
    imul r8d, dword ptr [dword_1820F8C70], -203C2D1Eh
    lea r9, unk_181D5B160
    cmp r12, qword ptr [r9+rax*8]
    mov eax, r8d
    lea eax, [rcx+rax+563D0A83h]
    cmova eax, edx
    mov edx, -1A412436h
    jmp loc_1815A3020
    loc_1815A300F:
    mov edx, 139CD0CDh
    nop word ptr [rax+rax+00000000h]
    loc_1815A3020:
    mov ecx, edx
    cmp edx, -0CC5228Dh
    jle loc_1815A3050
    cmp ecx, 139CD0CCh
    jg loc_1815A3071
    cmp ecx, -0CC5228Ch
    jz loc_1815A300F
    mov edx, ecx
    cmp ecx, 0AE16598h
    jnz loc_1815A3020
    mov edx, 472A0F40h
    jmp loc_1815A3020
    loc_1815A3050:
    mov edx, r15d
    cmp ecx, -646444E5h
    jz loc_1815A3020
    cmp ecx, -312C5882h
    jz loc_1815A3080
    mov edx, ecx
    cmp ecx, -1A412436h
    jnz loc_1815A3020
    mov edx, eax
    jmp loc_1815A3020
    loc_1815A3071:
    cmp ecx, 139CD0CDh
    jnz loc_1815A3087
    mov edx, 2D02E08Ch
    jmp loc_1815A3020
    loc_1815A3080:
    mov edx, 139CD0CDh
    jmp loc_1815A3020
    loc_1815A3087:
    cmp ecx, 2D02E08Ch
    jz loc_1815A30A6
    mov edx, ecx
    cmp ecx, 472A0F40h
    jnz loc_1815A3020
    jmp loc_1815A3B2A
    loc_1815A309E:
    mov rdx, rbx
    mov rcx, r12
    jmp loc_1815A30B6
    loc_1815A30A6:
    mov rdx, r14
    mov rcx, rbx
    mov r15, 203DD5BC762154ABh
    loc_1815A30B6:
    mov rax, qword ptr [off_182108198]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov ecx, 0C1F9B7Dh
    jmp loc_1815A2EB9
    loc_1815A30D4:
    mov rax, qword ptr [off_182108378]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov rax, qword ptr [qword_1820F8C78]
    mov rcx, qword ptr [qword_1820F8C80]
    shrd rcx, rax, 35h
    mov rax, 11AF4EB7628B72B3h
    xor rax, rcx
    mov rsi, qword ptr [rbp-30h]
    mov qword ptr [rsi+10h], rax
    mov rax, qword ptr [off_182108380]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, qword_181D5B180
    mov rax, qword ptr [rcx+rax*8]
    mov qword ptr [rsi+18h], rax
    mov rax, qword ptr [off_182108388]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    movzx eax, byte ptr [byte_1820F8C88]
    movzx ecx, byte ptr [byte_1820F8C89]
    shr cl, 4
    shl al, 4
    or al, cl
    xor al, 0FDh
    mov byte ptr [rsi], al
    lea rsi, qword_181D5B1C0
    lea rdi, qword_181D5B1E0
    lea r13, qword_181D5B1A0
    mov ecx, 73B79306h
    jmp loc_1815A31E6
    loc_1815A3180:
    mov rax, qword ptr [rbp-28h]
    mov rbx, qword ptr [rax+18h]
    mov rax, qword ptr [off_182108390]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    imul ecx, dword ptr [dword_1820F8C8C], 37DBCBE3h
    imul edx, dword ptr [dword_1820F8C90], -269D9767h
    imul r8d, dword ptr [dword_1820F8C94], 43C713CCh
    imul r9d, dword ptr [dword_1820F8C98], -5136C336h
    cmp rbx, qword ptr [r13+rax*8+0]
    mov eax, edx
    lea eax, [rcx+rax-390A4F5Bh]
    mov ecx, r9d
    mov edx, r8d
    lea ecx, [rdx+rcx+57EB6B83h]
    cmova ecx, eax
    loc_1815A31E6:
    cmp ecx, 5C1BC03Fh
    jz loc_1815A3210
    mov eax, ecx
    cmp ecx, 73B79306h
    jz loc_1815A3180
    mov ecx, eax
    cmp eax, 0C1F9B7Dh
    jnz loc_1815A31E6
    jmp loc_1815A3404
    loc_1815A3210:
    mov rax, qword ptr [rbp-28h]
    mov r12, qword ptr [rax]
    mov r14, qword ptr [rax+18h]
    mov rax, qword ptr [off_182108398]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov rbx, qword ptr [rsi+rax*8]
    add rbx, r14
    mov rax, qword ptr [off_1821083A0]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    cmp rbx, qword ptr [rdi+rax*8]
    jbe loc_1815A33CE
    mov rax, qword ptr [off_1821083A8]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, unk_181D5B200
    add r14, qword ptr [rcx+rax*8]
    mov rbx, qword ptr [r12-8]
    sub r12, rbx
    mov rax, qword ptr [off_1821083B0]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov ecx, dword ptr [dword_1820F8C9C]
    mov edx, dword ptr [dword_1820F8CA0]
    shrd edx, ecx, 0Ch
    cdqe
    xor edx, -19BF63BBh
    mov ecx, dword ptr [dword_1820F8CA4]
    mov r8d, dword ptr [dword_1820F8CA8]
    shrd r8d, ecx, 0Ch
    mov rcx, r15
    mov r15d, r8d
    xor r15d, -56D4CCF6h
    lea r8, unk_181D5B220
    cmp r12, qword ptr [r8+rax*8]
    cmovb r15d, edx
    mov rax, qword ptr [off_1821083B8]
    add rax, rcx
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    imul ecx, dword ptr [dword_1820F8CAC], 77680DF4h
    imul edx, dword ptr [dword_1820F8CB0], 124B3ACDh
    imul r8d, dword ptr [dword_1820F8CB4], -2506A71Eh
    imul r9d, dword ptr [dword_1820F8CB8], -54AD6879h
    lea r10, unk_181D5B240
    cmp r12, qword ptr [r10+rax*8]
    mov eax, edx
    lea ecx, [rcx+rax-57B7D551h]
    mov eax, r9d
    mov edx, r8d
    lea eax, [rdx+rax+43E832ACh]
    cmova eax, ecx
    mov edx, -1A412436h
    jmp loc_1815A3350
    loc_1815A3346:
    mov edx, 139CD0CDh
    nop dword ptr [rax+rax+00h]
    loc_1815A3350:
    mov ecx, edx
    cmp edx, -0CC5228Dh
    jle loc_1815A3380
    cmp ecx, 139CD0CCh
    jg loc_1815A33A1
    cmp ecx, -0CC5228Ch
    jz loc_1815A3346
    mov edx, ecx
    cmp ecx, 0AE16598h
    jnz loc_1815A3350
    mov edx, 472A0F40h
    jmp loc_1815A3350
    loc_1815A3380:
    mov edx, r15d
    cmp ecx, -646444E5h
    jz loc_1815A3350
    cmp ecx, -312C5882h
    jz loc_1815A33B0
    mov edx, ecx
    cmp ecx, -1A412436h
    jnz loc_1815A3350
    mov edx, eax
    jmp loc_1815A3350
    loc_1815A33A1:
    cmp ecx, 139CD0CDh
    jnz loc_1815A33B7
    mov edx, 2D02E08Ch
    jmp loc_1815A3350
    loc_1815A33B0:
    mov edx, 139CD0CDh
    jmp loc_1815A3350
    loc_1815A33B7:
    cmp ecx, 2D02E08Ch
    jz loc_1815A33D6
    mov edx, ecx
    cmp ecx, 472A0F40h
    jnz loc_1815A3350
    jmp loc_1815A3B39
    loc_1815A33CE:
    mov rdx, rbx
    mov rcx, r12
    jmp loc_1815A33E6
    loc_1815A33D6:
    mov rdx, r14
    mov rcx, rbx
    mov r15, 203DD5BC762154ABh
    loc_1815A33E6:
    mov rax, qword ptr [off_182108198]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov ecx, 0C1F9B7Dh
    jmp loc_1815A31E6
    loc_1815A3404:
    mov rax, qword ptr [off_1821083C0]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov rax, -150C9C8DAE8532D8h
    imul rax, qword ptr [qword_1820F8CC0]
    mov rcx, -16F0A294236378FCh
    imul rcx, qword ptr [qword_1820F8CC8]
    add rcx, rax
    mov rax, -833F4174A5FAF20h
    add rax, rcx
    mov rsi, qword ptr [rbp-28h]
    mov qword ptr [rsi+10h], rax
    mov rax, qword ptr [off_1821083C8]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, qword_181D5B260
    mov rax, qword ptr [rcx+rax*8]
    mov qword ptr [rsi+18h], rax
    mov rax, qword ptr [off_1821083D0]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    movzx eax, byte ptr [byte_1820F8CD0]
    movzx ecx, byte ptr [byte_1820F8CD1]
    shr cl, 4
    shl al, 4
    or al, cl
    xor al, 0C1h
    mov byte ptr [rsi], al
    lea rsi, qword_181D5B2A0
    lea rdi, qword_181D5B2C0
    lea r13, qword_181D5B280
    mov ecx, 73B79306h
    jmp loc_1815A3536
    loc_1815A34D0:
    mov rax, qword ptr [rbp-40h]
    mov rbx, qword ptr [rax+18h]
    mov rax, qword ptr [off_1821083D8]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    imul ecx, dword ptr [dword_1820F8CD4], 6AE14DDCh
    imul edx, dword ptr [dword_1820F8CD8], -51C96887h
    imul r8d, dword ptr [dword_1820F8CDC], -3306D6C6h
    imul r9d, dword ptr [dword_1820F8CE0], 7512A9D0h
    cmp rbx, qword ptr [r13+rax*8+0]
    mov eax, edx
    lea eax, [rcx+rax+3741463Fh]
    mov ecx, r9d
    mov edx, r8d
    lea ecx, [rdx+rcx+2862DB7h]
    cmova ecx, eax
    loc_1815A3536:
    cmp ecx, 5C1BC03Fh
    jz loc_1815A3560
    mov eax, ecx
    cmp ecx, 73B79306h
    jz loc_1815A34D0
    mov ecx, eax
    cmp eax, 0C1F9B7Dh
    jnz loc_1815A3536
    jmp loc_1815A3754
    loc_1815A3560:
    mov rax, qword ptr [rbp-40h]
    mov r12, qword ptr [rax]
    mov rbx, qword ptr [rax+18h]
    mov rax, qword ptr [off_1821083E0]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov r14, qword ptr [rsi+rax*8]
    add r14, rbx
    mov rax, qword ptr [off_1821083E8]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    cmp r14, qword ptr [rdi+rax*8]
    jbe loc_1815A371E
    mov rax, qword ptr [off_1821083F0]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, unk_181D5B2E0
    add rbx, qword ptr [rcx+rax*8]
    mov r14, qword ptr [r12-8]
    sub r12, r14
    mov rax, qword ptr [off_1821083F8]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    imul ecx, dword ptr [dword_1820F8CE4], 4A574B8Dh
    imul edx, dword ptr [dword_1820F8CE8], -51B631BFh
    cdqe
    mov r8d, dword ptr [dword_1820F8CEC]
    mov r9d, dword ptr [dword_1820F8CF0]
    shrd r9d, r8d, 0Eh
    xor r9d, 4D10DE73h
    lea r8, unk_181D5B300
    cmp r12, qword ptr [r8+rax*8]
    mov eax, edx
    mov rdx, r15
    lea r15d, [rcx+rax+2BD7DF96h]
    cmovnb r15d, r9d
    mov rax, qword ptr [off_182108400]
    add rax, rdx
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8CF4]
    mov edx, dword ptr [dword_1820F8CF8]
    shrd edx, ecx, 18h
    xor edx, 37B1BBB3h
    mov ecx, dword ptr [dword_1820F8CFC]
    mov r8d, dword ptr [dword_1820F8D00]
    shrd r8d, ecx, 9
    xor r8d, 3EB8D077h
    lea rcx, unk_181D5B320
    cmp r12, qword ptr [rcx+rax*8]
    mov eax, r8d
    cmova eax, edx
    mov edx, -1A412436h
    jmp loc_1815A36A0
    loc_1815A368E:
    mov edx, 139CD0CDh
    nop word ptr [rax+rax+00000000h]
    loc_1815A36A0:
    mov ecx, edx
    cmp edx, -0CC5228Dh
    jle loc_1815A36D0
    cmp ecx, 139CD0CCh
    jg loc_1815A36F1
    cmp ecx, -0CC5228Ch
    jz loc_1815A368E
    mov edx, ecx
    cmp ecx, 0AE16598h
    jnz loc_1815A36A0
    mov edx, 472A0F40h
    jmp loc_1815A36A0
    loc_1815A36D0:
    mov edx, r15d
    cmp ecx, -646444E5h
    jz loc_1815A36A0
    cmp ecx, -312C5882h
    jz loc_1815A3700
    mov edx, ecx
    cmp ecx, -1A412436h
    jnz loc_1815A36A0
    mov edx, eax
    jmp loc_1815A36A0
    loc_1815A36F1:
    cmp ecx, 139CD0CDh
    jnz loc_1815A3707
    mov edx, 2D02E08Ch
    jmp loc_1815A36A0
    loc_1815A3700:
    mov edx, 139CD0CDh
    jmp loc_1815A36A0
    loc_1815A3707:
    cmp ecx, 2D02E08Ch
    jz loc_1815A3726
    mov edx, ecx
    cmp ecx, 472A0F40h
    jnz loc_1815A36A0
    jmp loc_1815A3B48
    loc_1815A371E:
    mov rdx, r14
    mov rcx, r12
    jmp loc_1815A3736
    loc_1815A3726:
    mov rdx, rbx
    mov rcx, r14
    mov r15, 203DD5BC762154ABh
    loc_1815A3736:
    mov rax, qword ptr [off_182108198]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov ecx, 0C1F9B7Dh
    jmp loc_1815A3536
    loc_1815A3754:
    mov rax, qword ptr [rbp-20h]
    jmp loc_1815A3AE8
    loc_1815A375D:
    mov r15, rcx
    mov rax, qword ptr [rdi]
    mov rsi, qword ptr [rax+538h]
    mov edx, dword ptr [Seed]
    mov rax, qword ptr [off_182108150]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov rdi, qword ptr [r15]
    mov rbx, qword ptr [r15+18h]
    mov rax, qword ptr [off_182108158]
    add rax, r14
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, qword_181D5ABC0
    mov edx, dword ptr [dword_1820F8A38]
    mov r8d, dword ptr [dword_1820F8A3C]
    shrd r8d, edx, 13h
    xor r8d, -553B9B00h
    imul edx, dword ptr [dword_1820F8A40], 7BCF4B43h
    imul r9d, dword ptr [dword_1820F8A44], -78662BF7h
    cmp rbx, qword ptr [rcx+rax*8]
    mov eax, r9d
    mov ecx, edx
    lea eax, [rcx+rax-3C6141AFh]
    cmova eax, r8d
    mov qword ptr [rbp-20h], r15
    mov r9d, 1BD0B1Ah
    jmp loc_1815A3809
    loc_1815A3800:
    mov r15, rdi
    mov r9d, -430C8278h
    loc_1815A3809:
    cmp r9d, -30785FF3h
    jz loc_1815A3800
    mov r8d, r9d
    mov rdx, r15
    mov r9d, eax
    cmp r8d, 1BD0B1Ah
    jz loc_1815A3809
    mov r15, rdx
    mov r9d, r8d
    cmp r8d, -430C8278h
    jnz loc_1815A3809
    nop
    loc_1815A3834:
    sub rsp, 20h
    mov rcx, qword ptr [rbp-48h]
    call rsi
    add rsp, 20h
    nop
    loc_1815A3843:
    mov qword ptr [rbp-28h], rax
    lea rdi, qword_181D5AC00
    lea rbx, qword_181D5AC20
    lea r13, qword_181D5ABE0
    mov ecx, 73B79306h
    mov r15, 203DD5BC762154ABh
    jmp loc_1815A38C9
    loc_1815A3870:
    mov rax, qword ptr [rbp-20h]
    mov rsi, qword ptr [rax+18h]
    mov rax, qword ptr [off_182108160]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8A48]
    mov edx, dword ptr [dword_1820F8A4C]
    shrd edx, ecx, 17h
    xor edx, 37BCF9FDh
    mov ecx, dword ptr [dword_1820F8A50]
    mov r8d, dword ptr [dword_1820F8A54]
    shrd r8d, ecx, 14h
    xor r8d, -590A030Ch
    cmp rsi, qword ptr [r13+rax*8+0]
    cmova r8d, edx
    mov ecx, r8d
    loc_1815A38C9:
    cmp ecx, 5C1BC03Fh
    jz loc_1815A38F0
    mov eax, ecx
    cmp ecx, 73B79306h
    jz loc_1815A3870
    mov ecx, eax
    cmp eax, 0C1F9B7Dh
    jnz loc_1815A38C9
    jmp loc_1815A3AE4
    loc_1815A38F0:
    mov rax, qword ptr [rbp-20h]
    mov r12, qword ptr [rax]
    mov rsi, qword ptr [rax+18h]
    mov rax, qword ptr [off_182108168]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov r14, qword ptr [rdi+rax*8]
    add r14, rsi
    mov rax, qword ptr [off_182108170]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    cmp r14, qword ptr [rbx+rax*8]
    jbe loc_1815A3AAE
    mov rax, qword ptr [off_182108178]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    lea rcx, unk_181D5AC40
    add rsi, qword ptr [rcx+rax*8]
    mov r14, qword ptr [r12-8]
    sub r12, r14
    mov rax, qword ptr [off_182108180]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    imul ecx, dword ptr [dword_1820F8A58], -1CBFC775h
    imul edx, dword ptr [dword_1820F8A5C], -458B8881h
    imul r8d, dword ptr [dword_1820F8A60], 263BF047h
    imul r9d, dword ptr [dword_1820F8A64], -2A9AF374h
    cdqe
    lea r10, unk_181D5AC60
    cmp r12, qword ptr [r10+rax*8]
    mov eax, edx
    lea eax, [rcx+rax+21CA3CFBh]
    mov ecx, r9d
    mov edx, r8d
    mov r8, r15
    lea r15d, [rdx+rcx+4276E46Ah]
    cmovb r15d, eax
    mov rax, qword ptr [off_182108188]
    add rax, r8
    sub rsp, 20h
    call rax
    add rsp, 20h
    cdqe
    mov ecx, dword ptr [dword_1820F8A68]
    mov edx, dword ptr [dword_1820F8A6C]
    shrd edx, ecx, 14h
    xor edx, -10629BB0h
    mov ecx, dword ptr [dword_1820F8A70]
    mov r8d, dword ptr [dword_1820F8A74]
    shrd r8d, ecx, 13h
    xor r8d, -29B3820Ah
    lea rcx, unk_181D5AC80
    cmp r12, qword ptr [rcx+rax*8]
    mov eax, r8d
    cmova eax, edx
    mov edx, -1A412436h
    jmp loc_1815A3A30
    loc_1815A3A27:
    mov edx, 139CD0CDh
    nop dword ptr [rax]
    loc_1815A3A30:
    mov ecx, edx
    cmp edx, -0CC5228Dh
    jle loc_1815A3A60
    cmp ecx, 139CD0CCh
    jg loc_1815A3A81
    cmp ecx, -0CC5228Ch
    jz loc_1815A3A27
    mov edx, ecx
    cmp ecx, 0AE16598h
    jnz loc_1815A3A30
    mov edx, 472A0F40h
    jmp loc_1815A3A30
    loc_1815A3A60:
    mov edx, r15d
    cmp ecx, -646444E5h
    jz loc_1815A3A30
    cmp ecx, -312C5882h
    jz loc_1815A3A90
    mov edx, ecx
    cmp ecx, -1A412436h
    jnz loc_1815A3A30
    mov edx, eax
    jmp loc_1815A3A30
    loc_1815A3A81:
    cmp ecx, 139CD0CDh
    jnz loc_1815A3A97
    mov edx, 2D02E08Ch
    jmp loc_1815A3A30
    loc_1815A3A90:
    mov edx, 139CD0CDh
    jmp loc_1815A3A30
    loc_1815A3A97:
    cmp ecx, 2D02E08Ch
    jz loc_1815A3AB6
    mov edx, ecx
    cmp ecx, 472A0F40h
    jnz loc_1815A3A30
    jmp loc_1815A3B57
    loc_1815A3AAE:
    mov rdx, r14
    mov rcx, r12
    jmp loc_1815A3AC6
    loc_1815A3AB6:
    mov rdx, rsi
    mov rcx, r14
    mov r15, 203DD5BC762154ABh
    loc_1815A3AC6:
    mov rax, qword ptr [off_182108198]
    add rax, r15
    sub rsp, 20h
    call rax
    add rsp, 20h
    mov ecx, 0C1F9B7Dh
    jmp loc_1815A38C9
    loc_1815A3AE4:
    mov rax, qword ptr [rbp-28h]
    loc_1815A3AE8:
    movups xmm6, xmmword ptr [rbp-10h]
    lea rsp, [rbp+8]
    pop rbx
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    pop rbp
    ret
    loc_1815A3AFD:
    nop
    loc_1815A3AFE:
    sub rsp, 20h
    call _invalid_parameter_noinfo_noreturn
    add rsp, 20h
    nop
    loc_1815A3B0C:
    nop
    loc_1815A3B0D:
    sub rsp, 20h
    call _invalid_parameter_noinfo_noreturn
    add rsp, 20h
    nop
    loc_1815A3B1B:
    nop
    loc_1815A3B1C:
    sub rsp, 20h
    call _invalid_parameter_noinfo_noreturn
    add rsp, 20h
    nop
    loc_1815A3B2A:
    nop
    loc_1815A3B2B:
    sub rsp, 20h
    call _invalid_parameter_noinfo_noreturn
    add rsp, 20h
    nop
    loc_1815A3B39:
    nop
    loc_1815A3B3A:
    sub rsp, 20h
    call _invalid_parameter_noinfo_noreturn
    add rsp, 20h
    nop
    loc_1815A3B48:
    nop
    loc_1815A3B49:
    sub rsp, 20h
    call _invalid_parameter_noinfo_noreturn
    add rsp, 20h
    nop
    loc_1815A3B57:
    nop
    loc_1815A3B58:
    sub rsp, 20h
    call _invalid_parameter_noinfo_noreturn
    add rsp, 20h
    nop
    loc_1815A3B66:
    int 3
_TEXT ENDS
END

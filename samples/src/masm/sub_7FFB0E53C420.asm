; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: sub_7FFB0E53C420  @ 0x7ffb0e53c420
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN __security_check_cookie:PROC
EXTERN sub_7FFB0E3A4960:PROC
EXTERN sub_7FFB0E3E75C0:PROC
EXTERN sub_7FFB0F63EBA0:PROC
EXTERN sub_7FFB0F81DFA0:PROC
EXTERN sub_7FFB0F884630:PROC

CONST SEGMENT
jpt_7FFB0E53F757 dd 0FE6EFC9Dh
dd 0FE6F0AAFh
dd 0FE6EE892h
dd 0FE6F054Bh
__security_cookie dq 77104A6308CEh
byte_7FFB0FEA4068 db 0CCh
byte_7FFB0FEA4069 db 0C8h
byte_7FFB0FEA406A db 0F6h
byte_7FFB0FEA406B db 0B6h
byte_7FFB0FEA406C db 0F0h
byte_7FFB0FEA406D db 63h
dword_7FFB0FEA4070 dd 8E2887DDh
byte_7FFB0FEA4074 db 6Eh
dword_7FFB0FEA4078 dd 0FDFC16EAh
byte_7FFB0FEA407C db 0C5h
byte_7FFB0FEA407D db 2
dword_7FFB0FEA4080 dd 2D8E72C4h
byte_7FFB0FEA4084 db 27h
byte_7FFB0FEA4085 db 32h
qword_7FFB0FEA4088 dq -1213C43AD449F67Fh
byte_7FFB0FEA4090 db 53h
byte_7FFB0FEA4091 db 14h
dword_7FFB0FEA4094 dd 3E237B6Bh
dword_7FFB0FEECE38 dd 0E166B821h
dword_7FFB0FEECE3C dd 0B0848707h
dword_7FFB0FEECE40 dd 0D3B19CF2h
dword_7FFB0FEECE44 dd 6D0272DDh
dword_7FFB0FEECE48 dd 4DB62171h
dword_7FFB0FEECE4C dd 14A8EC3Bh
dword_7FFB0FEECE50 dd 0DA7FCA94h
dword_7FFB0FEECE54 dd 0F2E9278Ch
dword_7FFB0FEECE58 dd 97A3ECDAh
dword_7FFB0FEECE5C dd 88352EE5h
dword_7FFB0FEECE60 dd 0E46725FEh
dword_7FFB0FEECE64 dd 3504BAA0h
dword_7FFB0FEECE68 dd 0A420D23Fh
dword_7FFB0FEECE6C dd 0FCC25552h
dword_7FFB0FEECE70 dd 171407C4h
dword_7FFB0FEECE74 dd 0C16EF15h
dword_7FFB0FEECE78 dd 0AEB83048h
dword_7FFB0FEECE7C dd 8D6417F4h
dword_7FFB0FEECE80 dd 0B8571740h
dword_7FFB0FEECE84 dd 8E94B32h
dword_7FFB0FEECE88 dd 5BDDD42Bh
dword_7FFB0FEECE8C dd 9CD44802h
dword_7FFB0FEECE90 dd 3377CAEAh
dword_7FFB0FEECE94 dd 0DDD5FFF4h
dword_7FFB0FEECE98 dd 38BF26FEh
dword_7FFB0FEECE9C dd 0A350DF78h
dword_7FFB0FEECEA0 dd 15F32830h
dword_7FFB0FEECEA4 dd 8C5F7C64h
dword_7FFB0FEECEA8 dd 98B18F82h
dword_7FFB0FEECEAC dd 4D12943Ah
dword_7FFB0FEECEB0 dd 0C74A0E75h
dword_7FFB0FEECEB4 dd 37EF0401h
dword_7FFB0FEECEB8 dd 54D19C9Ah
dword_7FFB0FEECEBC dd 0C3CFB2ADh
dword_7FFB0FEECEC0 dd 973961E2h
dword_7FFB0FEECEC4 dd 3A12B183h
dword_7FFB0FEECEC8 dd 698D7315h
dword_7FFB0FEECECC dd 0CB5D7798h
dword_7FFB0FEECED0 dd 2BFE7A34h
dword_7FFB0FEECED4 dd 753E64FDh
dword_7FFB0FEECED8 dd 8D10110Dh
dword_7FFB0FEECEDC dd 5717FF07h
dword_7FFB0FEECEE0 dd 0C71F37AAh
dword_7FFB0FEECEE4 dd 289725A5h
dword_7FFB0FEECEE8 dd 0E0137F3h
dword_7FFB0FEECEEC dd 0E6FFBD40h
dword_7FFB0FEECEF0 dd 254D98Ch
dword_7FFB0FEECEF4 dd 2E66E6FBh
dword_7FFB0FEECEF8 dd 93A479E7h
dword_7FFB0FEECEFC dd 0D3D1EA89h
dword_7FFB0FEECF00 dd 0B3CD54D8h
dword_7FFB0FEECF04 dd 216540EDh
dword_7FFB0FEECF08 dd 0C4421CBDh
dword_7FFB0FEECF0C dd 71E66F14h
dword_7FFB0FEECF10 dd 5515D143h
dword_7FFB0FEECF14 dd 132A0D7Bh
dword_7FFB0FEECF18 dd 910D6011h
dword_7FFB0FEECF1C dd 3FD2568Ah
dword_7FFB0FEECF20 dd 0BA880A93h
dword_7FFB0FEECF24 dd 7C0E4518h
dword_7FFB0FEECF28 dd 0B0FA7615h
dword_7FFB0FEECF2C dd 4C38B000h
dword_7FFB0FEECF30 dd 41E315C3h
dword_7FFB0FEECF34 dd 8BCC9FC6h
dword_7FFB0FEECF38 dd 16D1B2Ch
dword_7FFB0FEECF3C dd 29CA12F7h
dword_7FFB0FEECF40 dd 60E67ECBh
dword_7FFB0FEECF44 dd 832044F3h
dword_7FFB0FEECF48 dd 9DD4EEF2h
dword_7FFB0FEECF4C dd 5B6225A6h
dword_7FFB0FEECF50 dd 0B897CEC9h
dword_7FFB0FEECF54 dd 1E82F79Ah
dword_7FFB0FEECF58 dd 0CB23DDC9h
dword_7FFB0FEECF5C dd 678B4DCCh
dword_7FFB0FEECF60 dd 932CFD2Dh
dword_7FFB0FEECF64 dd 0D603C7A3h
dword_7FFB0FEECF68 dd 2794BB65h
dword_7FFB0FEECF6C dd 7C67E221h
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC sub_7FFB0E53C420
sub_7FFB0E53C420:
    push r15
    push r14
    push r13
    push r12
    push rsi
    push rdi
    push rbp
    push rbx
    sub rsp, 198h
    mov rsi, r9
    mov rdi, rcx
    mov rbx, qword ptr [rsp+200h]
    mov rax, qword ptr [__security_cookie]
    xor rax, rsp
    mov qword ptr [rsp+190h], rax
    mov eax, dword ptr [dword_7FFB0FEECE40]
    mov ecx, eax
    xor ecx, -433BC251h
    lea edx, [rcx+1D405AC5h]
    lea r8d, [rcx+3478E924h]
    xor r8d, -5473F9C3h
    mov r9d, -11E1C2AAh
    sub r9d, r8d
    xor r9d, edx
    sub r9d, ecx
    lea ecx, [r9+r8]
    add ecx, -7B629B7Dh
    add ecx, eax
    lea eax, [r8+rcx]
    add eax, -0AFEFA8Fh
    mov dword ptr [rsp+48h], eax
    lea r14, [rbx+20h]
    mov r12d, 6E6174DFh
    lea r15, [rsp+18Eh]
    jmp loc_7FFB0E53C500
    loc_7FFB0E53C4B1:
    mov eax, dword ptr [dword_7FFB0FEECF0C]
    lea ecx, [rax-4945AA63h]
    xor ecx, 1697C25Ch
    lea edx, [rcx-13B3677Ah]
    mov r8d, edx
    xor r8d, -5971CB52h
    add eax, ecx
    add eax, -4945AA63h
    add eax, r8d
    add r8d, 2D64F0C1h
    mov ecx, 19BC075Ah
    sub ecx, eax
    xor ecx, r8d
    sub ecx, edx
    loc_7FFB0E53C4F0:
    mov dword ptr [rsp+48h], ecx
    nop word ptr [rax+rax+00000000h]
    loc_7FFB0E53C500:
    mov eax, dword ptr [rsp+48h]
    cmp eax, 3D8C750Fh
    jg loc_7FFB0E53C590
    cmp eax, 14C690E2h
    jg loc_7FFB0E53C600
    cmp eax, 8AF5651h
    jle loc_7FFB0E53C843
    cmp eax, 0DBC98A6h
    jg loc_7FFB0E53CBE8
    cmp eax, 90D289Eh
    jle loc_7FFB0E53D192
    cmp eax, 90D289Fh
    jz loc_7FFB0E53E1B7
    cmp eax, 0BA150B5h
    jnz loc_7FFB0E53E7C5
    movzx eax, byte ptr [rbx+101h]
    cmp al, 4
    setz byte ptr [rsp+0A4h]
    mov byte ptr [rsp+0A3h], al
    movzx eax, byte ptr [rsp+52h]
    test eax, eax
    jz loc_7FFB0E540462
    cmp eax, 1
    jnz loc_7FFB0E54049A
    mov byte ptr [rsp+54h], 8
    jmp loc_7FFB0E5404A8
    loc_7FFB0E53C590:
    cmp eax, 5D1E77B1h
    jg loc_7FFB0E53C680
    cmp eax, 4CFBD453h
    jle loc_7FFB0E53C93E
    cmp eax, 53658CF2h
    jg loc_7FFB0E53CC3A
    cmp eax, 4D768043h
    jle loc_7FFB0E53D1A2
    cmp eax, 4D768044h
    jz loc_7FFB0E53E286
    cmp eax, 4ED51626h
    jnz loc_7FFB0E53E7FF
    mov eax, dword ptr [rsp+0C8h]
    mov dword ptr [rsp+68h], eax
    mov eax, dword ptr [dword_7FFB0FEECE3C]
    lea ecx, [rax+rax]
    add eax, 1B63D8DAh
    sub ecx, eax
    add ecx, 1E24149Fh
    xor ecx, eax
    jmp loc_7FFB0E53C4F0
    loc_7FFB0E53C600:
    cmp eax, 30258B44h
    jg loc_7FFB0E53C74F
    cmp eax, 24176467h
    jg loc_7FFB0E53CDA8
    cmp eax, 19992C71h
    jle loc_7FFB0E53D6C7
    cmp eax, 19992C72h
    jz loc_7FFB0E53E401
    cmp eax, 1ABA1C59h
    jnz loc_7FFB0E53EE04
    movzx eax, byte ptr [rsp+0ABh]
    add al, byte ptr [rsp+0A8h]
    mov byte ptr [rsp+0ACh], al
    mov eax, dword ptr [dword_7FFB0FEECF38]
    mov ecx, eax
    xor ecx, -53E1F09Dh
    mov edx, eax
    xor edx, 18535343h
    sub eax, edx
    add eax, ecx
    add eax, -48A612B8h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53C680:
    cmp eax, 72D7BB5Ah
    jle loc_7FFB0E53CB79
    cmp eax, 78AC9D2Ch
    jg loc_7FFB0E53CCB9
    cmp eax, 7749F221h
    jle loc_7FFB0E53D421
    cmp eax, 7749F222h
    jz loc_7FFB0E53E358
    cmp eax, 775E2604h
    jnz loc_7FFB0E53EBD0
    movzx eax, byte ptr [rsp+9Bh]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    test al, al
    jz loc_7FFB0E5403F2
    mov eax, dword ptr [dword_7FFB0FEECEF8]
    mov ecx, eax
    xor ecx, -0B94AA08h
    lea edx, [rcx+2C83D323h]
    xor edx, -0A379A88h
    add ecx, eax
    sub edx, ecx
    add edx, -5D19CB95h
    mov dword ptr [rsp+48h], edx
    jmp loc_7FFB0E53C500
    loc_7FFB0E53C74F:
    cmp eax, 35F1B5F3h
    jg loc_7FFB0E53CEC0
    cmp eax, 3204A75Ch
    jle loc_7FFB0E53D724
    cmp eax, 3204A75Dh
    jz loc_7FFB0E53E6A3
    cmp eax, 33260BAAh
    jnz loc_7FFB0E53F13C
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rsp+0ADh]
    add al, 0DFh
    mov ecx, eax
    xor cl, 17h
    sub cl, byte ptr [rsp+4Dh]
    add cl, 57h
    xor cl, al
    xor cl, 0EAh
    sub cl, al
    cmp byte ptr [rsp+0A6h], cl
    jnz loc_7FFB0E54029E
    mov eax, dword ptr [dword_7FFB0FEECE78]
    lea ecx, [rax+4CA466B9h]
    mov edx, ecx
    xor edx, 1D123375h
    xor ecx, 7320425Ah
    sub edx, ecx
    add edx, 3A2ED677h
    jmp loc_7FFB0E5403AC
    loc_7FFB0E53C843:
    cmp eax, 347846Dh
    jle loc_7FFB0E53CF30
    cmp eax, 64979AFh
    jle loc_7FFB0E53DA23
    cmp eax, 64979B0h
    jz loc_7FFB0E53ECA2
    cmp eax, 6C97571h
    jnz loc_7FFB0E53F571
    movzx eax, byte ptr [rsp+0BAh]
    sub al, byte ptr [rsp+0B5h]
    add al, byte ptr [rsp+0B9h]
    xor al, byte ptr [rsp+0B3h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add al, byte ptr [rsp+0B8h]
    mov byte ptr [rsp+0BBh], al
    mov eax, dword ptr [dword_7FFB0FEECF60]
    mov ecx, eax
    xor ecx, -1AC379CEh
    lea edx, [rcx-750E874Bh]
    mov r8d, edx
    xor r8d, 5CF43778h
    xor edx, -1C81BD90h
    add edx, r8d
    sub edx, ecx
    xor edx, eax
    mov dword ptr [rsp+48h], edx
    jmp loc_7FFB0E53C500
    loc_7FFB0E53C93E:
    cmp eax, 449F469Dh
    jle loc_7FFB0E53D071
    cmp eax, 46D8D45Dh
    jle loc_7FFB0E53DB60
    cmp eax, 46D8D45Eh
    jz loc_7FFB0E53ED76
    cmp eax, 47B08C15h
    jnz loc_7FFB0E53F5B7
    movzx eax, byte ptr [rbx+17h]
    mov byte ptr [rsp+9Eh], al
    movzx r8d, byte ptr [byte_7FFB0FEA406B]
    lea edx, [r8-45h]
    mov byte ptr [rsp+9Fh], dl
    mov r9d, edx
    xor r9b, 0EBh
    lea eax, [r9-6]
    mov ecx, eax
    sub cl, r8b
    add cl, 62h
    xor cl, dl
    mov byte ptr [rsp+50h], r9b
    mov edx, eax
    xor dl, 51h
    xor cl, 3Bh
    add cl, r8b
    xor al, 0AEh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, ecx
    or r8b, al
    not r8b
    movzx r8d, r8b
    add r8d, r8d
    lea r8d, [r8+r8*4]
    mov r9d, ecx
    or r9b, dl
    movzx r9d, r9b
    lea r10d, [r9+r9*4]
    lea r9d, [r9+r10*2]
    mov r10d, ecx
    xor r10b, dl
    add r10b, r10b
    and al, cl
    shl al, 3
    and cl, dl
    movzx ecx, cl
    imul ecx, 0F5h
    sub cl, al
    sub cl, r10b
    add cl, r9b
    sub cl, r8b
    mov byte ptr [rsp+51h], cl
    movzx eax, byte ptr [rsp+50h]
    or cl, al
    not cl
    movzx ecx, cl
    add ecx, ecx
    lea ecx, [rcx+rcx*2]
    mov byte ptr [rsp+0A0h], cl
    not al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or al, byte ptr [rsp+51h]
    movzx eax, al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add eax, eax
    lea eax, [rax+rax*2]
    mov byte ptr [rsp+0A1h], al
    movzx eax, byte ptr [rsp+51h]
    xor al, byte ptr [rsp+50h]
    mov byte ptr [rsp+0A2h], al
    mov eax, dword ptr [dword_7FFB0FEECEF0]
    mov ecx, eax
    xor ecx, 7E516532h
    lea edx, [rcx-74682EE2h]
    mov r8d, edx
    xor r8d, 596EAE6Dh
    lea r9d, [rcx+rcx]
    add r9d, eax
    add r9d, r8d
    add r8d, 55189887h
    mov eax, -412CF8D8h
    sub eax, r9d
    xor r8d, edx
    xor r8d, eax
    sub r8d, ecx
    add r8d, 43F24EFh
    mov dword ptr [rsp+48h], r8d
    jmp loc_7FFB0E53C500
    loc_7FFB0E53CB79:
    cmp eax, 66F210DDh
    jle loc_7FFB0E53D170
    cmp eax, 6B1A62C9h
    jle loc_7FFB0E53E0B5
    cmp eax, 6B1A62CAh
    jz loc_7FFB0E53F25B
    cmp eax, 702BBCBFh
    jnz loc_7FFB0E53FD33
    mov byte ptr [rsp+4Eh], 1
    mov eax, dword ptr [dword_7FFB0FEECEB0]
    lea ecx, [rax-63B736A0h]
    mov edx, ecx
    xor edx, -0A64F177h
    lea r8d, 0FFFFFFFFE293A6D6h[rdx*2]
    mov r9d, edx
    sub r9d, r8d
    sub r9d, eax
    lea eax, [r9+rdx]
    add eax, -1D6C592Ah
    add eax, ecx
    add eax, -6C233E1Bh
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53CBE8:
    cmp eax, 1078B350h
    jle loc_7FFB0E53D20A
    cmp eax, 1078B351h
    jz loc_7FFB0E53E2C0
    cmp eax, 11832EDAh
    jnz loc_7FFB0E53E84B
    movzx eax, byte ptr [rsp+4Fh]
    mov ecx, eax
    not cl
    and cl, 0E8h
    mov byte ptr [rsp+6Fh], cl
    xor al, 0E8h
    mov byte ptr [rsp+70h], al
    mov eax, dword ptr [dword_7FFB0FEECE7C]
    mov ecx, -757483CEh
    add eax, ecx
    xor eax, 71100C74h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53CC3A:
    cmp eax, 5948061Bh
    jle loc_7FFB0E53D293
    cmp eax, 5948061Ch
    jz loc_7FFB0E53E339
    cmp eax, 5B074F82h
    jnz loc_7FFB0E53E9EC
    movzx eax, byte ptr [rsp+57h]
    mov byte ptr [rsp+61h], al
    mov eax, dword ptr [dword_7FFB0FEECEA0]
    lea ecx, [rax-5F89B36Ah]
    mov edx, ecx
    xor edx, -75EA2478h
    add edx, 4B504CA1h
    mov r8d, ecx
    xor r8d, -37CBD363h
    mov r9d, ecx
    xor r9d, r8d
    xor r9d, edx
    xor r9d, eax
    xor r9d, -45BB8536h
    sub r9d, r8d
    add r9d, -18CE8B91h
    xor r9d, ecx
    xor r9d, -35449F52h
    mov dword ptr [rsp+48h], r9d
    jmp loc_7FFB0E53C500
    loc_7FFB0E53CCB9:
    cmp eax, 7E6FC735h
    jg loc_7FFB0E53D9C1
    cmp eax, 78D2268Fh
    jnz loc_7FFB0E540575
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rbx+8]
    mov byte ptr [rbx+106h], al
    mov qword ptr [rsp+28h], r15
    mov qword ptr [rsp+20h], 24h
    mov ecx, 1Ah
    mov r8d, 58h
    mov rdx, rsi
    mov r9, rbx
    call sub_7FFB0F63EBA0
    mov dword ptr [rsp+0D0h], eax
    mov eax, dword ptr [dword_7FFB0FEECF30]
    lea ecx, [rax-681A9F2Ah]
    xor ecx, 6F23FDBEh
    lea edx, [rcx+rax]
    add edx, 1241725Dh
    add edx, eax
    add edx, ecx
    add edx, 7A5C1187h
    sub ecx, edx
    sub ecx, eax
    add eax, 53EC36EBh
    add ecx, -62511AF0h
    xor ecx, eax
    mov dword ptr [rsp+48h], ecx
    jmp loc_7FFB0E53C500
    loc_7FFB0E53CDA8:
    cmp eax, 27FF409Fh
    jle loc_7FFB0E53DF06
    cmp eax, 27FF40A0h
    jz loc_7FFB0E53FAE1
    cmp eax, 2A7B26E8h
    jnz loc_7FFB0E540606
    movzx eax, byte ptr [rsp+94h]
    sub al, byte ptr [rsp+90h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub al, byte ptr [rsp+8Fh]
    mov byte ptr [rsp+95h], al
    add al, 0D2h
    mov byte ptr [rsp+96h], al
    xor al, 54h
    mov byte ptr [rsp+97h], al
    add al, 0ACh
    mov byte ptr [rsp+98h], al
    mov ecx, eax
    not cl
    and cl, 61h
    movzx ecx, cl
    add ecx, ecx
    lea ecx, [rcx+rcx*4]
    mov byte ptr [rsp+99h], cl
    mov ecx, eax
    or cl, 0E1h
    movzx ecx, cl
    lea ecx, [rcx+rcx*2]
    mov edx, eax
    and dl, 1Eh
    shl dl, 2
    and al, 0E1h
    movzx eax, al
    lea eax, [rax+rax*8]
    add al, dl
    sub al, cl
    mov byte ptr [rsp+9Ah], al
    mov eax, dword ptr [dword_7FFB0FEECE60]
    lea ecx, [rax-549DDC9Ch]
    lea edx, 0FFFFFFFFEA7137E6h[rax*2]
    add edx, eax
    add edx, 3F0F1482h
    mov r8d, -3958D7DCh
    sub r8d, edx
    xor r8d, ecx
    add r8d, eax
    mov dword ptr [rsp+48h], r8d
    jmp loc_7FFB0E53C500
    loc_7FFB0E53CEC0:
    cmp eax, 3AF7A521h
    jle loc_7FFB0E53E089
    cmp eax, 3C89C22Dh
    jz loc_7FFB0E53FCF7
    cmp eax, 3D250850h
    jnz loc_7FFB0E5405FC
    mov rax, qword ptr [rsp+170h]
    sub rax, qword ptr [rsp+158h]
    add rax, qword ptr [rsp+168h]
    sub rax, qword ptr [rsp+150h]
    xor rax, qword ptr [rsp+160h]
    or rax, qword ptr [rsp+148h]
    mov rcx, qword ptr [rsp+140h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rsp+138h]
    movzx eax, byte ptr [rax]
    mov byte ptr [rsp+64h], al
    jmp loc_7FFB0E53CFB7
    loc_7FFB0E53CF30:
    cmp eax, 1B3D811h
    jg loc_7FFB0E53D4B9
    cmp eax, 62220Fh
    jz loc_7FFB0E53F18F
    movzx eax, byte ptr [rsp+8Ah]
    add al, byte ptr [rsp+5Dh]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add al, byte ptr [rsp+5Bh]
    cmp byte ptr [rsp+7Bh], al
    jnz loc_7FFB0E5402D4
    mov byte ptr [rsp+64h], 0
    loc_7FFB0E53CFB7:
    movzx eax, byte ptr [rsp+64h]
    mov byte ptr [rsp+8Bh], al
    movzx eax, byte ptr [rdi+7]
    mov byte ptr [rsp+8Ch], al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+0D8h]
    movzx eax, byte ptr [rax+8]
    mov byte ptr [rsp+8Dh], al
    mov eax, dword ptr [dword_7FFB0FEECEC0]
    lea ecx, [rax-0AFC6098h]
    add eax, 7F308183h
    xor eax, ecx
    xor ecx, -1F2D4D62h
    add eax, ecx
    lea edx, [rcx-0E676171h]
    sub eax, edx
    xor edx, 3E996158h
    sub eax, edx
    add eax, ecx
    add eax, ecx
    add eax, 3976CFBCh
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53D071:
    cmp eax, 417EE0C0h
    jg loc_7FFB0E53D57A
    cmp eax, 3D8C7510h
    jnz loc_7FFB0E53F21A
    mov eax, dword ptr [rbx]
    mov dword ptr [rsp+100h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FEA4070]
    mov dword ptr [rsp+104h], eax
    not eax
    mov ecx, eax
    and ecx, 1EE96080h
    lea ecx, [rcx+rcx*2]
    mov dword ptr [rsp+108h], ecx
    and eax, 61169F7Fh
    add eax, eax
    mov dword ptr [rsp+10Ch], eax
    mov eax, dword ptr [dword_7FFB0FEECF48]
    lea ecx, [rax+3A202838h]
    xor ecx, 2464D384h
    lea edx, [rcx+56DE90CDh]
    lea r8d, [rcx-2B12ECD4h]
    xor r8d, 453F9447h
    add ecx, -3EBF6E6Fh
    xor ecx, eax
    xor ecx, edx
    xor ecx, 7F0C8C83h
    sub ecx, eax
    lea eax, [rcx+r8]
    add eax, 1D5E2C7h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53D170:
    cmp eax, 61FE4E70h
    jg loc_7FFB0E53DDE0
    cmp eax, 5D1E77B2h
    jnz loc_7FFB0E53F67E
    movzx eax, byte ptr [rdi]
    mov byte ptr [rsp+63h], al
    jmp loc_7FFB0E53D72F
    loc_7FFB0E53D192:
    cmp eax, 8AF5652h
    jz loc_7FFB0E53DD2B
    jmp loc_7FFB0E5404A8
    loc_7FFB0E53D1A2:
    cmp eax, 4CFBD454h
    jnz loc_7FFB0E53EBDA
    movzx eax, byte ptr [rsp+0ACh]
    sub al, byte ptr [rsp+0A7h]
    mov byte ptr [rsp+0ADh], al
    mov eax, dword ptr [dword_7FFB0FEECF20]
    mov ecx, eax
    xor ecx, -7395C429h
    lea edx, [rcx-6CAB6298h]
    mov r8d, edx
    xor r8d, -42B43985h
    lea r9d, [r8+1E453C16h]
    xor edx, ecx
    xor edx, -45F22EDAh
    sub edx, r9d
    sub edx, r8d
    sub edx, eax
    lea eax, [rdx+r8]
    add eax, 3C972C5Ch
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53D20A:
    cmp eax, 0DBC98A7h
    jnz loc_7FFB0E53F14E
    mov eax, dword ptr [rsp+104h]
    mov ecx, eax
    and ecx, -1EE96081h
    lea edx, [rcx+rcx*2]
    not ecx
    add ecx, ecx
    and eax, 1EE96080h
    mov r8d, eax
    not r8d
    add eax, eax
    sub eax, edx
    lea eax, [rax+r8*4]
    sub eax, ecx
    sub eax, dword ptr [rsp+10Ch]
    sub eax, dword ptr [rsp+108h]
    mov dword ptr [rsp+110h], eax
    add eax, 4D31F86Fh
    mov dword ptr [rsp+0D4h], eax
    mov eax, dword ptr [dword_7FFB0FEECF4C]
    mov ecx, 73312962h
    xor eax, ecx
    lea ecx, [rax+49EE322Fh]
    xor eax, ecx
    xor ecx, -4409B05Ah
    xor eax, ecx
    xor eax, 40CF3D58h
    sub eax, ecx
    add eax, 584B418Ch
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53D293:
    cmp eax, 53658CF3h
    jnz loc_7FFB0E53EC6D
    mov eax, dword ptr [dword_7FFB0FEA4080]
    mov ecx, eax
    xor ecx, 273C1B6Ch
    lea edx, [rcx+53DB4AA6h]
    mov r8d, edx
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
    mov r9d, edx
    or r9d, -7E884518h
    and r8d, -7E884518h
    lea r10d, [rdx+rdx]
    sub eax, edx
    and edx, 7E884517h
    add edx, edx
    sub r10d, edx
    add r10d, r8d
    lea edx, [r9+r10]
    add edx, 7E884519h
    lea r8d, [r9+r10]
    add r8d, 0C57E61Bh
    xor r8d, -1514C495h
    lea r9d, [r8-55D7C286h]
    add eax, -0F912B74h
    xor eax, r9d
    add r8d, ecx
    add r8d, eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r8d, edx
    cmp dword ptr [rsp+0C4h], r8d
    jle loc_7FFB0E540254
    mov eax, dword ptr [dword_7FFB0FEECEC4]
    mov ecx, eax
    xor ecx, -78B2EF81h
    mov edx, eax
    xor edx, 3EE0D018h
    lea r8d, [rdx+57817382h]
    xor r8d, 596E01D3h
    lea r9d, [r8-48FC337Dh]
    add ecx, edx
    add ecx, -5977BDC6h
    xor ecx, eax
    sub ecx, r9d
    lea eax, [rcx+rdx]
    add eax, 57817382h
    add eax, r8d
    add eax, -48FC337Dh
    add eax, r8d
    add eax, -573C268Bh
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53D421:
    cmp eax, 72D7BB5Bh
    jnz loc_7FFB0E53EDC7
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rax, [rdi+1]
    mov qword ptr [rsp+120h], rax
    mov rax, qword ptr [rsp+0D8h]
    movzx eax, byte ptr [rax+9]
    mov qword ptr [rsp+128h], rax
    mov eax, dword ptr [dword_7FFB0FEECEB4]
    mov ecx, eax
    add ecx, 454F3448h
    add ecx, eax
    add ecx, 454F3448h
    neg ecx
    add eax, ecx
    add eax, -3A2B0F01h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53D4B9:
    cmp eax, 1B3D812h
    jnz loc_7FFB0E540177
    mov eax, dword ptr [rsp+0D0h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    test eax, eax
    js loc_7FFB0E54060F
    mov eax, dword ptr [dword_7FFB0FEECEDC]
    lea ecx, [rax-6FBC2C02h]
    lea edx, [rax-4AD0CDD7h]
    xor edx, -1D0DC026h
    sub edx, eax
    add edx, eax
    add edx, -4AD0CDD7h
    sub edx, ecx
    sub edx, eax
    sub edx, eax
    add eax, edx
    add eax, -1696F8ABh
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53D57A:
    cmp eax, 417EE0C1h
    jnz loc_7FFB0E53F224
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rax, [rbx+0FFh]
    mov qword ptr [rsp+0E0h], rax
    lea rax, [rbx+102h]
    mov qword ptr [rsp+118h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+118h]
    movzx eax, byte ptr [rax]
    mov byte ptr [rsp+6Dh], al
    movzx eax, byte ptr [byte_7FFB0FEA4068]
    mov byte ptr [rsp+4Fh], al
    not al
    and al, 17h
    mov byte ptr [rsp+6Eh], al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FEECE70]
    lea ecx, [rax-34F6FA66h]
    xor ecx, -1CD52915h
    add ecx, eax
    add ecx, 2352FB1h
    add eax, 2352FB1h
    xor ecx, eax
    xor ecx, 124B0A85h
    jmp loc_7FFB0E53C4F0
    loc_7FFB0E53D6C7:
    cmp eax, 14C690E3h
    jnz loc_7FFB0E53F3FB
    movzx eax, byte ptr [rsp+0B1h]
    sub al, byte ptr [rsp+0B0h]
    cmp byte ptr [rsp+0A3h], al
    jnz loc_7FFB0E540310
    mov eax, dword ptr [dword_7FFB0FEECF44]
    lea ecx, [rax+59FF3Ch]
    lea edx, [rax-17632BDBh]
    mov r8d, eax
    xor r8d, edx
    xor r8d, -4E4A8253h
    add eax, r8d
    add eax, 21A7CDF7h
    xor ecx, edx
    xor ecx, eax
    xor ecx, 28BB1B17h
    jmp loc_7FFB0E53C4F0
    loc_7FFB0E53D724:
    cmp eax, 30258B45h
    jz loc_7FFB0E54000C
    loc_7FFB0E53D72F:
    movzx eax, byte ptr [rsp+63h]
    mov ecx, eax
    and cl, 4
    movzx edx, byte ptr [byte_7FFB0FEA4084]
    lea r9d, [rdx-41h]
    mov r8d, r9d
    xor r8b, 74h
    lea r10d, [r8+6]
    mov r11d, r10d
    not r11b
    and r11b, 0B1h
    mov ebp, r10d
    or bpl, 0B1h
    mov r13d, r10d
    xor r13b, 4Eh
    add r13b, bpl
    add r13b, r11b
    lea r11d, [r10+r10]
    mov ebp, r10d
    and bpl, 4Eh
    movzx ebp, bpl
    lea ebp, [rbp+rbp*2+0]
    and r10b, 0B1h
    movzx r10d, r10b
    lea r10d, [r10+r10*2]
    add r10b, bpl
    sub r10b, r11b
    add r10b, r13b
    lea r11d, [r10+1]
    add r10b, 43h
    xor r8b, r9b
    xor r8b, r10b
    xor r8b, r11b
    xor r8b, 32h
    add dl, dl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add dl, r10b
    add dl, r8b
    add dl, 0A3h
    cmp cl, dl
    jnz loc_7FFB0E53F445
    mov byte ptr [rsp+65h], al
    mov eax, dword ptr [dword_7FFB0FEECEEC]
    lea ecx, [rax+693462D9h]
    add eax, -70D61B90h
    mov edx, eax
    xor edx, 173154Ch
    lea r8d, [rdx-153D8B26h]
    lea r9d, [rdx-589DF3E9h]
    xor r9d, ecx
    xor r9d, 31CAC740h
    lea ecx, [rdx+r9]
    add ecx, -3B7DC475h
    xor r8d, eax
    xor r8d, ecx
    xor r8d, -57F823AFh
    add r8d, edx
    xor r8d, eax
    mov dword ptr [rsp+48h], r8d
    jmp loc_7FFB0E53C500
    loc_7FFB0E53D9C1:
    cmp eax, 7E6FC736h
    jz loc_7FFB0E540007
    cmp eax, 7F4C1B4Ch
    jnz loc_7FFB0E540113
    movzx eax, byte ptr [rsp+4Dh]
    and al, 8Eh
    movzx ecx, byte ptr [rsp+0AAh]
    sub cl, al
    add cl, byte ptr [rsp+0A9h]
    mov byte ptr [rsp+0ABh], cl
    mov eax, dword ptr [dword_7FFB0FEECE94]
    mov edx, 7AABDB5Fh
    sub edx, eax
    sub edx, eax
    lea ecx, [rax+3DB070C1h]
    xor ecx, edx
    xor ecx, 633CE05Bh
    add eax, ecx
    add eax, 769ED0CCh
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53DA23:
    cmp eax, 347846Eh
    jnz loc_7FFB0E53F5E8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+120h]
    mov rcx, qword ptr [rsp+128h]
    movzx eax, byte ptr [rax+rcx]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+28h], rsi
    mov byte ptr [rsp+20h], al
    mov edx, 53h
    mov r8d, 0Eh
    mov r9d, 22h
    mov rcx, rbx
    call sub_7FFB0F884630
    mov dword ptr [rsp+0C4h], eax
    mov eax, dword ptr [dword_7FFB0FEECEB8]
    lea ecx, [rax+7305C097h]
    lea edx, [rax+34C1D07Ch]
    mov r8d, 6223E2ACh
    sub r8d, eax
    xor r8d, edx
    xor edx, 4271C145h
    xor r8d, eax
    sub r8d, edx
    xor r8d, ecx
    sub r8d, edx
    add eax, r8d
    add eax, 67D4632h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53DB60:
    cmp eax, 449F469Eh
    jnz loc_7FFB0E53F625
    movzx edx, byte ptr [rsp+9Ah]
    add dl, byte ptr [rsp+99h]
    add dl, 0BAh
    mov al, 0EEh
    sub al, byte ptr [rsp+95h]
    mov r8d, edx
    not r8b
    mov ecx, eax
    or cl, r8b
    not cl
    movzx ecx, cl
    lea ecx, [rcx+rcx*2]
    and r8b, al
    movzx r8d, r8b
    lea r9d, [r8+r8*2]
    mov r10d, eax
    or r10b, dl
    not r10b
    add r10b, r10b
    not r8b
    add r8b, r8b
    and al, dl
    mov edx, eax
    not dl
    shl dl, 2
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add al, al
    sub al, r9b
    add al, dl
    sub al, r8b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub al, r10b
    sub al, cl
    sub al, byte ptr [rsp+97h]
    xor al, byte ptr [rsp+96h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor al, byte ptr [rsp+98h]
    movzx r8d, byte ptr [rsp+8Bh]
    movzx ecx, byte ptr [rsp+8Ch]
    movzx edx, byte ptr [rsp+8Eh]
    mov byte ptr [rsp+40h], al
    mov qword ptr [rsp+38h], rsi
    mov byte ptr [rsp+30h], dl
    mov byte ptr [rsp+20h], cl
    mov qword ptr [rsp+28h], 3Ch
    mov ecx, 1Eh
    mov edx, 42h
    mov r9, rbx
    call sub_7FFB0E3A4960
    test eax, eax
    js loc_7FFB0E54061F
    movzx eax, byte ptr [rdi]
    mov byte ptr [rsp+65h], al
    loc_7FFB0E53DD2B:
    movzx eax, byte ptr [rsp+65h]
    and al, 8
    mov byte ptr [rsp+9Bh], al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FEECEF4]
    mov ecx, eax
    xor ecx, -54285F0Eh
    lea edx, [rcx+373D734Dh]
    mov r8d, edx
    xor r8d, 6F5ED317h
    sub r8d, edx
    add r8d, eax
    lea eax, [rcx+r8]
    add eax, -537BB7EBh
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53DDE0:
    cmp eax, 61FE4E71h
    jnz loc_7FFB0E53F82D
    mov eax, dword ptr [rsp+0D4h]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and eax, 3EBDE73Ch
    lea ecx, [rax+rax*4]
    mov eax, dword ptr [rsp+0D4h]
    mov edx, eax
    or edx, 3EBDE73Ch
    lea edx, [rdx+rdx*2]
    mov r8d, eax
    and r8d, 14218C3h
    mov r9d, eax
    and r9d, 3EBDE73Ch
    lea r9d, [r9+r9*8]
    lea r8d, [r9+r8*4]
    sub r8d, edx
    lea edx, [r8+rcx*2]
    lea ecx, [r8+rcx*2]
    add ecx, -40D1334h
    mov r8d, ecx
    xor r8d, -4B1FAC92h
    xor ecx, 4629387h
    sub ecx, edx
    sub ecx, r8d
    add ecx, 78736B68h
    xor ecx, dword ptr [rsp+110h]
    add ecx, eax
    cmp dword ptr [rsp+100h], ecx
    jnz loc_7FFB0E540172
    mov eax, dword ptr [dword_7FFB0FEECF50]
    mov ecx, eax
    xor ecx, 6181A003h
    mov edx, 2B971F7Dh
    sub edx, ecx
    xor edx, eax
    lea eax, [rcx+rdx]
    add eax, 649CF845h
    add eax, ecx
    add eax, 7E773D8Fh
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53DF06:
    cmp eax, 24176468h
    jz loc_7FFB0E53F18F
    movzx eax, byte ptr [rsp+79h]
    not al
    movzx eax, al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ecx, [rax+rax*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rsp+59h]
    mov edx, eax
    not dl
    and dl, 5Ah
    movzx edx, dl
    lea edx, [rdx+rdx*4]
    mov r8d, eax
    xor r8b, 25h
    add r8b, r8b
    and al, 1Ah
    shl al, 3
    sub al, r8b
    add al, cl
    add al, dl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ecx, [rax+48h]
    mov edx, ecx
    xor dl, 11h
    add dl, 46h
    xor dl, cl
    xor cl, 58h
    add cl, byte ptr [rsp+59h]
    add cl, al
    add cl, 3Eh
    xor dl, cl
    and dl, byte ptr [rsp+78h]
    mov byte ptr [rsp+4Eh], dl
    jmp loc_7FFB0E54000C
    loc_7FFB0E53E089:
    cmp eax, 35F1B5F4h
    jz loc_7FFB0E53E2C7
    mov rax, qword ptr [rsp+0E0h]
    cmp byte ptr [rax], 1
    mov eax, 20h
    mov ecx, 8
    cmovz eax, ecx
    mov byte ptr [rsp+67h], al
    jmp loc_7FFB0E53F145
    loc_7FFB0E53E0B5:
    cmp eax, 66F210DEh
    jnz loc_7FFB0E53FEC5
    movzx eax, byte ptr [rsp+5Ch]
    and al, 0EDh
    movzx eax, al
    lea eax, [rax+rax*2]
    neg eax
    sub al, byte ptr [rsp+87h]
    add al, byte ptr [rsp+86h]
    sub al, byte ptr [rsp+85h]
    add al, 26h
    mov byte ptr [rsp+5Dh], al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rsp+5Dh]
    add al, 0EEh
    movzx ecx, byte ptr [rsp+5Ch]
    xor cl, 0F9h
    add cl, byte ptr [rsp+83h]
    add cl, byte ptr [rsp+7Fh]
    mov byte ptr [rsp+88h], al
    mov byte ptr [rsp+89h], cl
    mov eax, dword ptr [dword_7FFB0FEECEE0]
    lea ecx, [rax+3470FF7Dh]
    lea edx, [rax+0BD766C7h]
    mov r8d, -3B53AC47h
    sub r8d, eax
    xor r8d, edx
    xor r8d, ecx
    sub r8d, edx
    add eax, r8d
    add eax, 7FEE4AACh
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53E1B7:
    lea rax, [rdi+9]
    mov qword ptr [rsp+178h], rax
    movzx eax, byte ptr [rdi+0Dh]
    mov byte ptr [rsp+9Ch], al
    movzx eax, byte ptr [rdi+0Ch]
    mov byte ptr [rsp+9Dh], al
    mov rax, qword ptr [rsp+0D8h]
    add rax, 8
    mov qword ptr [rsp+180h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FEECEFC]
    mov ecx, eax
    xor ecx, -0FD9B459h
    lea edx, [rcx-5AC07E4h]
    mov r8d, edx
    xor r8d, -2825B970h
    lea r9d, [r8-31D7C344h]
    mov r10d, r9d
    xor r10d, -0E5051B0h
    xor r9d, r8d
    xor r9d, -523A3751h
    sub r9d, ecx
    add r9d, eax
    xor r9d, edx
    add r9d, r10d
    mov dword ptr [rsp+48h], r9d
    jmp loc_7FFB0E53C500
    loc_7FFB0E53E286:
    movzx eax, byte ptr [byte_7FFB0FEA407C]
    add al, 0B1h
    mov byte ptr [rsp+59h], al
    or al, 5Ah
    mov byte ptr [rsp+79h], al
    mov eax, dword ptr [dword_7FFB0FEECEA8]
    mov ecx, eax
    xor ecx, 5F411099h
    lea edx, [rcx-7FE073D6h]
    sub ecx, eax
    add ecx, 3F0D9574h
    loc_7FFB0E53E2B5:
    xor ecx, edx
    mov dword ptr [rsp+48h], ecx
    jmp loc_7FFB0E53C500
    loc_7FFB0E53E2C0:
    movzx eax, byte ptr [rdi]
    mov byte ptr [rsp+61h], al
    loc_7FFB0E53E2C7:
    movzx eax, byte ptr [rsp+61h]
    shr al, 4
    mov byte ptr [rsp+78h], al
    mov eax, dword ptr [dword_7FFB0FEECE38]
    mov ecx, eax
    xor ecx, 74F0AD81h
    lea edx, [rcx-56DE2F9Dh]
    mov r8d, edx
    xor r8d, -1C1E4A25h
    mov r9d, edx
    xor r9d, -184806Eh
    add r9d, 347F21A0h
    mov r10d, r9d
    xor r10d, -7A93C76Dh
    xor r9d, 141F82F2h
    mov r11d, edx
    xor r11d, -27179EB6h
    add r11d, r8d
    add r11d, ecx
    add r11d, r9d
    add r10d, eax
    add r10d, r11d
    sub r10d, edx
    mov dword ptr [rsp+48h], r10d
    jmp loc_7FFB0E53C500
    loc_7FFB0E53E339:
    movzx eax, byte ptr [rsp+0B2h]
    cmp al, byte ptr [rsp+0BBh]
    jnz loc_7FFB0E540227
    loc_7FFB0E53E34E:
    mov byte ptr [rsp+4Ch], 10h
    jmp loc_7FFB0E540177
    loc_7FFB0E53E358:
    movzx eax, byte ptr [rsp+82h]
    sub al, byte ptr [rsp+81h]
    add al, byte ptr [rsp+80h]
    lea ecx, [rax+16h]
    mov byte ptr [rsp+83h], cl
    lea ecx, [rax-42h]
    mov byte ptr [rsp+84h], cl
    add al, 0B5h
    mov byte ptr [rsp+5Ch], al
    mov ecx, eax
    not cl
    and cl, 2Dh
    shl cl, 2
    mov byte ptr [rsp+85h], cl
    mov ecx, eax
    or cl, 0EDh
    movzx ecx, cl
    lea ecx, [rcx+rcx*4]
    mov byte ptr [rsp+86h], cl
    and al, 12h
    shl al, 2
    mov byte ptr [rsp+87h], al
    mov eax, dword ptr [dword_7FFB0FEECED8]
    lea ecx, [rax-253FC87Eh]
    xor ecx, -632785B0h
    lea edx, [rcx-1AB65C07h]
    lea r8d, [rcx-5D20F19h]
    xor r8d, 4AA8261Dh
    xor eax, 788A5FE9h
    add eax, ecx
    add eax, -5D20F19h
    xor eax, edx
    add eax, ecx
    xor eax, r8d
    add eax, r8d
    add eax, -12C3C787h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53E401:
    mov eax, dword ptr [rsp+0BCh]
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
    and eax, 62C1D714h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea eax, [rax+rax*4]
    mov ecx, dword ptr [rsp+0BCh]
    mov edx, ecx
    or edx, 62C1D714h
    lea edx, [rdx+rdx*2]
    mov r8d, ecx
    and r8d, 1D3E28EBh
    and ecx, 62C1D714h
    lea ecx, [rcx+rcx*8]
    lea ecx, [rcx+r8*4]
    sub ecx, edx
    lea eax, [rcx+rax*2]
    add eax, -508B0A78h
    mov ecx, eax
    xor ecx, -794EDA42h
    mov edx, dword ptr [rsp+0F0h]
    xor edx, eax
    xor edx, -4996F09Eh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub edx, dword ptr [rsp+0BCh]
    add edx, dword ptr [rsp+0ECh]
    xor edx, ecx
    mov r8d, edx
    xor r8d, 8C0023Ah
    xor edx, -8C0023Bh
    mov dword ptr [rsp+0F4h], edx
    xor eax, 794EDA41h
    mov edx, r8d
    or edx, eax
    not edx
    lea r9d, [rdx+rdx*4]
    lea edx, [rdx+r9*2]
    mov dword ptr [rsp+0F8h], edx
    mov edx, r8d
    or edx, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r9d, [rcx+rcx*4]
    lea r9d, [rcx+r9*2]
    and eax, r8d
    and r8d, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    imul ecx, r8d, 0F5h
    add eax, r9d
    add eax, ecx
    add eax, edx
    inc eax
    mov dword ptr [rsp+0FCh], eax
    mov eax, dword ptr [dword_7FFB0FEECE48]
    lea ecx, [rax+1859B908h]
    xor ecx, -331A7045h
    lea edx, 691C7074h[rax*2]
    sub ecx, edx
    add ecx, eax
    add ecx, eax
    add ecx, 50C2B76Ch
    add eax, ecx
    add eax, 26F7DD82h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53E6A3:
    movzx eax, byte ptr [rsp+7Eh]
    shl al, 2
    movzx ecx, byte ptr [rsp+5Ah]
    and cl, 0BDh
    movzx ecx, cl
    lea ecx, [rcx+rcx*2]
    neg ecx
    sub cl, al
    add cl, byte ptr [rsp+7Dh]
    sub cl, byte ptr [rsp+7Ch]
    add cl, 86h
    mov byte ptr [rsp+7Fh], cl
    mov eax, ecx
    xor al, 0A8h
    mov byte ptr [rsp+5Bh], al
    xor cl, 7
    and cl, 27h
    movzx ecx, cl
    add ecx, ecx
    lea ecx, [rcx+rcx*4]
    mov byte ptr [rsp+80h], cl
    mov ecx, eax
    or cl, 0A7h
    movzx ecx, cl
    lea ecx, [rcx+rcx*2]
    mov byte ptr [rsp+81h], cl
    and al, 18h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    shl al, 2
    movzx ecx, byte ptr [rsp+5Bh]
    and cl, 0A7h
    movzx ecx, cl
    lea ecx, [rcx+rcx*8]
    add cl, al
    mov byte ptr [rsp+82h], cl
    mov eax, dword ptr [dword_7FFB0FEECED4]
    mov ecx, eax
    xor ecx, -4643E6FBh
    mov edx, eax
    xor edx, -5C60CB4h
    lea r8d, [rdx+40B338D1h]
    xor r8d, 781458F2h
    lea r9d, [r8+5C1B4374h]
    mov r10d, r9d
    xor r10d, -60B370C5h
    sub r10d, ecx
    lea ecx, [r10+rdx]
    add ecx, 40B338D1h
    sub ecx, r8d
    sub ecx, eax
    sub ecx, r9d
    add ecx, 2843140Ah
    jmp loc_7FFB0E53C4F0
    loc_7FFB0E53E7C5:
    mov eax, dword ptr [dword_7FFB0FEECE44]
    mov ecx, eax
    xor ecx, 49C32B45h
    lea edx, [rcx-3A560436h]
    mov r8d, edx
    xor r8d, -120D7085h
    sub edx, r8d
    add edx, 5D489D10h
    xor r8d, eax
    xor r8d, edx
    sub r8d, ecx
    mov dword ptr [rsp+48h], r8d
    jmp loc_7FFB0E53C500
    loc_7FFB0E53E7FF:
    movzx r9d, byte ptr [rsp+18Eh]
    mov qword ptr [rsp+20h], 3Eh
    mov ecx, 33h
    mov r8d, 56h
    mov rdx, rbx
    call sub_7FFB0E3E75C0
    mov eax, dword ptr [dword_7FFB0FEECF34]
    lea ecx, [rax-1062EDDAh]
    mov edx, ecx
    xor edx, -268B66C3h
    sub edx, eax
    sub edx, ecx
    add edx, -2FCC7455h
    mov dword ptr [rsp+48h], edx
    jmp loc_7FFB0E53C500
    loc_7FFB0E53E84B:
    movzx eax, byte ptr [rsp+0B7h]
    not al
    movzx eax, al
    lea ecx, [rax+rax*4]
    lea eax, [rax+rcx*2]
    movzx ecx, byte ptr [rsp+53h]
    not cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or cl, 0CDh
    movzx ecx, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea edx, [rcx+rcx*4]
    lea edx, [rcx+rdx*2]
    movzx ecx, byte ptr [rsp+53h]
    mov r8d, ecx
    or r8b, 32h
    movzx r8d, r8b
    lea r9d, [r8+r8*4]
    lea r8d, [r8+r9*2]
    mov r9d, ecx
    and r9b, 0CDh
    movzx r9d, r9b
    lea r10d, [r9+r9*4]
    lea r9d, [r9+r10*4]
    mov r10d, ecx
    and r10b, 32h
    movzx r10d, r10b
    lea r10d, [r10+r10*8]
    neg r10d
    sub r10b, r9b
    add r10b, r8b
    add r10b, dl
    sub r10b, al
    sub r10b, byte ptr [rsp+0B6h]
    add r10b, 0A8h
    mov byte ptr [rsp+0B8h], r10b
    xor r10b, 0B0h
    mov byte ptr [rsp+0B9h], r10b
    add cl, byte ptr [rsp+0B4h]
    mov al, 0A5h
    sub al, cl
    mov byte ptr [rsp+0BAh], al
    mov eax, dword ptr [dword_7FFB0FEECF5C]
    lea ecx, [rax-57CBB51h]
    lea edx, 0FFFFFFFF8F94D065h[rax*2]
    lea r8d, [rax-1768EE3Ch]
    xor r8d, ecx
    xor r8d, -3914326h
    lea ecx, [r8+rax]
    add ecx, -706B2F9Bh
    add ecx, eax
    sub ecx, edx
    add ecx, 38870440h
    jmp loc_7FFB0E53C4F0
    loc_7FFB0E53E9EC:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rsp+8Dh]
    mov rcx, qword ptr [rsp+130h]
    movzx eax, byte ptr [rcx+rax]
    mov byte ptr [rsp+8Eh], al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [byte_7FFB0FEA4090]
    mov byte ptr [rsp+5Eh], al
    not al
    mov ecx, eax
    and cl, 12h
    movzx ecx, cl
    lea ecx, [rcx+rcx*2]
    mov byte ptr [rsp+8Fh], cl
    mov ecx, eax
    and cl, 2Dh
    shl cl, 2
    mov byte ptr [rsp+90h], cl
    mov ecx, eax
    or cl, 12h
    mov byte ptr [rsp+91h], cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [rsp+5Eh]
    and al, cl
    not al
    movzx eax, al
    lea eax, [rax+rax*2]
    mov byte ptr [rsp+92h], al
    and cl, 6Dh
    add cl, cl
    mov byte ptr [rsp+93h], cl
    mov eax, dword ptr [dword_7FFB0FEECE98]
    mov ecx, eax
    xor ecx, 2E7BE4F1h
    lea edx, [rcx-36A99FDDh]
    mov r8d, edx
    xor r8d, -29E26891h
    mov r9d, edx
    xor r9d, 513C66CDh
    lea r10d, [r9+38D6FE27h]
    add ecx, eax
    sub ecx, r8d
    sub ecx, r10d
    add ecx, -3D6EADE9h
    xor ecx, r9d
    sub ecx, edx
    lea eax, [rcx+r9]
    add eax, 38D6FE27h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53EBD0:
    movzx eax, byte ptr [rsp+55h]
    jmp loc_7FFB0E54001F
    loc_7FFB0E53EBDA:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rsp+5Eh]
    and al, 12h
    add al, al
    add al, byte ptr [rsp+93h]
    movzx ecx, byte ptr [rsp+92h]
    sub cl, al
    add cl, byte ptr [rsp+91h]
    mov byte ptr [rsp+94h], cl
    mov eax, dword ptr [dword_7FFB0FEECEE8]
    lea ecx, [rax+1678D928h]
    xor ecx, eax
    jmp loc_7FFB0E53C4F0
    loc_7FFB0E53EC6D:
    mov eax, dword ptr [dword_7FFB0FEECE64]
    mov ecx, eax
    xor ecx, -1DF86F28h
    add ecx, 52E725C1h
    mov edx, ecx
    xor edx, 714EE633h
    xor ecx, 2835172Ah
    sub edx, ecx
    sub edx, eax
    add edx, 22751575h
    mov dword ptr [rsp+48h], edx
    jmp loc_7FFB0E53C500
    loc_7FFB0E53ECA2:
    mov qword ptr [rsp+140h], r14
    mov rax, qword ptr [rbx+20h]
    mov qword ptr [rsp+148h], rax
    mov rax, qword ptr [qword_7FFB0FEA4088]
    mov qword ptr [rsp+150h], rax
    mov rcx, 7EC5AB2A99CCEFDh
    add rcx, rax
    mov qword ptr [rsp+158h], rcx
    mov rcx, -257C68F3C8946DD0h
    add rcx, rax
    mov qword ptr [rsp+160h], rcx
    mov rcx, -46C7A2E8013989DCh
    add rax, rcx
    mov rcx, rax
    mov rdx, 8C74167C62E1FF7h
    xor rcx, rdx
    mov qword ptr [rsp+168h], rcx
    mov rcx, 5B74538E5DA4637Bh
    xor rax, rcx
    mov qword ptr [rsp+170h], rax
    mov eax, dword ptr [dword_7FFB0FEECE9C]
    mov ecx, eax
    xor ecx, -486C8889h
    lea edx, [rcx-1BF688B8h]
    xor edx, -4AE73D69h
    add edx, ecx
    add edx, 203594B6h
    add edx, ecx
    add edx, 46D47BE7h
    xor edx, eax
    add edx, ecx
    add ecx, 203594B6h
    xor ecx, 1DA6B116h
    sub edx, ecx
    add edx, -542175BCh
    xor edx, ecx
    mov dword ptr [rsp+48h], edx
    jmp loc_7FFB0E53C500
    loc_7FFB0E53ED76:
    movzx eax, byte ptr [rsp+0A5h]
    mov byte ptr [rsp+4Ch], al
    mov eax, dword ptr [dword_7FFB0FEECF24]
    lea ecx, [rax+60026162h]
    mov edx, ecx
    xor edx, 326A3E8Eh
    lea r8d, [rdx+762FB78Bh]
    add edx, 4B3C8AD4h
    xor r8d, edx
    xor r8d, 762927EBh
    add r8d, eax
    sub r8d, ecx
    add r8d, 6D3081C9h
    xor r8d, edx
    mov dword ptr [rsp+48h], r8d
    jmp loc_7FFB0E53C500
    loc_7FFB0E53EDC7:
    movzx eax, byte ptr [rsp+7Ah]
    mov byte ptr [rsp+63h], al
    mov eax, dword ptr [dword_7FFB0FEECEC8]
    lea ecx, [rax+32522588h]
    mov edx, ecx
    xor edx, -44522C83h
    mov r8d, ecx
    xor r8d, 7F526DD0h
    add edx, r8d
    add edx, -364233Eh
    xor edx, ecx
    sub edx, eax
    mov dword ptr [rsp+48h], edx
    jmp loc_7FFB0E53C500
    loc_7FFB0E53EE04:
    mov rax, qword ptr [rsp+180h]
    movzx eax, byte ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rsp+178h]
    movzx eax, byte ptr [rcx+rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [byte_7FFB0FEA4091]
    mov edx, ecx
    not dl
    mov r8d, ecx
    or r8b, 0E0h
    and dl, 60h
    movzx edx, dl
    add edx, edx
    lea r9d, [rdx+rdx*2]
    lea r10d, [rcx+rcx*2]
    mov edx, ecx
    and dl, 20h
    shl dl, 2
    mov r11d, ecx
    and r11b, 1Fh
    movzx r11d, r11b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r11d, [r11+r11*2]
    neg r11d
    add dl, r10b
    add dl, r11b
    add dl, r9b
    add dl, r8b
    add dl, 0C1h
    xor dl, 0C8h
    lea r8d, [rdx-22h]
    xor r8b, 0ABh
    add dl, cl
    add dl, r8b
    movzx r8d, byte ptr [rsp+9Ch]
    movzx ecx, byte ptr [rsp+9Dh]
    mov qword ptr [rsp+38h], rsi
    mov byte ptr [rsp+30h], al
    mov byte ptr [rsp+20h], cl
    mov byte ptr [rsp+40h], dl
    mov qword ptr [rsp+28h], 4Bh
    mov ecx, 49h
    mov edx, 17h
    mov r9, rbx
    call sub_7FFB0E3A4960
    mov dword ptr [rsp+0C8h], eax
    mov eax, dword ptr [dword_7FFB0FEA4094]
    mov ecx, eax
    xor ecx, 5154EC71h
    lea edx, [rcx+4F45F3B5h]
    lea r8d, [rcx-4E9D55B9h]
    lea r9d, [rcx+5145C783h]
    xor r8d, 127F6711h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    sub r8d, eax
    sub r8d, ecx
    sub r8d, r9d
    add r8d, 3DB31E7Fh
    xor r8d, edx
    cmp dword ptr [rsp+0C8h], r8d
    jg loc_7FFB0E5405FC
    mov eax, dword ptr [dword_7FFB0FEECF04]
    lea ecx, [rax-24AA53D4h]
    mov edx, ecx
    xor edx, 1C48B48h
    add edx, -635A773Ch
    mov r8d, edx
    xor r8d, 3B962B29h
    sub r8d, edx
    sub r8d, eax
    add ecx, r8d
    add ecx, -73372A88h
    xor ecx, eax
    jmp loc_7FFB0E53C4F0
    loc_7FFB0E53F13C:
    movzx eax, byte ptr [rsp+5Fh]
    mov byte ptr [rsp+67h], al
    loc_7FFB0E53F145:
    movzx eax, byte ptr [rsp+67h]
    mov byte ptr [rsp+66h], al
    loc_7FFB0E53F14E:
    movzx eax, byte ptr [rsp+66h]
    mov byte ptr [rsp+0A5h], al
    test al, al
    jz loc_7FFB0E53F18F
    mov eax, dword ptr [dword_7FFB0FEECF18]
    lea ecx, [rax-417838ADh]
    xor ecx, 23CF4FCAh
    add eax, ecx
    add eax, -417838ADh
    mov edx, 5F297F80h
    sub edx, eax
    xor edx, ecx
    xor edx, -7644AC62h
    mov dword ptr [rsp+48h], edx
    jmp loc_7FFB0E53C500
    loc_7FFB0E53F18F:
    mov rax, qword ptr [rsp+0E0h]
    cmp byte ptr [rax], 3
    jnz loc_7FFB0E53F1D0
    mov eax, dword ptr [dword_7FFB0FEECEAC]
    mov ecx, -28B187DBh
    xor eax, ecx
    lea ecx, [rax+4FEE28DDh]
    mov edx, ecx
    xor edx, 515A3685h
    sub edx, eax
    sub edx, ecx
    add edx, 6E1D293Ch
    xor edx, -2B5209DBh
    mov dword ptr [rsp+48h], edx
    jmp loc_7FFB0E53C500
    loc_7FFB0E53F1D0:
    mov eax, dword ptr [dword_7FFB0FEECE90]
    mov ecx, eax
    xor ecx, -5ED7C17Eh
    lea edx, [rcx+3E4F4B8h]
    xor edx, 20B0389Eh
    lea r8d, [rdx-3478E765h]
    xor r8d, -1DFD0419h
    add r8d, ecx
    lea ecx, [rdx+r8]
    add ecx, -37959682h
    add edx, 4B8EF61Bh
    xor ecx, edx
    add ecx, eax
    xor ecx, -4BB41D0Ch
    jmp loc_7FFB0E53C4F0
    loc_7FFB0E53F21A:
    movzx eax, byte ptr [rsp+55h]
    jmp loc_7FFB0E53F902
    loc_7FFB0E53F224:
    mov rax, qword ptr [rsi+8]
    mov qword ptr [rsp+0D8h], rax
    movzx eax, byte ptr [rdi]
    mov byte ptr [rsp+55h], al
    and al, 1
    mov byte ptr [rsp+6Ch], al
    mov eax, dword ptr [dword_7FFB0FEECE5C]
    lea ecx, [rax+1900B9F8h]
    xor eax, ecx
    xor eax, -6ED9F6FDh
    sub eax, ecx
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53F25B:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rbx+105h]
    mov byte ptr [rsp+0A6h], al
    movzx eax, byte ptr [byte_7FFB0FEA4074]
    mov byte ptr [rsp+4Dh], al
    not al
    add al, al
    mov byte ptr [rsp+0A7h], al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rsp+4Dh]
    not al
    and al, 8Eh
    mov byte ptr [rsp+0A8h], al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rsp+4Dh]
    mov byte ptr [rsp+0AAh], al
    not al
    and al, 71h
    add al, al
    mov byte ptr [rsp+0A9h], al
    mov eax, dword ptr [dword_7FFB0FEECF2C]
    lea ecx, [rax-1C4654Ch]
    xor ecx, -3428A223h
    lea edx, [rcx-6144D760h]
    mov r8d, edx
    xor r8d, 7CC293C7h
    lea r9d, [r8-4CAEB3D2h]
    sub ecx, r9d
    add ecx, -2CF50A9Eh
    xor ecx, eax
    add eax, ecx
    add eax, -1C4654Ch
    sub eax, r9d
    add eax, r8d
    sub eax, edx
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53F3FB:
    cmp byte ptr [rsp+6Ch], 0
    jz loc_7FFB0E540436
    mov eax, dword ptr [dword_7FFB0FEECE6C]
    mov ecx, 5CB0EA89h
    sub ecx, eax
    xor eax, -1147F332h
    lea edx, [rax+15D0DD23h]
    xor ecx, edx
    xor edx, -3A3781FFh
    xor ecx, 4580C37Ch
    add ecx, eax
    add eax, ecx
    add eax, 15D0DD23h
    sub eax, edx
    add eax, -3DE8C7D0h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53F445:
    lea rax, [rdi+4]
    mov qword ptr [rsp+130h], rax
    lea rax, [rdi+8]
    mov qword ptr [rsp+138h], rax
    movzx eax, byte ptr [rdi+8]
    mov byte ptr [rsp+7Bh], al
    movzx eax, byte ptr [byte_7FFB0FEA4085]
    mov byte ptr [rsp+5Ah], al
    not al
    and al, 3Dh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    shl al, 2
    mov byte ptr [rsp+7Ch], al
    movzx eax, byte ptr [rsp+5Ah]
    mov ecx, eax
    or cl, 0BDh
    movzx ecx, cl
    lea ecx, [rcx+rcx*4]
    mov byte ptr [rsp+7Dh], cl
    and al, 42h
    mov byte ptr [rsp+7Eh], al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FEECECC]
    lea ecx, [rax+687B3E93h]
    xor ecx, 49A74776h
    lea edx, [rcx-482BDFA6h]
    mov r8d, edx
    xor r8d, -6878D260h
    mov r10d, 61278973h
    sub r10d, eax
    sub r10d, r8d
    xor r10d, ecx
    sub r10d, eax
    sub r10d, edx
    xor r10d, r8d
    mov dword ptr [rsp+48h], r10d
    jmp loc_7FFB0E53C500
    loc_7FFB0E53F571:
    mov eax, dword ptr [rsp+0FCh]
    sub eax, dword ptr [rsp+0F8h]
    add eax, dword ptr [rsp+0F4h]
    cmp dword ptr [rsp+0CCh], eax
    jle loc_7FFB0E540618
    mov eax, dword ptr [dword_7FFB0FEECE68]
    lea ecx, [rax-2AB483E9h]
    xor ecx, -29A8BFEBh
    add ecx, 292ADDC2h
    add eax, ecx
    add eax, 7FEBCA29h
    jmp loc_7FFB0E540293
    loc_7FFB0E53F5B7:
    movzx eax, byte ptr [rsp+89h]
    xor al, byte ptr [rsp+88h]
    xor al, byte ptr [rsp+84h]
    mov byte ptr [rsp+8Ah], al
    mov eax, 28F99E39h
    sub eax, dword ptr [dword_7FFB0FEECEE4]
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53F5E8:
    movzx eax, byte ptr [rsp+73h]
    add al, byte ptr [rsp+4Fh]
    sub al, byte ptr [rsp+71h]
    add al, byte ptr [rsp+56h]
    xor al, byte ptr [rsp+72h]
    mov byte ptr [rsp+74h], al
    mov eax, dword ptr [dword_7FFB0FEECE80]
    lea ecx, [rax-7D76E1FCh]
    xor ecx, 7DC2BB8Ah
    add ecx, eax
    add eax, ecx
    add eax, -51C3055Ah
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53F625:
    movzx eax, byte ptr [rsp+5Fh]
    mov byte ptr [rsp+66h], al
    mov eax, dword ptr [dword_7FFB0FEECE4C]
    lea ecx, [rax-36922B88h]
    lea edx, [rax-16F34248h]
    mov r8d, edx
    xor r8d, 7BBC1E1h
    lea r9d, [r8-5545A504h]
    xor r9d, -5A264780h
    sub r9d, edx
    xor edx, -36D092D0h
    add r9d, edx
    xor ecx, eax
    xor ecx, r9d
    lea eax, [r8+rcx]
    add eax, -2E5CCDFh
    xor eax, r8d
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53F67E:
    movzx eax, byte ptr [rsp+50h]
    mov ecx, eax
    not cl
    movzx edx, byte ptr [rsp+51h]
    and cl, dl
    movzx ecx, cl
    add ecx, ecx
    lea ecx, [rcx+rcx*2]
    and dl, al
    movzx eax, dl
    add eax, eax
    lea eax, [rax+rax*2]
    add al, cl
    add al, byte ptr [rsp+0A2h]
    sub al, byte ptr [rsp+0A1h]
    add al, byte ptr [rsp+0A0h]
    xor al, byte ptr [rsp+9Fh]
    movzx ecx, byte ptr [rsp+9Eh]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rsp+0E0h]
    movzx edx, byte ptr [rdx]
    mov byte ptr [rsp+52h], dl
    cmp cl, al
    jnz loc_7FFB0E540349
    movzx eax, byte ptr [rsp+52h]
    lea rcx, jpt_7FFB0E53F757
    movsxd rax, dword ptr (jpt_7FFB0E53F757 - 7FFB0FE4FABCh)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E53F759:
    movzx eax, byte ptr [rbx+101h]
    mov byte ptr [rsp+0B2h], al
    movzx eax, byte ptr [byte_7FFB0FEA406C]
    mov byte ptr [rsp+0B3h], al
    xor al, 18h
    mov byte ptr [rsp+0B4h], al
    add al, 0A1h
    mov byte ptr [rsp+0B5h], al
    mov ecx, eax
    xor cl, 37h
    mov byte ptr [rsp+53h], cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and al, 32h
    movzx eax, al
    lea ecx, [rax+rax*4]
    lea eax, [rax+rcx*4]
    mov byte ptr [rsp+0B6h], al
    movzx eax, byte ptr [rsp+53h]
    or al, 32h
    mov byte ptr [rsp+0B7h], al
    mov eax, dword ptr [dword_7FFB0FEECF58]
    lea ecx, [rax-3DA6B429h]
    mov edx, ecx
    xor edx, 23E52EF8h
    lea r8d, [rdx-69D6DD62h]
    mov r9d, -3B9F3826h
    sub r9d, edx
    xor r9d, r8d
    add edx, r9d
    add edx, -3A0BD1B5h
    xor edx, ecx
    add edx, eax
    mov dword ptr [rsp+48h], edx
    jmp loc_7FFB0E53C500
    loc_7FFB0E53F82D:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rsp+6Dh]
    cmp al, byte ptr [rsp+74h]
    jnz loc_7FFB0E540384
    movzx eax, byte ptr [rbx+8]
    mov rcx, qword ptr [rsp+118h]
    mov byte ptr [rcx], al
    lea rax, [rsp+18Fh]
    mov qword ptr [rsp+28h], rax
    mov qword ptr [rsp+20h], 47h
    mov ecx, 5Ah
    mov r8d, 3Ah
    mov rdx, rsi
    mov r9, rbx
    call sub_7FFB0F63EBA0
    mov dword ptr [rsp+114h], eax
    test eax, eax
    js loc_7FFB0E54054A
    movzx edx, byte ptr [rsp+18Fh]
    mov qword ptr [rsp+20h], 2
    mov r8d, 64h
    mov r9d, 5Ch
    mov rcx, rbx
    call sub_7FFB0F81DFA0
    movzx eax, byte ptr [rdi]
    loc_7FFB0E53F902:
    mov byte ptr [rsp+60h], al
    movzx eax, byte ptr [rsp+60h]
    mov byte ptr [rsp+57h], al
    movzx ecx, byte ptr [byte_7FFB0FEA4069]
    mov byte ptr [rsp+75h], cl
    xor cl, 4Dh
    mov byte ptr [rsp+76h], cl
    add cl, 0CCh
    mov byte ptr [rsp+58h], cl
    mov eax, ecx
    not al
    mov edx, ecx
    or dl, 0A3h
    xor cl, 5Ch
    movzx ecx, cl
    lea ecx, [rcx+rcx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx r8d, byte ptr [rsp+58h]
    mov r9d, r8d
    and r9b, 0A3h
    and r8b, 5Ch
    sub r8b, r9b
    add r8b, cl
    sub r8b, dl
    not dl
    shl dl, 2
    and al, 0A3h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8b, al
    sub r8b, dl
    mov byte ptr [rsp+77h], r8b
    not r8b
    and r8b, 9Ch
    mov byte ptr [rsp+0C3h], r8b
    mov eax, dword ptr [dword_7FFB0FEECE84]
    lea ecx, [rax+680E58FEh]
    lea edx, [rax+34BE5BA4h]
    xor edx, 61588CE8h
    lea r8d, [rdx+7D34B992h]
    xor r8d, 11E37034h
    lea r9d, [rax+72CE3CA0h]
    xor r9d, eax
    add r9d, edx
    add r9d, 7D34B992h
    add r9d, r8d
    sub r9d, edx
    sub r9d, eax
    add r9d, -5C71EA94h
    xor r9d, ecx
    mov dword ptr [rsp+48h], r9d
    jmp loc_7FFB0E53C500
    loc_7FFB0E53FAE1:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rsp+77h]
    add al, 19h
    xor al, byte ptr [rsp+75h]
    sub al, byte ptr [rsp+76h]
    xor al, byte ptr [rsp+58h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and al, byte ptr [rsp+57h]
    movzx ecx, byte ptr [byte_7FFB0FEA406A]
    lea edx, [rcx+2Dh]
    lea r8d, [rcx-50h]
    add cl, r8b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add cl, r8b
    mov r8b, 65h
    sub r8b, cl
    xor r8b, dl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp al, r8b
    jnz loc_7FFB0E5403B7
    mov eax, dword ptr [dword_7FFB0FEECF10]
    lea ecx, [rax+3C34AC33h]
    lea edx, [rax+15778F2h]
    xor edx, ecx
    xor ecx, 45226CFAh
    xor edx, -1B16C506h
    add edx, ecx
    add eax, edx
    add eax, -10C22E5Bh
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53FCF7:
    mov eax, dword ptr [dword_7FFB0FEECF14]
    lea ecx, [rax+2DE05337h]
    xor ecx, 24A9D633h
    lea edx, [rcx-36BDA02h]
    lea r8d, [rcx+rax]
    add r8d, 2A747935h
    mov r9d, 7F8BD0C3h
    sub r9d, r8d
    xor edx, eax
    xor edx, r9d
    sub edx, ecx
    mov dword ptr [rsp+48h], edx
    jmp loc_7FFB0E53C500
    loc_7FFB0E53FD33:
    movzx eax, byte ptr [rsp+0AFh]
    add al, 81h
    mov byte ptr [rsp+0B0h], al
    mov ecx, eax
    xor cl, 0A2h
    mov edx, eax
    xor dl, 51h
    and dl, 71h
    movzx edx, dl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9d, ecx
    mov r8d, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx r10d, byte ptr [rsp+0AEh]
    sub r10b, cl
    or cl, 71h
    movzx ecx, cl
    and r9b, 71h
    movzx r9d, r9b
    add edx, edx
    lea edx, [rdx+rdx*2]
    add ecx, ecx
    lea ecx, [rcx+rcx*2]
    xor al, 0ACh
    add r9d, r9d
    lea r9d, [r9+r9*2]
    and r8b, 0Eh
    movzx r8d, r8b
    add r8d, r8d
    lea r8d, [r8+r8*2]
    add r8b, r9b
    add r8b, al
    sub r8b, cl
    add r8b, dl
    lea eax, [r8-1Ah]
    add r10b, al
    add r8b, al
    add r8b, r10b
    add r8b, 0B6h
    mov byte ptr [rsp+0B1h], r8b
    mov eax, dword ptr [dword_7FFB0FEECF40]
    lea ecx, [rax-255DB142h]
    mov edx, ecx
    xor edx, 23216183h
    add edx, -8FFFD9h
    xor edx, -7B5CA60h
    add eax, edx
    add eax, -11EBBAF2h
    xor eax, ecx
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E53FEC5:
    movzx eax, byte ptr [rsp+4Fh]
    lea ecx, [rax+rax]
    mov edx, eax
    and dl, 0E8h
    movzx edx, dl
    lea edx, [rdx+rdx*2]
    and al, 17h
    movzx eax, al
    lea eax, [rax+rax*2]
    add al, dl
    sub al, cl
    add al, byte ptr [rsp+70h]
    sub al, byte ptr [rsp+6Fh]
    add al, byte ptr [rsp+6Eh]
    lea ecx, [rax+45h]
    mov byte ptr [rsp+56h], cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [rsp+56h]
    add cl, 0E2h
    mov byte ptr [rsp+71h], cl
    xor cl, 1Bh
    mov byte ptr [rsp+72h], cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov cl, 0Ah
    sub cl, al
    mov byte ptr [rsp+73h], cl
    mov eax, dword ptr [dword_7FFB0FEECE50]
    mov ecx, eax
    add ecx, -57CE2DF8h
    add ecx, eax
    add ecx, -57CE2DF8h
    add eax, ecx
    add eax, 2CDF4406h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E540007:
    mov byte ptr [rsp+4Eh], 1
    loc_7FFB0E54000C:
    movzx eax, byte ptr [rsp+4Eh]
    mov rcx, qword ptr [rsp+0D8h]
    mov byte ptr [rcx+14h], al
    movzx eax, byte ptr [rdi]
    loc_7FFB0E54001F:
    mov byte ptr [rsp+62h], al
    movzx eax, byte ptr [rsp+62h]
    mov byte ptr [rsp+7Ah], al
    and al, 2
    movzx ecx, byte ptr [byte_7FFB0FEA407D]
    lea r9d, [rcx+0Ch]
    mov edx, r9d
    xor dl, 0CDh
    xor r9b, 0Eh
    add r9b, 9
    mov bpl, 34h
    sub bpl, cl
    mov r10d, r9d
    not r10b
    movzx r11d, r10b
    lea r10d, [r11+r11*4]
    mov r8d, ebp
    or r8b, r11b
    not r8b
    movzx r8d, r8b
    lea r8d, [r8+r8*2]
    mov r13d, ebp
    or r13b, r9b
    not r13b
    movzx r13d, r13b
    lea r13d, [r13+r13*4+0]
    xor r9b, bpl
    add r9b, r9b
    and bpl, r11b
    shl bpl, 3
    sub bpl, r9b
    add bpl, r13b
    add bpl, r8b
    sub bpl, r10b
    add dl, cl
    add dl, bpl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp al, dl
    jz loc_7FFB0E53C4B1
    mov eax, dword ptr [dword_7FFB0FEECE74]
    add eax, r12d
    mov ecx, eax
    xor ecx, -5D8E2579h
    sub eax, ecx
    add eax, -241C5852h
    xor eax, ecx
    add eax, -33843001h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E540113:
    mov rax, qword ptr [rbx+20h]
    mov ecx, 80h
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
    mov qword ptr [rbx+20h], rax
    loc_7FFB0E540172:
    mov byte ptr [rsp+4Ch], 20h
    loc_7FFB0E540177:
    movzx eax, byte ptr [rsp+4Ch]
    mov qword ptr [rsp+28h], rsi
    mov byte ptr [rsp+20h], al
    mov edx, 17h
    mov r8d, 10h
    mov r9d, 15h
    mov rcx, rbx
    call sub_7FFB0F884630
    mov dword ptr [rsp+0CCh], eax
    mov eax, dword ptr [dword_7FFB0FEA4078]
    lea ecx, [rax+16016C87h]
    mov dword ptr [rsp+0ECh], ecx
    lea ecx, [rax-696C428h]
    mov dword ptr [rsp+0F0h], ecx
    add eax, 727BB651h
    mov dword ptr [rsp+0BCh], eax
    mov eax, dword ptr [dword_7FFB0FEECF00]
    mov ecx, eax
    xor ecx, 49D69DEBh
    lea edx, [rcx-364860D1h]
    lea r8d, [rcx+68F04A41h]
    mov r9d, r8d
    xor r9d, 64E13952h
    add r9d, -12F9D3B2h
    xor edx, 21078B83h
    sub edx, ecx
    xor edx, eax
    xor edx, r9d
    sub edx, ecx
    add edx, 2883259Fh
    xor edx, r8d
    sub edx, r9d
    add edx, 4FAA1BCCh
    mov dword ptr [rsp+48h], edx
    jmp loc_7FFB0E53C500
    loc_7FFB0E540227:
    mov eax, dword ptr [dword_7FFB0FEECF64]
    mov ecx, eax
    xor ecx, -5B909D7Dh
    lea edx, [rcx+443985B8h]
    xor edx, -2CF5F952h
    add edx, eax
    sub edx, ecx
    add edx, -6E3BFF77h
    mov dword ptr [rsp+48h], edx
    jmp loc_7FFB0E53C500
    loc_7FFB0E540254:
    mov eax, dword ptr [dword_7FFB0FEECEBC]
    lea ecx, [rax+44E07A1Bh]
    xor ecx, -51217624h
    lea edx, [rcx+13F4931Bh]
    lea r8d, [rcx+15B26668h]
    xor r8d, 15108D33h
    xor eax, 3DFEF8E3h
    sub eax, r8d
    xor eax, edx
    add eax, ecx
    add eax, 15B26668h
    add eax, r8d
    add eax, 3A765126h
    loc_7FFB0E540293:
    xor eax, ecx
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E54029E:
    mov eax, dword ptr [dword_7FFB0FEECF1C]
    lea ecx, [rax-1DC52310h]
    xor ecx, 1930B0Ch
    add ecx, -3217B60Eh
    mov edx, ecx
    xor edx, 3ADB181Fh
    sub edx, eax
    sub edx, ecx
    sub edx, eax
    add eax, edx
    add eax, -645415C6h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E5402D4:
    mov eax, dword ptr [dword_7FFB0FEECED0]
    lea ecx, [rax+26AAA0AAh]
    mov edx, ecx
    xor edx, 779DA6FBh
    lea r8d, [rdx+28A419D2h]
    mov r9d, edx
    sub r9d, eax
    sub r9d, ecx
    add r9d, edx
    lea eax, [rdx+r9]
    add eax, 5A9B0CEAh
    xor eax, r8d
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E540310:
    mov byte ptr [rsp+54h], 0
    mov eax, dword ptr [dword_7FFB0FEECE54]
    lea ecx, [rax-0B2B0806h]
    lea edx, [rax+83CD6F2h]
    xor ecx, 70A071B6h
    sub ecx, eax
    add eax, -72FD50B0h
    add ecx, 789353FCh
    xor ecx, eax
    add ecx, -6F903562h
    xor ecx, edx
    jmp loc_7FFB0E53C4F0
    loc_7FFB0E540349:
    cmp byte ptr [rsp+52h], 3
    jnz loc_7FFB0E54050D
    mov eax, dword ptr [dword_7FFB0FEECF54]
    lea ecx, [rax-7155FD65h]
    xor ecx, 359E9F46h
    mov edx, eax
    sub edx, ecx
    add edx, -5BC2E213h
    xor edx, ecx
    add edx, eax
    add eax, edx
    add eax, -7155FD65h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E540384:
    mov eax, dword ptr [dword_7FFB0FEECE88]
    mov ecx, 78E7DA1Dh
    xor eax, ecx
    lea ecx, [rax-1A0F25A9h]
    xor ecx, -386EE568h
    add ecx, eax
    add ecx, -1A0F25A9h
    mov edx, 3BC4316Fh
    sub edx, ecx
    loc_7FFB0E5403AC:
    xor edx, eax
    mov dword ptr [rsp+48h], edx
    jmp loc_7FFB0E53C500
    loc_7FFB0E5403B7:
    mov eax, dword ptr [dword_7FFB0FEECE8C]
    lea ecx, [rax-8675FCAh]
    lea edx, 565AA0AEh[rax*2]
    neg edx
    add edx, eax
    add edx, 565AA0AEh
    add edx, 517A848Fh
    xor edx, ecx
    mov ecx, eax
    add ecx, ecx
    add ecx, edx
    add eax, ecx
    add eax, 91A7554h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E5403F2:
    mov eax, dword ptr [dword_7FFB0FEECF08]
    lea ecx, [rax-513C1077h]
    lea edx, [rax-7FF3B652h]
    xor edx, -2C2FB24h
    lea r8d, [rdx-68AB4D4Dh]
    xor ecx, eax
    xor ecx, 2209EFD5h
    sub ecx, edx
    add ecx, eax
    sub ecx, r8d
    add ecx, -3CD32844h
    xor ecx, edx
    sub ecx, r8d
    add ecx, -20325EA5h
    jmp loc_7FFB0E53C4F0
    loc_7FFB0E540436:
    mov eax, dword ptr [dword_7FFB0FEECF6C]
    lea ecx, [rax+2C205C52h]
    xor ecx, 655BFA2Ch
    mov edx, -3F8AC6AAh
    sub edx, eax
    xor edx, ecx
    sub edx, ecx
    add edx, -43668DAFh
    mov dword ptr [rsp+48h], edx
    jmp loc_7FFB0E53C500
    loc_7FFB0E540462:
    movzx eax, byte ptr [byte_7FFB0FEA406D]
    mov byte ptr [rsp+0AEh], al
    xor al, 8Ah
    mov byte ptr [rsp+0AFh], al
    mov eax, dword ptr [dword_7FFB0FEECF3C]
    lea ecx, [rax+7E3A1A4Bh]
    xor ecx, -575336A0h
    add ecx, eax
    add ecx, 2F1A81B8h
    xor ecx, eax
    jmp loc_7FFB0E53C4F0
    loc_7FFB0E54049A:
    cmp eax, 2
    jnz loc_7FFB0E540655
    mov byte ptr [rsp+54h], 20h
    loc_7FFB0E5404A8:
    movzx eax, byte ptr [rsp+54h]
    mov byte ptr [rsp+5Fh], al
    cmp byte ptr [rsp+0A4h], 0
    jz loc_7FFB0E5404E5
    mov eax, dword ptr [dword_7FFB0FEECF28]
    mov ecx, -7088D6E9h
    add eax, ecx
    xor eax, 72E3C887h
    add eax, 6B10A55Dh
    xor eax, -2559322h
    add eax, 18C994B9h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E53C500
    loc_7FFB0E5404E5:
    mov eax, dword ptr [dword_7FFB0FEECEA4]
    lea ecx, [rax-195F5F69h]
    xor ecx, 1F66CEF2h
    mov edx, 31C9B0B4h
    sub edx, eax
    xor edx, ecx
    add ecx, 20877632h
    xor ecx, edx
    jmp loc_7FFB0E53C4F0
    loc_7FFB0E54050D:
    mov eax, dword ptr [dword_7FFB0FEECE58]
    lea ecx, [rax+43D7D08h]
    xor ecx, -3796DD81h
    lea edx, [rcx+43C0EE60h]
    lea r8d, [rax+rdx]
    add r8d, 59EDD06Dh
    xor r8d, ecx
    add r8d, eax
    sub r8d, edx
    add r8d, 2FF3E0FFh
    mov dword ptr [rsp+48h], r8d
    jmp loc_7FFB0E53C500
    loc_7FFB0E54054A:
    mov eax, dword ptr [dword_7FFB0FEECF68]
    mov ecx, eax
    xor ecx, 7E45B1D5h
    lea edx, [rcx+0B35AB77h]
    sub ecx, eax
    add ecx, -194B67D5h
    jmp loc_7FFB0E53E2B5
    loc_7FFB0E54056B:
    mov byte ptr [rsp+4Ch], 8
    jmp loc_7FFB0E540177
    loc_7FFB0E540575:
    cmp eax, 78AC9D2Dh
    jz loc_7FFB0E540623
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+114h]
    jmp loc_7FFB0E54061F
    loc_7FFB0E5405FC:
    mov dword ptr [rsp+68h], 100000h
    jmp loc_7FFB0E540623
    loc_7FFB0E540606:
    mov eax, dword ptr [rsp+0C4h]
    jmp loc_7FFB0E54061F
    loc_7FFB0E54060F:
    mov eax, dword ptr [rsp+0D0h]
    jmp loc_7FFB0E54061F
    loc_7FFB0E540618:
    mov eax, dword ptr [rsp+0CCh]
    loc_7FFB0E54061F:
    mov dword ptr [rsp+68h], eax
    loc_7FFB0E540623:
    mov eax, dword ptr [rsp+68h]
    mov rcx, qword ptr [rsp+190h]
    xor rcx, rsp
    cmp rcx, qword ptr [__security_cookie]
    jnz loc_7FFB0E54064F
    add rsp, 198h
    pop rbx
    pop rbp
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    ret
    loc_7FFB0E54064F:
    call __security_check_cookie
    int 3
    loc_7FFB0E540655:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    int 3
_TEXT ENDS
END

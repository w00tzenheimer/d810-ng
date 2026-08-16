; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: sub_7FF856629E30  @ 0x7ff856629e30
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN __security_check_cookie:PROC
EXTERN sub_7FF856A42160:PROC
EXTERN sub_7FF85703FF30:PROC

CONST SEGMENT
__security_cookie dq 9E26FE5431Dh
dword_7FF8571C8EC8 dd 0E95ADFFEh
dword_7FF8571C8ECC dd 19FBC22Eh
dword_7FF8571C8ED0 dd 0AC833A00h
qword_7FF8571C8ED8 dq 2FA1B2399AD0C762h
dword_7FF8571C8EE0 dd 0ED12C918h
dword_7FF8571C8EE4 dd 0EC139CFh
qword_7FF8571C8EE8 dq 7EBF917B10ACD83Dh
dword_7FF8571C8EF0 dd 56BB1DF9h
dword_7FF8571C8EF4 dd 0AB09653Ah
dword_7FF8571C8EF8 dd 0CD393FB1h
dword_7FF8571C8EFC dd 0BDE54F4Fh
dword_7FF8571C8F00 dd 2AAFBC94h
dword_7FF8571C8F04 dd 1F90175Eh
dword_7FF8571C8F08 dd 465B1F8Dh
dword_7FF8571C8F0C dd 4374905h
dword_7FF8571C8F10 dd 2FE27B19h
dword_7FF8571C8F14 dd 8C6E3BE6h
dword_7FF8571C8F18 dd 0DF1A185Fh
dword_7FF857232B18 dd 9497D68Fh
dword_7FF857232B1C dd 0C87F78DBh
dword_7FF857232B20 dd 0C0F52350h
dword_7FF857232B24 dd 0B9E94C30h
dword_7FF857232B28 dd 0AD4FA9B7h
dword_7FF857232B2C dd 1C977869h
dword_7FF857232B30 dd 0A7ED954Bh
dword_7FF857232B34 dd 74F5AC8Eh
dword_7FF857232B38 dd 108DD9D2h
dword_7FF857232B3C dd 91F8CAC2h
dword_7FF857232B40 dd 0F050584Bh
dword_7FF857232B44 dd 46B15A00h
dword_7FF857232B48 dd 271F36C5h
dword_7FF857232B4C dd 2AFD8D74h
dword_7FF857232B50 dd 51E658BAh
dword_7FF857232B54 dd 65462F78h
dword_7FF857232B58 dd 7DD21A7Bh
dword_7FF857232B5C dd 7F4394B4h
dword_7FF857232B60 dd 3E97272Dh
dword_7FF857232B64 dd 0B85942D7h
dword_7FF857232B68 dd 60307B45h
dword_7FF857232B6C dd 44403E52h
dword_7FF857232B70 dd 0DC21400Ah
dword_7FF857232B74 dd 0FF9AA8B0h
dword_7FF857232B78 dd 88A1BBCh
dword_7FF857232B7C dd 571CC1DAh
dword_7FF857232B80 dd 0C739C56Ch
dword_7FF857232B84 dd 14C77EC8h
dword_7FF857232B88 dd 8257A20Ch
dword_7FF857232B8C dd 0C98C47EEh
dword_7FF857232B90 dd 7D8B9BC2h
dword_7FF857232B94 dd 0A1EC1102h
dword_7FF857232B98 dd 3B1393BBh
dword_7FF857232B9C dd 27891779h
dword_7FF857232BA0 dd 0CC601009h
dword_7FF857232BA4 dd 64C69704h
dword_7FF857232BA8 dd 56FFCF44h
dword_7FF857232BAC dd 682C47A4h
dword_7FF857232BB0 dd 25DD2590h
dword_7FF857232BB4 dd 0DB5B17C7h
dword_7FF857232BB8 dd 86C51EAh
dword_7FF857232BBC dd 6093E272h
dword_7FF857232BC0 dd 0D4926B75h
dword_7FF857232BC4 dd 0A608AD20h
dword_7FF857232BC8 dd 0FEB7E884h
dword_7FF857232BCC dd 0D7E947D0h
dword_7FF857232BD0 dd 7785D0A7h
dword_7FF857232BD4 dd 19788063h
dword_7FF857232BD8 dd 0E040006Bh
dword_7FF857232BDC dd 4C9F1A87h
dword_7FF857232BE0 dd 0E166C4Bh
dword_7FF857232BE4 dd 80C511C6h
dword_7FF857232BE8 dd 0E092039h
dword_7FF857232BEC dd 9034B92Ch
dword_7FF857232BF0 dd 927B0F36h
dword_7FF857232BF4 dd 315467EBh
dword_7FF857232BF8 dd 11AC97B9h
dword_7FF857232BFC dd 0BF3CB741h
dword_7FF857232C00 dd 0E7CC8F1Dh
dword_7FF857232C04 dd 7464D1D7h
dword_7FF857232C08 dd 0D927000h
dword_7FF857232C0C dd 73D40Eh
dword_7FF857232C10 dd 0EDEFA367h
dword_7FF857232C14 dd 42C178C8h
dword_7FF857232C18 dd 62C43425h
xmmword_7FF857261690 db 0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC sub_7FF856629E30
sub_7FF856629E30:
    push r15
    push r14
    push r13
    push r12
    push rsi
    push rdi
    push rbp
    push rbx
    sub rsp, 298h
    mov rsi, r8
    mov rax, qword ptr [__security_cookie]
    xor rax, rsp
    mov qword ptr [rsp+290h], rax
    mov eax, dword ptr [dword_7FF857232B1C]
    lea ecx, 1C6AB2Eh[rax*2]
    lea edx, [rax+4FD3FEFAh]
    lea r8d, [rax+1C6AB2Eh]
    xor r8d, edx
    mov edx, -51E4E03Ah
    sub edx, ecx
    xor edx, r8d
    xor edx, eax
    mov dword ptr [rsp+38h], edx
    mov ebx, 1D41AD2h
    lea rdi, [rsp+280h]
    mov r13d, 30C218B4h
    jmp loc_7FF856629F84
    loc_7FF856629E9D:
    mov eax, dword ptr [rsp+5Ch]
    mov ecx, 4F113C34h
    add eax, ecx
    xor eax, -0A4BA65Fh
    mov dword ptr [rsp+124h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FF857232BB8]
    lea ecx, [rax-41D46B8Dh]
    xor ecx, -228F5253h
    lea edx, [rcx-20D93B0Ch]
    mov r8d, edx
    xor r8d, -4E9AB9A8h
    xor edx, 6E73C8AEh
    mov r9d, eax
    xor r9d, ecx
    xor r9d, -21A65F6Dh
    add r9d, edx
    sub r9d, r8d
    add eax, r9d
    add eax, -41D46B8Dh
    add eax, ecx
    add eax, -20D93B0Ch
    sub eax, edx
    add eax, 23BCB27Bh
    nop word ptr [rax+rax+00000000h]
    loc_7FF856629F80:
    mov dword ptr [rsp+38h], eax
    loc_7FF856629F84:
    mov eax, dword ptr [rsp+38h]
    cmp eax, 3F9A40A7h
    jg loc_7FF85662A020
    cmp eax, 1FC541DCh
    jle loc_7FF85662A160
    cmp eax, 2F16FA71h
    jg loc_7FF85662A275
    cmp eax, 25263000h
    jg loc_7FF85662A5AF
    cmp eax, 212E031Fh
    jg loc_7FF85662B04E
    cmp eax, 1FC541DDh
    jnz loc_7FF85662CD91
    mov eax, dword ptr [rsp+0D4h]
    mov dword ptr [rsp+0ACh], eax
    mov eax, dword ptr [dword_7FF857232B5C]
    lea ecx, [rax-45717182h]
    xor ecx, 665C996Ah
    lea edx, [rcx+rax]
    add edx, -4B121767h
    add eax, edx
    add eax, -45717182h
    add eax, ecx
    add eax, -4B121767h
    mov ecx, -3D6B048h
    sub ecx, eax
    mov dword ptr [rsp+38h], ecx
    jmp loc_7FF856629F84
    nop word ptr [rax+rax+00000000h]
    loc_7FF85662A020:
    cmp eax, 68CA0D88h
    jg loc_7FF85662A0C0
    cmp eax, 59ED170Fh
    jle loc_7FF85662A2E5
    cmp eax, 61E8F4E2h
    jg loc_7FF85662A40D
    cmp eax, 5B17C9DAh
    jg loc_7FF85662AC6A
    cmp eax, 59ED1710h
    jnz loc_7FF85662C037
    mov rax, qword ptr [rsp+0B8h]
    mov rcx, qword ptr [rsp+0C0h]
    xor rcx, rax
    lea rdx, [rcx*8]
    sub rdx, rcx
    mov qword ptr [rsp+270h], rdx
    not rax
    mov qword ptr [rsp+278h], rax
    mov eax, dword ptr [dword_7FF857232BE0]
    lea ecx, [rax-506A6F98h]
    mov edx, ecx
    xor edx, 4C8D2E18h
    add edx, edx
    mov r8d, 21ACD113h
    sub r8d, edx
    xor r8d, ecx
    add eax, r8d
    add eax, -343A96D9h
    jmp loc_7FF856629F80
    nop word ptr [rax+rax+00000000h]
    loc_7FF85662A0C0:
    cmp eax, 70EAFB63h
    jle loc_7FF85662A340
    cmp eax, 79B63D2Bh
    jg loc_7FF85662A4FD
    cmp eax, 76423282h
    jg loc_7FF85662AE84
    cmp eax, 70EAFB64h
    jnz loc_7FF85662C608
    mov eax, dword ptr [rsp+1E0h]
    xor eax, dword ptr [rsp+1DCh]
    add eax, dword ptr [rsp+1D4h]
    add eax, dword ptr [rsp+1D8h]
    mov dword ptr [rsp+0A4h], eax
    mov ecx, dword ptr [rsp+74h]
    not ecx
    or ecx, eax
    mov dword ptr [rsp+1E4h], ecx
    mov eax, dword ptr [dword_7FF857232BC8]
    mov ecx, eax
    xor ecx, 4564F690h
    mov edx, eax
    xor edx, 109E36FCh
    lea r8d, [rdx-2E246069h]
    xor eax, 94236A1h
    sub eax, r8d
    sub eax, ecx
    add eax, edx
    add eax, edx
    add eax, -3FFB95F1h
    jmp loc_7FF856629F80
    nop word ptr [rax+rax+00000000h]
    loc_7FF85662A160:
    cmp eax, 119B904Bh
    jle loc_7FF85662A3B9
    cmp eax, 1A1A51EFh
    jg loc_7FF85662A543
    cmp eax, 18756900h
    jg loc_7FF85662AF37
    cmp eax, 119B904Ch
    jnz loc_7FF85662C989
    imul eax, dword ptr [rsp+174h], 0F5h
    sub eax, dword ptr [rsp+170h]
    sub eax, dword ptr [rsp+168h]
    add eax, dword ptr [rsp+164h]
    sub eax, dword ptr [rsp+160h]
    mov dword ptr [rsp+68h], eax
    add eax, 6B46297Ah
    mov dword ptr [rsp+94h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+94h]
    lea ecx, [rax+4A0C4C11h]
    mov dword ptr [rsp+178h], ecx
    add eax, 73E6AF4Ah
    mov dword ptr [rsp+48h], eax
    not eax
    and eax, 1D41AD2h
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+17Ch], eax
    mov eax, dword ptr [dword_7FF857232BF0]
    lea ecx, [rax+995925Ah]
    lea edx, [rax-553ADA49h]
    xor edx, ecx
    add edx, eax
    add eax, edx
    add eax, 448206C0h
    jmp loc_7FF856629F80
    loc_7FF85662A275:
    cmp eax, 39ED22D9h
    jle loc_7FF85662A621
    cmp eax, 3E60D26Dh
    jle loc_7FF85662AA1E
    cmp eax, 3E8EB119h
    jz loc_7FF85662BB40
    cmp eax, 3F4E076Bh
    jnz loc_7FF85662D496
    mov eax, dword ptr [rsp+98h]
    mov ecx, 2B933398h
    add eax, ecx
    mov dword ptr [rsp+19Ch], eax
    mov eax, dword ptr [dword_7FF857232BAC]
    lea ecx, [rax-529263C1h]
    xor ecx, -2B93F04Eh
    neg ecx
    add ecx, eax
    add ecx, -60189BA0h
    xor ecx, eax
    sub ecx, eax
    add ecx, 44C05B00h
    mov dword ptr [rsp+38h], ecx
    jmp loc_7FF856629F84
    loc_7FF85662A2E5:
    cmp eax, 502071ECh
    jg loc_7FF85662A6AA
    cmp eax, 464CA564h
    jg loc_7FF85662B606
    cmp eax, 3F9A40A8h
    jnz loc_7FF85662CF7A
    mov eax, dword ptr [dword_7FF8571C8EF0]
    mov dword ptr [rsp+15Ch], eax
    xor eax, -4D1D2883h
    mov dword ptr [rsp+90h], eax
    mov eax, dword ptr [dword_7FF857232B68]
    lea ecx, [rax+2AB94DF4h]
    mov edx, 5F47414h
    sub edx, eax
    xor edx, ecx
    add eax, edx
    add eax, -2D71B858h
    jmp loc_7FF856629F80
    loc_7FF85662A340:
    cmp eax, 6FB0F9CDh
    jle loc_7FF85662A958
    cmp eax, 7035A19Eh
    jg loc_7FF85662AA6D
    cmp eax, 6FB0F9CEh
    jnz loc_7FF85662BC39
    mov rax, qword ptr [rsi]
    mov qword ptr [rsp+238h], rax
    mov eax, dword ptr [rax]
    mov dword ptr [rsp+4Ch], eax
    mov eax, dword ptr [dword_7FF857232B3C]
    mov ecx, eax
    xor ecx, 5F9F74E5h
    add ecx, 37C1FA76h
    mov edx, ecx
    xor edx, 79AC29Ah
    add edx, -6DF76A5Eh
    xor edx, -19EE16FAh
    lea r8d, 4141B986h[rdx*2]
    add edx, r8d
    add edx, 4141B986h
    sub edx, ecx
    add eax, edx
    add eax, -30CD8825h
    jmp loc_7FF856629F80
    loc_7FF85662A3B9:
    cmp eax, 0AC60B72h
    jle loc_7FF85662A9D3
    cmp eax, 0C02A652h
    jg loc_7FF85662ABF4
    cmp eax, 0AC60B73h
    jnz loc_7FF85662BF4E
    mov eax, dword ptr [dword_7FF857232B9C]
    lea ecx, [rax+4383E523h]
    lea edx, [rax-59F07F8Dh]
    xor edx, 62291A83h
    lea r8d, [rdx-1EAC8F5Bh]
    xor r8d, ecx
    add edx, eax
    add eax, edx
    add eax, -239DBAB9h
    xor eax, r8d
    jmp loc_7FF856629F80
    loc_7FF85662A40D:
    cmp eax, 65A0C7F0h
    jg loc_7FF85662AE39
    cmp eax, 61E8F4E3h
    jnz loc_7FF85662C0C6
    mov eax, dword ptr [rsp+90h]
    mov ecx, 128A1234h
    add eax, ecx
    mov dword ptr [rsp+64h], eax
    mov ecx, eax
    not ecx
    and ecx, -69F46329h
    lea edx, [rcx+rcx*4]
    lea ecx, [rcx+rdx*2]
    mov dword ptr [rsp+160h], ecx
    mov ecx, eax
    or ecx, -69F46329h
    lea edx, [rcx+rcx*4]
    lea ecx, [rcx+rdx*2]
    mov dword ptr [rsp+164h], ecx
    xor eax, -69F46329h
    mov dword ptr [rsp+168h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+64h]
    mov ecx, 69F46328h
    and eax, ecx
    mov dword ptr [rsp+16Ch], eax
    mov eax, dword ptr [dword_7FF857232B74]
    mov ecx, eax
    xor ecx, 548F6E98h
    lea edx, [rcx-7E4CB780h]
    mov r8d, edx
    xor r8d, 2A65445Ah
    add r8d, -3572D346h
    xor r8d, edx
    sub r8d, ecx
    add r8d, eax
    mov dword ptr [rsp+38h], r8d
    jmp loc_7FF856629F84
    loc_7FF85662A4FD:
    cmp eax, 7CB1E440h
    jg loc_7FF85662AF20
    cmp eax, 79B63D2Ch
    jnz loc_7FF85662C676
    mov eax, dword ptr [dword_7FF857232B94]
    lea ecx, [rax-26F8872Bh]
    lea edx, [rax-76B2687Fh]
    xor edx, 3D369F30h
    sub edx, eax
    add edx, -4B11E066h
    xor edx, ecx
    add edx, eax
    add eax, edx
    add eax, -76B2687Fh
    jmp loc_7FF856629F80
    loc_7FF85662A543:
    cmp eax, 1DEF7386h
    jg loc_7FF85662AFDA
    cmp eax, 1A1A51F0h
    jz loc_7FF85662B546
    cmp byte ptr [rsp+3Fh], 1
    jnz loc_7FF85662D31F
    mov rax, qword ptr [rsp+200h]
    add rax, qword ptr [rsp+230h]
    cmp rax, qword ptr [rsp+210h]
    jbe loc_7FF85662D31F
    mov eax, dword ptr [dword_7FF857232BD8]
    lea ecx, [rax+1B2CEB7Fh]
    lea edx, [rax+2231DE8Dh]
    xor edx, -29AA5F10h
    neg edx
    add eax, edx
    add eax, 1B2CEB7Fh
    sub eax, ecx
    add eax, 683ABEBh
    jmp loc_7FF856629F80
    loc_7FF85662A5AF:
    cmp eax, 29297409h
    jg loc_7FF85662B0BF
    cmp eax, 25263001h
    jnz loc_7FF85662CE74
    mov eax, dword ptr [rsp+70h]
    or eax, dword ptr [rsp+1A0h]
    not eax
    mov dword ptr [rsp+1A4h], eax
    mov eax, dword ptr [dword_7FF857232B20]
    lea ecx, [rax+20E5E7A1h]
    lea edx, [rax-39F5F372h]
    mov r8d, edx
    xor r8d, 0E4DC54Fh
    lea r9d, [r8+6E8F14E5h]
    xor r9d, -6438AE19h
    add r9d, r9d
    add eax, r9d
    add eax, -0E55A065h
    xor r8d, ecx
    xor r8d, edx
    xor r8d, eax
    mov dword ptr [rsp+38h], r8d
    jmp loc_7FF856629F84
    loc_7FF85662A621:
    cmp eax, 34225373h
    jle loc_7FF85662B631
    cmp eax, 34225374h
    jz loc_7FF856629E9D
    cmp eax, 342988C0h
    jnz loc_7FF85662D4D7
    mov rax, qword ptr [rsp+260h]
    lea rax, [rax+rax*2]
    mov qword ptr [rsp+268h], rax
    mov eax, dword ptr [dword_7FF857232BDC]
    lea ecx, [rax+117411ACh]
    xor ecx, -69CBC995h
    lea edx, [rcx+57929696h]
    lea r8d, [rcx-7CF7626Fh]
    xor r8d, -4F65E76Fh
    lea r9d, [r8-0B3E14h]
    xor r9d, edx
    xor r9d, -31577870h
    sub r9d, ecx
    xor r8d, eax
    xor r8d, r9d
    add eax, r8d
    add eax, 117411ACh
    sub eax, ecx
    add eax, -11BD9908h
    jmp loc_7FF856629F80
    loc_7FF85662A6AA:
    cmp eax, 54FCEDDFh
    jle loc_7FF85662B705
    cmp eax, 54FCEDE0h
    jnz loc_7FF85662C912
    mov eax, dword ptr [rsp+54h]
    mov ecx, -621A9328h
    and eax, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add eax, dword ptr [rsp+114h]
    sub eax, dword ptr [rsp+110h]
    mov edx, dword ptr [rsp+10Ch]
    lea ecx, [rax+rdx]
    add ecx, 621A9328h
    lea r8d, [rax+rdx+7007C2E4h]
    mov edx, r8d
    mov r9d, r8d
    mov eax, dword ptr [rsp+54h]
    sub eax, r8d
    not r8d
    mov r10d, r8d
    and r10d, 6847BBFEh
    lea r10d, [r10+r10*8]
    add r10d, r8d
    and r8d, 17B84401h
    lea r8d, [r8+r8*4]
    and edx, -6847BBFFh
    and r9d, 6847BBFEh
    lea r11d, [r9+r9*4]
    lea r9d, [r9+r11*2]
    add r9d, edx
    not edx
    lea r11d, [rdx+rdx*4]
    lea edx, [rdx+r11*2]
    sub r9d, edx
    lea edx, [r9+r8*2]
    add r10d, edx
    sub eax, r10d
    add eax, 296B56E7h
    xor eax, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor eax, dword ptr [rsp+88h]
    xor eax, dword ptr [rsp+108h]
    mov ecx, dword ptr [rsp+44h]
    mov edx, ecx
    not edx
    mov r8d, eax
    or r8d, edx
    not r8d
    lea r8d, [r8+r8*2]
    or ecx, eax
    not ecx
    add ecx, ecx
    and edx, eax
    not edx
    add edx, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9d, dword ptr [rsp+44h]
    and r9d, eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not r9d
    mov r10d, dword ptr [rsp+44h]
    mov r11d, r10d
    not r11d
    and r11d, eax
    lea r11d, [r11+r11*2]
    and eax, r10d
    add eax, eax
    sub eax, r11d
    lea eax, [rax+r9*4]
    sub eax, edx
    sub eax, ecx
    sub eax, r8d
    mov dword ptr [rsp+118h], eax
    mov eax, dword ptr [dword_7FF857232B34]
    lea ecx, [rax-4059C3A1h]
    add ecx, eax
    add ecx, -4059C3A1h
    add ecx, eax
    mov eax, 0F1E0CEBh
    sub eax, ecx
    jmp loc_7FF856629F80
    loc_7FF85662A958:
    cmp eax, 68CA0D89h
    jz loc_7FF85662B753
    cmp eax, 6CD333EAh
    jnz loc_7FF85662BBE1
    mov eax, dword ptr [rsp+1B0h]
    sub eax, dword ptr [rsp+1ACh]
    add eax, dword ptr [rsp+1A8h]
    mov edx, dword ptr [rsp+198h]
    mov dword ptr [rsp+28h], eax
    mov qword ptr [rsp+20h], 28h
    mov r8d, 35h
    mov r9d, 16h
    mov rcx, rsi
    call sub_7FF85703FF30
    mov eax, dword ptr [dword_7FF857232C08]
    mov ecx, 21CCF901h
    xor eax, ecx
    lea ecx, [rax-79F6B648h]
    xor ecx, -6F039E61h
    neg ecx
    add ecx, eax
    add ecx, 223CD42h
    jmp loc_7FF85662D262
    loc_7FF85662A9D3:
    cmp eax, 13FA9E5h
    jz loc_7FF85662B847
    cmp eax, 595F423h
    jnz loc_7FF85662BEE6
    mov eax, dword ptr [dword_7FF857232BD4]
    lea ecx, [rax+546E1770h]
    lea edx, [rax-213BF7BDh]
    mov r8d, edx
    xor r8d, 48B14FC7h
    add r8d, 18C2B7F9h
    xor ecx, eax
    sub eax, r8d
    add eax, -6191E8BEh
    xor eax, r8d
    jmp loc_7FF85662C030
    loc_7FF85662AA1E:
    cmp eax, 39ED22DAh
    jnz loc_7FF85662B897
    mov eax, dword ptr [dword_7FF857232B8C]
    mov ecx, 25FA9088h
    xor eax, ecx
    lea ecx, [rax-2F5E8622h]
    lea edx, [rax+rcx]
    add edx, -6644FB96h
    mov r8d, -7C81E951h
    sub r8d, edx
    xor r8d, ecx
    xor r8d, 4145FFE3h
    lea ecx, [r8+rax]
    add ecx, -6644FB96h
    add ecx, eax
    mov dword ptr [rsp+38h], ecx
    jmp loc_7FF856629F84
    loc_7FF85662AA6D:
    cmp eax, 7035A19Fh
    jnz loc_7FF85662BCD4
    mov eax, dword ptr [dword_7FF8571C8EC8]
    mov ecx, eax
    xor ecx, -6C6C1E5h
    mov dword ptr [rsp+1B4h], ecx
    lea edx, [rcx-3C454C80h]
    mov dword ptr [rsp+1B8h], edx
    add ecx, 4B43BA4h
    xor ecx, -479E9CBh
    mov dword ptr [rsp+1BCh], ecx
    add ecx, -420F1486h
    mov dword ptr [rsp+9Ch], ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [rsp+9Ch]
    mov edx, 63A3F847h
    xor ecx, edx
    mov dword ptr [rsp+1C0h], ecx
    add ecx, 14CEA78Eh
    mov dword ptr [rsp+0A0h], ecx
    xor eax, 2FDDCE2Eh
    mov dword ptr [rsp+1C4h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FF857232B44]
    lea ecx, [rax-77297B8Bh]
    lea edx, [rax-63A4D836h]
    mov r8d, edx
    xor r8d, 0BBF43DFh
    xor ecx, edx
    xor edx, -19110FAh
    add edx, r8d
    add edx, -6D3AA85Ch
    add eax, eax
    add eax, edx
    add r8d, -6D3AA85Ch
    add eax, r8d
    add eax, -6097BF1Fh
    xor eax, ecx
    jmp loc_7FF856629F80
    loc_7FF85662ABF4:
    cmp eax, 0C02A653h
    jnz loc_7FF85662BFF4
    mov eax, dword ptr [rsp+188h]
    lea ecx, [rax+73E584DBh]
    mov dword ptr [rsp+18Ch], ecx
    lea ecx, [rax-4EA245F6h]
    mov dword ptr [rsp+190h], ecx
    mov ecx, -40243606h
    sub ecx, eax
    mov dword ptr [rsp+194h], ecx
    mov eax, dword ptr [dword_7FF857232BF8]
    lea ecx, [rax+1431D7D3h]
    xor ecx, -0A5A2EE8h
    lea edx, [rcx-6602B266h]
    mov r8d, edx
    xor r8d, -0FAD241Bh
    add r8d, -668C7EC3h
    xor r8d, eax
    sub r8d, ecx
    add eax, r8d
    add eax, 1431D7D3h
    jmp loc_7FF85662B840
    loc_7FF85662AC6A:
    cmp eax, 5B17C9DBh
    jnz loc_7FF85662C24E
    mov eax, dword ptr [rsp+60h]
    not eax
    and eax, 5DF1BF49h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov ecx, dword ptr [rsp+60h]
    mov edx, ecx
    not edx
    and edx, -5DF1BF4Ah
    lea edx, [rdx+rdx*4]
    mov r8d, ecx
    xor r8d, 5DF1BF49h
    add r8d, r8d
    and ecx, 20E40B6h
    shl ecx, 3
    sub ecx, r8d
    add ecx, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add eax, -29677152h
    xor eax, dword ptr [rsp+154h]
    xor eax, 484668F2h
    sub eax, dword ptr [rsp+158h]
    xor eax, dword ptr [rsp+150h]
    sub eax, dword ptr [rsp+60h]
    mov edx, dword ptr [rsp+14Ch]
    mov dword ptr [rsp+28h], eax
    mov qword ptr [rsp+20h], 12h
    mov r8d, 62h
    mov r9d, 62h
    mov rcx, rsi
    call sub_7FF85703FF30
    mov rax, qword ptr [rsi]
    mov eax, dword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jmp loc_7FF85662AE93
    loc_7FF85662AE39:
    cmp eax, 65A0C7F1h
    jnz loc_7FF85662C422
    mov eax, dword ptr [rsp+0E8h]
    add eax, dword ptr [rsp+0DCh]
    cmp dword ptr [rsp+80h], eax
    jnz loc_7FF85662D2AB
    mov eax, dword ptr [dword_7FF857232BB0]
    lea ecx, [rax-54CF3929h]
    mov edx, -2FE9F821h
    sub edx, eax
    add eax, -110428E3h
    xor edx, ecx
    xor edx, eax
    mov dword ptr [rsp+38h], edx
    jmp loc_7FF856629F84
    loc_7FF85662AE84:
    cmp eax, 76423283h
    jz loc_7FF85662C06D
    mov eax, dword ptr [rsp+7Ch]
    loc_7FF85662AE93:
    mov dword ptr [rsp+0B0h], eax
    mov eax, dword ptr [rsp+0B0h]
    mov dword ptr [rsp+80h], eax
    mov eax, dword ptr [dword_7FF8571C8F04]
    mov dword ptr [rsp+0D8h], eax
    lea ecx, [rax+17C00C8Ch]
    mov dword ptr [rsp+0DCh], ecx
    lea ecx, [rax+48EFC4E4h]
    mov dword ptr [rsp+0E0h], ecx
    add eax, -44034945h
    mov dword ptr [rsp+0E4h], eax
    mov eax, dword ptr [dword_7FF857232B6C]
    lea ecx, [rax+67F5BDF4h]
    mov edx, ecx
    xor edx, 6DF96695h
    mov r8d, ecx
    xor r8d, 71C06E80h
    lea r9d, [r8+r8]
    sub r9d, edx
    lea edx, [r8+7E90089h]
    add r9d, 65E0B815h
    xor r9d, edx
    lea edx, [r8+r9]
    add edx, -76C4299Bh
    jmp loc_7FF85662B624
    loc_7FF85662AF20:
    cmp eax, 7CB1E441h
    jnz loc_7FF85662C794
    mov eax, dword ptr [rsp+80h]
    jmp loc_7FF85662D0BE
    loc_7FF85662AF37:
    cmp eax, 18756901h
    jnz loc_7FF85662C9DB
    mov eax, dword ptr [rsp+1E4h]
    not eax
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+1E8h], eax
    mov ecx, dword ptr [rsp+74h]
    mov eax, dword ptr [rsp+0A4h]
    mov edx, eax
    or edx, ecx
    not edx
    add edx, edx
    mov dword ptr [rsp+1ECh], edx
    mov edx, ecx
    not edx
    and edx, eax
    mov dword ptr [rsp+1F8h], edx
    not edx
    add edx, edx
    mov dword ptr [rsp+1F0h], edx
    and eax, ecx
    not eax
    shl eax, 2
    mov dword ptr [rsp+1F4h], eax
    mov eax, dword ptr [dword_7FF857232B58]
    lea ecx, [rax-5D218F93h]
    lea edx, [rax+4579D29Eh]
    xor edx, -62D4E12Ch
    xor ecx, -125A0714h
    sub ecx, eax
    add ecx, eax
    add ecx, 611FA1FEh
    xor ecx, edx
    xor ecx, -70E6BC5Bh
    sub ecx, eax
    sub ecx, eax
    sub ecx, edx
    add ecx, -5EFAD642h
    mov dword ptr [rsp+38h], ecx
    jmp loc_7FF856629F84
    loc_7FF85662AFDA:
    cmp eax, 1DEF7387h
    jnz loc_7FF85662CB01
    mov eax, dword ptr [rsp+194h]
    xor eax, dword ptr [rsp+18Ch]
    xor eax, dword ptr [rsp+190h]
    sub eax, dword ptr [rsp+184h]
    mov dword ptr [rsp+198h], eax
    mov eax, dword ptr [dword_7FF8571C8EE4]
    mov dword ptr [rsp+6Ch], eax
    add eax, -6B78A151h
    mov dword ptr [rsp+98h], eax
    mov eax, dword ptr [dword_7FF857232B60]
    lea ecx, [rax-8CFCF5Ah]
    mov edx, ecx
    xor edx, -5E12EF6Fh
    xor ecx, -7AE6EED5h
    add ecx, -6512F77Dh
    xor ecx, eax
    add eax, ecx
    add eax, -8CFCF5Ah
    add eax, edx
    jmp loc_7FF856629F80
    loc_7FF85662B04E:
    cmp eax, 212E0320h
    jnz loc_7FF85662CEE8
    mov eax, dword ptr [rsp+98h]
    mov ecx, 1CD1FBCFh
    add eax, ecx
    mov dword ptr [rsp+70h], eax
    mov eax, dword ptr [rsp+6Ch]
    not eax
    mov dword ptr [rsp+1A0h], eax
    mov eax, dword ptr [dword_7FF857232C00]
    lea ecx, [rax+7D89918Ch]
    lea edx, [rax-3DF56308h]
    xor edx, -45946DD3h
    lea r8d, 3F942E84h[rax*2]
    sub r8d, edx
    sub r8d, eax
    sub r8d, ecx
    add r8d, -2FDC5099h
    xor r8d, eax
    sub r8d, edx
    add r8d, -60DA1301h
    mov dword ptr [rsp+38h], r8d
    jmp loc_7FF856629F84
    loc_7FF85662B0BF:
    cmp eax, 2929740Ah
    jnz loc_7FF85662CF45
    mov ecx, dword ptr [rsp+180h]
    not ecx
    add ecx, ecx
    mov edx, dword ptr [rsp+48h]
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
    add edx, edx
    or edx, 3A835A4h
    mov eax, dword ptr [rsp+48h]
    mov r8d, eax
    not r8d
    shl r8d, 2
    or r8d, -7506B4Ch
    and eax, -1D41AD3h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r9d, [rax+rax*2]
    mov eax, dword ptr [rsp+48h]
    and eax, ebx
    add eax, eax
    sub eax, r9d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add eax, r8d
    sub eax, edx
    sub eax, ecx
    sub eax, dword ptr [rsp+17Ch]
    mov r8d, dword ptr [rsp+64h]
    mov ecx, -646CD1D9h
    xor r8d, ecx
    add r8d, dword ptr [rsp+178h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8d, dword ptr [rsp+94h]
    mov edx, dword ptr [rsp+68h]
    mov ecx, edx
    not ecx
    or ecx, r8d
    not ecx
    or edx, r8d
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
    shl edx, 2
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9d, dword ptr [rsp+68h]
    xor r9d, r8d
    not r9d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r10d, dword ptr [rsp+68h]
    mov r11d, r8d
    xor r11d, r10d
    lea ebp, [r11*8]
    mov r14d, r10d
    not r14d
    and r14d, r8d
    shl r14d, 3
    and r8d, r10d
    add r8d, r8d
    sub r14d, r8d
    sub r11d, ebp
    add r11d, r14d
    lea r8d, [r11+r9*4]
    sub r8d, edx
    lea ecx, [r8+rcx*8]
    mov r8d, eax
    not r8d
    mov r9d, ecx
    or r9d, r8d
    not r9d
    shl r9d, 2
    lea r10d, [rax+rax]
    mov edx, ecx
    or edx, eax
    lea edx, [rdx+rdx*4]
    and r8d, ecx
    and eax, ecx
    lea eax, [rax+rax*2]
    lea eax, [rax+r8*4]
    sub edx, eax
    sub edx, r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub edx, r9d
    add edx, dword ptr [rsp+90h]
    xor edx, dword ptr [rsp+15Ch]
    mov eax, dword ptr [dword_7FF8571C8EF4]
    lea ecx, [rax-47421372h]
    xor ecx, -6060DA72h
    lea r8d, [rcx+50CFCDC0h]
    xor r8d, 74BBFh
    add r8d, r8d
    add r8d, ecx
    add ecx, r8d
    add ecx, 50CFCDC0h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    neg ecx
    add eax, ecx
    add eax, 38D5668Fh
    mov dword ptr [rsp+28h], eax
    mov qword ptr [rsp+20h], 6
    mov r8d, 57h
    mov r9d, 3Bh
    mov rcx, rsi
    call sub_7FF85703FF30
    mov rax, qword ptr [rsi]
    mov eax, dword ptr [rax]
    mov dword ptr [rsp+0ACh], eax
    loc_7FF85662B546:
    mov eax, dword ptr [rsp+0ACh]
    mov dword ptr [rsp+7Ch], eax
    mov eax, dword ptr [dword_7FF8571C8EF8]
    mov ecx, -3EE130B7h
    sub ecx, eax
    xor ecx, eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub ecx, eax
    add ecx, 0E5C8F89h
    cmp dword ptr [rsp+7Ch], ecx
    jnz loc_7FF85662CD62
    mov eax, dword ptr [dword_7FF857232BCC]
    mov ecx, eax
    xor ecx, 55A9F5B8h
    lea edx, [rcx-10827B59h]
    xor edx, 695DAA6Eh
    sub edx, eax
    lea eax, [rdx+rcx]
    add eax, 55A3AF05h
    jmp loc_7FF856629F80
    loc_7FF85662B606:
    cmp eax, 464CA565h
    jnz loc_7FF85662D126
    mov eax, dword ptr [dword_7FF857232C14]
    lea ecx, [rax+47A786DCh]
    mov edx, 3987DCCEh
    sub edx, eax
    loc_7FF85662B624:
    xor edx, ecx
    sub edx, eax
    mov dword ptr [rsp+38h], edx
    jmp loc_7FF856629F84
    loc_7FF85662B631:
    cmp eax, 2F16FA72h
    jnz loc_7FF85662D373
    mov eax, dword ptr [rsp+1F8h]
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
    nop
    nop
    mov ecx, dword ptr [rsp+0A4h]
    and ecx, dword ptr [rsp+74h]
    add ecx, ecx
    sub ecx, eax
    add ecx, dword ptr [rsp+1F4h]
    sub ecx, dword ptr [rsp+1F0h]
    sub ecx, dword ptr [rsp+1ECh]
    sub ecx, dword ptr [rsp+1E8h]
    mov dword ptr [rsp+1FCh], ecx
    mov eax, dword ptr [dword_7FF857232B7C]
    mov ecx, -1046588Bh
    sub ecx, eax
    xor eax, -2A330E7Bh
    xor ecx, eax
    add eax, -38638C36h
    xor eax, ecx
    jmp loc_7FF856629F80
    loc_7FF85662B705:
    cmp eax, 52755B8Ch
    jnz loc_7FF85662D4A0
    mov eax, dword ptr [rsp+16Ch]
    lea eax, [rax+rax*8]
    mov dword ptr [rsp+170h], eax
    mov eax, dword ptr [rsp+64h]
    mov ecx, -69F46329h
    and eax, ecx
    mov dword ptr [rsp+174h], eax
    mov eax, dword ptr [dword_7FF857232BEC]
    mov ecx, -1BD8B8ADh
    sub ecx, eax
    xor ecx, 21105033h
    add ecx, eax
    add ecx, 7E979220h
    jmp loc_7FF85662D262
    loc_7FF85662B753:
    mov eax, dword ptr [rsp+124h]
    add eax, dword ptr [rsp+11Ch]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub eax, dword ptr [rsp+120h]
    mov dword ptr [rsp+8Ch], eax
    mov ecx, dword ptr [rsp+58h]
    mov edx, ecx
    not edx
    or edx, eax
    not edx
    shl edx, 2
    mov dword ptr [rsp+128h], edx
    or eax, ecx
    not eax
    mov dword ptr [rsp+12Ch], eax
    mov eax, dword ptr [dword_7FF857232BC0]
    lea ecx, [rax-36FBABD5h]
    lea edx, [rax+5F6F93F3h]
    lea r8d, [rax-77BD3E32h]
    xor r8d, 5466B7B4h
    mov r9d, eax
    xor r9d, 7032A116h
    sub r9d, r8d
    xor r9d, ecx
    add eax, r9d
    add eax, -77BD3E32h
    loc_7FF85662B840:
    xor eax, edx
    jmp loc_7FF856629F80
    loc_7FF85662B847:
    mov rax, qword ptr [xmmword_7FF857261690]
    test rax, rax
    jz loc_7FF85662D342
    mov qword ptr [rsp+220h], rax
    mov eax, dword ptr [dword_7FF857232B24]
    mov ecx, eax
    xor ecx, 748480CBh
    mov edx, eax
    xor edx, 5532963Dh
    xor eax, -12AD98ADh
    add eax, ecx
    add eax, edx
    add eax, -1D964F26h
    mov ecx, edx
    add ecx, -1D964F26h
    xor eax, ecx
    xor eax, 48693B21h
    jmp loc_7FF856629F80
    loc_7FF85662B897:
    mov edx, dword ptr [rsp+84h]
    lea r8d, [rdx+41ACB720h]
    lea r9d, [rdx-52613499h]
    add edx, -19D2D196h
    mov eax, edx
    mov ecx, edx
    xor ecx, 1CA84CEDh
    lea r10d, [rcx-3F298E67h]
    xor r9d, -2A205530h
    mov r11d, r10d
    not r11d
    mov r14d, r9d
    or r14d, r11d
    lea ebp, [r14+r14*4]
    lea ebp, [r14+rbp*2]
    not r14d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r15d, [r14*8]
    sub r15d, r14d
    mov r14d, r9d
    or r14d, r10d
    not r14d
    mov r12d, r14d
    shl r12d, 4
    add r12d, r14d
    add r12d, r15d
    and r11d, r9d
    lea r14d, [r11+r11*2]
    not r11d
    add r11d, r11d
    lea r11d, [r11+r11*2]
    and r9d, r10d
    lea r10d, [r9+r9*8]
    lea r9d, [r9+r10*2]
    lea r9d, [r9+r14*4]
    sub r9d, ebp
    sub r9d, r11d
    add r9d, r12d
    xor r9d, r8d
    xor edx, -1CA84CEEh
    mov r10d, r9d
    or r10d, edx
    mov r8d, r9d
    mov r11d, r9d
    xor r11d, ecx
    lea r11d, [r11+r11*2]
    and edx, r9d
    and r9d, ecx
    sub r9d, edx
    add r9d, r11d
    sub r9d, r10d
    not r10d
    shl r10d, 2
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or r8d, ecx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9d, r8d
    sub r9d, r10d
    add r9d, dword ptr [rsp+84h]
    xor eax, 1182AF00h
    sub r9d, eax
    cmp dword ptr [rsp+0ECh], r9d
    jnz loc_7FF85662D193
    mov eax, dword ptr [dword_7FF857232B80]
    lea ecx, [rax+33DB5C65h]
    xor ecx, 38847628h
    lea edx, [rcx-2A1EE5B5h]
    add eax, 144EE4BDh
    jmp loc_7FF85662C5FB
    loc_7FF85662BB40:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp dword ptr [rsp+4Ch], -7FFFFFFCh
    jnz loc_7FF85662D26D
    mov eax, dword ptr [dword_7FF857232C0C]
    lea ecx, [rax-32989A9Bh]
    lea edx, [rax-59212387h]
    xor ecx, edx
    xor edx, 3704C0FEh
    add edx, 4B3DF389h
    xor edx, -78BE744Ah
    add eax, edx
    add eax, 77CE5E42h
    xor eax, ecx
    add eax, -4F5C0A51h
    jmp loc_7FF856629F80
    loc_7FF85662BBE1:
    mov eax, dword ptr [rsp+1C4h]
    sub eax, dword ptr [rsp+1B4h]
    sub eax, dword ptr [rsp+9Ch]
    xor eax, dword ptr [rsp+1BCh]
    mov dword ptr [rsp+1C8h], eax
    mov eax, dword ptr [rsp+0A0h]
    not eax
    mov dword ptr [rsp+1CCh], eax
    mov eax, dword ptr [dword_7FF857232BFC]
    lea ecx, [rax+23789745h]
    lea edx, [rax+1FD275D4h]
    xor edx, ecx
    xor edx, eax
    xor edx, -1B0C1901h
    mov dword ptr [rsp+38h], edx
    jmp loc_7FF856629F84
    loc_7FF85662BC39:
    mov eax, dword ptr [dword_7FF8571C8F08]
    mov dword ptr [rsp+11Ch], eax
    lea ecx, [rax-18F61570h]
    mov dword ptr [rsp+120h], ecx
    lea ecx, [rax-7231AC91h]
    mov dword ptr [rsp+58h], ecx
    add eax, 26800CD0h
    mov dword ptr [rsp+5Ch], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FF857232BB4]
    lea ecx, [rax-53E81F3Fh]
    xor ecx, 1300FB4Fh
    lea edx, [rcx+4EF4BB51h]
    xor edx, ecx
    add edx, eax
    add edx, -53E81F3Fh
    add edx, eax
    lea eax, [rcx+rdx]
    add eax, -3A327D81h
    jmp loc_7FF856629F80
    loc_7FF85662BCD4:
    mov ecx, dword ptr [rsp+78h]
    mov eax, dword ptr [rsp+0D0h]
    or eax, ecx
    not eax
    mov edx, dword ptr [rsp+50h]
    mov r8d, ecx
    or r8d, edx
    not r8d
    and ecx, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not ecx
    add ecx, r8d
    mov edx, dword ptr [rsp+50h]
    mov r8d, edx
    not r8d
    mov r9d, dword ptr [rsp+78h]
    and r8d, r9d
    add r8d, r8d
    and r9d, edx
    lea edx, [r8+r9*2]
    add edx, ecx
    lea eax, [rdx+rax*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [rsp+0CCh]
    add eax, ecx
    add eax, 2
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp ecx, eax
    jnz loc_7FF85662D1BC
    mov rax, qword ptr [qword_7FF8571C8ED8]
    mov rcx, rax
    mov rdx, -0CA8F0F10CF59467h
    xor rcx, rdx
    mov rdx, rax
    mov r8, 2339DD497E0A7D0Ch
    xor rdx, r8
    sub rdx, rcx
    xor rdx, rax
    cmp qword ptr [rsp+240h], rdx
    jz loc_7FF85662D1BC
    mov eax, dword ptr [dword_7FF8571C8EE0]
    mov dword ptr [rsp+184h], eax
    xor eax, -3FBCF0F6h
    mov dword ptr [rsp+188h], eax
    mov eax, dword ptr [dword_7FF857232BF4]
    lea ecx, [rax-3D367FAh]
    mov edx, ecx
    xor edx, 6FEAFCD4h
    mov r8d, 405CC67Fh
    sub r8d, edx
    xor ecx, eax
    xor ecx, r8d
    sub ecx, edx
    sub ecx, edx
    add ecx, -504FAEA3h
    mov dword ptr [rsp+38h], ecx
    jmp loc_7FF856629F84
    loc_7FF85662BEE6:
    mov rax, qword ptr [rsp+208h]
    mov rax, qword ptr [rax+80h]
    mov qword ptr [rsp+240h], rax
    mov eax, dword ptr [dword_7FF8571C8ED0]
    mov ecx, eax
    xor ecx, 5E876F81h
    xor eax, 0DA06A48h
    mov dword ptr [rsp+50h], eax
    add eax, 44FF61E3h
    mov dword ptr [rsp+0CCh], eax
    add ecx, 46F9C80Fh
    mov dword ptr [rsp+78h], ecx
    mov eax, dword ptr [dword_7FF857232B48]
    lea ecx, [rax-693A0867h]
    mov edx, ecx
    xor edx, 589682E3h
    add edx, eax
    mov eax, -5FEC28A8h
    sub eax, edx
    xor eax, ecx
    jmp loc_7FF856629F80
    loc_7FF85662BF4E:
    mov eax, dword ptr [rsp+48h]
    or eax, ebx
    mov dword ptr [rsp+180h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FF857232B28]
    lea ecx, [rax-30061759h]
    xor ecx, -6677F252h
    sub ecx, eax
    add ecx, -0E48822Fh
    mov dword ptr [rsp+38h], ecx
    jmp loc_7FF856629F84
    loc_7FF85662BFF4:
    mov eax, dword ptr [rsp+44h]
    mov ecx, 4F3DE74Bh
    and eax, ecx
    lea ecx, [rax+rax*8]
    lea eax, [rax+rcx*2]
    add eax, dword ptr [rsp+100h]
    mov dword ptr [rsp+104h], eax
    mov eax, dword ptr [dword_7FF857232B98]
    lea ecx, [rax+58E11972h]
    lea edx, [rax-7CBF600Fh]
    xor edx, -4980A5E6h
    xor eax, -368195F4h
    loc_7FF85662C030:
    sub eax, edx
    jmp loc_7FF85662CE69
    loc_7FF85662C037:
    mov ecx, 6
    mov edx, 4Bh
    mov r8d, 0Ch
    mov r9, rdi
    call sub_7FF856A42160
    movups xmm0, xmmword ptr [rsp+280h]
    movups xmmword ptr [xmmword_7FF857261690], xmm0
    mov rax, qword ptr [xmmword_7FF857261690]
    mov qword ptr [rsp+220h], rax
    loc_7FF85662C06D:
    mov rax, qword ptr [rsp+220h]
    mov qword ptr [rsp+200h], rax
    mov rax, qword ptr [xmmword_7FF857261690+8]
    mov qword ptr [rsp+230h], rax
    mov rax, qword ptr [rsi+8]
    mov qword ptr [rsp+208h], rax
    mov eax, dword ptr [dword_7FF857232B38]
    lea ecx, [rax-1A48E26Bh]
    lea edx, [rax+62F03E13h]
    mov r8d, -1145E0Ch
    sub r8d, eax
    xor r8d, edx
    sub r8d, eax
    xor r8d, ecx
    mov dword ptr [rsp+38h], r8d
    jmp loc_7FF856629F84
    loc_7FF85662C0C6:
    mov eax, dword ptr [rsp+1A4h]
    lea ecx, [rax+rax*2]
    mov edx, dword ptr [rsp+6Ch]
    mov eax, dword ptr [rsp+70h]
    mov r8d, eax
    or r8d, edx
    not r8d
    shl r8d, 2
    not edx
    and edx, eax
    mov eax, edx
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
    add edx, edx
    mov r9d, dword ptr [rsp+70h]
    and r9d, dword ptr [rsp+6Ch]
    lea edx, [rdx+r9*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub eax, edx
    sub eax, r8d
    sub eax, ecx
    add eax, -3
    mov ecx, dword ptr [rsp+19Ch]
    mov edx, eax
    or edx, ecx
    not edx
    add edx, edx
    lea edx, [rdx+rdx*2]
    mov dword ptr [rsp+1A8h], edx
    mov edx, ecx
    not edx
    mov r8d, eax
    or r8d, edx
    add r8d, r8d
    lea r8d, [r8+r8*2]
    mov dword ptr [rsp+1ACh], r8d
    mov r8d, eax
    xor r8d, ecx
    and edx, eax
    lea edx, [rdx+rdx*2]
    add edx, edx
    and eax, ecx
    lea eax, [rax+rax*2]
    lea eax, [rdx+rax*2]
    add eax, r8d
    mov dword ptr [rsp+1B0h], eax
    mov eax, dword ptr [dword_7FF857232C04]
    mov ecx, eax
    xor ecx, 5FDFA76Dh
    lea edx, [rcx+1E16651h]
    lea r8d, [rcx+23D00E65h]
    mov r9d, r8d
    xor r9d, -72775900h
    add ecx, 5C507E36h
    xor ecx, eax
    sub ecx, r9d
    add ecx, 186C5317h
    xor ecx, r9d
    sub ecx, r8d
    xor ecx, edx
    mov dword ptr [rsp+38h], ecx
    jmp loc_7FF856629F84
    loc_7FF85662C24E:
    mov rax, qword ptr [rsp+0C0h]
    and rax, qword ptr [rsp+278h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rax, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rsp+0C0h]
    and rcx, qword ptr [rsp+0B8h]
    lea rax, [rax+rax*2]
    add rcx, rcx
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
    add rcx, qword ptr [rsp+270h]
    add rcx, qword ptr [rsp+268h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rcx, qword ptr [rsp+258h]
    sub rcx, qword ptr [rsp+250h]
    cmp qword ptr [rsp+248h], rcx
    jnz loc_7FF85662D2DE
    mov eax, dword ptr [dword_7FF857232BE8]
    lea ecx, [rax-35BE3E61h]
    lea edx, [rax-2BCA4ACAh]
    mov r8d, 4098DAB0h
    sub r8d, eax
    xor r8d, eax
    add r8d, eax
    add r8d, -4A927DFDh
    xor r8d, ecx
    sub r8d, eax
    add r8d, -3C0A2752h
    jmp loc_7FF85662C97C
    loc_7FF85662C422:
    mov eax, dword ptr [rsp+1C8h]
    mov ecx, dword ptr [rsp+1CCh]
    or ecx, eax
    not ecx
    mov edx, dword ptr [rsp+0A0h]
    mov r8d, eax
    or r8d, edx
    add r8d, r8d
    mov r9d, eax
    xor r9d, edx
    mov r10d, edx
    not r10d
    and r10d, eax
    shl r10d, 2
    and eax, edx
    lea eax, [r10+rax*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub eax, r9d
    sub eax, r8d
    lea eax, [rax+rcx*4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add eax, dword ptr [rsp+1C0h]
    xor eax, dword ptr [rsp+1B8h]
    mov dword ptr [rsp+1D0h], eax
    mov eax, dword ptr [dword_7FF8571C8ECC]
    mov dword ptr [rsp+74h], eax
    xor eax, 51DD7A85h
    lea ecx, [rax-3BF1368Fh]
    mov edx, ecx
    xor edx, -6D1F20AEh
    lea r8d, [rdx-223597E1h]
    mov dword ptr [rsp+1D4h], r8d
    lea r8d, [rdx+41FE7E07h]
    mov dword ptr [rsp+1D8h], r8d
    lea r8d, [rdx+450AD1C1h]
    xor r8d, 256AFEE4h
    mov dword ptr [rsp+1DCh], r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add eax, -70C4A576h
    xor eax, ecx
    mov dword ptr [rsp+1E0h], eax
    mov eax, dword ptr [dword_7FF857232C10]
    lea ecx, [rax+49C87C1Eh]
    xor ecx, -71895715h
    lea edx, [rcx-6F47533Eh]
    add eax, 724F337Bh
    loc_7FF85662C5FB:
    xor eax, edx
    sub eax, ecx
    mov dword ptr [rsp+38h], eax
    jmp loc_7FF856629F84
    loc_7FF85662C608:
    mov eax, dword ptr [rsp+8Ch]
    mov ecx, dword ptr [rsp+13Ch]
    and ecx, eax
    and eax, dword ptr [rsp+58h]
    sub eax, ecx
    add eax, dword ptr [rsp+138h]
    sub eax, dword ptr [rsp+134h]
    mov dword ptr [rsp+140h], eax
    mov eax, dword ptr [dword_7FF857232BC4]
    mov ecx, eax
    xor ecx, -0AF72066h
    lea edx, [rcx-52B34B11h]
    lea r8d, [rcx+6F8A63D7h]
    xor r8d, 42866BA1h
    add r8d, -34AACD0Fh
    xor edx, -4C2A8893h
    add edx, eax
    lea eax, [rcx+rdx]
    add eax, 6F8A63D7h
    add eax, ecx
    xor eax, r8d
    jmp loc_7FF856629F80
    loc_7FF85662C676:
    mov rax, qword ptr [rsp+208h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rax+0F8h]
    mov qword ptr [rsp+210h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+200h]
    cmp rax, qword ptr [rsp+210h]
    setbe byte ptr [rsp+3Fh]
    mov eax, dword ptr [dword_7FF857232B30]
    mov ecx, eax
    xor ecx, -3F14B7CDh
    lea edx, [rcx-50A25617h]
    xor edx, eax
    add ecx, -3A21539h
    xor eax, ecx
    xor ecx, 6B0CA797h
    xor edx, 0CE9B294h
    sub edx, ecx
    xor edx, eax
    xor edx, 6BE968B5h
    mov dword ptr [rsp+38h], edx
    jmp loc_7FF856629F84
    loc_7FF85662C794:
    mov eax, dword ptr [dword_7FF8571C8F14]
    mov dword ptr [rsp+44h], eax
    mov ecx, eax
    or ecx, -4F3DE74Ch
    lea edx, [rcx+rcx*4]
    lea edx, [rcx+rdx*2]
    not ecx
    lea r8d, [rcx*8]
    sub r8d, ecx
    mov dword ptr [rsp+0F0h], r8d
    not eax
    mov ecx, eax
    and ecx, -4F3DE74Ch
    mov r8d, ecx
    shl r8d, 4
    add r8d, ecx
    mov dword ptr [rsp+0F4h], r8d
    add eax, eax
    or eax, -6184316Ah
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+0F8h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov dword ptr [rsp+0FCh], edx
    mov eax, dword ptr [rsp+44h]
    and eax, r13d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    shl eax, 2
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+100h], eax
    mov eax, dword ptr [dword_7FF857232B90]
    mov ecx, eax
    xor ecx, -50256FAEh
    xor eax, -6AAB8E67h
    lea edx, [rax+12BCE483h]
    add ecx, -51A5F6D8h
    xor ecx, edx
    sub ecx, eax
    add ecx, 65BFB2B7h
    jmp loc_7FF85662D262
    loc_7FF85662C912:
    mov eax, dword ptr [rsp+12Ch]
    mov dword ptr [rsp+130h], eax
    mov eax, dword ptr [rsp+8Ch]
    mov ecx, dword ptr [rsp+58h]
    mov edx, eax
    xor eax, ecx
    not ecx
    or edx, ecx
    mov dword ptr [rsp+134h], edx
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+138h], eax
    mov dword ptr [rsp+13Ch], ecx
    mov eax, dword ptr [dword_7FF857232B2C]
    mov ecx, eax
    xor ecx, 196BFEDEh
    lea edx, [rcx+7D475D53h]
    xor edx, 5593FE5Ch
    lea r8d, [rcx+17E2247Ah]
    xor r8d, edx
    xor r8d, 4710B18Ah
    sub r8d, ecx
    add r8d, eax
    loc_7FF85662C97C:
    xor r8d, edx
    mov dword ptr [rsp+38h], r8d
    jmp loc_7FF856629F84
    loc_7FF85662C989:
    mov eax, dword ptr [rsp+54h]
    mov ecx, eax
    xor ecx, -621A9328h
    lea ecx, [rcx+rcx*4]
    mov dword ptr [rsp+110h], ecx
    and eax, 621A9327h
    add eax, eax
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+114h], eax
    mov eax, dword ptr [dword_7FF857232BA8]
    lea ecx, [rax+2D5653A4h]
    mov edx, -41A89E7Bh
    sub edx, eax
    add eax, -0A76539Fh
    xor edx, ecx
    xor edx, eax
    add edx, -5A8BDD2Ch
    mov dword ptr [rsp+38h], edx
    jmp loc_7FF856629F84
    loc_7FF85662C9DB:
    mov eax, dword ptr [dword_7FF8571C8EFC]
    mov ecx, eax
    xor ecx, -7BEAA59Ch
    lea edx, [rcx+2FD77552h]
    xor edx, eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor edx, -561AE413h
    sub edx, ecx
    add ecx, 9E7B48Ah
    xor ecx, edx
    mov dword ptr [rsp+14Ch], ecx
    mov eax, dword ptr [dword_7FF8571C8F00]
    mov dword ptr [rsp+150h], eax
    lea ecx, [rax-0EBB2404h]
    mov dword ptr [rsp+154h], ecx
    lea ecx, [rax-4EB45566h]
    mov dword ptr [rsp+158h], ecx
    add eax, -0ACA625Eh
    mov dword ptr [rsp+60h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FF857232BD0]
    lea ecx, [rax+1F5092DEh]
    mov edx, 43C543E9h
    sub edx, eax
    xor edx, ecx
    xor edx, eax
    xor edx, 28F93443h
    mov dword ptr [rsp+38h], edx
    jmp loc_7FF856629F84
    loc_7FF85662CB01:
    mov rax, qword ptr [rsp+218h]
    mov eax, dword ptr [rax+18h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    jz loc_7FF85662D496
    mov rax, qword ptr [rsp+218h]
    mov rax, qword ptr [rax+20h]
    mov qword ptr [rsp+248h], rax
    mov rax, qword ptr [qword_7FF8571C8EE8]
    mov rcx, 64F41339D736BBE7h
    add rcx, rax
    mov rdx, -661A7E1B311CC91Eh
    add rdx, rax
    mov qword ptr [rsp+0B8h], rdx
    mov rdx, 4DD0645939EB7073h
    xor rax, rdx
    mov rdx, -2E86AD0D61BB4381h
    add rax, rdx
    mov rdx, rax
    or rdx, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r8, [rdx+rdx*2]
    not rdx
    lea r9, [rdx*8]
    sub r9, rdx
    and rax, rcx
    lea rax, [rax+r8*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rax, r9
    mov rcx, -7
    sub rcx, rax
    mov qword ptr [rsp+0C0h], rcx
    mov rax, rcx
    not rax
    lea rax, [rax+rax*2]
    mov qword ptr [rsp+250h], rax
    mov rax, qword ptr [rsp+0B8h]
    mov rdx, rax
    not rdx
    or rdx, rcx
    not rdx
    lea rdx, [rdx+rdx*2]
    mov qword ptr [rsp+258h], rdx
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
    not rcx
    mov qword ptr [rsp+260h], rcx
    mov eax, dword ptr [dword_7FF857232BBC]
    mov ecx, -30DE275Fh
    xor eax, ecx
    lea ecx, [rax-16351416h]
    lea edx, [rax-2D50D64Ch]
    mov r8d, -8F701F8h
    sub r8d, eax
    xor r8d, edx
    sub r8d, eax
    add r8d, 6521784Fh
    xor r8d, ecx
    sub r8d, eax
    mov dword ptr [rsp+38h], r8d
    jmp loc_7FF856629F84
    loc_7FF85662CD62:
    mov eax, dword ptr [dword_7FF857232B64]
    lea ecx, [rax-5668F17Bh]
    mov edx, ecx
    xor edx, 30333EB8h
    add edx, eax
    mov r8d, 6BD4A681h
    sub r8d, edx
    xor r8d, eax
    sub r8d, ecx
    mov dword ptr [rsp+38h], r8d
    jmp loc_7FF856629F84
    loc_7FF85662CD91:
    mov eax, dword ptr [rsp+104h]
    sub eax, dword ptr [rsp+0FCh]
    sub eax, dword ptr [rsp+0F8h]
    add eax, dword ptr [rsp+0F4h]
    add eax, dword ptr [rsp+0F0h]
    mov dword ptr [rsp+88h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+88h]
    mov ecx, -2331C42h
    add eax, ecx
    mov dword ptr [rsp+108h], eax
    mov ecx, eax
    not ecx
    mov edx, ecx
    and edx, 78F2054Eh
    add edx, edx
    add ecx, ecx
    or ecx, -0E1BF564h
    xor eax, -78F2054Fh
    sub ecx, eax
    sub ecx, edx
    mov dword ptr [rsp+54h], ecx
    not ecx
    and ecx, -621A9328h
    lea eax, [rcx*8]
    sub eax, ecx
    mov dword ptr [rsp+10Ch], eax
    mov eax, dword ptr [dword_7FF857232BA0]
    lea ecx, [rax-4D7EADBCh]
    mov edx, -7DC98980h
    sub edx, eax
    add eax, -1C5EB35Ah
    xor eax, edx
    add eax, 653ABA39h
    loc_7FF85662CE69:
    xor eax, ecx
    mov dword ptr [rsp+38h], eax
    jmp loc_7FF856629F84
    loc_7FF85662CE74:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsi]
    mov ecx, dword ptr [rax]
    jmp loc_7FF85662D1C8
    loc_7FF85662CEE8:
    mov eax, dword ptr [rsp+140h]
    add eax, dword ptr [rsp+130h]
    sub eax, dword ptr [rsp+128h]
    mov dword ptr [rsp+144h], eax
    mov ecx, dword ptr [rsp+5Ch]
    not ecx
    or ecx, eax
    mov dword ptr [rsp+148h], ecx
    mov eax, dword ptr [dword_7FF857232B50]
    lea ecx, [rax-612FEECh]
    mov edx, ecx
    xor edx, 21767E57h
    xor ecx, 55171B44h
    add ecx, -6CED63B1h
    add eax, -337969D3h
    xor eax, ecx
    sub eax, edx
    mov dword ptr [rsp+38h], eax
    jmp loc_7FF856629F84
    loc_7FF85662CF45:
    mov eax, dword ptr [rsp+50h]
    not eax
    mov dword ptr [rsp+0D0h], eax
    mov eax, dword ptr [dword_7FF857232B4C]
    lea ecx, [rax+1FAD7A69h]
    xor ecx, 4CDBFA91h
    add ecx, eax
    add ecx, 1FAD7A69h
    add ecx, eax
    mov eax, -13130FAAh
    sub eax, ecx
    jmp loc_7FF856629F80
    loc_7FF85662CF7A:
    mov eax, dword ptr [rsp+5Ch]
    mov ecx, dword ptr [rsp+144h]
    mov edx, ecx
    or edx, eax
    mov r8d, eax
    not r8d
    mov r9d, ecx
    and r9d, r8d
    xor r8d, ecx
    add r8d, edx
    lea r10d, [rcx+rcx]
    lea r9d, [r9+r9*2]
    and ecx, eax
    lea edx, [rcx+rcx*2]
    add edx, r9d
    sub edx, r10d
    add edx, r8d
    sub edx, dword ptr [rsp+148h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FF8571C8F0C]
    lea ecx, [rax-547F833Fh]
    xor ecx, 468D4D93h
    add ecx, eax
    add ecx, 45C2F762h
    add eax, 45C2F762h
    xor eax, 0F80B262h
    sub ecx, eax
    add ecx, 13462B55h
    mov dword ptr [rsp+28h], ecx
    mov qword ptr [rsp+20h], 11h
    mov r8d, 1Bh
    mov r9d, 2Bh
    mov rcx, rsi
    call sub_7FF85703FF30
    mov rax, qword ptr [rsi]
    mov eax, dword ptr [rax]
    loc_7FF85662D0BE:
    mov dword ptr [rsp+0B4h], eax
    mov eax, dword ptr [rsp+0B4h]
    mov dword ptr [rsp+0ECh], eax
    mov eax, dword ptr [dword_7FF8571C8F10]
    mov dword ptr [rsp+84h], eax
    mov eax, dword ptr [dword_7FF857232B84]
    lea ecx, [rax-7DEE8FC0h]
    lea edx, [rax-722739A3h]
    lea r8d, [rax-21D9C306h]
    xor r8d, 3430FD1Dh
    lea r9d, [rax+4D0C1CF9h]
    xor r9d, eax
    sub r9d, eax
    add eax, r9d
    add eax, -33E0F58h
    xor eax, ecx
    add eax, r8d
    add eax, edx
    add eax, -155AEAAAh
    jmp loc_7FF856629F80
    loc_7FF85662D126:
    mov eax, dword ptr [rsp+0E4h]
    lea ecx, [rax-7CDC7413h]
    mov edx, ecx
    xor edx, 144CADF4h
    sub edx, ecx
    sub edx, dword ptr [rsp+0D8h]
    sub edx, eax
    sub edx, dword ptr [rsp+0E0h]
    mov dword ptr [rsp+0E8h], edx
    mov eax, dword ptr [dword_7FF857232B70]
    lea ecx, [rax+4C8C94F7h]
    lea edx, [rax+2F188A81h]
    mov r8d, 313447A2h
    sub r8d, eax
    xor r8d, ecx
    sub r8d, edx
    sub r8d, eax
    xor r8d, edx
    xor r8d, 3502338Eh
    add r8d, -42B76910h
    mov dword ptr [rsp+38h], r8d
    jmp loc_7FF856629F84
    loc_7FF85662D193:
    mov dword ptr [rsp+40h], 0
    mov eax, dword ptr [dword_7FF857232B88]
    mov ecx, eax
    xor ecx, 7ABA1D19h
    sub ecx, eax
    xor eax, -44FF297h
    add eax, ecx
    add eax, 44201394h
    jmp loc_7FF856629F80
    loc_7FF85662D1BC:
    mov rax, qword ptr [rsp+238h]
    mov ecx, dword ptr [rsp+4Ch]
    loc_7FF85662D1C8:
    mov dword ptr [rsp+0A8h], ecx
    mov qword ptr [rsp+228h], rax
    mov rax, qword ptr [rsp+228h]
    mov ecx, dword ptr [rsp+0A8h]
    mov qword ptr [rsp+218h], rax
    mov dword ptr [rsp+0D4h], ecx
    cmp ecx, -3FFFFFFBh
    jnz loc_7FF85662D23A
    mov eax, dword ptr [dword_7FF857232BA4]
    lea ecx, [rax+5F2B4431h]
    sub eax, ecx
    xor ecx, -5D6552D3h
    add ecx, 43A177ABh
    mov edx, ecx
    xor edx, -66FA4E8Dh
    mov r8d, ecx
    xor r8d, -48D71289h
    sub eax, edx
    add eax, r8d
    add eax, 44CFFCA8h
    xor eax, ecx
    jmp loc_7FF856629F80
    loc_7FF85662D23A:
    mov eax, dword ptr [dword_7FF857232B54]
    mov ecx, -379DFC3Eh
    add eax, ecx
    xor eax, 6AF82FC5h
    lea ecx, [rax-6BD6F2A0h]
    mov edx, ecx
    xor edx, 7EC5DDC2h
    add ecx, edx
    add ecx, -28A0C4DAh
    loc_7FF85662D262:
    xor ecx, eax
    mov dword ptr [rsp+38h], ecx
    jmp loc_7FF856629F84
    loc_7FF85662D26D:
    mov eax, dword ptr [dword_7FF857232B40]
    lea ecx, [rax+42E19850h]
    lea edx, [rax-653A68ECh]
    xor edx, -3E3682C1h
    lea r8d, [rdx-75818A83h]
    mov r9d, -39B6AAFAh
    sub r9d, eax
    xor r9d, ecx
    xor r9d, r8d
    sub r9d, eax
    xor r9d, edx
    mov dword ptr [rsp+38h], r9d
    jmp loc_7FF856629F84
    loc_7FF85662D2AB:
    mov eax, dword ptr [dword_7FF857232B78]
    mov ecx, eax
    xor ecx, -6777D855h
    lea edx, [rcx-5D18DA7h]
    xor edx, -3DAEF3AFh
    lea r8d, 0FFFFFFFFFA2E7259h[rcx*2]
    sub eax, r8d
    sub eax, edx
    sub eax, ecx
    add eax, 66BE9144h
    jmp loc_7FF856629F80
    loc_7FF85662D2DE:
    mov eax, dword ptr [dword_7FF857232BE4]
    lea ecx, [rax-1333ADF2h]
    xor ecx, -544849A2h
    lea edx, [rcx+2B2669F3h]
    lea r8d, [rcx+4BE0D1EAh]
    xor edx, -7187F8CFh
    sub edx, ecx
    xor edx, r8d
    add edx, eax
    add edx, -1333ADF2h
    add edx, eax
    lea eax, [rcx+rdx]
    add eax, -21263E6Ch
    jmp loc_7FF856629F80
    loc_7FF85662D31F:
    mov eax, dword ptr [dword_7FF857232B18]
    lea ecx, [rax+0CADD784h]
    xor eax, ecx
    xor eax, 75A7705Bh
    sub eax, ecx
    add eax, -2F7E60E6h
    mov dword ptr [rsp+38h], eax
    jmp loc_7FF856629F84
    loc_7FF85662D342:
    mov eax, dword ptr [dword_7FF857232C18]
    lea ecx, [rax-3B16614Fh]
    mov edx, ecx
    xor edx, 3FCBEDB3h
    xor ecx, -481F3F41h
    add edx, eax
    sub edx, ecx
    sub edx, ecx
    sub edx, ecx
    add edx, -6FEC45AEh
    mov dword ptr [rsp+38h], edx
    jmp loc_7FF856629F84
    loc_7FF85662D373:
    cmp eax, 30F08E83h
    jnz loc_7FF85662D496
    mov r8d, dword ptr [dword_7FF8571C8F18]
    lea ecx, [r8-5ADBDB13h]
    mov eax, ecx
    xor eax, 0E4DC54Fh
    lea edx, [rax+6E8F14E5h]
    mov r9d, edx
    not r9d
    and r9d, -6438AE19h
    lea r10d, [r9*8]
    sub r10d, r9d
    mov r9d, edx
    xor r9d, -6438AE19h
    lea r9d, [r9+r9*4]
    mov r11d, edx
    and r11d, 6438AE18h
    lea r11d, [r11+r11*2]
    mov edi, edx
    and edi, -6438AE19h
    lea r11d, [rdi+r11*2]
    sub r11d, r9d
    lea r9d, [r11+r10]
    add r9d, 29C924F5h
    xor r9d, r8d
    mov r8d, r9d
    or r8d, edx
    lea r10d, [r8+r8*2]
    not r8d
    lea r11d, [r8*8]
    sub r11d, r8d
    and r9d, edx
    lea edx, [r9+r10*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add edx, r11d
    mov r8d, -7
    sub r8d, edx
    xor r8d, ecx
    sub r8d, eax
    mov edx, dword ptr [rsp+118h]
    mov dword ptr [rsp+28h], r8d
    mov qword ptr [rsp+20h], 43h
    mov r8d, 2Ah
    mov r9d, 1Ah
    mov rcx, rsi
    call sub_7FF85703FF30
    loc_7FF85662D496:
    mov dword ptr [rsp+40h], 0
    jmp loc_7FF85662D4D7
    loc_7FF85662D4A0:
    mov edx, dword ptr [rsp+1D0h]
    mov eax, dword ptr [rsp+1FCh]
    mov dword ptr [rsp+28h], eax
    mov qword ptr [rsp+20h], 2
    mov r8d, 0Ch
    mov r9d, 4Fh
    mov rcx, rsi
    call sub_7FF85703FF30
    mov dword ptr [rsp+40h], -1
    loc_7FF85662D4D7:
    mov eax, dword ptr [rsp+40h]
    mov rcx, qword ptr [rsp+290h]
    xor rcx, rsp
    cmp rcx, qword ptr [__security_cookie]
    jnz loc_7FF85662D503
    add rsp, 298h
    pop rbx
    pop rbp
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    ret
    loc_7FF85662D503:
    call __security_check_cookie
    int 3
_TEXT ENDS
END

; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: sub_7FF859C06F60  @ 0x7ff859c06f60
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN CreateEventW:PROC
EXTERN sub_7FF8597D72F0:PROC
EXTERN sub_7FF85A9D8874:PROC

CONST SEGMENT
xmmword_7FF85AA27A6C db 1,45h,80h,79h,74h,0Eh,3Dh,9,0C4h,27h,2Ah,68h,0B0h,82h,9Eh,0EFh
xmmword_7FF85AA27A83 db 57h,67h,0C2h,0C9h,14h,0E2h,29h,35h,2Fh,3Dh,0A8h,0Ah,96h,53h,55h,5Bh
xmmword_7FF85AA27AA1 db 3Ah,81h,26h,3Fh,2,0A0h,4Bh,94h,36h,0C7h,0Ah,0E6h,5Ah,60h,84h,57h
xmmword_7FF85AA2C037 db 3Dh,3Ch,0ADh,32h,20h,4Bh,0FAh,0EEh,0F9h,0C0h,1,0Eh,0F4h,1Ch,6,0A6h
qword_7FF85AAD3ED8 dq -7AEC0AC94C460C30h
dword_7FF85AAD3EE0 dd 5A1AE5E0h
dword_7FF85AAD3EE4 dd 0E5744FF2h
dword_7FF85AAD3EE8 dd 0DED0D3C8h
dword_7FF85AB31FC0 dd 7C717A5Dh
dword_7FF85AB31FC4 dd 94396DAh
dword_7FF85AB31FC8 dd 6E1C17DDh
dword_7FF85AB31FCC dd 38500A2Eh
dword_7FF85AB31FD0 dd 0ABC3599Ch
dword_7FF85AB31FD4 dd 490BBE3Eh
dword_7FF85AB31FD8 dd 99FB9342h
dword_7FF85AB31FDC dd 8FF68965h
dword_7FF85AB31FE0 dd 114EFB5Bh
dword_7FF85AB31FE4 dd 0E6641582h
dword_7FF85AB31FE8 dd 8D7493BBh
dword_7FF85AB31FEC dd 8A97B657h
dword_7FF85AB31FF0 dd 1B9A4336h
dword_7FF85AB31FF4 dd 501C403Dh
dword_7FF85AB31FF8 dd 0C1857637h
dword_7FF85AB31FFC dd 497FDB57h
dword_7FF85AB32000 dd 35D613DAh
dword_7FF85AB32004 dd 52EADB87h
dword_7FF85AB32008 dd 0B0282516h
dword_7FF85AB3200C dd 7E174EE2h
dword_7FF85AB32010 dd 60506E25h
dword_7FF85AB32014 dd 2A505B25h
dword_7FF85AB32018 dd 2D91B8F5h
dword_7FF85AB3201C dd 91F5E101h
dword_7FF85AB32020 dd 44355318h
dword_7FF85AB32024 dd 0D338CDCCh
dword_7FF85AB32028 dd 456807FBh
dword_7FF85AB3202C dd 5557C1EAh
dword_7FF85AB32030 dd 7AD601E8h
dword_7FF85AB32034 dd 0E7111DCh
dword_7FF85AB32038 dd 0A831A46Dh
dword_7FF85AB3203C dd 0C9F48A6Ch
dword_7FF85AB32040 dd 66A1C609h
dword_7FF85AB32044 dd 0B6FADC8Bh
dword_7FF85AB32048 dd 139F1BCh
dword_7FF85AB3204C dd 41DF35D6h
dword_7FF85AB32050 dd 20CCDD6Bh
dword_7FF85AB32054 dd 0EC22BE5h
dword_7FF85AB32058 dd 0F8F36E99h
dword_7FF85AB3205C dd 0AC4EBF55h
dword_7FF85AB32060 dd 573D467Fh
dword_7FF85AB32064 dd 0BCA1A0C0h
dword_7FF85AB32068 dd 4F37962Eh
dword_7FF85AB3206C dd 96752029h
dword_7FF85AB32070 dd 0C503DA5Fh
dword_7FF85AB32074 dd 0CA027F85h
dword_7FF85AB32078 dd 0EDCCBDF1h
dword_7FF85AB3207C dd 0C8092323h
dword_7FF85AB32080 dd 44A303E6h
dword_7FF85AB32084 dd 0A9E5ECA6h
dword_7FF85AB32088 dd 34F8F0D2h
dword_7FF85AB3208C dd 0EFDEE230h
dword_7FF85AB32090 dd 2383C20Bh
dword_7FF85AB32094 dd 3F01C4C1h
dword_7FF85AB32098 dd 0A2574860h
dword_7FF85AB3209C dd 6DD7168Bh
dword_7FF85AB320A0 dd 42116FB6h
dword_7FF85AB320A4 dd 0E4BAF95Eh
dword_7FF85AB320A8 dd 85F4ECB0h
dword_7FF85AB320AC dd 0AE42BAE3h
dword_7FF85AB320B0 dd 126CFFDAh
dword_7FF85AB320B4 dd 0FD608A7Bh
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC sub_7FF859C06F60
sub_7FF859C06F60:
    push r15
    push r14
    push r13
    push r12
    push rsi
    push rdi
    push rbp
    push rbx
    sub rsp, 258h
    mov eax, dword ptr [dword_7FF85AB31FD0]
    mov ecx, eax
    xor ecx, 393B786Fh
    lea edx, [rcx+26F60648h]
    xor edx, -1563925Eh
    add ecx, eax
    add ecx, edx
    mov eax, -201FB38Ch
    sub eax, ecx
    mov dword ptr [rsp+28h], eax
    mov rbx, 660D85AF62BC0C04h
    mov r12, 4E90030CE10FAF78h
    mov r13, 316FFCF31EF05087h
    mov ebp, 3500BFEBh
    mov r15, -660D85AF62BC0C05h
    mov rsi, 33E4F4A13A87E7F6h
    mov edi, 5C67FE3Ah
    mov r14d, -4F515A41h
    jmp loc_7FF859C070C4
    loc_7FF859C06FE3:
    mov rax, qword ptr [rsp+188h]
    sub rax, qword ptr [rsp+160h]
    mov qword ptr [rsp+148h], rax
    not rax
    mov rcx, rax
    and rcx, r12
    mov qword ptr [rsp+190h], rcx
    and rax, r13
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    lea rax, [rax+rax*2]
    mov qword ptr [rsp+198h], rax
    mov eax, dword ptr [dword_7FF85AB31FD4]
    mov ecx, eax
    xor ecx, -1324A031h
    add ecx, -3E9F17A2h
    mov edx, ecx
    xor edx, -67AFA2FFh
    mov r8d, ecx
    xor r8d, -661A2ACAh
    neg edx
    add edx, r8d
    add edx, 68EA2CA7h
    xor edx, eax
    add edx, r8d
    xor edx, ecx
    nop word ptr [rax+rax+00000000h]
    loc_7FF859C070C0:
    mov dword ptr [rsp+28h], edx
    loc_7FF859C070C4:
    mov eax, dword ptr [rsp+28h]
    cmp eax, 44E0B719h
    jle loc_7FF859C07190
    cmp eax, 572FE738h
    jle loc_7FF859C072F0
    cmp eax, 7140823Dh
    jg loc_7FF859C073E5
    cmp eax, 67F3014Ah
    jg loc_7FF859C07703
    cmp eax, 5E9963E8h
    jg loc_7FF859C07C51
    cmp eax, 572FE739h
    jnz loc_7FF859C0896A
    mov eax, dword ptr [rsp+90h]
    mov ecx, -5E96D65Ch
    add eax, ecx
    mov dword ptr [rsp+94h], eax
    mov eax, dword ptr [rsp+48h]
    mov ecx, eax
    xor ecx, -4DCEEBD1h
    mov dword ptr [rsp+3Ch], ecx
    xor eax, 4DCEEBD0h
    mov dword ptr [rsp+98h], eax
    mov eax, dword ptr [dword_7FF85AB3206C]
    lea ecx, [rax-424CB494h]
    mov edx, ecx
    xor edx, -2AA819A8h
    lea r8d, [rdx+6E615FE3h]
    lea r9d, [rdx+3F479745h]
    lea r10d, [rdx+13387774h]
    xor r10d, r9d
    xor r8d, ecx
    xor r8d, r10d
    xor r8d, edx
    xor r8d, 389DEC6h
    sub r8d, eax
    add r8d, 4C2208F2h
    mov dword ptr [rsp+28h], r8d
    jmp loc_7FF859C070C4
    loc_7FF859C07190:
    cmp eax, 25D1AF4Ah
    jg loc_7FF859C07210
    cmp eax, 10806E95h
    jle loc_7FF859C07459
    cmp eax, 1AE34281h
    jg loc_7FF859C076A5
    cmp eax, 12E5EC97h
    jg loc_7FF859C07B88
    cmp eax, 10806E96h
    jnz loc_7FF859C086CE
    mov eax, dword ptr [rsp+2Ch]
    mov ecx, -2DD3B982h
    and eax, ecx
    mov dword ptr [rsp+0E4h], eax
    mov eax, dword ptr [dword_7FF85AB32098]
    mov ecx, eax
    xor ecx, -3A204561h
    lea edx, [rcx-41E4A94Fh]
    lea r8d, [rcx-2C882176h]
    xor r8d, edx
    sub r8d, ecx
    add eax, r8d
    add eax, -0AAD1461h
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C07210:
    cmp eax, 370F4D47h
    jle loc_7FF859C074BB
    cmp eax, 3EDE27C8h
    jg loc_7FF859C07640
    cmp eax, 3AC0C5EEh
    jg loc_7FF859C07A8C
    cmp eax, 370F4D48h
    jnz loc_7FF859C08260
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+30h]
    add rax, 1Ch
    mov qword ptr [rsp+208h], rax
    mov eax, dword ptr [dword_7FF85AB32044]
    lea ecx, [rax-380E893Fh]
    lea edx, [rax-4278E1F1h]
    mov r8d, edx
    xor r8d, -7E273A8Dh
    xor ecx, 552AE795h
    sub ecx, r8d
    add ecx, eax
    sub ecx, edx
    add ecx, -71BFA19Ah
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF859C070C4
    loc_7FF859C072F0:
    cmp eax, 4DB28B4Bh
    jle loc_7FF859C075BA
    cmp eax, 5394B6D0h
    jg loc_7FF859C077D8
    cmp eax, 4EC5D938h
    jg loc_7FF859C07E46
    cmp eax, 4DB28B4Ch
    jnz loc_7FF859C08D9E
    mov rax, qword ptr [qword_7FF85AAD3ED8]
    mov qword ptr [rsp+60h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, -325F05E920CB3976h
    add rax, rcx
    mov qword ptr [rsp+150h], rax
    mov rcx, -7B1039EF22C790A0h
    xor rax, rcx
    mov qword ptr [rsp+158h], rax
    mov rcx, -2C7D0B35AE100597h
    add rax, rcx
    mov qword ptr [rsp+58h], rax
    mov eax, dword ptr [dword_7FF85AB31FD8]
    mov ecx, eax
    xor ecx, 5A1CA9Ch
    add ecx, 1AE58EFFh
    mov edx, ecx
    xor edx, -0FA5453Bh
    xor eax, edx
    add edx, -2EB461A4h
    xor edx, eax
    xor edx, ecx
    xor edx, 16E2D8B8h
    jmp loc_7FF859C070C0
    loc_7FF859C073E5:
    cmp eax, 768000C3h
    jg loc_7FF859C07773
    cmp eax, 7539EBCCh
    jg loc_7FF859C07D2E
    cmp eax, 7140823Eh
    jnz loc_7FF859C089A0
    mov eax, dword ptr [rsp+0ACh]
    not eax
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+0B0h], eax
    mov eax, dword ptr [rsp+38h]
    not eax
    mov dword ptr [rsp+0B4h], eax
    mov eax, dword ptr [dword_7FF85AB32080]
    lea ecx, [rax-12B26160h]
    xor ecx, -7D1B1FDEh
    add ecx, eax
    lea edx, [rax-6238AFCEh]
    lea r8d, [rax+3E9E90C7h]
    add ecx, eax
    add ecx, 1C5D0CA6h
    xor ecx, r8d
    sub ecx, eax
    jmp loc_7FF859C089ED
    loc_7FF859C07459:
    cmp eax, 78CAFFDh
    jle loc_7FF859C07835
    cmp eax, 973B8DEh
    jg loc_7FF859C07A19
    cmp eax, 78CAFFEh
    jnz loc_7FF859C0814F
    mov eax, dword ptr [rsp+140h]
    add eax, dword ptr [rsp+118h]
    mov dword ptr [rsp+144h], eax
    mov eax, dword ptr [dword_7FF85AB31FFC]
    lea ecx, [rax+5E5B1463h]
    lea edx, [rax-1B36875Eh]
    xor edx, 26C86C07h
    add edx, eax
    xor edx, ecx
    add eax, edx
    add eax, 0F5081C2h
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C074BB:
    cmp eax, 32F59B6Ch
    jle loc_7FF859C07893
    cmp eax, 353360FCh
    jg loc_7FF859C0798C
    cmp eax, 32F59B6Dh
    jnz loc_7FF859C080E8
    mov rax, qword ptr [rsp+30h]
    lea rcx, [rax+48h]
    mov qword ptr [rsp+228h], rcx
    mov qword ptr [rax+48h], 0
    mov rax, qword ptr [rsp+30h]
    lea rcx, [rax+50h]
    mov qword ptr [rsp+230h], rcx
    add rax, 58h
    mov qword ptr [rsp+238h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+30h]
    add rax, 5Ch
    mov qword ptr [rsp+240h], rax
    mov eax, dword ptr [dword_7FF85AB32008]
    lea ecx, [rax+30737644h]
    xor ecx, 1F0B3DE2h
    mov edx, 5F4137C6h
    sub edx, ecx
    xor ecx, eax
    xor ecx, edx
    xor ecx, 22B143BAh
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF859C070C4
    loc_7FF859C075BA:
    cmp eax, 471AE029h
    jle loc_7FF859C0793F
    cmp eax, 49D4DFA4h
    jg loc_7FF859C07B32
    cmp eax, 471AE02Ah
    jnz loc_7FF859C08637
    mov rax, qword ptr [rsp+148h]
    lea rcx, [rax+rax*2]
    mov qword ptr [rsp+1A0h], rcx
    mov rcx, rax
    and rcx, r13
    shl rcx, 2
    and rax, r12
    lea rax, [rax+rax*2]
    sub rcx, rax
    mov qword ptr [rsp+1A8h], rcx
    mov eax, dword ptr [dword_7FF85AB31FF4]
    lea ecx, [rax-3EBE0892h]
    lea edx, [rax-31D08EE5h]
    mov r8d, 72ED3060h
    sub r8d, eax
    xor r8d, ecx
    xor r8d, edx
    sub r8d, eax
    add r8d, -63FE6BB3h
    mov dword ptr [rsp+28h], r8d
    jmp loc_7FF859C070C4
    loc_7FF859C07640:
    cmp eax, 40B6AA27h
    jg loc_7FF859C07AD9
    cmp eax, 3EDE27C9h
    jnz loc_7FF859C082E5
    mov rax, qword ptr [rsp+1F0h]
    add rax, qword ptr [rsp+1E8h]
    mov rcx, qword ptr [rsp+1E0h]
    sub rcx, rax
    mov qword ptr [rsp+1F8h], rcx
    mov eax, dword ptr [dword_7FF85AB3200C]
    mov ecx, eax
    xor ecx, -384AA31Bh
    lea edx, [rcx+7118A83Ch]
    xor edx, -126CED0Eh
    add ecx, edx
    add ecx, 7118A83Ch
    mov edx, -5C8C1E8h
    jmp loc_7FF859C08D35
    loc_7FF859C076A5:
    cmp eax, 22EEDE45h
    jg loc_7FF859C07BE1
    cmp eax, 1AE34282h
    jnz loc_7FF859C08745
    mov eax, dword ptr [rsp+40h]
    mov ecx, 50117224h
    and eax, ecx
    add eax, eax
    neg eax
    mov dword ptr [rsp+108h], eax
    mov eax, dword ptr [dword_7FF85AB3209C]
    lea ecx, [rax+0AEA2E6Ch]
    add eax, -61CA36DCh
    mov edx, eax
    xor edx, 4750FE51h
    xor ecx, -5F3A35CEh
    sub ecx, edx
    sub ecx, eax
    add ecx, -28003EE8h
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF859C070C4
    loc_7FF859C07703:
    cmp eax, 6A95442Ah
    jg loc_7FF859C07D8D
    cmp eax, 67F3014Bh
    jnz loc_7FF859C089F8
    mov rax, qword ptr [rsp+58h]
    not rax
    mov rcx, rax
    and rcx, r15
    lea rcx, [rcx+rcx*2]
    mov qword ptr [rsp+160h], rcx
    mov rcx, rax
    and rcx, rbx
    add rcx, rcx
    mov qword ptr [rsp+168h], rcx
    add rax, rax
    or rax, rsi
    mov qword ptr [rsp+170h], rax
    mov eax, dword ptr [dword_7FF85AB31FC4]
    lea ecx, [rax+0E36AA74h]
    mov edx, -5AF21EA7h
    sub edx, eax
    xor edx, eax
    add eax, edx
    add eax, 69D23A57h
    jmp loc_7FF859C088A2
    loc_7FF859C07773:
    cmp eax, 79AACADFh
    jg loc_7FF859C07DFA
    cmp eax, 768000C4h
    jnz loc_7FF859C08A27
    mov eax, dword ptr [rsp+0A4h]
    not eax
    add eax, eax
    lea eax, [rax+rax*4]
    mov dword ptr [rsp+0A8h], eax
    mov eax, dword ptr [rsp+3Ch]
    and eax, dword ptr [rsp+38h]
    mov dword ptr [rsp+0ACh], eax
    mov eax, dword ptr [dword_7FF85AB31FCC]
    lea ecx, [rax-14514613h]
    xor ecx, -73CA08B6h
    lea edx, [rcx-77DB92F0h]
    add ecx, -114C0744h
    xor ecx, edx
    sub ecx, eax
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF859C070C4
    loc_7FF859C077D8:
    cmp eax, 54F5D79Ah
    jg loc_7FF859C07F26
    cmp eax, 5394B6D1h
    jnz loc_7FF859C08E1B
    mov rcx, qword ptr [rsp+200h]
    call sub_7FF85A9D8874
    mov qword ptr [rsp+30h], rax
    mov rcx, -483FD663D4410111h
    mov qword ptr [rax+0Fh], rcx
    movups xmm0, xmmword ptr [xmmword_7FF85AA27A6C]
    movups xmmword ptr [rax], xmm0
    mov eax, dword ptr [dword_7FF85AB3203C]
    lea ecx, [rax+210F46F5h]
    mov edx, ecx
    xor edx, 7065705Dh
    sub edx, ecx
    xor edx, eax
    jmp loc_7FF859C070C0
    loc_7FF859C07835:
    cmp eax, 70436E4h
    jle loc_7FF859C07F8A
    cmp eax, 70436E5h
    jnz loc_7FF859C08532
    mov eax, dword ptr [rsp+0BCh]
    sub eax, dword ptr [rsp+0B8h]
    add eax, dword ptr [rsp+0B0h]
    mov dword ptr [rsp+0C0h], eax
    mov eax, dword ptr [dword_7FF85AB32088]
    mov ecx, 6F1E7B0Fh
    xor eax, ecx
    lea ecx, [rax-0A85F0FBh]
    xor ecx, 45B70FA3h
    sub ecx, eax
    sub ecx, eax
    add ecx, 1580922Dh
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF859C070C4
    loc_7FF859C07893:
    cmp eax, 25D1AF4Bh
    jz loc_7FF859C07FF3
    cmp eax, 2F6D83FFh
    jnz loc_7FF859C0803D
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+124h]
    not eax
    add eax, eax
    mov dword ptr [rsp+128h], eax
    mov eax, dword ptr [dword_7FF85AB31FC8]
    lea ecx, [rax-5EC92C27h]
    lea edx, [rax-6FB529BAh]
    mov r8d, edx
    xor r8d, 700B3964h
    xor edx, -199468D3h
    sub edx, eax
    add edx, -4C722098h
    xor edx, ecx
    sub edx, r8d
    add edx, eax
    add eax, edx
    add eax, -7A265457h
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C0793F:
    cmp eax, 44E0B71Ah
    jz loc_7FF859C08225
    cmp eax, 46386C46h
    jnz loc_7FF859C085ED
    mov eax, dword ptr [rsp+2Ch]
    not eax
    and eax, -2DD3B982h
    lea eax, [rax+rax*8]
    mov dword ptr [rsp+0D0h], eax
    mov eax, dword ptr [dword_7FF85AB32094]
    lea ecx, [rax+2DCF07A4h]
    mov edx, -654FBF4Eh
    sub edx, eax
    xor edx, ecx
    sub edx, eax
    add edx, 50CDB79Eh
    jmp loc_7FF859C070C0
    loc_7FF859C0798C:
    cmp eax, 353360FDh
    jz loc_7FF859C06FE3
    mov eax, dword ptr [rsp+74h]
    mov dword ptr [rsp+78h], eax
    mov eax, dword ptr [rsp+44h]
    mov ecx, eax
    not ecx
    and ecx, 27E9441Fh
    add ecx, ecx
    mov dword ptr [rsp+7Ch], ecx
    mov dword ptr [rsp+80h], eax
    and eax, -27E94420h
    neg eax
    mov dword ptr [rsp+84h], eax
    mov eax, dword ptr [dword_7FF85AB32064]
    mov ecx, eax
    xor ecx, 5526CA89h
    lea edx, [rcx+6F526B14h]
    mov r8d, edx
    xor r8d, 4154F3FCh
    lea r9d, [r8-2203547Ch]
    xor r9d, edx
    add r8d, -10110B73h
    xor r9d, 78A18DB4h
    sub r9d, eax
    xor r8d, ecx
    xor r8d, r9d
    lea eax, [r8+rcx]
    add eax, 6F526B14h
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C07A19:
    cmp eax, 973B8DFh
    jnz loc_7FF859C081E3
    mov eax, dword ptr [rsp+0E8h]
    add eax, dword ptr [rsp+0CCh]
    mov dword ptr [rsp+0ECh], eax
    mov eax, dword ptr [rsp+40h]
    not eax
    or eax, 50117224h
    mov dword ptr [rsp+0F0h], eax
    mov eax, dword ptr [dword_7FF85AB32048]
    lea ecx, [rax-571EE8B8h]
    xor ecx, 6E94DE51h
    lea edx, [rcx-5B3D8838h]
    mov r8d, edx
    xor r8d, -7EB920Fh
    mov r9d, edx
    xor r9d, 140BDA8h
    add r9d, -313D1C03h
    xor r9d, ecx
    add r9d, r8d
    sub r9d, edx
    jmp loc_7FF859C08D91
    loc_7FF859C07A8C:
    cmp eax, 3AC0C5EFh
    jnz loc_7FF859C0844D
    mov eax, dword ptr [rsp+0D8h]
    not eax
    lea ecx, [rax+rax*4]
    lea eax, [rax+rcx*2]
    mov dword ptr [rsp+0DCh], eax
    mov eax, dword ptr [rsp+2Ch]
    mov ecx, 2DD3B981h
    and eax, ecx
    mov dword ptr [rsp+0E0h], eax
    mov eax, dword ptr [dword_7FF85AB3201C]
    mov ecx, eax
    xor ecx, -54C6E413h
    add ecx, eax
    xor eax, -2DB78C58h
    jmp loc_7FF859C08B2C
    loc_7FF859C07AD9:
    cmp eax, 40B6AA28h
    jnz loc_7FF859C084E6
    mov eax, dword ptr [rsp+50h]
    mov ecx, eax
    xor ecx, -22FFD431h
    mov dword ptr [rsp+54h], ecx
    xor eax, 2DB5030h
    and eax, -28248604h
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+120h], eax
    or ecx, -28248604h
    mov dword ptr [rsp+124h], ecx
    mov eax, dword ptr [dword_7FF85AB320AC]
    lea ecx, [rax-0E119EDAh]
    xor ecx, 7D8122EBh
    sub ecx, eax
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF859C070C4
    loc_7FF859C07B32:
    cmp eax, 49D4DFA5h
    jnz loc_7FF859C0867C
    mov rax, qword ptr [rsp+220h]
    mov rcx, 6C5F4ABF42EF7841h
    mov qword ptr [rax], rcx
    mov rax, qword ptr [rsp+30h]
    mov dword ptr [rax+40h], -294000DAh
    mov eax, dword ptr [dword_7FF85AB32058]
    lea ecx, [rax-2D8C1D0Fh]
    mov edx, -57F1A9B1h
    sub edx, eax
    xor edx, eax
    xor edx, ecx
    xor ecx, 5B3F95DAh
    xor edx, 5FC08718h
    sub edx, ecx
    jmp loc_7FF859C070C0
    loc_7FF859C07B88:
    cmp eax, 12E5EC98h
    jnz loc_7FF859C087CD
    mov rax, qword ptr [rsp+58h]
    not rax
    or rax, rbx
    mov qword ptr [rsp+178h], rax
    mov eax, dword ptr [dword_7FF85AB31FE0]
    mov ecx, eax
    xor ecx, 977277h
    mov edx, eax
    xor edx, 7D864410h
    lea r8d, [rdx-1DD0A49h]
    add edx, ecx
    sub edx, r8d
    add edx, 5F6DBD42h
    xor eax, r8d
    xor eax, edx
    xor eax, 72DC9CEEh
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C07BE1:
    cmp eax, 22EEDE46h
    jnz loc_7FF859C088AD
    mov eax, dword ptr [rsp+98h]
    lea ecx, [rax*8]
    sub ecx, eax
    mov dword ptr [rsp+9Ch], ecx
    mov eax, dword ptr [rsp+38h]
    not eax
    or eax, dword ptr [rsp+3Ch]
    not eax
    lea eax, [rax+rax*8]
    mov dword ptr [rsp+0A0h], eax
    mov eax, dword ptr [dword_7FF85AB32074]
    lea ecx, [rax-57142765h]
    lea edx, [rax-21FF967Bh]
    mov r8d, 4CA6FCCBh
    sub r8d, eax
    xor r8d, edx
    sub r8d, eax
    sub r8d, eax
    add r8d, -70860587h
    xor r8d, ecx
    mov dword ptr [rsp+28h], r8d
    jmp loc_7FF859C070C4
    loc_7FF859C07C51:
    cmp eax, 5E9963E9h
    jnz loc_7FF859C08A63
    mov rax, qword ptr [rsp+210h]
    mov byte ptr [rax], 0AFh
    mov rax, qword ptr [rsp+30h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, 552FAEB537A6061Ch
    mov qword ptr [rax+2Bh], rcx
    movups xmm0, xmmword ptr [xmmword_7FF85AA2C037]
    movups xmmword ptr [rax+1Eh], xmm0
    mov rax, qword ptr [rsp+30h]
    lea rcx, [rax+34h]
    mov qword ptr [rsp+218h], rcx
    add rax, 38h
    mov qword ptr [rsp+220h], rax
    mov eax, dword ptr [dword_7FF85AB32054]
    mov ecx, eax
    xor ecx, -5BBD443Dh
    add eax, ecx
    lea edx, [rcx+2954DCDFh]
    mov r8d, edx
    xor r8d, 56735F82h
    lea r9d, [r8+160A346h]
    xor r9d, 6DF6D5E1h
    sub eax, r9d
    sub eax, ecx
    add eax, -12B6C6DCh
    xor eax, edx
    add eax, r8d
    add eax, 160A346h
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C07D2E:
    cmp eax, 7539EBCDh
    jnz loc_7FF859C08B37
    mov eax, dword ptr [rsp+3Ch]
    mov ecx, dword ptr [rsp+0B4h]
    and ecx, eax
    add ecx, ecx
    mov dword ptr [rsp+0B8h], ecx
    and eax, dword ptr [rsp+38h]
    add eax, eax
    mov dword ptr [rsp+0BCh], eax
    mov eax, dword ptr [dword_7FF85AB32084]
    mov ecx, eax
    xor ecx, -263FA146h
    lea edx, [rcx-2957E28h]
    xor edx, 66D49BEh
    add edx, ecx
    neg edx
    add ecx, edx
    add ecx, 1ADF548Dh
    xor ecx, eax
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF859C070C4
    loc_7FF859C07D8D:
    cmp eax, 6A95442Bh
    jnz loc_7FF859C08BFE
    mov eax, dword ptr [rsp+40h]
    mov ecx, eax
    not ecx
    and ecx, 2FEE8DDBh
    shl ecx, 2
    mov dword ptr [rsp+0F8h], ecx
    mov ecx, eax
    xor ecx, 2FEE8DDBh
    shl ecx, 2
    mov dword ptr [rsp+0FCh], ecx
    xor eax, 50117224h
    lea ecx, [rax*8]
    sub ecx, eax
    mov dword ptr [rsp+100h], ecx
    mov eax, dword ptr [dword_7FF85AB31FEC]
    lea ecx, 39573B3Ah[rax*2]
    add eax, 11B7D79Eh
    xor ecx, eax
    xor ecx, -67F6CBF8h
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF859C070C4
    loc_7FF859C07DFA:
    cmp eax, 79AACAE0h
    jnz loc_7FF859C08D3E
    mov rax, qword ptr [rsp+1A8h]
    add rax, qword ptr [rsp+1A0h]
    mov qword ptr [rsp+1B0h], rax
    mov eax, dword ptr [dword_7FF85AB31FF8]
    mov ecx, eax
    xor ecx, 3AD97FFDh
    lea edx, [rcx-44F80598h]
    add ecx, -18E8E614h
    xor edx, eax
    xor edx, ecx
    xor edx, -2A0CE0F9h
    jmp loc_7FF859C070C0
    loc_7FF859C07E46:
    cmp eax, 4EC5D939h
    jnz loc_7FF859C08E7A
    mov eax, dword ptr [rsp+0E4h]
    lea ecx, [rax+rax*4]
    lea eax, [rax+rcx*2]
    add eax, dword ptr [rsp+0E0h]
    sub eax, dword ptr [rsp+0DCh]
    add eax, dword ptr [rsp+0D4h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add eax, dword ptr [rsp+0D0h]
    mov dword ptr [rsp+0E8h], eax
    mov eax, dword ptr [dword_7FF85AB320A0]
    lea ecx, [rax+64FAFD8h]
    mov edx, ecx
    xor edx, -54360165h
    lea r8d, [rdx+1EE9B936h]
    mov r9d, r8d
    xor r9d, 602FF6C1h
    add edx, r9d
    neg edx
    add edx, eax
    add edx, 64FAFD8h
    sub edx, r8d
    add edx, 49EC2F21h
    xor edx, ecx
    xor edx, 6591A5D4h
    add r9d, eax
    add r9d, edx
    mov dword ptr [rsp+28h], r9d
    jmp loc_7FF859C070C4
    loc_7FF859C07F26:
    cmp eax, 54F5D79Bh
    jnz loc_7FF859C08EC9
    mov eax, dword ptr [rsp+3Ch]
    or eax, dword ptr [rsp+38h]
    mov dword ptr [rsp+0A4h], eax
    mov eax, dword ptr [dword_7FF85AB32078]
    mov ecx, eax
    xor ecx, -29041C0h
    mov edx, eax
    xor edx, 22E6565Dh
    lea r8d, [rdx-7488B950h]
    xor r8d, 25577886h
    mov r9d, 25D73782h
    sub r9d, r8d
    add r8d, 1C21FEB6h
    xor r8d, r9d
    add r8d, ecx
    xor r8d, eax
    add r8d, edx
    mov dword ptr [rsp+28h], r8d
    jmp loc_7FF859C070C4
    loc_7FF859C07F8A:
    cmp eax, 515FD69h
    jnz loc_7FF859C08F14
    mov rax, qword ptr [rsp+248h]
    movups xmm0, xmmword ptr [xmmword_7FF85AA27AA1+0Ch]
    movups xmmword ptr [rax+0Ch], xmm0
    movups xmm0, xmmword ptr [xmmword_7FF85AA27AA1]
    movups xmmword ptr [rax], xmm0
    mov rax, qword ptr [rsp+238h]
    mov dword ptr [rax], 70D4D8C7h
    mov eax, dword ptr [dword_7FF85AAD3EE0]
    mov dword ptr [rsp+44h], eax
    mov eax, dword ptr [dword_7FF85AB32050]
    mov ecx, eax
    xor ecx, -3D232D9Ch
    lea edx, [rcx+30D20698h]
    xor edx, -67E53066h
    sub edx, eax
    sub edx, ecx
    add edx, -547C5019h
    jmp loc_7FF859C070C0
    loc_7FF859C07FF3:
    mov eax, dword ptr [rsp+54h]
    mov ecx, eax
    not ecx
    add ecx, ecx
    or ecx, -50490C08h
    mov dword ptr [rsp+12Ch], ecx
    and eax, -28248604h
    mov dword ptr [rsp+130h], eax
    mov eax, dword ptr [dword_7FF85AB320B0]
    mov ecx, eax
    xor ecx, 204A7D25h
    lea edx, [rcx-6875D237h]
    xor edx, 36DD5D1Fh
    add ecx, eax
    add ecx, edx
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF859C070C4
    loc_7FF859C0803D:
    mov rax, qword ptr [rsp+240h]
    movups xmm0, xmmword ptr [xmmword_7FF85AA27A83+0Eh]
    movups xmmword ptr [rax+0Eh], xmm0
    movups xmm0, xmmword ptr [xmmword_7FF85AA27A83]
    movups xmmword ptr [rax], xmm0
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+30h]
    add rax, 7Ah
    mov qword ptr [rsp+248h], rax
    mov eax, dword ptr [dword_7FF85AB31FC0]
    mov ecx, eax
    xor ecx, -35C87A87h
    lea edx, [rcx-6E4D1BF0h]
    xor eax, 1BB3607Ah
    sub eax, edx
    add eax, ecx
    sub eax, edx
    add eax, 7700AA86h
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C080E8:
    mov eax, dword ptr [rsp+44h]
    not eax
    lea ecx, [rax+rax]
    mov dword ptr [rsp+70h], ecx
    and eax, -27E94420h
    mov dword ptr [rsp+74h], eax
    mov eax, dword ptr [dword_7FF85AB3205C]
    lea ecx, [rax+74C50530h]
    mov edx, ecx
    xor edx, 7B1C4A5Eh
    mov r8d, ecx
    xor r8d, 2B1C44B9h
    lea r9d, [r8+7B2AC642h]
    xor r9d, 4B933FF5h
    neg edx
    add eax, edx
    add eax, 74C50530h
    add eax, r9d
    xor ecx, -645CC62Fh
    add eax, ecx
    add eax, -10F58573h
    xor eax, r8d
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C0814F:
    mov rax, qword ptr [rsp+58h]
    mov rcx, rax
    and rcx, rbx
    lea rcx, [rcx+rcx*2]
    mov rdx, 19F27A509D43F3FBh
    and rax, rdx
    add rax, rax
    sub rax, rcx
    add rax, qword ptr [rsp+180h]
    sub rax, qword ptr [rsp+170h]
    sub rax, qword ptr [rsp+168h]
    mov qword ptr [rsp+188h], rax
    mov eax, dword ptr [dword_7FF85AB31FE8]
    mov ecx, 3A1984Dh
    sub ecx, eax
    xor eax, -174E9546h
    lea edx, [rax+60C52EE8h]
    xor ecx, edx
    mov r8d, edx
    xor r8d, -8EAA23Ch
    lea r9d, [r8-545ADDEFh]
    lea r10d, [r8+6C6F8C4Ah]
    xor r10d, ecx
    xor r10d, 373782F2h
    add r10d, r8d
    xor r9d, eax
    xor r9d, edx
    xor r9d, r10d
    mov dword ptr [rsp+28h], r9d
    jmp loc_7FF859C070C4
    loc_7FF859C081E3:
    mov eax, dword ptr [rsp+10Ch]
    sub eax, dword ptr [rsp+100h]
    add eax, dword ptr [rsp+0FCh]
    mov dword ptr [rsp+110h], eax
    mov eax, dword ptr [dword_7FF85AB32018]
    mov ecx, eax
    xor ecx, 0BFB7F74h
    mov edx, 225D5C10h
    sub edx, ecx
    xor edx, ecx
    sub edx, ecx
    sub edx, eax
    add edx, -21AA2195h
    jmp loc_7FF859C070C0
    loc_7FF859C08225:
    mov eax, dword ptr [dword_7FF85AB32034]
    mov ecx, -6DF5844Ah
    add eax, ecx
    mov ecx, eax
    xor ecx, -0E1F9BB2h
    mov edx, eax
    xor edx, -76A052Ch
    add edx, ecx
    sub edx, eax
    add edx, 2D71860Fh
    xor edx, eax
    xor eax, -404CA537h
    xor edx, -1B59A5DFh
    sub edx, eax
    jmp loc_7FF859C070C0
    loc_7FF859C08260:
    mov rax, qword ptr [rsp+68h]
    mov rcx, qword ptr [rsp+1D8h]
    and rcx, rax
    not rcx
    lea rdx, [rcx*8]
    sub rdx, rcx
    mov qword ptr [rsp+1E0h], rdx
    or rax, qword ptr [rsp+60h]
    add rax, rax
    lea rax, [rax+rax*2]
    mov qword ptr [rsp+1E8h], rax
    mov eax, dword ptr [dword_7FF85AB32024]
    lea ecx, [rax-60736405h]
    xor ecx, 763D191Dh
    lea edx, [rcx-48EA03EEh]
    mov r8d, edx
    xor r8d, 6C29778Fh
    add r8d, -2E4DA9A1h
    xor edx, 0CF74C4Eh
    add edx, ecx
    add edx, -48EA03EEh
    add edx, eax
    add edx, -60736405h
    xor edx, r8d
    add edx, ecx
    xor edx, eax
    jmp loc_7FF859C070C0
    loc_7FF859C082E5:
    mov rax, qword ptr [rsp+1B0h]
    add rax, qword ptr [rsp+198h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rax, qword ptr [rsp+190h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, -289FEDB2B9A1E32Ah
    add rax, rcx
    mov qword ptr [rsp+1B8h], rax
    mov rax, -79451897EFAFB559h
    sub rax, qword ptr [rsp+150h]
    mov qword ptr [rsp+1C0h], rax
    mov eax, dword ptr [dword_7FF85AB32000]
    lea ecx, [rax-2E3BB651h]
    mov edx, ecx
    xor edx, -21B409BBh
    lea r8d, [rdx+7F357D12h]
    xor r8d, 2761157Fh
    mov r9d, edx
    sub r9d, ecx
    lea ecx, [r9+r8]
    add ecx, -4587EBEFh
    add ecx, eax
    lea eax, [rdx+rcx]
    add eax, 7F357D12h
    add eax, r8d
    add eax, -774027Bh
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C0844D:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+218h]
    mov ecx, dword ptr [rsp+0C8h]
    mov dword ptr [rax], ecx
    mov eax, dword ptr [dword_7FF85AAD3EE4]
    mov dword ptr [rsp+40h], eax
    xor eax, -37E1C71Eh
    add eax, 566E8D3Ah
    mov dword ptr [rsp+2Ch], eax
    mov eax, dword ptr [dword_7FF85AB3208C]
    lea ecx, [rax-7BC25018h]
    xor ecx, 7D19F913h
    add ecx, 2CD113E2h
    mov edx, ecx
    xor edx, 0E9EBA12h
    add edx, 3674A389h
    xor edx, eax
    sub edx, ecx
    jmp loc_7FF859C070C0
    loc_7FF859C084E6:
    mov eax, dword ptr [rsp+130h]
    not eax
    shl eax, 2
    mov dword ptr [rsp+134h], eax
    mov eax, dword ptr [dword_7FF85AB320B4]
    lea ecx, [rax-0F6D8938h]
    xor ecx, -3CA156C9h
    mov edx, 76210E73h
    sub edx, eax
    xor edx, ecx
    add ecx, -442A724Eh
    lea eax, [rdx+rcx]
    add eax, -7E1B6FA9h
    xor eax, ecx
    add eax, 4307A27Ah
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C08532:
    mov rax, qword ptr [rsp+208h]
    mov byte ptr [rax], 0Eh
    mov rax, qword ptr [rsp+30h]
    add rax, 1Dh
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FF85AB3204C]
    mov ecx, 29FCF6D1h
    add eax, ecx
    xor eax, 48834903h
    lea ecx, [rax-26443D76h]
    xor ecx, 7B7EFA2Ch
    sub ecx, eax
    add ecx, -46D0875h
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF859C070C4
    loc_7FF859C085ED:
    mov eax, dword ptr [rsp+48h]
    mov ecx, -22D3DCACh
    add eax, ecx
    mov dword ptr [rsp+8Ch], eax
    xor eax, 58901329h
    mov dword ptr [rsp+90h], eax
    mov eax, dword ptr [dword_7FF85AB32040]
    lea ecx, [rax+41168DA9h]
    xor ecx, -6A2FB02h
    sub ecx, eax
    add ecx, eax
    add ecx, 41168DA9h
    add eax, ecx
    add eax, 50923C3Bh
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C08637:
    mov eax, dword ptr [rsp+2Ch]
    mov ecx, eax
    not ecx
    and ecx, 2DD3B981h
    add ecx, ecx
    lea ecx, [rcx+rcx*4]
    mov dword ptr [rsp+0D4h], ecx
    and eax, 2DD3B981h
    mov dword ptr [rsp+0D8h], eax
    mov eax, dword ptr [dword_7FF85AB32004]
    mov ecx, -8426EC1h
    xor eax, ecx
    add eax, eax
    mov ecx, -7A90A4A1h
    sub ecx, eax
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF859C070C4
    loc_7FF859C0867C:
    mov eax, dword ptr [rsp+40h]
    not eax
    and eax, 10117224h
    shl eax, 3
    mov dword ptr [rsp+104h], eax
    mov eax, dword ptr [dword_7FF85AB31FE4]
    lea ecx, [rax+4558DA6Dh]
    xor ecx, 39A7E9BFh
    add ecx, eax
    lea edx, [rax-746421D3h]
    add ecx, edx
    add ecx, -4B122F1Bh
    xor ecx, edx
    xor ecx, 12F4582h
    add ecx, eax
    add ecx, -599914CDh
    xor ecx, eax
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF859C070C4
    loc_7FF859C086CE:
    mov rax, qword ptr [rsp+1C0h]
    add rax, qword ptr [rsp+148h]
    sub rax, qword ptr [rsp+158h]
    sub rax, qword ptr [rsp+58h]
    add rax, qword ptr [rsp+1B8h]
    mov qword ptr [rsp+68h], rax
    or rax, qword ptr [rsp+60h]
    mov qword ptr [rsp+1C8h], rax
    mov eax, dword ptr [dword_7FF85AB32010]
    lea ecx, [rax+63F95B4Ch]
    xor ecx, -128B2DD6h
    lea edx, [rcx+5C36E6CDh]
    mov r8d, 0A3B719Fh
    sub r8d, ecx
    xor r8d, edx
    xor edx, 2A39F804h
    sub r8d, eax
    add eax, r8d
    add eax, 63F95B4Ch
    sub eax, edx
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C08745:
    mov eax, dword ptr [rsp+0F0h]
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
    shl eax, 3
    mov dword ptr [rsp+0F4h], eax
    mov eax, dword ptr [dword_7FF85AB320A4]
    mov ecx, eax
    xor ecx, 8A75590h
    lea edx, [rcx-3B11AA38h]
    xor edx, -49364296h
    sub edx, ecx
    add eax, edx
    add eax, 6A32379Fh
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C087CD:
    mov rax, qword ptr [rsp+1C8h]
    not rax
    lea rcx, [rax*8]
    sub rcx, rax
    mov qword ptr [rsp+1D0h], rcx
    mov rax, qword ptr [rsp+68h]
    not rax
    mov qword ptr [rsp+1D8h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FF85AB32014]
    lea ecx, [rax-2619EAAEh]
    lea edx, [rax-2CFF9B5Dh]
    lea r8d, [rax+13C2BAB7h]
    xor ecx, r8d
    xor r8d, -1C9E0500h
    add r8d, 4FE020DAh
    xor r8d, edx
    add eax, r8d
    add eax, 139B18B8h
    loc_7FF859C088A2:
    xor eax, ecx
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C088AD:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+108h]
    add eax, dword ptr [rsp+104h]
    mov dword ptr [rsp+10Ch], eax
    mov eax, dword ptr [dword_7FF85AB320A8]
    mov ecx, eax
    xor ecx, -1612B966h
    lea edx, [rcx+0A316D76h]
    mov r8d, edx
    xor r8d, -1E43A931h
    add r8d, 2AFBD66h
    mov r9d, r8d
    xor r9d, 35503AF2h
    lea r10d, [r9+53A3BB43h]
    add r9d, 5A9C502Ch
    xor r9d, r10d
    sub r9d, eax
    sub r9d, r8d
    xor r9d, ecx
    sub r9d, edx
    mov dword ptr [rsp+28h], r9d
    jmp loc_7FF859C070C4
    loc_7FF859C0896A:
    mov eax, dword ptr [dword_7FF85AB32028]
    mov ecx, eax
    xor ecx, -283480B5h
    mov edx, eax
    xor edx, 72C18D65h
    add eax, edx
    lea r8d, [rdx-3B69C3E6h]
    add eax, edx
    add eax, -6EF29100h
    xor eax, edx
    sub eax, ecx
    xor eax, r8d
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C089A0:
    mov eax, dword ptr [rsp+0C0h]
    sub eax, dword ptr [rsp+0A8h]
    sub eax, dword ptr [rsp+0A0h]
    add eax, dword ptr [rsp+9Ch]
    mov dword ptr [rsp+0C4h], eax
    mov eax, dword ptr [dword_7FF85AB32070]
    mov ecx, eax
    xor ecx, -2DA49DE0h
    lea edx, [rcx+106AAE7h]
    xor edx, -766853F9h
    add edx, ecx
    add edx, -236E5CA5h
    add ecx, -72E5DFh
    xor ecx, eax
    loc_7FF859C089ED:
    xor ecx, edx
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF859C070C4
    loc_7FF859C089F8:
    mov eax, dword ptr [rsp+2Ch]
    not eax
    mov dword ptr [rsp+0CCh], eax
    mov eax, dword ptr [dword_7FF85AB32090]
    lea ecx, [rax+440201B2h]
    xor ecx, -36E85DFAh
    add eax, ecx
    add eax, 74224880h
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C08A27:
    mov rax, qword ptr [rsp+30h]
    mov dword ptr [rax+17h], 5C9FE1F0h
    mov rax, qword ptr [rsp+30h]
    mov byte ptr [rax+1Bh], 4Ch
    mov eax, dword ptr [dword_7FF85AB32020]
    xor eax, edi
    lea ecx, [rax-585BCAD5h]
    xor ecx, eax
    xor ecx, -7904D880h
    sub ecx, eax
    add ecx, 2E02917Bh
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF859C070C4
    loc_7FF859C08A63:
    mov eax, dword ptr [rsp+110h]
    sub eax, dword ptr [rsp+0F8h]
    add eax, dword ptr [rsp+0F4h]
    sub eax, dword ptr [rsp+2Ch]
    sub eax, dword ptr [rsp+0ECh]
    mov dword ptr [rsp+114h], eax
    mov eax, dword ptr [dword_7FF85AAD3EE8]
    mov dword ptr [rsp+118h], eax
    add eax, -581C7B59h
    mov dword ptr [rsp+4Ch], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add eax, ebp
    mov dword ptr [rsp+11Ch], eax
    xor eax, 47BC8C6h
    mov dword ptr [rsp+50h], eax
    mov eax, dword ptr [dword_7FF85AB3207C]
    mov ecx, eax
    xor ecx, -72C24B30h
    add ecx, -48477A64h
    xor ecx, -7BBF6576h
    loc_7FF859C08B2C:
    add ecx, eax
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF859C070C4
    loc_7FF859C08B37:
    mov rax, qword ptr [rsp+1F8h]
    sub rax, qword ptr [rsp+1D0h]
    mov qword ptr [rsp+200h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FF85AB32030]
    lea ecx, [rax+2E3CBA8Dh]
    xor ecx, -61464EBFh
    lea edx, [rcx+1B876C80h]
    mov r8d, edx
    xor r8d, -53E84E6Bh
    lea r9d, [r8-78499179h]
    xor r9d, -7195805Ah
    sub r9d, edx
    add r9d, r8d
    xor eax, ecx
    xor eax, r9d
    sub eax, ecx
    add eax, -7D48D759h
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C08BFE:
    mov eax, dword ptr [rsp+54h]
    mov ecx, eax
    and ecx, 28248603h
    lea ecx, [rcx+rcx*2]
    and eax, 57DB79FCh
    add eax, eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub eax, ecx
    add eax, dword ptr [rsp+134h]
    sub eax, dword ptr [rsp+12Ch]
    sub eax, dword ptr [rsp+128h]
    sub eax, dword ptr [rsp+120h]
    mov dword ptr [rsp+138h], eax
    mov ecx, eax
    xor ecx, -4CDF3D52h
    xor eax, -0E95CBCBh
    mov dword ptr [rsp+13Ch], eax
    sub ecx, dword ptr [rsp+50h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add ecx, -1D430D39h
    mov dword ptr [rsp+140h], ecx
    mov eax, dword ptr [dword_7FF85AB31FDC]
    mov ecx, eax
    xor ecx, 629EA339h
    mov edx, eax
    xor edx, 48D55977h
    add edx, -1B3C9369h
    xor edx, -21FA93A2h
    loc_7FF859C08D35:
    sub edx, ecx
    xor edx, eax
    jmp loc_7FF859C070C0
    loc_7FF859C08D3E:
    mov rax, qword ptr [rsp+178h]
    shl rax, 2
    mov qword ptr [rsp+180h], rax
    mov eax, dword ptr [dword_7FF85AB31FF0]
    xor eax, r14d
    lea ecx, [rax-2DF6A8B0h]
    mov edx, ecx
    xor edx, -0A8E0476h
    lea r8d, [rdx+13D66CDCh]
    lea r9d, [rdx+23C10A92h]
    xor r8d, 2562E522h
    add r8d, edx
    add r8d, -3CE542FCh
    xor r9d, edx
    xor r9d, r8d
    sub r9d, ecx
    loc_7FF859C08D91:
    xor r9d, eax
    mov dword ptr [rsp+28h], r9d
    jmp loc_7FF859C070C4
    loc_7FF859C08D9E:
    mov r8d, dword ptr [rsp+144h]
    xor r8d, dword ptr [rsp+11Ch]
    add r8d, dword ptr [rsp+138h]
    add r8d, dword ptr [rsp+13Ch]
    sub r8d, dword ptr [rsp+4Ch]
    mov edx, dword ptr [rsp+114h]
    xor ecx, ecx
    xor r9d, r9d
    call qword ptr [CreateEventW]
    mov qword ptr [rsp+250h], rax
    mov eax, dword ptr [dword_7FF85AB32060]
    mov ecx, -43C1BA48h
    add eax, ecx
    xor eax, 274273ADh
    lea ecx, [rax-399742B0h]
    add eax, 68C13D49h
    mov edx, eax
    xor edx, -6E76841Eh
    xor eax, ecx
    xor eax, edx
    xor eax, 4DB842D5h
    sub eax, edx
    add eax, -16D13E3Ah
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C08E1B:
    mov eax, dword ptr [rsp+84h]
    add eax, dword ptr [rsp+80h]
    add eax, dword ptr [rsp+7Ch]
    add eax, dword ptr [rsp+78h]
    sub eax, dword ptr [rsp+70h]
    mov dword ptr [rsp+38h], eax
    xor eax, -0BC7AD0Ch
    mov dword ptr [rsp+88h], eax
    add eax, -197BC40Fh
    mov dword ptr [rsp+48h], eax
    mov eax, dword ptr [dword_7FF85AB32068]
    lea ecx, [rax-29CFD29Bh]
    xor ecx, -2015406h
    add ecx, eax
    add ecx, -29CFD29Bh
    neg ecx
    add eax, ecx
    add eax, -0AEC696Bh
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C08E7A:
    mov rax, qword ptr [rsp+68h]
    and rax, qword ptr [rsp+60h]
    mov qword ptr [rsp+1F0h], rax
    mov eax, dword ptr [dword_7FF85AB3202C]
    mov ecx, eax
    xor ecx, -400A8EFFh
    lea edx, [rcx-3318C6F7h]
    mov r8d, edx
    xor r8d, -54C68A7Bh
    xor eax, 32D2A85h
    sub eax, ecx
    add eax, r8d
    sub eax, edx
    add eax, 778CFDAEh
    xor eax, r8d
    add eax, ecx
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF859C070C4
    loc_7FF859C08EC9:
    mov eax, dword ptr [rsp+0C4h]
    xor eax, dword ptr [rsp+44h]
    add eax, dword ptr [rsp+94h]
    sub eax, dword ptr [rsp+8Ch]
    sub eax, dword ptr [rsp+88h]
    mov dword ptr [rsp+0C8h], eax
    mov eax, dword ptr [dword_7FF85AB32038]
    mov ecx, eax
    xor ecx, 7EB5705Ah
    add ecx, eax
    mov edx, -33D03C98h
    sub edx, ecx
    xor edx, eax
    xor edx, -219417C1h
    jmp loc_7FF859C070C0
    loc_7FF859C08F14:
    mov rax, -14783AF53CE68813h
    xor rax, qword ptr [rsp+250h]
    mov rcx, qword ptr [rsp+230h]
    mov qword ptr [rcx], rax
    mov rdx, qword ptr [rsp+228h]
    mov ecx, 1Fh
    mov r8d, 64h
    mov r9d, 47h
    call sub_7FF8597D72F0
    mov rax, qword ptr [rsp+30h]
    add rsp, 258h
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

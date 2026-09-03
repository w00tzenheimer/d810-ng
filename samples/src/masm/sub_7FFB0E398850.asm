; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: sub_7FFB0E398850  @ 0x7ffb0e398850
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN __security_check_cookie:PROC
EXTERN sub_7FFB0E2ADB60:PROC
EXTERN sub_7FFB0E8830E0:PROC
EXTERN sub_7FFB0EA6EAB0:PROC
EXTERN sub_7FFB0EAA6C70:PROC
EXTERN sub_7FFB0EE4B6C0:PROC
EXTERN sub_7FFB0EEA1FE0:PROC
EXTERN sub_7FFB0EF33730:PROC
EXTERN sub_7FFB0F740560:PROC
EXTERN sub_7FFB0F874C30:PROC

CONST SEGMENT
__security_cookie dq 77104A6308CEh
qword_7FFB0FE92110 dq 7FFC7F0E0000h
dword_7FFB0FE92168 dd 26B000h
dword_7FFB0FEA1468 dd 624BC6DCh
qword_7FFB0FEA1470 dq -237136F7DC326AFCh
dword_7FFB0FEA1478 dd 51A6FF2Dh
dword_7FFB0FEA147C dd 35B39841h
dword_7FFB0FEA1480 dd 3484E11h
dword_7FFB0FEA1484 dd 59ACE19Eh
dword_7FFB0FEA1488 dd 63F52073h
qword_7FFB0FEA1490 dq -57044E8C308DB88h
dword_7FFB0FEA1498 dd 0BBB0E4ABh
byte_7FFB0FEA149C db 9Ah
dword_7FFB0FEA14A0 dd 1E2B756Bh
dword_7FFB0FEE5A6C dd 7231962Bh
dword_7FFB0FEE5A70 dd 0B223EF8Fh
dword_7FFB0FEE5A74 dd 830338DBh
dword_7FFB0FEE5A78 dd 722D0522h
dword_7FFB0FEE5A7C dd 0B0758C95h
dword_7FFB0FEE5A80 dd 977FDA4Dh
dword_7FFB0FEE5A84 dd 0B1872FA3h
dword_7FFB0FEE5A88 dd 0E0C52A78h
dword_7FFB0FEE5A8C dd 90D86D1Bh
dword_7FFB0FEE5A90 dd 905E5667h
dword_7FFB0FEE5A94 dd 9913894Ch
dword_7FFB0FEE5A98 dd 0A56969AAh
dword_7FFB0FEE5A9C dd 0E5988737h
dword_7FFB0FEE5AA0 dd 726CC400h
dword_7FFB0FEE5AA4 dd 0A995F0DBh
dword_7FFB0FEE5AA8 dd 19CE5CBBh
dword_7FFB0FEE5AAC dd 7882BAEBh
dword_7FFB0FEE5AB0 dd 94345ECBh
dword_7FFB0FEE5AB4 dd 4B4394ACh
dword_7FFB0FEE5AB8 dd 8BB20BD6h
dword_7FFB0FEE5ABC dd 48EB5CA3h
dword_7FFB0FEE5AC0 dd 6900152Fh
dword_7FFB0FEE5AC4 dd 28733888h
dword_7FFB0FEE5AC8 dd 0A090B4ACh
dword_7FFB0FEE5ACC dd 96C85879h
dword_7FFB0FEE5AD0 dd 40F02BA8h
dword_7FFB0FEE5AD4 dd 6C63AC2Dh
dword_7FFB0FEE5AD8 dd 0A367C24h
dword_7FFB0FEE5ADC dd 0D525F644h
dword_7FFB0FEE5AE0 dd 6BB98B19h
dword_7FFB0FEE5AE4 dd 263E5249h
dword_7FFB0FEE5AE8 dd 39065D21h
dword_7FFB0FEE5AEC dd 1383528Eh
dword_7FFB0FEE5AF0 dd 4E85780Ch
dword_7FFB0FEE5AF4 dd 8CDC405h
dword_7FFB0FEE5AF8 dd 91C11BD7h
dword_7FFB0FEE5AFC dd 98966A43h
dword_7FFB0FEE5B00 dd 40224F53h
dword_7FFB0FEE5B04 dd 3EE6B850h
dword_7FFB0FEE5B08 dd 0D6ED96C8h
dword_7FFB0FEE5B0C dd 0F6D558CBh
dword_7FFB0FEE5B10 dd 0A69E46E7h
dword_7FFB0FEE5B14 dd 74944F50h
dword_7FFB0FEE5B18 dd 0C25A5B3Eh
dword_7FFB0FEE5B1C dd 4D820F51h
dword_7FFB0FEE5B20 dd 8D3B2C7Bh
dword_7FFB0FEE5B24 dd 0F159F881h
dword_7FFB0FEE5B28 dd 754A3927h
dword_7FFB0FEE5B2C dd 304F387Dh
dword_7FFB0FEE5B30 dd 904ADE84h
dword_7FFB0FEE5B34 dd 4A6971C3h
dword_7FFB0FEE5B38 dd 0BF14A216h
dword_7FFB0FEE5B3C dd 0D80B0595h
dword_7FFB0FEE5B40 dd 68F75FFh
dword_7FFB0FEE5B44 dd 4983C24Eh
dword_7FFB0FEE5B48 dd 0E6637E5Fh
dword_7FFB0FEE5B4C dd 65ED40A8h
dword_7FFB0FEE5B50 dd 0EF5CCA05h
dword_7FFB0FEE5B54 dd 0E1FF1A8Ch
dword_7FFB0FEE5B58 dd 802F63C2h
dword_7FFB0FEE5B5C dd 0F285047Ch
dword_7FFB0FEE5B60 dd 0A63C4EB3h
dword_7FFB0FEE5B64 dd 0F4D9B77Ah
dword_7FFB0FEE5B68 dd 4178F42Dh
dword_7FFB0FEE5B6C dd 2EB6AAC7h
dword_7FFB0FEE5B70 dd 50CB8216h
dword_7FFB0FEE5B74 dd 0C3F37B95h
dword_7FFB0FEE5B78 dd 7E538816h
dword_7FFB0FEE5B7C dd 95D86538h
dword_7FFB0FEE5B80 dd 0F0FCE83Bh
dword_7FFB0FEE5B84 dd 2226270Eh
dword_7FFB0FEE5B88 dd 61B02493h
dword_7FFB0FEE5B8C dd 44EE5328h
dword_7FFB0FEE5B90 dd 0C6A8C1A7h
qword_7FFB0FF56B08 dq -1
dword_7FFB0FF56B10 dd 0FFFFFFFFh
qword_7FFB0FF56B18 dq -1
qword_7FFB0FF56B20 dq -1
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC sub_7FFB0E398850
sub_7FFB0E398850:
    push r15
    push r14
    push r13
    push r12
    push rsi
    push rdi
    push rbp
    push rbx
    sub rsp, 428h
    mov rsi, rcx
    mov rax, qword ptr [__security_cookie]
    xor rax, rsp
    mov qword ptr [rsp+420h], rax
    mov r14, 7D25BC4B17664007h
    mov eax, dword ptr [dword_7FFB0FEE5A70]
    mov ecx, eax
    xor ecx, -78B8F7Fh
    mov edx, eax
    xor edx, -136AF67Dh
    sub ecx, edx
    add ecx, -73911537h
    xor ecx, eax
    lea eax, [rcx+rdx]
    add eax, 4DCE7AE8h
    mov dword ptr [rsp+30h], eax
    mov r15, -13DCF3D39450CA52h
    mov rdi, -130AA66E7DD7869Ch
    mov rbp, 5FE674D546B6348Dh
    mov r12, -1493E338F648473h
    mov r13, 20F301791121B0DCh
    jmp loc_7FFB0E398956
    loc_7FFB0E3988E2:
    mov r8d, dword ptr [rsp+15Ch]
    mov eax, -30000000h
    or r8d, eax
    mov ecx, 56h
    mov edx, 49h
    mov r9d, 3Fh
    call sub_7FFB0EAA6C70
    loc_7FFB0E398907:
    mov eax, dword ptr [dword_7FFB0FEA14A0]
    mov dword ptr [rsp+0FCh], eax
    add eax, 264ACCCh
    mov dword ptr [rsp+48h], eax
    mov eax, dword ptr [dword_7FFB0FEE5A90]
    lea ecx, [rax-5DFEE9A1h]
    lea edx, [rax+1AE4BF18h]
    mov r8d, 0D4EAA71h
    sub r8d, eax
    xor r8d, edx
    sub r8d, eax
    add r8d, -34655354h
    xor ecx, eax
    xor ecx, r8d
    sub ecx, eax
    add ecx, 418223B7h
    loc_7FFB0E398952:
    mov dword ptr [rsp+30h], ecx
    loc_7FFB0E398956:
    mov eax, dword ptr [rsp+30h]
    cmp eax, 3C7DB668h
    jle loc_7FFB0E398A00
    cmp eax, 68838EADh
    jle loc_7FFB0E398AB0
    cmp eax, 73DBE913h
    jg loc_7FFB0E398BE7
    cmp eax, 6C73B328h
    jle loc_7FFB0E3991FA
    cmp eax, 6F95F6EFh
    jle loc_7FFB0E399FD7
    cmp eax, 6F95F6F0h
    jz loc_7FFB0E39B2CE
    cmp eax, 6FB6D410h
    jnz loc_7FFB0E398907
    movzx eax, byte ptr [rsp+46h]
    sub al, byte ptr [rsp+45h]
    add al, byte ptr [rsp+43h]
    mov byte ptr [rsp+47h], al
    mov eax, dword ptr [dword_7FFB0FEE5B34]
    mov ecx, eax
    xor ecx, -56CC4B23h
    lea edx, [rcx-5D940409h]
    xor edx, -9C0039h
    lea r8d, [rdx+3DEB230Eh]
    add edx, 7EC645CDh
    xor edx, 675D5155h
    add edx, ecx
    add edx, -5D940409h
    sub edx, eax
    sub edx, ecx
    xor edx, r8d
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E398A00:
    cmp eax, 18E12B84h
    jle loc_7FFB0E398B70
    cmp eax, 281DE791h
    jle loc_7FFB0E398E96
    cmp eax, 37495B7Ah
    jg loc_7FFB0E398F62
    cmp eax, 31DC4741h
    jle loc_7FFB0E3999EB
    cmp eax, 31DC4742h
    jz loc_7FFB0E39A2AD
    cmp eax, 32825589h
    jz loc_7FFB0E398907
    mov eax, dword ptr [rsp+0E0h]
    imul rax, qword ptr [rsp+1C0h]
    mov qword ptr [rsp+1C8h], rax
    mov rax, qword ptr [qword_7FFB0FEA1470]
    mov qword ptr [rsp+1D0h], rax
    mov rcx, -4FE0041A1B5CEFEBh
    xor rax, rcx
    mov qword ptr [rsp+88h], rax
    mov eax, dword ptr [dword_7FFB0FEE5AD0]
    lea ecx, [rax+11E2A251h]
    xor ecx, -43C7FC24h
    add ecx, eax
    add ecx, eax
    add ecx, 11E2A251h
    add ecx, eax
    mov eax, 149FBC10h
    jmp loc_7FFB0E39A817
    loc_7FFB0E398AB0:
    cmp eax, 5101C8A1h
    jg loc_7FFB0E398C4F
    cmp eax, 4640A3D6h
    jle loc_7FFB0E3994DF
    cmp eax, 4B21D23Fh
    jle loc_7FFB0E39A116
    cmp eax, 4B21D240h
    jz loc_7FFB0E39ADAB
    cmp eax, 4B2FB66Eh
    jnz loc_7FFB0E39B40B
    mov r8, qword ptr [rsp+60h]
    lea rax, [rsp+2C8h]
    mov qword ptr [rsp+20h], rax
    mov ecx, 37h
    mov edx, 0Eh
    mov r9d, 0Ah
    call sub_7FFB0EF33730
    mov eax, dword ptr [dword_7FFB0FEE5B38]
    lea ecx, [rax-791EF82Bh]
    xor ecx, -0ADBBD65h
    lea edx, [rcx-5554785Bh]
    mov r8d, edx
    xor r8d, -28A914C4h
    mov r9d, ecx
    sub r9d, eax
    add r9d, 20678BC0h
    xor r9d, edx
    add r9d, r8d
    xor r9d, edx
    xor r9d, -74E2D52Fh
    add ecx, ecx
    sub r9d, ecx
    add r9d, -30627CD0h
    mov dword ptr [rsp+30h], r9d
    jmp loc_7FFB0E398956
    loc_7FFB0E398B70:
    cmp eax, 0E75C780h
    jg loc_7FFB0E398CDB
    cmp eax, 6BB5DDDh
    jle loc_7FFB0E398FCD
    cmp eax, 0AFBB177h
    jle loc_7FFB0E399861
    cmp eax, 0AFBB178h
    jz loc_7FFB0E39A21D
    cmp eax, 0BD31BA6h
    jnz loc_7FFB0E39A863
    mov eax, dword ptr [rsp+128h]
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+12Ch], eax
    mov eax, dword ptr [rsp+54h]
    mov ecx, 7CF03F77h
    xor eax, ecx
    lea ecx, [rax*8]
    sub ecx, eax
    mov dword ptr [rsp+130h], ecx
    mov eax, dword ptr [dword_7FFB0FEE5A78]
    add eax, eax
    mov ecx, 5B674C50h
    sub ecx, eax
    jmp loc_7FFB0E398952
    loc_7FFB0E398BE7:
    cmp eax, 770D420Bh
    jle loc_7FFB0E399427
    cmp eax, 7D021311h
    jle loc_7FFB0E39A0B4
    cmp eax, 7D021312h
    jz loc_7FFB0E39AA0B
    cmp eax, 7E16A597h
    jnz loc_7FFB0E39B215
    mov eax, dword ptr [dword_7FFB0FEE5B20]
    lea ecx, [rax+1B0EF76Dh]
    lea edx, [rax+27F89A7Ch]
    mov r8d, edx
    xor r8d, -5A49EEF6h
    mov r10d, 4C8C5DA0h
    sub r10d, eax
    sub r10d, r8d
    xor eax, edx
    xor eax, r10d
    xor eax, -37F86A9Ah
    add eax, r8d
    sub eax, edx
    jmp loc_7FFB0E39AFB0
    loc_7FFB0E398C4F:
    cmp eax, 5D231862h
    jle loc_7FFB0E399561
    cmp eax, 62127A6Ah
    jg loc_7FFB0E39972D
    cmp eax, 5D231863h
    jz loc_7FFB0E39B6B5
    cmp eax, 5E9A1188h
    jnz loc_7FFB0E39BB7E
    movzx eax, byte ptr [rsp+38h]
    xor al, 97h
    mov byte ptr [rsp+3Dh], al
    mov eax, dword ptr [dword_7FFB0FEE5B18]
    mov ecx, eax
    xor ecx, -5EA1CE21h
    lea edx, [rcx-5E8904C9h]
    mov r8d, edx
    xor r8d, -37306A4Fh
    mov r9d, 57EFB2B4h
    sub r9d, ecx
    xor r9d, ecx
    sub r9d, eax
    sub r9d, r8d
    xor r9d, edx
    xor edx, 6A906C5Eh
    xor r9d, -1BDD0E6Ah
    sub r9d, edx
    lea eax, [r9+rcx]
    add eax, -5E8904C9h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E398CDB:
    cmp eax, 12DE3D68h
    jle loc_7FFB0E399190
    cmp eax, 15A3B686h
    jle loc_7FFB0E399806
    cmp eax, 160CB3B4h
    jz loc_7FFB0E39AC6B
    cmp eax, 16A1AEF5h
    jnz loc_7FFB0E39BB98
    mov eax, dword ptr [rsp+4Ch]
    mov ecx, 232AC029h
    and eax, ecx
    lea eax, [rax+rax*2]
    mov ecx, dword ptr [rsp+0A8h]
    sub ecx, eax
    add ecx, dword ptr [rsp+0A4h]
    add ecx, dword ptr [rsp+0A0h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub ecx, dword ptr [rsp+9Ch]
    lea eax, [rcx+0DA23D6h]
    mov dword ptr [rsp+0ACh], eax
    lea eax, [rcx-59334A1Fh]
    mov dword ptr [rsp+68h], eax
    lea eax, [rcx-692359DEh]
    mov dword ptr [rsp+6Ch], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add eax, ecx
    add eax, 709EF576h
    mov dword ptr [rsp+0B0h], eax
    mov ecx, dword ptr [rsp+68h]
    mov edx, ecx
    not edx
    lea r8d, [rdx+rdx]
    mov dword ptr [rsp+0B4h], r8d
    mov r8d, eax
    or r8d, edx
    not r8d
    mov dword ptr [rsp+0B8h], r8d
    or ecx, eax
    not ecx
    shl ecx, 2
    mov dword ptr [rsp+0BCh], ecx
    and edx, eax
    not edx
    mov dword ptr [rsp+0C0h], edx
    mov eax, dword ptr [dword_7FFB0FEE5A80]
    lea ecx, [rax-693D7E23h]
    add eax, -3C8C13DFh
    mov edx, eax
    xor edx, -5103E5Fh
    lea r8d, [rdx-43C7FC13h]
    sub eax, r8d
    add eax, edx
    add eax, -578B4F4h
    xor ecx, r8d
    xor ecx, eax
    xor ecx, -566171C9h
    jmp loc_7FFB0E398952
    loc_7FFB0E398E96:
    cmp eax, 208318D6h
    jle loc_7FFB0E39948E
    cmp eax, 223A3BB9h
    jle loc_7FFB0E399A96
    cmp eax, 223A3BBAh
    jz loc_7FFB0E39B06A
    cmp eax, 22C1A29Dh
    jnz loc_7FFB0E39BA33
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp byte ptr [rsp+3Bh], 1
    jnz loc_7FFB0E39B862
    mov rax, qword ptr [rsp+288h]
    add rax, qword ptr [rsp+290h]
    cmp rax, qword ptr [rsp+60h]
    jbe loc_7FFB0E39B862
    mov eax, dword ptr [dword_7FFB0FEE5B60]
    mov ecx, eax
    xor ecx, -3E9E523h
    mov edx, eax
    xor edx, 2F49A398h
    add edx, ecx
    sub edx, eax
    add edx, 2E62D996h
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E398F62:
    cmp eax, 3B08664Bh
    jg loc_7FFB0E3997A6
    cmp eax, 37495B7Bh
    jz loc_7FFB0E39A618
    cmp eax, 3A6FB9A6h
    jnz loc_7FFB0E39BA40
    mov eax, dword ptr [dword_7FFB0FEE5AE0]
    lea ecx, [rax-751E3BDBh]
    sub eax, ecx
    xor ecx, -121A8128h
    lea edx, [rcx+44972B92h]
    sub eax, edx
    xor edx, -60ABDB4Dh
    add edx, 28EED280h
    mov r8d, edx
    xor r8d, -372116A1h
    add r8d, eax
    sub r8d, edx
    lea eax, [r8+rcx]
    add eax, 3ED87E80h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E398FCD:
    cmp eax, 17520B5h
    jg loc_7FFB0E39976A
    cmp eax, 69EF2Bh
    jnz loc_7FFB0E39A353
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [rsp+138h]
    sub ecx, dword ptr [rsp+124h]
    sub ecx, dword ptr [rsp+120h]
    mov eax, ecx
    xor eax, 103380CFh
    mov edx, dword ptr [rsp+54h]
    add eax, edx
    add eax, 1B78569Dh
    xor eax, ecx
    xor ecx, 0F981071h
    sub eax, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add eax, dword ptr [rsp+11Ch]
    add eax, dword ptr [rsp+118h]
    mov dword ptr [rsp+13Ch], eax
    mov edx, dword ptr [rsp+74h]
    mov ecx, edx
    not ecx
    mov r8d, eax
    or r8d, ecx
    mov dword ptr [rsp+14Ch], r8d
    not r8d
    lea r9d, [r8*8]
    sub r9d, r8d
    mov dword ptr [rsp+140h], r9d
    or edx, eax
    not edx
    mov r8d, edx
    shl r8d, 4
    add r8d, edx
    mov dword ptr [rsp+144h], r8d
    and ecx, eax
    not ecx
    add ecx, ecx
    lea eax, [rcx+rcx*2]
    mov dword ptr [rsp+148h], eax
    mov eax, dword ptr [dword_7FFB0FEE5B64]
    lea ecx, [rax-6B815812h]
    xor ecx, -61663769h
    lea edx, [rcx+552CE53Dh]
    xor edx, -65652847h
    lea r8d, [rax-1EF1045Eh]
    xor r8d, edx
    xor r8d, -17941B58h
    add edx, ecx
    add edx, r8d
    sub edx, eax
    add edx, 3626E0C1h
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E399190:
    cmp eax, 125C141Fh
    jg loc_7FFB0E399944
    cmp eax, 0E75C781h
    jnz loc_7FFB0E39ACC6
    mov eax, dword ptr [dword_7FFB0FEE5AA0]
    lea ecx, [rax-5E70BB67h]
    mov edx, ecx
    xor edx, -63DD95FAh
    lea r8d, [rdx+7771FC7Bh]
    mov r9d, 3A14F347h
    sub r9d, edx
    xor r9d, r8d
    add r9d, edx
    sub r9d, ecx
    xor ecx, -676D6F8Dh
    xor r8d, 22B920EDh
    add r8d, eax
    add r8d, r9d
    sub r8d, ecx
    add r8d, 263AD554h
    mov dword ptr [rsp+30h], r8d
    jmp loc_7FFB0E398956
    loc_7FFB0E3991FA:
    cmp eax, 6A0816D8h
    jg loc_7FFB0E399B06
    cmp eax, 68838EAEh
    jnz loc_7FFB0E39AF72
    mov rax, qword ptr [rsp+278h]
    lea rcx, [rax*8]
    mov rdx, qword ptr [rsp+1B8h]
    mov r8, rdx
    not r8
    and r8, r14
    shl r8, 3
    and rdx, r14
    add rdx, rdx
    sub r8, rdx
    sub rax, rcx
    add rax, r8
    add rax, qword ptr [rsp+270h]
    sub rax, qword ptr [rsp+268h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rax, qword ptr [rsp+260h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rax, qword ptr [rsp+238h]
    add rax, qword ptr [rsp+240h]
    xor rax, qword ptr [rsp+250h]
    xor rax, qword ptr [rsp+248h]
    sub rax, qword ptr [rsp+258h]
    xor rax, qword ptr [rsp+230h]
    mov qword ptr [rsp+280h], rax
    mov qword ptr [rsp+288h], rax
    mov eax, dword ptr [dword_7FFB0FF56B10]
    mov dword ptr [rsp+0E8h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FEA1498]
    mov dword ptr [rsp+0ECh], eax
    add eax, -9E3AC75h
    mov dword ptr [rsp+50h], eax
    not eax
    and eax, 63A010C7h
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+0F0h], eax
    mov eax, dword ptr [dword_7FFB0FEE5B04]
    mov ecx, eax
    xor ecx, 47D221E1h
    lea edx, [rcx-586D0B39h]
    mov r8d, edx
    xor r8d, 1A0C3565h
    xor eax, -70D71206h
    sub eax, r8d
    add r8d, -6DFEAD82h
    xor eax, edx
    sub eax, ecx
    xor eax, r8d
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E399427:
    cmp eax, 758FF472h
    jg loc_7FFB0E399D50
    cmp eax, 73DBE914h
    jnz loc_7FFB0E39AFBB
    mov eax, dword ptr [rsp+0E4h]
    sub eax, dword ptr [rsp+0DCh]
    cmp eax, 493DFh
    jbe loc_7FFB0E39B8D5
    mov eax, dword ptr [dword_7FFB0FEE5B7C]
    lea ecx, [rax+136D603Bh]
    xor ecx, 4F33B63Fh
    lea edx, [rcx+7DF03C8Ah]
    mov r8d, eax
    sub r8d, edx
    add eax, r8d
    add eax, 136D603Bh
    sub eax, ecx
    add eax, edx
    add eax, 343B926h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39948E:
    cmp eax, 1B7B68FBh
    jg loc_7FFB0E399DC5
    cmp eax, 18E12B85h
    jnz loc_7FFB0E39B095
    mov eax, dword ptr [rsp+110h]
    add eax, dword ptr [rsp+104h]
    mov dword ptr [rsp+114h], eax
    mov eax, dword ptr [dword_7FFB0FEE5A84]
    mov ecx, eax
    xor ecx, -155140BEh
    lea edx, [rcx+5BA66455h]
    add eax, -4914660Ah
    xor eax, edx
    add eax, ecx
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E3994DF:
    cmp eax, 4298026Eh
    jg loc_7FFB0E399E8E
    cmp eax, 3C7DB669h
    jz loc_7FFB0E3988E2
    mov eax, dword ptr [rsp+70h]
    and eax, dword ptr [rsp+6Ch]
    imul eax, 0F5h
    add eax, dword ptr [rsp+0D4h]
    add eax, dword ptr [rsp+0D0h]
    sub eax, dword ptr [rsp+0CCh]
    sub eax, dword ptr [rsp+0C8h]
    mov dword ptr [rsp+0D8h], eax
    mov eax, dword ptr [dword_7FFB0FEE5AB4]
    lea ecx, [rax-22812FC5h]
    lea edx, [rax-2C05E835h]
    mov r8d, eax
    add r8d, -4581D5DAh
    xor r8d, edx
    xor edx, -6D3F513Bh
    add edx, eax
    add eax, edx
    add eax, 4A994217h
    xor r8d, ecx
    xor r8d, eax
    mov dword ptr [rsp+30h], r8d
    jmp loc_7FFB0E398956
    loc_7FFB0E399561:
    cmp eax, 5C6BAA18h
    jg loc_7FFB0E39A183
    cmp eax, 5101C8A2h
    jnz loc_7FFB0E39B4C1
    mov rax, qword ptr [rsp+88h]
    mov rcx, -6FF1DC490BB6BC45h
    add rcx, rax
    mov rdx, 4C80A5512F845161h
    sub rdx, qword ptr [rsp+1D0h]
    mov qword ptr [rsp+1D8h], rcx
    mov qword ptr [rsp+90h], rdx
    mov rcx, rax
    not rcx
    lea r8, [rcx+rcx]
    lea r8, [r8+r8*2]
    mov qword ptr [rsp+1E0h], r8
    or rcx, rdx
    not rcx
    mov qword ptr [rsp+1E8h], rcx
    or rdx, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not rdx
    add rdx, rdx
    lea rax, [rdx+rdx*2]
    mov qword ptr [rsp+1F0h], rax
    mov rax, qword ptr [rsp+90h]
    lea rax, [rax+rax*2]
    mov qword ptr [rsp+1F8h], rax
    mov rax, qword ptr [rsp+88h]
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
    and rax, qword ptr [rsp+90h]
    shl rax, 2
    mov qword ptr [rsp+200h], rax
    mov eax, dword ptr [dword_7FFB0FEE5AD4]
    lea ecx, [rax-10DA3F8Ch]
    mov edx, ecx
    xor edx, 2754EDE3h
    lea r8d, [rdx+1DE96482h]
    lea r9d, [rdx+49B7DAAFh]
    lea r10d, [rdx+2C792301h]
    xor r10d, r8d
    xor r9d, ecx
    xor r9d, r10d
    sub r9d, eax
    lea eax, [rdx+r9]
    add eax, 5516D785h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39972D:
    cmp eax, 62127A6Bh
    jz loc_7FFB0E39B74B
    cmp eax, 635681C9h
    jnz loc_7FFB0E39BA33
    mov eax, dword ptr [dword_7FFB0FEE5B2C]
    lea ecx, [rax-4630CA5Bh]
    mov edx, ecx
    xor edx, 1C7E8B32h
    sub edx, eax
    sub edx, ecx
    add edx, -6BD2BDC1h
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E39976A:
    cmp eax, 17520B6h
    jnz loc_7FFB0E39A7E4
    movzx eax, byte ptr [rsp+41h]
    sub al, byte ptr [rsp+40h]
    add al, byte ptr [rsp+3Ah]
    mov byte ptr [rsp+42h], al
    mov eax, dword ptr [dword_7FFB0FEE5B0C]
    lea ecx, 42EDB240h[rax*2]
    add eax, ecx
    add eax, 42EDB240h
    mov ecx, -18A27E0Dh
    sub ecx, eax
    jmp loc_7FFB0E398952
    loc_7FFB0E3997A6:
    cmp eax, 3B08664Ch
    jnz loc_7FFB0E39A822
    mov rcx, qword ptr [rsp+60h]
    mov edx, 5
    mov r8d, 3Bh
    mov r9d, 44h
    call sub_7FFB0EA6EAB0
    test al, al
    jz loc_7FFB0E39B8C1
    mov eax, dword ptr [dword_7FFB0FEE5B3C]
    lea ecx, [rax+2B5E786Bh]
    xor ecx, 46523DBDh
    add ecx, -40F5B3FFh
    mov edx, ecx
    xor edx, -62EFAFEBh
    sub edx, ecx
    add eax, edx
    add eax, -26DAB1ABh
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E399806:
    cmp eax, 12DE3D69h
    jnz loc_7FFB0E39A9AE
    mov eax, dword ptr [dword_7FFB0FEE5AF0]
    lea ecx, [rax-4CCB141Eh]
    lea edx, [rax+790DD58Ah]
    mov r8d, edx
    xor r8d, 3C75E2A3h
    mov r9d, -56617802h
    sub r9d, r8d
    xor r8d, ecx
    xor r8d, r9d
    lea ecx, [rax+r8]
    add ecx, 32C51880h
    xor edx, eax
    xor edx, ecx
    xor edx, -362E4FEDh
    sub edx, eax
    add edx, 33413675h
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E399861:
    cmp eax, 6BB5DDEh
    jnz loc_7FFB0E39AA21
    mov eax, dword ptr [rsp+4Ch]
    not eax
    mov ecx, eax
    and ecx, 232AC029h
    mov dword ptr [rsp+9Ch], ecx
    and eax, 5CD53FD6h
    add eax, eax
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+0A0h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    lea ecx, [rax+rax*2]
    mov dword ptr [rsp+0A4h], ecx
    and eax, 1CD53FD6h
    shl eax, 2
    mov dword ptr [rsp+0A8h], eax
    mov eax, dword ptr [dword_7FFB0FEE5A94]
    lea ecx, [rax+28171834h]
    mov edx, ecx
    xor edx, 15ADA99Ch
    xor ecx, -13C37B36h
    add edx, eax
    sub edx, ecx
    sub edx, ecx
    add edx, 3336821h
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E399944:
    cmp eax, 125C1420h
    jnz loc_7FFB0E39AD02
    movzx eax, byte ptr [rsp+3Dh]
    add al, 6Eh
    mov byte ptr [rsp+36h], al
    mov ecx, eax
    xor cl, 36h
    mov byte ptr [rsp+3Eh], cl
    xor al, 0B1h
    mov byte ptr [rsp+39h], al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FEE5B24]
    lea ecx, 0FFFFFFFFDEEE5156h[rax*2]
    add eax, eax
    add eax, ecx
    mov ecx, -50AE1B2Eh
    sub ecx, eax
    jmp loc_7FFB0E398952
    loc_7FFB0E3999EB:
    cmp eax, 281DE792h
    jnz loc_7FFB0E39AD4D
    mov rax, qword ptr [rsp+208h]
    add rax, qword ptr [rsp+1F0h]
    sub rax, qword ptr [rsp+1E8h]
    sub rax, qword ptr [rsp+1E0h]
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
    mov eax, dword ptr [dword_7FFB0FEE5AE4]
    mov ecx, eax
    xor ecx, -48D09D41h
    mov edx, eax
    xor edx, 753B522Dh
    mov r8d, eax
    xor r8d, 69483BD5h
    add r8d, edx
    add r8d, ecx
    add eax, r8d
    add eax, -27EEA5FDh
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E399A96:
    cmp eax, 208318D7h
    jnz loc_7FFB0E39AE8C
    movzx eax, byte ptr [rsp+42h]
    add al, byte ptr [rsp+3Fh]
    mov byte ptr [rsp+37h], al
    movzx eax, byte ptr [rsp+36h]
    not al
    lea ecx, [rax+rax]
    mov byte ptr [rsp+43h], cl
    mov byte ptr [rsp+44h], al
    mov eax, dword ptr [dword_7FFB0FEE5AC0]
    mov ecx, eax
    xor ecx, 2026DA81h
    lea edx, 1189BC6h[rcx*2]
    lea r8d, [rcx+1189BC6h]
    mov r9d, r8d
    xor r9d, -7A09DF6Ch
    sub edx, r9d
    xor r8d, 1FD2D683h
    add edx, -29EFBFCFh
    xor edx, ecx
    sub edx, eax
    sub edx, r8d
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E399B06:
    cmp eax, 6A0816D9h
    jnz loc_7FFB0E398907
    mov edx, dword ptr [rsp+190h]
    xor edx, dword ptr [rsp+18Ch]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9, qword ptr [rsp+2A8h]
    mov qword ptr [rsp+20h], 3Dh
    mov ecx, 2Dh
    mov r8d, 2Bh
    call sub_7FFB0F874C30
    mov rax, qword ptr [qword_7FFB0FF56B20]
    mov qword ptr [rsp+2B0h], rax
    mov eax, dword ptr [dword_7FFB0FEA147C]
    mov dword ptr [rsp+194h], eax
    xor eax, 76964623h
    lea ecx, [rax-6D55F03Ch]
    mov dword ptr [rsp+198h], ecx
    lea ecx, [rax-1BB7074Bh]
    mov dword ptr [rsp+84h], ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [rsp+84h]
    lea edx, [rcx+145D81D6h]
    mov r8d, edx
    not r8d
    mov r9d, edx
    or r9d, 5A6EEE8h
    and r8d, 5A6EEE8h
    lea r8d, [r8+r8*2]
    mov r10d, edx
    and r10d, 5A6EEE8h
    lea r10d, [r10+r10*2]
    and edx, -5A6EEE9h
    sub r10d, edx
    lea edx, [r10+rcx]
    add edx, 145D81D6h
    add edx, r8d
    mov r10d, 1E2B2C73h
    sub r10d, edx
    sub r10d, r9d
    add edx, r9d
    add edx, 61BFD50Dh
    xor edx, eax
    xor edx, r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea eax, [rdx+rcx]
    add eax, 145D81D6h
    mov dword ptr [rsp+19Ch], eax
    mov eax, dword ptr [dword_7FFB0FEE5B90]
    lea ecx, [rax-6BB2AAD0h]
    lea edx, [rax-5AD315C5h]
    mov r8d, edx
    xor r8d, -71E0AE82h
    add r8d, eax
    add r8d, 77B0BDFh
    xor r8d, edx
    xor edx, -7268A49Fh
    xor r8d, 202D7EE2h
    add r8d, edx
    sub r8d, eax
    add r8d, -2AF72912h
    xor r8d, ecx
    add r8d, eax
    mov dword ptr [rsp+30h], r8d
    jmp loc_7FFB0E398956
    loc_7FFB0E399D50:
    cmp eax, 758FF473h
    jnz loc_7FFB0E39AFFC
    mov rax, qword ptr [rsp+1A0h]
    movzx eax, byte ptr [rax+2Ch]
    mov byte ptr [rsp+3Ch], al
    movzx eax, byte ptr [byte_7FFB0FEA149C]
    mov byte ptr [rsp+38h], al
    mov eax, dword ptr [dword_7FFB0FEE5B14]
    lea ecx, [rax-61AA12AEh]
    xor ecx, -45255057h
    lea edx, [rcx+482416F3h]
    lea r8d, [rcx+528DA061h]
    xor r8d, -763AA72Eh
    lea r9d, [r8+62CEC130h]
    add r8d, eax
    add r8d, -11F8BBD3h
    xor r8d, r9d
    xor r9d, -5CBCEC1Ah
    sub r8d, r9d
    xor r8d, ecx
    sub r8d, eax
    jmp loc_7FFB0E39B8B4
    loc_7FFB0E399DC5:
    cmp eax, 1B7B68FCh
    jnz loc_7FFB0E39B0FF
    mov eax, dword ptr [rsp+14Ch]
    lea ecx, [rax+rax*4]
    lea eax, [rax+rcx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [rsp+74h]
    mov edx, ecx
    not edx
    mov r8d, dword ptr [rsp+13Ch]
    and edx, r8d
    lea edx, [rdx+rdx*2]
    and r8d, ecx
    lea ecx, [r8+r8*8]
    lea ecx, [r8+rcx*2]
    lea ecx, [rcx+rdx*4]
    sub ecx, eax
    sub ecx, dword ptr [rsp+148h]
    add ecx, dword ptr [rsp+144h]
    add ecx, dword ptr [rsp+140h]
    mov dword ptr [rsp+150h], ecx
    mov eax, dword ptr [dword_7FFB0FEE5B68]
    lea ecx, [rax-7D8737FDh]
    mov edx, ecx
    xor edx, -2C15263Dh
    sub edx, eax
    lea eax, [rdx+rcx]
    add eax, -47725BB6h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E399E8E:
    cmp eax, 4298026Fh
    jnz loc_7FFB0E39B1B5
    mov eax, dword ptr [rsp+158h]
    mov ecx, 4A41EFCCh
    add eax, ecx
    mov ecx, dword ptr [rsp+78h]
    add ecx, eax
    mov r8d, -3C13E0F8h
    sub r8d, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, r8d
    not ecx
    mov r10d, dword ptr [rsp+7Ch]
    mov r9d, r10d
    not r9d
    mov edx, r8d
    or edx, r9d
    not edx
    lea edx, [rdx+rdx*8]
    or r10d, r8d
    not r10d
    lea r10d, [r10+r10*4]
    and r9d, r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r8d, dword ptr [rsp+7Ch]
    lea r11d, [r8+r8*4]
    lea r8d, [r8+r11*2]
    add r8d, r9d
    not r9d
    lea r11d, [r9+r9*4]
    lea r9d, [r9+r11*2]
    sub r8d, r9d
    lea r8d, [r8+r10*2]
    add edx, ecx
    add edx, r8d
    sub edx, eax
    and edx, dword ptr [rsp+154h]
    mov dword ptr [rsp+15Ch], edx
    mov eax, dword ptr [dword_7FFB0FEE5B74]
    mov ecx, 12221095h
    xor eax, ecx
    add eax, -42958161h
    xor eax, -4CB9A00Ah
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E399FD7:
    cmp eax, 6C73B329h
    jnz loc_7FFB0E39B243
    mov eax, dword ptr [rsp+178h]
    add eax, eax
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+17Ch], eax
    mov eax, dword ptr [rsp+58h]
    mov ecx, eax
    xor ecx, -6E09FBFEh
    mov dword ptr [rsp+180h], ecx
    and eax, 6E09FBFDh
    add eax, eax
    lea eax, [rax+rax*2]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+58h]
    mov ecx, -6E09FBFEh
    and eax, ecx
    mov dword ptr [rsp+188h], eax
    mov eax, dword ptr [dword_7FFB0FEE5B88]
    lea ecx, [rax+344435E8h]
    xor ecx, 3370CC45h
    add eax, ecx
    add eax, ecx
    mov ecx, -4A1E86E4h
    sub ecx, eax
    jmp loc_7FFB0E398952
    loc_7FFB0E39A0B4:
    cmp eax, 770D420Ch
    jnz loc_7FFB0E39B291
    mov eax, dword ptr [rsp+54h]
    mov ecx, eax
    and ecx, 30FC088h
    add ecx, ecx
    lea ecx, [rcx+rcx*2]
    and eax, 7CF03F77h
    add eax, eax
    sub eax, ecx
    mov dword ptr [rsp+134h], eax
    mov eax, dword ptr [dword_7FFB0FEE5AEC]
    mov ecx, eax
    xor ecx, 4F613D67h
    lea edx, [rcx-18266A41h]
    add eax, -1DB7A29Bh
    xor eax, edx
    xor eax, -584AEABh
    sub eax, edx
    xor edx, 174BC772h
    xor eax, edx
    sub eax, edx
    add eax, 70E19DF1h
    jmp loc_7FFB0E39B942
    loc_7FFB0E39A116:
    cmp eax, 4640A3D7h
    jz loc_7FFB0E398907
    mov eax, dword ptr [rsp+48h]
    mov ecx, eax
    and ecx, 4161E0A8h
    lea ecx, [rcx+rcx*2]
    add ecx, ecx
    and eax, 1E9E1F57h
    lea eax, [rcx+rax*8]
    sub eax, dword ptr [rsp+10Ch]
    sub eax, dword ptr [rsp+108h]
    mov dword ptr [rsp+110h], eax
    mov eax, dword ptr [dword_7FFB0FEE5B50]
    mov ecx, eax
    xor ecx, -65AF954Dh
    mov edx, ecx
    sub edx, eax
    xor eax, -7629573Ch
    lea r8d, [rcx-3E4972DBh]
    add edx, -7A26D0DCh
    xor edx, r8d
    add ecx, eax
    add ecx, edx
    mov dword ptr [rsp+30h], ecx
    jmp loc_7FFB0E398956
    loc_7FFB0E39A183:
    cmp eax, 5C6BAA19h
    jnz loc_7FFB0E39B5EB
    mov ecx, dword ptr [rsp+6Ch]
    mov eax, dword ptr [rsp+70h]
    mov edx, eax
    or edx, ecx
    lea r8d, [rcx+rcx*4]
    lea r8d, [rcx+r8*2]
    not ecx
    mov r9d, eax
    or r9d, ecx
    not r9d
    lea r10d, [r9+r9*4]
    lea r9d, [r9+r10*2]
    mov dword ptr [rsp+0C8h], r9d
    not edx
    mov dword ptr [rsp+0CCh], edx
    mov dword ptr [rsp+0D0h], r8d
    and ecx, eax
    mov dword ptr [rsp+0D4h], ecx
    mov eax, dword ptr [dword_7FFB0FEE5AA8]
    lea ecx, [rax+1B07D75Fh]
    xor ecx, -37BD6D23h
    lea edx, [rcx-340D5F15h]
    mov r8d, edx
    xor r8d, 578CE610h
    add ecx, r8d
    add r8d, -4400350Dh
    mov r9d, 328DF2E2h
    sub r9d, ecx
    xor edx, eax
    xor edx, r8d
    xor edx, r9d
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E39A21D:
    movzx eax, byte ptr [rsp+39h]
    lea ecx, [rax-48h]
    mov byte ptr [rsp+3Fh], cl
    add al, 0Ch
    mov byte ptr [rsp+3Ah], al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rsp+3Ah]
    add al, 83h
    mov byte ptr [rsp+40h], al
    movzx eax, byte ptr [rsp+39h]
    xor al, 57h
    mov byte ptr [rsp+41h], al
    mov eax, dword ptr [dword_7FFB0FEE5A88]
    lea ecx, [rax-5F87A136h]
    add eax, eax
    mov edx, 266ACF35h
    sub edx, eax
    xor edx, ecx
    add edx, 1B972DAFh
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E39A2AD:
    mov rax, qword ptr [rsp+210h]
    add rax, qword ptr [rsp+1D8h]
    mov qword ptr [rsp+218h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FEE5AD8]
    lea ecx, 2725FCBAh[rax*2]
    add ecx, eax
    add ecx, 18946FFAh
    add eax, 2725FCBAh
    xor ecx, eax
    jmp loc_7FFB0E398952
    loc_7FFB0E39A353:
    mov ebx, dword ptr [dword_7FFB0FE92168]
    mov r9, qword ptr [rsp+1B0h]
    mov qword ptr [rsp+20h], 6
    mov edx, 30h
    mov r8d, 52h
    mov ecx, ebx
    call sub_7FFB0EEA1FE0
    cmp rax, qword ptr [rsp+60h]
    jbe loc_7FFB0E39A618
    mov rax, qword ptr [rsp+1B0h]
    mov qword ptr [rsp+28h], rax
    mov qword ptr [rsp+20h], 1
    mov edx, 0Ah
    mov r8d, 24h
    lea rcx, [rsp+2B8h]
    mov r9d, ebx
    call sub_7FFB0E2ADB60
    mov rax, qword ptr [rsp+2B8h]
    movsxd rcx, dword ptr [rax+3Ch]
    lea rdx, [rax+rcx]
    mov eax, dword ptr [rax+rcx]
    mov ecx, dword ptr [dword_7FFB0FEA1480]
    lea r8d, [rcx+403D9C1h]
    xor r8d, 70DE0C68h
    add r8d, r8d
    neg r8d
    add ecx, r8d
    add ecx, -1423B14Dh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp eax, ecx
    mov eax, 0
    cmovnz rdx, rax
    loc_7FFB0E39A461:
    mov eax, dword ptr [rdx+8]
    mov ecx, dword ptr [rdx+50h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    shl rax, 20h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or rax, rcx
    mov qword ptr [rsp+298h], rax
    mov eax, dword ptr [dword_7FFB0FEA1484]
    mov dword ptr [rsp+118h], eax
    lea ecx, [rax-4450522Bh]
    mov dword ptr [rsp+11Ch], ecx
    add eax, 571021ADh
    mov dword ptr [rsp+74h], eax
    mov ecx, eax
    xor ecx, -48BE1A29h
    mov dword ptr [rsp+54h], ecx
    xor eax, 48BE1A28h
    lea ecx, [rax+rax*2]
    mov dword ptr [rsp+120h], ecx
    and eax, 7CF03F77h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov eax, dword ptr [rsp+54h]
    not eax
    and eax, -7CF03F78h
    mov dword ptr [rsp+128h], eax
    mov eax, dword ptr [dword_7FFB0FEE5AB0]
    mov ecx, eax
    xor ecx, 6C848E6Bh
    add ecx, 6A9D7F12h
    xor ecx, eax
    mov edx, eax
    xor edx, 6208C9DDh
    lea r8d, [rdx-4A9BA50Ah]
    xor r8d, -2D8058D1h
    xor ecx, -53643011h
    add r8d, eax
    add r8d, ecx
    lea eax, [rdx+r8]
    add eax, -4A9BA50Ah
    add eax, edx
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39A618:
    mov rax, qword ptr [qword_7FFB0FF56B08]
    mov qword ptr [rsp+230h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [qword_7FFB0FEA1490]
    mov qword ptr [rsp+238h], rax
    mov rcx, 18E7CEEFECD9F5A0h
    add rcx, rax
    mov qword ptr [rsp+240h], rcx
    add rax, r15
    xor rax, rdi
    mov qword ptr [rsp+248h], rax
    lea rcx, [rax+rbp]
    mov qword ptr [rsp+1B8h], rcx
    lea rdx, [rsp]
    mov qword ptr [rsp+250h], rdx
    add rax, r13
    mov qword ptr [rsp+258h], rax
    not rcx
    or rcx, r14
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    shl rcx, 3
    mov qword ptr [rsp+260h], rcx
    mov rax, qword ptr [rsp+1B8h]
    mov rcx, r14
    or rcx, rax
    not rcx
    shl rcx, 2
    mov qword ptr [rsp+268h], rcx
    xor rax, r14
    mov qword ptr [rsp+278h], rax
    not rax
    shl rax, 2
    mov qword ptr [rsp+270h], rax
    mov eax, dword ptr [dword_7FFB0FEE5B00]
    lea ecx, [rax+76453476h]
    mov edx, ecx
    xor edx, -78B4DB40h
    xor ecx, -7E77328Ch
    add ecx, 532B42E7h
    xor ecx, -50A89A4Bh
    add ecx, edx
    sub ecx, eax
    add ecx, 532B42E7h
    jmp loc_7FFB0E398952
    loc_7FFB0E39A7E4:
    mov rax, qword ptr [qword_7FFB0FE92110]
    mov qword ptr [rsp+1B0h], rax
    cmp rax, qword ptr [rsp+60h]
    jbe loc_7FFB0E39B883
    mov eax, dword ptr [dword_7FFB0FEE5B78]
    lea ecx, [rax-3B91BE74h]
    xor ecx, -26FEC204h
    add ecx, eax
    mov eax, 515DD7EFh
    loc_7FFB0E39A817:
    sub eax, ecx
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39A822:
    mov eax, dword ptr [dword_7FFB0FEE5B4C]
    lea ecx, [rax-2646CFBAh]
    xor ecx, 4DBF3F6Eh
    lea edx, [rcx-2B09D739h]
    xor edx, 7B93EEFBh
    add edx, edx
    add ecx, edx
    add ecx, -2B09D739h
    add ecx, eax
    add ecx, -2646CFBAh
    neg ecx
    add ecx, eax
    add ecx, -38454118h
    xor ecx, eax
    jmp loc_7FFB0E398952
    loc_7FFB0E39A863:
    movzx eax, byte ptr [rsp+37h]
    or al, byte ptr [rsp+36h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not al
    shl al, 2
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [rsp+36h]
    not cl
    and cl, byte ptr [rsp+37h]
    mov edx, ecx
    not dl
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
    sub dl, cl
    sub dl, al
    mov byte ptr [rsp+46h], dl
    mov eax, dword ptr [dword_7FFB0FEE5B28]
    lea ecx, [rax-5AD62C9Ah]
    mov edx, ecx
    xor edx, 23FF56E0h
    lea r8d, [rdx+112D35E9h]
    mov r9d, r8d
    xor r9d, -6F868686h
    xor ecx, 14F970EDh
    add ecx, eax
    add ecx, r9d
    sub ecx, edx
    xor ecx, r8d
    jmp loc_7FFB0E398952
    loc_7FFB0E39A9AE:
    mov rax, qword ptr [rsp+90h]
    and rax, qword ptr [rsp+88h]
    lea rax, [rax+rax*2]
    mov rcx, qword ptr [rsp+200h]
    sub rcx, rax
    add rcx, qword ptr [rsp+1F8h]
    mov qword ptr [rsp+208h], rcx
    mov eax, dword ptr [dword_7FFB0FEE5ADC]
    lea ecx, [rax+6DED011Eh]
    lea edx, [rax+20693681h]
    xor edx, 749D0A98h
    sub edx, eax
    sub edx, eax
    add eax, edx
    add eax, -326EE155h
    xor eax, ecx
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39AA0B:
    mov eax, dword ptr [dword_7FFB0FEE5AB8]
    mov ecx, -6B2EF2FFh
    add eax, ecx
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39AA21:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+188h]
    lea eax, [rax+rax*2]
    add eax, eax
    add eax, dword ptr [rsp+184h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add eax, dword ptr [rsp+180h]
    sub eax, dword ptr [rsp+17Ch]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [rsp+174h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea edx, [rax+rcx]
    add edx, 45D3EE70h
    mov dword ptr [rsp+18Ch], edx
    add eax, ecx
    add eax, -249F8350h
    mov ecx, eax
    xor ecx, -457836E0h
    mov edx, eax
    xor edx, 7894482h
    mov r8d, 0A7115BCh
    sub r8d, dword ptr [rsp+58h]
    xor r8d, edx
    sub r8d, edx
    sub r8d, dword ptr [rsp+80h]
    add ecx, r8d
    add ecx, 3EA239EDh
    xor ecx, eax
    mov dword ptr [rsp+190h], ecx
    mov eax, dword ptr [dword_7FFB0FEE5B8C]
    lea ecx, [rax-699A0FD5h]
    lea edx, [rax-623DFC6h]
    xor edx, -0D5FE6CDh
    mov r8d, eax
    xor r8d, -7D83BE44h
    add r8d, edx
    xor r8d, ecx
    add r8d, eax
    lea eax, [rdx+r8]
    add eax, 0F0719AAh
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39AC6B:
    mov eax, dword ptr [rsp+0F8h]
    xor eax, dword ptr [rsp+50h]
    xor eax, dword ptr [rsp+0ECh]
    xor eax, dword ptr [rsp+0E8h]
    mov rcx, qword ptr [rsp+280h]
    cmp rcx, qword ptr [rsp+1A8h]
    setbe byte ptr [rsp+3Bh]
    mov qword ptr [rsp+290h], rax
    mov eax, dword ptr [dword_7FFB0FEE5B08]
    lea ecx, [rax-135BB6CBh]
    xor ecx, -72980FB2h
    lea edx, [rcx-53F844ECh]
    xor edx, -4DA77C21h
    sub edx, ecx
    jmp loc_7FFB0E39B08A
    loc_7FFB0E39ACC6:
    movzx eax, byte ptr [rsp+37h]
    or al, byte ptr [rsp+44h]
    not al
    mov byte ptr [rsp+45h], al
    mov eax, dword ptr [dword_7FFB0FEE5A98]
    mov ecx, eax
    xor ecx, 7783DF3Ch
    lea edx, [rcx-763174BEh]
    xor eax, 476EAA29h
    sub eax, edx
    sub eax, ecx
    xor eax, edx
    xor eax, -1DC0D915h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39AD02:
    mov eax, dword ptr [rsp+50h]
    not eax
    and eax, -63A010C8h
    lea eax, [rax+rax*4]
    mov dword ptr [rsp+0F4h], eax
    mov eax, dword ptr [dword_7FFB0FEE5AC4]
    lea ecx, [rax-623557C3h]
    lea edx, [rax+13107003h]
    xor ecx, eax
    xor ecx, edx
    mov eax, edx
    xor eax, -1A009C6Bh
    mov edx, -2D971562h
    sub edx, eax
    xor ecx, edx
    add eax, ecx
    add eax, 57F1FA9Bh
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39AD4D:
    mov eax, dword ptr [rsp+134h]
    add eax, dword ptr [rsp+130h]
    add eax, dword ptr [rsp+12Ch]
    mov dword ptr [rsp+138h], eax
    mov eax, dword ptr [dword_7FFB0FEE5A74]
    mov ecx, eax
    xor ecx, 27969B2Fh
    lea edx, [rcx+6E05A972h]
    lea r8d, [rcx-5BA0EA5Bh]
    mov r9d, r8d
    xor r9d, 87B2245h
    add r9d, eax
    sub r9d, r8d
    add r9d, -314F14CDh
    xor r9d, edx
    add r9d, ecx
    mov dword ptr [rsp+30h], r9d
    jmp loc_7FFB0E398956
    loc_7FFB0E39ADAB:
    mov r9, qword ptr [rsp+298h]
    mov edx, dword ptr [rsp+150h]
    mov qword ptr [rsp+20h], 63h
    mov ecx, 1Eh
    mov r8d, 7
    call sub_7FFB0F874C30
    mov rax, qword ptr [rsp+1A8h]
    sub rax, qword ptr [qword_7FFB0FE92110]
    mov qword ptr [rsp+2A0h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FEE5B58]
    lea ecx, [rax+2BF6B6C3h]
    mov edx, ecx
    xor edx, -25FBDAD3h
    lea r8d, [rdx-63F7495Bh]
    mov r9d, r8d
    xor r9d, 0C15FA38h
    sub r9d, edx
    add r9d, -6555600Ah
    xor r9d, ecx
    sub r9d, eax
    lea eax, [r9+r8]
    add eax, -666F06CCh
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39AE8C:
    mov eax, dword ptr [rsp+170h]
    lea ecx, [rax+rax*4]
    lea eax, [rax+rcx*4]
    mov ecx, dword ptr [rsp+80h]
    mov edx, -506B5496h
    and ecx, edx
    lea ecx, [rcx+rcx*8]
    add ecx, eax
    mov eax, dword ptr [rsp+16Ch]
    sub eax, ecx
    add eax, dword ptr [rsp+168h]
    sub eax, dword ptr [rsp+164h]
    sub eax, dword ptr [rsp+160h]
    mov dword ptr [rsp+58h], eax
    not eax
    and eax, 6E09FBFDh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov dword ptr [rsp+174h], eax
    mov eax, dword ptr [rsp+58h]
    mov ecx, 6E09FBFDh
    or eax, ecx
    mov dword ptr [rsp+178h], eax
    mov eax, dword ptr [dword_7FFB0FEE5B84]
    mov ecx, eax
    xor ecx, 653BB57Ah
    mov edx, eax
    xor edx, -3100DE37h
    sub edx, ecx
    add edx, -5765E02Ch
    xor edx, eax
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E39AF72:
    mov eax, dword ptr [rsp+78h]
    mov ecx, eax
    xor ecx, 507B0413h
    mov dword ptr [rsp+7Ch], ecx
    xor eax, -5FF8A2C4h
    mov dword ptr [rsp+158h], eax
    mov eax, dword ptr [dword_7FFB0FEE5B70]
    mov ecx, -3A6E2340h
    xor eax, ecx
    add eax, 1D7E708h
    xor eax, 566A6463h
    lea ecx, [rax-617D02B4h]
    add eax, 5BEAFBA9h
    loc_7FFB0E39AFB0:
    xor eax, ecx
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39AFBB:
    cmp byte ptr [rsp+418h], 0
    jz loc_7FFB0E39B903
    mov eax, dword ptr [dword_7FFB0FEE5B1C]
    lea ecx, [rax+123CB04Ah]
    lea edx, [rax-21DB7A31h]
    xor edx, -3AC0C731h
    add edx, eax
    add edx, 3FD1A582h
    xor edx, ecx
    sub edx, eax
    add edx, 3C0C6F61h
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E39AFFC:
    mov rax, qword ptr [rsi]
    mov eax, dword ptr [rax]
    mov dword ptr [rsp+98h], eax
    mov eax, dword ptr [dword_7FFB0FEA1468]
    mov dword ptr [rsp+4Ch], eax
    mov eax, dword ptr [dword_7FFB0FEE5A7C]
    mov ecx, eax
    xor ecx, -6A7650C6h
    lea edx, [rcx-1A2081D9h]
    mov r8d, edx
    xor r8d, -315A6E0Dh
    lea r9d, [r8+3AFDDA5Fh]
    mov r10d, r9d
    xor r9d, edx
    xor edx, 1ADFA0B5h
    xor r10d, -2E2C8C08h
    xor r9d, 1833C858h
    add r10d, ecx
    add r10d, r9d
    xor r10d, eax
    sub r10d, r8d
    add r10d, edx
    mov dword ptr [rsp+30h], r10d
    jmp loc_7FFB0E398956
    loc_7FFB0E39B06A:
    mov eax, dword ptr [dword_7FFB0FEE5B30]
    lea ecx, [rax+54C0B75Eh]
    xor ecx, 6D3A5D5h
    add ecx, 506EE4A8h
    lea edx, [rax+5EF2A1A9h]
    xor edx, ecx
    loc_7FFB0E39B08A:
    sub edx, eax
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E39B095:
    mov eax, dword ptr [rsp+2A0h]
    mov dword ptr [rsp+154h], eax
    mov eax, dword ptr [dword_7FFB0FEA1488]
    mov dword ptr [rsp+78h], eax
    mov eax, dword ptr [dword_7FFB0FEE5B6C]
    lea ecx, [rax-26F20F9Ah]
    mov edx, ecx
    xor edx, -58AA534Ah
    mov r8d, ecx
    xor r8d, 31560111h
    add r8d, edx
    mov edx, ecx
    xor edx, -53D7C4D1h
    xor ecx, 2F7E30D3h
    add ecx, 0F936E77h
    lea r9d, [rax+269A9FBFh]
    xor r9d, ecx
    sub r9d, eax
    sub r9d, edx
    add r9d, r8d
    mov dword ptr [rsp+30h], r9d
    jmp loc_7FFB0E398956
    loc_7FFB0E39B0FF:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FEE5AAC]
    mov ecx, eax
    xor ecx, -745BCDECh
    lea edx, [rcx-440FB202h]
    lea r8d, [rcx+18A8573Ch]
    xor r8d, -50F6913h
    xor edx, 644330CDh
    sub edx, ecx
    sub edx, eax
    add edx, ecx
    lea eax, [rcx+rdx]
    add eax, 7C34717Ah
    xor eax, ecx
    sub eax, r8d
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39B1B5:
    mov eax, dword ptr [rsp+0C0h]
    add eax, eax
    mov ecx, dword ptr [rsp+68h]
    not ecx
    and ecx, dword ptr [rsp+0B0h]
    sub eax, ecx
    sub eax, dword ptr [rsp+0BCh]
    sub eax, dword ptr [rsp+0B8h]
    add eax, dword ptr [rsp+0B4h]
    mov dword ptr [rsp+70h], eax
    not eax
    mov dword ptr [rsp+0C4h], eax
    mov eax, dword ptr [dword_7FFB0FEE5A9C]
    mov ecx, 1F71E256h
    xor eax, ecx
    lea ecx, [rax+708233C6h]
    lea edx, [rax-5AF2299Ah]
    xor edx, ecx
    xor edx, eax
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E39B215:
    mov eax, dword ptr [dword_7FFB0FEE5B44]
    lea edx, [rax-48BC8053h]
    xor edx, 3D0A5727h
    add edx, eax
    add edx, eax
    neg edx
    lea ecx, [rax+rdx]
    add ecx, -48BC8053h
    sub ecx, eax
    add ecx, 79574C2Eh
    jmp loc_7FFB0E398952
    loc_7FFB0E39B243:
    mov rax, qword ptr [rsp+1C8h]
    movzx ecx, byte ptr [rsp+218h]
    shr rax, cl
    mov dword ptr [rsp+0E4h], eax
    mov eax, dword ptr [dword_7FFB0FEE5AE8]
    mov ecx, eax
    xor ecx, 2F0A08D0h
    lea edx, [rcx-72999F11h]
    xor eax, -4DBF2D0Ch
    sub eax, ecx
    sub eax, ecx
    sub eax, ecx
    add eax, 3AF62EDh
    xor eax, edx
    xor eax, -638650E5h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39B291:
    mov edx, dword ptr [rsp+19Ch]
    xor edx, dword ptr [rsp+84h]
    sub edx, dword ptr [rsp+194h]
    add edx, dword ptr [rsp+198h]
    mov r9, qword ptr [rsp+2B0h]
    mov qword ptr [rsp+20h], 5Ch
    mov ecx, 7
    mov r8d, 3Dh
    call sub_7FFB0F874C30
    loc_7FFB0E39B2CE:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov qword ptr [rsp+220h], rax
    mov r9, qword ptr [rax+28h]
    mov ecx, 36h
    mov edx, 54h
    mov r8d, 59h
    call sub_7FFB0F740560
    mov qword ptr [rsp+1A0h], rax
    test rax, rax
    jz loc_7FFB0E39B847
    lea rax, [rsi+8]
    mov qword ptr [rsp+228h], rax
    mov rax, qword ptr [rsi+8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov qword ptr [rsp+1A8h], rax
    mov qword ptr [rsp+60h], rax
    mov eax, dword ptr [dword_7FFB0FEE5AC8]
    mov ecx, eax
    xor ecx, -26DC5EA5h
    lea edx, [rcx+18DA1EA2h]
    xor edx, -768E7CB3h
    mov r8d, eax
    xor r8d, -3A71F583h
    add r8d, ecx
    add r8d, edx
    add eax, r8d
    add eax, -7121657Fh
    xor eax, edx
    xor eax, 3290B6C8h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39B40B:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rsp+47h]
    sub al, byte ptr [rsp+38h]
    sub al, byte ptr [rsp+3Eh]
    cmp byte ptr [rsp+3Ch], al
    jnz loc_7FFB0E39B94D
    mov eax, dword ptr [dword_7FFB0FEE5B5C]
    mov ecx, eax
    xor ecx, 4916D95Bh
    add ecx, 305E5F9Ah
    add eax, -37A08441h
    xor eax, ecx
    xor eax, 6394E973h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39B4C1:
    mov rax, qword ptr [qword_7FFB0FF56B18]
    mov qword ptr [rsp+2A8h], rax
    mov eax, dword ptr [dword_7FFB0FEA1478]
    mov dword ptr [rsp+80h], eax
    mov ecx, eax
    not ecx
    mov edx, ecx
    and edx, -506B5496h
    lea r8d, [rdx+rdx*4]
    lea edx, [rdx+r8*4]
    mov dword ptr [rsp+160h], edx
    mov edx, ecx
    and edx, 506B5495h
    lea r8d, [rdx+rdx*4]
    lea edx, [rdx+r8*2]
    mov dword ptr [rsp+164h], edx
    or ecx, 506B5495h
    lea edx, [rcx+rcx*4]
    lea ecx, [rcx+rdx*2]
    mov dword ptr [rsp+168h], ecx
    mov ecx, eax
    or ecx, -506B5496h
    lea edx, [rcx+rcx*4]
    lea ecx, [rcx+rdx*2]
    mov dword ptr [rsp+16Ch], ecx
    and eax, 506B5495h
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FEE5B80]
    lea ecx, [rax-5D0C4B17h]
    mov edx, ecx
    xor edx, 1846A82h
    lea r8d, [rdx-4F132DAEh]
    sub ecx, edx
    add edx, 552D6C6Ah
    add ecx, 741082D1h
    xor edx, eax
    xor edx, ecx
    xor edx, r8d
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E39B5EB:
    mov eax, dword ptr [rsp+50h]
    mov ecx, 63A010C7h
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
    nop
    nop
    nop
    nop
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
    mov ecx, dword ptr [rsp+50h]
    mov edx, 1C5FEF38h
    and ecx, edx
    shl ecx, 3
    sub ecx, eax
    add ecx, dword ptr [rsp+0F4h]
    mov eax, dword ptr [rsp+0F0h]
    lea edx, [rcx+rax]
    add eax, ecx
    add eax, -0DDFAC18h
    xor eax, 1C091596h
    add eax, edx
    add eax, 486BA656h
    mov dword ptr [rsp+0F8h], eax
    mov eax, dword ptr [dword_7FFB0FEE5AF4]
    mov ecx, eax
    xor ecx, 4F5EA27Dh
    lea edx, [rcx+31A235Fh]
    xor edx, ecx
    add edx, eax
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E39B6B5:
    mov eax, dword ptr [rsp+0D8h]
    add eax, dword ptr [rsp+0C4h]
    add eax, dword ptr [rsp+0ACh]
    cmp dword ptr [rsp+98h], eax
    jnz loc_7FFB0E39B9D9
    mov ecx, 0Ch
    mov edx, 10h
    mov r8d, 27h
    call sub_7FFB0EE4B6C0
    mov dword ptr [rsp+0DCh], eax
    mov eax, dword ptr [7FFE0004h]
    mov dword ptr [rsp+0E0h], eax
    mov rax, qword ptr [7FFE0320h]
    mov qword ptr [rsp+1C0h], rax
    mov eax, dword ptr [dword_7FFB0FEE5ACC]
    mov ecx, eax
    xor ecx, -8C50694h
    lea edx, [rcx-30EB89C5h]
    lea r8d, [rcx+3C94E6B2h]
    add eax, -7A8B5B26h
    xor eax, r8d
    add eax, 2DF294A6h
    xor eax, edx
    sub eax, ecx
    add eax, 1773A6A2h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39B74B:
    mov eax, dword ptr [rsp+48h]
    mov ecx, eax
    not ecx
    mov edx, ecx
    and edx, 3E9E1F57h
    mov dword ptr [rsp+100h], edx
    and ecx, 161E0A8h
    shl ecx, 3
    mov dword ptr [rsp+104h], ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor eax, -3E9E1F58h
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+108h], eax
    mov eax, dword ptr [rsp+48h]
    mov ecx, -3E9E1F58h
    or eax, ecx
    lea eax, [rax+rax*4]
    mov dword ptr [rsp+10Ch], eax
    mov eax, dword ptr [dword_7FFB0FEE5A6C]
    mov ecx, eax
    xor ecx, 551875E7h
    lea edx, [rcx-1372D8C2h]
    mov r8d, edx
    xor r8d, 44346CFAh
    xor edx, -12D0B113h
    add edx, r8d
    add edx, -1EAE84E2h
    xor edx, ecx
    xor edx, 6FFA5CF6h
    add ecx, edx
    add ecx, -1372D8C2h
    xor ecx, eax
    xor ecx, -25EA74B5h
    jmp loc_7FFB0E398952
    loc_7FFB0E39B847:
    mov eax, dword ptr [dword_7FFB0FEE5B54]
    mov ecx, 61F3867Bh
    add eax, ecx
    xor eax, 20339393h
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39B862:
    mov eax, dword ptr [dword_7FFB0FEE5A8C]
    mov ecx, eax
    xor ecx, 6CB7B73Eh
    lea edx, [rcx-54CFACBBh]
    xor edx, eax
    sub edx, ecx
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E39B883:
    mov eax, dword ptr [dword_7FFB0FEE5AFC]
    lea ecx, [rax+6419456Bh]
    mov edx, ecx
    xor edx, 1B4580A1h
    add edx, -1C876C73h
    mov r8d, edx
    xor r8d, -2B110D97h
    add r8d, 3EDDE391h
    xor r8d, eax
    sub r8d, ecx
    loc_7FFB0E39B8B4:
    xor r8d, edx
    mov dword ptr [rsp+30h], r8d
    jmp loc_7FFB0E398956
    loc_7FFB0E39B8C1:
    mov eax, 1C2E3B5Ah
    sub eax, dword ptr [dword_7FFB0FEE5B10]
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39B8D5:
    mov eax, dword ptr [dword_7FFB0FEE5AF8]
    mov ecx, eax
    xor ecx, -0C79E23Ch
    lea edx, [rcx+2173AE11h]
    xor edx, eax
    xor eax, 21B1BEF5h
    add edx, ecx
    sub edx, eax
    add edx, -54BC19F4h
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E39B903:
    mov eax, dword ptr [dword_7FFB0FEE5B40]
    mov ecx, eax
    xor ecx, -130E8EE9h
    lea edx, [rcx+75285E02h]
    mov r8d, edx
    xor r8d, 5B19A400h
    mov r9d, edx
    xor r9d, -588240E8h
    xor edx, 77D462Eh
    add edx, eax
    xor edx, r9d
    sub edx, r8d
    lea eax, [r9+rdx]
    add eax, 64105436h
    loc_7FFB0E39B942:
    xor eax, ecx
    mov dword ptr [rsp+30h], eax
    jmp loc_7FFB0E398956
    loc_7FFB0E39B94D:
    mov rax, qword ptr [rsp+220h]
    mov rax, qword ptr [rax+20h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp rax, 8
    jnz loc_7FFB0E39BA0D
    mov eax, dword ptr [dword_7FFB0FEE5B48]
    lea ecx, [rax+58FF0F8Eh]
    mov edx, ecx
    xor edx, -757C697h
    lea r8d, [rdx-78898904h]
    add edx, 2894A9C9h
    mov r9d, 40AF8DAh
    sub r9d, eax
    xor r9d, r8d
    xor r9d, edx
    sub r9d, ecx
    mov dword ptr [rsp+30h], r9d
    jmp loc_7FFB0E398956
    loc_7FFB0E39B9D9:
    mov eax, dword ptr [dword_7FFB0FEE5ABC]
    lea ecx, [rax+4808F98Dh]
    xor ecx, 651205E0h
    lea edx, [rcx-199E3D99h]
    mov r8d, 61A522Ah
    sub r8d, eax
    xor r8d, edx
    sub r8d, ecx
    xor r8d, eax
    mov dword ptr [rsp+30h], r8d
    jmp loc_7FFB0E398956
    loc_7FFB0E39BA0D:
    mov eax, dword ptr [dword_7FFB0FEE5AA4]
    lea ecx, [rax+5FC9FA5Fh]
    mov edx, -268FF1h
    sub edx, eax
    xor edx, ecx
    xor edx, eax
    xor edx, -2B4CA091h
    mov dword ptr [rsp+30h], edx
    jmp loc_7FFB0E398956
    loc_7FFB0E39BA33:
    mov dword ptr [rsp+5Ch], 0
    jmp loc_7FFB0E39BBA0
    loc_7FFB0E39BA40:
    mov ecx, dword ptr [rsp+114h]
    add ecx, dword ptr [rsp+100h]
    mov eax, dword ptr [rsp+48h]
    mov edx, eax
    not edx
    mov r8d, eax
    and r8d, 244B68FAh
    lea r8d, [r8+r8*2]
    and edx, 244B68FAh
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
    or eax, 244B68FAh
    mov r9d, dword ptr [rsp+48h]
    mov r10d, r9d
    not r10d
    and r10d, 5BB49705h
    add r10d, r10d
    and r9d, 5BB49705h
    lea r9d, [r10+r9*2]
    sub eax, r9d
    sub eax, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub eax, r8d
    add eax, ecx
    mov ecx, dword ptr [rsp+0FCh]
    lea edx, [rcx+rax]
    add edx, -387E6C09h
    mov r8, qword ptr [rsp+1A0h]
    mov qword ptr [rsp+20h], 55h
    mov ecx, 42h
    mov r9d, 63h
    call sub_7FFB0E8830E0
    jmp loc_7FFB0E39BB98
    loc_7FFB0E39BB7E:
    movzx eax, byte ptr [rsp+2D8h]
    mov rcx, qword ptr [rsp+228h]
    mov rcx, qword ptr [rcx]
    add qword ptr [rcx+0F8h], rax
    loc_7FFB0E39BB98:
    mov dword ptr [rsp+5Ch], -1
    loc_7FFB0E39BBA0:
    mov eax, dword ptr [rsp+5Ch]
    mov rcx, qword ptr [rsp+420h]
    xor rcx, rsp
    cmp rcx, qword ptr [__security_cookie]
    jnz loc_7FFB0E39BBCC
    add rsp, 428h
    pop rbx
    pop rbp
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    ret
    loc_7FFB0E39BBCC:
    call __security_check_cookie
_TEXT ENDS
END

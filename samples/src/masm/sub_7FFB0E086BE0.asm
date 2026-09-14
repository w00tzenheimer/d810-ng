; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: sub_7FFB0E086BE0  @ 0x7ffb0e086be0
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN __security_check_cookie:PROC
EXTERN sub_7FFB0DE6D7D0:PROC
EXTERN sub_7FFB0E9F4760:PROC
EXTERN sub_7FFB0EBED1F0:PROC
EXTERN sub_7FFB0ECBE2C0:PROC
EXTERN sub_7FFB0F148750:PROC
EXTERN sub_7FFB0F283030:PROC

CONST SEGMENT
jpt_7FFB0E08A7BC dd 0FE23BC8Eh
dd 0FE23C953h
dd 0FE23C7BBh
dd 0FE23C81Dh
dd 0FE23C75Dh
dd 0FE23C9B5h
dd 0FE2402D9h
dd 0FE23C8F3h
dd 0FE2403BAh
jpt_7FFB0E08A81A dd 0FE23BFA1h
dd 0FE23CB24h
dd 0FE23CC0Dh
dd 0FE23CCEFh
dd 0FE23CB5Eh
dd 0FE23CF04h
dd 0FE23D374h
dd 0FE23CD64h
dd 0FE2401AAh
jpt_7FFB0E08AB29 dd 0FE23D86Eh
dd 0FE23DB0Eh
dd 0FE23DA78h
dd 0FE23DAABh
dd 0FE23D98Eh
dd 0FE23DB41h
dd 0FE23DB7Bh
dd 0FE23DADDh
dd 0FE23DBA6h
jpt_7FFB0E08ABE7 dd 0FE23DBB7h
dd 0FE23DCCEh
dd 0FE23DC23h
dd 0FE23DC5Dh
dd 0FE23DBEDh
dd 0FE23DD08h
dd 0FE23DF9Ch
dd 0FE23DC96h
dd 0FE2400D2h
jpt_7FFB0E08AFDA dd 0FE23DFAAh
dd 0FE23E1DCh
dd 0FE23E06Ah
dd 0FE23E0A4h
dd 0FE23E034h
dd 0FE23E216h
dd 0FE23E248h
dd 0FE23E132h
dd 0FE23E309h
jpt_7FFB0E08B259 dd 0FE23E481h
dd 0FE23E67Fh
dd 0FE23E530h
dd 0FE23E563h
dd 0FE23E501h
dd 0FE23E6B2h
dd 0FE23E7A5h
dd 0FE23E64Eh
dd 0FE23E7D0h
jpt_7FFB0E08AB91 dd 0FE23E8D9h
dd 0FE23EBEEh
dd 0FE23EA37h
dd 0FE23EACCh
dd 0FE23E9A6h
dd 0FE23EC83h
dd 0FE23F08Ch
dd 0FE23EBABh
dd 0FE23F4FAh
jpt_7FFB0E08AD6D dd 0FE23F5D8h
dd 0FE23F711h
dd 0FE23F636h
dd 0FE23F666h
dd 0FE23F607h
dd 0FE23F741h
dd 0FE23F769h
dd 0FE23F695h
dd 0FE23F791h
jpt_7FFB0E08E231 dd 0FE23F7F1h
dd 0FE23FA16h
dd 0FE23F875h
dd 0FE23F8FDh
dd 0FE23F83Eh
dd 0FE23FA4Eh
dd 0FE23FE62h
dd 0FE23F995h
dd 0FE23FE92h
jpt_7FFB0E08AC0C dd 0FE23FFC6h
dd 0FE240421h
dd 0FE24039Ch
dd 0FE240439h
dd 0FE240322h
dd 0FE240312h
dd 0FE238000h
dd 0FE2405B6h
dd 0FE2404CEh
__security_cookie dq 77104A6308CEh
dword_7FFB0FE9C548 dd 6FD84AC5h
byte_7FFB0FE9C54C db 98h
dword_7FFB0FE9C550 dd 0B163F82Dh
dword_7FFB0FE9C554 dd 0EA76822Dh
byte_7FFB0FE9C558 db 69h
dword_7FFB0FE9C55C dd 5CE5CB18h
dword_7FFB0FE9C560 dd 0DE04D2F0h
byte_7FFB0FE9C564 db 0CFh
dword_7FFB0FE9C568 dd 43563C07h
dword_7FFB0FE9C56C dd 6399D70h
dword_7FFB0FE9C570 dd 0D9311A0Eh
dword_7FFB0FE9C574 dd 7AAA4EEEh
dword_7FFB0FE9C578 dd 0FC68251Ah
byte_7FFB0FE9C57C db 0FAh
byte_7FFB0FE9C57D db 0ACh
dword_7FFB0FE9C580 dd 677A489Bh
dword_7FFB0FE9C584 dd 8429D8B9h
byte_7FFB0FE9C588 db 16h
byte_7FFB0FE9C589 db 38h
dword_7FFB0FE9C58C dd 12F04DFAh
dword_7FFB0FE9C590 dd 6D0AA7D5h
byte_7FFB0FE9C594 db 0Fh
dword_7FFB0FE9C598 dd 26D0AC8Fh
byte_7FFB0FE9C59C db 60h
dword_7FFB0FE9C5A0 dd 0C9D71F60h
qword_7FFB0FE9C5A8 dq -17BD46C086007D03h
qword_7FFB0FE9C5B0 dq 2362B3EF027A346Bh
qword_7FFB0FE9C5B8 dq -9D406E2B56AB1B5h
qword_7FFB0FE9C5C0 dq -4AE93F2BDB052519h
qword_7FFB0FE9C5C8 dq 19187A8CDC3F5103h
qword_7FFB0FE9C5D0 dq -0B30EBE59EA2C137h
qword_7FFB0FE9C5D8 dq 4590C2B5D9B87EE2h
qword_7FFB0FE9C5E0 dq -7238C8C7C649AA74h
qword_7FFB0FE9C5E8 dq -590B5E390BB7ABD0h
qword_7FFB0FE9C5F0 dq -4BD674D4A852E4A0h
qword_7FFB0FE9C5F8 dq 75DA5F1E6761A4A8h
qword_7FFB0FE9C600 dq 408FA46F6581E530h
dword_7FFB0FED857C dd 0F140B889h
dword_7FFB0FED8580 dd 149CC61Bh
dword_7FFB0FED8584 dd 0ACB7F8D5h
dword_7FFB0FED8588 dd 0A7BC8F08h
dword_7FFB0FED858C dd 4CDD1857h
dword_7FFB0FED8590 dd 40D52EE5h
dword_7FFB0FED8594 dd 0F3CF5F0Bh
dword_7FFB0FED8598 dd 59E2547Ah
dword_7FFB0FED859C dd 0E1FF8E6Fh
dword_7FFB0FED85A0 dd 0E28AB3Eh
dword_7FFB0FED85A4 dd 0CBBB2749h
dword_7FFB0FED85A8 dd 31D7545Ah
dword_7FFB0FED85AC dd 510A8044h
dword_7FFB0FED85B0 dd 0C85A4ED8h
dword_7FFB0FED85B4 dd 37367A87h
dword_7FFB0FED85B8 dd 618515BBh
dword_7FFB0FED85BC dd 6830403Bh
dword_7FFB0FED85C0 dd 3B255E2Fh
dword_7FFB0FED85C4 dd 3BF23BE6h
dword_7FFB0FED85C8 dd 0ED3AB957h
dword_7FFB0FED85CC dd 0C5215647h
dword_7FFB0FED85D0 dd 63AD0FB0h
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC sub_7FFB0E086BE0
sub_7FFB0E086BE0:
    push r15
    push r14
    push r13
    push r12
    push rsi
    push rdi
    push rbp
    push rbx
    sub rsp, 238h
    mov r12, r9
    mov rax, qword ptr [__security_cookie]
    xor rax, rsp
    mov qword ptr [rsp+230h], rax
    mov r13, -0D1B5571EEC53855h
    mov rbp, -11DFDD7F47900ADAh
    mov eax, 1D194F57h
    xor eax, dword ptr [dword_7FFB0FED8588]
    lea ecx, [rax+3C1F9FCBh]
    lea edx, [rax+7B2EAF61h]
    mov r8d, 5AE3B439h
    sub r8d, eax
    xor r8d, edx
    sub r8d, eax
    xor r8d, ecx
    mov dword ptr [rsp+48h], r8d
    lea r15, jpt_7FFB0E08A81A
    lea r14, jpt_7FFB0E08ABE7
    lea rsi, jpt_7FFB0E08AB91
    lea rbx, [rsp+22Ch]
    mov qword ptr [rsp+0F8h], r9
    jmp loc_7FFB0E086D93
    loc_7FFB0E086C74:
    mov rax, qword ptr [qword_7FFB0FE9C5F0]
    mov qword ptr [rsp+148h], rax
    mov rcx, 59243BC1C38A0F10h
    add rax, rcx
    mov qword ptr [rsp+108h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+108h]
    mov rcx, -2FAEAAF1E05C7695h
    xor rax, rcx
    mov qword ptr [rsp+150h], rax
    mov rcx, -69C0C391AE331BC5h
    add rcx, rax
    mov qword ptr [rsp+158h], rcx
    mov rcx, -22F4C986D1C10475h
    add rcx, rax
    mov qword ptr [rsp+160h], rcx
    mov rcx, 4DF2E7B6AAC88EF6h
    add rax, rcx
    mov qword ptr [rsp+168h], rax
    mov eax, dword ptr [dword_7FFB0FED85A8]
    mov ecx, eax
    xor ecx, -464F8977h
    lea edx, [rcx-5C6EAEACh]
    xor edx, ecx
    xor edx, 17786EFDh
    add edx, eax
    sub edx, ecx
    add edx, -3FC848BFh
    loc_7FFB0E086D8F:
    mov dword ptr [rsp+48h], edx
    loc_7FFB0E086D93:
    mov eax, dword ptr [rsp+48h]
    cmp eax, 4C815852h
    jg loc_7FFB0E086F90
    cmp eax, 295D4032h
    jg loc_7FFB0E087060
    cmp eax, 2244B5ECh
    jle loc_7FFB0E08A8AE
    cmp eax, 2244B5EDh
    jz loc_7FFB0E08AD6F
    cmp eax, 22DF5749h
    jnz loc_7FFB0E08B27D
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+50h]
    not rax
    mov qword ptr [rsp+1E0h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+50h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rsp+50h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rsp+50h]
    sub rdx, rcx
    lea rax, [rdx+rax*2]
    mov qword ptr [rsp+1E8h], rax
    mov eax, dword ptr [dword_7FFB0FED85CC]
    lea ecx, [rax+13D7A82Ah]
    add eax, -0F721BDAh
    mov edx, eax
    xor edx, -34738B4Ch
    sub edx, eax
    add edx, -1A0A7B61h
    xor edx, ecx
    jmp loc_7FFB0E086D8F
    loc_7FFB0E086F90:
    cmp eax, 6E642F98h
    jg loc_7FFB0E08A820
    cmp eax, 51FAE031h
    jle loc_7FFB0E08AB2B
    cmp eax, 51FAE032h
    jz loc_7FFB0E08AC0E
    cmp eax, 643B57E8h
    jnz loc_7FFB0E08AE34
    mov rax, qword ptr [rsp+110h]
    and rax, qword ptr [rsp+190h]
    shl rax, 3
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rax, qword ptr [rsp+188h]
    add rax, qword ptr [rsp+180h]
    mov qword ptr [rsp+198h], rax
    mov eax, dword ptr [dword_7FFB0FED85BC]
    mov ecx, eax
    xor ecx, -53F70C9Dh
    add eax, -4E68A6E6h
    xor eax, ecx
    add eax, ecx
    add eax, -78629EDCh
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E086D93
    loc_7FFB0E087060:
    cmp eax, 2A9EEF90h
    jle loc_7FFB0E08A8DF
    cmp eax, 2A9EEF91h
    jz loc_7FFB0E08ABE9
    cmp eax, 2D86BB91h
    jnz loc_7FFB0E08AC8D
    rdtsc
    mov qword ptr [rsp+20h], rbx
    mov ecx, 2
    mov r8d, 0Eh
    mov r9d, 21h
    mov edx, eax
    call sub_7FFB0ECBE2C0
    mov ecx, 10h
    mov r8d, 4Ch
    mov r9d, 2Dh
    mov rdx, rbx
    call sub_7FFB0DE6D7D0
    mov byte ptr [rsp+4Fh], al
    mov ecx, dword ptr [dword_7FFB0FE9C548]
    mov eax, ecx
    xor eax, -2BE7731Ah
    lea edx, [rax-6A7BF013h]
    mov r8d, edx
    not r8d
    mov r9d, r8d
    or r9d, 6F02A5FEh
    mov r10d, r8d
    and r10d, -6F02A5FFh
    add r10d, r9d
    and edx, 6F02A5FEh
    add edx, edx
    xor edx, -21FAB404h
    add edx, r10d
    sub edx, r8d
    add edx, eax
    add eax, 3651992Ah
    add ecx, edx
    add ecx, 4496BFDDh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor ecx, eax
    mov qword ptr [rsp+20h], rbx
    mov edx, 46h
    mov r8d, 1Ch
    mov r9d, 51h
    call sub_7FFB0F148750
    mov ecx, eax
    not ecx
    movzx edx, byte ptr [rsp+4Fh]
    dec dl
    movzx edi, byte ptr [byte_7FFB0FE9C54C]
    lea r11d, [rdi+33h]
    mov r10d, r11d
    xor r10b, 25h
    lea r8d, [r10+1Fh]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r9d, [r10-48h]
    lea r15d, [r10-47h]
    mov r14d, r15d
    not r14b
    and r14b, 5
    shl r14b, 2
    mov r12d, r15d
    or r12b, 45h
    movzx r12d, r12b
    lea r12d, [r12]
    mov r13d, r15d
    and r13b, 3Ah
    shl r13b, 2
    mov ebp, r15d
    and bpl, 45h
    movzx ebp, bpl
    lea ebp, [rbp+rbp*2+0]
    neg ebp
    sub bpl, r13b
    add bpl, r12b
    sub bpl, r14b
    add r15b, dil
    add r15b, bpl
    add r15b, 7Dh
    xor r8b, r11b
    xor r8b, r15b
    add r8b, r10b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11d, r9d
    not r11b
    mov r10d, r8d
    or r10b, r11b
    mov edi, r8d
    or dil, r9b
    mov ebp, r8d
    and bpl, r11b
    xor r11b, r8b
    add r11b, dil
    lea edi, [r8+r8]
    movzx r14d, bpl
    lea ebp, [r14+r14*2]
    and r8b, r9b
    movzx r8d, r8b
    lea r8d, [r8+r8*2]
    add r8b, bpl
    sub r8b, dil
    add r8b, r11b
    sub r8b, r10b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and ecx, 3Fh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9d, eax
    or r9d, 3Fh
    mov r10d, r9d
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r10d, r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9d, r9d
    lea r9d, [r9+r9*2]
    mov r11d, eax
    and r11d, 3FFFFFC0h
    mov edi, eax
    and edi, 3Fh
    lea edi, [rdi+rdi*4]
    lea r11d, [rdi+r11*4]
    sub r11d, r9d
    sub r11d, r10d
    cmp dl, r8b
    lea ecx, [r11+rcx*4-2]
    cmovnb ecx, eax
    mov dword ptr [rsp+0D0h], ecx
    rdtsc
    mov qword ptr [rsp+20h], rbx
    mov ecx, 2Bh
    mov r8d, 20h
    mov r9d, 10h
    mov edx, eax
    call sub_7FFB0ECBE2C0
    mov ecx, 63h
    mov r8d, 15h
    mov r9d, 7
    mov rdx, rbx
    call sub_7FFB0DE6D7D0
    mov byte ptr [rsp+3Fh], al
    mov edx, dword ptr [dword_7FFB0FE9C550]
    lea eax, [rdx-7438DDEAh]
    lea r8d, [rdx+592FE9E7h]
    lea r9d, [rdx+467399E7h]
    xor r9d, -16035D33h
    mov r10d, r8d
    not r10d
    mov r11d, r10d
    or r11d, -426C7690h
    mov ecx, r10d
    and ecx, 426C768Fh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r8d, 3D938970h
    add r8d, r8d
    xor r8d, 7B2712E0h
    add ecx, r11d
    add ecx, r8d
    sub ecx, r10d
    add ecx, r9d
    sub ecx, edx
    add ecx, 230E05B5h
    xor ecx, eax
    mov qword ptr [rsp+20h], rbx
    mov edx, 1Ah
    mov r8d, 24h
    mov r9d, 54h
    call sub_7FFB0F148750
    movzx ecx, byte ptr [rsp+3Fh]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not cl
    movzx ecx, cl
    lea edx, [rcx*8]
    sub edx, ecx
    movzx ecx, byte ptr [rsp+3Fh]
    lea r8d, [rcx+rcx*4]
    lea ecx, [rcx+r8*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx r8d, byte ptr [rsp+3Fh]
    lea r9d, [r8+r8*8]
    lea r8d, [r8+r9*2]
    sub r8b, cl
    add r8b, dl
    add r8b, 6
    mov ecx, eax
    and ecx, 3Fh
    cmp r8b, 2
    cmovnb ecx, eax
    mov dword ptr [rsp+0D4h], ecx
    rdtsc
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+20h], rbx
    mov ecx, 2Bh
    mov r8d, 43h
    mov r9d, 9
    mov edx, eax
    call sub_7FFB0ECBE2C0
    mov ecx, 0Ch
    mov r8d, 7
    mov r9d, 10h
    mov rdx, rbx
    call sub_7FFB0DE6D7D0
    mov byte ptr [rsp+44h], al
    mov eax, dword ptr [dword_7FFB0FE9C554]
    mov ecx, eax
    xor ecx, -153FA508h
    mov edx, eax
    xor edx, 112B2107h
    and edx, -26D4D609h
    lea r8d, [rdx+rdx*4]
    lea r8d, [rdx+r8*2]
    mov edx, ecx
    or edx, -26D4D609h
    lea r9d, [rdx+rdx*4]
    lea r9d, [rdx+r9*2]
    mov r10d, eax
    xor r10d, 33EB730Fh
    mov edx, ecx
    and edx, 26D4D608h
    lea r11d, [rdx+rdx*8]
    mov edx, ecx
    and edx, -26D4D609h
    imul edx, 0F5h
    sub edx, r11d
    sub edx, r10d
    add edx, r9d
    sub edx, r8d
    xor edx, -5FD24A19h
    mov r8d, ecx
    or r8d, -630CB396h
    lea r9d, [r8+r8*2]
    not r8d
    lea r10d, [r8*8]
    sub r10d, r8d
    and ecx, -630CB396h
    lea ecx, [rcx+r9*2]
    add ecx, r10d
    neg ecx
    lea r8d, [rdx+rcx]
    add r8d, -7
    xor r8d, edx
    mov ecx, r8d
    xor ecx, -31C4C913h
    xor r8d, 31C4C912h
    add r8d, r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edx, eax
    not edx
    mov r9d, ecx
    or r9d, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    or eax, ecx
    not eax
    and edx, ecx
    lea ecx, [rdx+rax*2]
    add ecx, r9d
    sub ecx, r8d
    mov qword ptr [rsp+20h], rbx
    mov edx, 57h
    mov r8d, 58h
    mov r9d, 2Ah
    call sub_7FFB0F148750
    movzx ecx, byte ptr [rsp+44h]
    dec cl
    movzx r8d, byte ptr [byte_7FFB0FE9C558]
    lea edx, [r8-4Ah]
    mov r9d, edx
    xor r9b, 75h
    mov r10b, 77h
    sub r10b, r8b
    xor r10b, r8b
    xor dl, 8Ah
    mov r11d, r10d
    or r11b, dl
    or r9b, r10b
    and dl, r10b
    not r10b
    add r10b, r10b
    not r11b
    not r9b
    add r9b, r9b
    add dl, r11b
    add dl, r9b
    sub dl, r10b
    add dl, r8b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add dl, 9Ch
    mov r8d, dword ptr [dword_7FFB0FE9C55C]
    lea r9d, [r8+275637FAh]
    xor r8d, r9d
    xor r9d, 6F03148Ah
    lea r10d, [r9-364336EDh]
    mov r11d, r10d
    xor r11d, -427D813Ah
    xor r8d, 716D5EE5h
    sub r8d, r11d
    sub r8d, r10d
    sub r8d, r9d
    and r8d, eax
    cmp cl, dl
    cmovnb r8d, eax
    mov dword ptr [rsp+0D8h], r8d
    rdtsc
    mov qword ptr [rsp+20h], rbx
    mov ecx, 3
    mov r8d, 0Ch
    mov r9d, 4
    mov edx, eax
    call sub_7FFB0ECBE2C0
    mov ecx, 37h
    mov r8d, 3Eh
    mov r9d, 11h
    mov rdx, rbx
    call sub_7FFB0DE6D7D0
    mov byte ptr [rsp+45h], al
    mov eax, dword ptr [dword_7FFB0FE9C560]
    lea edx, [rax-73D1057Dh]
    lea ecx, [rax-48C4AC71h]
    xor ecx, eax
    xor ecx, edx
    sub ecx, eax
    add ecx, 3C8D98F3h
    mov qword ptr [rsp+20h], rbx
    mov edx, 54h
    mov r8d, 45h
    mov r9d, 0Dh
    call sub_7FFB0F148750
    movzx ecx, byte ptr [rsp+45h]
    dec cl
    movzx edx, byte ptr [byte_7FFB0FE9C564]
    lea r10d, [rdx+5Dh]
    mov r9d, r10d
    xor r9b, 0E0h
    lea r8d, [r9+29h]
    sub dl, r8b
    add dl, 1Bh
    xor dl, r10b
    xor r10b, 1Fh
    mov r11d, edx
    or r11b, r10b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edi, edx
    mov ebp, edx
    xor bpl, r9b
    movzx r14d, bpl
    lea ebp, [r14+r14*2]
    and r10b, dl
    and dl, r9b
    sub dl, r10b
    add dl, bpl
    sub dl, r11b
    not r11b
    shl r11b, 2
    or dil, r9b
    not dil
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add dl, dil
    sub dl, r11b
    add dl, r8b
    mov r9d, dword ptr [dword_7FFB0FE9C568]
    mov r8d, r9d
    xor r8d, -54B9055Eh
    lea r10d, [r8+65B44D14h]
    xor r10d, -211C99A1h
    add r10d, -3C6366h
    xor r10d, r8d
    mov r11d, r9d
    not r11d
    mov edi, r10d
    or edi, r11d
    not edi
    mov ebp, r10d
    or ebp, r9d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r14d, r11d
    xor r14d, r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r15d, [r10+r10]
    and r11d, r10d
    lea r11d, [r11+r11*2]
    and r10d, r9d
    lea r9d, [r10+r10*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9d, r11d
    sub r9d, r15d
    add r14d, ebp
    add r14d, edi
    add r14d, r9d
    add r8d, r14d
    add r8d, 599E296Fh
    and r8d, eax
    cmp cl, dl
    cmovnb r8d, eax
    mov dword ptr [rsp+0DCh], r8d
    rdtsc
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+20h], rbx
    mov ecx, 21h
    mov r8d, 6
    mov r9d, 15h
    mov edx, eax
    call sub_7FFB0ECBE2C0
    mov ecx, 0Eh
    mov r8d, 37h
    mov r9d, 0Fh
    mov rdx, rbx
    call sub_7FFB0DE6D7D0
    mov byte ptr [rsp+40h], al
    mov edx, dword ptr [dword_7FFB0FE9C56C]
    lea eax, [rdx+60F7BC9Ch]
    mov ecx, eax
    not ecx
    and ecx, 32672029h
    shl ecx, 2
    mov r8d, eax
    or r8d, 72672029h
    lea r8d, [r8+r8*4]
    mov r9d, eax
    and r9d, 0D98DFD6h
    mov r10d, eax
    and r10d, 72672029h
    lea r10d, [r10+r10*2]
    lea r9d, [r10+r9*4]
    sub r8d, r9d
    sub r8d, ecx
    add r8d, 1B31BFAEh
    mov ecx, 432EF310h
    sub ecx, edx
    xor ecx, r8d
    xor ecx, -7C59A707h
    sub ecx, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub ecx, edx
    add ecx, -265753E7h
    xor ecx, eax
    mov qword ptr [rsp+20h], rbx
    mov edx, 4Fh
    mov r8d, 31h
    mov r9d, 2Ch
    call sub_7FFB0F148750
    movzx ecx, byte ptr [rsp+40h]
    not cl
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
    lea ecx, [rcx+rcx*2]
    movzx edx, byte ptr [rsp+40h]
    not dl
    movzx edx, dl
    lea edx, [rdx+rdx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx r8d, byte ptr [rsp+40h]
    mov r9d, r8d
    not r9b
    movzx r9d, r9b
    lea r10d, [r9*8]
    sub r10d, r9d
    add r8b, r8b
    add r8b, r10b
    sub r8b, dl
    sub r8b, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, eax
    and ecx, 3Fh
    cmp r8b, 2
    cmovnb ecx, eax
    mov dword ptr [rsp+0E0h], ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    rdtsc
    mov qword ptr [rsp+20h], rbx
    mov ecx, 28h
    mov r8d, 5Ah
    mov r9d, 5Bh
    mov edx, eax
    call sub_7FFB0ECBE2C0
    mov ecx, 11h
    mov r8d, 3Ah
    mov r9d, 18h
    mov rdx, rbx
    call sub_7FFB0DE6D7D0
    mov byte ptr [rsp+46h], al
    mov edx, dword ptr [dword_7FFB0FE9C570]
    mov eax, edx
    not eax
    mov ecx, eax
    and ecx, 796F90AAh
    lea ecx, [rcx+rcx*2]
    mov r8d, eax
    and r8d, 6906F55h
    shl r8d, 2
    or eax, 796F90AAh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    sub eax, edx
    sub eax, r8d
    sub eax, ecx
    add eax, -3
    mov r8d, eax
    xor r8d, 4868280Fh
    lea r9d, [r8-6FDBA017h]
    mov ecx, r9d
    not ecx
    and ecx, -7960DBACh
    lea r10d, [rcx+rcx*4]
    lea r10d, [rcx+r10*4]
    mov r11d, r9d
    or r11d, -7960DBACh
    lea ecx, [r11+r11*4]
    lea ecx, [r11+rcx*2]
    not r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea edi, [r11+r11*4]
    lea r11d, [r11+rdi*2]
    mov edi, r9d
    and edi, -7960DBACh
    lea ebp, [rdi+rdi*8]
    not edi
    lea r14d, [rdi+rdi*4]
    lea edi, [rdi+r14*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r14d, r9d
    and r14d, 7960DBABh
    lea r15d, [r14+r14*4]
    lea r14d, [r14+r15*4]
    add ebp, r14d
    sub ecx, ebp
    add ecx, edi
    sub ecx, r11d
    sub ecx, r10d
    sub r9d, ecx
    add ecx, -6B20F5C6h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add edx, r9d
    add edx, -60952EDCh
    xor ecx, eax
    xor ecx, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add ecx, r8d
    mov qword ptr [rsp+20h], rbx
    mov edx, 7
    mov r8d, 54h
    mov r9d, 4Dh
    call sub_7FFB0F148750
    movzx ecx, byte ptr [rsp+46h]
    dec cl
    mov edx, dword ptr [dword_7FFB0FE9C574]
    mov r8d, -6E8C59B1h
    xor edx, r8d
    lea r8d, [rdx-375E0426h]
    mov r9d, r8d
    or r9d, -0E942304h
    lea r10d, [r9+r9*2]
    not r9d
    lea r11d, [r9*8]
    sub r11d, r9d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r8d, -0E942304h
    lea r9d, [r8+r10*2]
    add r9d, r11d
    mov r8d, -6F39046Eh
    sub r8d, r9d
    mov r9d, r8d
    not r9d
    mov r10d, r8d
    or r10d, -573758A9h
    mov r11d, r8d
    xor r11d, 573758A8h
    lea r11d, [r11+r11*2]
    mov edi, r8d
    and edi, -573758A9h
    and r8d, 573758A8h
    sub r8d, edi
    add r8d, r11d
    sub r8d, r10d
    not r10d
    shl r10d, 2
    and r9d, -573758A9h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8d, r9d
    sub r8d, r10d
    mov r9d, 5693B587h
    sub r9d, edx
    xor r9d, r8d
    add r9d, edx
    and r9d, eax
    cmp cl, 2
    cmovnb r9d, eax
    mov dword ptr [rsp+0E4h], r9d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+20h], rbx
    mov ecx, 1Ch
    mov r8d, 16h
    mov r9d, 24h
    mov edx, eax
    call sub_7FFB0ECBE2C0
    mov ecx, 6
    mov r8d, 29h
    mov r9d, 51h
    mov rdx, rbx
    call sub_7FFB0DE6D7D0
    mov byte ptr [rsp+47h], al
    mov eax, dword ptr [dword_7FFB0FE9C578]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea edx, 5D0F13Ah[rax*2]
    lea r8d, 0BA1E274h[rax*4]
    add eax, -7B096089h
    mov ecx, eax
    not ecx
    mov r9d, edx
    or r9d, ecx
    mov r10d, edx
    or r10d, eax
    mov r11d, edx
    and r11d, ecx
    xor ecx, edx
    lea r11d, [r11+r11*2]
    and eax, edx
    lea eax, [rax+rax*2]
    add eax, r11d
    sub eax, r8d
    add ecx, r10d
    add ecx, eax
    sub ecx, r9d
    mov qword ptr [rsp+20h], rbx
    mov edx, 4
    mov r8d, 47h
    mov r9d, 2Ch
    call sub_7FFB0F148750
    movzx edx, byte ptr [byte_7FFB0FE9C57C]
    mov r10d, edx
    xor r10b, 2Fh
    add r10b, 22h
    mov r8d, r10d
    xor r8b, 8Ah
    lea r9d, [r8+59h]
    mov ecx, r9d
    xor cl, 21h
    sub r9b, cl
    add cl, 27h
    add r9b, r10b
    add r9b, 0CCh
    mov r10d, ecx
    not r10b
    mov r11d, r9d
    or r11b, r10b
    not r11b
    movzx edi, r11b
    mov r11d, r9d
    or r11b, cl
    not r11b
    movzx r14d, r11b
    mov r11d, r9d
    and r10b, r9b
    and r9b, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not r11b
    lea edi, [rdi+rdi*8]
    add r14d, r14d
    lea ecx, [r14+r14*4]
    movzx r9d, r9b
    lea r14d, [r9+r9*4]
    lea r9d, [r9+r14*2]
    add r9b, r10b
    not r10b
    movzx r10d, r10b
    lea r14d, [r10+r10*4]
    lea r10d, [r10+r14*2]
    sub r9b, r10b
    add cl, dil
    add cl, r9b
    add cl, r11b
    xor cl, r8b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub cl, dl
    add cl, byte ptr [rsp+47h]
    movzx edi, byte ptr [byte_7FFB0FE9C57D]
    mov r8d, edi
    not r8b
    mov edx, r8d
    and dl, 7Bh
    movzx edx, dl
    lea edx, [rdx+rdx*2]
    mov r9d, r8d
    and r9b, 4
    shl r9b, 2
    or r8b, 7Bh
    lea r10d, [rdi+rdi]
    sub r8b, r10b
    sub r8b, r9b
    sub r8b, dl
    add r8b, 0FDh
    mov r14d, r8d
    xor r14b, 0EDh
    lea r11d, [r14+38h]
    mov r9d, r11d
    xor r9b, 0ABh
    lea edx, [r9+5Fh]
    mov r10d, edx
    xor r10b, 0EFh
    add r10b, 0B0h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r10b, dil
    xor r10b, 97h
    add r10b, r14b
    mov edi, r10d
    not dil
    movzx edi, dil
    lea edi, [rdi+rdi*2]
    mov ebp, r11d
    not bpl
    mov r14d, r10d
    or r14b, bpl
    not r14b
    movzx r14d, r14b
    lea r15d, [r14+r14*2]
    mov r14d, r10d
    or r14b, r11b
    not r14b
    movzx r14d, r14b
    lea r12d, [r14+r14*2]
    mov r14d, r10d
    xor r14b, r11b
    movzx r13d, r14b
    lea r14d, [r13*8]
    sub r14d, r13d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and bpl, r10b
    movzx r13d, bpl
    add r13d, r13d
    lea ebp, [r13+r13*2+0]
    and r10b, r11b
    add r10b, r10b
    sub r10b, bpl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r14b, r12b
    add r14b, r10b
    sub r14b, r15b
    sub r14b, dil
    add dl, r9b
    add dl, r14b
    sub dl, r8b
    mov r8d, dword ptr [dword_7FFB0FE9C580]
    mov r9d, r8d
    or r9d, 42127E50h
    lea r10d, [r9+r9*4]
    lea r10d, [r9+r10*2]
    not r9d
    lea r11d, [r9*8]
    sub r11d, r9d
    mov r9d, r8d
    not r9d
    mov edi, r9d
    and edi, 42127E50h
    mov ebp, edi
    shl ebp, 4
    add ebp, edi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edi, r8d
    and edi, 42127E50h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r14d, [rdi+rdi*2]
    not edi
    add edi, edi
    lea edi, [rdi+rdi*2]
    mov r15d, r8d
    and r15d, -42127E51h
    lea r12d, [r15+r15*8]
    lea r15d, [r12]
    lea r14d, [r15+r14*4]
    sub r14d, r10d
    sub r14d, edi
    add r14d, ebp
    lea r10d, [r11+r14]
    add r10d, -28DCE710h
    add r11d, r14d
    add r11d, 1A0E50F4h
    mov edi, r11d
    xor edi, -1D0E411Ch
    lea ebp, [rdi-22A68A43h]
    mov r15d, 2F093E5Eh
    sub r15d, edi
    xor r15d, r11d
    xor r15d, ebp
    xor r11d, 1D0E411Bh
    mov r14d, r15d
    or r14d, r11d
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
    lea r12d, [r14+r14*4]
    lea r12d, [r12]
    mov r14d, r15d
    and r11d, r15d
    mov r13d, r15d
    or r13d, edi
    lea r15d, [r13+r13*4+0]
    lea r15d, [r13+r15*2+0]
    not r13d
    lea ebp, [r13+r13*4+0]
    lea ebp, [r13+rbp*2+0]
    and r14d, edi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r13d, [r14+r14*8]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea esi, [r14+r14*4]
    lea esi, [r14+rsi*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r14d, [r11+r11*4]
    lea r11d, [r11+r14*4]
    add r13d, r11d
    sub r15d, r13d
    add r15d, esi
    sub r15d, ebp
    sub r15d, r12d
    mov r11d, r15d
    not r11d
    mov esi, r15d
    or esi, r9d
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
    lea r14d, [rsi+rsi*4]
    lea esi, [rsi+r14*2]
    mov ebp, r15d
    or ebp, r8d
    lea r14d, [r8+r8*4]
    lea r14d, [r8+r14*2]
    and r9d, r15d
    and r15d, r8d
    imul r8d, r15d, 0F5h
    add r9d, r14d
    add r9d, ebp
    add r9d, r8d
    sub r9d, esi
    add r9d, r11d
    add edi, r9d
    add edi, 481EC704h
    mov r8d, edi
    not r8d
    mov r11d, r10d
    not r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9d, edi
    or r9d, r11d
    not r9d
    lea r9d, [r9+r9*8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov esi, edi
    or esi, r10d
    not esi
    lea esi, [rsi+rsi*4]
    and r11d, edi
    and edi, r10d
    lea r10d, [rdi+rdi*4]
    lea r10d, [rdi+r10*2]
    add r10d, r11d
    not r11d
    lea edi, [r11+r11*4]
    lea r11d, [r11+rdi*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r10d, r11d
    lea r10d, [r10+rsi*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add r9d, r10d
    and r9d, eax
    cmp cl, dl
    cmovnb r9d, eax
    mov dword ptr [rsp+0E8h], r9d
    rdtsc
    mov qword ptr [rsp+20h], rbx
    mov ecx, 36h
    mov r8d, 2
    mov r9d, 3Ch
    mov edx, eax
    call sub_7FFB0ECBE2C0
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, 21h
    mov r8d, 62h
    mov r9d, 63h
    mov rdx, rbx
    call sub_7FFB0DE6D7D0
    mov byte ptr [rsp+41h], al
    mov ecx, dword ptr [dword_7FFB0FE9C584]
    lea edx, [rcx-1AB4CCA3h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor edx, -4FD37F10h
    lea eax, [rdx+41D9A2F7h]
    lea r8d, [rdx+6CC84394h]
    lea r9d, [rax+rax*4]
    lea r9d, [rdx+r9*2]
    add r9d, 41D9A2F7h
    xor edx, ecx
    xor edx, r8d
    xor edx, -1FF9BFD7h
    add edx, ecx
    add edx, -1AB4CCA3h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, eax
    not ecx
    mov r8d, edx
    or r8d, ecx
    not r8d
    lea r10d, [r8+r8*4]
    lea r8d, [r8+r10*2]
    mov r10d, edx
    or r10d, eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and ecx, edx
    and eax, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add ecx, r9d
    add ecx, r10d
    add ecx, eax
    sub ecx, r8d
    sub ecx, edx
    mov qword ptr [rsp+20h], rbx
    mov edx, 2
    mov r8d, 3
    mov r9d, 2Ah
    call sub_7FFB0F148750
    movzx edx, byte ptr [byte_7FFB0FE9C588]
    lea r8d, [rdx-3Bh]
    mov r9d, r8d
    mov ecx, r8d
    mov r10d, r8d
    inc dl
    xor dl, r8b
    not r8b
    and r8b, 28h
    shl r8b, 2
    or r9b, 0A8h
    movzx r9d, r9b
    lea r9d, [r9+r9*4]
    and cl, 17h
    shl cl, 2
    and r10b, 0A8h
    movzx r10d, r10b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r10d, [r10+r10*2]
    neg r10d
    sub r10b, cl
    add r10b, r9b
    sub r10b, r8b
    add r10b, 0B0h
    xor dl, r10b
    mov r8d, edx
    not r8b
    movzx r9d, byte ptr [rsp+41h]
    mov ecx, r9d
    or cl, r8b
    movzx ecx, cl
    lea r10d, [rcx+rcx*4]
    lea r11d, [rcx+r10*2]
    not cl
    movzx ecx, cl
    lea r10d, [rcx*8]
    sub r10d, ecx
    mov ecx, r9d
    or cl, dl
    not cl
    movzx esi, cl
    mov ecx, esi
    shl ecx, 4
    add ecx, esi
    and r9b, r8b
    not r9b
    movzx r9d, r9b
    add r9d, r9d
    lea r9d, [r9+r9*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r8b, byte ptr [rsp+41h]
    movzx r8d, r8b
    shl r8d, 2
    lea r8d, [r8+r8*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and dl, byte ptr [rsp+41h]
    movzx edx, dl
    lea esi, [rdx+rdx*8]
    lea edx, [rdx+rsi*2]
    add dl, r8b
    sub dl, r11b
    sub dl, r9b
    add cl, r10b
    add cl, dl
    movzx edx, byte ptr [byte_7FFB0FE9C589]
    mov r8d, edx
    xor r8b, 56h
    lea r10d, [r8+14h]
    lea r11d, [r8-3Fh]
    add r8b, 0E1h
    xor r11b, 0A0h
    mov r9d, r11d
    or r9b, r10b
    not r9b
    movzx r9d, r9b
    add r9d, r9d
    lea r9d, [r9+r9*2]
    mov esi, r10d
    not sil
    mov edi, r11d
    or dil, sil
    movzx edi, dil
    add edi, edi
    lea edi, [rdi+rdi*2]
    mov ebp, r11d
    xor bpl, r10b
    and sil, r11b
    movzx esi, sil
    add esi, esi
    lea esi, [rsi+rsi*2]
    and r11b, r10b
    movzx r10d, r11b
    add r10d, r10d
    lea r11d, [r10+r10*2]
    add r11b, sil
    add r11b, bpl
    sub r11b, dil
    add r9b, r8b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r10d, r8d
    not r10b
    mov esi, r10d
    and sil, 66h
    add sil, sil
    add r10b, r10b
    or r10b, 0CCh
    xor r8b, 99h
    sub r10b, r8b
    sub r10b, sil
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r10b, r9b
    add r10b, r11b
    add r10b, 8
    mov r9d, edx
    not r9b
    mov r8d, r10d
    or r8b, r9b
    not r8b
    movzx r8d, r8b
    lea r11d, [r8+r8*4]
    lea r8d, [r8+r11*2]
    mov r11d, r10d
    or r11b, dl
    movzx r11d, r11b
    lea esi, [r11+r11*4]
    lea r11d, [r11+rsi*2]
    mov esi, r10d
    xor sil, dl
    and r9b, r10b
    movzx r9d, r9b
    lea r9d, [r9+r9*8]
    and r10b, dl
    movzx edx, r10b
    imul edx, 0F5h
    sub dl, r9b
    sub dl, sil
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add dl, r11b
    sub dl, r8b
    mov r8d, dword ptr [dword_7FFB0FE9C58C]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r9d, [r8+6D894655h]
    mov r10d, r9d
    xor r10d, 4D2BEEC7h
    lea r11d, [r10-191F3AB7h]
    xor r11d, 582CFE1Ch
    add r11d, r8d
    lea r8d, [r10+r11]
    add r8d, -4BE8F5DFh
    xor r8d, r9d
    and r8d, eax
    cmp cl, dl
    cmovnb r8d, eax
    mov dword ptr [rsp+0ECh], r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    rdtsc
    mov qword ptr [rsp+20h], rbx
    mov ecx, 61h
    mov r8d, 0Eh
    mov r9d, 0Bh
    mov edx, eax
    call sub_7FFB0ECBE2C0
    mov ecx, 38h
    mov r8d, 54h
    mov r9d, 3Bh
    mov rdx, rbx
    call sub_7FFB0DE6D7D0
    mov byte ptr [rsp+42h], al
    mov eax, dword ptr [dword_7FFB0FE9C590]
    mov ecx, eax
    not ecx
    mov r9d, eax
    or r9d, -4B961D4Fh
    and ecx, 3469E2B1h
    shl ecx, 2
    and eax, -4B961D4Fh
    mov r10d, eax
    not r10d
    add r10d, r10d
    sub r10d, eax
    sub r10d, ecx
    lea ecx, [r10+r9]
    lea r8d, [r10+r9]
    add r8d, 36E786DBh
    lea edx, [r10+r9+78F3308Ah]
    mov eax, edx
    not eax
    mov r11d, eax
    and r11d, -345695E0h
    lea r11d, [r11+r11*2]
    mov esi, eax
    and esi, 345695DFh
    shl esi, 2
    or eax, -345695E0h
    add edx, edx
    sub eax, edx
    sub eax, esi
    sub eax, r11d
    lea edx, [rax-13FCA836h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9d, r10d
    add r9d, 4DD02936h
    mov r10d, r8d
    not r10d
    mov r11d, r9d
    or r11d, r10d
    not r11d
    lea esi, [r11+r11*4]
    lea r11d, [r11+rsi*2]
    mov esi, r9d
    or esi, r8d
    lea edi, [rsi+rsi*4]
    lea esi, [rsi+rdi*2]
    mov edi, r9d
    xor edi, r8d
    and r10d, r9d
    lea r10d, [r10+r10*8]
    and r9d, r8d
    imul r8d, r9d, 0F5h
    sub r8d, r10d
    sub r8d, edi
    add r8d, esi
    sub r8d, r11d
    add ecx, r8d
    add ecx, 78F3308Ah
    sub ecx, edx
    add ecx, 34C987F0h
    mov r8d, ecx
    or r8d, edx
    lea r9d, [r8+r8*2]
    not r8d
    lea r10d, [r8*8]
    sub r10d, r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and ecx, edx
    lea edx, [rcx+r9*2]
    add edx, eax
    add edx, r10d
    mov ecx, -4
    sub ecx, edx
    mov qword ptr [rsp+20h], rbx
    mov edx, 17h
    mov r8d, 4Ah
    mov r9d, 15h
    call sub_7FFB0F148750
    movzx edx, byte ptr [byte_7FFB0FE9C594]
    mov r8d, edx
    xor r8b, 0FDh
    mov ecx, edx
    xor cl, 9Ch
    sub cl, r8b
    sub cl, dl
    xor dl, 0CFh
    add dl, 0ADh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor cl, dl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx r8d, byte ptr [rsp+42h]
    mov edx, r8d
    not dl
    movzx edx, dl
    lea edx, [rdx+rdx*2]
    mov r9d, ecx
    not r9b
    or r8b, r9b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not r8b
    movzx r8d, r8b
    lea r8d, [r8+r8*2]
    movzx r10d, byte ptr [rsp+42h]
    or r10b, cl
    not r10b
    movzx r10d, r10b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r10d, [r10+r10*2]
    movzx r11d, byte ptr [rsp+42h]
    mov esi, r11d
    xor sil, cl
    movzx esi, sil
    lea edi, [rsi*8]
    sub edi, esi
    and r9b, r11b
    movzx r9d, r9b
    add r9d, r9d
    lea r9d, [r9+r9*2]
    and cl, r11b
    add cl, cl
    sub cl, r9b
    add cl, dil
    add cl, r10b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub cl, r8b
    sub cl, dl
    mov edx, eax
    and edx, 3Fh
    cmp cl, 2
    cmovnb edx, eax
    mov dword ptr [rsp+0F0h], edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    rdtsc
    mov qword ptr [rsp+20h], rbx
    mov ecx, 3Ch
    mov r8d, 4
    mov r9d, 1Bh
    mov edx, eax
    call sub_7FFB0ECBE2C0
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, 30h
    mov r8d, 6
    mov r9d, 38h
    mov rdx, rbx
    call sub_7FFB0DE6D7D0
    mov byte ptr [rsp+43h], al
    mov ecx, dword ptr [dword_7FFB0FE9C598]
    lea edx, [rcx+60C20C77h]
    lea eax, [rcx+497D6328h]
    mov r8d, eax
    xor r8d, -781DF4EFh
    mov r9d, eax
    xor r9d, 781DF4EEh
    mov r10d, r8d
    and r10d, 3943DE88h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11d, r9d
    and r11d, -46BC2178h
    and r8d, 46BC2177h
    and r9d, 46BC2177h
    add r9d, r9d
    lea r9d, [r9+r8*2]
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
    add r8d, r11d
    add r8d, r9d
    lea r8d, [r8+r10*2]
    add r8d, 2
    xor r8d, edx
    sub r8d, ecx
    mov edx, eax
    not edx
    mov ecx, r8d
    or ecx, edx
    not ecx
    lea r9d, [rcx+rcx*2]
    mov r10d, r8d
    or r10d, eax
    not r10d
    shl r10d, 2
    and edx, r8d
    mov ecx, edx
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
    add edx, edx
    and r8d, eax
    lea eax, [rdx+r8*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    sub ecx, r10d
    sub ecx, r9d
    add ecx, -3
    mov qword ptr [rsp+20h], rbx
    mov edx, 1Ah
    mov r8d, 14h
    mov r9d, 0Ch
    call sub_7FFB0F148750
    movzx ecx, byte ptr [byte_7FFB0FE9C59C]
    lea edx, [rcx+64h]
    lea r8d, [rcx+5Eh]
    add cl, 0BFh
    xor cl, dl
    xor cl, r8b
    mov r9d, ecx
    xor r9b, 9Ah
    xor cl, 65h
    movzx r8d, byte ptr [rsp+43h]
    mov edx, r8d
    or dl, cl
    not dl
    shl dl, 3
    mov r10d, ecx
    xor r10b, r8b
    or r8b, r9b
    not r8b
    shl r8b, 2
    shl r10b, 2
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx r11d, byte ptr [rsp+43h]
    xor r11b, r9b
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
    lea esi, [r11*8]
    sub esi, r11d
    movzx r11d, byte ptr [rsp+43h]
    and cl, r11b
    shl cl, 3
    and r9b, r11b
    add r9b, r9b
    sub cl, r9b
    sub cl, sil
    add cl, r10b
    sub cl, r8b
    add cl, dl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edi, dword ptr [dword_7FFB0FE9C5A0]
    mov r8d, edi
    xor r8d, 2B4DF602h
    lea edx, [r8-33C7BE4h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r10d, [r8-53CA8956h]
    mov r9d, r10d
    xor r9d, -12E5454Eh
    lea r11d, [r9-6054363Ah]
    mov esi, r11d
    or esi, -42A45CDAh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r14d, [rsi+rsi*2]
    not esi
    lea ebp, [rsi*8]
    sub ebp, esi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r11d, -42A45CDAh
    lea r11d, [r11+r14*2]
    add r11d, edi
    add r11d, ebp
    mov esi, 1DA64433h
    sub esi, r8d
    xor r10d, 12E5454Dh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edi, esi
    or edi, r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not edi
    mov ebp, esi
    or ebp, r9d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add ebp, ebp
    mov r14d, esi
    xor r14d, r9d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r10d, esi
    shl r10d, 2
    and esi, r9d
    lea r10d, [r10+rsi*2]
    sub r10d, r14d
    sub r10d, ebp
    lea r10d, [r10+rdi*4]
    add r9d, r10d
    add r9d, -6054363Ah
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r9d, r11d
    add r8d, r9d
    add r8d, -53CA895Dh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov edx, r8d
    not edx
    mov r9d, eax
    or r9d, edx
    mov r10d, r9d
    not r10d
    add r10d, r10d
    mov r11d, eax
    or r11d, r8d
    not r11d
    shl r11d, 2
    shl r9d, 2
    and edx, eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov esi, eax
    and esi, r8d
    lea esi, [rsi+rsi*4]
    lea edx, [rsi+rdx*4]
    sub r9d, edx
    lea edx, [r9+r8*2]
    sub edx, r11d
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
    cmp cl, 2
    cmovnb edx, eax
    mov dword ptr [rsp+0F4h], edx
    movzx eax, byte ptr [rsp+4Fh]
    lea rcx, jpt_7FFB0E08A7BC
    movsxd rax, dword ptr (jpt_7FFB0E08A7BC - 7FFB0FE4EB30h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08A7BE:
    mov eax, dword ptr [rsp+0D0h]
    mov r12, qword ptr [rsp+0F8h]
    xor rax, r12
    mov qword ptr [rsp+88h], rax
    mov rax, qword ptr [rsp+88h]
    mov qword ptr [rsp+58h], rax
    movzx eax, byte ptr [rsp+3Fh]
    lea r15, jpt_7FFB0E08A81A
    movsxd rax, dword ptr (jpt_7FFB0E08A81A - 7FFB0FE4EB54h)[r15+rax*4]
    add rax, r15
    mov r13, -0D1B5571EEC53855h
    mov rbp, -11DFDD7F47900ADAh
    lea r14, jpt_7FFB0E08ABE7
    lea rsi, jpt_7FFB0E08AB91
    jmp rax
    loc_7FFB0E08A820:
    cmp eax, 76916779h
    jle loc_7FFB0E08AB6D
    cmp eax, 7691677Ah
    jz loc_7FFB0E08AC5A
    cmp eax, 7ACCC969h
    jnz loc_7FFB0E08AFDC
    mov rax, qword ptr [rsp+138h]
    xor rax, r12
    mov qword ptr [rsp+88h], rax
    mov eax, dword ptr [dword_7FFB0FED8594]
    lea ecx, [rax-3B8D5161h]
    mov edx, ecx
    xor edx, 27D03EF9h
    mov r8d, ecx
    xor r8d, -738B3DCh
    mov r9d, ecx
    xor r9d, 5D7951CBh
    lea r10d, [r9+18EF8CEFh]
    xor r10d, 6AF65F4Fh
    add r8d, 6A81BCCh
    xor r8d, eax
    add r8d, edx
    lea eax, [r9+r8]
    add eax, 18EF8CEFh
    sub eax, ecx
    sub eax, r10d
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E086D93
    loc_7FFB0E08A8AE:
    cmp eax, 17E34F84h
    jg loc_7FFB0E08AB93
    cmp eax, 5805B2Bh
    jnz loc_7FFB0E08F334
    mov rax, qword ptr [rsp+88h]
    mov qword ptr [rsp+58h], rax
    movzx eax, byte ptr [rsp+3Fh]
    movsxd rax, dword ptr (jpt_7FFB0E08A81A - 7FFB0FE4EB54h)[r15+rax*4]
    add rax, r15
    jmp rax
    loc_7FFB0E08A8DF:
    cmp eax, 295D4033h
    jnz loc_7FFB0E08ACD2
    mov r8, qword ptr [rsp+220h]
    sub r8, qword ptr [rsp+218h]
    mov rax, 498F46C65A7B3E80h
    lea rdx, [r8+rax]
    mov rcx, rdx
    mov rax, 6E5DB624452CBA49h
    xor rcx, rax
    mov rax, rdx
    mov r9, -61FBA4459FF474C4h
    xor rax, r9
    mov r9, rax
    mov rsi, -14F371404B0CF159h
    or r9, rsi
    not r9
    lea r9, [r9+r9*2]
    mov r10, rax
    mov rdi, 14F371404B0CF158h
    and r10, rdi
    lea r10, [r10+r10*2]
    add r10, r10
    mov r11, rax
    and r11, rsi
    lea r11, [r11+r11*2]
    lea r10, [r10+r11*2]
    mov r11, rax
    xor r11, rsi
    lea rsi, jpt_7FFB0E08AB91
    add r10, r11
    mov r11, rax
    or r11, rdi
    add r11, r11
    lea r11, [r11+r11*2]
    sub r10, r11
    lea r9, [r10+r9*2]
    add rcx, r8
    mov r8, 32BB4B71FED27E01h
    add rcx, r8
    add rcx, r9
    mov r8, rdx
    not r8
    mov r9, rcx
    or r9, r8
    mov r10, rcx
    or r10, rdx
    mov r11, rcx
    xor r11, rdx
    and r8, rcx
    and rcx, rdx
    shl r8, 2
    lea rcx, [r8+rcx*2]
    sub rcx, r11
    add r10, r10
    sub rcx, r10
    not r9
    lea rcx, [rcx+r9*4]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rcx, r12
    mov qword ptr [rsp+88h], rcx
    mov rax, qword ptr [rsp+88h]
    mov qword ptr [rsp+58h], rax
    movzx eax, byte ptr [rsp+3Fh]
    movsxd rax, dword ptr (jpt_7FFB0E08A81A - 7FFB0FE4EB54h)[r15+rax*4]
    add rax, r15
    jmp rax
    loc_7FFB0E08AAF5:
    mov eax, dword ptr [rsp+0D4h]
    xor rax, qword ptr [rsp+58h]
    mov qword ptr [rsp+90h], rax
    mov rax, qword ptr [rsp+90h]
    mov qword ptr [rsp+50h], rax
    movzx eax, byte ptr [rsp+44h]
    lea rcx, jpt_7FFB0E08AB29
    movsxd rax, dword ptr (jpt_7FFB0E08AB29 - 7FFB0FE4EB78h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08AB2B:
    cmp eax, 4C815853h
    jnz loc_7FFB0E08B0D5
    mov rax, qword ptr [rsp+58h]
    xor rax, qword ptr [rsp+140h]
    mov qword ptr [rsp+90h], rax
    mov rax, qword ptr [rsp+90h]
    mov qword ptr [rsp+50h], rax
    movzx eax, byte ptr [rsp+44h]
    lea rcx, jpt_7FFB0E08AB29
    movsxd rax, dword ptr (jpt_7FFB0E08AB29 - 7FFB0FE4EB78h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08AB6D:
    cmp eax, 6E642F99h
    jnz loc_7FFB0E08B25B
    mov rax, qword ptr [rsp+0B0h]
    mov qword ptr [rsp+70h], rax
    movzx eax, byte ptr [rsp+47h]
    movsxd rax, dword ptr (jpt_7FFB0E08AB91 - 7FFB0FE4EC08h)[rsi+rax*4]
    add rax, rsi
    jmp rax
    loc_7FFB0E08AB93:
    cmp eax, 17E34F85h
    jnz loc_7FFB0E08F240
    mov rax, qword ptr [rsp+210h]
    add rax, qword ptr [rsp+208h]
    sub rax, qword ptr [rsp+200h]
    add rax, qword ptr [rsp+1F8h]
    add rax, qword ptr [rsp+1F0h]
    mov qword ptr [rsp+98h], rax
    mov rax, qword ptr [rsp+98h]
    mov qword ptr [rsp+60h], rax
    movzx eax, byte ptr [rsp+45h]
    movsxd rax, dword ptr (jpt_7FFB0E08ABE7 - 7FFB0FE4EB9Ch)[r14+rax*4]
    add rax, r14
    jmp rax
    loc_7FFB0E08ABE9:
    mov rax, qword ptr [rsp+0C8h]
    mov qword ptr [rsp+80h], rax
    movzx eax, byte ptr [rsp+43h]
    lea rcx, jpt_7FFB0E08AC0C
    movsxd rax, dword ptr (jpt_7FFB0E08AC0C - 7FFB0FE4EC74h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08AC0E:
    mov rax, qword ptr [rsp+1C8h]
    add rax, rax
    mov qword ptr [rsp+1D0h], rax
    mov rax, qword ptr [rsp+128h]
    xor rax, rbp
    neg rax
    mov qword ptr [rsp+1D8h], rax
    mov eax, dword ptr [dword_7FFB0FED85C4]
    lea ecx, [rax-6C5F95ABh]
    xor ecx, 0BDCC305h
    add ecx, -2FE670F2h
    lea edx, [rax-1C35772Eh]
    jmp loc_7FFB0E08C4FD
    loc_7FFB0E08AC5A:
    mov rax, qword ptr [rsp+1E8h]
    add rax, qword ptr [rsp+1E0h]
    mov qword ptr [rsp+98h], rax
    mov rax, qword ptr [rsp+98h]
    mov qword ptr [rsp+60h], rax
    movzx eax, byte ptr [rsp+45h]
    movsxd rax, dword ptr (jpt_7FFB0E08ABE7 - 7FFB0FE4EB9Ch)[r14+rax*4]
    add rax, r14
    jmp rax
    loc_7FFB0E08AC8D:
    mov rax, qword ptr [rsp+130h]
    mov rax, qword ptr [rax]
    mov qword ptr [rsp+138h], rax
    mov eax, dword ptr [dword_7FFB0FED8590]
    lea ecx, [rax+0DC0617h]
    lea edx, [rax-44BBB1C3h]
    xor edx, -662ED9E5h
    add edx, 1A0EFB25h
    xor ecx, eax
    xor ecx, edx
    add eax, ecx
    add eax, -44BBB1C3h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E086D93
    loc_7FFB0E08ACD2:
    mov rax, qword ptr [rsp+198h]
    add rax, qword ptr [rsp+178h]
    sub rax, qword ptr [rsp+170h]
    mov qword ptr [rsp+0B8h], rax
    mov rax, qword ptr [rsp+0B8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [rsp+41h]
    lea rdx, jpt_7FFB0E08AD6D
    movsxd rcx, dword ptr (jpt_7FFB0E08AD6D - 7FFB0FE4EC2Ch)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08AD6F:
    mov rax, qword ptr [rsp+1A8h]
    not rax
    shl rax, 2
    mov rcx, qword ptr [rsp+120h]
    add rcx, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rsp+120h]
    mov r8, r13
    or r8, rdx
    lea r8, [r8+r8*4]
    mov r9, r13
    and r9, rdx
    not rdx
    and rdx, r13
    lea r9, [r9+r9*2]
    lea rdx, [r9+rdx*4]
    sub r8, rdx
    sub r8, rcx
    sub r8, rax
    xor r8, qword ptr [rsp+118h]
    xor r8, qword ptr [rsp+1A0h]
    add r8, qword ptr [rsp+78h]
    mov qword ptr [rsp+0B0h], r8
    mov rax, qword ptr [rsp+0B0h]
    mov qword ptr [rsp+70h], rax
    movzx eax, byte ptr [rsp+47h]
    movsxd rax, dword ptr (jpt_7FFB0E08AB91 - 7FFB0FE4EC08h)[rsi+rax*4]
    add rax, rsi
    jmp rax
    loc_7FFB0E08AE34:
    mov rax, qword ptr [60h]
    mov rax, qword ptr [rax+18h]
    mov rcx, qword ptr [rsp+60h]
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
    nop
    nop
    nop
    nop
    nop
    not rcx
    lea rcx, [rcx+rcx*2]
    mov rdx, rax
    not rdx
    mov r8, qword ptr [rsp+60h]
    mov r9, r8
    or r9, rdx
    add r9, r9
    lea r9, [r9+r9*2]
    xor r8, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and rdx, qword ptr [rsp+60h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    and rax, qword ptr [rsp+60h]
    add rdx, rdx
    lea rax, [rax+rax*2]
    lea rax, [rdx+rax*2]
    add rax, r8
    sub rax, r9
    lea rax, [rax+rcx*2]
    mov qword ptr [rsp+0A0h], rax
    mov rax, qword ptr [rsp+0A0h]
    mov qword ptr [rsp+68h], rax
    movzx eax, byte ptr [rsp+40h]
    lea rcx, jpt_7FFB0E08AFDA
    movsxd rax, dword ptr (jpt_7FFB0E08AFDA - 7FFB0FE4EBC0h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08AFDC:
    mov rax, qword ptr [60h]
    mov qword ptr [rsp+110h], rax
    mov rax, qword ptr [rsp+70h]
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
    lea rax, [rax+rax*4]
    mov qword ptr [rsp+170h], rax
    mov rax, qword ptr [rsp+110h]
    mov rcx, qword ptr [rsp+70h]
    mov rdx, rax
    mov r8, rax
    or r8, rcx
    xor rax, rcx
    not rcx
    or rdx, rcx
    not rdx
    lea rdx, [rdx+rdx*2]
    mov qword ptr [rsp+178h], rdx
    not r8
    lea rdx, [r8+r8*4]
    mov qword ptr [rsp+180h], rdx
    add rax, rax
    mov qword ptr [rsp+188h], rax
    mov qword ptr [rsp+190h], rcx
    mov eax, dword ptr [dword_7FFB0FED85B4]
    lea ecx, [rax-61C23351h]
    mov edx, ecx
    xor edx, -22B7BB71h
    add edx, edx
    mov r8d, -58639E55h
    sub r8d, edx
    xor r8d, ecx
    xor ecx, -812069Dh
    sub r8d, ecx
    xor r8d, eax
    mov dword ptr [rsp+48h], r8d
    jmp loc_7FFB0E086D93
    loc_7FFB0E08B0D5:
    mov rax, qword ptr [rsp+1D8h]
    add rax, qword ptr [rsp+1D0h]
    sub rax, qword ptr [rsp+1C0h]
    mov rcx, -10FF7EC507A3AFF1h
    add rcx, rax
    mov rdx, -242E4D3F84B4B44h
    add rax, rdx
    mov rdx, qword ptr [rsp+128h]
    mov r8, 5495A95C0890E784h
    add rdx, r8
    xor rdx, qword ptr [rsp+1B8h]
    xor rdx, rax
    mov r8, -286048524195BBE7h
    add rax, r8
    add rax, rdx
    xor rax, qword ptr [rsp+1B0h]
    mov rdx, rax
    or rdx, rcx
    not rdx
    add rdx, rdx
    mov r8, rax
    and r8, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    xor rax, rcx
    sub r8, rax
    sub r8, rdx
    add r8, qword ptr [rsp+68h]
    mov qword ptr [rsp+0A8h], r8
    mov rax, qword ptr [rsp+0A8h]
    mov qword ptr [rsp+78h], rax
    movzx eax, byte ptr [rsp+46h]
    lea rcx, jpt_7FFB0E08B259
    movsxd rax, dword ptr (jpt_7FFB0E08B259 - 7FFB0FE4EBE4h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08B25B:
    mov rax, qword ptr [rsp+0A8h]
    mov qword ptr [rsp+78h], rax
    movzx eax, byte ptr [rsp+46h]
    lea rcx, jpt_7FFB0E08B259
    movsxd rax, dword ptr (jpt_7FFB0E08B259 - 7FFB0FE4EBE4h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08B27D:
    mov eax, dword ptr [dword_7FFB0FED85B8]
    mov ecx, 5BE4253h
    jmp loc_7FFB0E08EC63
    loc_7FFB0E08B28D:
    mov eax, dword ptr [rsp+0D0h]
    mov r12, qword ptr [rsp+0F8h]
    add rax, r12
    mov qword ptr [rsp+88h], rax
    mov rax, qword ptr [rsp+88h]
    mov qword ptr [rsp+58h], rax
    movzx eax, byte ptr [rsp+3Fh]
    lea r15, jpt_7FFB0E08A81A
    movsxd rax, dword ptr (jpt_7FFB0E08A81A - 7FFB0FE4EB54h)[r15+rax*4]
    add rax, r15
    mov r13, -0D1B5571EEC53855h
    mov rbp, -11DFDD7F47900ADAh
    lea r14, jpt_7FFB0E08ABE7
    lea rsi, jpt_7FFB0E08AB91
    jmp rax
    loc_7FFB0E08B2EB:
    movzx ecx, byte ptr [rsp+0D0h]
    mov r12, qword ptr [rsp+0F8h]
    mov rax, r12
    ror rax, cl
    mov qword ptr [rsp+88h], rax
    mov rax, qword ptr [rsp+88h]
    mov qword ptr [rsp+58h], rax
    movzx eax, byte ptr [rsp+3Fh]
    lea r15, jpt_7FFB0E08A81A
    movsxd rax, dword ptr (jpt_7FFB0E08A81A - 7FFB0FE4EB54h)[r15+rax*4]
    add rax, r15
    mov r13, -0D1B5571EEC53855h
    mov rbp, -11DFDD7F47900ADAh
    lea r14, jpt_7FFB0E08ABE7
    lea rsi, jpt_7FFB0E08AB91
    jmp rax
    loc_7FFB0E08B34D:
    mov eax, dword ptr [rsp+0D0h]
    mov r12, qword ptr [rsp+0F8h]
    mov rcx, r12
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
    nop
    mov qword ptr [rsp+88h], rcx
    mov rax, qword ptr [rsp+88h]
    mov qword ptr [rsp+58h], rax
    movzx eax, byte ptr [rsp+3Fh]
    lea r15, jpt_7FFB0E08A81A
    movsxd rax, dword ptr (jpt_7FFB0E08A81A - 7FFB0FE4EB54h)[r15+rax*4]
    add rax, r15
    mov r13, -0D1B5571EEC53855h
    mov rbp, -11DFDD7F47900ADAh
    lea r14, jpt_7FFB0E08ABE7
    lea rsi, jpt_7FFB0E08AB91
    jmp rax
    loc_7FFB0E08B423:
    mov rax, qword ptr [60h]
    mov r12, qword ptr [rsp+0F8h]
    xor rax, r12
    mov qword ptr [rsp+88h], rax
    mov rax, qword ptr [rsp+88h]
    mov qword ptr [rsp+58h], rax
    movzx eax, byte ptr [rsp+3Fh]
    lea r15, jpt_7FFB0E08A81A
    movsxd rax, dword ptr (jpt_7FFB0E08A81A - 7FFB0FE4EB54h)[r15+rax*4]
    add rax, r15
    mov r13, -0D1B5571EEC53855h
    mov rbp, -11DFDD7F47900ADAh
    lea r14, jpt_7FFB0E08ABE7
    lea rsi, jpt_7FFB0E08AB91
    jmp rax
    loc_7FFB0E08B483:
    movzx ecx, byte ptr [rsp+0D0h]
    mov r12, qword ptr [rsp+0F8h]
    mov rax, r12
    rol rax, cl
    mov qword ptr [rsp+88h], rax
    mov rax, qword ptr [rsp+88h]
    mov qword ptr [rsp+58h], rax
    movzx eax, byte ptr [rsp+3Fh]
    lea r15, jpt_7FFB0E08A81A
    movsxd rax, dword ptr (jpt_7FFB0E08A81A - 7FFB0FE4EB54h)[r15+rax*4]
    add rax, r15
    mov r13, -0D1B5571EEC53855h
    mov rbp, -11DFDD7F47900ADAh
    lea r14, jpt_7FFB0E08ABE7
    lea rsi, jpt_7FFB0E08AB91
    jmp rax
    loc_7FFB0E08B4E5:
    mov r12, qword ptr [rsp+0F8h]
    mov rax, r12
    not rax
    lea rcx, [rax*8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rdx, [0]
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
    lea rcx, [rsp]
    sub rdx, rcx
    lea rax, [rdx+rax*8]
    mov qword ptr [rsp+88h], rax
    mov rax, qword ptr [rsp+88h]
    mov qword ptr [rsp+58h], rax
    movzx eax, byte ptr [rsp+3Fh]
    lea r15, jpt_7FFB0E08A81A
    movsxd rax, dword ptr (jpt_7FFB0E08A81A - 7FFB0FE4EB54h)[r15+rax*4]
    add rax, r15
    mov r13, -0D1B5571EEC53855h
    mov rbp, -11DFDD7F47900ADAh
    lea r14, jpt_7FFB0E08ABE7
    lea rsi, jpt_7FFB0E08AB91
    jmp rax
    loc_7FFB0E08B678:
    movzx ecx, byte ptr [rsp+0D4h]
    mov rax, qword ptr [rsp+58h]
    rol rax, cl
    mov qword ptr [rsp+90h], rax
    mov rax, qword ptr [rsp+90h]
    mov qword ptr [rsp+50h], rax
    movzx eax, byte ptr [rsp+44h]
    lea rcx, jpt_7FFB0E08AB29
    movsxd rax, dword ptr (jpt_7FFB0E08AB29 - 7FFB0FE4EB78h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08B6B2:
    mov eax, dword ptr [rsp+0D4h]
    mov rcx, qword ptr [rsp+58h]
    mov rdx, rcx
    or rcx, rax
    not rax
    or rdx, rax
    not rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    shl rcx, 2
    mov r8, qword ptr [rsp+58h]
    and r8, rax
    mov r9, r8
    not r9
    add r9, r9
    sub r9, r8
    sub r9, rcx
    add r9, rdx
    lea rax, [r9+rax*2]
    inc rax
    mov qword ptr [rsp+90h], rax
    mov rax, qword ptr [rsp+90h]
    mov qword ptr [rsp+50h], rax
    movzx eax, byte ptr [rsp+44h]
    lea rcx, jpt_7FFB0E08AB29
    movsxd rax, dword ptr (jpt_7FFB0E08AB29 - 7FFB0FE4EB78h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08B761:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [rsp+0D4h]
    mov rax, qword ptr [rsp+58h]
    ror rax, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+90h], rax
    mov rax, qword ptr [rsp+90h]
    mov qword ptr [rsp+50h], rax
    movzx eax, byte ptr [rsp+44h]
    lea rcx, jpt_7FFB0E08AB29
    movsxd rax, dword ptr (jpt_7FFB0E08AB29 - 7FFB0FE4EB78h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08B843:
    mov eax, dword ptr [rsp+0D4h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rsp+58h]
    sub rcx, rax
    mov qword ptr [rsp+90h], rcx
    mov rax, qword ptr [rsp+90h]
    mov qword ptr [rsp+50h], rax
    movzx eax, byte ptr [rsp+44h]
    lea rcx, jpt_7FFB0E08AB29
    movsxd rax, dword ptr (jpt_7FFB0E08AB29 - 7FFB0FE4EB78h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08B8B8:
    mov rax, qword ptr [60h]
    mov rcx, qword ptr [rsp+58h]
    mov rdx, rcx
    not rdx
    mov r8, rax
    or r8, rdx
    not r8
    lea r9, [r8*8]
    sub r9, r8
    mov r8, rax
    xor r8, rcx
    lea r8, [r8+r8*4]
    and rdx, rax
    lea rdx, [rdx+rdx*2]
    and rax, rcx
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
    sub rax, r8
    sub rax, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+90h], rax
    mov rax, qword ptr [rsp+90h]
    mov qword ptr [rsp+50h], rax
    movzx eax, byte ptr [rsp+44h]
    lea rcx, jpt_7FFB0E08AB29
    movsxd rax, dword ptr (jpt_7FFB0E08AB29 - 7FFB0FE4EB78h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08BA58:
    mov rax, qword ptr [qword_7FFB0FE9C5B8]
    mov rcx, rax
    mov rdx, 125C7109814D1D09h
    xor rcx, rdx
    mov rdx, 416D1ED783E04330h
    add rdx, rcx
    mov r10, rdx
    not r10
    mov r11, -291360EC8A1C77E6h
    mov r9, r11
    not r9
    and r9, r10
    mov rdi, 291360EC8A1C77E5h
    mov r8, rdi
    not r8
    and r8, r10
    mov r10, rdx
    and r10, r11
    and rdx, rdi
    mov r11, rdx
    lea rdi, [r10+r10*2]
    add rdx, rdx
    sub rdx, rdi
    not r11
    lea rdx, [rdx+r11*4]
    lea r9, [r9+r9*2]
    add r8, r8
    not r10
    add r10, r10
    sub rdx, r10
    sub rdx, r8
    sub rdx, r9
    mov r8, rax
    mov r9, -125C7109814D1D0Ah
    xor r8, r9
    mov r11, -66735FE591ED1C07h
    mov r9, r11
    not r9
    mov r10, rcx
    and r10, r9
    and r9, r8
    and rcx, r11
    and r8, r11
    add r8, r8
    lea r8, [r8+rcx*2]
    not rcx
    add rcx, r9
    mov r9, 78B866A5E5AEBF72h
    add r9, rdx
    add r8, rcx
    mov rcx, 0A681B6B8DAA3F0h
    lea r11, [rdx+rcx]
    lea rcx, [r8+r10*2]
    add rcx, 2
    xor rcx, rax
    xor rcx, rdx
    xor rcx, r9
    mov rdx, r11
    not rdx
    mov rax, rcx
    or rax, rdx
    mov r8, rcx
    or r8, r11
    mov r9, rcx
    and r9, rdx
    xor rdx, rcx
    and rcx, r11
    lea r9, [r9+r9*2]
    add r9, r9
    lea rcx, [r9+rcx*8]
    lea r9, [rax+rax*4]
    sub rcx, r9
    lea rdx, [rdx+rdx*2]
    sub rcx, rdx
    not r8
    lea rcx, [rcx+r8*8]
    not rax
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp esp, -6F6FFA00h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp esp, -6F6FEF00h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rcx, qword ptr [rsp+58h]
    mov qword ptr [rsp+90h], rcx
    mov rax, qword ptr [rsp+90h]
    mov qword ptr [rsp+50h], rax
    movzx eax, byte ptr [rsp+44h]
    lea rcx, jpt_7FFB0E08AB29
    movsxd rax, dword ptr (jpt_7FFB0E08AB29 - 7FFB0FE4EB78h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08BEC8:
    mov r8, qword ptr [qword_7FFB0FE9C5B0]
    mov rax, 136DC619FDB47253h
    lea r9, [r8+rax]
    mov rax, r9
    not rax
    mov r10, 535CC82005425F0Bh
    mov rcx, r10
    not rcx
    and rcx, rax
    lea rax, [rcx*8]
    sub rax, rcx
    mov rcx, r9
    mov r11, -535CC82005425F0Ch
    xor rcx, r11
    lea rdx, [rcx+rcx*4]
    mov rcx, r9
    and rcx, r10
    lea rcx, [rcx+rcx*2]
    mov r10, r9
    and r10, r11
    lea rcx, [r10+rcx*2]
    sub rcx, rdx
    sub rcx, r11
    add rcx, rax
    mov rax, 42CB02A241DE141Eh
    add rax, rcx
    mov rdx, rax
    mov r10, -5DD1CBDBB30F0E3Bh
    xor rdx, r10
    mov r10, -7C7680C3A436F1ABh
    lea rdi, [rdx+r10]
    mov r10, -6E29C4CB49A9CA9Bh
    xor rdi, r10
    sub rdi, r9
    mov r9, rdi
    mov r14, r8
    not r14
    mov r10, rdi
    or r10, r14
    mov r11, rdi
    or r11, r8
    and r14, rdi
    and rdi, r8
    lea r8, [rdi+rdi*4]
    lea r8, [rdi+r8*2]
    add r8, r14
    not r14
    lea rdi, [r14+r14*4]
    lea rdi, [r14+rdi*2]
    lea r14, jpt_7FFB0E08ABE7
    sub r8, rdi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdi, 326E44998E8651E9h
    add rdx, rdi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    not r10
    lea r10, [r10+r10*8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    lea r11, [r11+r11*4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r8, [r8+r11*2]
    add r10, r9
    add r10, r8
    add rax, rdx
    add rax, rdx
    mov rdx, 211B00BA489D7C79h
    add rax, rdx
    add rax, r10
    xor rax, rcx
    mov rdx, qword ptr [rsp+58h]
    mov rcx, rdx
    mov r9, rax
    not r9
    or rdx, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, qword ptr [rsp+58h]
    or r8, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r10, qword ptr [rsp+58h]
    xor r10, rax
    lea r11, [r10*8]
    sub r11, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r10, qword ptr [rsp+58h]
    and r9, r10
    and rax, r10
    add r9, r9
    lea r9, [r9+r9*2]
    add rax, rax
    sub rax, r9
    add rax, r11
    not r8
    lea r8, [r8+r8*2]
    add rax, r8
    not rdx
    lea rdx, [rdx+rdx*2]
    sub rax, rdx
    not rcx
    lea rcx, [rcx+rcx*2]
    sub rax, rcx
    mov qword ptr [rsp+90h], rax
    mov rax, qword ptr [rsp+90h]
    mov qword ptr [rsp+50h], rax
    movzx eax, byte ptr [rsp+44h]
    lea rcx, jpt_7FFB0E08AB29
    movsxd rax, dword ptr (jpt_7FFB0E08AB29 - 7FFB0FE4EB78h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08C3E6:
    mov eax, dword ptr [rsp+0D8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov rdx, qword ptr [rsp+50h]
    mov r8, rdx
    or r8, rcx
    not r8
    add r8, r8
    mov qword ptr [rsp+1F0h], r8
    or rdx, rax
    not rdx
    mov qword ptr [rsp+1F8h], rdx
    mov qword ptr [rsp+200h], -2
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rsp+50h]
    and rcx, rdx
    and edx, eax
    add rcx, rcx
    lea rax, [rcx+rdx*2]
    not rdx
    mov qword ptr [rsp+208h], rdx
    mov qword ptr [rsp+210h], rax
    mov eax, dword ptr [dword_7FFB0FED85D0]
    lea ecx, [rax+7D4808E7h]
    mov edx, -0EDA8AEh
    sub edx, eax
    loc_7FFB0E08C4FD:
    xor edx, ecx
    sub edx, eax
    jmp loc_7FFB0E086D8F
    loc_7FFB0E08C506:
    mov ecx, dword ptr [rsp+0D8h]
    mov rdx, qword ptr [rsp+50h]
    mov rax, rdx
    not rax
    lea rax, [rax+rax*2]
    mov r9, rcx
    not r9
    or rdx, r9
    not rdx
    lea r8, [rdx+rdx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rsp+50h]
    mov r10, rdx
    or r10, rcx
    not r10
    lea r10, [r10+r10*2]
    mov r11, rcx
    xor r11, rdx
    lea rsi, [r11*8]
    sub rsi, r11
    add rsi, r10
    and r9, rdx
    add r9, r9
    lea r9, [r9+r9*2]
    and edx, ecx
    add rdx, rdx
    sub rdx, r9
    add rdx, rsi
    lea rsi, jpt_7FFB0E08AB91
    sub rdx, r8
    sub rdx, rax
    mov qword ptr [rsp+98h], rdx
    mov rax, qword ptr [rsp+98h]
    mov qword ptr [rsp+60h], rax
    movzx eax, byte ptr [rsp+45h]
    movsxd rax, dword ptr (jpt_7FFB0E08ABE7 - 7FFB0FE4EB9Ch)[r14+rax*4]
    add rax, r14
    jmp rax
    loc_7FFB0E08C5F0:
    movzx ecx, byte ptr [rsp+0D8h]
    mov rax, qword ptr [rsp+50h]
    ror rax, cl
    mov qword ptr [rsp+98h], rax
    mov rax, qword ptr [rsp+98h]
    mov qword ptr [rsp+60h], rax
    movzx eax, byte ptr [rsp+45h]
    movsxd rax, dword ptr (jpt_7FFB0E08ABE7 - 7FFB0FE4EB9Ch)[r14+rax*4]
    add rax, r14
    jmp rax
    loc_7FFB0E08C623:
    mov eax, dword ptr [rsp+0D8h]
    mov rcx, qword ptr [rsp+50h]
    sub rcx, rax
    mov qword ptr [rsp+98h], rcx
    mov rax, qword ptr [rsp+98h]
    mov qword ptr [rsp+60h], rax
    movzx eax, byte ptr [rsp+45h]
    movsxd rax, dword ptr (jpt_7FFB0E08ABE7 - 7FFB0FE4EB9Ch)[r14+rax*4]
    add rax, r14
    jmp rax
    loc_7FFB0E08C655:
    mov rax, qword ptr [60h]
    xor rax, qword ptr [rsp+50h]
    mov qword ptr [rsp+98h], rax
    mov rax, qword ptr [rsp+98h]
    mov qword ptr [rsp+60h], rax
    movzx eax, byte ptr [rsp+45h]
    movsxd rax, dword ptr (jpt_7FFB0E08ABE7 - 7FFB0FE4EB9Ch)[r14+rax*4]
    add rax, r14
    jmp rax
    loc_7FFB0E08C686:
    movzx ecx, byte ptr [rsp+0D8h]
    mov rax, qword ptr [rsp+50h]
    rol rax, cl
    mov qword ptr [rsp+98h], rax
    mov rax, qword ptr [rsp+98h]
    mov qword ptr [rsp+60h], rax
    movzx eax, byte ptr [rsp+45h]
    movsxd rax, dword ptr (jpt_7FFB0E08ABE7 - 7FFB0FE4EB9Ch)[r14+rax*4]
    add rax, r14
    jmp rax
    loc_7FFB0E08C6B9:
    mov eax, dword ptr [dword_7FFB0FED85C8]
    lea ecx, [rax+5144F52Dh]
    mov edx, ecx
    xor edx, 1565DCBDh
    mov r8d, -3F6718A4h
    sub r8d, edx
    xor r8d, ecx
    sub r8d, edx
    sub r8d, eax
    sub r8d, eax
    add r8d, 7D6D6089h
    mov dword ptr [rsp+48h], r8d
    jmp loc_7FFB0E086D93
    loc_7FFB0E08C6F3:
    mov rax, qword ptr [rsp+50h]
    inc rax
    mov qword ptr [rsp+98h], rax
    mov rax, qword ptr [rsp+98h]
    mov qword ptr [rsp+60h], rax
    movzx eax, byte ptr [rsp+45h]
    movsxd rax, dword ptr (jpt_7FFB0E08ABE7 - 7FFB0FE4EB9Ch)[r14+rax*4]
    add rax, r14
    jmp rax
    loc_7FFB0E08C71E:
    mov rax, qword ptr [60h]
    mov rcx, qword ptr [rsp+50h]
    xor rcx, qword ptr [rax+18h]
    mov qword ptr [rsp+98h], rcx
    mov rax, qword ptr [rsp+98h]
    mov qword ptr [rsp+60h], rax
    movzx eax, byte ptr [rsp+45h]
    movsxd rax, dword ptr (jpt_7FFB0E08ABE7 - 7FFB0FE4EB9Ch)[r14+rax*4]
    add rax, r14
    jmp rax
    loc_7FFB0E08C753:
    mov eax, dword ptr [rsp+0DCh]
    xor rax, qword ptr [rsp+60h]
    mov qword ptr [rsp+0A0h], rax
    mov rax, qword ptr [rsp+0A0h]
    mov qword ptr [rsp+68h], rax
    movzx eax, byte ptr [rsp+40h]
    lea rcx, jpt_7FFB0E08AFDA
    movsxd rax, dword ptr (jpt_7FFB0E08AFDA - 7FFB0FE4EBC0h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08C789:
    mov eax, dword ptr [rsp+0DCh]
    add rax, qword ptr [rsp+60h]
    mov qword ptr [rsp+0A0h], rax
    mov rax, qword ptr [rsp+0A0h]
    mov qword ptr [rsp+68h], rax
    movzx eax, byte ptr [rsp+40h]
    lea rcx, jpt_7FFB0E08AFDA
    movsxd rax, dword ptr (jpt_7FFB0E08AFDA - 7FFB0FE4EBC0h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08C7BF:
    movzx ecx, byte ptr [rsp+0DCh]
    mov rax, qword ptr [rsp+60h]
    ror rax, cl
    mov qword ptr [rsp+0A0h], rax
    mov rax, qword ptr [rsp+0A0h]
    mov qword ptr [rsp+68h], rax
    movzx eax, byte ptr [rsp+40h]
    lea rcx, jpt_7FFB0E08AFDA
    movsxd rax, dword ptr (jpt_7FFB0E08AFDA - 7FFB0FE4EBC0h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08C7F9:
    mov eax, dword ptr [rsp+0DCh]
    mov rcx, qword ptr [rsp+60h]
    sub rcx, rax
    mov qword ptr [rsp+0A0h], rcx
    mov rax, qword ptr [rsp+0A0h]
    mov qword ptr [rsp+68h], rax
    movzx eax, byte ptr [rsp+40h]
    lea rcx, jpt_7FFB0E08AFDA
    movsxd rax, dword ptr (jpt_7FFB0E08AFDA - 7FFB0FE4EBC0h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08C832:
    mov rax, qword ptr [60h]
    xor rax, qword ptr [rsp+60h]
    mov qword ptr [rsp+0A0h], rax
    mov rax, qword ptr [rsp+0A0h]
    mov qword ptr [rsp+68h], rax
    movzx eax, byte ptr [rsp+40h]
    lea rcx, jpt_7FFB0E08AFDA
    movsxd rax, dword ptr (jpt_7FFB0E08AFDA - 7FFB0FE4EBC0h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08C86A:
    movzx ecx, byte ptr [rsp+0DCh]
    mov rax, qword ptr [rsp+60h]
    rol rax, cl
    mov qword ptr [rsp+0A0h], rax
    mov rax, qword ptr [rsp+0A0h]
    mov qword ptr [rsp+68h], rax
    movzx eax, byte ptr [rsp+40h]
    lea rcx, jpt_7FFB0E08AFDA
    movsxd rax, dword ptr (jpt_7FFB0E08AFDA - 7FFB0FE4EBC0h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08C8A4:
    mov rax, qword ptr [qword_7FFB0FE9C5C0]
    mov rcx, rax
    not rcx
    mov r10, -5F1FFBDAF2544920h
    mov rdx, r10
    not rdx
    and rdx, rcx
    lea rcx, [rdx+rdx*2]
    mov rdx, rax
    mov r11, 5F1FFBDAF254491Fh
    or rdx, r11
    add rdx, rdx
    lea rdx, [rdx+rdx*2]
    mov r8, rax
    xor r8, r10
    mov r9, rax
    and r9, r11
    lea r9, [r9+r9*2]
    add r9, r9
    and rax, r10
    lea rax, [rax+rax*2]
    lea rax, [r9+rax*2]
    add rax, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rax, rdx
    lea rax, [rax+rcx*2]
    mov rcx, rax
    not rcx
    mov r10, 34FFF2AE1259BA3h
    mov rdx, r10
    not rdx
    and rdx, rcx
    lea r8, [rdx+rdx*4]
    lea rdx, [rdx+r8*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, rax
    mov r11, -34FFF2AE1259BA4h
    or r8, r11
    mov r9, rax
    and r9, r10
    mov r10, rax
    and r10, r11
    imul r10, 0F5h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add r9, r10
    sub r9, rdx
    mov rdx, -246FF6D7AC9DB00Bh
    add rcx, rdx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rax, rcx
    sub rax, rcx
    add rax, qword ptr [rsp+60h]
    mov rcx, -43693CA8BA3B5B52h
    add rax, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+0A0h], rax
    mov rax, qword ptr [rsp+0A0h]
    mov qword ptr [rsp+68h], rax
    movzx eax, byte ptr [rsp+40h]
    lea rcx, jpt_7FFB0E08AFDA
    movsxd rax, dword ptr (jpt_7FFB0E08AFDA - 7FFB0FE4EBC0h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08CB38:
    mov rax, qword ptr [rsp+60h]
    inc rax
    mov qword ptr [rsp+0A0h], rax
    mov rax, qword ptr [rsp+0A0h]
    mov qword ptr [rsp+68h], rax
    movzx eax, byte ptr [rsp+40h]
    lea rcx, jpt_7FFB0E08AFDA
    movsxd rax, dword ptr (jpt_7FFB0E08AFDA - 7FFB0FE4EBC0h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08CB6A:
    mov eax, dword ptr [rsp+0E0h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor rax, qword ptr [rsp+68h]
    mov qword ptr [rsp+0A8h], rax
    mov eax, dword ptr [dword_7FFB0FED859C]
    mov ecx, eax
    xor ecx, -577B8A85h
    lea edx, [rcx+55B241AFh]
    xor edx, 3AF8ECA6h
    sub edx, ecx
    sub edx, eax
    lea eax, [rdx+rcx]
    add eax, -4D662748h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E086D93
    loc_7FFB0E08CBF4:
    mov eax, dword ptr [rsp+0E0h]
    add rax, qword ptr [rsp+68h]
    mov qword ptr [rsp+0A8h], rax
    mov rax, qword ptr [rsp+0A8h]
    mov qword ptr [rsp+78h], rax
    movzx eax, byte ptr [rsp+46h]
    lea rcx, jpt_7FFB0E08B259
    movsxd rax, dword ptr (jpt_7FFB0E08B259 - 7FFB0FE4EBE4h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08CC2A:
    movzx ecx, byte ptr [rsp+0E0h]
    mov rax, qword ptr [rsp+68h]
    ror rax, cl
    mov qword ptr [rsp+0A8h], rax
    mov rax, qword ptr [rsp+0A8h]
    mov qword ptr [rsp+78h], rax
    movzx eax, byte ptr [rsp+46h]
    lea rcx, jpt_7FFB0E08B259
    movsxd rax, dword ptr (jpt_7FFB0E08B259 - 7FFB0FE4EBE4h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08CC64:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+0E0h]
    mov rcx, qword ptr [rsp+68h]
    sub rcx, rax
    mov qword ptr [rsp+0A8h], rcx
    mov rax, qword ptr [rsp+0A8h]
    mov qword ptr [rsp+78h], rax
    movzx eax, byte ptr [rsp+46h]
    lea rcx, jpt_7FFB0E08B259
    movsxd rax, dword ptr (jpt_7FFB0E08B259 - 7FFB0FE4EBE4h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08CCF2:
    mov rax, qword ptr [60h]
    xor rax, qword ptr [rsp+68h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+0A8h], rax
    mov rax, qword ptr [rsp+0A8h]
    mov qword ptr [rsp+78h], rax
    movzx eax, byte ptr [rsp+46h]
    lea rcx, jpt_7FFB0E08B259
    movsxd rax, dword ptr (jpt_7FFB0E08B259 - 7FFB0FE4EBE4h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08CD9C:
    movzx ecx, byte ptr [rsp+0E0h]
    mov rax, qword ptr [rsp+68h]
    rol rax, cl
    mov qword ptr [rsp+0A8h], rax
    mov rax, qword ptr [rsp+0A8h]
    mov qword ptr [rsp+78h], rax
    movzx eax, byte ptr [rsp+46h]
    lea rcx, jpt_7FFB0E08B259
    movsxd rax, dword ptr (jpt_7FFB0E08B259 - 7FFB0FE4EBE4h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08CDD6:
    mov rax, qword ptr [rsp+68h]
    dec rax
    mov qword ptr [rsp+0A8h], rax
    mov rax, qword ptr [rsp+0A8h]
    mov qword ptr [rsp+78h], rax
    movzx eax, byte ptr [rsp+46h]
    lea rcx, jpt_7FFB0E08B259
    movsxd rax, dword ptr (jpt_7FFB0E08B259 - 7FFB0FE4EBE4h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08CE08:
    mov rax, qword ptr [qword_7FFB0FE9C5C8]
    mov qword ptr [rsp+1B0h], rax
    mov rcx, 5F3D7D27C33292CBh
    add rcx, rax
    mov qword ptr [rsp+1B8h], rcx
    mov rcx, -28C6C861DD57068Dh
    add rax, rcx
    mov qword ptr [rsp+128h], rax
    mov rcx, rax
    or rcx, rbp
    not rcx
    add rcx, rcx
    mov qword ptr [rsp+1C0h], rcx
    and rax, rbp
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov qword ptr [rsp+1C8h], rax
    mov eax, dword ptr [dword_7FFB0FED85C0]
    lea ecx, [rax-2BE9580h]
    xor ecx, -58BB9AE4h
    add eax, ecx
    add eax, -2BE9580h
    add eax, ecx
    add eax, -24B143E3h
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E086D93
    loc_7FFB0E08CEC9:
    mov rax, qword ptr [60h]
    mov rax, qword ptr [rax+18h]
    mov rcx, rax
    not rcx
    mov rdx, qword ptr [rsp+68h]
    mov r8, rdx
    or r8, rcx
    not r8
    mov r9, rdx
    or r9, rax
    not r9
    and rdx, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and rcx, qword ptr [rsp+68h]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and rax, qword ptr [rsp+68h]
    add rcx, rcx
    lea rax, [rcx+rax*2]
    add rdx, r9
    add rdx, rax
    lea rax, [rdx+r8*2]
    add rax, 2
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+0A8h], rax
    mov rax, qword ptr [rsp+0A8h]
    mov qword ptr [rsp+78h], rax
    movzx eax, byte ptr [rsp+46h]
    lea rcx, jpt_7FFB0E08B259
    movsxd rax, dword ptr (jpt_7FFB0E08B259 - 7FFB0FE4EBE4h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08D065:
    mov eax, dword ptr [rsp+0E4h]
    xor rax, qword ptr [rsp+78h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+0B0h], rax
    mov eax, dword ptr [dword_7FFB0FED857C]
    lea ecx, [rax-2E0CCC22h]
    lea edx, [rax+50F5A888h]
    xor edx, ecx
    xor edx, eax
    xor edx, 1E211A66h
    jmp loc_7FFB0E086D8F
    loc_7FFB0E08D0E5:
    mov eax, dword ptr [rsp+0E4h]
    add rax, qword ptr [rsp+78h]
    mov qword ptr [rsp+0B0h], rax
    mov rax, qword ptr [rsp+0B0h]
    mov qword ptr [rsp+70h], rax
    movzx eax, byte ptr [rsp+47h]
    movsxd rax, dword ptr (jpt_7FFB0E08AB91 - 7FFB0FE4EC08h)[rsi+rax*4]
    add rax, rsi
    jmp rax
    loc_7FFB0E08D114:
    movzx ecx, byte ptr [rsp+0E4h]
    mov rax, qword ptr [rsp+78h]
    ror rax, cl
    mov qword ptr [rsp+0B0h], rax
    mov rax, qword ptr [rsp+0B0h]
    mov qword ptr [rsp+70h], rax
    movzx eax, byte ptr [rsp+47h]
    movsxd rax, dword ptr (jpt_7FFB0E08AB91 - 7FFB0FE4EC08h)[rsi+rax*4]
    add rax, rsi
    jmp rax
    loc_7FFB0E08D147:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+0E4h]
    mov rcx, qword ptr [rsp+78h]
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
    mov qword ptr [rsp+0B0h], rcx
    mov rax, qword ptr [rsp+0B0h]
    mov qword ptr [rsp+70h], rax
    movzx eax, byte ptr [rsp+47h]
    movsxd rax, dword ptr (jpt_7FFB0E08AB91 - 7FFB0FE4EC08h)[rsi+rax*4]
    add rax, rsi
    jmp rax
    loc_7FFB0E08D232:
    mov rax, qword ptr [60h]
    xor rax, qword ptr [rsp+78h]
    mov qword ptr [rsp+0B0h], rax
    mov rax, qword ptr [rsp+0B0h]
    mov qword ptr [rsp+70h], rax
    movzx eax, byte ptr [rsp+47h]
    movsxd rax, dword ptr (jpt_7FFB0E08AB91 - 7FFB0FE4EC08h)[rsi+rax*4]
    add rax, rsi
    jmp rax
    loc_7FFB0E08D263:
    movzx ecx, byte ptr [rsp+0E4h]
    mov rax, qword ptr [rsp+78h]
    rol rax, cl
    mov qword ptr [rsp+0B0h], rax
    mov rax, qword ptr [rsp+0B0h]
    mov qword ptr [rsp+70h], rax
    movzx eax, byte ptr [rsp+47h]
    movsxd rax, dword ptr (jpt_7FFB0E08AB91 - 7FFB0FE4EC08h)[rsi+rax*4]
    add rax, rsi
    jmp rax
    loc_7FFB0E08D296:
    mov rax, qword ptr [qword_7FFB0FE9C5D0]
    mov rcx, 447FE0A20AC28CCEh
    add rax, rcx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov rcx, 31DD69C145CE5698h
    xor rax, rcx
    mov qword ptr [rsp+1A0h], rax
    mov rcx, 1C2E76D22D378135h
    add rax, rcx
    mov qword ptr [rsp+120h], rax
    not rax
    or rax, r13
    mov qword ptr [rsp+1A8h], rax
    mov eax, dword ptr [dword_7FFB0FED8584]
    lea ecx, [rax+5155A218h]
    xor ecx, -494D6E54h
    add ecx, -25D263B0h
    mov edx, eax
    xor edx, -5188B51Ah
    sub edx, ecx
    add eax, edx
    add eax, 5155A218h
    xor eax, ecx
    xor eax, -22B6480Dh
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E086D93
    loc_7FFB0E08D389:
    mov rax, qword ptr [rsp+78h]
    inc rax
    mov qword ptr [rsp+0B0h], rax
    mov rax, qword ptr [rsp+0B0h]
    mov qword ptr [rsp+70h], rax
    movzx eax, byte ptr [rsp+47h]
    movsxd rax, dword ptr (jpt_7FFB0E08AB91 - 7FFB0FE4EC08h)[rsi+rax*4]
    add rax, rsi
    jmp rax
    loc_7FFB0E08D3B4:
    mov rax, qword ptr [60h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rax+18h]
    mov rcx, qword ptr [rsp+78h]
    mov rdx, rcx
    or rdx, rax
    lea r8, [rdx+rdx*2]
    not rdx
    lea r9, [rdx*8]
    sub r9, rdx
    and rcx, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rax, [rcx+r8*2]
    add rax, r9
    mov rcx, -7
    sub rcx, rax
    mov qword ptr [rsp+0B0h], rcx
    mov rax, qword ptr [rsp+0B0h]
    mov qword ptr [rsp+70h], rax
    movzx eax, byte ptr [rsp+47h]
    movsxd rax, dword ptr (jpt_7FFB0E08AB91 - 7FFB0FE4EC08h)[rsi+rax*4]
    add rax, rsi
    jmp rax
    loc_7FFB0E08D4E1:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+0E8h]
    xor rax, qword ptr [rsp+70h]
    mov qword ptr [rsp+0B8h], rax
    mov rax, qword ptr [rsp+0B8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [rsp+41h]
    lea rdx, jpt_7FFB0E08AD6D
    movsxd rcx, dword ptr (jpt_7FFB0E08AD6D - 7FFB0FE4EC2Ch)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08D5AE:
    mov eax, dword ptr [rsp+0E8h]
    add rax, qword ptr [rsp+70h]
    mov qword ptr [rsp+0B8h], rax
    mov rax, qword ptr [rsp+0B8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [rsp+41h]
    lea rdx, jpt_7FFB0E08AD6D
    movsxd rcx, dword ptr (jpt_7FFB0E08AD6D - 7FFB0FE4EC2Ch)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08D63F:
    movzx ecx, byte ptr [rsp+0E8h]
    mov rax, qword ptr [rsp+70h]
    ror rax, cl
    mov qword ptr [rsp+0B8h], rax
    mov rax, qword ptr [rsp+0B8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [rsp+41h]
    lea rdx, jpt_7FFB0E08AD6D
    movsxd rcx, dword ptr (jpt_7FFB0E08AD6D - 7FFB0FE4EC2Ch)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08D6D4:
    mov eax, dword ptr [rsp+0E8h]
    mov rcx, qword ptr [rsp+70h]
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
    mov qword ptr [rsp+0B8h], rcx
    mov rax, qword ptr [rsp+0B8h]
    cmp esp, -6FFFF200h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [rsp+41h]
    lea rdx, jpt_7FFB0E08AD6D
    movsxd rcx, dword ptr (jpt_7FFB0E08AD6D - 7FFB0FE4EC2Ch)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08D7B3:
    mov eax, dword ptr [dword_7FFB0FED85B0]
    lea ecx, [rax+362FBD2Ah]
    lea edx, [rax+65EAEC15h]
    xor edx, -5C41357h
    lea r8d, [rax+rdx]
    add r8d, -3E184A9Ah
    xor r8d, ecx
    lea ecx, [rax+r8]
    add ecx, 2F7F4446h
    xor ecx, eax
    sub ecx, edx
    add ecx, 365281h
    mov dword ptr [rsp+48h], ecx
    jmp loc_7FFB0E086D93
    loc_7FFB0E08D7F6:
    movzx ecx, byte ptr [rsp+0E8h]
    mov rax, qword ptr [rsp+70h]
    rol rax, cl
    mov qword ptr [rsp+0B8h], rax
    mov rax, qword ptr [rsp+0B8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [rsp+41h]
    lea rdx, jpt_7FFB0E08AD6D
    movsxd rcx, dword ptr (jpt_7FFB0E08AD6D - 7FFB0FE4EC2Ch)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08D88B:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [qword_7FFB0FE9C5E0]
    mov rcx, -75A131208D3C0F3Ch
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, 6BE620D16CC09D8Bh
    add rdx, rax
    mov r8, rdx
    sub r8, rcx
    sub r8, rax
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
    sub r8, rcx
    mov rax, -35476CABBA430403h
    add r8, rax
    mov rax, r8
    not rax
    mov rcx, qword ptr [rsp+70h]
    mov rdx, rcx
    or rdx, rax
    mov r9, rcx
    or r9, r8
    mov r10, rax
    xor r10, rcx
    add rcx, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11, qword ptr [rsp+70h]
    and rax, r11
    lea rax, [rax+rax*2]
    and r8, r11
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8, rax
    stc
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r8, rcx
    add r10, r9
    add r10, r8
    sub r10, rdx
    mov qword ptr [rsp+0B8h], r10
    mov rax, qword ptr [rsp+0B8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [rsp+41h]
    lea rdx, jpt_7FFB0E08AD6D
    movsxd rcx, dword ptr (jpt_7FFB0E08AD6D - 7FFB0FE4EC2Ch)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08DC94:
    mov rax, qword ptr [qword_7FFB0FE9C5D8]
    mov rcx, rax
    not rcx
    mov rdx, rax
    mov r10, -0FEFD999F8D482FFh
    or rdx, r10
    mov r11, 0FEFD999F8D482FEh
    mov r8, r11
    not r8
    and r8, rcx
    lea rcx, [r8+r8*2]
    lea r8, [rax+rax*2]
    mov r9, rax
    and r9, r10
    shl r9, 2
    and rax, r11
    lea rax, [rax+rax*2]
    sub r9, rax
    add r9, r8
    lea rax, [r9+rcx*2]
    add rax, rdx
    mov rcx, 5F9F199BD4FB11FBh
    add rcx, rax
    mov rdx, -4889A6217FF6871Ch
    add rax, rdx
    mov r8, rax
    mov rdx, 1409401005004640h
    xor r8, rdx
    mov rdx, rax
    mov r9, 2276BD6DF0BF989Fh
    xor rdx, r9
    lea r9, [rdx+rdx*2]
    mov r10, rdx
    mov rdi, 340BC01495154E46h
    or r10, rdi
    mov r11, rdi
    not r11
    and r11, rdx
    lea r11, [r11+r11*2]
    add r11, r10
    and rdx, rdi
    lea rdx, [rdx+rdx*2]
    and r8, rdi
    sub rdx, r8
    add rdx, r11
    add rdx, rdi
    sub rdx, r9
    inc rdx
    mov r10, rax
    not r10
    mov r9, rdx
    or r9, r10
    mov r8, rdx
    and r10, rdx
    mov r11, rdx
    not r11
    lea rdi, [r11*8]
    sub rdi, r11
    and r8, rax
    mov r11, r8
    add r10, r10
    add r8, r8
    sub r8, r10
    not r11
    lea r10, [r11+r11*2]
    add r8, r10
    or rdx, rax
    not rdx
    add rdx, rdx
    lea rdx, [rdx+rdx*4]
    sub r8, rdx
    not r9
    lea rdx, [r9+r9*8]
    sub r8, rdx
    add r8, rdi
    mov rdx, rax
    mov r9, 6EAE30675886937Ah
    xor rax, r9
    xor rax, r8
    mov r8, -2F24AD221A30C3DFh
    xor rdx, r8
    sub rax, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor rax, rcx
    add rax, qword ptr [rsp+70h]
    mov qword ptr [rsp+0B8h], rax
    mov rax, qword ptr [rsp+0B8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [rsp+41h]
    lea rdx, jpt_7FFB0E08AD6D
    movsxd rcx, dword ptr (jpt_7FFB0E08AD6D - 7FFB0FE4EC2Ch)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08E102:
    mov rax, qword ptr [60h]
    mov rcx, qword ptr [rsp+70h]
    xor rcx, qword ptr [rax+18h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+0B8h], rcx
    mov rax, qword ptr [rsp+0B8h]
    cmp esp, -6FFFF200h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [rsp+41h]
    lea rdx, jpt_7FFB0E08AD6D
    movsxd rcx, dword ptr (jpt_7FFB0E08AD6D - 7FFB0FE4EC2Ch)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08E204:
    mov ecx, dword ptr [rsp+0ECh]
    xor rcx, rax
    mov qword ptr [rsp+0C0h], rcx
    mov rax, qword ptr [rsp+0C0h]
    movzx ecx, byte ptr [rsp+42h]
    lea rdx, jpt_7FFB0E08E231
    movsxd rcx, dword ptr (jpt_7FFB0E08E231 - 7FFB0FE4EC50h)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08E233:
    mov ecx, dword ptr [rsp+0ECh]
    add rcx, rax
    mov qword ptr [rsp+0C0h], rcx
    mov rax, qword ptr [rsp+0C0h]
    movzx ecx, byte ptr [rsp+42h]
    lea rdx, jpt_7FFB0E08E231
    movsxd rcx, dword ptr (jpt_7FFB0E08E231 - 7FFB0FE4EC50h)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08E262:
    movzx ecx, byte ptr [rsp+0ECh]
    ror rax, cl
    mov qword ptr [rsp+0C0h], rax
    mov rax, qword ptr [rsp+0C0h]
    movzx ecx, byte ptr [rsp+42h]
    lea rdx, jpt_7FFB0E08E231
    movsxd rcx, dword ptr (jpt_7FFB0E08E231 - 7FFB0FE4EC50h)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08E292:
    mov ecx, dword ptr [rsp+0ECh]
    sub rax, rcx
    mov qword ptr [rsp+0C0h], rax
    mov rax, qword ptr [rsp+0C0h]
    movzx ecx, byte ptr [rsp+42h]
    lea rdx, jpt_7FFB0E08E231
    movsxd rcx, dword ptr (jpt_7FFB0E08E231 - 7FFB0FE4EC50h)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08E2C1:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor rax, qword ptr [60h]
    mov qword ptr [rsp+0C0h], rax
    mov rax, qword ptr [rsp+0C0h]
    movzx ecx, byte ptr [rsp+42h]
    lea rdx, jpt_7FFB0E08E231
    movsxd rcx, dword ptr (jpt_7FFB0E08E231 - 7FFB0FE4EC50h)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08E33D:
    movzx ecx, byte ptr [rsp+0ECh]
    rol rax, cl
    mov qword ptr [rsp+0C0h], rax
    mov rax, qword ptr [rsp+0C0h]
    movzx ecx, byte ptr [rsp+42h]
    lea rdx, jpt_7FFB0E08E231
    movsxd rcx, dword ptr (jpt_7FFB0E08E231 - 7FFB0FE4EC50h)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08E36D:
    dec rax
    mov qword ptr [rsp+0C0h], rax
    mov rax, qword ptr [rsp+0C0h]
    movzx ecx, byte ptr [rsp+42h]
    lea rdx, jpt_7FFB0E08E231
    movsxd rcx, dword ptr (jpt_7FFB0E08E231 - 7FFB0FE4EC50h)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08E395:
    inc rax
    mov qword ptr [rsp+0C0h], rax
    mov rax, qword ptr [rsp+0C0h]
    movzx ecx, byte ptr [rsp+42h]
    lea rdx, jpt_7FFB0E08E231
    movsxd rcx, dword ptr (jpt_7FFB0E08E231 - 7FFB0FE4EC50h)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08E3BD:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FFB0E08E3F0:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [60h]
    xor rax, qword ptr [rcx+18h]
    mov qword ptr [rsp+0C0h], rax
    mov rax, qword ptr [rsp+0C0h]
    movzx ecx, byte ptr [rsp+42h]
    lea rdx, jpt_7FFB0E08E231
    movsxd rcx, dword ptr (jpt_7FFB0E08E231 - 7FFB0FE4EC50h)[rdx+rcx*4]
    add rcx, rdx
    jmp rcx
    loc_7FFB0E08E441:
    mov ecx, dword ptr [rsp+0F0h]
    xor rcx, rax
    mov qword ptr [rsp+0C8h], rcx
    mov eax, dword ptr [dword_7FFB0FED85A0]
    mov ecx, eax
    xor ecx, -3244FC1Dh
    lea edx, [rcx+383B8E21h]
    loc_7FFB0E08E46A:
    or al, 37h
    stc
    js loc_7FFB0E08E3F0
    sar ebp, 22h
    fsubr dword ptr [rdi-3A20D7Fh]
    retf
    sub r10, rcx
    add edx, 1AB811A3h
    xor edx, ecx
    sub edx, eax
    xor edx, r8d
    jmp loc_7FFB0E086D8F
    loc_7FFB0E08E48E:
    mov ecx, dword ptr [rsp+0F0h]
    add rcx, rax
    mov qword ptr [rsp+0C8h], rcx
    loc_7FFB0E08E4A1:
    mov eax, dword ptr [rsp+0C8h]
    mov qword ptr [rsp+80h], rax
    movzx eax, byte ptr [rsp+43h]
    lea rcx, jpt_7FFB0E08AC0C
    movsxd rax, dword ptr (jpt_7FFB0E08AC0C - 7FFB0FE4EC74h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08E4C5:
    movzx ecx, byte ptr [rsp+0F0h]
    ror rax, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+0C8h], rax
    loc_7FFB0E08E529:
    mov eax, dword ptr [rsp+0C8h]
    mov qword ptr [rsp+80h], rax
    movzx eax, byte ptr [rsp+43h]
    lea rcx, jpt_7FFB0E08AC0C
    movsxd rax, dword ptr (jpt_7FFB0E08AC0C - 7FFB0FE4EC74h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08E54D:
    mov ecx, dword ptr [rsp+0F0h]
    sub rax, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+0C8h], rax
    loc_7FFB0E08E5C1:
    mov eax, dword ptr [rsp+0C8h]
    mov qword ptr [rsp+80h], rax
    movzx eax, byte ptr [rsp+43h]
    lea rcx, jpt_7FFB0E08AC0C
    movsxd rax, dword ptr (jpt_7FFB0E08AC0C - 7FFB0FE4EC74h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08E5E5:
    xor rax, qword ptr [60h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+0C8h], rax
    loc_7FFB0E08E642:
    mov eax, dword ptr [rsp+0C8h]
    mov qword ptr [rsp+80h], rax
    movzx eax, byte ptr [rsp+43h]
    lea rcx, jpt_7FFB0E08AC0C
    movsxd rax, dword ptr (jpt_7FFB0E08AC0C - 7FFB0FE4EC74h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08E666:
    movzx ecx, byte ptr [rsp+0F0h]
    rol rax, cl
    mov qword ptr [rsp+0C8h], rax
    loc_7FFB0E08E67A:
    mov eax, dword ptr [rsp+0C8h]
    mov qword ptr [rsp+80h], rax
    movzx eax, byte ptr [rsp+43h]
    lea rcx, jpt_7FFB0E08AC0C
    movsxd rax, dword ptr (jpt_7FFB0E08AC0C - 7FFB0FE4EC74h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08E69E:
    mov rcx, qword ptr [qword_7FFB0FE9C5E8]
    mov rdx, 4E489C9E3ED46553h
    lea r9, [rcx+rdx]
    mov rdx, r9
    mov r8, 29DF8A45F47FC7C2h
    xor rdx, r8
    mov r8, 1D85EF72C4275BECh
    lea r10, [rdx+r8]
    mov r8, r10
    mov rdi, r10
    mov r11, -53637977D7481A0Dh
    xor rdi, r11
    mov r14, r9
    mov r11, -32FE18FEA5AA2EAAh
    xor r14, r11
    mov r11, 53637977D7481A0Ch
    xor r10, r11
    mov r11, r14
    or r11, r10
    mov rsi, r15
    mov r15, r14
    or r15, rdi
    and r10, r14
    and r14, rdi
    lea rdi, [r14+r14*4]
    lea rdi, [r14+rdi*2]
    add rdi, r10
    not r10
    lea r14, [r10+r10*4]
    lea r10, [r10+r14*2]
    sub rdi, r10
    mov r10, -30497A135B833DA7h
    add r10, rcx
    mov r14, 32FE18FEA5AA2EA9h
    xor r9, r14
    not r11
    lea r11, [r11+r11*8]
    not r15
    lea r14, [r15+r15*4]
    lea rdi, [rdi+r14*2]
    add r11, r9
    add r11, rdi
    mov rdi, r10
    not rdi
    mov r14, r11
    or r14, rdi
    mov r15, r11
    or r15, r10
    and rdi, r11
    and r11, r10
    mov r9, rdi
    add rdi, rdi
    lea r10, [rdi+r11*2]
    not r9
    sub r9, r10
    not r15
    shl r15, 2
    sub r9, r15
    mov r15, rsi
    lea rsi, jpt_7FFB0E08AB91
    not r14
    lea r10, [r14+r14*2]
    lea r14, jpt_7FFB0E08ABE7
    sub r9, r10
    mov r10, 2F703559E49298D5h
    add r10, rcx
    mov r11, 40E906A5F5CE00BAh
    xor r8, r11
    add r9, -3
    xor r9, rdx
    sub r9, r8
    sub r9, rcx
    xor r9, r10
    mov rdx, r9
    not rdx
    mov rcx, rax
    or rcx, rdx
    mov r8, rax
    or r8, r9
    mov r10, rax
    xor r10, r9
    and rdx, rax
    and r9, rax
    mov rax, r10
    shl rdx, 3
    add r9, r9
    sub rdx, r9
    lea r9, [r10*8]
    sub r10, r9
    add r10, rdx
    not rax
    lea rax, [r10+rax*4]
    not r8
    shl r8, 2
    sub rax, r8
    not rcx
    lea rax, [rax+rcx*8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+0C8h], rax
    loc_7FFB0E08EA8E:
    mov eax, dword ptr [rsp+0C8h]
    mov qword ptr [rsp+80h], rax
    movzx eax, byte ptr [rsp+43h]
    lea rcx, jpt_7FFB0E08AC0C
    movsxd rax, dword ptr (jpt_7FFB0E08AC0C - 7FFB0FE4EC74h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08EAB2:
    inc rax
    mov qword ptr [rsp+0C8h], rax
    loc_7FFB0E08EABE:
    mov eax, dword ptr [rsp+0C8h]
    mov qword ptr [rsp+80h], rax
    movzx eax, byte ptr [rsp+43h]
    lea rcx, jpt_7FFB0E08AC0C
    movsxd rax, dword ptr (jpt_7FFB0E08AC0C - 7FFB0FE4EC74h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08EAE2:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [60h]
    xor rax, qword ptr [rcx+18h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+0C8h], rax
    mov rax, qword ptr [rsp+0C8h]
    mov qword ptr [rsp+80h], rax
    movzx eax, byte ptr [rsp+43h]
    lea rcx, jpt_7FFB0E08AC0C
    movsxd rax, dword ptr (jpt_7FFB0E08AC0C - 7FFB0FE4EC74h)[rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FFB0E08EC3A:
    mov eax, dword ptr [rsp+0F4h]
    xor rax, qword ptr [rsp+80h]
    mov qword ptr [rsp+100h], rax
    mov eax, dword ptr [dword_7FFB0FED85A4]
    mov ecx, 1CEF7981h
    sub ecx, eax
    add eax, 74F30C39h
    loc_7FFB0E08EC63:
    xor eax, ecx
    mov dword ptr [rsp+48h], eax
    jmp loc_7FFB0E086D93
    loc_7FFB0E08EC6E:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FFB0FED8598]
    lea ecx, [rax+2E886CBBh]
    mov edx, ecx
    xor edx, -179B7AB0h
    add eax, edx
    add eax, 293FDD4Fh
    jmp loc_7FFB0E08EC63
    loc_7FFB0E08ECFE:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [60h]
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
    nop
    nop
    mov rax, qword ptr [rax+18h]
    mov qword ptr [rsp+140h], rax
    mov eax, dword ptr [dword_7FFB0FED8580]
    mov ecx, eax
    xor ecx, 2D484F21h
    lea edx, [rcx+64CF12Eh]
    mov r8d, ecx
    xor r8d, edx
    xor edx, -799B4EB3h
    add ecx, edx
    add ecx, -2F2930EBh
    add ecx, edx
    add ecx, -2F2930EBh
    add ecx, edx
    sub ecx, eax
    add ecx, 1BBDE849h
    xor ecx, r8d
    mov dword ptr [rsp+48h], ecx
    jmp loc_7FFB0E086D93
    loc_7FFB0E08EE09:
    mov rax, qword ptr [qword_7FFB0FE9C5A8]
    mov rcx, rax
    mov r9, -1012D5360121B02Bh
    or rcx, r9
    lea rdx, [rcx+rcx*2]
    not rcx
    lea r8, [rcx*8]
    sub r8, rcx
    mov qword ptr [rsp+218h], r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and rax, r9
    lea rax, [rax+rdx*2]
    mov rcx, -7
    sub rcx, rax
    mov qword ptr [rsp+220h], rcx
    mov eax, dword ptr [dword_7FFB0FED85AC]
    mov ecx, eax
    xor ecx, 55152D80h
    lea edx, 0FFFFFFFFE32F5ECBh[rcx*2]
    xor edx, eax
    add edx, ecx
    lea eax, [rcx+rdx]
    add eax, 66B9AA94h
    jmp loc_7FFB0E08EF4C
    loc_7FFB0E08EEEA:
    mov rax, qword ptr [60h]
    add rax, 18h
    mov qword ptr [rsp+130h], rax
    mov eax, dword ptr [dword_7FFB0FED858C]
    lea ecx, [rax-6FF783E6h]
    lea edx, [rax+79FC9DA7h]
    lea r8d, [rax+0A85FFC2h]
    xor r8d, edx
    lea edx, [rax-7CEEF921h]
    lea r9d, [rax+40FA646Eh]
    xor r9d, ecx
    xor edx, -46A7E3EAh
    lea ecx, [rax+rdx]
    add ecx, -409F7F1Eh
    xor ecx, r8d
    add eax, ecx
    add eax, 40FA646Eh
    xor eax, r9d
    xor eax, -3F9BF9F6h
    loc_7FFB0E08EF4C:
    mov dword ptr [rsp+48h], eax
    mov r12, qword ptr [rsp+0F8h]
    mov r13, -0D1B5571EEC53855h
    mov rbp, -11DFDD7F47900ADAh
    lea r15, jpt_7FFB0E08A81A
    lea r14, jpt_7FFB0E08ABE7
    lea rsi, jpt_7FFB0E08AB91
    jmp loc_7FFB0E086D93
    loc_7FFB0E08EF86:
    mov rax, qword ptr [rsp+80h]
    dec rax
    jmp loc_7FFB0E08F32C
    loc_7FFB0E08EF96:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add rax, qword ptr [rsp+80h]
    jmp loc_7FFB0E08F32C
    loc_7FFB0E08F010:
    movzx ecx, byte ptr [rsp+0F4h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+80h]
    ror rax, cl
    jmp loc_7FFB0E08F32C
    loc_7FFB0E08F095:
    movzx ecx, byte ptr [rsp+0F4h]
    mov rax, qword ptr [rsp+80h]
    rol rax, cl
    jmp loc_7FFB0E08F32C
    loc_7FFB0E08F0AD:
    mov eax, dword ptr [rsp+0F4h]
    mov rcx, qword ptr [rsp+80h]
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
    nop
    nop
    mov qword ptr [rsp+100h], rcx
    jmp loc_7FFB0E08F334
    loc_7FFB0E08F142:
    mov rax, qword ptr [60h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rsp+80h]
    xor rcx, qword ptr [rax+18h]
    mov qword ptr [rsp+100h], rcx
    jmp loc_7FFB0E08F334
    loc_7FFB0E08F22A:
    mov rax, qword ptr [60h]
    xor rax, qword ptr [rsp+80h]
    jmp loc_7FFB0E08F32C
    loc_7FFB0E08F240:
    mov rax, 4A2C3FD57F384897h
    add rax, qword ptr [rsp+160h]
    xor rax, qword ptr [rsp+148h]
    xor rax, qword ptr [rsp+108h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor rax, qword ptr [rsp+168h]
    sub rax, qword ptr [rsp+158h]
    add rax, qword ptr [rsp+150h]
    add rax, qword ptr [rsp+80h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FFB0E08F32C:
    mov qword ptr [rsp+100h], rax
    loc_7FFB0E08F334:
    mov rdx, qword ptr [rsp+100h]
    mov qword ptr [rsp+20h], 3Eh
    mov ecx, 51h
    mov r9d, 1Dh
    mov r15, qword ptr [rsp+2A0h]
    mov r8, r15
    call sub_7FFB0E9F4760
    lea r9, [r15+0Ah]
    movzx edx, byte ptr [rsp+43h]
    mov eax, dword ptr [rsp+0F4h]
    mov dword ptr [rsp+20h], eax
    mov qword ptr [rsp+28h], 5Bh
    mov ecx, 63h
    mov r8d, 28h
    call sub_7FFB0EBED1F0
    mov rdx, qword ptr [qword_7FFB0FE9C5F8]
    mov rcx, -233FA3763980E061h
    add rcx, rdx
    mov r9, 64DE020FDDAAA5CAh
    xor r9, rcx
    mov r8, -1877BB9454E5ABF2h
    add r8, r9
    mov r10, 0CC8A30221AFB4EFh
    mov r11, r9
    or r11, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rsi, [r11+r11*2]
    not r11
    lea rdi, [r11*8]
    sub rdi, r11
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r9, r10
    lea r9, [r9+rsi*2]
    add r9, rdi
    mov rbx, -7
    mov r10, -7
    sub r10, r9
    mov r9, r10
    or r9, rdx
    lea r11, [r9+r9*2]
    not r9
    lea rsi, [r9*8]
    sub rsi, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r10, rdx
    lea rdx, [r10+r11*2]
    add rdx, rsi
    sub rbx, rdx
    xor rbx, r8
    sub rbx, rcx
    add rbx, rax
    lea r9, [r15+rbx]
    movzx edx, byte ptr [rsp+42h]
    mov eax, dword ptr [rsp+0F0h]
    mov dword ptr [rsp+20h], eax
    mov qword ptr [rsp+28h], 51h
    mov ecx, 30h
    mov r8d, 0Ch
    call sub_7FFB0EBED1F0
    mov rdi, rax
    add rdi, rbx
    lea r9, [r15+rdi]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx edx, byte ptr [rsp+41h]
    mov eax, dword ptr [rsp+0ECh]
    mov dword ptr [rsp+20h], eax
    mov qword ptr [rsp+28h], 49h
    mov ecx, 21h
    mov r8d, 5Eh
    call sub_7FFB0EBED1F0
    mov rbx, rax
    add rbx, rdi
    lea r9, [r15+rbx]
    movzx edx, byte ptr [rsp+47h]
    mov eax, dword ptr [rsp+0E8h]
    mov dword ptr [rsp+20h], eax
    mov qword ptr [rsp+28h], 36h
    mov ecx, 63h
    mov r8d, 3Bh
    call sub_7FFB0EBED1F0
    mov r14, rax
    add r14, rbx
    lea r9, [r15+r14]
    movzx edx, byte ptr [rsp+46h]
    mov eax, dword ptr [rsp+0E4h]
    mov dword ptr [rsp+20h], eax
    mov qword ptr [rsp+28h], 3
    mov ecx, 0Ch
    mov r8d, 43h
    call sub_7FFB0EBED1F0
    mov rdi, rax
    add rdi, r14
    lea r9, [r15+rdi]
    movzx edx, byte ptr [rsp+40h]
    mov eax, dword ptr [rsp+0E0h]
    mov dword ptr [rsp+20h], eax
    mov qword ptr [rsp+28h], 1Eh
    mov ecx, 56h
    mov r8d, 3Eh
    call sub_7FFB0EBED1F0
    mov rcx, rdi
    not rcx
    mov rdx, rax
    or rdx, rcx
    not rdx
    mov r8, rax
    or r8, rdi
    not r8
    add r8, r8
    mov r9, rcx
    xor r9, rax
    and ecx, eax
    and edi, eax
    lea rcx, [rdi+rcx*2]
    sub rcx, rax
    lea rsi, [rcx+r9*2]
    sub rsi, r8
    add rsi, rdx
    lea r9, [r15+rsi]
    movzx edx, byte ptr [rsp+45h]
    mov eax, dword ptr [rsp+0DCh]
    mov dword ptr [rsp+20h], eax
    mov qword ptr [rsp+28h], 42h
    mov ecx, 29h
    mov r8d, 11h
    call sub_7FFB0EBED1F0
    mov rdi, rax
    add rdi, rsi
    lea r9, [r15+rdi]
    movzx edx, byte ptr [rsp+44h]
    mov eax, dword ptr [rsp+0D8h]
    mov dword ptr [rsp+20h], eax
    mov qword ptr [rsp+28h], 59h
    mov ecx, 35h
    mov r8d, 52h
    call sub_7FFB0EBED1F0
    mov rbx, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rbx, rdi
    lea r9, [r15+rbx]
    movzx edx, byte ptr [rsp+3Fh]
    mov eax, dword ptr [rsp+0D4h]
    mov dword ptr [rsp+20h], eax
    mov qword ptr [rsp+28h], 5Ch
    mov ecx, 0Ch
    mov r8d, 2Eh
    call sub_7FFB0EBED1F0
    mov r14, rax
    add r14, rbx
    lea r9, [r15+r14]
    movzx edx, byte ptr [rsp+4Fh]
    mov eax, dword ptr [rsp+0D0h]
    mov dword ptr [rsp+20h], eax
    mov qword ptr [rsp+28h], 46h
    mov ecx, 44h
    mov r8d, 51h
    call sub_7FFB0EBED1F0
    mov rdi, rax
    add rdi, r14
    add r15, rdi
    mov edx, 2Ah
    mov r8d, 7
    mov r9d, 61h
    mov rcx, r15
    call sub_7FFB0F283030
    mov rax, qword ptr [qword_7FFB0FE9C600]
    mov rcx, -4BCBCEC95526F80Dh
    add rcx, rax
    mov rdx, 5B682412D81B1B30h
    xor rdx, rcx
    mov r8, -5EB3DC8910629CBFh
    sub r8, rax
    xor r8, rcx
    sub r8, rax
    add r8, rdx
    mov rax, -39BF7E6FD01A413h
    add rax, r8
    add rax, rdi
    mov rcx, qword ptr [rsp+230h]
    xor rcx, rsp
    cmp rcx, qword ptr [__security_cookie]
    jnz loc_7FFB0E08F88A
    add rsp, 238h
    pop rbx
    pop rbp
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    ret
    loc_7FFB0E08F88A:
    call __security_check_cookie
    int 3
_TEXT ENDS
END

; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: sub_7FF85A13D930  @ 0x7ff85a13d930
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN RaiseException:PROC
EXTERN ResetEvent:PROC
EXTERN WaitForSingleObject:PROC
EXTERN __security_check_cookie:PROC
EXTERN sub_7FF8599865B0:PROC
EXTERN sub_7FF85A8A9100:PROC

CONST SEGMENT
__security_cookie dq 0C6DD3C173A62h
qword_7FF85AADC750 dq 4BBC1B3FFD250566h
qword_7FF85AADC758 dq -58D1E93128907270h
dword_7FF85AADC760 dd 0F770BEDh
qword_7FF85AADC768 dq 6562A008BDC76AEAh
dword_7FF85AADC770 dd 54367732h
dword_7FF85AADC774 dd 89BBA55Ch
dword_7FF85AADC778 dd 0F1D36C2Ch
qword_7FF85AADC780 dq 7A7FC2929F2AE18Fh
dword_7FF85AADC788 dd 15A86A8h
dword_7FF85AADC78C dd 0FFE85585h
dword_7FF85AADC790 dd 0A618E4C1h
dword_7FF85AADC794 dd 16549E28h
dword_7FF85AB4A1B0 dd 0F76F6FD9h
dword_7FF85AB4A1B4 dd 7C03453Bh
dword_7FF85AB4A1B8 dd 45CC4F12h
dword_7FF85AB4A1BC dd 0EA53F75h
dword_7FF85AB4A1C0 dd 0B7BECF30h
dword_7FF85AB4A1C4 dd 0F8EAD425h
dword_7FF85AB4A1C8 dd 64885F96h
dword_7FF85AB4A1CC dd 0E8FD63EBh
dword_7FF85AB4A1D0 dd 0F00B5059h
dword_7FF85AB4A1D4 dd 5820FBDDh
dword_7FF85AB4A1D8 dd 0EA84D609h
dword_7FF85AB4A1DC dd 0DA46442h
dword_7FF85AB4A1E0 dd 6BF033F2h
dword_7FF85AB4A1E4 dd 8F5B3D61h
dword_7FF85AB4A1E8 dd 91FF33BBh
dword_7FF85AB4A1EC dd 16FB8477h
dword_7FF85AB4A1F0 dd 7DED876h
dword_7FF85AB4A1F4 dd 0CC7846BDh
dword_7FF85AB4A1F8 dd 0A133692Ah
dword_7FF85AB4A1FC dd 3046EE07h
dword_7FF85AB4A200 dd 4EB15B40h
dword_7FF85AB4A204 dd 89909CDDh
dword_7FF85AB4A208 dd 62107A33h
dword_7FF85AB4A20C dd 3A02242Dh
dword_7FF85AB4A210 dd 0F456DD96h
dword_7FF85AB4A214 dd 0DAAD8123h
dword_7FF85AB4A218 dd 0C5AC9917h
dword_7FF85AB4A21C dd 0C28C61D1h
dword_7FF85AB4A220 dd 9D31D27Dh
dword_7FF85AB4A224 dd 0F0D5C9ADh
dword_7FF85AB4A228 dd 29CB68Bh
dword_7FF85AB4A22C dd 1BD2F23Ah
dword_7FF85AB4A230 dd 0A543F814h
dword_7FF85AB4A234 dd 0E609E0DDh
dword_7FF85AB4A238 dd 7B8DAE95h
dword_7FF85AB4A23C dd 0BD5EB758h
dword_7FF85AB4A240 dd 7AA6131Bh
dword_7FF85AB4A244 dd 5D429D2Ah
dword_7FF85AB4A248 dd 0CFDDBB20h
dword_7FF85AB4A24C dd 39174288h
dword_7FF85AB4A250 dd 1558636h
dword_7FF85AB4A254 dd 0E69D17BFh
dword_7FF85AB4A258 dd 0A9DC03BCh
dword_7FF85AB4A25C dd 0FC0F13ACh
dword_7FF85AB4A260 dd 0F6E342FBh
dword_7FF85AB4A264 dd 0F13883EEh
dword_7FF85AB4A268 dd 4BF90170h
dword_7FF85AB4A26C dd 0CD9FE6DBh
dword_7FF85AB4A270 dd 0B230A31Dh
dword_7FF85AB4A274 dd 0B97FB119h
dword_7FF85AB4A278 dd 0F938EC92h
dword_7FF85AB4A27C dd 8EE5BA65h
dword_7FF85AB4A280 dd 0FB665F23h
dword_7FF85AB4A284 dd 0EB71A2B9h
dword_7FF85AB4A288 dd 0A48895B4h
dword_7FF85AB4A28C dd 8084CC3Dh
dword_7FF85AB4A290 dd 944452C0h
dword_7FF85AB4A294 dd 0B385776Dh
dword_7FF85AB4A298 dd 0C97A9ACh
dword_7FF85AB4A29C dd 64AE54C1h
dword_7FF85AB4A2A0 dd 0BDD95428h
dword_7FF85AB4A2A4 dd 6630E957h
dword_7FF85AB4A2A8 dd 4570CE39h
dword_7FF85AB4A2AC dd 0E091DA85h
dword_7FF85AB4A2B0 dd 0BBD22F3Bh
dword_7FF85AB4A2B4 dd 0C00FFEDDh
dword_7FF85AB4A2B8 dd 0B1450523h
dword_7FF85AB4A2BC dd 7746ADD0h
dword_7FF85AB4A2C0 dd 0EB42DFF3h
dword_7FF85AB4A2C4 dd 0BDB89256h
dword_7FF85AB4A2C8 dd 0C40866Eh
dword_7FF85AB4A2CC dd 6C89B45Bh
dword_7FF85AB4A2D0 dd 0C8CCD9CCh
dword_7FF85AB4A2D4 dd 0E1B47781h
dword_7FF85AB4A2D8 dd 33E0AE11h
qword_7FF85AB77648 dq -1
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC sub_7FF85A13D930
sub_7FF85A13D930:
    push r15
    push r14
    push r13
    push r12
    push rsi
    push rdi
    push rbp
    push rbx
    sub rsp, 308h
    mov rax, qword ptr [__security_cookie]
    xor rax, rsp
    mov qword ptr [rsp+300h], rax
    mov rdi, -4521B7ACF596A71Bh
    mov rbx, -60657A1106CA3014h
    mov r14, -761FDCB396BF9189h
    mov r15, 761FDCB396BF9188h
    mov r12, 60657A1106CA3013h
    mov r13, 4521B7ACF596A71Ah
    mov eax, dword ptr [dword_7FF85AB4A1B0]
    lea ecx, [rax+5F8217F8h]
    lea edx, [rax-274B3F27h]
    mov r8d, edx
    xor r8d, -4383A3FEh
    lea r9d, [rax+r8]
    xor edx, -372AC016h
    add r9d, r8d
    add r9d, 428A3E3Ah
    add r9d, edx
    mov edx, -4B7C07CCh
    sub edx, r9d
    xor edx, ecx
    lea ecx, [r8+rdx]
    add ecx, 428A3E3Ah
    lea eax, [rax+rcx-2DE7EF85h]
    mov dword ptr [rsp+28h], eax
    mov ebp, 7825A26Dh
    mov rsi, qword ptr [WaitForSingleObject]
    jmp loc_7FF85A13DA34
    loc_7FF85A13D9F1:
    mov eax, dword ptr [rsp+0B0h]
    add eax, dword ptr [rsp+0A8h]
    sub eax, dword ptr [rsp+9Ch]
    mov dword ptr [rsp+0B4h], eax
    mov eax, dword ptr [dword_7FF85AB4A1F8]
    lea ecx, [rax+56EA9960h]
    xor ecx, -7AAB85ACh
    add ecx, 248EB9FCh
    xor ecx, eax
    nop word ptr [rax+rax+00000000h]
    loc_7FF85A13DA30:
    mov dword ptr [rsp+28h], ecx
    loc_7FF85A13DA34:
    mov eax, dword ptr [rsp+28h]
    cmp eax, 3EE63408h
    jle loc_7FF85A13DB50
    cmp eax, 6B157D78h
    jle loc_7FF85A13DC20
    cmp eax, 77E44529h
    jle loc_7FF85A13DEDA
    cmp eax, 7BDC338Dh
    jg loc_7FF85A13E16B
    cmp eax, 79160213h
    jle loc_7FF85A13E78B
    cmp eax, 79160214h
    jz loc_7FF85A13EF21
    cmp eax, 794D72B3h
    jnz loc_7FF85A13F115
    mov rax, qword ptr [rsp+290h]
    not rax
    mov rcx, qword ptr [rsp+88h]
    mov rdx, rcx
    and rdx, rbx
    lea rdx, [rdx+rdx*2]
    and rcx, r12
    add rcx, rcx
    sub rcx, rdx
    lea rax, [rcx+rax*4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rax, qword ptr [rsp+288h]
    sub rax, qword ptr [rsp+280h]
    sub rax, qword ptr [rsp+278h]
    mov qword ptr [rsp+1B8h], rax
    mov eax, dword ptr [dword_7FF85AB4A238]
    lea ecx, [rax+58DF224Ah]
    mov edx, ecx
    xor edx, -6B218E95h
    add edx, eax
    sub edx, ecx
    add edx, 78F73EEFh
    mov dword ptr [rsp+28h], edx
    jmp loc_7FF85A13DA34
    loc_7FF85A13DB50:
    cmp eax, 1E323EF1h
    jle loc_7FF85A13DCD0
    cmp eax, 2E88C0F8h
    jle loc_7FF85A13DFD1
    cmp eax, 365AFA25h
    jg loc_7FF85A13E2B0
    cmp eax, 33C3D95Dh
    jle loc_7FF85A13ECB5
    cmp eax, 33C3D95Eh
    jz loc_7FF85A13F473
    cmp eax, 345244EAh
    jnz loc_7FF85A13FCBF
    mov rax, qword ptr [rsp+238h]
    sub rax, qword ptr [rsp+240h]
    add rax, qword ptr [rsp+230h]
    add rax, qword ptr [rsp+228h]
    sub rax, qword ptr [rsp+220h]
    mov rcx, 625F961AC43EB49Bh
    add rax, rcx
    mov qword ptr [rsp+1B0h], rax
    mov eax, dword ptr [dword_7FF85AB4A21C]
    mov ecx, eax
    xor ecx, -2FF7D71Ch
    lea edx, [rcx+348BC753h]
    lea r8d, [rcx+3E2DC677h]
    mov r9d, r8d
    xor r9d, 44A28240h
    add eax, 49C34683h
    xor eax, edx
    sub eax, ecx
    add r9d, ecx
    add r9d, eax
    sub r9d, r8d
    add r9d, 5DF63661h
    mov dword ptr [rsp+28h], r9d
    jmp loc_7FF85A13DA34
    loc_7FF85A13DC20:
    cmp eax, 4CD64C7Ah
    jle loc_7FF85A13DD3E
    cmp eax, 5851E4CDh
    jg loc_7FF85A13E32F
    cmp eax, 52F1CDE4h
    jle loc_7FF85A13E6DC
    cmp eax, 52F1CDE5h
    jz loc_7FF85A13EE7D
    cmp eax, 53A71A12h
    jnz loc_7FF85A13F068
    mov edx, dword ptr [rsp+10Ch]
    xor edx, dword ptr [rsp+0E0h]
    xor edx, dword ptr [rsp+0BCh]
    sub edx, dword ptr [rsp+0D8h]
    sub edx, dword ptr [rsp+0DCh]
    sub edx, dword ptr [rsp+0E4h]
    mov rcx, qword ptr [rsp+70h]
    call rsi
    cmp eax, 102h
    jnz loc_7FF85A13DF7E
    mov eax, dword ptr [dword_7FF85AB4A2B0]
    mov ecx, eax
    xor ecx, -342F3203h
    lea edx, [rcx+6A3C614Dh]
    xor edx, 4189FDF5h
    sub edx, ecx
    sub edx, eax
    lea eax, [rcx+rdx]
    add eax, 49EF6519h
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13DCD0:
    cmp eax, 13CB9577h
    jg loc_7FF85A13DF52
    cmp eax, 8065708h
    jle loc_7FF85A13E525
    cmp eax, 0CC636D2h
    jle loc_7FF85A13EBE8
    cmp eax, 0CC636D3h
    jz loc_7FF85A13F3AE
    cmp eax, 0E7015F1h
    jnz loc_7FF85A13FC00
    mov eax, dword ptr [rsp+164h]
    not eax
    shl eax, 2
    mov dword ptr [rsp+168h], eax
    mov eax, dword ptr [dword_7FF85AB4A1C4]
    mov ecx, eax
    xor ecx, -3BB3FB31h
    add ecx, 3E4EBEEBh
    xor ecx, 346E039Eh
    xor eax, 59678E15h
    jmp loc_7FF85A140222
    loc_7FF85A13DD3E:
    cmp eax, 44D3F2AAh
    jle loc_7FF85A13E3BE
    cmp eax, 48C8A6DDh
    jle loc_7FF85A13EAF0
    cmp eax, 48C8A6DEh
    jz loc_7FF85A13F097
    cmp eax, 48CD40EBh
    jnz loc_7FF85A13F63D
    mov eax, dword ptr [rsp+124h]
    not eax
    mov edx, dword ptr [rsp+4Ch]
    mov ecx, edx
    not ecx
    and ecx, 1D534F17h
    shl ecx, 2
    mov r8d, edx
    xor r8d, -1D534F18h
    mov r9d, edx
    xor r9d, 1D534F17h
    lea r10d, [r8*8]
    and edx, 1D534F17h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    shl edx, 3
    mov r11d, dword ptr [rsp+4Ch]
    mov rbp, r13
    mov r13, r15
    mov r15d, 62ACB0E8h
    and r11d, r15d
    mov r15, r13
    mov r13, rbp
    mov ebp, 7825A26Dh
    add r11d, r11d
    sub edx, r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r8d, r10d
    add r8d, edx
    lea edx, [r8+r9*4]
    sub edx, ecx
    lea eax, [rdx+rax*8]
    add eax, -10C00AE3h
    mov dword ptr [rsp+128h], eax
    mov eax, dword ptr [rsp+4Ch]
    mov ecx, -3F2723A7h
    add eax, ecx
    mov dword ptr [rsp+12Ch], eax
    mov eax, dword ptr [dword_7FF85AB4A280]
    mov ecx, 735A272Eh
    add eax, ecx
    mov ecx, eax
    xor ecx, 3B0EDC46h
    xor eax, -0B408702h
    lea edx, [rax-3DB6C5F5h]
    add eax, 49A61164h
    xor eax, edx
    xor eax, -1068F566h
    add eax, ecx
    add eax, -3F72DA1Ah
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13DEDA:
    cmp eax, 6DD3A22Fh
    jle loc_7FF85A13E4B7
    cmp eax, 71B44ABEh
    jle loc_7FF85A13EB51
    cmp eax, 71B44ABFh
    jz loc_7FF85A13F205
    cmp eax, 741CCF02h
    jnz loc_7FF85A13FB31
    mov eax, dword ptr [rsp+3Ch]
    and eax, dword ptr [rsp+100h]
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+104h], eax
    mov eax, dword ptr [dword_7FF85AB4A264]
    lea ecx, [rax+1047E55Ch]
    lea edx, [rax-69CEA892h]
    lea r8d, 0FFFFFFFFB2EDB94Ah[rax*2]
    neg r8d
    add r8d, eax
    add r8d, -44E0D94h
    xor edx, eax
    xor edx, ecx
    xor edx, r8d
    mov dword ptr [rsp+28h], edx
    jmp loc_7FF85A13DA34
    loc_7FF85A13DF52:
    cmp eax, 19CAFA10h
    jle loc_7FF85A13E590
    cmp eax, 1B5E92FBh
    jle loc_7FF85A13EC67
    cmp eax, 1B5E92FCh
    jz loc_7FF85A13F3F6
    cmp eax, 1C1B4302h
    jnz loc_7FF85A13FC8D
    loc_7FF85A13DF7E:
    mov rax, qword ptr [qword_7FF85AADC780]
    mov qword ptr [rsp+2A8h], rax
    mov rcx, -0A161AEB87ADD532h
    add rax, rcx
    mov qword ptr [rsp+1C8h], rax
    mov eax, dword ptr [dword_7FF85AB4A278]
    lea ecx, [rax+4DF4BCD6h]
    mov edx, ecx
    xor edx, 3F2DB277h
    xor ecx, 355F676Ah
    add edx, eax
    add edx, ecx
    add eax, edx
    add eax, 4DF4BCD6h
    mov ecx, -5C107ED1h
    jmp loc_7FF85A13F4D7
    loc_7FF85A13DFD1:
    cmp eax, 23925573h
    jle loc_7FF85A13E5FD
    cmp eax, 29D3EFC3h
    jle loc_7FF85A13EE2F
    cmp eax, 29D3EFC4h
    jz loc_7FF85A13FEE9
    cmp eax, 2B95EC13h
    jnz loc_7FF85A14022D
    mov rax, qword ptr [qword_7FF85AADC750]
    mov rcx, 78F1E14540D11931h
    add rcx, rax
    mov rdx, -51A7F3AA0EF0B011h
    add rdx, rax
    mov r8, 2B474D68012F39F0h
    xor rax, r8
    add rax, rdx
    mov r8, -0C9391ECA5486DDCh
    xor rdx, r8
    xor rax, rcx
    add rax, rdx
    xor rax, qword ptr [rsp+1E0h]
    mov rax, qword ptr [rax+50h]
    mov qword ptr [rsp+1E8h], rax
    mov rax, qword ptr [qword_7FF85AADC758]
    mov rcx, 43AEB426FAA4FBCEh
    add rcx, rax
    mov qword ptr [rsp+1F0h], rcx
    mov rcx, -44CF35F65610DB03h
    add rcx, rax
    mov qword ptr [rsp+1F8h], rcx
    mov rdx, rcx
    mov r8, 136419DB50C33D44h
    xor rdx, r8
    mov qword ptr [rsp+200h], rdx
    mov rdx, 4ACF4DC35D5FA56Dh
    xor rcx, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, -444C1021B090750h
    add rdx, rcx
    mov r8, 1DC5693360A88EF7h
    sub r8, rcx
    xor r8, rcx
    sub r8, rax
    xor r8, rdx
    mov qword ptr [rsp+208h], r8
    mov eax, dword ptr [dword_7FF85AB4A1D0]
    lea ecx, [rax+rax]
    add eax, 5ECB6FC7h
    mov edx, eax
    xor edx, -553851A7h
    sub ecx, edx
    add ecx, -1CE7A971h
    xor ecx, eax
    add ecx, -6DCF25FAh
    jmp loc_7FF85A13DA30
    loc_7FF85A13E16B:
    cmp eax, 7EED0E32h
    jle loc_7FF85A13E7F5
    cmp eax, 7EED0E33h
    jz loc_7FF85A13EFF4
    cmp eax, 7F80BA6Ch
    jz loc_7FF85A13EAFB
    mov rdx, qword ptr [rsp+2A0h]
    add rdx, qword ptr [rsp+1C0h]
    add rdx, qword ptr [rsp+78h]
    add rdx, qword ptr [rsp+298h]
    sub rdx, qword ptr [rsp+1B0h]
    mov eax, dword ptr [rsp+40h]
    mov dword ptr [rsp+20h], eax
    mov ecx, 4Eh
    mov r8d, 61h
    mov r9d, 48h
    call sub_7FF85A8A9100
    mov byte ptr [rsp+2Fh], al
    mov eax, dword ptr [dword_7FF85AADC770]
    mov dword ptr [rsp+0BCh], eax
    mov ecx, eax
    xor ecx, -18A9F29Ah
    mov dword ptr [rsp+44h], ecx
    xor eax, 18808210h
    and eax, 5E868356h
    lea eax, [rax+rax*2]
    mov dword ptr [rsp+0C0h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+44h]
    not eax
    mov ecx, eax
    and ecx, 21797CA9h
    add ecx, ecx
    mov dword ptr [rsp+0C4h], ecx
    add eax, eax
    or eax, -42F2F954h
    mov dword ptr [rsp+0C8h], eax
    mov eax, dword ptr [dword_7FF85AB4A24C]
    mov ecx, eax
    xor ecx, 3FF3EC8Bh
    add ecx, -59F01032h
    xor ecx, -61B212B6h
    sub ecx, eax
    add ecx, 3E76BDCDh
    jmp loc_7FF85A13DA30
    loc_7FF85A13E2B0:
    cmp eax, 3A0381C9h
    jle loc_7FF85A13ED37
    cmp eax, 3A0381CAh
    jz loc_7FF85A13F4B7
    cmp eax, 3C6F5E26h
    jnz loc_7FF85A13FD82
    mov rax, qword ptr [rsp+1C0h]
    mov rcx, -337FB853CEA0C147h
    xor rax, rcx
    mov qword ptr [rsp+298h], rax
    mov rax, qword ptr [rsp+88h]
    sub rax, qword ptr [rsp+1B8h]
    sub rax, qword ptr [rsp+80h]
    mov rcx, -1EFF43DB772F8D88h
    add rax, rcx
    mov qword ptr [rsp+2A0h], rax
    mov eax, 3D2B0F4Ch
    sub eax, dword ptr [dword_7FF85AB4A23C]
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13E32F:
    cmp eax, 60CABE58h
    jg loc_7FF85A13E847
    cmp eax, 5F8FA837h
    jz loc_7FF85A13F4DE
    cmp eax, 6047EC5Bh
    jnz loc_7FF85A14042F
    mov eax, dword ptr [rsp+180h]
    lea eax, [rax+rax*8]
    mov dword ptr [rsp+184h], eax
    mov eax, dword ptr [rsp+30h]
    not eax
    mov ecx, eax
    and ecx, 48ACF8D6h
    add ecx, ecx
    lea ecx, [rcx+rcx*4]
    mov dword ptr [rsp+188h], ecx
    or eax, 37530729h
    lea ecx, [rax+rax*4]
    lea eax, [rax+rcx*2]
    mov dword ptr [rsp+18Ch], eax
    mov eax, dword ptr [dword_7FF85AB4A2A8]
    mov ecx, eax
    xor ecx, 42C11CF0h
    lea edx, [rcx+21892933h]
    add ecx, 22E264BDh
    add eax, -325D6DA6h
    xor eax, edx
    xor eax, ecx
    add eax, 4ED1FB4Eh
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13E3BE:
    cmp eax, 410E48E5h
    jg loc_7FF85A13E890
    cmp eax, 3EE63409h
    jnz loc_7FF85A13F2CC
    mov eax, dword ptr [rsp+194h]
    lea ecx, [rax+rax*4]
    lea r8d, [rax+rcx*2]
    add r8d, dword ptr [rsp+190h]
    sub r8d, dword ptr [rsp+18Ch]
    add r8d, dword ptr [rsp+188h]
    add r8d, dword ptr [rsp+184h]
    add r8d, dword ptr [rsp+17Ch]
    xor r8d, -38CA7277h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8d, dword ptr [rsp+30h]
    add r8d, dword ptr [rsp+60h]
    xor r8d, dword ptr [rsp+64h]
    xor r8d, -23F7B375h
    mov ecx, dword ptr [rsp+130h]
    mov edx, dword ptr [rsp+178h]
    lea r9, [rsp+2F0h]
    call qword ptr [RaiseException]
    mov eax, dword ptr [dword_7FF85AB4A1FC]
    lea ecx, [rax-457EE282h]
    add ecx, eax
    add ecx, -457EE282h
    add ecx, eax
    mov eax, 521AFE2Bh
    jmp loc_7FF85A140222
    loc_7FF85A13E4B7:
    cmp eax, 6BF29095h
    jg loc_7FF85A13E9DD
    cmp eax, 6B157D79h
    jnz loc_7FF85A13F53D
    mov eax, dword ptr [rsp+34h]
    add eax, eax
    mov dword ptr [rsp+0ACh], eax
    mov eax, dword ptr [dword_7FF85AB4A1E4]
    mov ecx, eax
    xor ecx, -0EFAF955h
    mov r8d, -5DD00D36h
    sub r8d, ecx
    sub r8d, ecx
    add ecx, 486A6633h
    xor r8d, eax
    add r8d, -2539BA00h
    xor r8d, ecx
    mov eax, ecx
    xor eax, -1EA2E390h
    add eax, -2F1F3063h
    xor eax, 4D297BFDh
    sub r8d, eax
    mov dword ptr [rsp+28h], r8d
    jmp loc_7FF85A13DA34
    loc_7FF85A13E525:
    cmp eax, 38CD893h
    jg loc_7FF85A13EA4A
    cmp eax, 0EA5BF0h
    jnz loc_7FF85A13F675
    mov eax, dword ptr [rsp+0B4h]
    mov ecx, 7825A26Eh
    add eax, ecx
    mov ecx, -58518985h
    sub ecx, dword ptr [rsp+34h]
    xor ecx, eax
    sub ecx, dword ptr [rsp+94h]
    mov dword ptr [rsp+0B8h], ecx
    mov eax, dword ptr [dword_7FF85AB4A200]
    mov ecx, eax
    xor ecx, -30B50307h
    add eax, ecx
    add eax, -517162CAh
    add eax, ecx
    add eax, -517162CAh
    neg eax
    add eax, ecx
    add eax, 5C52FE5Eh
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13E590:
    cmp eax, 14CE0D2Eh
    jg loc_7FF85A13EAA0
    cmp eax, 13CB9578h
    jnz loc_7FF85A13F697
    mov eax, dword ptr [rsp+11Ch]
    sub eax, dword ptr [rsp+110h]
    mov ecx, eax
    xor ecx, 0C29AAC1h
    mov dword ptr [rsp+120h], ecx
    xor eax, 674E608Ah
    mov dword ptr [rsp+4Ch], eax
    or eax, 1D534F17h
    mov dword ptr [rsp+124h], eax
    mov eax, dword ptr [dword_7FF85AB4A228]
    lea ecx, [rax+3DD87F5Ch]
    add eax, 734EABF9h
    xor eax, 3508AA1Ah
    xor ecx, eax
    xor ecx, -76D80B10h
    sub ecx, eax
    jmp loc_7FF85A13DA30
    loc_7FF85A13E5FD:
    cmp eax, 205A84CBh
    jg loc_7FF85A13EDD0
    cmp eax, 1E323EF2h
    jnz loc_7FF85A13FFB4
    mov eax, dword ptr [rsp+60h]
    mov ecx, -3CEEF383h
    add eax, ecx
    mov dword ptr [rsp+64h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov ecx, 596DC48Eh
    add eax, ecx
    mov dword ptr [rsp+30h], eax
    mov eax, dword ptr [dword_7FF85AB4A270]
    mov ecx, eax
    xor ecx, -499B065Eh
    lea edx, [rcx+0BFE3825h]
    xor edx, 77A054AAh
    mov r8d, -32F275C4h
    sub r8d, ecx
    xor r8d, 40CFD7A8h
    sub r8d, eax
    add r8d, edx
    xor r8d, edx
    xor r8d, 676BAE65h
    lea eax, [rcx+r8]
    add eax, -3DF2010Dh
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13E6DC:
    cmp eax, 4CD64C7Bh
    jz loc_7FF85A13D9F1
    mov rax, qword ptr [rsp+260h]
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
    add rax, rax
    lea rax, [rax+rax*4]
    mov qword ptr [rsp+268h], rax
    mov rax, qword ptr [rsp+78h]
    and rax, rdi
    mov qword ptr [rsp+270h], rax
    mov eax, dword ptr [dword_7FF85AB4A230]
    lea ecx, [rax+44F1AB96h]
    xor ecx, 6A1212E2h
    lea edx, [rcx+142F0B41h]
    xor edx, 0C3F27A7h
    mov r8d, 3FEFD6DDh
    sub r8d, ecx
    xor r8d, eax
    lea eax, [r8+rcx]
    add eax, 142F0B41h
    jmp loc_7FF85A13F08C
    loc_7FF85A13E78B:
    cmp eax, 77E4452Ah
    jnz loc_7FF85A13F175
    mov eax, dword ptr [rsp+174h]
    sub eax, dword ptr [rsp+158h]
    add eax, dword ptr [rsp+140h]
    mov dword ptr [rsp+178h], eax
    mov eax, dword ptr [dword_7FF85AADC790]
    mov dword ptr [rsp+60h], eax
    mov eax, dword ptr [dword_7FF85AB4A1EC]
    mov ecx, eax
    xor ecx, -6A7CB232h
    lea edx, [rcx+6ADB7FFBh]
    mov r8d, edx
    xor r8d, -7FB671E1h
    add ecx, -51EB0C2Bh
    xor ecx, r8d
    sub ecx, r8d
    add ecx, edx
    add ecx, 2902BE57h
    xor ecx, eax
    jmp loc_7FF85A13DA30
    loc_7FF85A13E7F5:
    cmp eax, 7BDC338Eh
    jnz loc_7FF85A13F1C1
    mov eax, dword ptr [rsp+38h]
    not eax
    mov dword ptr [rsp+0E8h], eax
    mov eax, dword ptr [dword_7FF85AB4A260]
    lea ecx, [rax+61E3CA63h]
    mov edx, ecx
    xor edx, -0B02A8CBh
    lea r8d, [rax+rdx]
    add r8d, -771EE1DCh
    mov r9d, 1315046Dh
    sub r9d, r8d
    add edx, -771EE1DCh
    xor ecx, eax
    xor ecx, r9d
    sub ecx, edx
    jmp loc_7FF85A13DA30
    loc_7FF85A13E847:
    cmp eax, 60CABE59h
    jnz loc_7FF85A13F283
    mov rax, qword ptr [rsp+1B8h]
    mov rcx, -7F4023E98F7F414Bh
    xor rax, rcx
    mov qword ptr [rsp+1C0h], rax
    mov eax, dword ptr [dword_7FF85AB4A240]
    lea ecx, [rax+1AAB4F59h]
    mov edx, ecx
    xor edx, -7B88B083h
    sub edx, ecx
    add edx, -350B7D58h
    jmp loc_7FF85A13EB46
    loc_7FF85A13E890:
    cmp eax, 410E48E6h
    jnz loc_7FF85A13F2F8
    mov eax, dword ptr [rsp+58h]
    mov ecx, -12E69E67h
    add eax, ecx
    mov dword ptr [rsp+140h], eax
    mov eax, dword ptr [rsp+134h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [rsp+58h]
    sub ecx, eax
    add ecx, 40D2C6EFh
    mov dword ptr [rsp+5Ch], ecx
    mov eax, dword ptr [rsp+50h]
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
    mov ecx, dword ptr [rsp+5Ch]
    or eax, ecx
    not eax
    shl eax, 3
    mov dword ptr [rsp+144h], eax
    mov eax, dword ptr [rsp+50h]
    mov edx, ecx
    or edx, eax
    not edx
    shl edx, 2
    mov dword ptr [rsp+148h], edx
    xor ecx, eax
    not ecx
    mov dword ptr [rsp+14Ch], ecx
    mov eax, dword ptr [dword_7FF85AB4A29C]
    mov ecx, eax
    xor ecx, 536757CFh
    lea edx, [rcx-76AFE21Fh]
    xor edx, 391A2748h
    sub edx, eax
    lea eax, [rcx+rdx]
    add eax, -55DF7BD1h
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13E9DD:
    cmp eax, 6BF29096h
    jnz loc_7FF85A13F5C7
    mov eax, dword ptr [rsp+1ACh]
    sub eax, dword ptr [rsp+1A4h]
    cmp dword ptr [rsp+1A0h], eax
    jnz loc_7FF85A1403ED
    mov eax, dword ptr [dword_7FF85AB4A2D8]
    mov ecx, eax
    xor ecx, 565B8546h
    lea edx, [rcx+4774A1FDh]
    mov r8d, edx
    xor r8d, 77240128h
    xor edx, eax
    xor edx, 3631200Dh
    sub edx, ecx
    sub edx, r8d
    sub edx, r8d
    sub edx, ecx
    add edx, -59F1C9A6h
    xor edx, eax
    xor edx, -7CE1627Fh
    mov dword ptr [rsp+28h], edx
    jmp loc_7FF85A13DA34
    loc_7FF85A13EA4A:
    cmp eax, 38CD894h
    jnz loc_7FF85A13F762
    mov eax, dword ptr [rsp+6Ch]
    mov ecx, -3D098786h
    xor eax, ecx
    lea ecx, [rax+4F1AC1E8h]
    mov dword ptr [rsp+1A4h], ecx
    add eax, -193DEA54h
    mov dword ptr [rsp+1A8h], eax
    mov eax, dword ptr [dword_7FF85AB4A2CC]
    mov ecx, -7F6A59A6h
    xor eax, ecx
    lea ecx, [rax-26D6D98Bh]
    mov edx, -35347081h
    sub edx, eax
    xor edx, ecx
    add edx, eax
    mov dword ptr [rsp+28h], edx
    jmp loc_7FF85A13DA34
    loc_7FF85A13EAA0:
    cmp eax, 14CE0D2Fh
    jnz loc_7FF85A13F7A0
    mov eax, dword ptr [dword_7FF85AB4A224]
    mov ecx, eax
    xor ecx, -7D9A3B34h
    lea edx, [rcx-174F5B1Ah]
    lea r8d, [rcx+2B5D800h]
    xor edx, -3344479Dh
    add edx, ecx
    add edx, 1936CA34h
    add ecx, -65206AA0h
    xor edx, r8d
    sub edx, eax
    xor edx, ecx
    add edx, -4CE306EEh
    mov dword ptr [rsp+28h], edx
    jmp loc_7FF85A13DA34
    loc_7FF85A13EAF0:
    cmp eax, 44D3F2ABh
    jnz loc_7FF85A13F94B
    loc_7FF85A13EAFB:
    mov eax, dword ptr [dword_7FF85AADC774]
    mov dword ptr [rsp+198h], eax
    mov eax, dword ptr [dword_7FF85AB4A2BC]
    lea ecx, [rax-4139A329h]
    xor eax, ecx
    xor ecx, 57FC3F1h
    lea edx, [rcx+108F28C4h]
    lea r8d, [rcx-6D4EBC14h]
    xor edx, -1674ED57h
    add r8d, ecx
    add r8d, -6D4EBC14h
    sub edx, r8d
    sub edx, ecx
    sub edx, ecx
    add edx, 65E33B6Eh
    loc_7FF85A13EB46:
    xor edx, eax
    mov dword ptr [rsp+28h], edx
    jmp loc_7FF85A13DA34
    loc_7FF85A13EB51:
    cmp eax, 6DD3A230h
    jnz loc_7FF85A13FBA6
    mov eax, dword ptr [rsp+12Ch]
    add eax, dword ptr [rsp+120h]
    xor eax, dword ptr [rsp+48h]
    xor eax, dword ptr [rsp+128h]
    mov dword ptr [rsp+130h], eax
    mov eax, dword ptr [dword_7FF85AADC78C]
    mov dword ptr [rsp+50h], eax
    lea ecx, [rax+39503895h]
    mov dword ptr [rsp+134h], ecx
    add eax, 650501A5h
    mov dword ptr [rsp+54h], eax
    mov ecx, eax
    xor ecx, -7D000675h
    mov dword ptr [rsp+138h], ecx
    xor eax, 5C000434h
    and eax, 5E3A1D3Dh
    add eax, eax
    lea eax, [rax+rax*4]
    mov dword ptr [rsp+13Ch], eax
    mov eax, dword ptr [dword_7FF85AB4A290]
    lea ecx, [rax+9DFC9EBh]
    mov edx, ecx
    xor edx, 3F36815Bh
    add edx, eax
    sub edx, ecx
    add edx, -257E8946h
    mov dword ptr [rsp+28h], edx
    jmp loc_7FF85A13DA34
    loc_7FF85A13EBE8:
    cmp eax, 8065709h
    jnz loc_7FF85A13FDAD
    mov eax, dword ptr [rsp+1A8h]
    sub eax, dword ptr [rsp+6Ch]
    add eax, 5A2C196Ah
    mov dword ptr [rsp+1ACh], eax
    mov eax, dword ptr [dword_7FF85AB4A2D0]
    mov ecx, eax
    xor ecx, -39745182h
    lea edx, [rcx+79222DC7h]
    lea r8d, [rcx+1E1F0F4Eh]
    xor r8d, -6F251985h
    lea r9d, [r8-722A563Eh]
    mov r10d, r9d
    xor r10d, -2256529Bh
    add r10d, ecx
    add r10d, 1E1F0F4Eh
    sub r10d, r8d
    add r10d, -10857349h
    xor r10d, edx
    sub r10d, r9d
    sub r10d, eax
    add r10d, ecx
    mov dword ptr [rsp+28h], r10d
    jmp loc_7FF85A13DA34
    loc_7FF85A13EC67:
    cmp eax, 19CAFA11h
    jnz loc_7FF85A13FDE4
    mov eax, dword ptr [rsp+98h]
    not eax
    mov dword ptr [rsp+9Ch], eax
    mov eax, dword ptr [rsp+34h]
    or eax, ebp
    mov dword ptr [rsp+0A0h], eax
    mov eax, dword ptr [dword_7FF85AB4A1BC]
    lea ecx, [rax-41CDA8C7h]
    mov edx, ecx
    xor edx, 37453596h
    xor eax, -3D852ABAh
    sub eax, edx
    xor eax, ecx
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13ECB5:
    cmp eax, 2E88C0F9h
    jnz loc_7FF85A13FE4A
    mov rcx, qword ptr [rsp+70h]
    mov edx, dword ptr [rsp+0B8h]
    call rsi
    mov rcx, qword ptr [rsp+70h]
    call qword ptr [ResetEvent]
    mov rax, qword ptr [qword_7FF85AB77648]
    mov rcx, -56E5351073B3A913h
    xor rax, rcx
    mov qword ptr [rsp+210h], rax
    mov eax, dword ptr [dword_7FF85AB4A20C]
    lea ecx, [rax+712CDC09h]
    lea edx, [rax+14B40A5Ch]
    xor edx, ecx
    xor ecx, -79B218CAh
    add ecx, -776006CAh
    sub edx, eax
    lea eax, [rdx+rcx]
    add eax, -5EA6B1B5h
    xor ecx, 751EC37Ah
    xor eax, ecx
    sub eax, ecx
    add eax, 37880313h
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13ED37:
    cmp eax, 365AFA26h
    jnz loc_7FF85A13FE8E
    mov rax, qword ptr [rsp+210h]
    mov eax, dword ptr [rax+58h]
    mov ecx, 70D4D8C7h
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov dword ptr [rsp+40h], eax
    jmp loc_7FF85A13FF3F
    loc_7FF85A13EDD0:
    cmp eax, 205A84CCh
    jnz loc_7FF85A14014B
    mov eax, dword ptr [rsp+3Ch]
    and eax, dword ptr [rsp+38h]
    lea eax, [rax+rax*2]
    add eax, dword ptr [rsp+104h]
    sub eax, dword ptr [rsp+0FCh]
    add eax, dword ptr [rsp+0F8h]
    mov dword ptr [rsp+108h], eax
    mov eax, dword ptr [dword_7FF85AB4A26C]
    mov ecx, eax
    xor ecx, -75EF1036h
    mov edx, eax
    xor edx, -4E3FDA8Ch
    add ecx, edx
    add ecx, edx
    add ecx, 62146D56h
    xor ecx, eax
    xor ecx, 14439641h
    jmp loc_7FF85A13DA30
    loc_7FF85A13EE2F:
    cmp eax, 23925574h
    jnz loc_7FF85A140358
    mov eax, dword ptr [dword_7FF85AB4A274]
    lea ecx, [rax-0A27D750h]
    mov edx, ecx
    xor edx, -65EF543Bh
    add eax, edx
    add eax, edx
    add eax, -3C7B0245h
    add eax, edx
    mov r8d, 2C8BFA5Dh
    sub r8d, eax
    add edx, -3C7B0245h
    xor r8d, ecx
    lea eax, [r8+rdx]
    add eax, -7D985971h
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13EE7D:
    mov eax, dword ptr [rsp+54h]
    mov ecx, eax
    not ecx
    mov edx, dword ptr [rsp+154h]
    and ecx, edx
    lea ecx, [rcx+rcx*2]
    mov dword ptr [rsp+16Ch], ecx
    and edx, eax
    add edx, edx
    mov dword ptr [rsp+170h], edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FF85AB4A1F0]
    lea ecx, [rax+6CF8DEB2h]
    xor ecx, -6FBBE922h
    lea edx, [rcx+54E9975Dh]
    mov r8d, edx
    xor r8d, -200CA64Bh
    xor eax, 55581ACFh
    add eax, ecx
    sub eax, r8d
    sub eax, r8d
    add eax, 7B7FCAAh
    jmp loc_7FF85A13F3A3
    loc_7FF85A13EF21:
    mov rax, qword ptr [rsp+1C8h]
    mov rcx, -6D292CF1E1C4BA44h
    add rcx, rax
    mov rdx, 60333EEE7B404ADAh
    add rdx, rax
    mov r8, rdx
    mov r9, -37B779DCBBE95CBEh
    xor r8, r9
    mov r9, rcx
    sub r9, r8
    mov qword ptr [rsp+1D0h], rcx
    mov r8, -66E6580BE75D6930h
    xor rdx, r8
    mov qword ptr [rsp+2B0h], rdx
    mov rdx, 6156E23777D88611h
    add rax, rdx
    add rax, r9
    mov qword ptr [rsp+1D8h], rax
    mov rdx, rax
    or rdx, rcx
    not rcx
    or rcx, rax
    not rcx
    add rcx, rcx
    mov qword ptr [rsp+2B8h], rcx
    not rdx
    mov qword ptr [rsp+2C0h], rdx
    not rax
    mov qword ptr [rsp+2C8h], rax
    mov eax, dword ptr [dword_7FF85AB4A27C]
    lea ecx, [rax+107B797Eh]
    mov edx, ecx
    xor edx, -65F013DEh
    sub ecx, edx
    add ecx, -7A40DAE2h
    xor edx, eax
    xor edx, ecx
    xor edx, -3F9DE2B0h
    add eax, edx
    add eax, 3C02301Ch
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13EFF4:
    mov eax, dword ptr [rsp+0D0h]
    add eax, dword ptr [rsp+0CCh]
    mov dword ptr [rsp+0D4h], eax
    mov eax, dword ptr [dword_7FF85AB4A254]
    lea ecx, [rax+3BC4148Eh]
    mov edx, ecx
    mov r8d, ecx
    xor r8d, 483A6985h
    add r8d, -634EE81Eh
    mov r9d, r8d
    xor r9d, -4C9915EAh
    lea r10d, [r9+7F918CE3h]
    xor r10d, -3B3A31C0h
    sub r10d, ecx
    xor ecx, 4051434Ah
    xor edx, 4A8EC9A4h
    add r10d, eax
    xor r10d, r8d
    sub r10d, edx
    sub r10d, ecx
    xor r10d, r9d
    mov dword ptr [rsp+28h], r10d
    jmp loc_7FF85A13DA34
    loc_7FF85A13F068:
    mov eax, dword ptr [dword_7FF85AB4A1CC]
    mov ecx, 26372DA9h
    add eax, ecx
    mov ecx, eax
    xor ecx, -2E7B18ECh
    mov edx, eax
    xor edx, 2B6943DEh
    xor eax, -73A60735h
    add eax, ecx
    loc_7FF85A13F08C:
    sub eax, edx
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13F097:
    mov eax, dword ptr [rsp+170h]
    sub eax, dword ptr [rsp+16Ch]
    add eax, dword ptr [rsp+168h]
    sub eax, dword ptr [rsp+160h]
    sub eax, dword ptr [rsp+15Ch]
    mov dword ptr [rsp+174h], eax
    mov eax, dword ptr [dword_7FF85AB4A220]
    lea ecx, [rax+3EB1302Eh]
    lea edx, [rax-356A04E8h]
    xor edx, 4D039732h
    lea r8d, [rdx-214660F7h]
    mov r9d, r8d
    xor r9d, 620EA038h
    lea r10d, [r9+5B9D430Bh]
    add edx, -770105A5h
    xor edx, r10d
    add edx, eax
    add edx, -356A04E8h
    xor edx, r8d
    sub edx, eax
    xor edx, ecx
    sub edx, r9d
    mov dword ptr [rsp+28h], edx
    jmp loc_7FF85A13DA34
    loc_7FF85A13F115:
    mov eax, dword ptr [rsp+108h]
    sub eax, dword ptr [rsp+0F0h]
    add eax, dword ptr [rsp+0ECh]
    mov dword ptr [rsp+10Ch], eax
    mov eax, dword ptr [dword_7FF85AB4A204]
    mov ecx, eax
    xor ecx, -3044AF92h
    lea edx, [rcx-673DD3F8h]
    add eax, ecx
    lea r8d, [rcx-4A78E55Dh]
    mov r9d, r8d
    xor r9d, -74F0CAF1h
    sub r9d, eax
    add r9d, -7055377Dh
    xor r9d, edx
    sub r9d, ecx
    xor r9d, r8d
    mov dword ptr [rsp+28h], r9d
    jmp loc_7FF85A13DA34
    loc_7FF85A13F175:
    mov eax, dword ptr [rsp+118h]
    not eax
    mov ecx, dword ptr [rsp+48h]
    add ecx, ecx
    sub eax, ecx
    sub eax, dword ptr [rsp+114h]
    add eax, -3
    mov dword ptr [rsp+11Ch], eax
    mov eax, dword ptr [dword_7FF85AB4A1B4]
    mov ecx, eax
    xor ecx, 78FFD6B7h
    mov edx, -1BAB62CEh
    sub edx, ecx
    xor edx, ecx
    add edx, eax
    lea eax, [rcx+rdx]
    add eax, -48D8DD79h
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13F1C1:
    mov eax, dword ptr [rsp+30h]
    not eax
    mov dword ptr [rsp+17Ch], eax
    mov eax, dword ptr [dword_7FF85AB4A2A4]
    mov ecx, eax
    xor ecx, -510931D5h
    add eax, ecx
    mov edx, 5F4853ACh
    sub edx, eax
    lea eax, [rcx+61093D43h]
    xor eax, 6CD7B87Eh
    xor edx, eax
    sub edx, eax
    lea eax, [rdx+rcx]
    add eax, 110BDA07h
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13F205:
    mov eax, dword ptr [rsp+138h]
    mov ecx, eax
    or ecx, 5E3A1D3Dh
    lea ecx, [rcx+rcx*2]
    mov edx, eax
    and edx, 21C5E2C2h
    and eax, 5E3A1D3Dh
    lea eax, [rax+rax*8]
    lea eax, [rax+rdx*4]
    sub eax, ecx
    mov ecx, dword ptr [rsp+13Ch]
    add eax, ecx
    add eax, -355CAF6Eh
    mov dword ptr [rsp+58h], eax
    mov eax, dword ptr [dword_7FF85AB4A298]
    lea ecx, [rax+1502E3F4h]
    mov edx, ecx
    xor edx, -678F5F7Eh
    mov r8d, ecx
    xor r8d, -6B9A964Eh
    sub edx, r8d
    xor ecx, -30F0DECAh
    add r8d, 1250A1C4h
    add ecx, eax
    add ecx, edx
    add eax, ecx
    add eax, 7DAF8432h
    xor eax, r8d
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13F283:
    mov eax, dword ptr [rsp+198h]
    mov ecx, 65F05C2Ch
    add eax, ecx
    xor eax, 2803E01Eh
    add eax, 38501ECEh
    mov dword ptr [rsp+19Ch], eax
    mov eax, dword ptr [dword_7FF85AB4A2C0]
    mov ecx, 19D6E86Ah
    add eax, ecx
    mov ecx, eax
    xor ecx, 1941A220h
    mov edx, eax
    xor edx, 562BB3DDh
    sub edx, ecx
    xor edx, eax
    mov dword ptr [rsp+28h], edx
    jmp loc_7FF85A13DA34
    loc_7FF85A13F2CC:
    mov eax, dword ptr [dword_7FF85AB4A2B8]
    mov ecx, eax
    xor ecx, 3E9824E1h
    lea edx, [rcx+277DF01Ah]
    xor edx, 510DA822h
    add eax, 205B144Ch
    xor eax, ecx
    add eax, edx
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13F2F8:
    mov rcx, qword ptr [rsp+70h]
    mov edx, dword ptr [rsp+19Ch]
    call rsi
    mov dword ptr [rsp+1A0h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FF85AADC778]
    mov dword ptr [rsp+6Ch], eax
    mov eax, dword ptr [dword_7FF85AB4A2C8]
    lea ecx, [rax+465DAA3Bh]
    mov edx, ecx
    add eax, -368126E2h
    xor eax, ecx
    xor ecx, -364964D5h
    xor edx, -366159F1h
    add edx, 4D738491h
    sub eax, ecx
    loc_7FF85A13F3A3:
    xor eax, edx
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13F3AE:
    mov eax, dword ptr [rsp+34h]
    and eax, ebp
    mov ecx, dword ptr [rsp+0ACh]
    add eax, eax
    sub ecx, eax
    mov dword ptr [rsp+0B0h], ecx
    mov eax, dword ptr [dword_7FF85AB4A1E8]
    lea ecx, [rax-12EB418h]
    xor ecx, -3EFD292Ah
    lea edx, 61097B6h[rax*2]
    xor edx, ecx
    add ecx, eax
    sub edx, ecx
    sub edx, eax
    add edx, -33D6228h
    mov dword ptr [rsp+28h], edx
    jmp loc_7FF85A13DA34
    loc_7FF85A13F3F6:
    mov rax, qword ptr [rsp+2D8h]
    sub rax, qword ptr [rsp+2D0h]
    add rax, qword ptr [rsp+2C0h]
    add rax, qword ptr [rsp+2B8h]
    xor rax, qword ptr [rsp+1C8h]
    add rax, qword ptr [rsp+2A8h]
    xor rax, qword ptr [rsp+2B0h]
    mov qword ptr [rsp+2F0h], rax
    lea rax, [rsp+2F8h]
    mov qword ptr [rsp+2E0h], rax
    mov eax, dword ptr [rsp+40h]
    mov qword ptr [rsp+2E8h], rax
    mov eax, dword ptr [dword_7FF85AB4A208]
    mov ecx, eax
    xor ecx, 46ECC60Fh
    add ecx, 22A3A360h
    xor ecx, eax
    xor ecx, 0E27E8B9h
    jmp loc_7FF85A13DA30
    loc_7FF85A13F473:
    mov eax, dword ptr [dword_7FF85AB4A2C4]
    lea ecx, [rax-75D4A662h]
    mov edx, ecx
    xor edx, 4051E807h
    lea r8d, [rdx+16EDF913h]
    xor r8d, 0D007223h
    mov r9d, edx
    sub r9d, r8d
    add edx, r9d
    add edx, 16EDF913h
    add edx, eax
    sub edx, ecx
    add edx, -43E39885h
    mov dword ptr [rsp+28h], edx
    jmp loc_7FF85A13DA34
    loc_7FF85A13F4B7:
    mov rax, qword ptr [rsp+80h]
    and rax, r15
    mov qword ptr [rsp+240h], rax
    mov eax, dword ptr [dword_7FF85AB4A218]
    add eax, eax
    mov ecx, -405488E8h
    loc_7FF85A13F4D7:
    sub ecx, eax
    jmp loc_7FF85A13DA30
    loc_7FF85A13F4DE:
    mov eax, dword ptr [rsp+30h]
    mov ecx, -3753072Ah
    and eax, ecx
    mov dword ptr [rsp+190h], eax
    mov eax, dword ptr [dword_7FF85AB4A2AC]
    mov ecx, eax
    xor ecx, 16661637h
    mov edx, eax
    xor edx, 4D49E5CBh
    lea r8d, [rdx-16C65698h]
    mov r9d, r8d
    xor r9d, -3771C4A2h
    mov r10d, edx
    sub r10d, ecx
    sub r10d, eax
    add r10d, r9d
    sub r10d, r8d
    sub r10d, edx
    sub r10d, edx
    add r10d, 28BA9A86h
    mov dword ptr [rsp+28h], r10d
    jmp loc_7FF85A13DA34
    loc_7FF85A13F53D:
    mov eax, dword ptr [rsp+30h]
    mov ecx, 37530729h
    and eax, ecx
    mov dword ptr [rsp+194h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FF85AB4A258]
    lea ecx, [rax-6C864F58h]
    xor ecx, 703B3A0Ch
    add ecx, eax
    neg ecx
    add eax, ecx
    add eax, -73AB3D8Fh
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13F5C7:
    mov rax, qword ptr [rsp+1B0h]
    mov rcx, 168BF221778D8722h
    add rax, rcx
    mov qword ptr [rsp+78h], rax
    not rax
    mov qword ptr [rsp+248h], rax
    mov eax, dword ptr [dword_7FF85AB4A22C]
    mov ecx, eax
    xor ecx, -78CBC68Bh
    lea edx, [rcx-2F124FB0h]
    xor edx, -2509C69h
    lea r8d, [rdx+70E72C2h]
    xor r8d, 3F195082h
    add edx, ecx
    add edx, -2803DCEEh
    neg edx
    add edx, r8d
    add edx, 29D70918h
    xor edx, r8d
    xor edx, -206DABh
    sub edx, eax
    add edx, ecx
    mov dword ptr [rsp+28h], edx
    jmp loc_7FF85A13DA34
    loc_7FF85A13F63D:
    mov eax, dword ptr [dword_7FF85AADC794]
    mov dword ptr [rsp+68h], eax
    mov eax, dword ptr [dword_7FF85AB4A294]
    lea ecx, [rax+3F941599h]
    mov edx, ecx
    xor edx, -551462E5h
    xor eax, -56CAD9DEh
    add eax, edx
    add edx, -1A28FF65h
    xor edx, eax
    sub edx, ecx
    mov dword ptr [rsp+28h], edx
    jmp loc_7FF85A13DA34
    loc_7FF85A13F675:
    mov eax, dword ptr [dword_7FF85AB4A1F4]
    mov ecx, -57466C12h
    add eax, ecx
    mov ecx, eax
    xor ecx, 6F3F31B9h
    add ecx, 1FD8ABBEh
    xor ecx, eax
    jmp loc_7FF85A13DA30
    loc_7FF85A13F697:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+3Ch]
    mov ecx, dword ptr [rsp+0E8h]
    or ecx, eax
    not ecx
    mov dword ptr [rsp+0ECh], ecx
    mov ecx, dword ptr [rsp+38h]
    mov edx, eax
    or edx, ecx
    not edx
    mov dword ptr [rsp+0F0h], edx
    xor eax, ecx
    not eax
    mov dword ptr [rsp+0F4h], eax
    mov eax, dword ptr [dword_7FF85AB4A268]
    lea ecx, [rax-48C9C4CFh]
    lea edx, [rax-295534A2h]
    xor edx, ecx
    lea ecx, [rax-75286990h]
    xor edx, ecx
    xor ecx, -285441Ah
    add ecx, eax
    mov eax, 4E2828BFh
    sub eax, ecx
    jmp loc_7FF85A13FFA9
    loc_7FF85A13F762:
    mov eax, dword ptr [dword_7FF85AB4A288]
    mov ecx, eax
    xor ecx, 4B60DDFAh
    lea edx, [rcx-2FF0ABF1h]
    mov r8d, eax
    xor r8d, -596536B3h
    sub r8d, edx
    sub r8d, eax
    xor r8d, ecx
    add r8d, ecx
    sub r8d, edx
    add r8d, -2431DCFCh
    mov dword ptr [rsp+28h], r8d
    jmp loc_7FF85A13DA34
    loc_7FF85A13F7A0:
    mov rax, qword ptr [rsp+270h]
    not rax
    lea rcx, [rax+rax*2]
    mov rax, qword ptr [rsp+78h]
    mov rdx, rax
    and rdx, r13
    add rdx, rdx
    and rax, rdi
    add rax, rax
    sub rax, rdx
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
    sub rax, qword ptr [rsp+268h]
    sub rax, qword ptr [rsp+258h]
    add rax, qword ptr [rsp+250h]
    mov qword ptr [rsp+88h], rax
    mov rcx, rax
    or rcx, rbx
    not rcx
    lea rcx, [rcx+rcx*2]
    mov qword ptr [rsp+278h], rcx
    mov rcx, rax
    or rcx, r12
    not rcx
    add rcx, rcx
    mov qword ptr [rsp+280h], rcx
    and rax, rbx
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
    add rax, rax
    mov qword ptr [rsp+288h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+88h]
    and rax, r12
    mov qword ptr [rsp+290h], rax
    mov eax, dword ptr [dword_7FF85AB4A234]
    mov ecx, 1A29B732h
    add eax, ecx
    xor eax, 797EEABCh
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13F94B:
    mov eax, dword ptr [rsp+0D4h]
    sub eax, dword ptr [rsp+0C8h]
    sub eax, dword ptr [rsp+0C4h]
    sub eax, dword ptr [rsp+0C0h]
    mov dword ptr [rsp+0D8h], eax
    mov ecx, eax
    not ecx
    mov edx, ecx
    and edx, -539FD77Ch
    lea edx, [rdx+rdx*2]
    and ecx, 539FD77Bh
    lea ecx, [rcx+rcx*4]
    mov r8d, eax
    xor r8d, 2C602884h
    add r8d, r8d
    and eax, 139FD77Bh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    sub eax, r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ecx, [rax+rdx]
    add ecx, 5DE0CA99h
    mov dword ptr [rsp+0DCh], ecx
    add eax, edx
    add eax, 159E538Fh
    mov dword ptr [rsp+0E0h], eax
    xor eax, -6AA538B4h
    mov dword ptr [rsp+0E4h], eax
    add eax, 64973F19h
    mov dword ptr [rsp+38h], eax
    mov eax, -3FE3FEA7h
    sub eax, dword ptr [rsp+44h]
    mov dword ptr [rsp+3Ch], eax
    mov eax, dword ptr [dword_7FF85AB4A25C]
    lea ecx, [rax-6E582B47h]
    xor ecx, 3220FFD3h
    lea edx, [rcx+63AD9FD5h]
    xor edx, -5B9EBD80h
    add ecx, edx
    add ecx, 411A1361h
    xor ecx, eax
    jmp loc_7FF85A13DA30
    loc_7FF85A13FB31:
    mov eax, dword ptr [rsp+14Ch]
    mov ecx, dword ptr [rsp+50h]
    mov edx, dword ptr [rsp+5Ch]
    mov r8d, edx
    xor r8d, ecx
    lea r9d, [r8*8]
    mov r10d, ecx
    not r10d
    and r10d, edx
    shl r10d, 3
    and edx, ecx
    add edx, edx
    sub r10d, edx
    sub r8d, r9d
    add r8d, r10d
    lea eax, [r8+rax*4]
    mov dword ptr [rsp+150h], eax
    mov eax, dword ptr [dword_7FF85AB4A248]
    mov ecx, eax
    xor ecx, 0E6DD693h
    add eax, ecx
    lea edx, [rcx-4251D693h]
    lea r8d, [rcx-0AA2D316h]
    xor r8d, -1D0B31C1h
    add eax, ecx
    sub eax, r8d
    add eax, 71318D65h
    jmp loc_7FF85A13FFA9
    loc_7FF85A13FBA6:
    mov eax, dword ptr [rsp+0A4h]
    mov dword ptr [rsp+0A8h], eax
    mov eax, dword ptr [dword_7FF85AB4A1E0]
    lea ecx, [rax-3772E7CDh]
    mov edx, ecx
    xor edx, 268E778Eh
    mov r8d, ecx
    xor r8d, 57A43804h
    mov r9d, ecx
    xor r9d, -41343AC8h
    add eax, r9d
    add eax, -3772E7CDh
    sub eax, r8d
    sub eax, edx
    add eax, 1E03D91Dh
    xor eax, ecx
    xor ecx, 0F561C61h
    xor eax, -0BA880F5h
    jmp loc_7FF85A140222
    loc_7FF85A13FC00:
    mov eax, dword ptr [rsp+150h]
    sub eax, dword ptr [rsp+148h]
    add eax, dword ptr [rsp+144h]
    mov dword ptr [rsp+154h], eax
    mov ecx, dword ptr [rsp+54h]
    mov edx, ecx
    not edx
    mov r8d, eax
    or r8d, edx
    not r8d
    lea r8d, [r8+r8*2]
    mov dword ptr [rsp+158h], r8d
    mov r8d, eax
    or r8d, ecx
    not r8d
    add r8d, r8d
    mov dword ptr [rsp+15Ch], r8d
    and edx, eax
    not edx
    add edx, edx
    mov dword ptr [rsp+160h], edx
    and eax, ecx
    mov dword ptr [rsp+164h], eax
    mov eax, dword ptr [dword_7FF85AB4A2A0]
    lea ecx, [rax+11E701C6h]
    mov edx, -213B8E9Ch
    sub edx, eax
    xor edx, ecx
    xor ecx, -7582EA46h
    add ecx, edx
    sub ecx, eax
    add ecx, -689F1F0Dh
    jmp loc_7FF85A13DA30
    loc_7FF85A13FC8D:
    mov eax, dword ptr [rsp+0A0h]
    not eax
    mov dword ptr [rsp+0A4h], eax
    mov eax, dword ptr [dword_7FF85AB4A1DC]
    mov ecx, eax
    xor ecx, -7ECB0AE8h
    sub ecx, eax
    xor eax, 2EEDE115h
    xor ecx, 342570F8h
    add ecx, eax
    jmp loc_7FF85A13DA30
    loc_7FF85A13FCBF:
    mov rax, qword ptr [rsp+80h]
    mov rcx, rax
    or rcx, r15
    not rcx
    lea rcx, [rcx+rcx*2]
    mov qword ptr [rsp+228h], rcx
    mov qword ptr [rsp+230h], rax
    and rax, r14
    lea rax, [rax+rax*2]
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
    mov eax, dword ptr [dword_7FF85AB4A214]
    mov ecx, eax
    xor ecx, -43D0F45Bh
    lea edx, [rcx+41623AE0h]
    mov r8d, edx
    xor r8d, -0ABA1BCh
    lea r9d, 0FD116CBh[r8*2]
    neg r9d
    add r9d, r8d
    add r9d, 0FD116CBh
    sub r9d, edx
    add r9d, ecx
    sub r9d, r8d
    add r9d, -2C8E8DF3h
    xor r9d, eax
    mov dword ptr [rsp+28h], r9d
    jmp loc_7FF85A13DA34
    loc_7FF85A13FD82:
    mov rax, qword ptr [qword_7FF85AB77648]
    mov qword ptr [rsp+1E0h], rax
    mov eax, dword ptr [dword_7FF85AB4A1C0]
    mov ecx, -7AE657CAh
    sub ecx, eax
    xor ecx, eax
    sub ecx, eax
    add ecx, 6870A50Dh
    jmp loc_7FF85A13DA30
    loc_7FF85A13FDAD:
    mov eax, dword ptr [rsp+30h]
    not eax
    and eax, 37530729h
    mov dword ptr [rsp+180h], eax
    mov eax, dword ptr [dword_7FF85AB4A244]
    mov ecx, eax
    xor ecx, -63DCAF5Fh
    add ecx, eax
    xor eax, 7372CAB3h
    add eax, ecx
    add eax, 13732A0Dh
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13FDE4:
    mov rax, qword ptr [rsp+248h]
    lea rcx, [rax*8]
    sub rcx, rax
    mov qword ptr [rsp+250h], rcx
    mov rax, qword ptr [rsp+78h]
    mov rcx, rax
    or rcx, r13
    not rcx
    lea rcx, [rcx+rcx*8]
    mov qword ptr [rsp+258h], rcx
    or rax, rdi
    mov qword ptr [rsp+260h], rax
    mov eax, dword ptr [dword_7FF85AB4A1B8]
    lea ecx, [rax+5EBE6912h]
    xor ecx, -612C9132h
    add ecx, eax
    add ecx, 5EBE6912h
    add ecx, eax
    mov eax, 72698C74h
    jmp loc_7FF85A140222
    loc_7FF85A13FE4A:
    mov rax, qword ptr [rsp+218h]
    mov qword ptr [rsp+220h], rax
    mov eax, dword ptr [dword_7FF85AB4A1C8]
    lea ecx, [rax-4E9F1566h]
    lea edx, [rax-35313E9Eh]
    xor edx, -25E1DDBBh
    add edx, eax
    add edx, 0A18A67Bh
    xor edx, ecx
    sub edx, eax
    add eax, edx
    add eax, -419260C1h
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13FE8E:
    mov eax, dword ptr [rsp+44h]
    mov ecx, eax
    and ecx, 5E868356h
    mov edx, ecx
    not edx
    shl edx, 2
    mov dword ptr [rsp+0CCh], edx
    and eax, -5E868357h
    lea eax, [rax+rax*2]
    add ecx, ecx
    sub ecx, eax
    mov dword ptr [rsp+0D0h], ecx
    mov eax, dword ptr [dword_7FF85AB4A250]
    lea ecx, [rax+5F19B216h]
    xor ecx, 15D9B47Dh
    mov edx, eax
    xor edx, 236768BDh
    sub edx, ecx
    add eax, edx
    add eax, 5D899972h
    xor eax, ecx
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13FEE9:
    cmp byte ptr [rsp+2Fh], 0
    jz loc_7FF85A13FF3F
    mov eax, dword ptr [dword_7FF85AB4A2B4]
    mov ecx, eax
    xor ecx, -61BE4933h
    lea edx, [rcx-157B359Ch]
    mov r8d, edx
    xor r8d, 5166F9CCh
    mov r9d, edx
    xor r9d, -59C76A84h
    add r9d, r8d
    add r8d, -2995B2A8h
    sub r9d, ecx
    add r9d, 6FE5BDDCh
    xor r9d, r8d
    add ecx, eax
    add ecx, r9d
    xor ecx, edx
    mov dword ptr [rsp+28h], ecx
    jmp loc_7FF85A13DA34
    loc_7FF85A13FF3F:
    mov edx, dword ptr [rsp+40h]
    mov ecx, 3Dh
    mov r8d, 39h
    mov r9d, 13h
    call sub_7FF8599865B0
    mov rax, qword ptr [qword_7FF85AADC768]
    mov qword ptr [rsp+80h], rax
    or rax, r14
    not rax
    mov qword ptr [rsp+218h], rax
    mov eax, dword ptr [dword_7FF85AB4A210]
    lea ecx, [rax+16C84E23h]
    lea edx, [rax-5B575116h]
    xor edx, -5DA444B9h
    lea r8d, [rax-60BF2FC0h]
    xor r8d, eax
    lea eax, [rdx+r8]
    add eax, -36CDAE81h
    add edx, 17DB755Ah
    xor eax, ecx
    loc_7FF85A13FFA9:
    xor eax, edx
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A13FFB4:
    mov rax, qword ptr [rsp+1D8h]
    mov rcx, qword ptr [rsp+2C8h]
    and rcx, rax
    not rcx
    add rcx, rcx
    mov qword ptr [rsp+2D0h], rcx
    and rax, qword ptr [rsp+1D0h]
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
    mov rcx, qword ptr [rsp+1D0h]
    mov rdx, rcx
    not rdx
    mov r8, qword ptr [rsp+1D8h]
    and rdx, r8
    add rdx, rdx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rcx, [rdx+r8*2]
    add rcx, rax
    mov qword ptr [rsp+2D8h], rcx
    mov eax, dword ptr [dword_7FF85AB4A284]
    lea ecx, [rax+657AD2C8h]
    lea edx, [rax-1293871h]
    mov r8d, edx
    xor r8d, 1322A2C4h
    add eax, 6FD8CB5h
    xor eax, ecx
    xor eax, r8d
    add r8d, -53FAD388h
    xor r8d, eax
    xor r8d, edx
    mov dword ptr [rsp+28h], r8d
    jmp loc_7FF85A13DA34
    loc_7FF85A14014B:
    mov eax, dword ptr [rsp+0F4h]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+3Ch]
    add eax, eax
    mov dword ptr [rsp+0FCh], eax
    mov eax, dword ptr [rsp+38h]
    not eax
    mov dword ptr [rsp+100h], eax
    mov eax, dword ptr [dword_7FF85AB4A1D4]
    lea ecx, [rax-75DEFEE5h]
    mov edx, ecx
    xor edx, 95DEB95h
    mov r8d, ecx
    xor r8d, 2BFAB43Fh
    xor ecx, -7D78EDDCh
    mov r9d, eax
    xor r9d, 4C227451h
    add eax, r9d
    add eax, -75DEFEE5h
    sub eax, edx
    add eax, r8d
    loc_7FF85A140222:
    sub eax, ecx
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A14022D:
    mov rax, qword ptr [rsp+2E0h]
    mov rcx, qword ptr [rsp+2E8h]
    mov qword ptr [rax], rcx
    mov eax, dword ptr [dword_7FF85AADC788]
    mov dword ptr [rsp+48h], eax
    not eax
    mov ecx, eax
    and ecx, -24E69CF2h
    lea ecx, [rcx+rcx*2]
    mov dword ptr [rsp+110h], ecx
    and eax, 24E69CF1h
    shl eax, 2
    mov dword ptr [rsp+114h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov ecx, 24E69CF1h
    and eax, ecx
    mov dword ptr [rsp+118h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FF85AB4A28C]
    mov ecx, eax
    xor ecx, 541ABC57h
    add ecx, eax
    add eax, -60E7516Fh
    xor eax, -482E995Ch
    sub ecx, eax
    add ecx, -343FEED3h
    jmp loc_7FF85A13DA30
    loc_7FF85A140358:
    mov rax, qword ptr [rsp+208h]
    xor rax, qword ptr [rsp+1F8h]
    xor rax, qword ptr [rsp+1F0h]
    xor rax, qword ptr [rsp+200h]
    xor rax, qword ptr [rsp+1E8h]
    mov qword ptr [rsp+70h], rax
    mov eax, dword ptr [dword_7FF85AADC760]
    mov dword ptr [rsp+94h], eax
    xor eax, -0E9B1BDCh
    add eax, 0D6C9EFDh
    mov dword ptr [rsp+34h], eax
    or eax, -7825A26Eh
    mov dword ptr [rsp+98h], eax
    mov eax, dword ptr [dword_7FF85AB4A1D8]
    mov ecx, eax
    xor ecx, -2E0717DFh
    mov edx, 7B3B08EAh
    sub edx, ecx
    xor edx, eax
    lea r8d, [rcx-419159ADh]
    xor r8d, 0F44232Ch
    xor edx, -221ACCB5h
    sub edx, ecx
    sub edx, eax
    lea eax, [rdx+r8]
    add eax, 403E176Bh
    mov dword ptr [rsp+28h], eax
    jmp loc_7FF85A13DA34
    loc_7FF85A1403ED:
    mov eax, dword ptr [dword_7FF85AB4A2D4]
    lea ecx, [rax-6AE51197h]
    mov edx, ecx
    xor edx, -8B7FE1h
    mov r8d, edx
    xor r8d, eax
    xor r8d, -5D465441h
    sub r8d, ecx
    xor r8d, edx
    xor r8d, -4AFC25F7h
    sub r8d, eax
    add r8d, -6A181F28h
    mov dword ptr [rsp+28h], r8d
    jmp loc_7FF85A13DA34
    loc_7FF85A14042F:
    mov ecx, dword ptr [rsp+68h]
    lea edx, [rcx+7D0D862Fh]
    xor edx, 3D36F6BAh
    lea r8d, [rdx-7EA35A90h]
    xor r8d, 520638Eh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8d, 0CDD8ABBh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, -3E6A17DAh
    sub eax, ecx
    xor eax, r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub eax, dword ptr [rsp+68h]
    add eax, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add eax, 1224E37Dh
    mov rcx, qword ptr [rsp+300h]
    xor rcx, rsp
    cmp rcx, qword ptr [__security_cookie]
    jnz loc_7FF85A1405FA
    add rsp, 308h
    pop rbx
    pop rbp
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    ret
    loc_7FF85A1405FA:
    call __security_check_cookie
    int 3
_TEXT ENDS
END

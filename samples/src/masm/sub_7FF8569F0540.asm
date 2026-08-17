; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: sub_7FF8569F0540  @ 0x7ff8569f0540
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN ??2@YAPEAX_K@Z:PROC
EXTERN memcpy:PROC
EXTERN strlen:PROC
EXTERN sub_7FF855343EB0:PROC
EXTERN sub_7FF855CA1330:PROC
EXTERN sub_7FF85702AFE0:PROC

CONST SEGMENT
Src db 0
off_7FF8571A2640 dq off_7FF85711D058
dword_7FF8571CF8E0 dd 0D17CED32h
byte_7FF8571CF8E4 db 0FDh
qword_7FF8571CF8E8 dq 56515009C666671Bh
dword_7FF8571CF8F0 dd 0A7C9991Fh
qword_7FF8571CF8F8 dq 7C5C2954AF6234ACh
qword_7FF8571CF900 dq -4212F3E1A2A83723h
qword_7FF8571CF908 dq -170DAEEC8D9FA89Fh
qword_7FF8571CF910 dq 332B8258F6FCBA5Dh
qword_7FF8571CF918 dq 2CEC71D443D00E94h
qword_7FF8571CF920 dq 3B1AA3405B23E4E9h
byte_7FF8571CF928 db 16h
qword_7FF8571CF930 dq 0B5B14DAF4B253FDh
byte_7FF8571CF938 db 0F2h
qword_7FF8571CF940 dq -31394F41CCADFD22h
qword_7FF8571CF948 dq 7A61D77BB30B183Fh
qword_7FF8571CF950 dq -34AF797AB8EBCD94h
qword_7FF8571CF958 dq -4A1BAE3E9036B78h
qword_7FF8571CF960 dq 7E0B184DAA6FB252h
byte_7FF8571CF968 db 44h
qword_7FF8571CF970 dq 15709DE3FF40CFE7h
qword_7FF8571CF978 dq -330F7A889CBF4E1Eh
qword_7FF8571CF980 dq -48F3560552BA21BAh
qword_7FF8571CF988 dq -3018714D51A4B41Eh
qword_7FF8571CF990 dq 70A9D31EC0C28089h
qword_7FF8571CF998 dq -6393262DC6B46BEDh
qword_7FF8571CF9A0 dq -31180725040BEC5h
dword_7FF8571CF9A8 dd 0B963EB9Bh
qword_7FF8571CF9B0 dq -0FD8A46CDF2F1CD7h
qword_7FF8571CF9B8 dq 15644491BD53564Bh
qword_7FF8571CF9C0 dq -1E80E91DF91DE0BBh
qword_7FF8571CF9C8 dq -46966643A728F7D2h
qword_7FF8571CF9D0 dq 8566872D1B07FA1h
qword_7FF8571CF9D8 dq -2D14C03912BA8AC1h
qword_7FF8571CF9E0 dq 1D23EBC3638799Bh
byte_7FF8571CF9E8 db 0A0h
qword_7FF8571CF9F0 dq 1C25C4A2C645D134h
byte_7FF8571CF9F8 db 49h
qword_7FF8571CFA00 dq 34F581456E9106C6h
qword_7FF8571CFA08 dq -77B1F4BB0537B5F4h
qword_7FF8571CFA10 dq -3D145037BC03D3F0h
qword_7FF8571CFA18 dq 793BDEB0BA258412h
dword_7FF8571CFA20 dd 46EF0003h
qword_7FF8571CFA28 dq 6048B184E67D3704h
qword_7FF8571CFA30 dq 43128E52CFE28DBh
qword_7FF8571CFA38 dq -77E88203ED2A9BC8h
qword_7FF8571CFA40 dq -3F9D2531EF870132h
qword_7FF8571CFA48 dq -392A998EA552ABBFh
qword_7FF8571CFA50 dq -55C196F4E92E25B1h
qword_7FF8571CFA58 dq 4C0ABFB799D32D49h
qword_7FF8571CFA60 dq -17E2A255DEE53541h
qword_7FF8571CFA68 dq 23B90145B63268D8h
qword_7FF8571CFA70 dq 2466F5F1A9D89472h
qword_7FF8571CFA78 dq -59FCF25D92D70835h
qword_7FF8571CFA80 dq 45AF9C6CE4AAB3DCh
qword_7FF8571CFA88 dq -524B40531A4DC39Ah
qword_7FF8571CFA90 dq -7E77C83493D57EAEh
qword_7FF8571CFA98 dq 757410376E0008BCh
qword_7FF8571CFAA0 dq 13828F7DE8E9C694h
byte_7FF8571CFAA8 db 7Fh
byte_7FF8571CFAC0 db 4Dh
qword_7FF8571CFAC8 dq -4A781E3ADD6D455Ah
byte_7FF8571CFAD0 db 0FCh
qword_7FF8571CFAD8 dq 1E8E32ACD7D9F836h
qword_7FF8571CFAE0 dq 21E0D4ACD0C71D66h
qword_7FF8571CFAE8 dq 0DD86CCC49C5D78Bh
qword_7FF8571CFAF0 dq 4B59DAB67068F43Fh
qword_7FF8571CFAF8 dq -44236FA12C4FA39Fh
dword_7FF8571CFB00 dd 0E17B032Fh
qword_7FF8571CFB08 dq 5073CDA084D491Dh
qword_7FF8571CFB10 dq -339C013B9B3927A6h
qword_7FF8571CFB18 dq -69242E7C2665B222h
qword_7FF8571CFB20 dq 3FDDF752DF790F79h
qword_7FF8571CFB28 dq 5C3AD871403CA41Ah
qword_7FF8571CFB30 dq -2A25C2419D629AFEh
qword_7FF8571CFB38 dq -25EBA13E1E04E9EAh
qword_7FF8571CFB40 dq -3E7A7A961B1DDF05h
byte_7FF8571CFB48 db 39h
qword_7FF8571CFB50 dq 7E2DBA9F6C55B55Ch
qword_7FF8571CFB58 dq -4A00D5B00649988Ah
qword_7FF8571CFB60 dq 30FB392EA1C45041h
qword_7FF8571CFB68 dq -71773FADE11411F9h
qword_7FF8571CFB70 dq -6A49589B425DAD73h
byte_7FF8571CFB78 db 0D7h
qword_7FF8571CFB80 dq 0F7AF0FFD7D3C0FBh
qword_7FF8571CFB88 dq 572727B2A54765E8h
qword_7FF8571CFB90 dq 6E811C307857CF50h
qword_7FF8571CFB98 dq 2BA85F30CDE0672Ch
qword_7FF8571CFBA0 dq 36E13619C3D85815h
qword_7FF8571CFBA8 dq -6F78C8EE23B30B8Eh
dword_7FF8571CFBB0 dd 275F4D63h
qword_7FF8571CFBB8 dq 55BA7DE3D8C222A1h
qword_7FF8571CFBC0 dq 24A9573625CF81A1h
byte_7FF8571CFBC8 db 8Ch
qword_7FF8571CFBD0 dq -2FF568BA5894205Dh
qword_7FF8571CFBD8 dq 738EAF8679C5C69Bh
qword_7FF8571CFBE0 dq -5B3DB71792D51789h
qword_7FF8571CFBE8 dq 26DED00F648E7116h
qword_7FF8571CFBF0 dq -102A425B07629AB4h
qword_7FF8571CFBF8 dq -7AFAA55C8649BCDh
qword_7FF8571CFC00 dq -2407F125EF5ED5CAh
qword_7FF8571CFC08 dq 4D3E2FEE73747211h
qword_7FF8571CFC10 dq -7E2F9F0E5CB80237h
qword_7FF8571CFC18 dq 5F8162917C2C0673h
byte_7FF8571CFC20 db 1Dh
qword_7FF8571CFC38 dq 23BF6F2054A27074h
dword_7FF8571CFC40 dd 12CE312Eh
dword_7FF8571CFC44 dd 15123F3Bh
qword_7FF8571CFC48 dq 6FA8D1B508952BF1h
dword_7FF8571CFC50 dd 0E0FCB79Eh
dword_7FF8571CFC54 dd 3BBBCAB4h
dword_7FF8571CFC58 dd 612B8D4Fh
qword_7FF8571CFC60 dq 3D14C1BE25AA6130h
dword_7FF8571CFC68 dd 7B48F907h
qword_7FF8571CFC70 dq 425375D6BD9F26CCh
qword_7FF8571CFC78 dq -13039687381BB1E4h
qword_7FF8571CFC80 dq 248A1AF2CEACB15Fh
dword_7FF8571CFC88 dd 3FBDD872h
qword_7FF8571CFC90 dq -24B6779B5CB8253Bh
qword_7FF8571CFC98 dq 494B2376C3369F7Dh
qword_7FF8571CFCA0 dq -6035EE2C609670DDh
qword_7FF8571CFCA8 dq 2958A3C1C6E7FD94h
qword_7FF8571CFCB0 dq -6B0A1DF4949000ECh
qword_7FF8571CFCB8 dq 2479CF6FE3067D7Ah
qword_7FF8571CFCC0 dq 1FAC8F15B6357AF9h
byte_7FF8571CFCC8 db 0ACh
qword_7FF8571CFCD0 dq 3A1EEC65B0DC0CC7h
qword_7FF8571CFCD8 dq 7DA6D89D6CDF58Bh
qword_7FF8571CFCE0 dq 79FDE94ED35C5A9Ah
qword_7FF8571CFCE8 dq 1BA2362BCC9ADCAFh
qword_7FF8571CFCF0 dq 15BF72C1B9CCB54Dh
dword_7FF85724290C dd 3418CF26h
dword_7FF857242910 dd 1AD845Dh
dword_7FF857242914 dd 65E079F7h
dword_7FF857242918 dd 0D715B52Eh
dword_7FF85724291C dd 0A25D6B79h
dword_7FF857242920 dd 4CFF46E9h
dword_7FF857242924 dd 960699A9h
dword_7FF857242928 dd 7B4E30DEh
dword_7FF85724292C dd 2DC92651h
dword_7FF857242930 dd 337FBF0Dh
dword_7FF857242934 dd 0E22D6517h
dword_7FF857242938 dd 0C209F27Eh
dword_7FF85724293C dd 2209B1A5h
dword_7FF857242940 dd 0B4F5E56Eh
dword_7FF857242944 dd 0DC66CBC9h
dword_7FF857242948 dd 5EFCD693h
dword_7FF85724294C dd 87FC0EF9h
dword_7FF857242950 dd 6C6929D3h
dword_7FF857242954 dd 34122B7Ah
dword_7FF857242958 dd 0D16C6C30h
dword_7FF85724295C dd 0A608E55h
dword_7FF857242960 dd 718797B3h
dword_7FF857242964 dd 0DC158180h
dword_7FF857242968 dd 0DCCCD75Ch
dword_7FF85724296C dd 0E5985AC7h
dword_7FF857242970 dd 7E677C7Dh
dword_7FF857242974 dd 8CACFB3Dh
dword_7FF857242978 dd 8A093ADFh
dword_7FF85724297C dd 0A41CB9B3h
dword_7FF857242980 dd 87F6AA38h
dword_7FF857242984 dd 962C1AB6h
dword_7FF857242988 dd 0D653B3F1h
dword_7FF85724298C dd 0D7CF7B1Fh
dword_7FF857242990 dd 31E9693Bh
dword_7FF857242994 dd 0E53A70A4h
dword_7FF857242998 dd 4771BF26h
dword_7FF85724299C dd 8A32BCB6h
dword_7FF8572429A0 dd 0C19D7C54h
dword_7FF8572429A4 dd 2432B08Dh
dword_7FF8572429A8 dd 5D941A10h
dword_7FF8572429AC dd 0DFCD2A3h
dword_7FF8572429B0 dd 0DC402CB2h
dword_7FF8572429B4 dd 540A745Dh
dword_7FF8572429B8 dd 0DB668A65h
dword_7FF8572429BC dd 606059A5h
dword_7FF8572429C0 dd 6A3A6899h
dword_7FF8572429C4 dd 0E8FA3521h
dword_7FF8572429C8 dd 26120ECBh
dword_7FF8572429CC dd 0D58EF7A5h
dword_7FF8572429D0 dd 3D4E2FC1h
dword_7FF8572429D4 dd 715A8994h
dword_7FF8572429D8 dd 244570Fh
dword_7FF8572429DC dd 0A573AD70h
dword_7FF8572429E0 dd 68C2A547h
dword_7FF8572429E4 dd 8B910F94h
dword_7FF8572429E8 dd 0BECEB940h
dword_7FF8572429EC dd 0FAEB01B0h
dword_7FF8572429F0 dd 5576F99Dh
dword_7FF8572429F4 dd 62834260h
dword_7FF8572429F8 dd 0C99FA857h
dword_7FF8572429FC dd 0CD37D389h
dword_7FF857242A00 dd 5833375Eh
dword_7FF857242A04 dd 6FEAC06Dh
dword_7FF857242A08 dd 601F78CDh
dword_7FF857242A0C dd 1EB5AED7h
dword_7FF857242A10 dd 0C47A4B51h
dword_7FF857242A14 dd 2AE30427h
dword_7FF857242A18 dd 0C23F703Dh
dword_7FF857242A1C dd 191E623Dh
dword_7FF857242A20 dd 8BD699ACh
dword_7FF857242A24 dd 32BDF944h
dword_7FF857242A28 dd 97271C95h
dword_7FF857242A2C dd 91BF8078h
dword_7FF857242A30 dd 86B4556Ch
dword_7FF857242A34 dd 0C8B4B7EBh
dword_7FF857242A38 dd 6FB29E2Dh
dword_7FF857242A3C dd 0AAD942FDh
dword_7FF857242A40 dd 0CA152FEFh
dword_7FF857242A44 dd 0E73EE1Eh
dword_7FF857242A48 dd 0AC46430Bh
dword_7FF857242A4C dd 7970C312h
dword_7FF857242A50 dd 1FEAB5B8h
dword_7FF857242A54 dd 24421543h
dword_7FF857242A58 dd 0C158B590h
dword_7FF857242A5C dd 0E154C451h
dword_7FF857242A60 dd 0EF22C083h
dword_7FF857242A64 dd 1FB8DFB0h
dword_7FF857242A68 dd 8426117h
dword_7FF857242A6C dd 0A35B4BEDh
dword_7FF857242A70 dd 0F0230A87h
dword_7FF857242A74 dd 32791CA0h
dword_7FF857242A78 dd 3D6F8D96h
dword_7FF857242A7C dd 6B4386ACh
dword_7FF857242A80 dd 50400331h
dword_7FF857242A84 dd 0EEEE6615h
dword_7FF857242A88 dd 8D6E4D0Eh
dword_7FF857242A8C dd 85193444h
dword_7FF857242A90 dd 39E68BB8h
dword_7FF857242A94 dd 0E4ED1BF6h
dword_7FF857242A98 dd 0BE43B7FFh
dword_7FF857242A9C dd 52F37BC4h
dword_7FF857242AA0 dd 57DD5667h
dword_7FF857242AA4 dd 808DA273h
dword_7FF857242AA8 dd 3A3C4BB7h
dword_7FF857242AAC dd 0A0F5561Ah
dword_7FF857242AB0 dd 9079E45h
dword_7FF857242AB4 dd 6D9EF785h
dword_7FF857242AB8 dd 5935288Fh
dword_7FF857242ABC dd 0ED4CCE54h
dword_7FF857242AC0 dd 165F6902h
dword_7FF857242AC4 dd 93579142h
dword_7FF857242AC8 dd 4F3C22A2h
dword_7FF857242ACC dd 64F587D0h
dword_7FF857242AD0 dd 8E1DAD8Ch
dword_7FF857242AD4 dd 14DD3B7Eh
dword_7FF857242AD8 dd 0E843FCF7h
dword_7FF857242ADC dd 312DB72Ah
dword_7FF857242AE0 dd 0A9809D2Ch
dword_7FF857242AE4 dd 4A7D67F2h
dword_7FF857242AE8 dd 99938C5Eh
dword_7FF857242AEC dd 440143D4h
dword_7FF857242AF0 dd 16BBD104h
dword_7FF857242AF4 dd 1534B708h
dword_7FF857242AF8 dd 0BFC77A3Ch
dword_7FF857242AFC dd 0D0B1DEF2h
dword_7FF857242B00 dd 0A7A6DC37h
dword_7FF857242B04 dd 9B08EAA0h
dword_7FF857242B08 dd 0E089FBC0h
dword_7FF857242B0C dd 4F47DA0Ch
dword_7FF857242B10 dd 0E717586Ch
dword_7FF857242B14 dd 7DEF5BA7h
dword_7FF857242B18 dd 0EE86085Ch
dword_7FF857242B1C dd 4592FCB4h
dword_7FF857242B20 dd 2F00656Dh
dword_7FF857242B24 dd 11DABA16h
dword_7FF857242B28 dd 0B303AA30h
dword_7FF857242B2C dd 47723229h
qword_7FF8572A3878 dq -1
qword_7FF8572A5980 dq -1
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC sub_7FF8569F0540
sub_7FF8569F0540:
    push rbp
    push r15
    push r14
    push r13
    push r12
    push rsi
    push rdi
    push rbx
    sub rsp, 6C8h
    lea rbp, [rsp+80h]
    mov qword ptr [rbp+640h], -2
    mov qword ptr [rbp+0B8h], rdx
    mov eax, 57136309h
    xor eax, dword ptr [dword_7FF85724290C]
    lea ecx, [rax-2D4C0A3Fh]
    lea edx, [rax+7D0B581Ch]
    lea r8d, [rax+18F1A723h]
    xor edx, r8d
    xor r8d, 0AB9B995h
    add r8d, -1E9E29F4h
    xor edx, ecx
    xor edx, 705A2E3Ch
    sub edx, eax
    xor edx, r8d
    mov dword ptr [rbp+63Ch], edx
    lea r12, off_7FF8571A2640
    mov r13, 7FFFFFFFFFFFFFFFh
    mov r15, 5C6A94959A3EC751h
    jmp loc_7FF8569F0600
    loc_7FF8569F05CC:
    mov eax, dword ptr [dword_7FF857242A90]
    lea ecx, [rax-744FA1F2h]
    lea edx, [rax+3ABCD0F3h]
    mov r8d, edx
    xor r8d, -1152738Bh
    sub r8d, eax
    add r8d, -678BB403h
    xor edx, eax
    xor edx, ecx
    xor edx, r8d
    loc_7FF8569F05F9:
    mov dword ptr [rbp+63Ch], edx
    nop
    loc_7FF8569F0600:
    mov eax, dword ptr [rbp+63Ch]
    cmp eax, 423C3FEBh
    jle loc_7FF8569F06A0
    cmp eax, 620805EBh
    jle loc_7FF8569F0790
    cmp eax, 6FB5D125h
    jle loc_7FF8569F0867
    cmp eax, 7859A184h
    jg loc_7FF8569F17EF
    cmp eax, 73748828h
    jle loc_7FF8569F1A3E
    cmp eax, 73FCE709h
    jle loc_7FF8569F495F
    cmp eax, 73FCE70Ah
    jz loc_7FF8569F9930
    cmp eax, 74F89B5Ah
    jnz loc_7FF8569FC783
    loc_7FF8569F065E:
    mov rax, qword ptr [rbp+5D8h]
    mov rax, qword ptr [rax]
    mov qword ptr [rbp+30h], rax
    test rax, rax
    js loc_7FF856A07F03
    mov rdx, qword ptr [rbp+138h]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569F0683:
    mov rcx, r12
    call qword ptr [rax+30h]
    mov rax, qword ptr [rbp+5D8h]
    mov rax, qword ptr [rax]
    jmp loc_7FF8569F679C
    loc_7FF8569F06A0:
    cmp eax, 1FF46793h
    jle loc_7FF8569F0820
    cmp eax, 3230A373h
    jle loc_7FF8569F08B7
    cmp eax, 3ADB522Ch
    jg loc_7FF8569F1834
    cmp eax, 34B74EDEh
    jle loc_7FF8569F2354
    cmp eax, 37000CEBh
    jle loc_7FF8569F69EE
    cmp eax, 37000CECh
    jz loc_7FF8569FDE6C
    cmp eax, 37351A8Dh
    jz loc_7FF8569F6839
    mov rdx, qword ptr [rbp+0E8h]
    mov rax, qword ptr [off_7FF8571A2640]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, r12
    call qword ptr [rax+30h]
    mov rax, qword ptr [rbp+5B0h]
    mov rax, qword ptr [rax]
    mov qword ptr [rbp+1C0h], rax
    jmp loc_7FF8569F94C9
    loc_7FF8569F0790:
    cmp eax, 512CF100h
    jg loc_7FF8569F0936
    cmp eax, 48240CC2h
    jle loc_7FF8569F1950
    cmp eax, 4B0FE5C7h
    jle loc_7FF8569F1B4E
    cmp eax, 4C4DB60Dh
    jle loc_7FF8569F5CD8
    cmp eax, 4C4DB60Eh
    jz loc_7FF8569FA82F
    cmp eax, 50884FCCh
    jz loc_7FF856A07140
    mov rax, qword ptr [rbp+528h]
    cmp rax, qword ptr [rbp+60h]
    jnz loc_7FF856A0619C
    mov eax, dword ptr [dword_7FF857242A80]
    mov ecx, eax
    xor ecx, 39F8E1Fh
    lea edx, [rcx+325E56ECh]
    xor edx, eax
    xor edx, 2864FE7h
    sub edx, ecx
    lea ecx, 325E56ECh[rcx*2]
    sub edx, ecx
    add eax, edx
    add eax, 50D6308Fh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F0820:
    cmp eax, 12A3BD5Eh
    jg loc_7FF8569F17B3
    cmp eax, 87A16AEh
    jle loc_7FF8569F19BA
    cmp eax, 0AE91650h
    jle loc_7FF8569F259D
    cmp eax, 0EE1BCACh
    jle loc_7FF8569F7E6C
    cmp eax, 0EE1BCADh
    jz loc_7FF856A01EAE
    cmp eax, 0FA5B501h
    jz loc_7FF8569F2CF2
    jmp loc_7FF8569F7E8E
    loc_7FF8569F0867:
    cmp eax, 67DD0A64h
    jle loc_7FF8569F1895
    cmp eax, 6A6EB593h
    jle loc_7FF8569F1AB0
    cmp eax, 6C1D52A9h
    jle loc_7FF8569F53A7
    cmp eax, 6C1D52AAh
    jz loc_7FF8569FA4D2
    cmp eax, 6C48B2B6h
    jz loc_7FF856A008D9
    mov rdx, qword ptr [rbp+160h]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569F08AC:
    mov rcx, r12
    call qword ptr [rax+30h]
    jmp loc_7FF856A0501C
    loc_7FF8569F08B7:
    cmp eax, 28F25B95h
    jle loc_7FF8569F18C2
    cmp eax, 2E160A8Fh
    jle loc_7FF8569F1AE5
    cmp eax, 2F6DC166h
    jle loc_7FF8569F553F
    cmp eax, 2F6DC167h
    jz loc_7FF8569FC7B8
    cmp eax, 30B3EB54h
    jnz loc_7FF8569FCE2E
    cmp byte ptr [rbp+637h], 0
    jz loc_7FF856A0613C
    mov eax, dword ptr [dword_7FF857242A74]
    lea ecx, [rax+1B89B1DBh]
    mov edx, ecx
    xor edx, -2F698811h
    mov r8d, ecx
    xor r8d, -2C9F9211h
    xor ecx, -5C3999B3h
    sub eax, edx
    add eax, r8d
    add eax, ecx
    add eax, 4D3D03E0h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F0936:
    cmp eax, 5733D742h
    jle loc_7FF8569F1980
    cmp eax, 5D79FC98h
    jle loc_7FF8569F1B6D
    cmp eax, 609157A8h
    jle loc_7FF8569F5D98
    cmp eax, 609157A9h
    jz loc_7FF856A001FC
    cmp eax, 60A0D558h
    jnz loc_7FF8569F7E8E
    mov ecx, dword ptr [dword_7FF8571CFB00]
    mov eax, ecx
    xor eax, 0EE4C38Bh
    lea edx, [rax+6A99FB60h]
    xor edx, 0B2h
    sub ecx, edx
    add ecx, eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rbp+38h]
    add cl, 0E4h
    mov rax, rdx
    shr rax, cl
    add rax, rdx
    mov rcx, qword ptr [rbp+5F0h]
    cmp rax, rcx
    cmovbe rax, rcx
    loc_7FF8569F0A09:
    mov rdx, rax
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
    nop
    nop
    nop
    nop
    nop
    nop
    lea rcx, [rdx+rdx*4]
    lea rcx, [rdx+rcx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r8, [rdx+rdx]
    lea r8, [r8+r8*8]
    or rdx, r13
    lea r9, [rax+rax]
    lea r9, [r9+r9*2]
    add r9, rdx
    add r9, r8
    sub rcx, r9
    add rcx, -8
    mov rdx, qword ptr [qword_7FF8571CFB08]
    mov r8, rdx
    not r8
    mov r9, r8
    mov r11, 5AB41E5DD8A802ECh
    and r9, r11
    lea r9, [r9+r9*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r10, -5AB41E5DD8A802EDh
    and r8, r10
    lea r8, [r8+r8*4]
    mov r10, rdx
    xor r10, r11
    add r10, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11, rdx
    mov rsi, 54BE1A22757FD13h
    and r11, rsi
    shl r11, 3
    sub r11, r10
    add r11, r8
    add r11, r9
    mov r8, 4F59E8D45DA402FCh
    add r8, r11
    mov r9, -765B1819226F800h
    xor rdx, r9
    sub rdx, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9, 5238CEFEAFA35073h
    add r11, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9, 71DA2B1A43AECCBEh
    add rdx, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor rdx, r11
    mov r9, r8
    not r9
    mov r10, rdx
    or r10, r9
    mov r11, rdx
    mov rdi, rdx
    xor rdi, r8
    lea rdi, [rdi+rdi*2]
    and r9, rdx
    and rdx, r8
    sub rdx, r9
    add rdx, rdi
    sub rdx, r10
    not r10
    shl r10, 2
    or r11, r8
    not r11
    add rdx, r11
    sub rdx, r10
    mov r8, qword ptr [rbp+368h]
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
    lea r9, [r8+r8*4]
    lea r8, [r8+r9*2]
    mov r10, rdx
    not r10
    mov r11, qword ptr [rbp+368h]
    mov r9, r11
    or r9, r10
    not r9
    add r9, r9
    lea r9, [r9+r9*8]
    and r10, r11
    not r10
    lea rdi, [r10*8]
    sub rdi, r10
    mov r10, r11
    or r10, rdx
    not r10
    add r10, r10
    lea r10, [r10+r10*8]
    and rdx, r11
    add rdx, rdx
    lea rdx, [rdx+rdx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rdi, rdx
    sub rdi, r10
    sub rdi, r9
    add rdi, r8
    or rdi, rcx
    mov rcx, qword ptr [rbp+620h]
    mov qword ptr [rcx], rdi
    mov rcx, qword ptr [qword_7FF8571CFB10]
    mov rdx, rcx
    not rdx
    mov r8, rcx
    mov r11, -6DFA452FF31BE24Fh
    or r8, r11
    lea r9, [r8+r8*4]
    lea r9, [r8+r9*2]
    not r8
    lea r10, [r8*8]
    sub r10, r8
    and rdx, r11
    mov r8, rdx
    shl r8, 4
    add r8, rdx
    mov rdx, rcx
    and rdx, r11
    mov r11, rcx
    mov rsi, 6DFA452FF31BE24Eh
    and r11, rsi
    lea rdi, [r11+r11*8]
    lea r11, [r11+rdi*2]
    lea rdi, [rdx+rdx*2]
    not rdx
    add rdx, rdx
    lea rdx, [rdx+rdx*2]
    lea r11, [r11+rdi*4]
    sub r11, r9
    sub r11, rdx
    add r8, r10
    add r8, r11
    mov rdx, -1B9E243B730DA6B5h
    lea r9, [r8+rdx]
    mov rdx, r9
    not rdx
    mov r10, r9
    mov r11, -21DA47B8C25AC68Ch
    or r10, r11
    mov r11, 5E25B8473DA53974h
    and rdx, r11
    lea rdx, [rdx+rdx*2]
    mov r11, r9
    mov rsi, 1E25B8473DA53974h
    and r11, rsi
    shl r11, 2
    mov rdi, r9
    mov rsi, 21DA47B8C25AC68Bh
    and rdi, rsi
    lea rdi, [rdi+rdi*2]
    sub r11, rdi
    lea rdi, [r9+r9*2]
    add r11, rdi
    lea rdx, [r11+rdx*2]
    mov r11, -34E251AB71DF58B7h
    add r10, r11
    add r10, rdx
    mov rdi, r10
    mov r11, r10
    mov rsi, 61BC83A0D33EE9DDh
    and r10, rsi
    mov rdx, r10
    not rdx
    add rdx, rdx
    sub rdx, r10
    not rdi
    mov r10, 21BC83A0D33EE9DDh
    and rdi, r10
    shl rdi, 2
    sub rdx, rdi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or r11, rsi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rdx, r11
    mov r10, rdx
    sub r10, r8
    mov r8, 2C86D240CBA964B8h
    add rdx, r8
    mov r8, -4EBF070724EDC60Ch
    add rcx, r8
    add rcx, r10
    xor rdx, r9
    xor rdx, rcx
    add rdx, rax
    mov r8, qword ptr [qword_7FF8571CFB18]
    mov rax, 64863E0917643E55h
    add r8, rax
    mov rcx, r8
    not rcx
    mov rax, 111FCCBA0A885DA3h
    and rcx, rax
    mov r9, r8
    mov rax, -2EE03345F577A25Dh
    or r9, rax
    mov r10, -5DC0668BEAEF44B9h
    add r9, r10
    shl rcx, 2
    mov r10, r8
    and r10, rax
    mov rax, r10
    not rax
    add rax, rax
    sub rax, r10
    sub rax, rcx
    add rax, r9
    mov rcx, rax
    mov r9, 3BCCC3463CCC9035h
    xor rcx, r9
    sub rcx, r8
    mov r8, -406EB4DAD0326115h
    add rcx, r8
    mov r8, rax
    not r8
    mov r9, rcx
    or r9, rax
    mov r10, rcx
    and r10, r8
    and rax, rcx
    lea rax, [rax+r10*2]
    mov r10, rcx
    or r10, r8
    xor r8, rcx
    sub rax, rcx
    lea r8, [rax+r8*2]
    not r9
    add r9, r9
    sub r8, r9
    not r10
    add r8, r10
    mov rax, qword ptr [off_7FF8571A2640]
    mov rax, qword ptr [rax+10h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FF8569F142B:
    mov rcx, r12
    call rax
    loc_7FF8569F1430:
    mov qword ptr [rbp+470h], rax
    mov rax, qword ptr [qword_7FF8571CFB20]
    mov rcx, 56DA7A818EA27DB7h
    xor rax, rcx
    mov rcx, 78A55404132D71EFh
    add rcx, rax
    mov rdx, rcx
    mov r8, 14CD36856D2FC608h
    xor rdx, r8
    mov r9, -361A7FFD2F2EABFBh
    sub r9, rax
    mov r8, rcx
    mov r10, -14CD36856D2FC609h
    xor r8, r10
    mov r10, r9
    or r10, r8
    lea r11, [r10+r10*4]
    lea r11, [r10+r11*2]
    not r10
    lea rdi, [r10*8]
    sub rdi, r10
    mov r10, r9
    or r10, rdx
    not r10
    mov rbx, r10
    shl rbx, 4
    add rbx, r10
    add rbx, rdi
    and r8, r9
    and r9, rdx
    lea r10, [r9+r9*8]
    lea r9, [r9+r10*2]
    lea r10, [r8+r8*2]
    lea r9, [r9+r10*4]
    sub r9, r11
    not r8
    add r8, r8
    lea r8, [r8+r8*2]
    sub r9, r8
    add r9, rbx
    sub r9, rcx
    mov rcx, 283393276BA84B2Bh
    add rcx, rdx
    xor rcx, rax
    mov rax, qword ptr [rbp+5C8h]
    xor rcx, r9
    add rcx, qword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rbp+358h], rcx
    mov rax, qword ptr [qword_7FF8571CFB28]
    mov rcx, rax
    mov rdx, 4C2B7C0784A4FFBBh
    xor rcx, rdx
    mov rdx, 54506A32A6DB2DA3h
    add rdx, rcx
    mov r8, -3EBF50AAE307014Fh
    xor rax, r8
    xor rax, rdx
    mov rdx, -40FA7FA7F41E6408h
    add rdx, rcx
    sub rax, rcx
    mov rcx, rdx
    mov r8, -622E2E719F64C087h
    xor rcx, r8
    add rax, rcx
    mov r8, 5FB205CCE7C1CE28h
    add rcx, r8
    sub rax, rdx
    mov r8, 17A9B4087FC6F216h
    add rax, r8
    xor rax, rcx
    mov rcx, 6F079AC646DA4C4h
    xor rdx, rcx
    add rax, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rbp+358h], rax
    jz loc_7FF8569F5427
    mov eax, dword ptr [dword_7FF857242910]
    lea ecx, [rax+7ADC5F13h]
    lea edx, [rax-1F52E93Ch]
    lea r8d, [rax-73F3D6E8h]
    xor r8d, edx
    sub r8d, eax
    add r8d, -1B495718h
    xor r8d, ecx
    sub r8d, eax
    sub r8d, eax
    add eax, r8d
    add eax, 3DB68042h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F17B3:
    cmp eax, 18512FD5h
    jle loc_7FF8569F1A0A
    cmp eax, 1C537A21h
    jle loc_7FF8569F25BF
    cmp eax, 1D42A1CCh
    jle loc_7FF8569F8069
    cmp eax, 1D42A1CDh
    jz loc_7FF856A02096
    cmp eax, 1D848F83h
    jnz loc_7FF8569F9EC3
    jmp loc_7FF8569FDE2C
    loc_7FF8569F17EF:
    cmp eax, 7BAB11ECh
    jle loc_7FF8569F1A8E
    cmp eax, 7E447D2Ch
    jle loc_7FF8569F5179
    cmp eax, 7E447D2Dh
    jz loc_7FF8569FA32E
    cmp eax, 7EC0E57Bh
    jnz loc_7FF8569FC7A4
    mov rdx, qword ptr [rbp+550h]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569F1829:
    mov rcx, r12
    call qword ptr [rax+30h]
    jmp loc_7FF8569F93C3
    loc_7FF8569F1834:
    cmp eax, 40C7610Eh
    jg loc_7FF8569F2FC7
    cmp eax, 3BFCE932h
    jle loc_7FF8569F678D
    cmp eax, 3EA252BCh
    jz loc_7FF8569FC74B
    cmp eax, 40131868h
    jnz loc_7FF856A0832D
    mov rax, qword ptr [rbp+8]
    mov qword ptr [rbp+1C0h], rax
    mov eax, dword ptr [dword_7FF857242AB8]
    lea ecx, [rax-6EA5A410h]
    mov edx, ecx
    xor edx, 1FED9BABh
    add eax, eax
    add eax, edx
    add eax, ecx
    add eax, -7F988BE2h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F1895:
    cmp eax, 64B1F680h
    jg loc_7FF8569F1B8F
    cmp eax, 62CF9F22h
    jg loc_7FF8569F554F
    cmp eax, 620805ECh
    jnz loc_7FF856A053C8
    mov rax, qword ptr [rbp+3B8h]
    jmp loc_7FF856A07751
    loc_7FF8569F18C2:
    cmp eax, 26DFAB0Eh
    jg loc_7FF8569F1BCF
    cmp eax, 2431DE87h
    jg loc_7FF8569F5919
    cmp eax, 1FF46794h
    jnz loc_7FF8569FEE70
    mov rax, qword ptr [rbp+3C8h]
    mov rcx, qword ptr [rax]
    mov rax, qword ptr [rax+10h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rbp+3C8h]
    mov qword ptr [rbp+260h], rax
    mov qword ptr [rbp+258h], rcx
    mov qword ptr [rbp+250h], rdx
    jmp loc_7FF8569F598B
    loc_7FF8569F1950:
    cmp eax, 4588EB63h
    jg loc_7FF8569F1C07
    cmp eax, 43F05323h
    jg loc_7FF8569F5DEF
    cmp eax, 423C3FECh
    jnz loc_7FF856A0137C
    mov rsi, r12
    mov rax, qword ptr [rbp+458h]
    jmp loc_7FF856A053E9
    loc_7FF8569F1980:
    cmp eax, 542353BCh
    jg loc_7FF8569F1C22
    cmp eax, 52EB5EB3h
    jg loc_7FF8569F64BD
    cmp eax, 512CF101h
    jnz loc_7FF856A01388
    mov rdx, qword ptr [rbp+110h]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569F19AF:
    mov rcx, r12
    call qword ptr [rax+30h]
    loc_7FF8569F19B5:
    jmp loc_7FF8569F84A7
    loc_7FF8569F19BA:
    cmp eax, 5E13549h
    jg loc_7FF8569F2FE2
    cmp eax, 22DF2D0h
    jg loc_7FF8569F8421
    cmp eax, 11A0881h
    jnz loc_7FF856A04F5B
    cmp byte ptr [rbp+638h], 0
    jnz loc_7FF8569F46F6
    mov rcx, qword ptr [rbp+3E0h]
    mov rdx, qword ptr [rbp+3E8h]
    add rdx, rcx
    mov r8, qword ptr [rbp+5A8h]
    call memcpy
    jmp loc_7FF8569F46F6
    loc_7FF8569F1A0A:
    cmp eax, 15D5FFA2h
    jg loc_7FF8569F3093
    cmp eax, 12DFC7CAh
    jg loc_7FF8569F89DA
    cmp eax, 12A3BD5Fh
    jnz loc_7FF8569F94C9
    mov rax, qword ptr [rbp+5E0h]
    mov rcx, qword ptr [rbp+538h]
    jmp loc_7FF856A001EE
    loc_7FF8569F1A3E:
    cmp eax, 709608EBh
    jg loc_7FF8569F340F
    cmp eax, 6FB5D126h
    jnz loc_7FF8569FA4DD
    lea rax, [rbp-50h]
    cmp qword ptr [rbp+3F0h], rax
    jz loc_7FF856A07F2E
    mov eax, dword ptr [dword_7FF857242994]
    mov ecx, eax
    xor ecx, -49D359E2h
    lea edx, [rcx+5FBFED6Dh]
    xor edx, -7ED150A0h
    sub ecx, eax
    lea eax, [rcx+rdx]
    add eax, 72321BE8h
    jmp loc_7FF856A082DD
    loc_7FF8569F1A8E:
    cmp eax, 79C49983h
    jg loc_7FF8569F3452
    cmp eax, 7859A185h
    jnz loc_7FF8569FA4E9
    movzx eax, byte ptr [rbp+639h]
    jmp loc_7FF856A0633F
    loc_7FF8569F1AB0:
    cmp eax, 68619D60h
    jg loc_7FF8569F34B2
    cmp eax, 67DD0A65h
    jnz loc_7FF8569FB8ED
    mov rdx, qword ptr [rbp+490h]
    mov r8, qword ptr [rbp+598h]
    mov rcx, qword ptr [rbp+3A8h]
    call memcpy
    jmp loc_7FF856A07ADC
    loc_7FF8569F1AE5:
    cmp eax, 2A672FADh
    jg loc_7FF8569F46D4
    cmp eax, 28F25B96h
    jnz loc_7FF8569FBEDA
    cmp byte ptr [rbp+637h], 0
    jnz loc_7FF856A008D9
    mov eax, dword ptr [dword_7FF857242A68]
    mov ecx, eax
    xor ecx, 5645D0F8h
    lea edx, [rcx-47D950EAh]
    lea r8d, [rcx-51057D69h]
    lea r9d, [rcx-0A99790Ah]
    xor r9d, edx
    xor r9d, r8d
    xor r9d, 3BC1B9FEh
    add r9d, eax
    lea eax, [rcx+r9]
    add eax, -73B6662Dh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F1B4E:
    cmp eax, 48AD8700h
    jg loc_7FF8569F5206
    cmp eax, 48240CC3h
    jnz loc_7FF856A0810E
    mov rax, qword ptr [rbp+78h]
    jmp loc_7FF8569FE9C7
    loc_7FF8569F1B6D:
    cmp eax, 5BCB9ACBh
    jg loc_7FF8569F5379
    cmp eax, 5733D743h
    jnz loc_7FF8569FCE3D
    mov rax, qword ptr [rbp+398h]
    jmp loc_7FF856A074F9
    loc_7FF8569F1B8F:
    cmp eax, 66178170h
    jg loc_7FF8569F58EF
    cmp eax, 64B1F681h
    jz loc_7FF856A07ADC
    mov rdx, qword ptr [rbp+4E8h]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569F1BB3:
    mov rcx, r12
    call qword ptr [rax+30h]
    loc_7FF8569F1BB9:
    mov rax, qword ptr [rbp+620h]
    mov rax, qword ptr [rax]
    mov qword ptr [rbp+198h], rax
    jmp loc_7FF8569F661B
    loc_7FF8569F1BCF:
    cmp eax, 27FE8601h
    jg loc_7FF8569F5958
    cmp eax, 26DFAB0Fh
    jnz loc_7FF856A009C6
    mov rcx, qword ptr [rbp+388h]
    mov rdx, qword ptr [rbp+390h]
    add rdx, rcx
    mov r8, qword ptr [rbp+600h]
    call memcpy
    jmp loc_7FF8569F7E8E
    loc_7FF8569F1C07:
    cmp eax, 47AC7F8Fh
    jg loc_7FF8569F65B0
    cmp eax, 4588EB64h
    jnz loc_7FF8569FEE8D
    jmp loc_7FF856A07CA7
    loc_7FF8569F1C22:
    cmp eax, 5501063Fh
    jg loc_7FF8569F65C7
    cmp eax, 542353BDh
    jz loc_7FF856A06505
    mov rdx, qword ptr [rbp+5E0h]
    cmp rdx, 17h
    mov eax, 16h
    cmovb rdx, rax
    loc_7FF8569F1C4C:
    mov rax, rdx
    mov rcx, -8000000000000000h
    or rax, rcx
    mov rcx, qword ptr [rbp+628h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [qword_7FF8571CF900]
    mov rcx, 19F44D6F403F104Ah
    lea r14, [rax+rcx]
    mov r9, r14
    mov rcx, -6F84547C7D20BC12h
    xor r9, rcx
    mov rcx, 3740DF603A7BA2D4h
    add rcx, r9
    mov r8, -21AD1F68E377699h
    xor r14, r8
    add r14, r9
    mov r8, -3A9ED082E757E2E1h
    add r9, r8
    mov r11, r9
    not r11
    mov r8, r14
    or r8, r11
    mov r10, r14
    or r10, r9
    mov rdi, r14
    xor rdi, r9
    and r11, r14
    and r9, r14
    mov rbx, rdi
    shl r11, 3
    add r9, r9
    sub r11, r9
    lea r9, [rdi*8]
    sub rdi, r9
    add rdi, r11
    not r8
    not r10
    shl r10, 2
    not rbx
    lea r9, [rdi+rbx*4]
    sub r9, r10
    lea r8, [r9+r8*8]
    mov r9, r8
    or r9, rcx
    not rcx
    mov r10, r8
    and r8, rcx
    mov r11, r8
    not r11
    add r11, r11
    sub r11, r8
    not r9
    shl r9, 2
    sub r11, r9
    or r10, rcx
    add r11, r10
    lea r8, [r11+rcx*2]
    inc rdx
    sub r8, rax
    mov rax, qword ptr [off_7FF8571A2640]
    mov rax, qword ptr [rax+10h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, -3F8A506E400717AFh
    add r8, rcx
    loc_7FF8569F2010:
    mov rcx, r12
    call rax
    mov qword ptr [rbp+420h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+608h]
    mov rax, qword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [qword_7FF8571CF908]
    mov rdx, rcx
    not rdx
    mov r8, rdx
    mov r9, 72DD09CCE99F296Eh
    and r8, r9
    add r8, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r9, [rdx+rdx]
    mov r10, -1A45EC662CC1AD24h
    or r9, r10
    mov r10, rcx
    mov r11, -72DD09CCE99F296Fh
    xor r10, r11
    sub r9, r10
    sub r9, r8
    mov r10, r9
    mov r8, 432C6A370A0CDD2Fh
    xor r10, r8
    mov r8, 58F49409525C556Ch
    add r10, r8
    mov r8, -0D2C68EC29F79B25h
    xor r10, r8
    mov r11, r10
    or r11, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add r11, r11
    mov r8, r10
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add r8, r8
    xor r10, r9
    sub r8, r10
    sub r8, r11
    lea r9, [rdx+rdx*4]
    mov r10, r8
    or r10, rdx
    not r10
    lea r10, [r10+r10*2]
    mov r11, r8
    or r11, rcx
    not r11
    lea r11, [r11+r11*4]
    xor rcx, r8
    add rcx, rcx
    and r8, rdx
    shl r8, 3
    sub r8, rcx
    add r8, r11
    add r8, r10
    sub r8, r9
    add r8, rax
    mov qword ptr [rbp-18h], r8
    jz loc_7FF856A07FDF
    mov eax, dword ptr [dword_7FF857242B24]
    mov ecx, eax
    xor ecx, -64816DE9h
    sub ecx, eax
    add ecx, -69E7B13Eh
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF8569F2354:
    cmp eax, 33D9A30Fh
    jg loc_7FF8569F6610
    cmp eax, 3230A374h
    jnz loc_7FF856A0725D
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+580h]
    mov rdx, rax
    not rdx
    lea rcx, [rdx+rdx*2]
    mov r8d, edx
    and r8d, 2
    lea r8, [r8+r8*2]
    and rdx, -3
    lea rdx, [rdx+rdx*2]
    mov r9, rax
    xor r9, 2
    lea r10, [r9*8]
    sub r10, r9
    add r10, rdx
    mov rdx, rax
    mov r9, 7FFFFFFFFFFFFFFDh
    and rdx, r9
    add rdx, rdx
    lea rdx, [rdx+rdx*2]
    and eax, 2
    add rax, rax
    sub rax, rdx
    add rax, r10
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
    cmp rax, qword ptr [rbp+528h]
    jbe loc_7FF856A06233
    mov rax, qword ptr [rbp+530h]
    mov rcx, qword ptr [rbp+528h]
    jmp loc_7FF856A07C99
    loc_7FF8569F259D:
    cmp eax, 0AA907E8h
    jg loc_7FF8569F67D8
    cmp eax, 87A16AFh
    jz loc_7FF8569FEFF3
    mov rax, qword ptr [rbp+4C0h]
    jmp loc_7FF856A02ED5
    loc_7FF8569F25BF:
    cmp eax, 1B1D5B8Eh
    jg loc_7FF8569F67F3
    cmp eax, 18512FD6h
    jnz loc_7FF856A0287F
    mov rdx, qword ptr [rbp+5E8h]
    cmp rdx, 17h
    mov eax, 16h
    cmovb rdx, rax
    loc_7FF8569F25E9:
    mov rax, qword ptr [qword_7FF8571CF978]
    mov rcx, -281B1E510ED3D57h
    add rax, rcx
    mov rcx, rax
    not rcx
    lea r8, [rcx+rcx*2]
    mov r9, rcx
    mov rdi, -3EDEC514ED4DDE11h
    and r9, rdi
    lea r9, [r9+r9*2]
    mov rbx, 3EDEC514ED4DDE10h
    and rcx, rbx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r10, [rcx+rcx*2]
    mov r11, rax
    xor r11, rdi
    lea rcx, [r11*8]
    sub rcx, r11
    mov r11, rax
    and r11, rbx
    add r11, r11
    lea r11, [r11+r11*2]
    mov rdi, rax
    mov rbx, 41213AEB12B221EFh
    and rdi, rbx
    add rdi, rdi
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rcx, r10
    add rcx, rdi
    sub rcx, r9
    sub rcx, r8
    mov r8, 49C4D9B6A4D313E2h
    add r8, rcx
    mov r9, r8
    mov r10, -0E26542DCED6E1DFh
    xor r9, r10
    mov r10, r8
    mov r11, 4880CBE2931B8DC0h
    xor r10, r11
    mov r11, r8
    mov rdi, 7C08CF07CFD5CA65h
    xor r11, rdi
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
    mov r10, -68E886CB99429209h
    xor r8, r10
    xor r8, r11
    add r9, rax
    add r9, rcx
    add r9, r8
    or r9, rdx
    mov rax, qword ptr [rbp+5D0h]
    mov qword ptr [rax], r9
    mov r8, qword ptr [qword_7FF8571CF980]
    mov rcx, r8
    mov rax, 2AEE4CAD7901596Fh
    xor rcx, rax
    mov rax, -4E1598979827E71Bh
    lea r9, [rcx+rax]
    mov rax, r9
    mov r10, r9
    not r10
    mov r11, r10
    mov rdi, r10
    mov rbx, r9
    mov r14, 795BBBED43037C9Bh
    and r10, r14
    and r9, r14
    sub r9, r10
    xor rbx, r14
    lea r10, [rbx+rbx*2]
    add r9, r10
    mov r10, -701E4420D8598CA2h
    xor rax, r10
    or r11, r14
    sub r9, r11
    not r11
    shl r11, 2
    mov r10, -795BBBED43037C9Ch
    and rdi, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9, rdi
    sub r9, r11
    add rax, rcx
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
    sub rax, r8
    sub rax, rcx
    mov rcx, -32AEBC51755BD196h
    add rdx, rcx
    add rdx, rax
    mov rcx, qword ptr [qword_7FF8571CF988]
    mov r8, rcx
    not r8
    mov rax, r8
    mov rdi, -4D126A8DA0F2FBCAh
    and rax, rdi
    lea r9, [rax+rax*4]
    lea r9, [rax+r9*2]
    mov rax, rcx
    or rax, rdi
    lea r10, [rax+rax*4]
    lea r10, [rax+r10*2]
    mov rax, rcx
    mov r11, 4D126A8DA0F2FBC9h
    and rax, r11
    lea r11, [rax+rax*8]
    mov rax, rcx
    and rax, rdi
    imul rax, 0F5h
    sub rax, r11
    mov r11, rcx
    xor r11, rdi
    sub rax, r11
    add rax, r10
    sub rax, r9
    mov r9, 6C773CC2CF3829C3h
    lea r10, [rax+r9]
    mov r9, r10
    not r9
    mov r11, r9
    mov rdi, 547A787A4C03F3ACh
    and r11, rdi
    add r11, r11
    add r9, r9
    mov rdi, -570B0F0B67F818A8h
    or r9, rdi
    mov rdi, 2B858785B3FC0C53h
    xor r10, rdi
    sub r9, r10
    sub r9, r11
    sub r9, rax
    mov r10, r9
    mov r11, r9
    or r11, r8
    or rcx, r9
    and r9, r8
    mov r8, -379202D9E651E437h
    add r8, rax
    not r10
    add r10, r10
    not r11
    not rcx
    lea r9, [r9+rcx*2]
    add r9, r11
    sub r9, r10
    mov r10, r8
    not r10
    mov rcx, r9
    or rcx, r10
    mov r11, r9
    or r11, r8
    and r10, r9
    and r9, r8
    mov r8, r10
    add r10, r10
    lea r9, [r10+r9*2]
    not r8
    sub r8, r9
    not r11
    shl r11, 2
    sub r8, r11
    not rcx
    lea rcx, [rcx+rcx*2]
    sub r8, rcx
    mov rcx, 7E8126B9C97F0576h
    add rax, rcx
    add r8, -3
    xor r8, rax
    mov rax, qword ptr [off_7FF8571A2640]
    mov rax, qword ptr [rax+10h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FF8569F2C6B:
    mov rcx, r12
    call rax
    loc_7FF8569F2C70:
    mov qword ptr [rbp+428h], rax
    mov rax, qword ptr [rbp+460h]
    mov rcx, qword ptr [rax]
    mov r8, rcx
    not r8
    lea rax, [r8*8]
    sub rax, r8
    mov edx, r8d
    and edx, 1
    lea rdx, [rdx+rdx*8]
    mov r11, 7FFFFFFFFFFFFFFEh
    and r8, r11
    add r8, r8
    lea r9, [r8+r8*4]
    mov r10d, ecx
    and r10d, 1
    mov r8d, r10d
    not r10
    lea r10, [r10+r10*2]
    and rcx, r11
    add rcx, rcx
    add r8, r8
    sub r8, rcx
    add r8, r10
    sub r8, r9
    sub r8, rdx
    add r8, rax
    jz loc_7FF856A0801D
    mov rdx, qword ptr [rbp+110h]
    mov rcx, qword ptr [rbp+428h]
    call memcpy
    loc_7FF8569F2CF2:
    mov rax, qword ptr [qword_7FF8571CF990]
    mov rcx, rax
    mov rdx, 17F23FA2DC187A8h
    xor rcx, rdx
    mov rdx, rax
    mov r8, 1600080550025057h
    xor rdx, r8
    mov r11, 16472A55558251F7h
    and rdx, r11
    lea rdx, [rdx+rdx*2]
    lea r8, [rcx+rcx]
    mov r9, 2C8E54AAAB04A3EEh
    or r8, r9
    lea r8, [r8+r8*2]
    mov r9, rax
    mov r10, -173809AF7843D660h
    xor r9, r10
    mov r10, rcx
    and r10, r11
    lea r10, [r10+r10*2]
    add r10, r10
    mov r11, 69B8D5AAAA7DAE08h
    and rcx, r11
    lea rcx, [rcx+rcx*2]
    lea rcx, [r10+rcx*2]
    add rcx, r9
    sub rcx, r8
    lea rcx, [rcx+rdx*2]
    mov rdx, rax
    mov r8, 2169604451117AC0h
    xor rdx, r8
    mov r8, -508AF5EF11283DEBh
    add rdx, r8
    add rdx, rcx
    mov r8, rax
    not r8
    mov r9, rdx
    or r9, r8
    mov r10, rdx
    or r10, rax
    not r10
    and r8, rdx
    lea r8, [r8+r10*2]
    not r9
    add r8, r9
    not rdx
    add rdx, rdx
    sub r8, rdx
    mov rdx, -3FC206347F2432A1h
    xor rax, rdx
    xor rax, r8
    sub rax, rcx
    mov rcx, qword ptr [rbp+5D0h]
    mov rcx, qword ptr [rcx]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp rcx, rax
    jle loc_7FF856A0533E
    mov eax, dword ptr [dword_7FF8572429A0]
    lea ecx, [rax+3C7AE7B2h]
    xor ecx, -50C7FA42h
    add ecx, 1299EEE2h
    xor ecx, -164B5609h
    add ecx, eax
    add eax, ecx
    add eax, 3C7AE7B2h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F2FC7:
    cmp eax, 41D9F0FEh
    jg loc_7FF8569F6A31
    cmp eax, 40C7610Fh
    jz loc_7FF8569F522B
    jmp loc_7FF856A025C3
    loc_7FF8569F2FE2:
    cmp eax, 738CE7Ah
    jg loc_7FF8569F9027
    cmp eax, 5E1354Ah
    jz loc_7FF8569F54A6
    mov rdx, qword ptr [rbp+160h]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569F3006:
    mov rcx, r12
    call qword ptr [rax+30h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+5C0h]
    mov rax, qword ptr [rax]
    jmp loc_7FF8569F9740
    loc_7FF8569F3093:
    cmp eax, 1740BAC3h
    jg loc_7FF8569F91C3
    cmp eax, 15D5FFA3h
    jnz loc_7FF8569F994A
    mov rcx, qword ptr [qword_7FF8571CFA18]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, rcx
    mov rdx, -7DA206F12588FD1Fh
    xor rax, rdx
    mov rdx, 73C7A34703929278h
    lea r8, [rax+rdx]
    mov r9, r8
    not r9
    mov rdx, r8
    mov rdi, 0EA7EBECF5EDE3B3h
    and rdx, rdi
    lea rdx, [rdx+rdx*8]
    mov r10, r9
    and r10, rdi
    lea r10, [r10+r10*4]
    mov r11, -0EA7EBECF5EDE3B4h
    and r9, r11
    and r8, r11
    lea r11, [r8+r8*4]
    lea r8, [r8+r11*2]
    add r8, r9
    not r9
    lea r11, [r9+r9*4]
    lea r9, [r9+r11*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r8, r9
    lea r8, [r8+r10*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add rdx, rdi
    add rdx, r8
    mov r8, 7DA206F12588FD1Eh
    xor rcx, r8
    mov r8, rdx
    or r8, rcx
    not r8
    mov r9, rdx
    or r9, rax
    not r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and rax, rdx
    and rcx, rdx
    add rcx, rcx
    lea rcx, [rcx+rax*2]
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
    add rax, r9
    add rax, rcx
    lea rax, [rax+r8*2]
    add rax, 2
    cmp qword ptr [rbp+5F8h], rax
    jnz loc_7FF856A070D8
    mov eax, dword ptr [dword_7FF857242AE4]
    lea ecx, [rax+40D45962h]
    mov edx, ecx
    xor edx, -7A80656Ch
    xor ecx, -5CDFE7EAh
    add ecx, eax
    lea eax, [rdx+rcx]
    add eax, -2E197824h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F340F:
    cmp eax, 709608ECh
    jnz loc_7FF8569F46F6
    mov eax, dword ptr [dword_7FF857242AEC]
    mov ecx, eax
    xor ecx, -7C82DE57h
    lea edx, [rcx+16458DC4h]
    xor edx, 1D502859h
    xor eax, -359ABE00h
    sub eax, edx
    xor eax, -65ADDCECh
    sub eax, ecx
    add eax, -3F7B585Fh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F3452:
    cmp eax, 79C49984h
    jz loc_7FF856A07ADC
    cmp byte ptr [rbp+636h], 0
    jnz loc_7FF8569FEE8D
    mov eax, dword ptr [dword_7FF857242AD8]
    lea ecx, [rax+3F5DBD9Ah]
    xor ecx, -35ACE256h
    lea edx, [rcx-3734D297h]
    mov r8d, eax
    sub r8d, ecx
    add r8d, eax
    add r8d, 87F551Eh
    xor edx, ecx
    xor edx, r8d
    lea ecx, [rdx+rax]
    add ecx, 3F5DBD9Ah
    add eax, ecx
    add eax, 5FC48AD6h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F34B2:
    cmp eax, 68619D61h
    jnz loc_7FF8569FB984
    mov rax, qword ptr [rbp+0C0h]
    mov qword ptr [rbp], rax
    mov rcx, qword ptr [rbp+550h]
    sub rax, rcx
    mov qword ptr [rbp+330h], rax
    mov rax, qword ptr [rbp+628h]
    mov rax, qword ptr [rax]
    mov rdx, rax
    and rdx, r13
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rbp+5F8h], rdx
    jbe loc_7FF856A05FF3
    mov r8d, dword ptr [dword_7FF8571CFA20]
    lea r9d, [r8+0F7B546Bh]
    mov ecx, r9d
    xor ecx, -67549BAAh
    mov r10d, r9d
    xor r10d, 67549BA9h
    lea r14d, [r10*8]
    sub r14d, r10d
    mov r11d, r10d
    and r11d, -57068DDEh
    mov rsi, r12
    lea r12d, [r11+r11*8]
    mov r11d, ecx
    and r11d, -57068DDEh
    mov edi, r11d
    mov ebx, ecx
    and ebx, 57068DDDh
    add ebx, ebx
    add r11d, r11d
    sub r11d, ebx
    mov ebx, r10d
    and ebx, 57068DDDh
    add ebx, ebx
    lea ebx, [rbx+rbx*4]
    not edi
    lea edi, [rdi+rdi*2]
    add r11d, edi
    sub r11d, ebx
    sub r11d, r12d
    add r11d, r14d
    mov edi, r11d
    not edi
    mov r14d, edi
    lea ebx, [rdi+rdi]
    mov r12d, r11d
    and edi, 5176D64Eh
    lea edi, [rdi+rdi*2]
    add edi, edi
    and r11d, 5176D64Eh
    lea r11d, [r11+r11*2]
    lea r11d, [rdi+r11*2]
    xor r12d, 5176D64Eh
    add r11d, r12d
    and r14d, 2E8929B1h
    lea edi, [r14+r14*2]
    or ebx, -5D125364h
    lea ebx, [rbx+rbx*2]
    sub r11d, ebx
    lea r12d, [r11+rdi*2]
    sub r12d, r8d
    add r12d, -11454FD9h
    mov r11d, r12d
    or r11d, r10d
    mov r14d, r12d
    or r14d, ecx
    and r10d, r12d
    and r12d, ecx
    mov ecx, r10d
    add r10d, r10d
    lea r10d, [r12]
    mov r12, rsi
    not ecx
    sub ecx, r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not r11d
    lea r10d, [r11+r11*2]
    not r14d
    shl r14d, 2
    sub ecx, r14d
    sub ecx, r10d
    sub ecx, r9d
    add ecx, -3
    xor ecx, r8d
    mov r8, rdx
    shr r8, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8, rdx
    mov rcx, qword ptr [rbp+5F8h]
    cmp r8, rcx
    cmovbe r8, rcx
    loc_7FF8569F382E:
    mov rcx, qword ptr [qword_7FF8571CFA28]
    mov rdx, rcx
    mov r9, -7368B8EF97C7003Bh
    xor rdx, r9
    mov r9, -65F3653748987374h
    add rdx, r9
    mov r9, rdx
    mov r10, 74488D9739C7CB89h
    xor r9, r10
    mov r10, 1DAC4ECB4F5E714Eh
    xor rdx, r10
    add rdx, r9
    mov r9, rdx
    or r9, rcx
    lea r10, [r9+r9*2]
    not r9
    lea r11, [r9*8]
    sub r11, r9
    mov r9, rcx
    and rdx, rcx
    lea rdx, [rdx+r10*2]
    mov r10, rcx
    mov rsi, 7ADDDB85217178EDh
    xor rcx, rsi
    mov rsi, -5E6CCB3D810EF4E2h
    xor r9, rsi
    mov rsi, 2A558CA826C4B6C3h
    xor r10, rsi
    add rdx, r10
    add rdx, r11
    sub rcx, rdx
    add rcx, r9
    add rcx, -7
    mov rdx, rcx
    not rdx
    or rdx, r8
    not rdx
    lea r9, [rdx+rdx*4]
    lea rdx, [rdx+r9*2]
    lea r9, [r8+r8*4]
    lea r9, [r8+r9*2]
    mov r10, r8
    or r10, rcx
    lea r11, [r10+r10*4]
    lea r10, [r10+r11*2]
    and rcx, r8
    sub rcx, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rcx, r9
    add rcx, rdx
    mov rdx, -8000000000000000h
    and rax, rdx
    or rax, rcx
    mov rcx, qword ptr [rbp+628h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [qword_7FF8571CFA30]
    mov rcx, -4351AE884BD41769h
    lea rdx, [rax+rcx]
    mov rcx, -6728C20E1B45CD3h
    add rcx, rax
    xor rcx, rax
    sub rcx, rdx
    mov rax, -790BC6798583DEEh
    xor rdx, rax
    xor rdx, rcx
    add rdx, r8
    mov rax, qword ptr [qword_7FF8571CFA38]
    mov rcx, -56121DC85E64574Dh
    lea r8, [rax+rcx]
    mov r9, r8
    not r9
    mov rcx, 0E411ACE6855D181h
    and r9, rcx
    mov rcx, r8
    mov r10, -71BEE53197AA2E7Fh
    and rcx, r10
    add r9, r9
    mov r10, r8
    mov r11, 71BEE53197AA2E7Eh
    and r10, r11
    sub r9, r10
    add rcx, rax
    add rcx, r9
    mov r9, r8
    lea r10, [r8+r8]
    mov r11, r8
    mov rsi, 632CAFDE2A19FBD5h
    and r11, rsi
    mov rsi, -632CAFDE2A19FBD6h
    and r8, rsi
    lea r8, [r8+r8*2]
    lea r8, [r8+r11*2]
    or r9, rsi
    sub r8, r10
    add r8, r9
    mov r9, r8
    mov r10, 6890776E4CF28F0h
    and r9, r10
    mov r10, r8
    mov r11, 3976F8891B30D70Fh
    and r10, r11
    lea r10, [r10+r10*2]
    lea r9, [r10+r9*4]
    mov r10, r8
    or r10, r11
    lea r10, [r10+r10*4]
    sub r10, r9
    mov r9, r8
    not r9
    and r9, r11
    shl r9, 2
    sub r10, r9
    add r8, rcx
    mov rcx, -10ECAC2B420E97E0h
    add rax, rcx
    mov rcx, -72EDF1123661AE1Eh
    add r10, rcx
    mov rcx, 7F252CDB1F726EACh
    add r8, rcx
    add r8, r10
    xor r8, rax
    mov rax, -4847718107E0BDB5h
    xor r10, rax
    sub r8, r10
    mov rax, qword ptr [off_7FF8571A2640]
    mov rax, qword ptr [rax+10h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FF8569F3DC8:
    mov rcx, r12
    call rax
    loc_7FF8569F3DCD:
    mov qword ptr [rbp+440h], rax
    mov rcx, qword ptr [qword_7FF8571CFA40]
    mov rax, rcx
    mov rdx, 1E4142E85AA93661h
    xor rax, rdx
    mov rdx, rcx
    mov r8, 601C85132550411Ch
    xor rdx, r8
    mov r11, 6C5C85133758535Ch
    and rdx, r11
    lea r8, [rdx*8]
    sub r8, rdx
    mov rdx, -6C5C85133758535Ch
    add r8, rdx
    mov rdx, rcx
    mov r9, 721DC7FB6DF1653Dh
    xor rdx, r9
    lea r9, [rdx+rdx*4]
    mov rdx, rax
    mov r10, 13A37AECC8A7ACA3h
    and rdx, r10
    lea rdx, [rdx+rdx*2]
    mov r10, rax
    and r10, r11
    lea rdx, [r10+rdx*2]
    sub rdx, r9
    add rdx, r8
    mov r8, rdx
    not r8
    lea r9, [r8+r8*2]
    mov r10, r8
    mov rbx, 2F4070E1D747F6A8h
    and r8, rbx
    lea r8, [r8+r8*2]
    mov r11, rdx
    mov rsi, -2F4070E1D747F6A9h
    xor r11, rsi
    lea rdi, [r11*8]
    sub rdi, r11
    add rdi, r8
    mov r8, rdx
    and r8, rbx
    add r8, r8
    lea r11, [r8+r8*2]
    mov r8, rdx
    mov rbx, 50BF8F1E28B80957h
    and r8, rbx
    add r8, r8
    sub r8, r11
    and r10, rsi
    lea r10, [r10+r10*2]
    add r8, rdi
    sub r8, r10
    sub r8, r9
    mov r9, -5E74B4BFF210CF5Dh
    add r9, r8
    mov r10, r9
    mov r11, 1584190E0027D69Dh
    and r10, r11
    mov r11, r9
    mov rsi, -1584190E0027D69Eh
    and r11, rsi
    lea r11, [r11+r11*2]
    lea r10, [r11+r10*4]
    mov r11, r9
    or r11, rsi
    lea r11, [r11+r11*4]
    sub r11, r10
    mov r10, r9
    not r10
    mov rsi, 2A7BE6F1FFD82962h
    and r10, rsi
    shl r10, 2
    sub r11, r10
    mov r10, qword ptr [rbp+608h]
    mov rsi, 2B08321C004FAD3Ch
    add r11, rsi
    mov rsi, -250C7A401A0B97F6h
    xor r9, rsi
    add r9, rdx
    add r9, r11
    xor r9, rcx
    add r9, rax
    sub r9, r11
    add r9, r8
    add r9, qword ptr [r10]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, -5279AEA5D09ABA18h
    add r9, rax
    mov qword ptr [rbp+320h], r9
    mov rcx, qword ptr [qword_7FF8571CFA48]
    mov rdx, rcx
    mov rax, 35462DD2807844E5h
    xor rdx, rax
    mov rax, -2CFFEB93058EBF3Ah
    lea r8, [rdx+rax]
    mov rax, r8
    not rax
    mov r9, rax
    mov rsi, 3C3A4840D625A3A1h
    and r9, rsi
    lea r10, [r9+r9*4]
    lea r9, [r9+r10*2]
    mov r10, r8
    or r10, rsi
    mov r11, r8
    mov rdi, -3C3A4840D625A3A2h
    and r11, rdi
    add r11, r10
    and r8, rsi
    imul r8, 0F5h
    add r8, r11
    sub r8, r9
    mov r9, -697EE536CC61F814h
    add rax, r9
    add rax, r8
    mov r8, 300F99C534A3B72Eh
    sub r8, rdx
    xor r8, rcx
    mov rcx, rax
    not rcx
    mov rdx, r8
    or rdx, rcx
    mov r9, r8
    and rcx, r8
    and r8, rax
    lea r8, [r8+r8*8]
    lea rcx, [r8+rcx*4]
    or r9, rax
    lea r8, [r9+r9*2]
    sub rcx, r8
    add rax, rax
    lea rax, [rax+rax*2]
    sub rcx, rax
    not rdx
    lea rax, [rdx+rdx*4]
    lea rax, [rcx+rax*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rbp+320h], rax
    jnz loc_7FF856A080B0
    mov eax, dword ptr [dword_7FF857242ADC]
    mov ecx, eax
    xor ecx, -6162AF2Eh
    lea edx, [rcx-57EB1F6Ch]
    add eax, 75F46BACh
    xor eax, edx
    xor eax, -11B4FB59h
    sub eax, edx
    sub eax, ecx
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F46D4:
    cmp eax, 2A672FAEh
    jnz loc_7FF8569FC6CC
    mov r8, qword ptr [rbp+5A8h]
    mov rdx, qword ptr [rbp+70h]
    mov rcx, qword ptr [rbp+3E0h]
    call memcpy
    loc_7FF8569F46F6:
    mov rax, qword ptr [rbp+578h]
    mov rax, qword ptr [rax]
    mov rcx, qword ptr [rbp+5A8h]
    movzx r9d, byte ptr [byte_7FF8571CFCC8]
    mov edx, r9d
    xor dl, 9Bh
    lea r8d, [rdx-2Ah]
    mov r14d, r8d
    xor r14b, 0D7h
    mov r10d, r8d
    xor r10b, 28h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11d, r14d
    and r11b, 11h
    shl r11b, 3
    mov r12d, r10d
    and r12b, 31h
    shl r12b, 2
    mov ebx, r8d
    xor bl, 0D9h
    movzx edi, bl
    mov ebx, r8d
    xor bl, 26h
    shl bl, 2
    lea r13d, [rdi*8]
    sub r13d, edi
    and r10b, 0Eh
    shl r10b, 3
    and r14b, 0Eh
    add r14b, r14b
    sub r10b, r14b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r10b, r13b
    lea rdi, off_7FF8571A2640
    mov r13, 7FFFFFFFFFFFFFFFh
    add r10b, bl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r10b, r12b
    mov r12, rdi
    add r10b, r11b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11d, r10d
    or r11b, r9b
    not r11b
    add r11b, r11b
    mov ebx, r10d
    and bl, r9b
    not bl
    add bl, bl
    xor r10b, r9b
    sub bl, r10b
    sub bl, r11b
    sub bl, r8b
    sub bl, dl
    mov byte ptr [rax+rcx], bl
    mov rax, qword ptr [rbp+5A8h]
    mov rcx, qword ptr [rbp+68h]
    mov qword ptr [rcx], rax
    jmp loc_7FF8569F906E
    loc_7FF8569F495F:
    cmp eax, 73748829h
    jz loc_7FF8569FA506
    mov rcx, qword ptr [rbp+160h]
    mov qword ptr [rbp+40h], rcx
    mov rax, qword ptr [rbp+550h]
    mov rdx, rax
    not rdx
    lea r8, [rdx+rdx]
    lea r8, [r8+r8*2]
    mov r9, rcx
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
    mov r10, rcx
    or r10, rax
    not r10
    lea r10, [r10+r10*2]
    lea r11, [rcx+rcx*2]
    and rdx, rcx
    shl rdx, 2
    and rcx, rax
    lea rcx, [rcx+rcx*2]
    sub rdx, rcx
    add rdx, r11
    lea rcx, [rdx+r10*2]
    add rcx, r9
    sub rcx, r8
    inc rcx
    mov qword ptr [rbp+390h], rcx
    mov rcx, qword ptr [rbp+628h]
    mov rcx, qword ptr [rcx]
    mov rdx, rcx
    and rdx, r13
    cmp qword ptr [rbp+600h], rdx
    jbe loc_7FF856A060B4
    mov rax, rdx
    shr rax, 1
    add rax, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rbp+600h]
    cmp rax, rdx
    cmovbe rax, rdx
    loc_7FF8569F4AB2:
    mov rdx, rax
    and rdx, r13
    mov r8, qword ptr [qword_7FF8571CFB80]
    mov r9, -46F861D4CD265693h
    add r8, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9, r8
    mov r10, 24DB6E00474D823Dh
    xor r9, r10
    mov r10, -24DB6E00474D823Eh
    xor r8, r10
    mov r10, r9
    mov r11, -6C59E12B4DE0E856h
    and r10, r11
    lea r10, [r10+r10*2]
    mov r11, r8
    mov rsi, 13A61ED4B21F17AAh
    and r11, rsi
    add r11, r11
    mov rsi, 6C59E12B4DE0E855h
    and r8, rsi
    lea rdi, [r8+r8*2]
    not r8
    add r8, r8
    and r9, rsi
    mov rbx, r9
    not rbx
    add r9, r9
    sub r9, rdi
    lea r9, [r9+rbx*4]
    sub r9, r8
    sub r9, r11
    sub r9, r10
    and rcx, r9
    or rcx, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rbp+628h]
    mov qword ptr [rdx], rcx
    mov rcx, qword ptr [qword_7FF8571CFB88]
    mov rdx, -14DBB1FF546737F8h
    lea r8, [rcx+rdx]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, -7E76BBCD0496681Ch
    add rdx, rcx
    xor rdx, r8
    sub rdx, rcx
    sub rdx, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, 1353310E5A3DFB95h
    add rdx, rcx
    add rdx, rax
    mov rax, qword ptr [off_7FF8571A2640]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9, qword ptr [qword_7FF8571CFB90]
    mov r8, r9
    not r8
    lea rcx, [r8*8]
    sub rcx, r8
    mov r10, r8
    mov rsi, 748B9430C9591C6h
    and r10, rsi
    lea r10, [r10+r10*8]
    mov rbx, 78B746BCF36A6E39h
    and r8, rbx
    add r8, r8
    lea r11, [r8+r8*4]
    mov r8, r9
    and r8, rsi
    mov rdi, r8
    not rdi
    lea rdi, [rdi+rdi*2]
    and r9, rbx
    add r9, r9
    add r8, r8
    sub r8, r9
    add r8, rdi
    sub r8, r11
    sub r8, r10
    add r8, rcx
    mov rcx, 1D67D728CFF8891Dh
    lea r10, [r8+rcx]
    mov rcx, r10
    mov r9, 18281FFDF1B9D60Dh
    xor rcx, r9
    mov r9, 218F652C813B4768h
    add r9, rcx
    add r10, r9
    mov r11, -68BFE171FE07FEBCh
    sub r11, r10
    mov rdi, r8
    not rdi
    mov r10, r11
    or r10, rdi
    mov rbx, r11
    or rbx, r8
    lea r14, [rbx+rbx*4]
    lea rbx, [rbx+r14*2]
    mov r14, r11
    and rdi, r11
    shl rdi, 3
    and r11, r8
    imul r11, 0F5h
    sub r11, rdi
    xor r14, r8
    add r14, r14
    sub r11, r14
    add r11, rbx
    not r10
    add r10, r10
    lea r10, [r10+r10*4]
    sub r11, r10
    mov r10, 3512C32C0C932993h
    xor r9, r10
    mov r10, -361D1E3B5EC8FAA9h
    add r8, r10
    add r8, r11
    mov r10, 365A10F532E16093h
    add r10, r9
    xor r8, r10
    add r8, r9
    xor r8, rcx
    mov rax, qword ptr [rax+10h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FF8569F4FCF:
    mov rcx, r12
    call rax
    loc_7FF8569F4FD4:
    mov qword ptr [rbp+480h], rax
    mov rax, qword ptr [rbp+608h]
    mov r8, qword ptr [rax]
    inc r8
    mov rax, qword ptr [qword_7FF8571CFB98]
    mov rcx, 104139D6A9800265h
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
    mov rdx, 471AF5D6AB8C2B57h
    xor rcx, rdx
    mov rdx, 2BB2D4B0432BBEBEh
    add rdx, rax
    mov r9, rdx
    or r9, rax
    lea r10, [r9+r9*2]
    not r9
    lea r11, [r9*8]
    sub r11, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and rdx, rax
    lea rax, [rdx+r10*2]
    add rax, rcx
    add rax, r11
    mov rcx, -7
    sub rcx, rax
    cmp r8, rcx
    jnz loc_7FF856A080FB
    mov eax, dword ptr [dword_7FF85724298C]
    mov ecx, eax
    xor ecx, -5A623B84h
    add ecx, 0D809EB0h
    xor ecx, 475A7BE9h
    sub ecx, eax
    add ecx, -18299A07h
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF8569F5179:
    cmp eax, 7BAB11EDh
    jz loc_7FF8569F9A5A
    mov r9, qword ptr [rbp+3F8h]
    add r9, 10h
    mov qword ptr [rsp+20h], 50h
    mov ecx, 4Bh
    mov edx, 10h
    lea r8, [rbp+58Ch]
    call sub_7FF855CA1330
    movzx ecx, byte ptr [rbp+639h]
    and cl, al
    mov byte ptr [rbp+61Dh], cl
    test al, al
    jz loc_7FF856A06110
    mov eax, dword ptr [dword_7FF8572429EC]
    lea ecx, [rax-4CCB29DAh]
    mov edx, ecx
    xor edx, 3121A1FFh
    mov r8d, -17EFC326h
    sub r8d, edx
    xor ecx, eax
    xor ecx, r8d
    xor ecx, -404AE52h
    add eax, ecx
    add eax, -4CCB29DAh
    sub eax, edx
    add eax, 4499E18Fh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F5206:
    cmp eax, 48AD8701h
    jnz loc_7FF8569FDB4F
    mov rdx, qword ptr [rbp+4E8h]
    mov rcx, qword ptr [rbp+430h]
    mov r8, qword ptr [rbp+2F8h]
    call memcpy
    loc_7FF8569F522B:
    mov rax, qword ptr [rbp+620h]
    mov rax, qword ptr [rax]
    mov rcx, qword ptr [qword_7FF8571CF9D0]
    mov rdx, 5519C17026302A1Ch
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
    mov rdx, 63192FE97C341348h
    add rdx, rcx
    mov r8, rdx
    mov r9, 6FFC4FA5F9DDF91Ch
    xor r8, r9
    sub rdx, r8
    mov r9, -3AF7FEE67349E91h
    add rdx, r9
    xor r8, rcx
    xor r8, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp rax, r8
    jle loc_7FF856A01B00
    mov eax, dword ptr [dword_7FF857242B14]
    mov ecx, -20FE4E2Fh
    add eax, ecx
    mov ecx, eax
    xor ecx, 8BF014Ch
    lea edx, [rcx+21C75766h]
    mov r8d, edx
    xor r8d, 53B913Eh
    sub r8d, eax
    add ecx, ecx
    add ecx, r8d
    sub ecx, edx
    add ecx, 1C5D5C0Eh
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF8569F5379:
    cmp eax, 5BCB9ACCh
    jnz loc_7FF8569F89FB
    mov rdx, qword ptr [rbp+0C0h]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569F5392:
    mov rcx, r12
    call qword ptr [rax+30h]
    loc_7FF8569F5398:
    mov rax, qword ptr [rbp+5B8h]
    mov rax, qword ptr [rax]
    jmp loc_7FF856A0719D
    loc_7FF8569F53A7:
    cmp eax, 6A6EB594h
    jnz loc_7FF8569FDB79
    mov rdx, qword ptr [rbp+4E8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rbp+470h]
    mov r8, qword ptr [rbp+358h]
    call memcpy
    loc_7FF8569F5427:
    mov rax, qword ptr [rbp+620h]
    mov rax, qword ptr [rax]
    test rax, rax
    js loc_7FF856A05F45
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rbp+4E8h]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569F548F:
    mov rcx, r12
    call qword ptr [rax+30h]
    mov rax, qword ptr [rbp+620h]
    mov rax, qword ptr [rax]
    mov qword ptr [rbp+218h], rax
    loc_7FF8569F54A6:
    mov rax, qword ptr [rbp+470h]
    mov qword ptr [rbp+4E8h], rax
    mov rax, qword ptr [rbp+218h]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rbp+620h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+470h]
    mov qword ptr [rbp+220h], rax
    jmp loc_7FF8569F91CE
    loc_7FF8569F553F:
    cmp eax, 2E160A90h
    jz loc_7FF856A00098
    jmp loc_7FF856A07339
    loc_7FF8569F554F:
    cmp eax, 62CF9F23h
    jnz loc_7FF8569FE8D5
    mov rax, qword ptr [rbp+5F8h]
    cmp rax, 17h
    mov ecx, 16h
    cmovb rax, rcx
    loc_7FF8569F556E:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov rdx, -8000000000000000h
    or rcx, rdx
    mov rdx, qword ptr [rbp+5B8h]
    mov qword ptr [rdx], rcx
    mov rdx, -77B1F4BB0537B5F3h
    sub rdx, qword ptr [qword_7FF8571CFA08]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, rdx
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
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, rax
    or r8, rdx
    mov r9, rax
    and r9, rcx
    and rdx, rax
    lea rdx, [rdx+r9*2]
    mov r9, rax
    or r9, rcx
    not r9
    not r8
    add r8, r8
    xor rcx, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rdx, rax
    lea rdx, [rdx+rcx*2]
    sub rdx, r8
    add rdx, r9
    mov rax, qword ptr [off_7FF8571A2640]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [qword_7FF8571CFA10]
    mov r8, 54FBA5961AA37BEDh
    lea r9, [rcx+r8]
    mov r8, 33B9FE06DFD2590Ah
    add r8, rcx
    mov r10, 7A2A9A2DE0A675A8h
    xor r9, r10
    sub r9, r8
    sub r9, rcx
    mov rcx, r8
    mov r10, 2E813BE6BE421D41h
    xor rcx, r10
    mov r10, -7AC4A5CAD0353C9Fh
    xor r8, r10
    add r8, rcx
    add r8, r9
    mov rax, qword ptr [rax+10h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FF8569F589B:
    mov rcx, r12
    call rax
    loc_7FF8569F58A0:
    mov qword ptr [rbp+438h], rax
    mov rax, qword ptr [rbp+4C8h]
    mov r8, qword ptr [rax]
    inc r8
    jnz loc_7FF856A0712D
    mov eax, dword ptr [dword_7FF857242AF4]
    lea ecx, [rax-22C10B12h]
    lea edx, [rax+2B787523h]
    lea r8d, [rax-782696FFh]
    xor r8d, ecx
    xor r8d, edx
    sub r8d, eax
    add r8d, 55FA1820h
    mov dword ptr [rbp+63Ch], r8d
    jmp loc_7FF8569F0600
    loc_7FF8569F58EF:
    cmp eax, 66178171h
    jnz loc_7FF8569FEE57
    mov r8, qword ptr [rbp+5F0h]
    mov rdx, qword ptr [rbp+378h]
    mov rcx, qword ptr [rbp+360h]
    call memcpy
    jmp loc_7FF856A008D9
    loc_7FF8569F5919:
    cmp eax, 2431DE88h
    jnz loc_7FF8569F598B
    mov eax, dword ptr [dword_7FF857242ACC]
    lea ecx, [rax-2475043h]
    xor ecx, 0E628986h
    lea edx, [rcx-7ACCB30Fh]
    xor edx, -697E4752h
    add edx, -7B602CE1h
    add eax, ecx
    add eax, -220135B3h
    xor eax, edx
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F5958:
    cmp eax, 27FE8602h
    jnz loc_7FF856A008BC
    mov rax, qword ptr [rbp+3F0h]
    mov rcx, qword ptr [rax]
    mov rdx, qword ptr [rax+10h]
    mov qword ptr [rbp+2C8h], rdx
    mov qword ptr [rbp+2C0h], rcx
    mov qword ptr [rbp+2B8h], rax
    jmp loc_7FF8569F6FC3
    loc_7FF8569F598B:
    mov rax, qword ptr [rbp+250h]
    mov rcx, qword ptr [rbp+258h]
    mov rdx, qword ptr [rbp+260h]
    mov qword ptr [rbp+5A0h], rax
    mov qword ptr [rbp+3B8h], rcx
    mov qword ptr [rbp+3C0h], rdx
    mov rcx, qword ptr [rbp+490h]
    call strlen
    mov qword ptr [rbp+598h], rax
    mov rax, qword ptr [rbp+490h]
    sub rax, qword ptr [rbp+3B8h]
    mov qword ptr [rbp+3B0h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+5A0h]
    add rax, 10h
    mov qword ptr [rbp+4D0h], rax
    mov rcx, qword ptr [qword_7FF8571CFBD0]
    mov rax, rcx
    not rax
    mov rdx, rax
    mov r9, 654B04BB903941DEh
    and rdx, r9
    lea rdx, [rdx+rdx*2]
    mov r8, rax
    mov r10, 1AB4FB446FC6BE21h
    and r8, r10
    shl r8, 2
    or rax, r9
    sub rax, rcx
    sub rax, rcx
    sub rax, r8
    sub rax, rdx
    add rax, -3
    mov rdx, rax
    not rdx
    mov r11, -0A6D9DC8ED6AFE2Fh
    and rdx, r11
    lea r8, [rdx+rdx*4]
    lea r8, [rdx+r8*4]
    mov r9, rax
    or r9, r11
    lea rdx, [r9+r9*4]
    lea rdx, [r9+rdx*2]
    not r9
    lea r10, [r9+r9*4]
    lea r9, [r9+r10*2]
    mov r10, rax
    and r10, r11
    mov r11, r10
    not r11
    lea rdi, [r11+r11*4]
    lea r11, [r11+rdi*2]
    mov rdi, rax
    mov rbx, 0A6D9DC8ED6AFE2Eh
    and rdi, rbx
    lea rbx, [rdi+rdi*4]
    lea rdi, [rdi+rbx*4]
    lea r10, [r10+r10*8]
    add r10, rdi
    sub rdx, r10
    add rdx, r11
    sub rdx, r9
    sub rdx, r8
    mov r8, rdx
    add rdx, rcx
    mov rcx, 5723A6C1434F23C6h
    xor r8, rcx
    mov rcx, -2A7549AB565BE33Ch
    add r8, rcx
    mov rcx, 1CF8C1CD65ADC6D1h
    xor r8, rcx
    add rdx, r8
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and rdx, qword ptr [rbp+3C0h]
    mov qword ptr [rbp+48h], rdx
    cmp qword ptr [rbp+598h], rdx
    jbe loc_7FF856A01336
    mov eax, dword ptr [dword_7FF857242A10]
    lea ecx, 7962438Fh[rax*2]
    add eax, ecx
    add eax, 7962438Fh
    mov ecx, 5D47498Eh
    jmp loc_7FF8569FC6BF
    loc_7FF8569F5CD8:
    cmp eax, 4B0FE5C8h
    jnz loc_7FF856A01359
    mov rax, qword ptr [rbp+138h]
    mov qword ptr [rbp+378h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+4E8h]
    mov rcx, qword ptr [rbp+378h]
    sub rcx, rax
    mov qword ptr [rbp+370h], rcx
    mov rcx, qword ptr [rbp+620h]
    mov rcx, qword ptr [rcx]
    mov qword ptr [rbp+368h], rcx
    and rcx, r13
    mov qword ptr [rbp+38h], rcx
    cmp qword ptr [rbp+5F0h], rcx
    jbe loc_7FF856A061D3
    mov eax, dword ptr [dword_7FF857242A78]
    mov ecx, eax
    xor ecx, 23B45294h
    add ecx, -634CF77Dh
    mov edx, eax
    xor edx, 7059EF63h
    add edx, 4B893D52h
    xor edx, ecx
    add edx, eax
    jmp loc_7FF8569F05F9
    loc_7FF8569F5D98:
    cmp eax, 5D79FC99h
    jz loc_7FF856A06917
    mov rax, qword ptr [rbp+620h]
    cmp qword ptr [rax], 0
    js loc_7FF856A07FA1
    mov rdx, qword ptr [rbp+4E8h]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569F5DC2:
    mov rcx, r12
    call qword ptr [rax+30h]
    mov rax, qword ptr [rbp+5D0h]
    mov rax, qword ptr [rax]
    mov rcx, qword ptr [rbp+460h]
    mov rcx, qword ptr [rcx]
    mov qword ptr [rbp+1F8h], rcx
    mov qword ptr [rbp+1F0h], rax
    jmp loc_7FF8569F69F9
    loc_7FF8569F5DEF:
    cmp eax, 43F05324h
    jz loc_7FF856A06917
    loc_7FF8569F5DFA:
    mov rax, qword ptr [qword_7FF8571CFBB8]
    mov rcx, 1A6AF2FAEBDD5F2Ah
    lea rdx, [rax+rcx]
    mov rcx, -4570E309A7FBA57Ah
    lea r8, [rax+rcx]
    xor rdx, r8
    mov rcx, -23701AEC50F4C1F8h
    xor rdx, rcx
    add rdx, r8
    mov rcx, -6774DD110D2ECF5Fh
    xor r8, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9, rdx
    or r9, r8
    not r9
    add r9, r9
    mov rcx, rdx
    and rcx, r8
    not rcx
    add rcx, rcx
    xor r8, rdx
    sub rcx, r8
    sub rcx, r9
    sub rcx, rax
    mov rax, 0FCC6C1E8AB4153Ch
    add rcx, rax
    loc_7FF8569F5ED5:
    call ??2@YAPEAX_K@Z
    mov rdx, qword ptr [qword_7FF8571CFBC0]
    mov rcx, 2BA89A1F73B0F61Ah
    add rcx, rdx
    mov r8, -4F6302D93D443268h
    add r8, rdx
    mov r9, -65895C0AD6E86B79h
    lea r10, [rdx+r9]
    mov r9, 3DAA2A417E452B46h
    xor r10, r9
    mov r9, 1F0920D524227BB5h
    add r10, r9
    xor r10, r8
    mov r8, rdx
    not r8
    lea r9, [r8+r8*4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    or r11, r8
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdi, r10
    or rdi, rdx
    not rdi
    lea rdi, [rdi+rdi*4]
    xor rdx, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    and r8, r10
    shl r8, 3
    sub r8, rdx
    add r8, rdi
    add r8, r11
    sub r8, r9
    xor r8, rcx
    mov qword ptr [rax+8], r8
    mov rcx, rax
    add rcx, 18h
    mov qword ptr [rax], rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx edx, byte ptr [byte_7FF8571CFBC8]
    add dl, 0A2h
    movzx r8d, dl
    mov edx, r8d
    not dl
    movzx edx, dl
    lea r10d, [rdx+rdx*2]
    mov r9d, edx
    and r9b, 56h
    movzx r9d, r9b
    lea r11d, [r9+r9*2]
    mov r14d, edx
    and r14b, 0A9h
    mov r9d, r8d
    xor r9b, 56h
    movzx edi, r9b
    lea r9d, [rdi*8]
    sub r9d, edi
    mov ebx, r8d
    and bl, 29h
    movzx edi, bl
    add edi, edi
    lea edi, [rdi+rdi*2]
    mov ebx, r8d
    and bl, 56h
    add bl, bl
    sub bl, dil
    movzx edi, r14b
    lea edi, [rdi+rdi*2]
    add r9b, dil
    add r9b, bl
    sub r9b, r11b
    sub r9b, r10b
    lea r10d, [r9+30h]
    xor r9b, 0A3h
    mov r11d, r9d
    or r11b, dl
    not r11b
    movzx r11d, r11b
    lea edi, [r11+r11*4]
    lea r11d, [r11+rdi*2]
    mov ebx, r9d
    or bl, r8b
    lea edi, [r8+r8*4]
    lea edi, [r8+rdi*2]
    mov r14d, r9d
    and r14b, r8b
    and dl, r9b
    add dl, dil
    add dl, bl
    movzx r8d, r14b
    imul r8d, 0F5h
    add dl, r8b
    sub dl, r11b
    mov r8d, r10d
    xor r8b, 33h
    sub dl, r9b
    lea r9d, [r8-3Ch]
    xor dl, r9b
    xor dl, 6Dh
    add dl, r10b
    mov r9, -7FFFFFFFFFFFFFF1h
    mov qword ptr [rax+10h], r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub dl, r8b
    add dl, 0A4h
    mov byte ptr [rax+18h], dl
    mov rdx, qword ptr [rbp+548h]
    mov qword ptr [rdx], rax
    mov qword ptr [rbp+258h], rcx
    mov qword ptr [rbp+250h], rax
    mov eax, dword ptr [dword_7FF857242A1C]
    lea ecx, [rax-581E88E1h]
    mov edx, ecx
    xor edx, 2D82A9Eh
    lea r8d, [rdx+3C5F3149h]
    xor r8d, -4E335259h
    sub r8d, eax
    add r8d, 6709042Ah
    xor r8d, ecx
    add r8d, edx
    add eax, r8d
    add eax, -14AA4E55h
    mov dword ptr [rbp+63Ch], eax
    mov qword ptr [rbp+260h], r9
    jmp loc_7FF8569F0600
    loc_7FF8569F64BD:
    cmp eax, 52EB5EB4h
    jnz loc_7FF856A01AC5
    mov r9, qword ptr [rbp+0A0h]
    mov qword ptr [rbp+3F8h], r9
    mov qword ptr [rsp+20h], 0Ah
    mov ecx, 2Eh
    mov edx, 23h
    lea r8, [rbp+40Ch]
    call sub_7FF855CA1330
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [rbp+63Bh]
    and cl, al
    mov byte ptr [rbp+61Fh], cl
    test al, al
    jz loc_7FF856A06209
    mov eax, dword ptr [dword_7FF8572429F4]
    lea edx, [rax-522F9B1h]
    mov r8d, -4F426C3Ch
    sub r8d, eax
    xor r8d, edx
    sub r8d, eax
    sub r8d, eax
    add eax, r8d
    add eax, -45C9C7ECh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F65B0:
    cmp eax, 47AC7F90h
    jz loc_7FF856A00032
    mov rax, qword ptr [rbp+4A8h]
    jmp loc_7FF8569F8A61
    loc_7FF8569F65C7:
    cmp eax, 55010640h
    jnz loc_7FF856A01EC5
    mov rax, qword ptr [rbp+5E8h]
    mov rcx, qword ptr [rbp+348h]
    mov qword ptr [rbp+1F8h], rax
    mov qword ptr [rbp+1F0h], rcx
    mov eax, dword ptr [dword_7FF857242AA4]
    lea ecx, [rax-25DDB324h]
    mov edx, -54A1EE4Eh
    sub edx, eax
    xor edx, ecx
    sub edx, eax
    add edx, 44C570E2h
    jmp loc_7FF8569F05F9
    loc_7FF8569F6610:
    cmp eax, 33D9A310h
    jnz loc_7FF856A01B4F
    loc_7FF8569F661B:
    mov rax, qword ptr [rbp+430h]
    mov qword ptr [rbp+4E8h], rax
    mov rcx, qword ptr [qword_7FF8571CF9D8]
    mov rax, 6E6B7E42416C08Eh
    lea rdx, [rcx+rax]
    mov rax, rdx
    not rax
    lea r8, [rax+rax*4]
    mov r9, rdx
    mov r11, 55B554C3EC5ED04h
    and r9, r11
    lea r9, [r9+r9*2]
    mov r10, rax
    and r10, r11
    lea r10, [r10+r10*4]
    add r10, r9
    mov r9, 7AA4AAB3C13A12FBh
    xor rdx, r9
    add rdx, rdx
    mov r9, 1AA4AAB3C13A12FBh
    and rax, r9
    shl rax, 3
    sub rax, rdx
    add rax, r10
    sub rax, r8
    sub rax, rcx
    mov rcx, 2F75E2AE1CDF4E08h
    add rax, rcx
    and rax, qword ptr [rbp+198h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rbp+620h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+430h]
    jmp loc_7FF8569FA335
    loc_7FF8569F678D:
    cmp eax, 3ADB522Dh
    jnz loc_7FF856A02450
    mov rax, qword ptr [rbp+30h]
    loc_7FF8569F679C:
    mov qword ptr [rbp+210h], rax
    mov rax, qword ptr [rbp+468h]
    mov qword ptr [rbp+138h], rax
    mov rax, qword ptr [rbp+210h]
    and rax, r13
    mov rcx, qword ptr [rbp+5D8h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+468h]
    mov qword ptr [rbp+2A0h], rax
    jmp loc_7FF8569F8A43
    loc_7FF8569F67D8:
    cmp eax, 0AA907E9h
    jnz loc_7FF8569FBE61
    mov eax, dword ptr [dword_7FF857242A4C]
    mov ecx, -1CF67E6Ch
    jmp loc_7FF856A0521B
    loc_7FF8569F67F3:
    cmp eax, 1B1D5B8Fh
    jnz loc_7FF8569F6839
    movzx eax, byte ptr [rbp+61Fh]
    mov byte ptr [rbp+634h], al
    mov eax, dword ptr [dword_7FF857242960]
    lea ecx, [rax+77A867D1h]
    mov edx, ecx
    xor edx, -541FE3BBh
    mov r8d, 31E3B3A8h
    sub r8d, eax
    xor r8d, eax
    add r8d, edx
    xor r8d, ecx
    mov dword ptr [rbp+63Ch], r8d
    jmp loc_7FF8569F0600
    loc_7FF8569F6839:
    mov rax, qword ptr [qword_7FF8571CFCE8]
    mov rcx, rax
    not rcx
    mov r11, -5BD4521BF82355C4h
    and rcx, r11
    lea rdx, [rcx+rcx*4]
    lea rdx, [rcx+rdx*2]
    mov rcx, rax
    or rcx, r11
    lea r8, [rcx+rcx*4]
    lea r8, [rcx+r8*2]
    mov r9, rax
    xor r9, r11
    mov rcx, rax
    mov r10, 5BD4521BF82355C3h
    and rcx, r10
    lea r10, [rcx+rcx*8]
    mov rcx, rax
    and rcx, r11
    imul rcx, 0F5h
    sub rcx, r10
    sub rcx, r9
    add rcx, r8
    sub rcx, rdx
    mov rdx, -3D04DB7264C244E6h
    add rcx, rdx
    mov rdx, rcx
    mov r8, 52A772C21EC5F567h
    xor rdx, r8
    add rdx, rdx
    mov r8, -5627725F183E8145h
    sub r8, rdx
    mov rdx, rcx
    not rdx
    mov r9, r8
    or r9, rdx
    mov r10, r8
    or r10, rcx
    not r10
    add r10, r9
    lea r9, [r8+r8]
    and r8, rcx
    add r8, r8
    sub r9, r8
    add r9, r10
    sub r9, rdx
    mov rdx, -7CD509E271E02E79h
    xor rcx, rdx
    sub r9, rcx
    add rax, r9
    inc rax
    mov rcx, qword ptr [rbp+628h]
    mov rcx, qword ptr [rcx]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp rcx, rax
    jle loc_7FF856A02820
    mov eax, dword ptr [dword_7FF857242998]
    lea ecx, [rax-10018DFCh]
    xor ecx, eax
    xor ecx, -2C29AD18h
    add eax, ecx
    add eax, -6C88B68Fh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F69EE:
    cmp eax, 34B74EDFh
    jnz loc_7FF8569F93C3
    loc_7FF8569F69F9:
    mov rax, qword ptr [rbp+1F8h]
    mov rcx, qword ptr [rbp+110h]
    mov qword ptr [rbp+4E8h], rcx
    mov rcx, qword ptr [rbp+5C8h]
    mov rdx, qword ptr [rbp+1F0h]
    and rdx, r13
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+620h]
    mov qword ptr [rax], rdx
    jmp loc_7FF8569F84A7
    loc_7FF8569F6A31:
    cmp eax, 41D9F0FFh
    jnz loc_7FF856A0406F
    loc_7FF8569F6A3C:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [qword_7FF8571CFC70]
    mov rax, -5B0120881D86EDB8h
    lea rcx, [rdx+rax]
    mov rax, rcx
    not rax
    mov r8, rax
    mov r9, rax
    mov r11, 57E78DFE4EDD2214h
    or rax, r11
    sub rax, rcx
    sub rax, rcx
    mov r10, 28187201B122DDEBh
    and r9, r10
    shl r9, 2
    sub rax, r9
    and r8, r11
    lea r8, [r8+r8*2]
    sub rax, r8
    mov r8, -699E206690A206Ah
    add r8, rax
    xor r8, rdx
    xor r8, rcx
    mov rcx, 4466CA1E5E4A5C2Fh
    add rcx, rax
    mov rdx, 8A4035DCD2A044h
    xor rcx, rdx
    mov rdx, 75F74F8FDB24668Dh
    add rcx, rdx
    xor r8, rcx
    mov rdx, -5CDF3D0BA97B8019h
    xor r8, rdx
    add r8, rcx
    lea rcx, [rax+r8]
    add rcx, -3
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FF8569F6C8F:
    call ??2@YAPEAX_K@Z
    mov rcx, qword ptr [qword_7FF8571CFC78]
    mov rdx, rcx
    not rdx
    mov r11, 1C43D0273969CB83h
    and rdx, r11
    lea rdx, [rdx+rdx*2]
    lea r8, [rcx+rcx]
    mov r9, 3887A04E72D39706h
    or r8, r9
    lea r8, [r8+r8*2]
    mov r9, rcx
    mov r10, -1C43D0273969CB84h
    xor r9, r10
    mov r10, rcx
    and r10, r11
    lea r10, [r10+r10*2]
    add r10, r10
    mov r11, rcx
    mov rsi, 63BC2FD8C696347Ch
    and r11, rsi
    lea r11, [r11+r11*2]
    lea r10, [r10+r11*2]
    add r10, r9
    sub r10, r8
    lea r8, [r10+rdx*2]
    mov rdx, -79EE773AA826DE77h
    add rdx, r8
    mov r9, rdx
    mov r10, -4BA28398668C3940h
    xor r9, r10
    mov r10, 60490D496D620E6Bh
    add rcx, r10
    add rcx, r9
    mov r9, r8
    not r9
    mov r10, rcx
    or r10, r9
    not r10
    lea r11, [r10+r10*4]
    lea r10, [r10+r11*2]
    lea r11, [r8+r8*4]
    lea r11, [r8+r11*2]
    and r9, rcx
    add r9, r11
    mov r11, rcx
    or r11, r8
    add r9, r11
    mov r11, rcx
    and r11, r8
    imul r11, 0F5h
    add r11, r9
    sub r11, r10
    sub r11, rcx
    sub r11, r8
    mov qword ptr [rax+8], 0
    mov rcx, -6723F82A4BE5E54Ah
    add rdx, rcx
    add rdx, r11
    mov rcx, rax
    add rcx, 18h
    mov qword ptr [rax], rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rax+10h], rdx
    mov byte ptr [rax+18h], 0
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rbp+548h]
    mov qword ptr [rdx], rax
    mov qword ptr [rbp+2C0h], rcx
    mov qword ptr [rbp+2B8h], rax
    mov rax, -7FFFFFFFFFFFFFF1h
    mov qword ptr [rbp+2C8h], rax
    loc_7FF8569F6FC3:
    mov rax, qword ptr [rbp+2B8h]
    mov rcx, qword ptr [rbp+2C0h]
    mov qword ptr [rbp+578h], rax
    mov qword ptr [rbp+78h], rcx
    mov rdx, qword ptr [rbp-50h]
    mov r8, qword ptr [rbp-48h]
    mov qword ptr [rbp+5A8h], r8
    mov qword ptr [rbp+70h], rdx
    sub rdx, rcx
    mov qword ptr [rbp+3E8h], rdx
    add rax, 10h
    mov qword ptr [rbp+4E0h], rax
    mov rax, qword ptr [qword_7FF8571CFC80]
    mov rcx, -6499E680A8891F12h
    lea rdx, [rax+rcx]
    mov r8, rdx
    mov r11, 51512706A79B0A22h
    or r8, r11
    mov rcx, rdx
    mov rdi, -51512706A79B0A23h
    xor rcx, rdi
    lea r9, [rcx+rcx*2]
    mov r10, rdx
    and r10, r11
    mov rcx, rdx
    and rcx, rdi
    sub rcx, r10
    add rcx, r9
    sub rcx, r8
    not r8
    shl r8, 2
    mov r9, rdx
    not r9
    mov r10, r9
    and r10, r11
    add rcx, r10
    sub rcx, r8
    lea r10, [r9+r9*2]
    mov r11, r9
    mov r8, r9
    mov rdi, 27BC31370B9BBF67h
    and r9, rdi
    shl r9, 2
    and rdx, rdi
    lea rdx, [rdx+rdx*2]
    sub r9, rdx
    mov rdx, 5843CEC8F4644098h
    and r8, rdx
    lea rdx, [r8+r8*2]
    lea r9, [r9+rdx*2]
    mov rdx, -73349E8C7D993CC2h
    lea r8, [rax+rdx]
    or r11, rdi
    add r9, r11
    mov rdx, -7DC58C7E36CC0B99h
    add rdx, rax
    lea r10, [rcx+r10*2]
    sub r9, r10
    mov r10, 11E5D0D7F8D8EB17h
    add r9, r10
    xor rdx, rax
    xor rdx, r9
    mov r9, rdx
    or r9, r8
    not r8
    mov r10, rdx
    or r10, r8
    not r9
    and r8, rdx
    lea r8, [r8+r9*2]
    not r10
    add r8, r10
    not rdx
    add rdx, rdx
    sub r8, rdx
    mov rdx, -77EB44FE004B0245h
    add rax, rdx
    add rax, r8
    xor rax, rcx
    mov r8, qword ptr [rbp+2C8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and rax, r8
    cmp qword ptr [rbp+5A8h], rax
    jbe loc_7FF856A04FA5
    mov ecx, dword ptr [dword_7FF8571CFC88]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea edx, [rcx-1]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add ecx, -4F42AF76h
    lea ecx, 0FFFFFFFF8F54E078h[rcx*2]
    xor ecx, edx
    mov rdx, rax
    shr rdx, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rdx, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+5A8h]
    cmp rdx, rax
    cmovbe rdx, rax
    loc_7FF8569F7647:
    mov rcx, qword ptr [qword_7FF8571CFC90]
    mov rax, 37507AD0D9D8CEAEh
    add rax, rcx
    mov r9, -0CA6D1C9009FD93Bh
    xor rax, r9
    mov r9, -40B94E63AA567E45h
    add r9, rax
    mov r10, 1A7E94C84D9D3BFDh
    sub r10, rcx
    mov rcx, r9
    not rcx
    mov r11, r10
    or r11, rcx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    xor r11, r9
    lea r11, [r11+r11*4]
    and rcx, r10
    lea rcx, [rcx+rcx*2]
    and r10, r9
    lea rcx, [r10+rcx*2]
    sub rcx, r11
    sub rcx, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rcx, rdi
    xor rcx, rax
    not rcx
    mov r9, rdx
    or r9, rcx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, rdx
    sub rax, r9
    add rax, rcx
    mov rcx, qword ptr [qword_7FF8571CFC98]
    mov r9, -59AE005F0776919Fh
    add r9, rcx
    mov r10, 65F9EB7FDD02F8FEh
    xor rcx, r10
    xor rcx, r9
    mov r10, -222AB1C5C0CCA446h
    xor r9, r10
    mov r10, 10E77DF1210113F9h
    add r9, r10
    mov r10, rcx
    mov r11, rcx
    lea rdi, [rcx+rcx]
    and rcx, r9
    add rcx, rcx
    sub rdi, rcx
    or r11, r9
    not r9
    or r10, r9
    not r11
    add r11, r10
    add r11, rdi
    sub r11, r9
    inc r11
    and r8, r11
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or r8, rax
    mov rax, qword ptr [rbp+4E0h]
    mov qword ptr [rax], r8
    inc rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [off_7FF8571A2640]
    mov rax, qword ptr [rax+10h]
    mov r8, qword ptr [qword_7FF8571CFCA0]
    mov rcx, 6035EE2C609670DEh
    add r8, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, r12
    call rax
    loc_7FF8569F7A5A:
    mov qword ptr [rbp+4B8h], rax
    mov rcx, qword ptr [qword_7FF8571CFCA8]
    lea rdx, [rcx+rcx]
    mov rax, -3E5940584E3B1100h
    add rdx, rax
    mov rax, -510CD06475A98DB1h
    add rcx, rax
    mov rax, rcx
    not rax
    mov r8, rax
    mov r10, 0BE4C4D9CE337DB8h
    and r8, r10
    lea r8, [r8+r8*2]
    mov r9, rax
    mov r11, 341B3B2631CC8247h
    and r9, r11
    shl r9, 2
    or rax, r10
    add rcx, rcx
    sub rax, rcx
    sub rax, r9
    sub rax, r8
    lea rcx, [rax-3]
    mov r8, 0C3806E501731A16h
    add r8, rax
    xor r8, rdx
    mov rdx, rcx
    not rdx
    mov r9, r8
    or r9, rdx
    mov r10, r8
    or r10, rcx
    and rdx, r8
    and r8, rcx
    lea rcx, [r8+r8*2]
    lea rcx, [rcx+rdx*4]
    lea rdx, [r10+r10*4]
    sub rdx, rcx
    lea rax, 0FFFFFFFFFFFFFFFAh[rax*2]
    sub rdx, rax
    mov rax, qword ptr [rbp+578h]
    not r9
    shl r9, 2
    sub rdx, r9
    add rdx, qword ptr [rax+8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rbp+3D8h], rdx
    mov rax, qword ptr [qword_7FF8571CFCB0]
    mov rcx, rax
    mov rdx, -63BF29CABE068733h
    xor rcx, rdx
    mov rdx, 5395896A531057C5h
    add rdx, rcx
    mov r8, -704CA67658739B64h
    xor rdx, r8
    add rcx, rax
    add rcx, rdx
    mov rax, 5F70BB09A9034D61h
    sub rax, rcx
    xor rax, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, -3E3224BFE2F8B070h
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
    cmp qword ptr [rbp+3D8h], rax
    jnz loc_7FF856A07ED3
    mov eax, dword ptr [dword_7FF8572429E0]
    mov ecx, -18B467DBh
    xor eax, ecx
    lea ecx, [rax-6E5454B6h]
    xor ecx, -36118563h
    add ecx, 6D423A32h
    xor ecx, eax
    xor ecx, -551E86D8h
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF8569F7E6C:
    cmp eax, 0AE91651h
    jnz loc_7FF856A08212
    mov r8, qword ptr [rbp+600h]
    mov rdx, qword ptr [rbp+40h]
    mov rcx, qword ptr [rbp+388h]
    call memcpy
    loc_7FF8569F7E8E:
    mov rax, qword ptr [rbp+550h]
    mov rcx, qword ptr [rbp+600h]
    mov byte ptr [rax+rcx], 0
    mov rax, qword ptr [rbp+608h]
    mov rcx, qword ptr [rbp+600h]
    mov qword ptr [rax], rcx
    mov rax, qword ptr [rbp+5C0h]
    mov rax, qword ptr [rax]
    mov rdx, qword ptr [qword_7FF8571CFBA8]
    mov rcx, 12357A752BEAC841h
    add rcx, rdx
    mov r8, rcx
    mov r9, 20A97F138D5C4906h
    xor r8, r9
    mov r9, rdx
    sub r9, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov r10, 40607D7E4A0645D2h
    add rdx, r10
    add rdx, r9
    mov r9, rdx
    not r9
    mov r10, -20A97F138D5C4907h
    xor rcx, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r10, rdx
    or r10, rcx
    not r10
    lea r10, [r10+r10*8]
    add r10, r9
    mov r9, rdx
    or r9, r8
    not r9
    lea r9, [r9+r9*4]
    and rcx, rdx
    and rdx, r8
    lea r8, [rdx+rdx*4]
    lea rdx, [rdx+r8*2]
    add rdx, rcx
    not rcx
    lea r8, [rcx+rcx*4]
    lea rcx, [rcx+r8*2]
    sub rdx, rcx
    lea rcx, [rdx+r9*2]
    add rcx, r10
    cmp rax, rcx
    jle loc_7FF856A0501C
    mov eax, dword ptr [dword_7FF857242990]
    lea ecx, 0FFFFFFFFE0A14EBEh[rax*2]
    add ecx, ecx
    add ecx, eax
    add ecx, -4AEE2A64h
    add eax, 28897E40h
    sub ecx, eax
    sub ecx, eax
    add ecx, -4B5BED2Fh
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF8569F8069:
    cmp eax, 1C537A22h
    jnz loc_7FF856A040C7
    mov rcx, qword ptr [rbp+610h]
    mov edx, dword ptr [dword_7FF8571CFC54]
    mov eax, edx
    xor eax, -6CC64378h
    mov r10d, edx
    xor r10d, 919C4h
    mov r8d, edx
    xor r8d, -235919E0h
    mov r9d, r8d
    or r9d, -2352401Ch
    and r10d, 5CADBFE4h
    lea r10d, [r10+r10*2]
    lea r11d, [r8+r8*2]
    mov edi, r8d
    and edi, 1CADBFE4h
    shl edi, 2
    mov ebx, r8d
    and ebx, 2352401Bh
    lea ebx, [rbx+rbx*2]
    sub edi, ebx
    add edi, r11d
    lea r10d, [rdi+r10*2]
    lea r11d, [r9+r10]
    add r11d, -3261B221h
    add r10d, r9d
    add eax, 7487F4D2h
    xor eax, r11d
    not r10d
    add eax, r10d
    add eax, 2C127F58h
    xor eax, edx
    sub eax, r8d
    and eax, dword ptr [rcx]
    mov r8d, dword ptr [dword_7FF8571CFC58]
    mov ecx, 1F28C385h
    xor r8d, ecx
    lea ecx, [r8+1F4828C9h]
    mov edx, ecx
    not edx
    mov r10d, edx
    and r10d, -4BE39421h
    mov r11d, edx
    and r11d, 4BE39420h
    add r11d, r11d
    mov r9d, ecx
    xor r9d, 4BE39420h
    mov edi, ecx
    and edi, 4BE39420h
    mov ebx, ecx
    and ebx, -4BE39421h
    lea edi, [rbx+rdi*2]
    sub edi, ecx
    lea r9d, [rdi+r9*2]
    sub r9d, r11d
    add r9d, r10d
    mov r11d, r9d
    or r11d, 3FABFD42h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r10d, r9d
    xor r10d, -3FABFD43h
    lea edi, [r10+r10*2]
    mov ebx, r9d
    and ebx, 3FABFD42h
    mov r10d, r9d
    and r10d, -3FABFD43h
    sub r10d, ebx
    add r10d, edi
    sub r10d, r11d
    mov edi, r11d
    not edi
    shl edi, 2
    mov r11d, r9d
    not r11d
    mov ebx, r11d
    and ebx, 3FABFD42h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r10d, ebx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r10d, edi
    lea edi, 624C8251h[r10*2]
    xor edi, r8d
    sub edi, r10d
    lea ebx, [rdi-0BA2B224h]
    mov r8d, ebx
    or r8d, r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r14d, ebx
    or r14d, r9d
    not r14d
    add r14d, r8d
    lea r8d, 0FFFFFFFFE8BA9BB8h[rdi*2]
    and ebx, r9d
    add ebx, ebx
    sub r8d, ebx
    add r8d, r14d
    sub r8d, r11d
    inc r8d
    xor r8d, r10d
    mov r9d, r8d
    or r9d, edx
    lea r10d, [r9+r9*4]
    not r9d
    mov r11d, r8d
    or r11d, ecx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    xor edi, r8d
    lea edi, [rdi+rdi*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and edx, r8d
    lea edx, [rdx+rdx*2]
    add edx, edx
    and r8d, ecx
    lea ecx, [rdx+r8*8]
    sub ecx, r10d
    sub ecx, edi
    lea ecx, [rcx+r11*8]
    add ecx, r9d
    cmp eax, ecx
    jnz loc_7FF856A07080
    mov eax, dword ptr [dword_7FF857242920]
    lea ecx, [rax-83B9283h]
    xor ecx, eax
    add eax, ecx
    add eax, -532382AFh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F8421:
    cmp eax, 22DF2D1h
    jnz loc_7FF8569F84A7
    mov rdx, qword ptr [rbp-50h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569F849C:
    mov rcx, r12
    call qword ptr [rax+30h]
    loc_7FF8569F84A2:
    jmp loc_7FF8569F9163
    loc_7FF8569F84A7:
    mov rax, qword ptr [rbp+608h]
    mov rax, qword ptr [rax]
    mov rcx, qword ptr [rbp+350h]
    cmp rcx, rax
    cmovb rax, rcx
    loc_7FF8569F84BF:
    mov qword ptr [rbp+5F8h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+550h]
    mov qword ptr [rbp+18h], rax
    lea rax, [rbp+0C8h]
    mov qword ptr [rbp+4C8h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+4C8h]
    mov qword ptr [rax], 0
    lea rax, [rbp+0D8h]
    mov qword ptr [rbp+450h], rax
    mov qword ptr [rbp+0C0h], rax
    lea rax, [rbp+0D0h]
    mov qword ptr [rbp+5B8h], rax
    mov rax, -7FFFFFFFFFFFFFF1h
    mov qword ptr [rbp+0D0h], rax
    movzx ecx, byte ptr [byte_7FF8571CF9F8]
    mov r8d, ecx
    or r8b, 0E1h
    mov edx, ecx
    not dl
    mov eax, edx
    and al, 0E1h
    movzx eax, al
    lea eax, [rax+rax*2]
    mov r9d, ecx
    and r9b, 0E1h
    movzx r9d, r9b
    lea r9d, [r9+r9*2]
    mov r10d, ecx
    and r10b, 1Eh
    sub r9b, r10b
    add r9b, cl
    add al, r8b
    add al, r9b
    mov r8d, ecx
    and r8b, 89h
    movzx r8d, r8b
    lea r9d, [r8+r8*4]
    lea r8d, [r8+r9*2]
    mov r9d, ecx
    or r9b, 76h
    movzx r9d, r9b
    lea r10d, [r9+r9*4]
    lea r9d, [r9+r10*2]
    mov r10d, ecx
    and dl, 76h
    movzx edx, dl
    lea edx, [rdx+rdx*8]
    and cl, 76h
    movzx ecx, cl
    imul ecx, 0F5h
    sub cl, dl
    xor r10b, 76h
    sub cl, r10b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add al, 5Eh
    add cl, r9b
    sub cl, r8b
    xor cl, al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor cl, 2Dh
    sub cl, al
    mov rax, qword ptr [rbp+450h]
    mov byte ptr [rax], cl
    mov rdx, qword ptr [qword_7FF8571CFA00]
    mov rax, rdx
    mov rcx, rdx
    mov r8, -4D23509E78B08E1Ah
    xor rcx, r8
    mov r8, 4103008408908811h
    xor rax, r8
    mov r9, -53DF8EE58D958854h
    or rax, r9
    sub rax, rcx
    sub rax, rcx
    mov r8, rdx
    mov r10, 103008408908811h
    xor r8, r10
    mov r10, 13DF8EE58D958853h
    and r8, r10
    shl r8, 2
    sub rax, r8
    mov r8, rdx
    mov r10, -43F525E800613821h
    xor r8, r10
    add r8, rdx
    mov r10, 0C20501A70200608h
    xor rdx, r10
    and rdx, r9
    lea rdx, [rdx+rdx*2]
    sub rax, rdx
    add rax, -3
    sub r8, rax
    sub r8, rcx
    sub r8, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, 2CC7900BA2CF8CE8h
    add r8, rax
    cmp qword ptr [rbp+5F8h], r8
    jbe loc_7FF8569F96EA
    mov eax, dword ptr [dword_7FF857242AE8]
    lea ecx, [rax-5DA6C206h]
    mov edx, ecx
    xor edx, -1F03F4Ah
    sub edx, eax
    sub edx, ecx
    xor ecx, 5657E65Fh
    add edx, 7C254B0Ah
    xor edx, eax
    add edx, ecx
    jmp loc_7FF8569F05F9
    loc_7FF8569F89DA:
    cmp eax, 12DFC7CBh
    jnz loc_7FF8569F8A43
    mov rdx, qword ptr [rbp+160h]
    mov rcx, qword ptr [rbp+478h]
    mov r8, qword ptr [rbp+380h]
    call memcpy
    loc_7FF8569F89FB:
    mov rax, qword ptr [rbp+5C0h]
    mov rax, qword ptr [rax]
    test rax, rax
    js loc_7FF8569F9740
    mov eax, dword ptr [dword_7FF857242A24]
    mov ecx, eax
    xor ecx, -2F40FC8Eh
    lea edx, [rcx-2E4B14E3h]
    add ecx, -242C8232h
    xor edx, -4ECFF384h
    add edx, -7A17D82Bh
    xor ecx, eax
    xor ecx, edx
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF8569F8A43:
    mov rcx, qword ptr [rbp+2A0h]
    mov r8, qword ptr [rbp+5F0h]
    mov rdx, qword ptr [rbp+58h]
    call memcpy
    mov rax, qword ptr [rbp+138h]
    loc_7FF8569F8A61:
    mov qword ptr [rbp+298h], rax
    mov rax, qword ptr [rbp+298h]
    mov rcx, qword ptr [rbp+5F0h]
    mov byte ptr [rax+rcx], 0
    mov rax, qword ptr [rbp+5F0h]
    mov rcx, qword ptr [rbp+4B0h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+5D8h]
    mov rax, qword ptr [rax]
    mov qword ptr [rbp+3D0h], rax
    mov rax, qword ptr [qword_7FF8571CFAF8]
    mov rcx, rax
    not rcx
    mov rdx, rcx
    mov r8, 49515A8A83857490h
    and rdx, r8
    mov r8, rcx
    mov r9, 36AEA5757C7A8B6Fh
    and r8, r9
    or rcx, r9
    lea rcx, [rcx+rax*2]
    add rcx, r8
    lea rcx, [rcx+rdx*2]
    add rcx, 2
    mov rdx, 76CBC900E0D2421Dh
    xor rax, rdx
    add rax, rcx
    mov rdx, rcx
    mov rcx, -653319C869DA017Ch
    xor rdx, rcx
    mov rcx, -16F1C9FF49D87642h
    add rcx, rdx
    mov r8, rcx
    mov rsi, -27E6511649A81DE2h
    or r8, rsi
    lea r10, [rcx+rcx]
    mov r9, rcx
    mov r11, 27E6511649A81DE1h
    and r9, r11
    mov r11, rcx
    and r11, rsi
    lea r11, [r11+r11*2]
    lea r9, [r11+r9*2]
    sub r9, r10
    add r9, r8
    add rax, rdx
    mov r10, r9
    not r10
    mov rdx, rax
    or rdx, r10
    not rdx
    lea r8, [rdx+rdx*4]
    lea r8, [rdx+r8*4]
    mov r11, rax
    or r11, r9
    lea rdx, [r11+r11*4]
    lea rdx, [r11+rdx*2]
    not r11
    lea rdi, [r11+r11*4]
    lea r11, [r11+rdi*2]
    and r9, rax
    lea rdi, [r9+r9*8]
    not r9
    lea r14, [r9+r9*4]
    lea r9, [r9+r14*2]
    and r10, rax
    lea rax, [r10+r10*4]
    lea rax, [r10+rax*4]
    add rax, rdi
    sub rdx, rax
    mov r10, rcx
    not r10
    add rdx, r9
    sub rdx, r11
    sub rdx, r8
    mov rax, rdx
    or rax, r10
    mov r8, rdx
    or r8, rcx
    mov r9, rdx
    xor r9, rcx
    and r10, rdx
    and rdx, rcx
    shl r10, 2
    lea rcx, [r10+rdx*2]
    sub rcx, r9
    add r8, r8
    sub rcx, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rax, [rcx+rax*4]
    mov rcx, qword ptr [rbp+3D0h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp rcx, rax
    jge loc_7FF8569F96C5
    mov eax, dword ptr [dword_7FF857242A5C]
    lea ecx, [rax-47A0354Eh]
    mov edx, ecx
    xor edx, 421001F9h
    add edx, eax
    xor edx, ecx
    xor ecx, 43897983h
    sub edx, ecx
    jmp loc_7FF8569F05F9
    loc_7FF8569F9027:
    cmp eax, 738CE7Bh
    jnz loc_7FF8569F906E
    movzx eax, byte ptr [rbp+61Dh]
    mov byte ptr [rbp+633h], al
    mov eax, dword ptr [dword_7FF8572429E8]
    lea ecx, [rax+6EABABCCh]
    mov edx, ecx
    xor edx, -6E1BFAA2h
    lea r8d, [rdx+23B6F468h]
    xor ecx, eax
    xor ecx, r8d
    xor ecx, -824A7CFh
    add ecx, edx
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF8569F906E:
    mov rcx, qword ptr [qword_7FF8571CFCD0]
    mov rax, rcx
    mov rdx, 1D788A32F741E813h
    xor rax, rdx
    mov rdx, rcx
    mov r8, -7D79BA7BF751EC1Ch
    xor rdx, r8
    mov r8, rcx
    mov r9, 6001304900100408h
    xor r8, r9
    mov r9, 7D31B06BF4504418h
    and r8, r9
    lea r8, [r8+r8*2]
    mov r9, -7D31B06BF4504419h
    and rdx, r9
    lea rdx, [rdx+rdx*4]
    add rdx, r8
    mov r8, rcx
    mov r9, 60493A590311AC0Bh
    xor r8, r9
    add r8, r8
    mov r9, rax
    mov r10, 2CE4F940BAFBBE7h
    and r9, r10
    shl r9, 3
    sub r9, r8
    add r9, rdx
    mov rdx, -4314A0FDB43C98Ah
    sub rdx, r9
    xor rdx, rcx
    sub rdx, r9
    mov rcx, -6878BFE0E0057F66h
    add rdx, rcx
    xor rdx, rax
    cmp qword ptr [rbp-40h], rdx
    jle loc_7FF8569F9163
    mov eax, dword ptr [dword_7FF857242978]
    lea ecx, [rax-7B5E55B3h]
    xor ecx, -77865EE0h
    lea edx, [rcx+48FA8D9Fh]
    lea r8d, [rcx+28E031DEh]
    mov r9d, eax
    sub r9d, r8d
    add eax, r9d
    add eax, -5FF41664h
    xor eax, edx
    add eax, ecx
    add eax, ecx
    add eax, 28E031DEh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F9163:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jmp loc_7FF856A06409
    loc_7FF8569F91C3:
    cmp eax, 1740BAC4h
    jz loc_7FF856A00098
    loc_7FF8569F91CE:
    mov rax, qword ptr [rbp+220h]
    mov qword ptr [rbp+360h], rax
    mov rcx, qword ptr [qword_7FF8571CFB30]
    mov rax, rcx
    mov rdx, -2B177378E3B43951h
    xor rax, rdx
    mov rdx, 6AADBFD419AFE6Ah
    add rax, rdx
    mov r8, rax
    not r8
    mov r9, rax
    mov r10, 605349C30EA0D254h
    and r9, r10
    mov rdx, rax
    mov r11, -605349C30EA0D255h
    and rdx, r11
    sub rdx, r9
    mov r9, rax
    xor r9, r11
    lea r9, [r9+r9*2]
    add rdx, r9
    mov r9, rax
    or r9, r10
    and r8, r10
    sub rdx, r9
    add rdx, r8
    not r9
    shl r9, 2
    sub rdx, r9
    mov r8, -3AFB06650AB063A0h
    xor rax, r8
    add rax, rcx
    sub rax, rdx
    xor rax, rdx
    mov rcx, 0D8C8F93101DE7F3h
    xor rdx, rcx
    mov rcx, -3CACA95434EE39B6h
    add rcx, rdx
    xor rcx, rax
    mov rax, qword ptr [rbp+5C8h]
    mov r8, 1401E4F572F59117h
    xor rcx, r8
    sub rcx, rdx
    mov rdx, qword ptr [rbp+370h]
    mov rax, qword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rbp+5F0h], rcx
    setz byte ptr [rbp+637h]
    cmp rdx, rax
    jnb loc_7FF8569F9900
    mov eax, dword ptr [dword_7FF85724297C]
    mov ecx, -3F915C02h
    sub ecx, eax
    xor eax, -508666BFh
    lea edx, [rax-3C4528CFh]
    xor ecx, edx
    add ecx, -913D226h
    xor ecx, edx
    xor ecx, 206B7203h
    add ecx, eax
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF8569F93C3:
    mov rax, qword ptr [qword_7FF8571CFCF0]
    mov rcx, -54AFBF643780C087h
    add rcx, rax
    mov r8, rcx
    mov r11, 0F245911181BFE47h
    or r8, r11
    mov rdx, rcx
    mov rsi, -0F245911181BFE48h
    or rdx, rsi
    mov r9, rcx
    xor r9, r11
    add r9, rdx
    lea r10, [rcx+rcx]
    mov rdx, rcx
    and rdx, r11
    lea r11, [rdx+rdx*2]
    mov rdx, rcx
    and rdx, rsi
    lea rdx, [rdx+rdx*2]
    add rdx, r11
    sub rdx, r10
    add rdx, r9
    sub rdx, r8
    mov r8, rdx
    mov r9, 1E7AA22BCD7489FAh
    xor r8, r9
    mov r9, -7C52395584A09ECDh
    add r8, r9
    mov r9, r8
    mov r10, 41F0A69E6F8F42B7h
    xor r9, r10
    mov r10, 8AF9C50C5E9AE78h
    add r10, r9
    mov r11, r10
    mov rsi, -1C9F7A44B67B75E8h
    xor r11, rsi
    sub r11, r8
    xor r10, rcx
    xor r10, r9
    xor r10, r11
    mov rcx, -6BCAA356C87D54DDh
    xor r10, rcx
    add r10, rdx
    xor r10, rax
    mov rax, qword ptr [rbp+5B0h]
    cmp qword ptr [rax], r10
    jle loc_7FF856A08345
    mov eax, dword ptr [dword_7FF857242984]
    mov ecx, 6A429590h
    add eax, ecx
    mov ecx, eax
    xor ecx, -7685C135h
    xor eax, 76474D62h
    sub eax, ecx
    add eax, 4EE77A9Ch
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F94C9:
    mov rdx, qword ptr [qword_7FF8571CFA98]
    mov rax, -549C84692009AD6h
    lea rcx, [rdx+rax]
    mov rax, rcx
    mov r8, -6BA24B897C2AE8B3h
    xor rax, r8
    mov r8, 23C001CBD46F9F41h
    add r8, rax
    mov r9, r8
    not r9
    mov r10, r9
    mov r11, 1BD0C9B2B35437A5h
    and r10, r11
    mov r11, r9
    mov rdi, 642F364D4CABC85Ah
    and r11, rdi
    or r9, rdi
    lea r9, [r9+r8*2]
    add r9, r11
    lea r11, [r9+r10*2]
    lea r9, [r9+r10*2]
    add r9, 2
    mov r10, 499FEB131D2C6425h
    add r10, rax
    mov rdi, -281E434A7DCE12Ch
    xor r10, rdi
    xor r9, r10
    sub r9, r8
    add r9, rdx
    xor r9, rcx
    sub r9, rax
    lea rax, [r9+r11]
    add rax, 2
    mov rcx, qword ptr [rbp+448h]
    mov rdx, -0D509CC17782649Ah
    add rax, rdx
    and rax, qword ptr [rbp+1C0h]
    mov qword ptr [rbp+0E8h], rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rbp+5B0h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+448h]
    jmp loc_7FF8569FFE29
    loc_7FF8569F96C5:
    mov eax, dword ptr [dword_7FF857242938]
    lea ecx, [rax+78A22822h]
    xor eax, ecx
    xor eax, 37509AC7h
    add eax, ecx
    add eax, 12A11514h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F96EA:
    mov eax, dword ptr [dword_7FF857242948]
    lea ecx, [rax+1F869D2Eh]
    xor ecx, 3BD595E2h
    lea edx, [rcx+348B5E68h]
    xor edx, -7C2CE42Eh
    lea r8d, [rdx-1F049A5Ch]
    lea r9d, [rdx+rax]
    add r9d, -1F049A5Ch
    sub edx, r9d
    add eax, edx
    add eax, 1F869D2Eh
    add eax, ecx
    add eax, 348B5E68h
    sub eax, r8d
    add eax, ecx
    add eax, -0CC19D98h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569F9740:
    mov qword ptr [rbp+228h], rax
    mov rax, qword ptr [rbp+478h]
    mov rdx, qword ptr [qword_7FF8571CFB70]
    mov rcx, 0FFE749EDC52E483h
    xor rdx, rcx
    mov rcx, 3F98B073FBC02459h
    lea r8, [rdx+rcx]
    mov rcx, r8
    not rcx
    mov r9, r8
    mov r11, 7A2A2BA88F7A0B2Ch
    and r9, r11
    lea r9, [r9+r9*2]
    mov r10, rcx
    and r10, r11
    lea r10, [r10+r10*4]
    add r10, r9
    lea r9, [rcx+rcx*4]
    mov r11, 5D5D4577085F4D3h
    xor r8, r11
    add r8, r8
    and rcx, r11
    shl rcx, 3
    sub rcx, r8
    add rcx, r10
    sub rcx, r9
    mov r8, -10C5F82DF1169AD1h
    add r8, rdx
    add rcx, r8
    xor rcx, rdx
    and rcx, qword ptr [rbp+228h]
    mov qword ptr [rbp+160h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+5C0h]
    mov qword ptr [rax], rcx
    mov rax, qword ptr [rbp+478h]
    jmp loc_7FF856A010C7
    loc_7FF8569F9900:
    mov eax, dword ptr [dword_7FF857242A64]
    lea ecx, [rax+321AC9C1h]
    mov edx, ecx
    xor edx, -33AC4D17h
    mov r8d, ecx
    xor r8d, -44493DE3h
    xor ecx, -35CB700Eh
    add r8d, 4E7C4DC5h
    jmp loc_7FF856A05D8F
    loc_7FF8569F9930:
    mov rdx, qword ptr [rbp+550h]
    mov rcx, qword ptr [rbp+440h]
    mov r8, qword ptr [rbp+320h]
    call memcpy
    loc_7FF8569F994A:
    mov rax, qword ptr [rbp+628h]
    mov rax, qword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    test rax, rax
    js loc_7FF856A05E05
    mov rdx, qword ptr [rbp+550h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569F9A43:
    mov rcx, r12
    call qword ptr [rax+30h]
    loc_7FF8569F9A49:
    mov rax, qword ptr [rbp+628h]
    mov rax, qword ptr [rax]
    mov qword ptr [rbp+1B0h], rax
    loc_7FF8569F9A5A:
    mov rax, qword ptr [rbp+1B0h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rbp+440h]
    mov qword ptr [rbp+550h], rcx
    mov r9, qword ptr [qword_7FF8571CFA50]
    mov rcx, r9
    not rcx
    mov rdx, rcx
    mov r11, 44383144CD36836Eh
    and rdx, r11
    lea rdx, [rdx+rdx*2]
    mov r8, rcx
    mov r10, 3BC7CEBB32C97C91h
    and r8, r10
    shl r8, 2
    or rcx, r11
    sub rcx, r9
    sub rcx, r9
    sub rcx, r8
    sub rcx, rdx
    add rcx, -3
    mov rdx, rcx
    mov r8, -4B2A5BA79D120767h
    xor rdx, r8
    mov r8, -6B51F34CA4AB33C4h
    add r8, rdx
    mov r10, r8
    mov r11, r8
    mov rsi, -355A0F272540B6D9h
    and r11, rsi
    lea r11, [r11+r11*2]
    mov rdi, r8
    mov rbx, 355A0F272540B6D8h
    and rdi, rbx
    sub r11, rdi
    add r11, r8
    not r8
    or r10, rsi
    and r8, rsi
    lea r8, [r8+r8*2]
    add r8, r10
    add r8, r11
    mov r10, -5FF1D28A903DDB74h
    add r8, r10
    mov r10, r8
    mov r11, 5CF44E1EA35DB9E4h
    xor r10, r11
    mov r11, 49582B9F701504B7h
    sub r11, r10
    xor r11, r9
    mov r9, rcx
    not r9
    mov rdi, r11
    or rdi, r9
    mov r14, r11
    or r14, rcx
    not r14
    lea r14, [r14+r14*2]
    add r14, rdi
    lea rdi, [r9+r9*2]
    and r9, r11
    lea r9, [r9+r9*2]
    and rcx, r11
    sub r9, rcx
    add r9, r11
    add r9, r14
    sub r9, rdi
    mov rcx, 73164359C394AA19h
    add rcx, rdx
    xor r8, rcx
    inc r9
    xor r8, r9
    add r8, rdx
    sub r8, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, 5EA53F5A04A2D555h
    add r8, rcx
    and r8, rax
    mov rax, qword ptr [rbp+628h]
    mov qword ptr [rax], r8
    mov rax, qword ptr [rbp+440h]
    mov qword ptr [rbp+1B8h], rax
    loc_7FF8569F9EC3:
    mov rax, qword ptr [rbp+1B8h]
    mov qword ptr [rbp+328h], rax
    mov rax, qword ptr [qword_7FF8571CFA58]
    mov rcx, rax
    not rcx
    mov rdx, 6F4050690E27DDA2h
    and rcx, rdx
    lea rcx, [rcx+rcx*4]
    mov rdx, rax
    mov r10, -10BFAF96F1D8225Eh
    or rdx, r10
    lea rdx, [rdx+rdx*2]
    mov r8, rax
    mov r9, 10BFAF96F1D8225Dh
    and r8, r9
    mov r9, rax
    and r9, r10
    lea r9, [r9+r9*8]
    lea r8, [r9+r8*4]
    sub r8, rdx
    lea rcx, [r8+rcx*2]
    mov rdx, 647E1D89AB10CE34h
    add rdx, rcx
    add rdx, rdx
    mov r8, -1350464685E826A0h
    add r8, rcx
    mov r9, 76612251ED8FA853h
    add r9, rcx
    mov r10, 50BF0FCB4BE955A3h
    add rcx, r10
    mov r10, rcx
    mov r11, -166692DAB3B6C481h
    xor r10, r11
    sub rdx, r10
    mov r10, -2B2F5F798F322A5h
    add rdx, r10
    xor rdx, r9
    mov r9, r8
    not r9
    mov r10, rdx
    or r10, r9
    mov r11, rdx
    or r11, r8
    mov rdi, rdx
    xor rdi, r8
    and r9, rdx
    and rdx, r8
    shl r9, 2
    lea rdx, [r9+rdx*2]
    sub rdx, rdi
    add r11, r11
    sub rdx, r11
    not r10
    lea rdx, [rdx+r10*4]
    add rdx, rax
    mov rax, qword ptr [rbp+608h]
    xor rdx, rcx
    mov rcx, qword ptr [rbp+330h]
    mov rax, qword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rbp+5F8h], rdx
    setz byte ptr [rbp+636h]
    cmp rcx, rax
    jnb loc_7FF8569FA2FE
    mov eax, dword ptr [dword_7FF857242AD4]
    lea ecx, [rax+5B3D0D6Ah]
    xor eax, ecx
    xor ecx, -7CF90B73h
    xor eax, -647AB01Ah
    add eax, ecx
    add eax, -77E1C323h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569FA2FE:
    cmp byte ptr [rbp+636h], 0
    jz loc_7FF856A05311
    mov eax, dword ptr [dword_7FF857242AD0]
    lea ecx, [rax-89AFFB5h]
    xor ecx, 7D5B5BA1h
    add ecx, 51DBD7C8h
    xor ecx, -705BDD6h
    jmp loc_7FF856A068ED
    loc_7FF8569FA32E:
    mov rax, qword ptr [rbp+318h]
    loc_7FF8569FA335:
    mov qword ptr [rbp+1A0h], rax
    mov rax, qword ptr [rbp+1A0h]
    mov qword ptr [rbp+300h], rax
    mov rcx, qword ptr [rbp+5C8h]
    mov rax, qword ptr [rbp+310h]
    mov rcx, qword ptr [rcx]
    mov rdx, qword ptr [qword_7FF8571CF9E0]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, 2042F70E99FC8C84h
    add r8, rdx
    mov r9, r8
    not r9
    mov r10, r8
    mov r11, -7242D215AD29629Fh
    and r10, r11
    lea r10, [r10+r10*2]
    mov r11, r9
    mov rsi, 0DBD2DEA52D69D61h
    and r11, rsi
    shl r11, 2
    mov rsi, 7242D215AD29629Eh
    and r9, rsi
    mov rdi, r9
    not rdi
    add r9, r9
    and r8, rsi
    lea r8, [r9+r8*2]
    sub rdi, r8
    sub rdi, r11
    sub rdi, r10
    mov r8, 6BA7F81F82A19740h
    add r8, rdx
    add rdi, r8
    xor rdi, rdx
    cmp qword ptr [rbp+5E8h], rdi
    setz byte ptr [rbp+635h]
    cmp rax, rcx
    jnb loc_7FF8569FA491
    mov eax, dword ptr [dword_7FF857242918]
    lea ecx, [rax-286D82FCh]
    xor ecx, 2D80E0F5h
    add ecx, eax
    add ecx, eax
    add ecx, eax
    add ecx, -40C508BEh
    add eax, ecx
    add eax, -5C86F7DCh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569FA491:
    cmp byte ptr [rbp+635h], 0
    jz loc_7FF856A05E5C
    mov eax, dword ptr [dword_7FF857242A34]
    mov ecx, eax
    xor ecx, -4953DAC0h
    lea edx, [rcx+rcx]
    sub edx, eax
    add edx, -4AAF4FE6h
    xor edx, eax
    xor edx, -19E6DC23h
    lea eax, [rcx+rdx]
    add eax, 66384F79h
    add ecx, 6B28A648h
    jmp loc_7FF856A06155
    loc_7FF8569FA4D2:
    mov eax, dword ptr [rbp+408h]
    jmp loc_7FF8569FC207
    loc_7FF8569FA4DD:
    mov rax, qword ptr [rbp+530h]
    jmp loc_7FF856A03637
    loc_7FF8569FA4E9:
    mov rax, qword ptr [rbp+578h]
    mov rdx, qword ptr [rax]
    mov rcx, qword ptr [rbp+4B8h]
    mov r8, qword ptr [rbp+3D8h]
    call memcpy
    loc_7FF8569FA506:
    mov rax, qword ptr [qword_7FF8571CFCB8]
    mov rcx, -1BA0A0AE8C65CCFEh
    lea rdx, [rax+rcx]
    mov r8, rdx
    not r8
    mov r9, r8
    mov rsi, -4AF2FDB9E8228739h
    and r9, rsi
    mov r11, 4AF2FDB9E8228738h
    and r8, r11
    add r8, r8
    mov rcx, rdx
    xor rcx, r11
    mov r10, rdx
    and r10, r11
    mov r11, rdx
    and r11, rsi
    lea r10, [r11+r10*2]
    sub r10, rdx
    lea rcx, [r10+rcx*2]
    sub rcx, r8
    add rcx, r9
    mov r8, rcx
    mov r9, -1FB2661131D09DBh
    xor r8, r9
    sub r8, rdx
    mov rdx, 1D1E2FF1145ED426h
    add r8, rdx
    mov rdx, rcx
    not rdx
    mov r9, r8
    or r9, rdx
    lea r10, [r9+r9*4]
    lea r10, [r9+r10*2]
    not r9
    lea r11, [r9*8]
    sub r11, r9
    mov rdi, r8
    or rdi, rcx
    not rdi
    mov r9, rdi
    shl r9, 4
    add r9, rdi
    add r9, r11
    and rdx, r8
    and r8, rcx
    lea rcx, [r8+r8*8]
    lea rcx, [r8+rcx*2]
    lea r8, [rdx+rdx*2]
    lea rcx, [rcx+r8*4]
    sub rcx, r10
    not rdx
    add rdx, rdx
    lea rdx, [rdx+rdx*2]
    sub rcx, rdx
    add r9, rax
    add r9, rcx
    mov rax, qword ptr [rbp+4E0h]
    mov rax, qword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, -3A87EA4091DFA9CEh
    add r9, rcx
    cmp rax, r9
    jle loc_7FF8569FE958
    mov eax, dword ptr [dword_7FF8572429DC]
    lea ecx, [rax-38BCA734h]
    xor ecx, -0AC35FFDh
    add eax, ecx
    add eax, 24F90426h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569FA82F:
    mov rax, qword ptr [rbp+4D8h]
    not rax
    lea rcx, [rax+rax*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+4D8h]
    mov rdx, rax
    not rdx
    mov r8d, edx
    and r8d, 1
    lea r8, [r8+r8*2]
    and rdx, -2
    lea rdx, [rdx+rdx*2]
    mov r9, rax
    xor r9, 1
    lea r10, [r9*8]
    sub r10, r9
    add r10, rdx
    mov rdx, rax
    mov r9, 7FFFFFFFFFFFFFFEh
    and rdx, r9
    add rdx, rdx
    lea rdx, [rdx+rdx*2]
    and eax, 1
    add rax, rax
    sub rax, rdx
    add rax, r10
    sub rax, r8
    sub rax, rcx
    mov qword ptr [rbp+60h], rax
    mov rcx, qword ptr [rbp+528h]
    sub rcx, rax
    mov qword ptr [rbp+5F0h], rcx
    add rax, qword ptr [rbp+530h]
    mov qword ptr [rbp+58h], rax
    lea rax, [rbp+140h]
    mov qword ptr [rbp+4B0h], rax
    mov qword ptr [rbp+140h], 0
    lea rax, [rbp+150h]
    mov qword ptr [rbp+4A8h], rax
    mov qword ptr [rbp+138h], rax
    lea rax, [rbp+148h]
    mov qword ptr [rbp+5D8h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+5D8h]
    mov rcx, -7FFFFFFFFFFFFFF1h
    mov qword ptr [rax], rcx
    movzx eax, byte ptr [byte_7FF8571CFAD0]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ecx, [rax-12h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edx, ecx
    xor dl, 33h
    mov r8d, ecx
    xor r8b, 3Fh
    sub r8b, al
    add r8b, dl
    add dl, 0AAh
    xor r8b, dl
    sub r8b, al
    add r8b, 3Bh
    xor r8b, cl
    xor r8b, 0BBh
    sub r8b, dl
    add r8b, 62h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+4A8h]
    mov byte ptr [rax], r8b
    cmp qword ptr [rbp+5F0h], 0Fh
    jbe loc_7FF856A05F97
    mov rax, qword ptr [rbp+5F0h]
    cmp rax, 17h
    mov ecx, 16h
    cmovb rax, rcx
    loc_7FF8569FAB24:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [qword_7FF8571CFAD8]
    mov rdx, -44DA11B6E15DF7AEh
    lea r8, [rcx+rdx]
    mov r9, r8
    not r9
    mov rdx, r8
    mov rsi, 0A31D71EBB78EC56h
    or rdx, rsi
    lea r10, [rdx+rdx*4]
    lea r10, [rdx+r10*2]
    not rdx
    lea r11, [rdx*8]
    sub r11, rdx
    and r9, rsi
    mov rdx, r9
    shl rdx, 4
    add rdx, r9
    mov r9, r8
    and r9, rsi
    lea rdi, [r9+r9*2]
    not r9
    add r9, r9
    lea r9, [r9+r9*2]
    mov rsi, -0A31D71EBB78EC57h
    and r8, rsi
    lea r14, [r8+r8*8]
    lea r8, [r8+r14*2]
    lea r8, [r8+rdi*4]
    sub r8, r10
    sub r8, r9
    add rdx, r11
    add rdx, r8
    mov r8, -627841BDEBEF05F1h
    add r8, rdx
    mov r11, r8
    not r11
    lea r9, [r11+r11*2]
    mov r10, r11
    mov rbx, 5BE2CCEA5B2CEE1h
    and r10, rbx
    lea r10, [r10+r10*2]
    mov rsi, -5BE2CCEA5B2CEE2h
    and r11, rsi
    lea r11, [r11+r11*2]
    mov rdi, r8
    xor rdi, rbx
    lea r14, [rdi*8]
    sub r14, rdi
    mov rdi, r8
    mov rsi, 7A41D3315A4D311Eh
    and rdi, rsi
    add rdi, rdi
    lea rdi, [rdi+rdi*2]
    mov rsi, r12
    mov r12, r8
    and r12, rbx
    add r12, r12
    sub r12, rdi
    add r14, r11
    add r14, r12
    sub r10, r14
    mov r11, -7FE7C69AB47103E0h
    add r9, r11
    add r9, r10
    mov r10, rcx
    not r10
    mov r11, r9
    or r11, r10
    lea rdi, [r11+r11*4]
    lea rdi, [r11+rdi*2]
    not r11
    lea r14, [r11*8]
    sub r14, r11
    mov r12, r9
    or r12, rcx
    not r12
    mov r11, r12
    shl r11, 4
    add r11, r12
    and r10, r9
    and r9, rcx
    lea r12, [r9+r9*8]
    lea r9, [r12]
    lea r12, [r10+r10*2]
    lea r9, [r12]
    mov r12, rsi
    sub r9, rdi
    not r10
    add r10, r10
    lea r10, [r10+r10*2]
    sub r9, r10
    add r11, r14
    mov r10, 4BFE40B3EE29B533h
    add r10, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r11, r9
    sub r11, rcx
    mov rcx, 6097B8B15D231967h
    add r8, rcx
    add r8, r11
    xor r8, r10
    mov rcx, rdx
    not rcx
    mov r9, r8
    or r9, rcx
    not r9
    lea r9, [r9+r9*2]
    mov r10, r8
    or r10, rdx
    not r10
    shl r10, 2
    and rcx, r8
    mov r11, rcx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rcx, rcx
    and r8, rdx
    lea rcx, [rcx+r8*2]
    sub r11, rcx
    sub r11, r10
    sub r11, r9
    add r11, -3
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or r11, rax
    mov rcx, qword ptr [rbp+5D8h]
    mov qword ptr [rcx], r11
    mov rdx, qword ptr [qword_7FF8571CFAE0]
    mov rcx, -1B1E61D53C14B3DAh
    xor rdx, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, -2DACCC1A7E98A1CEh
    add rcx, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, rcx
    mov r9, -889413B790CB01Ch
    xor r8, r9
    mov r9, 4E9C0442052C5080h
    add r9, r8
    mov r10, 251BA3FF7354D7E6h
    add rdx, r10
    xor rdx, r8
    mov r10, 5BB2A898059FC783h
    add r8, r10
    xor rdx, r9
    add rdx, rcx
    xor rdx, r8
    add rdx, rax
    mov rcx, qword ptr [qword_7FF8571CFAE8]
    mov rax, 7FD4DD20A57E66CAh
    xor rcx, rax
    mov rax, 6410555F8F695E84h
    add rax, rcx
    mov r8, rax
    mov rsi, 62B60151D2EDE633h
    or r8, rsi
    mov r9, rax
    mov rdi, -62B60151D2EDE634h
    or r9, rdi
    mov r10, rax
    and r10, rsi
    lea r10, [r10+r10*2]
    mov r11, rax
    and r11, rdi
    lea r11, [r11+r11*2]
    add r11, r10
    sub r11, rax
    sub r11, rax
    mov r10, rax
    xor r10, rsi
    add r10, r9
    add r10, r11
    sub r8, r10
    mov r9, 1778BC9B39D5E818h
    add r8, r9
    xor r8, rcx
    mov r9, rax
    not r9
    mov rcx, r8
    or rcx, r9
    mov r10, r8
    or r10, rax
    mov r11, r8
    xor r11, rax
    and r9, r8
    and r8, rax
    sub r8, r9
    lea rax, [r11+r11*2]
    add r8, rax
    not r10
    sub r8, rcx
    add r8, r10
    not rcx
    shl rcx, 2
    sub r8, rcx
    mov rax, qword ptr [off_7FF8571A2640]
    mov rax, qword ptr [rax+10h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FF8569FB6E4:
    mov rcx, r12
    call rax
    mov qword ptr [rbp+468h], rax
    mov rax, qword ptr [rbp+4B0h]
    mov r8, qword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc r8
    mov rax, qword ptr [qword_7FF8571CFAF0]
    mov rcx, 72A2977BE303EB4Ch
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
    mov rdx, -775B254725C4E26Ah
    add rdx, rax
    xor rcx, rdx
    mov r9, 6A7B3EC0D4C27D81h
    xor rdx, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9, 7490886B5152697Dh
    add rdx, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9, -0B4D09F18618EFB2h
    xor rcx, r9
    xor rcx, rdx
    add rcx, rax
    cmp r8, rcx
    jnz loc_7FF856A08098
    mov eax, dword ptr [dword_7FF85724294C]
    lea ecx, [rax-53AEC635h]
    lea edx, [rax-12B26345h]
    mov r8d, edx
    xor r8d, 2A8A0296h
    xor edx, 23461067h
    xor ecx, -71B78A43h
    add ecx, r8d
    add ecx, eax
    add ecx, -12B26345h
    sub ecx, edx
    xor ecx, eax
    add eax, ecx
    add eax, 4B01EA4h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569FB8ED:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rbp+138h]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569FB937:
    mov rcx, r12
    call qword ptr [rax+30h]
    mov eax, dword ptr [dword_7FF857242964]
    mov ecx, eax
    xor ecx, 43E9EF5Ah
    lea edx, [rcx-2B57D3A3h]
    lea r8d, [rcx-2A27E6C9h]
    mov r9d, r8d
    xor r9d, 562510FEh
    sub r9d, ecx
    add r9d, eax
    xor r9d, edx
    add r9d, ecx
    sub r9d, r8d
    add r9d, -175E172Ch
    mov dword ptr [rbp+63Ch], r9d
    jmp loc_7FF8569F0600
    loc_7FF8569FB984:
    mov rax, qword ptr [qword_7FF8571CFA60]
    mov rcx, -3E00DC18677953A8h
    add rcx, rax
    mov rdx, rcx
    not rdx
    lea r8, [rdx+rdx*2]
    mov r9, rdx
    mov rsi, 3BD563FEC2425901h
    and r9, rsi
    lea r9, [r9+r9*2]
    mov r10, -3BD563FEC2425902h
    and rdx, r10
    lea rdx, [rdx+rdx*2]
    mov r10, rcx
    xor r10, rsi
    lea r11, [r10*8]
    sub r11, r10
    add r11, rdx
    mov rdx, rcx
    mov r10, 442A9C013DBDA6FEh
    and rdx, r10
    add rdx, rdx
    lea r10, [rdx+rdx*2]
    mov rdx, rcx
    and rdx, rsi
    add rdx, rdx
    sub rdx, r10
    add rdx, r11
    sub rdx, r9
    sub rdx, r8
    mov r8, -6BBA0249C47E67F1h
    lea r10, [rdx+r8]
    mov r8, r10
    not r8
    mov rsi, -7F064C2F27C22CC6h
    and r8, rsi
    lea r9, [r8+r8*4]
    lea r9, [r8+r9*4]
    mov r11, r10
    or r11, rsi
    lea r8, [r11+r11*4]
    lea r8, [r11+r8*2]
    not r11
    lea rdi, [r11+r11*4]
    lea r11, [r11+rdi*2]
    mov rdi, r10
    and rdi, rsi
    lea rbx, [rdi+rdi*8]
    not rdi
    lea r14, [rdi+rdi*4]
    lea rdi, [rdi+r14*2]
    mov rsi, 7F064C2F27C22CC5h
    and r10, rsi
    lea r14, [r10+r10*4]
    lea r10, [r10+r14*4]
    add r10, rbx
    sub r8, r10
    add r8, rdi
    sub r8, r11
    sub r8, r9
    mov r9, r8
    mov r10, 31881FD1908B27Fh
    xor r9, r10
    sub r9, rdx
    sub r9, rdx
    sub r9, rcx
    mov rcx, 6713EFAE408A6431h
    add r9, rcx
    xor r9, rax
    mov rcx, r9
    mov rax, r9
    lea rdx, [r9+r9]
    and r9, r8
    add r9, r9
    sub rdx, r9
    mov r9, r8
    not r9
    or rcx, r9
    or rax, r8
    not rax
    add rax, rcx
    add rax, rdx
    sub rax, r9
    mov rcx, -13E25DC056E25CAh
    xor r8, rcx
    sub rax, r8
    mov rcx, qword ptr [rbp+628h]
    mov rcx, qword ptr [rcx]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc rax
    cmp rcx, rax
    jle loc_7FF856A0601F
    mov rdx, qword ptr [rbp+550h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569FBE39:
    mov rcx, r12
    call qword ptr [rax+30h]
    mov rax, qword ptr [rbp+5B8h]
    mov rax, qword ptr [rax]
    mov rcx, qword ptr [rbp+4C8h]
    mov rcx, qword ptr [rcx]
    mov qword ptr [rbp+1D8h], rcx
    mov qword ptr [rbp+1D0h], rax
    loc_7FF8569FBE61:
    mov rax, qword ptr [rbp+1D8h]
    mov rcx, qword ptr [rbp+0C0h]
    mov qword ptr [rbp+550h], rcx
    mov rcx, qword ptr [rbp+608h]
    mov rdx, qword ptr [rbp+1D0h]
    and rdx, r13
    mov qword ptr [rcx], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+628h]
    mov qword ptr [rax], rdx
    jmp loc_7FF8569FEFF3
    loc_7FF8569FBEDA:
    mov rbx, qword ptr [rbp+6B0h]
    lea rax, [rbx+38h]
    mov qword ptr [rbp+98h], rax
    mov dword ptr [rbx+38h], 0
    lea rax, [rbx+30h]
    mov qword ptr [rbp+610h], rax
    mov eax, dword ptr [rbx+30h]
    lea rcx, [rbx+3Ch]
    mov qword ptr [rbp+90h], rcx
    mov dword ptr [rbx+3Ch], 0
    lea rcx, [rbx+48h]
    mov qword ptr [rbp+88h], rcx
    mov dword ptr [rbx+48h], 0
    mov ecx, dword ptr [dword_7FF8571CF8E0]
    lea edx, [rcx-2B0CF54Ch]
    xor edx, 1D182AD2h
    lea r9d, [rdx+43705247h]
    mov r10d, r9d
    not r10d
    lea r8d, [r10*8]
    sub r8d, r10d
    mov r11d, r10d
    and r11d, 37A7EF9Bh
    lea r11d, [r11+r11*8]
    and r10d, 48581064h
    add r10d, r10d
    lea edi, [r10+r10*4]
    mov r10d, r9d
    and r10d, 37A7EF9Bh
    mov r14d, r10d
    not r14d
    lea r14d, [r14+r14*2]
    sub edx, r9d
    and r9d, 48581064h
    add r9d, r9d
    add r10d, r10d
    sub r10d, r9d
    add r10d, r14d
    sub r10d, edi
    sub r10d, r11d
    add r10d, r8d
    add ecx, edx
    add ecx, -2B0CF54Ch
    add ecx, r10d
    add ecx, 2FE01C39h
    xor ecx, r10d
    and ecx, eax
    mov dword ptr [rbp+408h], ecx
    mov rax, qword ptr [rbp+610h]
    mov dword ptr [rax], ecx
    lea rax, [rbx+40h]
    mov qword ptr [rbp+548h], rax
    mov rax, qword ptr [rbx+40h]
    cmp rax, qword ptr [qword_7FF8572A3878]
    jz loc_7FF856A07F6F
    mov rcx, qword ptr [rax]
    movzx r12d, byte ptr [byte_7FF8571CF8E4]
    lea r10d, [r12+39h]
    lea r9d, [r12-32h]
    mov r8d, r9d
    mov edx, r9d
    mov r11d, r9d
    mov r14b, 23h
    sub r14b, r12b
    mov ebx, r10d
    not bl
    mov edi, r14d
    or dil, bl
    mov r12d, r14d
    xor r12b, r10b
    movzx r12d, r12b
    mov r13d, r14d
    lea r12d, [r12]
    and bl, r14b
    and r14b, r10b
    sub r14b, bl
    add r14b, r12b
    sub r14b, dil
    not dil
    shl dil, 2
    or r13b, r10b
    not r13b
    add r14b, r13b
    lea r12, off_7FF8571A2640
    mov r13, 7FFFFFFFFFFFFFFFh
    sub r14b, dil
    sub r14b, r9b
    not r9b
    mov r10d, r9d
    and r10b, 0EEh
    movzx r10d, r10b
    lea edi, [r10+r10*4]
    lea r10d, [r10+rdi*2]
    or r8b, 0EEh
    and dl, 11h
    and r11b, 0EEh
    movzx r11d, r11b
    imul r11d, 0F5h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add dl, r8b
    add dl, r11b
    sub dl, r10b
    add dl, r9b
    add dl, 3Bh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r14b, dl
    mov byte ptr [rcx], r14b
    mov rcx, qword ptr [qword_7FF8571CF8E8]
    mov rdx, rcx
    mov r8, 1048E1078EC7CF7Dh
    xor rdx, r8
    sub rcx, rdx
    mov r8, -376A83079F5615B2h
    add rcx, r8
    mov r8, -612B55026930FE9Bh
    xor rdx, r8
    xor rdx, rcx
    mov qword ptr [rax+8], rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+610h]
    mov eax, dword ptr [rax]
    loc_7FF8569FC207:
    mov dword ptr [rbp+514h], eax
    mov eax, dword ptr [dword_7FF8571CF8F0]
    mov ecx, eax
    xor ecx, 73BAB67Ah
    mov edx, -9950764h
    sub edx, ecx
    xor edx, ecx
    xor edx, -524D7F76h
    add edx, eax
    and edx, dword ptr [rbp+514h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+610h]
    mov dword ptr [rax], edx
    lea rax, [rbp+0F0h]
    mov qword ptr [rbp+540h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+540h]
    mov qword ptr [rax], 0
    lea rax, [rbp+100h]
    mov qword ptr [rbp+0E8h], rax
    lea rax, [rbp+0F8h]
    mov qword ptr [rbp+5B0h], rax
    mov rax, -7FFFFFFFFFFFFFF1h
    mov qword ptr [rbp+0F8h], rax
    mov byte ptr [rbp+100h], 0
    mov rcx, qword ptr [rbp+0B8h]
    mov rax, qword ptr [rcx+8]
    mov qword ptr [rbp+5E0h], rax
    mov rax, qword ptr [rcx]
    mov qword ptr [rbp+80h], rax
    lea rax, [rbp+558h]
    mov qword ptr [rbp+608h], rax
    mov qword ptr [rbp+558h], 0
    lea rax, [rbp+568h]
    mov qword ptr [rbp+4C0h], rax
    mov qword ptr [rbp+550h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [qword_7FF8571CF8F8]
    mov rax, 47D40F47DB5D7235h
    lea r8, [rcx+rax]
    mov rax, r8
    mov rdx, 4F4A96BA220521C9h
    xor r8, rdx
    mov r9, rcx
    not r9
    mov rdx, r8
    or rdx, r9
    mov r10, r8
    and r9, r8
    and r8, rcx
    lea r8, [r8+r8*2]
    lea r8, [r8+r9*4]
    or r10, rcx
    lea r9, [r10+r10*4]
    sub r9, r8
    sub r9, rcx
    sub r9, rcx
    not rdx
    shl rdx, 2
    sub r9, rdx
    sub r9, rcx
    lea rcx, [rbp+560h]
    mov qword ptr [rbp+628h], rcx
    mov rcx, 39294048DEDB950h
    xor rax, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r9, rax
    mov rax, -4B1FAEE542A3FE10h
    add r9, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+628h]
    mov qword ptr [rax], r9
    mov rax, qword ptr [rbp+4C0h]
    mov byte ptr [rax], 0
    cmp qword ptr [rbp+5E0h], 0Fh
    jbe loc_7FF856A052EA
    mov eax, dword ptr [dword_7FF857242B20]
    add eax, eax
    mov ecx, -4D5C37D6h
    loc_7FF8569FC6BF:
    sub ecx, eax
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF8569FC6CC:
    mov rdx, qword ptr [rbp+4E8h]
    mov rax, qword ptr [off_7FF8571A2640]
    mov rax, qword ptr [rax+30h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FF8569FC724:
    mov rcx, r12
    call rax
    mov rax, qword ptr [rbp+5D8h]
    mov rax, qword ptr [rax]
    mov rcx, qword ptr [rbp+4B0h]
    mov rcx, qword ptr [rcx]
    mov qword ptr [rbp+290h], rcx
    mov qword ptr [rbp+288h], rax
    loc_7FF8569FC74B:
    mov rax, qword ptr [rbp+290h]
    mov rcx, qword ptr [rbp+138h]
    mov qword ptr [rbp+4E8h], rcx
    mov rcx, qword ptr [rbp+5C8h]
    mov rdx, qword ptr [rbp+288h]
    and rdx, r13
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+620h]
    mov qword ptr [rax], rdx
    jmp loc_7FF856A009C6
    loc_7FF8569FC783:
    mov rax, qword ptr [rbp+5E0h]
    cmp rax, qword ptr [rbp+28h]
    jnz loc_7FF856A06047
    mov eax, dword ptr [dword_7FF857242A88]
    mov ecx, -4B320D22h
    jmp loc_7FF856A0521B
    loc_7FF8569FC7A4:
    mov rax, qword ptr [rbp+548h]
    mov rax, qword ptr [rax]
    mov rax, qword ptr [rax]
    mov qword ptr [rbp+2D0h], rax
    loc_7FF8569FC7B8:
    mov r8, qword ptr [rbp+2D0h]
    mov r9, qword ptr [rbp+0E8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [qword_7FF8571CFC60]
    mov rax, 3D2C3F962E66CDF2h
    add rax, rdx
    mov r10, -5F1B4337596FABEDh
    sub r10, rax
    sub r10, rdx
    mov rcx, 56BB36D338443E96h
    add rdx, rcx
    mov rcx, rdx
    not rcx
    lea r11, [rcx+rcx*4]
    mov rdi, r10
    or rdi, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not rdi
    lea rdi, [rdi+rdi*2]
    mov r14, r10
    or r14, rdx
    not r14
    lea r14, [r14+r14*4]
    xor rdx, r10
    add rdx, rdx
    and rcx, r10
    shl rcx, 3
    sub rcx, rdx
    add rcx, r14
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rcx, rdi
    sub rcx, r11
    xor rcx, rax
    mov qword ptr [qword_7FF8572A5980], rcx
    loc_7FF8569FC991:
    lea rcx, [rbp-50h]
    lea rdx, qword_7FF8572A5980
    call sub_7FF855343EB0
    loc_7FF8569FC9A1:
    mov rax, qword ptr [rbp+610h]
    mov ecx, dword ptr [dword_7FF8571CFC68]
    lea edx, [rcx+47E8179Bh]
    mov r8d, edx
    not r8d
    mov r9d, r8d
    and r9d, 56DE3DC3h
    mov r10d, r8d
    and r10d, 2921C23Ch
    or r8d, 2921C23Ch
    lea edx, [r8+rdx*2]
    add edx, r10d
    lea r8d, [rdx+r9*2]
    lea edx, [rdx+r9*2]
    add edx, 2
    not edx
    mov r9d, edx
    and r9d, -1220481Ch
    lea r9d, [r9+r9*2]
    mov r10d, edx
    and r10d, 1220481Bh
    shl r10d, 2
    or edx, -1220481Ch
    lea r11d, 4[r8*2]
    sub edx, r11d
    sub edx, r10d
    sub edx, r9d
    mov r9d, ecx
    not r9d
    mov r10d, r9d
    or r10d, -58381C47h
    mov r11d, ecx
    or r11d, -58381C47h
    mov edi, ecx
    xor edi, 58381C46h
    and r9d, -58381C47h
    lea r9d, [r9+r9*2]
    mov ebx, ecx
    and ebx, -58381C47h
    lea ebx, [rbx+rbx*2]
    add ebx, edi
    add ebx, r9d
    add ebx, r11d
    sub ebx, r10d
    add r8d, ebx
    add r8d, 2
    add r8d, edx
    add ecx, r8d
    add ecx, -7A7AFDAh
    or ecx, dword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+610h]
    mov dword ptr [rax], ecx
    mov rax, qword ptr [rbp+548h]
    mov rax, qword ptr [rax]
    mov qword ptr [rbp+3F0h], rax
    mov rcx, qword ptr [qword_7FF8572A3878]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp rax, rcx
    jz loc_7FF856A05F16
    mov eax, dword ptr [dword_7FF857242988]
    mov ecx, -50907BA5h
    add eax, ecx
    mov ecx, eax
    xor ecx, -68D5618Dh
    lea edx, [rcx-2C98C04h]
    lea r8d, [rcx-564A1D4Bh]
    xor r8d, eax
    xor r8d, edx
    xor r8d, -541C221Ah
    sub r8d, ecx
    mov dword ptr [rbp+63Ch], r8d
    jmp loc_7FF8569F0600
    loc_7FF8569FCE2E:
    mov rsi, r12
    mov rax, qword ptr [rbp+498h]
    jmp loc_7FF856A010EF
    loc_7FF8569FCE3D:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [qword_7FF8571CF958]
    mov r8, rax
    not r8
    lea rdx, [r8*8]
    sub rdx, r8
    mov rcx, rax
    mov r11, -28443DCE6FA5CBB0h
    and rcx, r11
    mov r9, rcx
    mov r10, rax
    mov rsi, 28443DCE6FA5CBAFh
    and r10, rsi
    add r10, r10
    add rcx, rcx
    sub rcx, r10
    mov r10, r8
    and r10, r11
    lea r10, [r10+r10*8]
    and r8, rsi
    add r8, r8
    lea r8, [r8+r8*4]
    not r9
    lea r9, [r9+r9*2]
    add rcx, r9
    sub rcx, r8
    sub rcx, r10
    add rcx, rdx
    mov rdx, rcx
    mov r8, 3049820B77F36CDFh
    xor rdx, r8
    mov r8, rdx
    mov r9, -2B53052EBE37D2D6h
    and r8, r9
    mov r9, rdx
    mov rsi, 2B53052EBE37D2D5h
    and r9, rsi
    lea r10, [r9+r9*4]
    lea r9, [r9+r10*2]
    add r9, r8
    not r8
    lea r10, [r8+r8*4]
    lea r10, [r8+r10*2]
    mov r8, -4E5B8B34E92D9F6Eh
    sub r8, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11, -3049820B77F36CE0h
    xor rcx, r11
    sub r9, r10
    mov r10, rcx
    and r10, rsi
    lea r10, [r10+r10*8]
    add r10, rcx
    mov r11, 54ACFAD141C82D2Ah
    and rcx, r11
    lea rcx, [rcx+rcx*4]
    lea rcx, [r9+rcx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r10, rcx
    mov rcx, -3687AD57CDBD473Ch
    add rcx, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r8, r10
    xor r8, rcx
    xor r8, rdx
    add r8, rax
    add r8, qword ptr [rbp+350h]
    mov qword ptr [rbp+28h], r8
    mov rax, qword ptr [rbp+5E0h]
    sub rax, r8
    mov qword ptr [rbp+5E8h], rax
    add r8, qword ptr [rbp+538h]
    mov qword ptr [rbp+20h], r8
    lea rax, [rbp+118h]
    mov qword ptr [rbp+460h], rax
    mov qword ptr [rbp+118h], 0
    lea rax, [rbp+128h]
    mov qword ptr [rbp+458h], rax
    mov qword ptr [rbp+110h], rax
    lea rax, [rbp+120h]
    mov qword ptr [rbp+5D0h], rax
    mov r8, qword ptr [qword_7FF8571CF960]
    mov rax, r8
    mov rcx, 634E04AFE5885A6Eh
    xor rax, rcx
    add rax, r8
    add rax, r8
    mov rcx, 48E23924AF36083Bh
    add rcx, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, 0DED177B5F5BBEE1h
    add r8, rdx
    mov rdx, r8
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9, r8
    mov r10, -3954FE146FE640DAh
    and r9, r10
    mov r11, 3954FE146FE640D9h
    and r8, r11
    lea r10, [r8+r8*4]
    lea r8, [r8+r10*2]
    add r8, r9
    not r9
    lea r10, [r9+r9*4]
    lea r9, [r9+r10*2]
    mov r10, rdx
    and r10, r11
    lea r10, [r10+r10*8]
    add r10, rdx
    mov r11, 46AB01EB9019BF26h
    and rdx, r11
    lea rdx, [rdx+rdx*4]
    sub r8, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rdx, [r8+rdx*2]
    add r10, rdx
    sub rax, r10
    sub rax, r10
    mov rdx, -2D2798A2175731AAh
    add rax, rdx
    xor rax, rcx
    mov rcx, qword ptr [rbp+5D0h]
    mov qword ptr [rcx], rax
    movzx eax, byte ptr [byte_7FF8571CF968]
    mov ecx, eax
    not cl
    and cl, 40h
    movzx ecx, cl
    add ecx, ecx
    lea ecx, [rcx+rcx*4]
    mov edx, eax
    or dl, 40h
    movzx edx, dl
    lea r8d, [rdx+rdx*4]
    lea edx, [rdx+r8*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, eax
    xor r8b, 40h
    add r8b, r8b
    lea r9d, [rax*8]
    and al, 40h
    movzx eax, al
    imul eax, 0F5h
    sub al, r9b
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add al, dl
    sub al, cl
    mov ecx, eax
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edx, ecx
    and dl, 78h
    movzx edx, dl
    lea edx, [rdx+rdx*8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    and r8b, 7
    mov r9d, eax
    and r9b, 78h
    movzx r9d, r9b
    mov r10d, eax
    and r10b, 87h
    lea r11d, [r9+r9*4]
    lea r9d, [r9+r11*2]
    add r9b, r10b
    not r10b
    movzx r10d, r10b
    lea r11d, [r10+r10*4]
    lea r10d, [r10+r11*2]
    movzx r8d, r8b
    add r8d, r8d
    lea r8d, [r8+r8*4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r9b, r10b
    add r8b, dl
    add r8b, r9b
    add r8b, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea edx, [r8+3Dh]
    mov cl, 0CDh
    sub cl, r8b
    xor cl, al
    xor cl, dl
    mov edx, ecx
    mov eax, ecx
    or al, r8b
    lea r9d, [rcx+rcx]
    and cl, r8b
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
    or dl, r8b
    not al
    add cl, cl
    sub r9b, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add al, dl
    add al, r9b
    sub al, r8b
    inc al
    mov rcx, qword ptr [rbp+458h]
    mov byte ptr [rcx], al
    mov rax, qword ptr [qword_7FF8571CF970]
    mov rcx, 79FAB5FD6F822BBh
    add rcx, rax
    mov rdx, 5258C5565094AFBDh
    xor rcx, rdx
    mov rdx, 0F59873F4DBEF99Ah
    add rdx, rax
    sub rcx, rdx
    mov r8, rcx
    or r8, rax
    mov r9, r8
    not r9
    lea r10, [r9*8]
    sub r10, r9
    and rcx, rax
    lea rax, [r8+r8*2]
    lea rax, [rcx+rax*2]
    add rax, rdx
    add rax, r10
    mov rcx, -1A44D5EE79EC92F0h
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rbp+5E8h], rcx
    jbe loc_7FF856A06162
    mov eax, dword ptr [dword_7FF857242B18]
    lea ecx, [rax-57751383h]
    sub eax, ecx
    xor ecx, -63DA2B59h
    lea edx, [rcx+0E3862BCh]
    lea r8d, [rcx-2739B0FDh]
    add eax, -6D823070h
    xor eax, edx
    xor r8d, ecx
    xor r8d, eax
    mov dword ptr [rbp+63Ch], r8d
    jmp loc_7FF8569F0600
    loc_7FF8569FDB4F:
    mov rdx, qword ptr [rbp+110h]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569FDB5D:
    mov rcx, r12
    call qword ptr [rax+30h]
    mov rax, qword ptr [rbp+5D0h]
    mov rax, qword ptr [rax]
    mov qword ptr [rbp+190h], rax
    jmp loc_7FF856A05345
    loc_7FF8569FDB79:
    mov rax, qword ptr [rbp+610h]
    mov ecx, dword ptr [dword_7FF8571CFC40]
    mov edx, 42859608h
    xor ecx, edx
    lea r9d, [rcx+1843BE3h]
    mov r8d, r9d
    not r8d
    mov edx, r8d
    and edx, 1527D997h
    and r8d, 2AD82668h
    shl r8d, 2
    mov r10d, r9d
    xor r10d, 1527D997h
    mov r11d, r9d
    xor r11d, 2AD82668h
    lea edi, [r10*8]
    mov r14d, r9d
    and r14d, 0AD82668h
    shl r14d, 3
    and r9d, 1527D997h
    add r9d, r9d
    sub r14d, r9d
    sub r10d, edi
    add r10d, r14d
    lea r9d, [r10+r11*4]
    sub r9d, r8d
    lea r10d, [r9+rdx*8]
    lea edx, [r9+rdx*8]
    add edx, 7447C3EBh
    mov r8d, 74580BF0h
    sub r8d, ecx
    xor r8d, ecx
    add r8d, r10d
    mov ecx, edx
    not ecx
    mov r9d, r8d
    or r9d, ecx
    not r9d
    add r9d, r9d
    lea r9d, [r9+r9*4]
    mov r10d, r8d
    or r10d, edx
    lea r11d, [r10+r10*4]
    lea r10d, [r10+r11*2]
    mov r11d, r8d
    xor r11d, edx
    add r11d, r11d
    and ecx, r8d
    shl ecx, 3
    and r8d, edx
    imul edx, r8d, 0F5h
    sub edx, ecx
    sub edx, r11d
    add edx, r10d
    sub edx, r9d
    or edx, dword ptr [rax]
    mov eax, dword ptr [rbp+40Ch]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rbp+610h]
    mov dword ptr [rcx], edx
    mov rcx, qword ptr [rbp+98h]
    mov dword ptr [rcx], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rbp+63Bh]
    mov byte ptr [rbp+634h], al
    loc_7FF8569FDE2C:
    movzx eax, byte ptr [rbp+634h]
    mov byte ptr [rbp+639h], al
    cmp byte ptr [rbp+63Bh], 0
    jz loc_7FF856A02407
    mov eax, dword ptr [dword_7FF857242970]
    lea ecx, [rax+57D34FC8h]
    sub eax, ecx
    xor ecx, 3235A60Ch
    add eax, ecx
    add eax, -0FC6AF6Dh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569FDE6C:
    mov rax, qword ptr [rbp+600h]
    cmp rax, 17h
    mov ecx, 16h
    cmovb rax, rcx
    loc_7FF8569FDE80:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov rdx, -8000000000000000h
    or rcx, rdx
    mov rdx, qword ptr [rbp+5C0h]
    mov qword ptr [rdx], rcx
    mov rcx, qword ptr [qword_7FF8571CFB50]
    mov rdx, 63CE249D307F1996h
    add rcx, rdx
    mov rdx, rcx
    not rdx
    mov r11, -40C322F022D4891Eh
    and rdx, r11
    lea r8, [rdx+rdx*4]
    lea r8, [rdx+r8*4]
    mov r9, rcx
    or r9, r11
    lea rdx, [r9+r9*4]
    lea rdx, [r9+rdx*2]
    not r9
    lea r10, [r9+r9*4]
    lea r9, [r9+r10*2]
    mov r10, rcx
    and r10, r11
    mov r11, r10
    not r11
    lea rdi, [r11+r11*4]
    lea r11, [r11+rdi*2]
    mov rdi, rcx
    mov rsi, 40C322F022D4891Dh
    and rdi, rsi
    lea r14, [rdi+rdi*4]
    lea rdi, [rdi+r14*4]
    lea r10, [r10+r10*8]
    add r10, rdi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add rdx, r11
    sub rdx, r9
    sub rdx, r8
    mov r8, rdx
    not r8
    mov r9, rdx
    mov r10, -6A8B2500BF080A2h
    or r9, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r8, r10
    lea r10, [rdx+rdx]
    mov r11, rdx
    mov rsi, 6A8B2500BF080A1h
    and r11, rsi
    add r11, r11
    sub r10, r11
    add r8, r9
    add r8, r10
    mov r9, 6A8B2500BF080A3h
    add r8, r9
    mov r9, r8
    mov r10, 2AECC73737A77A73h
    xor rdx, r10
    sub rdx, r8
    not r8
    mov r10, r8
    mov r11, 762FA445D533EF52h
    and r10, r11
    mov r11, 9D05BBA2ACC10ADh
    and r8, r11
    mov r11, -762FA445D533EF53h
    and r9, r11
    mov r11, r9
    not r11
    add r11, r11
    xor rdx, rcx
    add rdx, r10
    sub r9, r11
    lea rcx, [r9+r8*4]
    add rdx, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, -13A0B7745598215Ah
    add rdx, rax
    add rdx, rcx
    mov rax, qword ptr [qword_7FF8571CFB58]
    mov rcx, rax
    not rcx
    mov rsi, 6A681592F839D238h
    and rcx, rsi
    lea r8, [rcx+rcx*4]
    lea r8, [rcx+r8*2]
    mov rcx, rax
    or rcx, rsi
    lea r9, [rcx+rcx*4]
    lea r9, [rcx+r9*2]
    mov r10, rax
    xor r10, rsi
    mov rcx, rax
    mov r11, -6A681592F839D239h
    and rcx, r11
    lea r11, [rcx+rcx*8]
    mov rcx, rax
    and rcx, rsi
    imul rcx, 0F5h
    sub rcx, r11
    sub rcx, r10
    add rcx, r9
    sub rcx, r8
    mov r8, 0FCD9ADD5F52A8E0h
    lea r9, [rcx+r8]
    mov r8, r9
    mov rdi, 72D54EAE9EAAA092h
    or r8, rdi
    mov r10, r9
    mov rsi, -72D54EAE9EAAA093h
    xor r10, rsi
    add r10, r8
    mov r8, r9
    and r8, rsi
    lea r11, [r8+r8*2]
    mov r8, r9
    and r8, rdi
    lea r8, [r8+r8*2]
    add r8, r11
    sub r8, r9
    sub r8, r9
    add r8, r10
    mov r10, r9
    or r10, rsi
    sub r8, r10
    mov r10, r8
    mov r11, 0F45F6A2B92CDCAh
    xor r10, r11
    mov r11, -3634965EA01F985Fh
    xor r8, r11
    sub r8, r10
    xor r8, rax
    add r8, rcx
    sub r8, r9
    mov rax, qword ptr [off_7FF8571A2640]
    mov rax, qword ptr [rax+10h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, -7D0E41ABD2C61A00h
    add r8, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, r12
    call rax
    mov qword ptr [rbp+478h], rax
    mov rax, qword ptr [rbp+4A0h]
    mov rcx, qword ptr [qword_7FF8571CFB60]
    mov rdx, 266784104F70CF39h
    add rdx, rcx
    mov r8, -74F40B54A0DF27A7h
    xor rdx, r8
    mov r8, 2A54D8F0F52E06C3h
    add r8, rcx
    mov r9, -751D5EA5C68C0A38h
    add r9, rcx
    xor r9, r8
    sub rdx, rcx
    mov rcx, 351FB83041789A2Ah
    add rdx, rcx
    xor rdx, r9
    add rdx, qword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rbp+380h], rdx
    mov rax, qword ptr [qword_7FF8571CFB68]
    mov rcx, rax
    not rcx
    mov r10, 3741F66DAE11B62Ch
    and rcx, r10
    lea r8, [rcx*8]
    sub r8, rcx
    mov rcx, rax
    xor rcx, r10
    lea rcx, [rcx+rcx*4]
    mov rdx, rax
    mov r9, 48BE099251EE49D3h
    and rdx, r9
    lea rdx, [rdx+rdx*2]
    mov r9, rax
    and r9, r10
    lea rdx, [r9+rdx*2]
    sub rdx, rcx
    add rdx, r8
    mov rcx, -3741F66DAE11B62Ch
    add rcx, rdx
    mov r8, 3474C85D3157E83Fh
    add rdx, r8
    mov r8, rdx
    mov r11, -4550BDEFA8AE2C9Fh
    or r8, r11
    lea r9, [r8+r8*4]
    lea r8, [r8+r9*2]
    mov r9, rdx
    mov r10, 550BDEFA8AE2C9Eh
    and r9, r10
    shl r9, 3
    mov r10, rdx
    and r10, r11
    imul r10, 0F5h
    sub r10, r9
    mov r9, rdx
    mov r11, 3AAF42105751D361h
    xor r9, r11
    add r9, r9
    sub r10, r9
    add r10, r8
    mov r8, rdx
    not r8
    and r8, r11
    add r8, r8
    lea r8, [r8+r8*4]
    sub r10, r8
    sub r10, rdx
    mov rdx, -1A104802169FC27Bh
    add rax, rdx
    add rax, r10
    xor rax, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rbp+380h], rax
    jnz loc_7FF856A070E4
    mov eax, dword ptr [dword_7FF857242A50]
    lea ecx, [rax-732AAEA2h]
    mov edx, ecx
    xor edx, 690ADDF4h
    lea r8d, [rdx-90FB8B4h]
    mov r9d, r8d
    xor r9d, -2E3FFA54h
    add eax, r9d
    add eax, 32A2EAB9h
    xor r8d, ecx
    xor r8d, eax
    sub r8d, edx
    mov dword ptr [rbp+63Ch], r8d
    jmp loc_7FF8569F0600
    loc_7FF8569FE8D5:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+578h]
    mov rdx, qword ptr [rax]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569FE948:
    mov rcx, r12
    call qword ptr [rax+30h]
    loc_7FF8569FE94E:
    mov rax, qword ptr [rbp+4E0h]
    mov rax, qword ptr [rax]
    loc_7FF8569FE958:
    mov qword ptr [rbp+2A8h], rax
    mov rax, qword ptr [rbp+2A8h]
    mov rcx, qword ptr [rbp+578h]
    mov rdx, qword ptr [rbp+4B8h]
    mov qword ptr [rcx], rdx
    mov rcx, rax
    mov rdx, rax
    mov r10, -8000000000000000h
    and rdx, r10
    lea r8, [rax*8]
    lea rdx, [rdx+rax*8]
    or rax, r10
    not rcx
    lea r9, [rcx+rcx]
    lea r9, [r9+r9*2]
    and rcx, r10
    sub rax, r8
    add rdx, rax
    sub rdx, r9
    add rcx, r9
    add rcx, rdx
    mov rax, qword ptr [rbp+4E0h]
    mov qword ptr [rax], rcx
    mov rax, qword ptr [rbp+4B8h]
    loc_7FF8569FE9C7:
    mov qword ptr [rbp+2B0h], rax
    mov rax, qword ptr [rbp+2B0h]
    mov qword ptr [rbp+3E0h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+578h]
    lea rcx, [rax+8]
    mov qword ptr [rbp+68h], rcx
    mov rcx, qword ptr [qword_7FF8571CFCC0]
    mov r8, rcx
    not r8
    mov rdx, rcx
    mov r11, -4B5D493987EAB480h
    or rdx, r11
    lea r9, [rdx+rdx*4]
    lea r9, [rdx+r9*2]
    not rdx
    lea r10, [rdx*8]
    sub r10, rdx
    and r8, r11
    mov rdx, r8
    shl rdx, 4
    add rdx, r8
    mov r8, rcx
    and r8, r11
    mov r11, rcx
    mov rsi, 4B5D493987EAB47Fh
    and r11, rsi
    lea rdi, [r11+r11*8]
    lea r11, [r11+rdi*2]
    lea rdi, [r8+r8*2]
    lea r11, [r11+rdi*4]
    not r8
    add r8, r8
    lea r8, [r8+r8*2]
    sub r11, r9
    sub r11, r8
    add rdx, r10
    add rdx, r11
    mov r8, rdx
    not r8
    mov r9, r8
    mov r11, 4C470024BB92B3F6h
    and r9, r11
    lea r9, [r9+r9*2]
    mov r10, 12EDC75701BB2809h
    add r9, r10
    mov r10, rdx
    xor r10, r11
    add r10, r10
    mov r11, rdx
    mov rsi, 13B8FFDB446D4C09h
    and r11, rsi
    shl r11, 3
    sub r11, r10
    mov r10, r8
    mov rsi, -4C470024BB92B3F7h
    and r10, rsi
    lea r10, [r10+r10*4]
    add r11, r10
    add r11, r9
    mov r9, 765E55CCD52BB1C7h
    add rcx, r9
    mov r9, 7B1CBD53C9817D48h
    xor rcx, r9
    xor rcx, r11
    sub rcx, r11
    mov r10, rcx
    not r10
    lea r9, [r10*8]
    sub r9, r10
    mov r10, rcx
    or r10, r8
    mov r11, rcx
    or r11, rdx
    and rdx, rcx
    and rcx, r8
    mov r8, rdx
    add rcx, rcx
    add rdx, rdx
    sub rdx, rcx
    not r8
    lea rcx, [r8+r8*2]
    add rdx, rcx
    not r11
    add r11, r11
    lea rcx, [r11+r11*4]
    sub rdx, rcx
    not r10
    lea rcx, [r10+r10*8]
    sub rdx, rcx
    add rdx, r9
    mov rcx, qword ptr [rbp+3E8h]
    mov rax, qword ptr [rax+8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rbp+5A8h], rdx
    setz byte ptr [rbp+638h]
    cmp rcx, rax
    jnb loc_7FF8569FEDFC
    mov eax, dword ptr [dword_7FF8572429D4]
    lea ecx, [rax+42A31E7Ah]
    lea edx, [rax-934189Ch]
    mov r8d, edx
    xor r8d, -20A9D817h
    sub edx, r8d
    add r8d, -31A220D4h
    add edx, -1DF80D30h
    xor edx, ecx
    add eax, edx
    add eax, -0DC9EF91h
    jmp loc_7FF856A01B41
    loc_7FF8569FEDFC:
    cmp byte ptr [rbp+638h], 0
    jz loc_7FF856A05EE4
    mov eax, dword ptr [dword_7FF8572429A8]
    lea ecx, [rax-1525D5EEh]
    mov edx, ecx
    xor edx, -5696BFC7h
    lea r8d, [rdx-33631E59h]
    lea r9d, [rax-77B38B9Ch]
    xor r9d, r8d
    sub r9d, edx
    lea edx, [r9+rax]
    add edx, 61C85521h
    xor ecx, eax
    xor ecx, edx
    xor ecx, -39394C71h
    add eax, ecx
    add eax, 2032E64Fh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569FEE57:
    mov r8, qword ptr [rbp+5F8h]
    mov rdx, qword ptr [rbp]
    mov rcx, qword ptr [rbp+328h]
    call memcpy
    jmp loc_7FF8569FEE8D
    loc_7FF8569FEE70:
    mov rcx, qword ptr [rbp+328h]
    mov rdx, qword ptr [rbp+330h]
    add rdx, rcx
    mov r8, qword ptr [rbp+5F8h]
    call memcpy
    loc_7FF8569FEE8D:
    mov rax, qword ptr [rbp+550h]
    mov rcx, qword ptr [rbp+5F8h]
    mov byte ptr [rax+rcx], 0
    mov rax, qword ptr [rbp+608h]
    mov rcx, qword ptr [rbp+5F8h]
    mov qword ptr [rax], rcx
    mov rax, qword ptr [rbp+5B8h]
    mov rax, qword ptr [rax]
    mov rdx, qword ptr [qword_7FF8571CFA68]
    mov rcx, -7FFEE5D9EDB988B1h
    add rcx, rdx
    mov r10, rcx
    mov r8, -370140F28682F8F3h
    xor r10, r8
    mov r8, 2D47BE97CF4CAF88h
    xor rdx, r8
    mov r8, rcx
    mov r9, 370140F28682F8F2h
    xor r8, r9
    mov r9, rdx
    or r9, r8
    not r9
    lea r9, [r9+r9*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11, rdx
    or r11, r10
    not r11
    add r11, r11
    and r8, rdx
    lea rdi, [r8+r8*2]
    not r8
    add r8, r8
    and rdx, r10
    mov r10, rdx
    not r10
    add rdx, rdx
    sub rdx, rdi
    lea rdx, [rdx+r10*4]
    sub rdx, r8
    sub rdx, r11
    sub rdx, r9
    sub rdx, rcx
    cmp rax, rdx
    jle loc_7FF8569FEFF3
    mov rdx, qword ptr [rbp+0C0h]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF8569FEFB4:
    mov rcx, r12
    call qword ptr [rax+30h]
    mov eax, dword ptr [dword_7FF857242A14]
    lea ecx, [rax+7C138FCh]
    xor ecx, -59C7FDB8h
    xor eax, 5AE5023Dh
    add eax, ecx
    add ecx, 61DD913Ah
    sub eax, ecx
    xor ecx, -5F458C52h
    add eax, ecx
    add eax, -5C72013Ch
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569FEFF3:
    mov rcx, qword ptr [rbp+4E8h]
    mov qword ptr [rbp+340h], rcx
    call strlen
    mov qword ptr [rbp+590h], rax
    mov rax, qword ptr [rbp+0E8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rbp+340h]
    sub rcx, rax
    mov qword ptr [rbp+338h], rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rbp+5B0h]
    mov rcx, qword ptr [rcx]
    mov rdx, rcx
    and rdx, r13
    cmp qword ptr [rbp+590h], rdx
    jbe loc_7FF8569FFE29
    mov rax, rdx
    shr rax, 1
    add rax, rdx
    mov rdx, qword ptr [rbp+590h]
    cmp rax, rdx
    cmovbe rax, rdx
    loc_7FF8569FF0F6:
    mov r10, qword ptr [qword_7FF8571CFA70]
    mov rdx, 5E1BF2553581DB74h
    add rdx, r10
    mov r8, rdx
    mov r9, 23AE7BDE4B59EB4Ch
    xor r8, r9
    mov r9, rdx
    mov r11, 7A9C38F3D68E237h
    xor r9, r11
    mov r11, 353ACADBD3F5FF8Fh
    add r9, r11
    mov r11, r10
    sub r11, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r11, rdx
    add r9, r10
    mov r10, -27779735085A3DA9h
    add r9, r10
    add r9, r11
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r10, -63AE7BDE4B59EB4Dh
    xor rdx, r10
    mov r10, r9
    or r10, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or r8, r9
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
    shl r8, 2
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov r11, r9
    not r11
    add r11, r11
    sub r11, r9
    sub r11, r8
    add r11, r10
    lea rdx, [r11+rdx*2]
    inc rdx
    and rdx, rax
    mov r8, -8000000000000000h
    and rcx, r8
    or rcx, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rbp+5B0h]
    mov qword ptr [rdx], rcx
    mov rcx, qword ptr [qword_7FF8571CFA78]
    mov rdx, -50C48DCE2674279Eh
    add rdx, rcx
    mov r8, rdx
    not r8
    mov r9, r8
    mov r10, 132416EE3BFE279Bh
    and r9, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rsi, 0CDBE911C401D864h
    and r8, rsi
    shl r8, 2
    mov r10, rdx
    mov r11, -0CDBE911C401D865h
    xor r10, r11
    mov r11, rdx
    and r11, rsi
    shl r11, 3
    mov rdi, rdx
    mov rbx, 732416EE3BFE279Bh
    and rdi, rbx
    add rdi, rdi
    sub r11, rdi
    lea rdi, [r10*8]
    sub r10, rdi
    mov rdi, rdx
    xor rdi, rsi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r10, r11
    lea r10, [r10+rdi*4]
    sub r10, r8
    lea r8, [r10+r9*8]
    mov r9, 351B375FD93BC1BFh
    add r9, r8
    mov r10, r9
    mov r11, -41495E77F6946EA0h
    xor r10, r11
    mov r11, -4AA57AACD2575157h
    xor r9, r11
    add rdx, r8
    add rdx, r9
    xor rdx, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add rdx, rax
    mov r8, qword ptr [qword_7FF8571CFA80]
    mov rax, -7ADC77C39EA692AAh
    lea rcx, [r8+rax]
    mov rax, -0F1AD8EFE78C7A4Dh
    lea r9, [r8+rax]
    mov r10, r9
    not r10
    mov rax, r10
    mov rsi, 1DFD928ABAB71AC6h
    and rax, rsi
    lea rax, [rax+rax*2]
    mov r11, -1DFD928ABAB71AC7h
    and r10, r11
    lea r10, [r10+r10*4]
    mov r11, r9
    xor r11, rsi
    add r11, r11
    mov rsi, 2026D754548E539h
    and r9, rsi
    shl r9, 3
    sub r9, r11
    add r9, r10
    mov r10, -6A0C234A5A6C7A1Dh
    add rax, r10
    add rax, r9
    mov r9, 276A11CBE657B656h
    sub r9, r8
    mov r8, r9
    or r8, rcx
    mov r10, rcx
    not r10
    mov r11, r9
    or r11, r10
    mov rdi, r9
    xor rdi, rcx
    and r10, r9
    and r9, rcx
    lea rcx, [r10+r10*2]
    add rcx, rcx
    lea r9, [r9+r9*2]
    lea rcx, [rcx+r9*2]
    add rcx, rdi
    add r11, r11
    lea r9, [r11+r11*2]
    sub rcx, r9
    not r8
    lea r8, [r8+r8*2]
    lea r8, [rcx+r8*2]
    xor r8, rax
    mov rax, qword ptr [off_7FF8571A2640]
    mov rax, qword ptr [rax+10h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FF8569FF878:
    mov rcx, r12
    call rax
    loc_7FF8569FF87D:
    mov qword ptr [rbp+448h], rax
    mov rdx, qword ptr [qword_7FF8571CFA88]
    mov rax, 799ACA9DB9ABEB07h
    add rax, rdx
    mov rcx, rax
    mov r8, -6193515188B69A65h
    xor rcx, r8
    mov r8, 27198EDBA46CCD70h
    add r8, rcx
    mov r9, r8
    not r9
    mov r10, r8
    mov rsi, 458D554F2C4FD70Ah
    or r10, rsi
    mov r11, r8
    mov rbx, -458D554F2C4FD70Bh
    xor r11, rbx
    lea r11, [r11+r11*2]
    mov rdi, r8
    and rdi, rsi
    and r8, rbx
    sub r8, rdi
    add r8, r11
    sub r8, r10
    not r10
    shl r10, 2
    and r9, rsi
    add r8, r9
    sub r8, r10
    mov r9, r8
    not r9
    mov rsi, 7D764A3C74D9F965h
    and r9, rsi
    lea r10, [r9+r9*4]
    lea r11, [r9+r10*2]
    mov r9, r8
    or r9, rsi
    lea r10, [r9+r9*4]
    lea rdi, [r9+r10*2]
    mov r9, r8
    mov r10, -7D764A3C74D9F966h
    and r9, r10
    lea r9, [r9+r9*8]
    mov r10, r8
    and r10, rsi
    imul r10, 0F5h
    sub r10, r9
    mov r9, r8
    xor r9, rsi
    sub r10, r9
    mov r9, qword ptr [rbp+540h]
    mov r9, qword ptr [r9]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r10, rdi
    sub r10, r11
    mov r11, -42D61F81B8F65C6h
    xor rdx, r11
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rdx, r10
    add r10, r8
    add r10, rdx
    mov rdx, -5EAB42FB8B43856Dh
    add r10, rdx
    mov rdx, rax
    mov r8, 6193515188B69A64h
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
    mov r8, r10
    or r8, rdx
    not r8
    lea r8, [r8+r8*2]
    mov r11, r10
    or r11, rcx
    not r11
    shl r11, 2
    and rdx, r10
    mov rdi, rdx
    not rdi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    and r10, rcx
    lea rcx, [rdx+r10*2]
    sub rdi, rcx
    sub rdi, r11
    sub rdi, r8
    sub rdi, rax
    lea r8, [rdi+r9]
    add r8, -3
    mov rax, qword ptr [qword_7FF8571CFA90]
    mov rcx, rax
    mov rdx, -4E943C3C502562D5h
    xor rcx, rdx
    mov rdx, -0F7C73199AF1EEAEh
    add rdx, rcx
    mov r9, rdx
    mov r10, rdx
    mov r11, rdx
    mov rdi, rdx
    mov rbx, 6FDEC532947870F2h
    and rdi, rbx
    mov rsi, -6FDEC532947870F3h
    and rdx, rsi
    sub rdx, rdi
    xor r11, rsi
    lea r11, [r11+r11*2]
    add rdx, r11
    not r9
    or r10, rbx
    and r9, rbx
    sub rdx, r10
    add rdx, r9
    not r10
    shl r10, 2
    sub rdx, r10
    mov r9, -1E1768ADF8BCCC7Bh
    add r9, rcx
    mov r10, -4B466DEE1A296F59h
    xor r9, r10
    mov r10, 79A86112E376221Ch
    add rax, r10
    add rax, r9
    xor rax, rcx
    xor rax, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp r8, rax
    jnz loc_7FF856A0001F
    mov eax, dword ptr [dword_7FF857242AC0]
    mov ecx, -210C42D8h
    xor eax, ecx
    add eax, 7EFFAB66h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF8569FFE29:
    mov qword ptr [rbp+1C8h], rax
    mov rdx, qword ptr [qword_7FF8571CFAA0]
    mov r8, rdx
    mov rax, -6145DD98DF926834h
    xor r8, rax
    mov rax, rdx
    mov rcx, 1FF760703F359787h
    xor rax, rcx
    mov rcx, -197508F91144A526h
    lea r9, [rax+rcx]
    mov rcx, -192F0C97EF2EF4EEh
    add rcx, rax
    mov r10, 5EFCD9F3DF16C60Ch
    add rax, r10
    mov r10, 5462DFEE31C968FFh
    xor rdx, r10
    add rdx, r8
    xor rdx, r9
    add rdx, rax
    mov r8, 0FBB6FCC4239216Fh
    add rax, r8
    add rax, rdx
    mov rdx, rcx
    not rdx
    mov r8, rax
    or r8, rdx
    lea r9, [r8+r8*4]
    lea r9, [r8+r9*2]
    not r8
    lea r10, [r8*8]
    sub r10, r8
    mov r8, rax
    or r8, rcx
    not r8
    mov r11, r8
    shl r11, 4
    add r11, r8
    add r11, r10
    and rdx, rax
    and rax, rcx
    lea rcx, [rax+rax*8]
    lea rax, [rax+rcx*2]
    lea rcx, [rdx+rdx*2]
    lea rax, [rax+rcx*4]
    mov rcx, qword ptr [rbp+1C8h]
    sub rax, r9
    mov r8, qword ptr [rbp+540h]
    not rdx
    add rdx, rdx
    lea rdx, [rdx+rdx*2]
    sub rax, rdx
    mov r9, qword ptr [rbp+338h]
    mov r8, qword ptr [r8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rax, r11
    mov rdx, qword ptr [rbp+590h]
    cmp r9, r8
    jnb loc_7FF8569FFFB4
    cmp rdx, rax
    jnz loc_7FF856A0006D
    mov eax, dword ptr [dword_7FF85724291C]
    lea ecx, [rax-665F211Bh]
    mov edx, ecx
    xor edx, 3781AB09h
    lea r8d, [rax-7C2C15CAh]
    xor r8d, edx
    add r8d, eax
    add edx, -43ACBA58h
    add eax, r8d
    add eax, 33BDE627h
    xor eax, edx
    jmp loc_7FF856A07073
    loc_7FF8569FFFB4:
    cmp rdx, rax
    jnz loc_7FF856A00085
    mov eax, dword ptr [dword_7FF857242AB0]
    lea ecx, [rax-66BEAE6Ch]
    lea edx, [rax+47EDD4C0h]
    xor edx, -14B4CFD5h
    lea r8d, [rdx+6E6B7D1Bh]
    mov r9d, r8d
    xor r9d, -494EFB77h
    mov r10d, r8d
    xor r10d, -2A58DB4h
    sub r10d, eax
    add eax, r10d
    add eax, 47EDD4C0h
    add eax, r9d
    add eax, 10A1CE9h
    xor r8d, ecx
    xor r8d, eax
    xor r8d, 6EE73068h
    add r8d, edx
    mov dword ptr [rbp+63Ch], r8d
    jmp loc_7FF8569F0600
    loc_7FF856A0001F:
    mov rdx, qword ptr [rbp+0E8h]
    mov rcx, qword ptr [rbp+448h]
    call memcpy
    loc_7FF856A00032:
    mov rax, qword ptr [rbp+5B0h]
    mov rax, qword ptr [rax]
    mov qword ptr [rbp+8], rax
    test rax, rax
    js loc_7FF856A05DE2
    mov eax, dword ptr [dword_7FF857242ABC]
    lea ecx, [rax+4B14B0ACh]
    xor ecx, 62B80EAEh
    add eax, ecx
    add eax, -109F29A4h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A0006D:
    mov rdx, qword ptr [rbp+338h]
    add rdx, rcx
    mov r8, qword ptr [rbp+590h]
    call memcpy
    jmp loc_7FF856A00098
    loc_7FF856A00085:
    mov rdx, qword ptr [rbp+340h]
    mov r8, qword ptr [rbp+590h]
    call memcpy
    loc_7FF856A00098:
    mov rax, qword ptr [rbp+0E8h]
    mov rcx, qword ptr [rbp+590h]
    movzx r8d, byte ptr [byte_7FF8571CFAA8]
    add r8b, 0DAh
    mov edx, r8d
    xor dl, 0B9h
    lea r10d, [rdx+61h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r10b, r10b
    mov r9b, 96h
    sub r9b, r10b
    mov r10d, r9d
    or r10b, dl
    movzx r10d, r10b
    mov r11d, r10d
    not r11b
    movzx r11d, r11b
    lea edi, [r11*8]
    sub edi, r11d
    add r10d, r10d
    lea r10d, [r10+r10*2]
    and r9b, dl
    add r9b, r10b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9b, dil
    add r9b, r8b
    sub dl, r9b
    add dl, 7Eh
    mov byte ptr [rax+rcx], dl
    mov rax, qword ptr [rbp+540h]
    mov rcx, qword ptr [rbp+590h]
    mov qword ptr [rax], rcx
    mov rax, qword ptr [rbp+608h]
    mov rax, qword ptr [rax]
    mov rcx, qword ptr [rbp+550h]
    loc_7FF856A001EE:
    mov qword ptr [rbp+418h], rcx
    mov qword ptr [rbp+410h], rax
    loc_7FF856A001FC:
    mov rax, qword ptr [rbp+410h]
    mov rcx, qword ptr [rbp+418h]
    mov qword ptr [rbp+528h], rax
    mov qword ptr [rbp+530h], rcx
    test rax, rax
    jz loc_7FF8569F05CC
    mov qword ptr [rbp+2D8h], 0
    loc_7FF856A0022C:
    mov rax, qword ptr [rbp+2D8h]
    mov qword ptr [rbp+580h], rax
    mov rcx, qword ptr [rbp+530h]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx ecx, byte ptr [byte_7FF8571CFAC0]
    lea r9d, [rcx+43h]
    mov edx, r9d
    xor dl, 0B0h
    mov r8d, r9d
    add dl, 0ACh
    xor dl, r9b
    xor r9b, 2Fh
    xor r8b, 0D0h
    mov r10d, r8d
    and r10b, 34h
    movzx r10d, r10b
    lea r10d, [r10+r10*8]
    mov r11d, r8d
    and r11b, 4Bh
    movzx r11d, r11b
    add r11d, r11d
    lea r11d, [r11+r11*4]
    mov edi, r9d
    add dl, r9b
    and r9b, 0CBh
    and dil, 34h
    movzx edi, dil
    lea r14d, [rdi+rdi*4]
    lea edi, [rdi+r14*2]
    add dil, r9b
    not r9b
    movzx r9d, r9b
    lea r14d, [r9+r9*4]
    lea r9d, [r9+r14*2]
    sub dil, r9b
    add r11b, r10b
    add r11b, r8b
    add r11b, dil
    movzx r8d, r11b
    lea r9d, [r8+17h]
    movzx r11d, r9b
    mov r9d, r11d
    not r9b
    mov r10d, edx
    or r10b, r9b
    not r10b
    movzx r10d, r10b
    add r10d, r10d
    lea r10d, [r10+r10*4]
    mov edi, edx
    or dil, r11b
    and r9b, dl
    and dl, r11b
    add r11d, r11d
    lea r11d, [r11+r11*2]
    movzx edi, dil
    lea edi, [rdi+rdi*2]
    shl r9b, 2
    movzx edx, dl
    lea edx, [rdx+rdx*8]
    add dl, r9b
    sub dl, dil
    sub dl, r11b
    add dl, r10b
    mov r9d, edx
    or r9b, r8b
    lea r10d, [r8+r8*4]
    lea r10d, [r8+r10*2]
    mov r11d, edx
    and r11b, r8b
    not r8b
    mov edi, edx
    or dil, r8b
    not dil
    movzx edi, dil
    lea r14d, [rdi+rdi*4]
    lea edi, [rdi+r14*2]
    and r8b, dl
    movzx r11d, r11b
    imul r11d, 0F5h
    add r8b, r10b
    add r8b, r9b
    add r8b, r11b
    sub r8b, dil
    sub r8b, dl
    xor r8b, cl
    add r8b, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8b, 61h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rbp+580h]
    mov qword ptr [rbp-20h], rcx
    cmp al, r8b
    jnz loc_7FF856A00823
    mov rax, qword ptr [rbp-20h]
    mov qword ptr [rbp+4D8h], rax
    mov rax, qword ptr [qword_7FF8571CFAC8]
    mov rcx, -7EBEF65F2DFF30F9h
    add rax, rcx
    mov rcx, rax
    mov rdx, -7154A48BA39CE0B1h
    xor rcx, rdx
    mov rdx, 1CED7B9E1BED978Ah
    xor rax, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rcx, rax
    mov rdx, -0CAED20987ECD331h
    add rax, rdx
    add rax, rcx
    cmp qword ptr [rbp+4D8h], rax
    jnz loc_7FF856A00860
    mov rax, qword ptr [rbp+530h]
    mov rcx, qword ptr [rbp+528h]
    mov qword ptr [rbp+520h], rcx
    mov qword ptr [rbp+518h], rax
    mov eax, dword ptr [dword_7FF857242934]
    mov ecx, eax
    xor ecx, -4CD2F8C6h
    add ecx, 5E10F17h
    mov edx, ecx
    xor edx, -7140AFF6h
    lea r8d, [rdx-1098F716h]
    xor eax, r8d
    xor eax, -2D575B59h
    sub eax, r8d
    sub eax, ecx
    add eax, -3AC385E2h
    jmp loc_7FF856A082DD
    loc_7FF856A00823:
    mov eax, dword ptr [dword_7FF857242950]
    mov ecx, 2DDF54F8h
    add eax, ecx
    mov ecx, eax
    xor ecx, 55516DFAh
    xor eax, 46E6C9A6h
    lea edx, [rax+350D3652h]
    add ecx, -0EA2C143h
    xor ecx, edx
    xor edx, -5E14D9DAh
    add ecx, edx
    add ecx, edx
    add ecx, -43D13F6Ah
    jmp loc_7FF856A08041
    loc_7FF856A00860:
    mov eax, dword ptr [dword_7FF857242A00]
    mov ecx, eax
    xor ecx, -483A1FB9h
    lea edx, [rcx-43905F3Fh]
    xor edx, -236B8BC4h
    mov r8d, eax
    xor r8d, 4B45676Fh
    add r8d, edx
    xor r8d, eax
    xor eax, 3097CAFEh
    sub r8d, eax
    add r8d, ecx
    lea eax, [rdx+441073Ah]
    xor eax, 5FD97F85h
    lea ecx, [rdx+r8]
    add ecx, 441073Ah
    add eax, ecx
    add eax, 4882F987h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A008BC:
    mov rcx, qword ptr [rbp+360h]
    mov rdx, qword ptr [rbp+370h]
    add rdx, rcx
    mov r8, qword ptr [rbp+5F0h]
    call memcpy
    loc_7FF856A008D9:
    mov rax, qword ptr [rbp+4E8h]
    mov rcx, qword ptr [rbp+5F0h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov byte ptr [rax+rcx], 0
    mov rax, qword ptr [rbp+5C8h]
    mov rcx, qword ptr [rbp+5F0h]
    mov qword ptr [rax], rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+5D8h]
    cmp qword ptr [rax], 0
    js loc_7FF856A009C6
    mov eax, dword ptr [dword_7FF857242A6C]
    mov ecx, -34A321F6h
    xor eax, ecx
    add eax, 345D56h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A009C6:
    mov rax, qword ptr [rbp+608h]
    mov rax, qword ptr [rax]
    mov rcx, qword ptr [rbp+4D8h]
    cmp rcx, rax
    cmovb rax, rcx
    loc_7FF856A009DE:
    mov qword ptr [rbp+600h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+550h]
    mov qword ptr [rbp+50h], rax
    lea rax, [rbp+168h]
    mov qword ptr [rbp+4A0h], rax
    mov qword ptr [rbp+168h], 0
    lea rax, [rbp+178h]
    mov qword ptr [rbp+498h], rax
    mov qword ptr [rbp+160h], rax
    lea rax, [rbp+170h]
    mov qword ptr [rbp+5C0h], rax
    mov rax, qword ptr [qword_7FF8571CFB40]
    mov rcx, 61064F381EA635Ah
    add rcx, rax
    mov rdx, -702C539B538CE10Bh
    sub rdx, rax
    mov r8, -3C0E6A313A653CDFh
    add rax, r8
    xor rdx, rcx
    xor rdx, rax
    sub rdx, rax
    mov rax, 78CA43999F5C4678h
    add rdx, rax
    mov qword ptr [rbp+170h], rdx
    movzx ecx, byte ptr [byte_7FF8571CFB48]
    lea eax, [rcx+1Bh]
    lea r8d, [rcx-62h]
    xor r8b, al
    xor r8b, 41h
    mov r9d, ecx
    not r9b
    mov edx, r8d
    or dl, r9b
    movzx edx, dl
    lea r10d, [rdx+rdx*4]
    lea r11d, [rdx+r10*2]
    not dl
    movzx edx, dl
    lea r10d, [rdx*8]
    sub r10d, edx
    mov edx, r8d
    or dl, cl
    not dl
    movzx edi, dl
    mov edx, edi
    shl edx, 4
    add edx, edi
    and r9b, r8b
    and r8b, cl
    movzx r8d, r8b
    lea edi, [r8+r8*8]
    lea r8d, [r8+rdi*2]
    movzx r9d, r9b
    mov edi, r9d
    shl r9d, 2
    lea r9d, [r9+r9*2]
    add r8b, r9b
    sub r8b, r11b
    not dil
    movzx r9d, dil
    add r9d, r9d
    lea r9d, [r9+r9*2]
    sub r8b, r9b
    add ecx, 6Eh
    add dl, r10b
    add dl, r8b
    mov r8d, ecx
    not r8b
    mov r9d, edx
    or r9b, cl
    movzx r9d, r9b
    lea r10d, [r9+r9*4]
    lea r9d, [r9+r10*2]
    mov r10d, edx
    or r10b, r8b
    mov r11d, edx
    xor r11b, cl
    and r8b, dl
    and dl, cl
    not r10b
    movzx ecx, r10b
    add ecx, ecx
    lea r10d, [rcx+rcx*4]
    add r11b, r11b
    shl r8b, 3
    movzx ecx, dl
    imul ecx, 0F5h
    sub cl, r8b
    sub cl, r11b
    add cl, r9b
    sub cl, r10b
    mov r8d, eax
    not r8b
    mov edx, ecx
    or dl, r8b
    and r8b, cl
    mov r9d, r8d
    not r9b
    movzx r9d, r9b
    lea r10d, [r9+r9*4]
    lea r10d, [r9+r10*2]
    mov r9d, ecx
    mov r11d, ecx
    or r11b, al
    and cl, al
    movzx eax, cl
    lea ecx, [rax+rax*4]
    lea eax, [rax+rcx*2]
    add al, r8b
    not dl
    sub al, r10b
    movzx ecx, dl
    lea ecx, [rcx+rcx*8]
    not r11b
    movzx edx, r11b
    add edx, edx
    lea edx, [rdx+rdx*4]
    add dl, cl
    add dl, al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not r9b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add dl, r9b
    mov rax, qword ptr [rbp+498h]
    mov byte ptr [rax], dl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rbp+600h], 0Fh
    jbe loc_7FF856A010B2
    mov eax, dword ptr [dword_7FF857242A44]
    mov ecx, eax
    xor ecx, -60DEF3CEh
    lea edx, [rcx+65C715C5h]
    xor edx, -199639E1h
    lea r8d, [rdx-50C46300h]
    lea r9d, [rdx-327C6A03h]
    xor r9d, -435C1CACh
    add r9d, 26366B3Ch
    lea r10d, [rdx+74E55FE0h]
    xor r10d, ecx
    xor r8d, edx
    xor r8d, r10d
    xor r8d, r9d
    sub r8d, eax
    lea eax, [r8+rcx]
    add eax, 65C715C5h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A010B2:
    cmp qword ptr [rbp+600h], 0
    jz loc_7FF856A05DA4
    mov rax, qword ptr [rbp+498h]
    loc_7FF856A010C7:
    mov qword ptr [rbp+280h], rax
    mov rsi, r12
    mov rcx, qword ptr [rbp+280h]
    mov r8, qword ptr [rbp+600h]
    mov rdx, qword ptr [rbp+50h]
    call memcpy
    mov rax, qword ptr [rbp+160h]
    loc_7FF856A010EF:
    mov qword ptr [rbp+278h], rax
    mov rax, qword ptr [rbp+278h]
    mov rcx, qword ptr [rbp+600h]
    movzx r8d, byte ptr [byte_7FF8571CFB78]
    mov edx, r8d
    xor dl, 0BFh
    mov r9b, 0F2h
    sub r9b, dl
    xor r9b, r8b
    lea r8d, [rdx-2Ch]
    lea r10d, [rdx+21h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r9b, 6Fh
    sub r9b, dl
    add r9b, 63h
    mov r11d, r9d
    or r11b, r10b
    not r11b
    movzx r11d, r11b
    add r11d, r11d
    lea r11d, [r11+r11*2]
    mov edi, r10d
    not dil
    mov r14d, r9d
    or r14b, dil
    movzx r14d, r14b
    add r14d, r14d
    lea r14d, [r14+r14*2]
    mov r12d, r9d
    xor r12b, r10b
    and dil, r9b
    movzx edi, dil
    add edi, edi
    lea edi, [rdi+rdi*2]
    and r9b, r10b
    movzx r9d, r9b
    add r9d, r9d
    lea r9d, [r9+r9*2]
    add r9b, dil
    add r9b, r12b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r9b, r14b
    add r9b, r11b
    xor r9b, r8b
    add r9b, dl
    mov byte ptr [rax+rcx], r9b
    mov rax, qword ptr [rbp+600h]
    mov rcx, qword ptr [rbp+4A0h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+5C0h]
    mov rax, qword ptr [rax]
    test rax, rax
    js loc_7FF856A012EC
    mov rcx, qword ptr [rbp+628h]
    cmp qword ptr [rcx], 0
    mov r12, rsi
    js loc_7FF856A04FD4
    mov rdx, qword ptr [rbp+550h]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF856A01285:
    mov rcx, r12
    call qword ptr [rax+30h]
    mov rax, qword ptr [rbp+5C0h]
    mov rax, qword ptr [rax]
    mov rcx, qword ptr [rbp+4A0h]
    mov rcx, qword ptr [rcx]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jmp loc_7FF856A04FDB
    loc_7FF856A012EC:
    mov eax, dword ptr [dword_7FF857242A30]
    lea ecx, [rax-64A53A3Fh]
    lea edx, [rax+7CF3A29Dh]
    xor edx, -3FAEA308h
    lea r8d, [rdx-537F570Bh]
    xor r8d, ecx
    xor r8d, 121ED78Eh
    add r8d, eax
    lea ecx, [rax-562F2E2Bh]
    add r8d, edx
    add r8d, -12ACB24h
    xor r8d, ecx
    sub r8d, edx
    xor r8d, eax
    jmp loc_7FF856A052DB
    loc_7FF856A01336:
    mov eax, dword ptr [dword_7FF8572429C0]
    mov ecx, eax
    xor ecx, -5E735EABh
    lea edx, [rcx-7CBECAB3h]
    xor edx, ecx
    xor edx, 728CAB86h
    add edx, eax
    jmp loc_7FF8569F05F9
    loc_7FF856A01359:
    mov eax, dword ptr [dword_7FF857242A84]
    lea ecx, [rax+2628BE9Ch]
    xor ecx, -1041DF16h
    mov edx, ecx
    sub edx, eax
    add ecx, edx
    add ecx, -6C4CA552h
    jmp loc_7FF856A08041
    loc_7FF856A0137C:
    movzx eax, byte ptr [rbp+63Bh]
    jmp loc_7FF856A0633F
    loc_7FF856A01388:
    mov eax, dword ptr [dword_7FF8571CF9A8]
    lea ecx, [rax+777B1A99h]
    mov edx, ecx
    xor edx, 1Ch
    mov r8d, -643AB1DAh
    sub r8d, eax
    xor r8d, eax
    sub r8d, edx
    xor ecx, 10h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add ecx, eax
    add ecx, r8d
    mov rdx, qword ptr [rbp-10h]
    add cl, 5Ah
    mov rax, rdx
    shr rax, cl
    add rax, rdx
    mov rcx, qword ptr [rbp+5E8h]
    cmp rax, rcx
    cmovbe rax, rcx
    loc_7FF856A01480:
    mov rdx, rax
    not rdx
    add rdx, rdx
    lea rcx, [rax*4]
    mov r8, rax
    and r8, r13
    lea r8, [r8+r8*4]
    sub rcx, r8
    sub rcx, rdx
    add rcx, -2
    mov rdx, qword ptr [qword_7FF8571CF9B0]
    mov r8, rdx
    mov r9, 33CE40E1B94BA391h
    xor r8, r9
    mov r9, r8
    mov rsi, -5BCD1C5FE7EFF3A8h
    or r9, rsi
    lea r10, [r9+r9*2]
    not r9
    lea r11, [r9*8]
    sub r11, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r8, rsi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9, -41D76FA54314CC5Ah
    xor rdx, r9
    lea r8, [r8+r10*2]
    add r8, rdx
    add r8, r11
    mov rdx, -6633D2F71AB083A8h
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
    and r8, qword ptr [rbp+308h]
    or r8, rcx
    mov rcx, qword ptr [rbp+620h]
    mov qword ptr [rcx], r8
    mov rcx, qword ptr [qword_7FF8571CF9B8]
    mov rdx, -755BC9063A4D9C40h
    add rdx, rcx
    lea r8, [rcx+rdx]
    mov r9, -0C8A7AFDB2B7E231h
    add rcx, r9
    mov r9, -52879E59C5FEB44Dh
    sub r9, r8
    xor r9, rdx
    mov rdx, -5803DA037AAD8155h
    add rdx, rcx
    add r9, rdx
    mov rdx, rcx
    not rdx
    lea r8, [rdx+rdx]
    mov r10, r9
    or r10, rdx
    mov r11, r9
    or r11, rcx
    lea rdi, [r9+r9*2]
    and rdx, r9
    and r9, rcx
    shl rdx, 2
    lea rcx, [r9+r9*2]
    sub rdx, rcx
    add rdx, rdi
    not r11
    lea rcx, [r11+r11*2]
    lea rcx, [rdx+rcx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rdx, [r8+r8*2]
    add rcx, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rcx, rdx
    lea rdx, [rcx+rax]
    inc rdx
    mov r8, qword ptr [qword_7FF8571CF9C0]
    mov rax, -57F3B361E33D6505h
    add rax, r8
    mov rcx, 4EEDD7C43DB66C61h
    sub rcx, r8
    xor rcx, rax
    mov rax, 364FDA30F75D02Fh
    add rax, r8
    xor rcx, rax
    add r8, r8
    mov rax, 3D001A54EF14A94Fh
    add r8, rax
    add r8, rcx
    mov rax, qword ptr [off_7FF8571A2640]
    mov rax, qword ptr [rax+10h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FF856A0187A:
    mov rcx, r12
    call rax
    loc_7FF856A0187F:
    mov qword ptr [rbp+430h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+5C8h]
    mov rax, qword ptr [rax]
    inc rax
    mov qword ptr [rbp+2F8h], rax
    mov rcx, qword ptr [qword_7FF8571CF9C8]
    mov rax, rcx
    not rax
    mov rdx, rax
    mov r9, 4DA98EC44CD6CF42h
    and rdx, r9
    lea rdx, [rdx+rdx*2]
    mov r8, rax
    mov r10, 3256713BB32930BDh
    and r8, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    shl r8, 2
    or rax, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rcx, rcx
    sub rax, rcx
    sub rax, r8
    sub rax, rdx
    mov rcx, -6E2A3B07B1993EF7h
    add rcx, rax
    mov rdx, -375DF7AA367709FFh
    sub rdx, rax
    mov r8, 52530A2D3221AF7Fh
    add rax, r8
    xor rdx, rcx
    xor rdx, rax
    cmp qword ptr [rbp+2F8h], rdx
    jnz loc_7FF856A07306
    mov eax, dword ptr [dword_7FF857242B0C]
    mov ecx, 242ACC13h
    sub ecx, eax
    add eax, 49C49AC4h
    xor eax, ecx
    xor eax, 0D29E7D8h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A01AC5:
    mov rax, qword ptr [rbp+450h]
    mov qword ptr [rbp+1E0h], rax
    mov eax, dword ptr [dword_7FF857242AA8]
    lea ecx, [rax-182BC9D8h]
    xor eax, ecx
    xor ecx, -3948F216h
    xor eax, 67CB8907h
    add eax, ecx
    add eax, ecx
    add eax, -168F7154h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A01B00:
    mov qword ptr [rbp+198h], rax
    mov eax, dword ptr [dword_7FF857242B10]
    lea ecx, [rax-66D73B3Ah]
    mov edx, -764E9C71h
    sub edx, eax
    xor edx, ecx
    mov eax, ecx
    xor eax, 2662FD18h
    lea ecx, [rax-17090B3Eh]
    xor ecx, -3F1A3BA6h
    lea r8d, [rcx-7AC3616Ah]
    xor edx, ecx
    sub edx, ecx
    add eax, edx
    add eax, 23943641h
    loc_7FF856A01B41:
    xor eax, r8d
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A01B4F:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [qword_7FF8571CF920]
    mov rcx, -41201399304346Ch
    add rax, rcx
    mov rdx, rax
    not rdx
    mov rcx, rdx
    mov r11, 59D700258EEA8880h
    and rcx, r11
    lea rcx, [rcx+rcx*4]
    mov r8, rax
    or r8, r11
    lea r8, [r8+r8*2]
    mov r9, rax
    mov r10, 2628FFDA7115777Fh
    and r9, r10
    mov r10, rax
    and r10, r11
    lea r10, [r10+r10*8]
    lea r9, [r10+r9*4]
    sub r9, r8
    lea r8, [r9+rcx*2]
    mov rcx, -632EC3432A81C8D3h
    add rcx, r8
    mov r9, rcx
    not r9
    mov r10, 394A62E06E3B7A7h
    and r9, r10
    lea r10, [rcx+rcx]
    mov r11, -78D6B3A3F23890B2h
    or r10, r11
    mov r11, rcx
    mov rsi, 3C6B59D1F91C4858h
    and r11, rsi
    shl r11, 2
    mov rdi, rcx
    mov rsi, 4394A62E06E3B7A7h
    and rdi, rsi
    lea r11, [r11+rdi*2]
    mov rdi, rcx
    mov rsi, -3C6B59D1F91C4859h
    xor rdi, rsi
    sub r11, rdi
    sub r11, r10
    lea r9, [r11+r9*4]
    mov r10, 5B9DCDC2D08F8CFFh
    add r10, r8
    xor r10, r9
    mov r11, r10
    or r11, rdx
    mov rdi, r10
    and rdx, r10
    and r10, rax
    lea r10, [r10+r10*8]
    lea rdx, [r10+rdx*4]
    or rdi, rax
    lea r10, [rdi+rdi*2]
    sub rdx, r10
    add rax, rax
    lea rax, [rax+rax*2]
    sub rdx, rax
    not r11
    lea rax, [r11+r11*4]
    lea rax, [rdx+rax*2]
    sub rax, r8
    mov rdx, 472950A57E346B68h
    xor r9, rdx
    sub rax, r9
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, 1B0A00E1597F3300h
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
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rbp+5E0h], rax
    jnz loc_7FF856A062C8
    mov rax, qword ptr [rbp+4C0h]
    jmp loc_7FF856A02EFD
    loc_7FF856A01EAE:
    mov rdx, qword ptr [rbp+550h]
    mov rcx, qword ptr [rbp+420h]
    mov r8, qword ptr [rbp-18h]
    call memcpy
    loc_7FF856A01EC5:
    mov rcx, qword ptr [qword_7FF8571CF910]
    mov rax, 55CDB2E585CB56B3h
    add rax, rcx
    mov rdx, rax
    not rdx
    mov r8, rax
    mov r9, -3F29ED5D1171DB7Ah
    or r8, r9
    mov r9, 7AFB902E68AB24DDh
    add r8, r9
    mov r9, 40D612A2EE8E2486h
    and rdx, r9
    lea rdx, [rdx+rdx*2]
    mov r9, rax
    mov r10, 0D612A2EE8E2486h
    and r9, r10
    shl r9, 2
    mov r10, rax
    mov r11, 3F29ED5D1171DB79h
    and r10, r11
    lea r10, [r10+r10*2]
    sub r9, r10
    lea r10, [rax+rax*2]
    add r9, r10
    lea rdx, [r9+rdx*2]
    add rdx, r8
    mov r8, rdx
    mov r11, 653F4E4F711F2980h
    or r8, r11
    lea r9, [r8+r8*2]
    not r8
    lea r10, [r8*8]
    sub r10, r8
    mov r8, rdx
    and r8, r11
    lea r8, [r8+r9*2]
    add r8, r10
    mov r9, -7
    sub r9, r8
    mov r8, 241C0E130212DCEDh
    xor r9, r8
    sub rdx, r9
    add rdx, rcx
    sub rdx, rax
    mov rax, qword ptr [rbp+628h]
    mov rax, qword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, 14EA72C132D0E215h
    add rdx, rcx
    cmp rax, rdx
    jle loc_7FF856A02905
    mov eax, dword ptr [dword_7FF857242A54]
    lea ecx, [rax-5E92E598h]
    mov edx, ecx
    xor edx, -356CB510h
    mov r8d, ecx
    xor r8d, 8AD3348h
    xor ecx, 34C96447h
    add ecx, eax
    add ecx, -5E92E598h
    add ecx, edx
    sub ecx, r8d
    sub ecx, eax
    sub ecx, eax
    add ecx, 6798AA85h
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF856A02096:
    mov rax, qword ptr [rbp+620h]
    mov rax, qword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, qword ptr [qword_7FF8571CFB38]
    mov rcx, r8
    mov rdx, 4C0A4C090A01120h
    xor rcx, rdx
    mov rdx, r8
    mov r9, 501F4B3A664E8A55h
    xor rdx, r9
    lea r9, [rdx+rdx]
    mov r10, rdx
    mov r11, -54D4AFE2D2A49365h
    and r10, r11
    mov r11, 54D4AFE2D2A49364h
    and rdx, r11
    and rcx, r11
    lea r11, [rcx+rdx*2]
    add r11, r10
    sub r11, r9
    mov rcx, -286EDE853F3330A0h
    lea rdx, [r11+rcx]
    mov rcx, rdx
    mov r9, -0B77178F90E801A8h
    xor rcx, r9
    mov r9, 1D14FE18231D067h
    add r9, rcx
    mov r10, -6CA52FDB2327EA4Eh
    add rcx, r10
    xor rcx, r11
    add rcx, r8
    xor rcx, r9
    mov r9, rdx
    not r9
    mov r8, rcx
    or r8, r9
    mov r10, rcx
    or r10, rdx
    mov r11, rcx
    xor r11, rdx
    and r9, rcx
    and rcx, rdx
    sub rcx, r9
    lea rdx, [r11+r11*2]
    add rcx, rdx
    not r10
    sub rcx, r8
    add rcx, r10
    not r8
    shl r8, 2
    sub rcx, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp rax, rcx
    jle loc_7FF856A062EF
    mov eax, dword ptr [dword_7FF857242A58]
    lea ecx, [rax+367B6B2Bh]
    xor ecx, eax
    xor ecx, 1E05F8FEh
    add ecx, 4A5A454h
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF856A02407:
    mov eax, dword ptr [dword_7FF857242968]
    mov ecx, eax
    xor ecx, 19AFDEADh
    lea edx, [rcx+45BB4CC1h]
    mov r8d, edx
    xor r8d, 6CD2862Dh
    mov r10d, -3E2A99DAh
    sub r10d, r8d
    sub r10d, ecx
    xor r10d, r8d
    add r10d, ecx
    sub r10d, eax
    sub r10d, edx
    add r10d, -58879567h
    mov dword ptr [rbp+63Ch], r10d
    jmp loc_7FF8569F0600
    loc_7FF856A02450:
    mov eax, dword ptr [rbp+58Ch]
    mov rcx, qword ptr [rbp+610h]
    mov edx, dword ptr [dword_7FF8571CFC44]
    lea r9d, [rdx+209A9462h]
    lea r8d, 1A2CD3AFh[rdx*2]
    add edx, 1A2CD3AFh
    mov r14d, 3DE39174h
    sub r14d, r8d
    mov r10d, r9d
    not r10d
    mov r8d, r14d
    or r8d, r10d
    not r8d
    mov r11d, r14d
    or r11d, r9d
    not r11d
    shl r11d, 2
    mov edi, r14d
    xor edi, r9d
    mov ebx, edi
    not ebx
    mov rsi, r12
    lea r12d, [rdi*8]
    and r10d, r14d
    shl r10d, 3
    and r14d, r9d
    add r14d, r14d
    sub r10d, r14d
    sub edi, r12d
    mov r12, rsi
    add edi, r10d
    lea r9d, [rdi+rbx*4]
    sub r9d, r11d
    lea r8d, [r9+r8*8]
    sub r8d, edx
    or r8d, dword ptr [rcx]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rbp+610h]
    mov dword ptr [rcx], r8d
    mov rcx, qword ptr [rbp+90h]
    mov dword ptr [rcx], eax
    movzx eax, byte ptr [rbp+639h]
    mov byte ptr [rbp+633h], al
    loc_7FF856A025C3:
    mov r8, qword ptr [qword_7FF8571CFC48]
    mov rax, r8
    mov rcx, 18C7CF08B0FE83FFh
    xor rax, rcx
    mov rcx, -513040F6D56402A7h
    lea r9, [rax+rcx]
    mov rcx, r9
    mov rdx, 576F59964EF22F3h
    xor rcx, rdx
    mov rdx, -66C98F3A2605AB57h
    lea r10, [rcx+rdx]
    mov rdx, r10
    mov r11, -3C794B926CC3F113h
    xor rdx, r11
    mov r11, -4C09527C926E3D0h
    add rdx, r11
    mov r11, 2FBBBD03A2752C43h
    xor r9, r11
    xor r9, rdx
    add r9, r10
    xor r9, r8
    mov r10, -18C7CF08B0FE8400h
    xor r8, r10
    mov r10, r9
    or r10, r8
    mov r11, r9
    or r11, rax
    and rax, r9
    and r8, r9
    not r9
    lea rdi, [r9*8]
    sub rdi, r9
    mov r9, rax
    add r8, r8
    add rax, rax
    sub rax, r8
    not r9
    lea r8, [r9+r9*2]
    add rax, r8
    not r11
    add r11, r11
    lea r8, [r11+r11*4]
    sub rax, r8
    not r10
    lea r8, [r10+r10*8]
    sub rax, r8
    add rax, rdi
    xor rax, rcx
    sub rax, rdx
    movzx r14d, byte ptr [rbp+633h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, -2008B204D389A708h
    add rax, rcx
    cmp qword ptr [rbp+400h], rax
    jnz loc_7FF856A03ED4
    and r14b, 1
    mov byte ptr [rbp+63Ah], r14b
    jmp loc_7FF856A06345
    loc_7FF856A02820:
    mov eax, dword ptr [dword_7FF8572429C4]
    lea ecx, [rax+7441121Ah]
    mov edx, ecx
    xor edx, -1D6FAD6h
    lea r8d, [rdx-267417B8h]
    lea r9d, [rdx+69CC4024h]
    mov r10d, r9d
    xor r10d, -45792228h
    lea r11d, [r10-21A3742Eh]
    add r10d, 26DE2EFh
    xor r10d, 1EB16B64h
    sub r10d, r9d
    xor r10d, r11d
    sub r10d, edx
    xor r8d, ecx
    xor r8d, r10d
    add r8d, eax
    mov dword ptr [rbp+63Ch], r8d
    jmp loc_7FF8569F0600
    loc_7FF856A0287F:
    mov rdx, qword ptr [rbp+550h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF856A028F5:
    mov rcx, r12
    call qword ptr [rax+30h]
    loc_7FF856A028FB:
    mov rax, qword ptr [rbp+628h]
    mov rax, qword ptr [rax]
    loc_7FF856A02905:
    mov qword ptr [rbp+188h], rax
    mov rax, qword ptr [rbp+420h]
    mov qword ptr [rbp+550h], rax
    mov rax, qword ptr [qword_7FF8571CF918]
    mov rcx, rax
    not rcx
    lea rdx, [rcx+rcx*2]
    mov r8, rcx
    mov r10, -16729AB346BA70F2h
    and r8, r10
    lea r8, [r8+r8*2]
    mov r11, 16729AB346BA70F1h
    and rcx, r11
    lea rcx, [rcx+rcx*2]
    mov r9, rax
    xor r9, r10
    lea r10, [r9*8]
    sub r10, r9
    add r10, rcx
    mov rcx, rax
    and rcx, r11
    add rcx, rcx
    lea r9, [rcx+rcx*2]
    mov rcx, rax
    mov r11, 698D654CB9458F0Eh
    and rcx, r11
    add rcx, rcx
    sub rcx, r9
    add rcx, r10
    sub rcx, r8
    sub rcx, rdx
    mov rdx, 0C041D024FD8D40Dh
    add rdx, rcx
    mov r8, rdx
    not r8
    mov r9, rdx
    mov r11, 4C01F5FA03C9AA00h
    and r8, r11
    lea r8, [r8+r8*2]
    mov r10, rdx
    and r10, r11
    lea r8, [r10+r8*2]
    mov r10, rdx
    xor r10, r11
    lea r10, [r10+r10*4]
    sub r8, r10
    sub r8, rdx
    mov r10, 352B32DE0DFDCC94h
    xor rdx, r10
    mov r10, -6A0794377635729Eh
    add rdx, r10
    mov r10, -4C01F5FA03C9AA01h
    and r9, r10
    lea r10, [r9*8]
    sub r10, r9
    add r8, r10
    sub r8, rcx
    mov r9, -6E1940E7C8199FA7h
    add rax, r9
    add rax, r8
    mov r8, rdx
    not r8
    mov r9, rax
    or r9, r8
    mov r10, rax
    or r10, rdx
    not r10
    lea r10, [r10+r10*2]
    add r10, r9
    lea r9, [r8+r8*2]
    and r8, rax
    lea r8, [r8+r8*2]
    and rdx, rax
    sub r8, rdx
    add r8, rax
    add r8, r10
    sub r8, r9
    lea rax, [r8+rcx]
    inc rax
    and rax, qword ptr [rbp+188h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rbp+628h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+420h]
    loc_7FF856A02ED5:
    mov qword ptr [rbp+2F0h], rax
    mov rcx, qword ptr [rbp+2F0h]
    mov r8, qword ptr [rbp+5E0h]
    mov rdx, qword ptr [rbp+80h]
    call memcpy
    mov rax, qword ptr [rbp+550h]
    loc_7FF856A02EFD:
    mov qword ptr [rbp+2E8h], rax
    mov rax, qword ptr [rbp+2E8h]
    mov rcx, qword ptr [rbp+5E0h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx edx, byte ptr [byte_7FF8571CF928]
    mov r8d, edx
    not r8b
    mov r9d, r8d
    and r9b, 86h
    movzx r9d, r9b
    lea r9d, [r9+r9*2]
    and r8b, 79h
    movzx r8d, r8b
    lea r10d, [r8+r8*4]
    mov r11d, edx
    xor r11b, 6
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r11b, r11b
    mov r8d, edx
    and r8b, 19h
    shl r8b, 3
    sub r8b, r11b
    add r8b, r10b
    add r8b, r9b
    lea r10d, [r8-4Bh]
    mov r11d, r10d
    not r11b
    mov edi, r10d
    or dil, 25h
    and r11b, 25h
    shl r11b, 2
    and r10b, 25h
    mov r9d, r10d
    not r9b
    add r9b, r9b
    sub r9b, r10b
    sub r9b, r11b
    add r9b, dil
    add r9b, 4Bh
    mov r10d, r9d
    not r10b
    movzx r11d, r10b
    lea r10d, [r11+r11*2]
    mov edi, r9d
    xor dil, 61h
    movzx edi, dil
    lea r14d, [rdi*8]
    sub r14d, edi
    mov edi, r9d
    and dil, 1Eh
    movzx edi, dil
    add edi, edi
    lea edi, [rdi+rdi*2]
    and r9b, 61h
    add r9b, r9b
    sub r9b, dil
    mov edi, r11d
    and dil, 61h
    movzx edi, dil
    lea edi, [rdi+rdi*2]
    and r11b, 9Eh
    movzx r11d, r11b
    lea r11d, [r11+r11*2]
    add r14b, r11b
    add r14b, r9b
    sub r14b, dil
    sub r14b, r10b
    lea r9d, [r8-7]
    xor r9b, r14b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add dl, r8b
    add dl, r9b
    add dl, r8b
    add dl, 0D5h
    mov byte ptr [rax+rcx], dl
    mov rax, qword ptr [rbp+5E0h]
    mov rcx, qword ptr [rbp+608h]
    mov qword ptr [rcx], rax
    lea rax, [rbp+4F0h]
    mov qword ptr [rbp+5C8h], rax
    mov qword ptr [rbp+4F0h], 0
    lea rax, [rbp+500h]
    mov qword ptr [rbp+4E8h], rax
    lea rax, [rbp+4F8h]
    mov qword ptr [rbp+620h], rax
    mov rax, qword ptr [qword_7FF8571CF930]
    mov rcx, rax
    mov rdx, 3D78C020F3E08A1Fh
    xor rcx, rdx
    mov rdx, -35019D335B4EE4C8h
    add rdx, rcx
    mov r8, rdx
    mov r9, -4D4A537FC86A8EA3h
    xor r8, r9
    mov r9, 5CC16E51805747A2h
    add r9, r8
    mov r10, -757C19BF39C2D34Ch
    add r10, r8
    xor r9, r10
    mov r11, 75B9AC601E33498h
    xor r10, r11
    sub r10, r8
    xor r9, r10
    sub r9, rcx
    sub r9, rdx
    add r9, rax
    mov qword ptr [rbp+4F8h], r9
    movzx r9d, byte ptr [byte_7FF8571CF938]
    add r9b, 41h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, r9d
    xor al, 60h
    lea r8d, [rax-60h]
    lea edx, [rax-40h]
    mov ecx, edx
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
    add al, 4Ah
    xor al, 76h
    add al, r9b
    mov r9d, r8d
    not r9b
    movzx r10d, r9b
    lea r9d, [r10+r10*4]
    mov r11d, eax
    or r11b, r10b
    not r11b
    movzx r11d, r11b
    lea r11d, [r11+r11*2]
    mov edi, eax
    or dil, r8b
    not dil
    movzx edi, dil
    lea edi, [rdi+rdi*4]
    xor r8b, al
    add r8b, r8b
    and al, r10b
    shl al, 3
    sub al, r8b
    add al, dil
    add al, r11b
    sub al, r9b
    mov r8d, eax
    or r8b, cl
    not r8b
    movzx r8d, r8b
    lea r8d, [r8+r8*2]
    mov r9d, eax
    or r9b, dl
    not r9b
    shl r9b, 2
    and cl, al
    mov r10d, ecx
    not r10b
    add cl, cl
    and al, dl
    add al, al
    add al, cl
    sub r10b, al
    sub r10b, r9b
    sub r10b, r8b
    add r10b, 0FDh
    mov byte ptr [rbp+500h], r10b
    mov rax, qword ptr [rbp+550h]
    mov qword ptr [rbp+538h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [qword_7FF8571CF940]
    mov rax, 3567D671CE0D622Ah
    lea r8, [rcx+rax]
    mov rax, r8
    mov rdx, 5882CCAABA70207h
    xor rax, rdx
    mov rdx, 54DCB747A526B134h
    add rdx, rax
    mov r9, rdx
    mov r10, 2D406C5A89BF769h
    xor r9, r10
    add r9, rax
    mov r10, -37D8CDCB1F56807Dh
    sub r10, r9
    mov r9, r8
    not r9
    mov r11, r10
    or r11, r9
    mov rdi, r10
    or rdi, r8
    and r8, r10
    and r9, r10
    not rdi
    add r9, r9
    lea r9, [r9+r8*2]
    not r8
    add r8, rdi
    add r9, r8
    not r11
    lea r8, [r9+r11*2]
    add r8, rdx
    sub r8, rcx
    mov rcx, 94F9FEFBC7374Ch
    add rax, rcx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rbp+5E0h], rax
    jnz loc_7FF856A03647
    mov rax, qword ptr [rbp+538h]
    loc_7FF856A03637:
    mov qword ptr [rbp+520h], 0
    jmp loc_7FF856A07CA0
    loc_7FF856A03647:
    mov rsi, r12
    mov qword ptr [rbp+2E0h], 0
    nop word ptr [rax+rax+00000000h]
    loc_7FF856A03660:
    mov rax, qword ptr [rbp+2E0h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rbp+538h]
    movzx ecx, byte ptr [rcx+rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rbp-28h], rax
    cmp cl, 2Bh
    jz loc_7FF856A05256
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [qword_7FF8571CF950]
    mov rdx, rcx
    not rdx
    mov r8, rcx
    or r8, r15
    mov r9, 1C6A94959A3EC751h
    and rdx, r9
    mov r9, rcx
    xor r9, r15
    lea r9, [r9+r9*2]
    lea r10, [r8+r8*4]
    not r8
    mov r11, rcx
    and r11, r15
    lea r11, [r11+r11*2]
    add r11, r11
    mov rdi, 3956B6A65C138AEh
    and rcx, rdi
    lea rcx, [r11+rcx*8]
    sub rcx, r10
    sub rcx, r9
    lea rdx, [rcx+rdx*8]
    add rdx, r8
    mov rcx, 5FBCD34BFD991541h
    lea r8, [rdx+rcx]
    mov r9, r8
    not r9
    mov r10, r8
    mov rbx, -153AB5716A22BADBh
    or r10, rbx
    mov rcx, r8
    mov r14, 153AB5716A22BADAh
    xor rcx, r14
    lea r11, [rcx+rcx*2]
    mov rdi, r8
    and rdi, rbx
    mov rcx, r8
    and rcx, r14
    sub rcx, rdi
    add rcx, r11
    sub rcx, r10
    not r10
    shl r10, 2
    and r9, rbx
    add rcx, r9
    sub rcx, r10
    mov r9, -1037371552A6596Ah
    add r9, rcx
    mov r11, 233B93E6C60AD3D2h
    sub r11, rcx
    xor r11, r8
    mov r14, r9
    not r14
    mov r8, r11
    or r8, r14
    not r8
    lea r10, [r8+r8*4]
    lea r10, [r8+r10*4]
    mov rdi, r11
    or rdi, r9
    lea r8, [rdi+rdi*4]
    lea r8, [rdi+r8*2]
    not rdi
    lea rbx, [rdi+rdi*4]
    lea rdi, [rdi+rbx*2]
    and r9, r11
    mov rbx, r9
    not rbx
    lea r12, [rbx+rbx*4]
    lea rbx, [rsp]
    and r14, r11
    lea r11, [r14+r14*4]
    lea r11, [r14+r11*4]
    lea r9, [r9+r9*8]
    add r9, r11
    sub r8, r9
    add r8, rbx
    sub r8, rdi
    sub r8, r10
    mov r11, rdx
    not r11
    mov r9, r8
    or r9, r11
    mov r10, r8
    or r10, rdx
    mov rdi, r8
    xor rdi, rdx
    and r11, r8
    and r8, rdx
    mov rdx, rdi
    shl r11, 3
    add r8, r8
    sub r11, r8
    lea r8, [rdi*8]
    sub rdi, r8
    add rdi, r11
    not rdx
    lea rdx, [rdi+rdx*4]
    not r10
    shl r10, 2
    sub rdx, r10
    not r9
    lea rdx, [rdx+r9*8]
    xor rdx, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rdx, rax
    cmp rdx, qword ptr [rbp+5E0h]
    ja loc_7FF856A0529C
    mov rcx, qword ptr [qword_7FF8571CF948]
    mov r8, rcx
    mov rdx, -7F40CEEC5618E5E6h
    xor r8, rdx
    mov rdx, 7AB4956CCC29D942h
    add rdx, r8
    mov r9, rdx
    mov r10, 3A10C5E1D3381F4Ah
    xor r9, r10
    mov r10, r9
    mov r11, r9
    mov rdi, 79DB3F875C5B43h
    and r11, rdi
    mov rbx, -79DB3F875C5B44h
    and r9, rbx
    lea r9, [r9+r9*8]
    lea r9, [r9+r11*4]
    mov r11, rdx
    mov rdi, 458620002883A0B4h
    xor r11, rdi
    mov rdi, 7F8624C078A3A4BCh
    and r11, rdi
    lea r11, [r11+r11*4]
    or r10, rbx
    lea r10, [r10+r10*2]
    sub r9, r10
    lea r9, [r9+r11*2]
    mov r10, 2DB237D2C2A2398h
    add r9, r10
    mov r10, -4F2FB7DC029B5E4Dh
    xor rdx, r10
    sub rdx, r8
    mov r8, r9
    not r8
    mov r10, rdx
    or r10, r8
    not r10
    lea r11, [r10+r10*4]
    lea r10, [r10+r11*2]
    lea r11, [r9+r9*4]
    lea r11, [r9+r11*2]
    and r8, rdx
    add r8, r11
    mov r11, rdx
    or r11, r9
    add r8, r11
    and r9, rdx
    imul r9, 0F5h
    add r9, r8
    sub r9, r10
    sub r9, rdx
    xor r9, rcx
    add rax, r9
    mov qword ptr [rbp+2E0h], rax
    jmp loc_7FF856A03660
    loc_7FF856A03ED4:
    mov r9, qword ptr [rbp+3F8h]
    add r9, 20h
    mov qword ptr [rsp+20h], 3Eh
    mov ecx, 2Dh
    mov edx, 55h
    lea r8, [rbp+58Ch]
    call sub_7FF855CA1330
    test al, al
    jz loc_7FF856A0632F
    mov eax, dword ptr [rbp+58Ch]
    mov rcx, qword ptr [rbp+610h]
    mov edx, dword ptr [dword_7FF8571CFC50]
    mov r8d, -0FE5AAEh
    xor edx, r8d
    lea r8d, [rdx+3B8046E0h]
    xor r8d, 65B0FB47h
    sub r8d, edx
    add r8d, -1ED0901Bh
    or r8d, dword ptr [rcx]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rbp+610h]
    mov dword ptr [rcx], r8d
    mov rcx, qword ptr [rbp+88h]
    mov dword ptr [rcx], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r14b, 1
    mov byte ptr [rbp+632h], r14b
    jmp loc_7FF856A06338
    loc_7FF856A0406F:
    cmp byte ptr [rbp+635h], 0
    jz loc_7FF856A068FA
    mov eax, dword ptr [dword_7FF857242940]
    lea ecx, [rax+73E90832h]
    mov edx, ecx
    xor edx, -52C0A5B1h
    lea r8d, [rdx-150711Ch]
    lea r9d, [rdx+2106026Bh]
    xor r9d, r8d
    xor ecx, -146AD02Fh
    add ecx, edx
    xor ecx, eax
    xor ecx, r9d
    xor ecx, 14B6954h
    lea eax, [rdx+rcx]
    add eax, -74CC629h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A040C7:
    mov rax, qword ptr [rbp+48h]
    mov rdx, rax
    shr rdx, 1
    add rdx, rax
    mov rax, qword ptr [rbp+598h]
    cmp rdx, rax
    cmovbe rdx, rax
    loc_7FF856A040E2:
    mov rcx, qword ptr [qword_7FF8571CFBD8]
    mov r8, rcx
    mov rax, 0D0002350AEE8D76h
    xor r8, rax
    mov rax, -3028ECD3063D1517h
    add rax, r8
    add r8, rax
    add r8, rax
    mov rax, 27CB7FEDD341F2FDh
    sub rax, r8
    xor rax, rcx
    mov rcx, qword ptr [qword_7FF8571CFBE0]
    mov r8, -33844AC73860EA1Ch
    add r8, rcx
    mov r9, -49675971C9CC8C01h
    lea r14, [rcx+r9]
    mov r9, r14
    mov r10, r14
    mov r11, r14
    mov rdi, r14
    mov rbx, -25A88D04CE805A25h
    xor r8, rbx
    sub r8, r14
    not r14
    mov rbx, 42C40A8F25CE3AA0h
    xor r9, rbx
    mov rsi, r12
    mov r12, 1D3BF570DA31C55Fh
    and r11, r12
    shl r11, 3
    and rdi, rbx
    add rdi, rdi
    sub r11, rdi
    lea rdi, [r9*8]
    sub r9, rdi
    mov rdi, r14
    mov rbx, 2C40A8F25CE3AA0h
    and rdi, rbx
    mov rbx, 3D3BF570DA31C55Fh
    and r14, rbx
    shl r14, 2
    xor r10, rbx
    add r9, r11
    lea r9, [r9+r10*4]
    sub r9, r14
    lea r10, [r9+rdi*8]
    mov r11, r10
    not r11
    mov r9, r8
    or r9, r11
    mov rdi, r8
    or rdi, r10
    mov r14, r8
    xor r14, r10
    and r11, r8
    and r8, r10
    shl r11, 2
    lea r8, [r11+r8*2]
    sub r8, r14
    mov r10, 4610E6A6592697F4h
    add r10, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add rdi, rdi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r8, rdi
    lea r8, [r8+r9*4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r10, rcx
    xor r10, r8
    and r10, qword ptr [rbp+3C0h]
    and rax, rdx
    or r10, rax
    mov rax, qword ptr [rbp+4D0h]
    mov qword ptr [rax], r10
    mov rax, qword ptr [qword_7FF8571CFBE8]
    mov rcx, 0D78B11457B828A4h
    lea r8, [rax+rcx]
    mov rcx, r8
    not rcx
    mov r9, r8
    mov rdi, 53FE34D8E8773A22h
    xor r9, rdi
    mov r10, r8
    mov r11, r8
    mov rbx, 0C01CB271788C5DDh
    and r11, rbx
    shl r11, 3
    and r8, rdi
    add r8, r8
    sub r11, r8
    lea r8, [r9*8]
    sub r9, r8
    mov r8, rcx
    mov rdi, 13FE34D8E8773A22h
    and r8, rdi
    mov rdi, 2C01CB271788C5DDh
    and rcx, rdi
    shl rcx, 2
    xor r10, rdi
    add r9, r11
    lea r9, [r9+r10*4]
    sub r9, rcx
    lea rcx, [r9+r8*8]
    mov r8, 1CDC106A6B203615h
    add r8, rcx
    mov r9, r8
    not r9
    mov r10, r9
    mov r11, r9
    mov rdi, -451B05E648CE9C47h
    or r9, rdi
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
    nop
    nop
    nop
    nop
    nop
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
    mov r9, 451B05E648CE9C46h
    and r10, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r11, rdi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8, r11
    lea r8, [r8+r10*2]
    sub rax, r8
    add rdx, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, -46B40C8E1D7DDB60h
    add rdx, rcx
    add rdx, rax
    mov rax, qword ptr [qword_7FF8571CFBF0]
    mov rcx, -128DE5DCB6835739h
    add rcx, rax
    mov r8, rcx
    not r8
    mov r9, r8
    mov r10, r8
    mov r11, 68069B68C2CDD953h
    or r8, r11
    lea rcx, [r8+rcx*2]
    mov r8, 17F964973D3226ACh
    and r9, r8
    and r10, r11
    add rcx, r10
    lea rcx, [rcx+r9*2]
    mov r8, -7A6385462F48EC66h
    lea r9, [rcx+r8]
    mov r8, r9
    mov r10, -2CA76666DBCF814Dh
    xor r8, r10
    sub r8, r9
    mov r9, 39EE98DAA8E153EAh
    add r8, r9
    xor r8, rax
    sub r8, rcx
    sub r8, rax
    mov rax, qword ptr [off_7FF8571A2640]
    mov rax, qword ptr [rax+10h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, -48AE2EE0C4A6B131h
    add r8, rcx
    loc_7FF856A0483D:
    mov rcx, rsi
    call rax
    loc_7FF856A04842:
    mov qword ptr [rbp+488h], rax
    mov r8, qword ptr [qword_7FF8571CFBF8]
    mov rax, r8
    mov rcx, -0E38AB7B540EB41h
    xor rax, rcx
    mov rcx, -5AED3628433166E2h
    add rcx, rax
    mov r9, rcx
    not r9
    mov rdx, r9
    mov rdi, -2F2603081F0E1812h
    and rdx, rdi
    lea r10, [rdx+rdx*4]
    lea r10, [rdx+r10*2]
    mov rdx, rcx
    or rdx, rdi
    mov r11, rcx
    mov rbx, 2F2603081F0E1811h
    and r11, rbx
    add r11, rdx
    mov rdx, rcx
    and rdx, rdi
    imul rdx, 0F5h
    add rdx, r11
    sub rdx, r10
    add rdx, r9
    mov r10, r8
    not r10
    mov r9, r8
    mov r11, -20AD0F643263F60Ah
    and r9, r11
    lea r11, [r9+r9*4]
    lea r9, [r9+r11*4]
    mov rdi, r8
    mov rbx, 20AD0F643263F609h
    or rdi, rbx
    lea r11, [rdi+rdi*4]
    lea r11, [rdi+r11*2]
    not rdi
    lea r14, [rdi+rdi*4]
    lea rdi, [rdi+r14*2]
    and r8, rbx
    lea r14, [r8+r8*8]
    not r8
    lea r12, [r8+r8*4]
    lea r12, [r12]
    and r10, rbx
    lea r8, [r10+r10*4]
    lea rbx, [r10+r8*4]
    mov r10, qword ptr [rbp+5A0h]
    add rbx, r14
    mov r8, 25D59965C6BB983Ah
    add r8, rdx
    sub r11, rbx
    add r11, r12
    sub r11, rdi
    sub r11, r9
    sub r11, rdx
    mov r9, 6A22159559B08C5h
    add rcx, r9
    add rcx, r11
    xor rcx, r8
    mov r9, -46CF8B33B8EDBDCAh
    xor r8, r9
    add r8, rax
    add r8, rcx
    sub r8, rdx
    add r8, qword ptr [r10+8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [qword_7FF8571CFC00]
    mov rcx, rax
    mov r10, 7253905D0379769Ah
    or rcx, r10
    lea rdx, [rcx+rcx*2]
    not rcx
    lea r9, [rcx*8]
    sub r9, rcx
    mov rcx, rax
    and rcx, r10
    lea r10, [rcx+rdx*2]
    add r10, r9
    mov r11, 2370B13A398DC9E5h
    sub r11, r10
    mov rdx, -2598F67F2F5C45E6h
    sub rdx, r10
    mov rcx, -32967BE2DCDED097h
    sub rcx, r10
    mov r9, -740F04DFB953E865h
    sub r9, r10
    mov rdi, r11
    not rdi
    mov rbx, rdi
    mov r12, 583AD06AC89E7F91h
    or rbx, r12
    mov r14, rdi
    mov r13, -583AD06AC89E7F92h
    and r14, r13
    add r14, rbx
    and r11, r12
    add r11, r11
    mov rbx, -4F8A5F2A6EC300DEh
    xor r11, rbx
    add r11, r14
    sub r11, rdi
    lea rdi, [r11+r10]
    add rdi, 8
    mov r14, r9
    not r14
    mov r10, rdi
    or r10, r14
    mov r11, rdi
    or r11, r9
    mov rbx, rdi
    xor rbx, r9
    and r14, rdi
    and r9, rdi
    mov rdi, rbx
    shl r14, 3
    add r9, r9
    sub r14, r9
    lea r9, [rbx*8]
    sub rbx, r9
    add rbx, r14
    not rdi
    lea r9, [rbx+rdi*4]
    not r11
    shl r11, 2
    sub r9, r11
    not r10
    lea r9, [r9+r10*8]
    add r9, rax
    xor rcx, rdx
    xor rcx, r9
    mov rax, -761D7772408941D8h
    add r8, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp r8, rcx
    jnz loc_7FF856A07316
    mov eax, dword ptr [dword_7FF857242A08]
    mov ecx, eax
    xor ecx, -1CA51398h
    lea edx, [rcx-7205A8DFh]
    xor edx, 6585CBBAh
    lea r8d, [rdx+538F70E7h]
    xor r8d, eax
    lea eax, [r8+rcx]
    add eax, -7205A8DFh
    add eax, edx
    mov dword ptr [rbp+63Ch], eax
    mov r13, 7FFFFFFFFFFFFFFFh
    mov r12, rsi
    jmp loc_7FF8569F0600
    loc_7FF856A04F5B:
    lea rax, Src
    mov qword ptr [rbp+2D0h], rax
    mov eax, dword ptr [dword_7FF857242980]
    mov ecx, -22236E9h
    xor eax, ecx
    add eax, -26228098h
    mov ecx, eax
    xor ecx, -6E8F9C46h
    lea edx, [rcx-6AE2F2ECh]
    mov r8d, edx
    xor r8d, -8607DB1h
    xor edx, ecx
    xor edx, 51B6188Eh
    add edx, r8d
    xor edx, eax
    jmp loc_7FF8569F05F9
    loc_7FF856A04FA5:
    mov eax, dword ptr [dword_7FF85724299C]
    lea ecx, [rax-66EDB584h]
    lea edx, [rax-53816437h]
    xor ecx, edx
    xor edx, 1BEE788Eh
    add edx, 21D1DF45h
    xor edx, ecx
    sub edx, eax
    add edx, 779169FEh
    jmp loc_7FF8569F05F9
    loc_7FF856A04FD4:
    mov rcx, qword ptr [rbp+600h]
    loc_7FF856A04FDB:
    mov qword ptr [rbp+270h], rcx
    mov qword ptr [rbp+268h], rax
    mov rax, qword ptr [rbp+270h]
    mov rcx, qword ptr [rbp+160h]
    mov qword ptr [rbp+550h], rcx
    mov rcx, qword ptr [rbp+608h]
    mov rdx, qword ptr [rbp+268h]
    and rdx, r13
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+628h]
    mov qword ptr [rax], rdx
    loc_7FF856A0501C:
    mov rax, qword ptr [rbp+4E8h]
    mov qword ptr [rbp+490h], rax
    mov rax, qword ptr [rbp+610h]
    mov ecx, dword ptr [dword_7FF8571CFBB0]
    mov edx, ecx
    mov r8d, -44F5E2B5h
    sub r8d, ecx
    not ecx
    lea r9d, [rcx+rcx]
    mov r10d, ecx
    and r10d, -23914FF3h
    and ecx, 23914FF2h
    and edx, 23914FF2h
    lea ecx, [rdx+rcx*2]
    add ecx, r10d
    sub ecx, r9d
    mov edx, ecx
    mov r9d, ecx
    and r9d, 37EE6D7Eh
    mov r10d, ecx
    and r10d, -37EE6D7Fh
    lea r9d, [r10+r9*2]
    sub r9d, ecx
    not ecx
    mov r10d, ecx
    and r10d, -37EE6D7Fh
    and ecx, 37EE6D7Eh
    add ecx, ecx
    xor edx, 37EE6D7Eh
    lea edx, [r9+rdx*2]
    sub edx, ecx
    add edx, r10d
    xor r8d, edx
    xor edx, 6C55301Eh
    add edx, r8d
    or edx, dword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+610h]
    mov dword ptr [rax], edx
    mov rax, qword ptr [rbp+548h]
    mov rax, qword ptr [rax]
    mov qword ptr [rbp+3C8h], rax
    cmp rax, qword ptr [qword_7FF8572A3878]
    jz loc_7FF856A05228
    mov eax, dword ptr [dword_7FF857242A18]
    mov ecx, 5DB4F757h
    loc_7FF856A0521B:
    add eax, ecx
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A05228:
    mov eax, dword ptr [dword_7FF8572429F8]
    lea ecx, [rax-49AD68BFh]
    xor ecx, -5E1B3CB7h
    add ecx, eax
    add ecx, eax
    add ecx, -49AD68BFh
    add eax, ecx
    add eax, 5313A29Ch
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A05256:
    mov rax, qword ptr [rbp-28h]
    mov qword ptr [rbp+350h], rax
    cmp rax, -1
    mov r12, rsi
    jz loc_7FF856A0804E
    mov eax, dword ptr [dword_7FF857242A94]
    mov ecx, -634AD88Dh
    add eax, ecx
    mov ecx, eax
    xor ecx, 5ACC6BFh
    lea edx, [rcx+5F40FD76h]
    xor eax, -508CE94h
    add eax, ecx
    add eax, 314A60E0h
    xor eax, edx
    jmp loc_7FF856A06103
    loc_7FF856A0529C:
    mov eax, dword ptr [dword_7FF857242928]
    lea ecx, [rax+32A7D830h]
    mov edx, ecx
    xor edx, 0BDCE5A5h
    lea r8d, [rdx+5E2B0F29h]
    lea r9d, [rdx-3E13741Ch]
    xor eax, 85D0BDAh
    add eax, edx
    sub eax, r9d
    xor r8d, ecx
    xor r8d, eax
    add r8d, edx
    sub r8d, r9d
    add r8d, -43F514B7h
    loc_7FF856A052DB:
    mov dword ptr [rbp+63Ch], r8d
    mov r12, rsi
    jmp loc_7FF8569F0600
    loc_7FF856A052EA:
    mov eax, dword ptr [dword_7FF85724292C]
    lea ecx, [rax+2697428Fh]
    mov edx, -424FA2Fh
    sub edx, eax
    xor edx, ecx
    add eax, edx
    add eax, 6C53A515h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A05311:
    mov eax, dword ptr [dword_7FF857242924]
    lea ecx, [rax+rax]
    lea edx, [rax-5B1AEB0Ah]
    xor edx, 14F862B1h
    lea r8d, [rdx-5D6D0875h]
    neg ecx
    add eax, ecx
    add eax, -259C2AA8h
    xor eax, r8d
    jmp loc_7FF856A07FD2
    loc_7FF856A0533E:
    mov qword ptr [rbp+190h], rcx
    loc_7FF856A05345:
    mov rax, qword ptr [rbp+190h]
    mov rcx, qword ptr [rbp+428h]
    mov qword ptr [rbp+110h], rcx
    mov rcx, rax
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
    and rax, r13
    lea rax, [rax+rax*4]
    lea rax, [rax+rcx*4]
    add rax, 4
    mov rcx, qword ptr [rbp+5D0h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+428h]
    mov qword ptr [rbp+208h], rax
    loc_7FF856A053C8:
    mov rsi, r12
    mov rcx, qword ptr [rbp+208h]
    mov r8, qword ptr [rbp+5E8h]
    mov rdx, qword ptr [rbp+20h]
    call memcpy
    mov rax, qword ptr [rbp+110h]
    loc_7FF856A053E9:
    mov qword ptr [rbp+200h], rax
    mov rax, qword ptr [rbp+200h]
    mov rcx, qword ptr [rbp+5E8h]
    mov byte ptr [rax+rcx], 0
    mov rax, qword ptr [rbp+5E8h]
    mov rcx, qword ptr [rbp+460h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+5D0h]
    mov rax, qword ptr [rax]
    mov qword ptr [rbp+348h], rax
    mov r9, qword ptr [qword_7FF8571CF998]
    mov rax, -1371144E6F028F27h
    add rax, r9
    mov rcx, rax
    mov r11, -3DA950BF4D4DC89h
    or rcx, r11
    lea r8, [rax+rax]
    mov rdx, rax
    mov r10, 3DA950BF4D4DC88h
    and rdx, r10
    mov r10, rax
    and r10, r11
    lea r10, [r10+r10*2]
    lea rdx, [r10+rdx*2]
    sub rdx, r8
    add rdx, rcx
    mov rcx, -7E7B077305163E51h
    add rcx, rdx
    mov r8, rcx
    not r8
    mov rbx, 3AD53EE5098A9E75h
    and r8, rbx
    add r8, r8
    lea r8, [r8+r8*4]
    mov r10, rcx
    mov r14, -452AC11AF675618Bh
    or r10, r14
    lea r11, [r10+r10*4]
    lea r10, [r10+r11*2]
    mov rdi, rcx
    xor rdi, rbx
    add rdi, rdi
    mov rbx, rcx
    mov r11, 52AC11AF675618Ah
    and rbx, r11
    shl rbx, 3
    mov r11, rcx
    and r11, r14
    imul r11, 0F5h
    sub r11, rbx
    sub r11, rdi
    add r11, r10
    sub r11, r8
    mov rdi, r11
    mov r12, 36144798908713C7h
    or rdi, r12
    mov r10, r11
    not r10
    lea rbx, [r11+r11]
    mov r8, r11
    mov r14, 49EBB8676F78EC38h
    and r8, r14
    mov r14, r11
    and r14, r12
    lea r14, [r14+r14*2]
    lea r8, [r14+r8*2]
    sub r8, rbx
    add r8, rdi
    mov rdi, 601ECCAAE2909FB7h
    lea r14, [r8+rdi]
    mov rdi, r14
    or rdi, r10
    mov r12, r14
    or r12, r11
    mov rbx, r14
    xor rbx, r11
    and r10, r14
    and r14, r11
    mov r11, rbx
    shl r10, 3
    add r14, r14
    sub r10, r14
    lea r14, [rbx*8]
    sub rbx, r14
    not rdi
    not r12
    shl r12, 2
    not r11
    add rbx, r10
    lea r10, [rbx+r11*4]
    sub r10, r12
    lea r11, [r10+rdi*8]
    mov r10, r9
    not r10
    lea rdi, [r10+r10*2]
    mov rbx, r11
    or rbx, r10
    mov r14, r11
    or r14, r9
    and r10, r11
    lea r12, [r10+r10*2]
    and r9, r11
    sub r12, r9
    not r14
    lea r10, [r14+r14*2]
    add r12, r11
    add r10, rbx
    add r10, r12
    sub r10, rdi
    inc r10
    mov r9, r10
    mov rdi, rdx
    not rdi
    mov r11, r10
    or r11, rdi
    mov rbx, r10
    or rbx, rdx
    and rdi, r10
    and r10, rdx
    lea rdx, [r10+r10*4]
    lea rdx, [r10+rdx*2]
    add rdx, rdi
    not rdi
    lea r10, [rdi+rdi*4]
    lea r10, [rdi+r10*2]
    sub rdx, r10
    not rbx
    lea r10, [rbx+rbx*4]
    lea rdx, [rdx+r10*2]
    not r9
    not r11
    lea r10, [r11+r11*8]
    add r10, r9
    add r10, rdx
    xor r10, rcx
    sub r10, rax
    xor r10, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rbp+348h], r10
    jge loc_7FF856A05D48
    mov rax, qword ptr [rbp+110h]
    mov qword ptr [rbp-8], rax
    mov rcx, qword ptr [rbp+4E8h]
    mov qword ptr [rbp+318h], rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rax, qword ptr [rbp+318h]
    mov qword ptr [rbp+310h], rax
    mov rax, qword ptr [rbp+620h]
    mov rax, qword ptr [rax]
    mov qword ptr [rbp+308h], rax
    mov rax, qword ptr [qword_7FF8571CF9A0]
    mov rcx, -547AA965EE0A7C1Bh
    add rcx, rax
    mov rdx, -59F5C30FE8D0B85Dh
    add rdx, rax
    xor rdx, rcx
    mov r8, 0A87F8DC81438D70h
    xor rcx, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, -5E960EBDADA75328h
    add rdx, r8
    mov r8, rax
    not r8
    mov r9, rdx
    or r9, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or rax, rdx
    not rax
    shl rax, 2
    and rdx, r8
    mov r10, rdx
    not r10
    add r10, r10
    sub r10, rdx
    sub r10, rax
    add r10, r9
    lea rax, [r10+r8*2]
    sub rax, rcx
    mov rcx, 7A1053D137850C3Fh
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
    and rax, qword ptr [rbp+308h]
    mov qword ptr [rbp-10h], rax
    cmp qword ptr [rbp+5E8h], rax
    mov r12, rsi
    jbe loc_7FF856A05D74
    mov eax, dword ptr [dword_7FF857242B04]
    lea ecx, [rax-4837834Ah]
    lea edx, [rax+604C368Ah]
    mov r8d, edx
    xor r8d, -770B7856h
    sub r8d, eax
    sub r8d, eax
    add r8d, -552070D3h
    xor edx, ecx
    xor edx, r8d
    xor edx, -9C7C936h
    add edx, eax
    jmp loc_7FF8569F05F9
    loc_7FF856A05D48:
    mov eax, dword ptr [dword_7FF8572429B0]
    mov ecx, eax
    xor ecx, -45E2E16Ah
    lea edx, [rcx-10F4F804h]
    xor edx, ecx
    xor edx, 9A08EDCh
    sub edx, eax
    mov dword ptr [rbp+63Ch], edx
    mov r12, rsi
    jmp loc_7FF8569F0600
    loc_7FF856A05D74:
    mov eax, dword ptr [dword_7FF857242AF8]
    lea ecx, [rax+1AFE6229h]
    mov edx, ecx
    xor edx, -7ECA0CC2h
    lea r8d, [rax-7CEA2A31h]
    loc_7FF856A05D8F:
    xor r8d, eax
    add r8d, edx
    sub r8d, ecx
    mov dword ptr [rbp+63Ch], r8d
    jmp loc_7FF8569F0600
    loc_7FF856A05DA4:
    mov eax, dword ptr [dword_7FF8572429F0]
    lea ecx, [rax-613F64B6h]
    mov edx, ecx
    xor edx, 1AA33F9h
    lea r8d, [rdx+77D17BEAh]
    add eax, -1BC36BF8h
    xor eax, edx
    xor eax, r8d
    xor eax, ecx
    xor eax, -61F5FCD9h
    add eax, edx
    add eax, 70D06700h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A05DE2:
    mov eax, dword ptr [dword_7FF857242AB4]
    lea ecx, [rax+3C7F5834h]
    add eax, 7F68BD7h
    xor eax, ecx
    add eax, 60874B83h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A05E05:
    mov qword ptr [rbp+1B0h], rax
    mov eax, dword ptr [dword_7FF857242AE0]
    mov ecx, eax
    xor ecx, 7524AB43h
    lea edx, [rcx-2F6B1A27h]
    lea r8d, [rcx+126B2262h]
    lea r9d, [rcx+3B65FAA3h]
    lea r10d, [rcx-421DC9D3h]
    xor r10d, r9d
    xor r10d, edx
    xor r10d, -5E04A8C2h
    add r10d, eax
    xor r10d, r8d
    lea eax, [rcx+r10]
    add eax, -39BB1177h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A05E5C:
    mov r8, qword ptr [rbp+5E8h]
    mov rdx, qword ptr [rbp-8]
    mov rcx, qword ptr [rbp+300h]
    call memcpy
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jmp loc_7FF856A06917
    loc_7FF856A05EE4:
    mov eax, dword ptr [dword_7FF8572429A4]
    mov ecx, eax
    xor ecx, -6BC79510h
    mov edx, ecx
    add edx, 7C60566Eh
    add ecx, edx
    add ecx, 7C60566Eh
    neg ecx
    add eax, ecx
    add eax, 5F0AE0F7h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A05F16:
    mov eax, dword ptr [dword_7FF8572429E4]
    lea ecx, [rax-57E55B86h]
    lea edx, [rax-2F80D4CCh]
    xor ecx, -66D8E266h
    add ecx, edx
    add ecx, -70441EB9h
    xor edx, eax
    xor edx, ecx
    mov dword ptr [rbp+63Ch], edx
    jmp loc_7FF8569F0600
    loc_7FF856A05F45:
    mov qword ptr [rbp+218h], rax
    mov eax, dword ptr [dword_7FF857242A7C]
    lea ecx, [rax+66E13BE8h]
    mov edx, ecx
    xor edx, 614AB06h
    lea r8d, [rdx+75AC0770h]
    mov r9d, r8d
    xor r9d, -61C71C2Ah
    lea r10d, [r9+0C399AD1h]
    xor r10d, 2425F085h
    xor r8d, ecx
    xor r8d, -5F2B23BEh
    sub r8d, edx
    sub r8d, r10d
    xor r8d, r9d
    jmp loc_7FF856A07F60
    loc_7FF856A05F97:
    mov eax, dword ptr [dword_7FF857242A04]
    lea ecx, [rax-344C51h]
    mov edx, ecx
    xor edx, -603A9F55h
    mov r8d, ecx
    xor r8d, -321E89A5h
    xor ecx, 6A0F6998h
    lea r9d, [rcx+32B595F0h]
    xor r9d, -1625B8A1h
    neg r8d
    add r8d, eax
    add r8d, -344C51h
    add r8d, edx
    sub r8d, eax
    add r8d, r9d
    lea eax, [rcx+r8]
    add eax, 2BC1E69Dh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A05FF3:
    mov qword ptr [rbp+1B8h], rcx
    mov eax, dword ptr [dword_7FF857242AC8]
    lea ecx, 0FFFFFFFF99DFAF3Bh[rax*2]
    add eax, 1CFC6057h
    xor ecx, eax
    xor ecx, 499E2B2Dh
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF856A0601F:
    mov rax, qword ptr [rbp+5F8h]
    mov rcx, qword ptr [rbp+10h]
    mov qword ptr [rbp+1D8h], rax
    mov qword ptr [rbp+1D0h], rcx
    mov dword ptr [rbp+63Ch], 0ABDD222h
    jmp loc_7FF8569F0600
    loc_7FF856A06047:
    mov rax, qword ptr [rbp+458h]
    mov qword ptr [rbp+208h], rax
    mov eax, dword ptr [dword_7FF857242A9C]
    mov ecx, eax
    xor ecx, 15338CA4h
    lea edx, [rcx+1B9B7129h]
    xor edx, -50D61C3Ch
    lea r8d, [rdx-1DF2B686h]
    mov r9d, r8d
    xor r9d, 5FA8EB00h
    lea r10d, [rcx+r9]
    add r10d, 1B9B7129h
    xor r9d, ecx
    xor r9d, -636E8298h
    sub r9d, edx
    sub r9d, r8d
    add r9d, eax
    sub r9d, r10d
    add r9d, -4B91A060h
    mov dword ptr [rbp+63Ch], r9d
    jmp loc_7FF8569F0600
    loc_7FF856A060B4:
    mov qword ptr [rbp+238h], rax
    mov eax, dword ptr [dword_7FF8572429CC]
    mov ecx, eax
    xor ecx, -3F801733h
    lea edx, [rcx-1874F839h]
    mov r8d, edx
    xor r8d, -6D43B736h
    lea r9d, [r8-2AF9CDB6h]
    lea r10d, [r8-5C58CEEAh]
    xor r10d, edx
    sub r10d, r8d
    xor r9d, eax
    xor r9d, r10d
    xor r9d, 5F5D391Bh
    lea eax, [r9+r8]
    add eax, -2AF9CDB6h
    loc_7FF856A06103:
    add eax, ecx
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A06110:
    mov eax, dword ptr [dword_7FF8572429D8]
    lea ecx, [rax+646C04F5h]
    xor ecx, 31C98C1h
    add ecx, -6ED7D9DFh
    xor ecx, eax
    add eax, ecx
    add eax, 1063B983h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A0613C:
    mov eax, dword ptr [dword_7FF857242A70]
    mov ecx, 48575AF9h
    sub ecx, eax
    xor eax, 2D6C378Fh
    xor ecx, eax
    add eax, -2F6703A7h
    loc_7FF856A06155:
    xor eax, ecx
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A06162:
    mov eax, dword ptr [dword_7FF857242A98]
    lea ecx, [rax-2AA38Ch]
    lea edx, [rax-3E14EF79h]
    mov r8d, -7FB1801Dh
    sub r8d, eax
    xor r8d, ecx
    xor r8d, edx
    sub r8d, eax
    sub r8d, eax
    add r8d, -9C760E3h
    mov dword ptr [rbp+63Ch], r8d
    jmp loc_7FF8569F0600
    loc_7FF856A0619C:
    mov rax, qword ptr [rbp+4A8h]
    mov qword ptr [rbp+2A0h], rax
    mov eax, dword ptr [dword_7FF857242A0C]
    mov ecx, 6785CEFBh
    add eax, ecx
    mov ecx, eax
    xor ecx, 58CF5394h
    sub eax, ecx
    sub eax, ecx
    add eax, 4D20BA76h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A061D3:
    mov qword ptr [rbp+220h], rax
    mov eax, dword ptr [dword_7FF857242A60]
    lea ecx, [rax+750321FEh]
    xor ecx, 48E93DA1h
    lea edx, [rcx+0B2E6BD6h]
    xor eax, edx
    xor edx, 7DD275B4h
    neg edx
    add ecx, edx
    add ecx, -21D29DC5h
    jmp loc_7FF856A08041
    loc_7FF856A06209:
    mov eax, dword ptr [dword_7FF85724295C]
    lea ecx, [rax+288E615Eh]
    xor ecx, -44B780h
    lea edx, [rcx+rcx]
    add ecx, -6771CAEAh
    sub edx, eax
    add edx, -114C384Bh
    xor edx, ecx
    jmp loc_7FF8569F05F9
    loc_7FF856A06233:
    mov eax, dword ptr [rbp+580h]
    not eax
    and eax, 1
    lea rcx, [rax*8]
    sub rcx, rax
    mov rdx, qword ptr [rbp+580h]
    not rdx
    and rdx, -2
    mov rax, rdx
    shl rax, 4
    add rax, rdx
    add rax, rcx
    mov rcx, qword ptr [rbp+580h]
    mov rdx, rcx
    not rdx
    add rdx, rdx
    or rdx, 2
    lea rdx, [rdx+rdx*2]
    or rcx, -2
    lea r8, [rcx+rcx*4]
    lea rcx, [rcx+r8*2]
    mov r8, qword ptr [rbp+580h]
    mov r9, r8
    mov r10, 3FFFFFFFFFFFFFFEh
    and r9, r10
    lea r9, [r9+r9*2]
    and r8d, 1
    lea r10, [r8+r8*8]
    lea r8, [r8+r10*2]
    lea r8, [r8+r9*4]
    sub r8, rcx
    sub r8, rdx
    add r8, rax
    mov qword ptr [rbp+2D8h], r8
    jmp loc_7FF856A0022C
    loc_7FF856A062C8:
    mov eax, dword ptr [dword_7FF85724293C]
    lea ecx, [rax-7DE66C42h]
    xor ecx, eax
    xor ecx, 1935D8B0h
    sub ecx, eax
    add ecx, -727B3999h
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF856A062EF:
    mov rax, qword ptr [rbp+5F0h]
    mov rcx, qword ptr [rbp+3D0h]
    mov qword ptr [rbp+290h], rax
    mov qword ptr [rbp+288h], rcx
    mov eax, dword ptr [dword_7FF857242930]
    mov ecx, -2BE4C068h
    xor eax, ecx
    lea ecx, [rax-7BB94F72h]
    mov edx, ecx
    xor edx, 57C6D517h
    sub edx, eax
    xor edx, ecx
    jmp loc_7FF8569F05F9
    loc_7FF856A0632F:
    and al, r14b
    mov byte ptr [rbp+632h], al
    loc_7FF856A06338:
    movzx eax, byte ptr [rbp+632h]
    loc_7FF856A0633F:
    mov byte ptr [rbp+63Ah], al
    loc_7FF856A06345:
    movzx eax, byte ptr [rbp+63Ah]
    mov byte ptr [rbp+61Eh], al
    mov rax, qword ptr [rbp+540h]
    mov rax, qword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    test rax, rax
    jz loc_7FF856A06409
    mov eax, dword ptr [dword_7FF857242974]
    mov ecx, eax
    xor ecx, 0FD40C32h
    lea edx, [rcx+5EC8E11Fh]
    mov r8d, edx
    xor r8d, -7E53A33Ch
    xor edx, 7BF2EA9Eh
    sub edx, r8d
    xor eax, ecx
    xor eax, edx
    add eax, ecx
    add eax, 5EC8E11Fh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A06409:
    mov rax, qword ptr [qword_7FF8571CFCD8]
    mov rcx, rax
    mov rdx, 12775E81300C1BA8h
    xor rcx, rdx
    mov rdx, rax
    mov r8, -583B7E94BF40A7EBh
    xor rdx, r8
    sub rdx, rcx
    mov rcx, 1B80FF0B7944CBBEh
    add rcx, rax
    add rdx, rcx
    mov rcx, 55E8B418D6F18AB0h
    xor rax, rcx
    xor rax, rdx
    cmp qword ptr [rbp+0B0h], rax
    jle loc_7FF856A06505
    mov rdx, qword ptr [rbp+0A0h]
    mov rax, qword ptr [off_7FF8571A2640]
    mov rax, qword ptr [rax+30h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FF856A064C0:
    mov rcx, r12
    call rax
    mov eax, dword ptr [dword_7FF857242944]
    mov ecx, eax
    xor ecx, -7C71F55Fh
    lea edx, [rcx-6C6DBF59h]
    mov r8d, edx
    xor r8d, -4E860FF9h
    mov r9d, edx
    xor r9d, 52DE6814h
    add r9d, r8d
    sub r9d, eax
    xor r9d, edx
    add r9d, ecx
    mov dword ptr [rbp+63Ch], r9d
    jmp loc_7FF8569F0600
    loc_7FF856A06505:
    mov rax, qword ptr [rbp+620h]
    mov rax, qword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [qword_7FF8571CFCE0]
    mov rcx, 18510899425965BDh
    lea r8, [rdx+rcx]
    mov rcx, -32C2F0D8C95B9F44h
    xor r8, rcx
    mov rcx, -727036BE1242C0B5h
    add rcx, r8
    add rdx, rcx
    mov r9, 7B93B9EF3E069111h
    xor rcx, r9
    mov r9, 69DBD98ECECB65BDh
    add r9, rcx
    add rcx, rdx
    mov rdx, 590A06264B4A6504h
    add rcx, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor rcx, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, -0A5C22D87AC386F5h
    add rcx, rdx
    mov rdx, rcx
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
    lea r8, [rcx+rcx]
    mov r10, r9
    not r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r10, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and rcx, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rcx, [rcx+rcx*2]
    lea rcx, [rcx+r10*2]
    sub rcx, r8
    add rcx, rdx
    cmp rax, rcx
    jle loc_7FF856A068C2
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rbp+4E8h]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF856A06873:
    mov rcx, r12
    call qword ptr [rax+30h]
    loc_7FF856A06879:
    mov eax, dword ptr [dword_7FF8572429BC]
    mov ecx, eax
    xor ecx, -700D7104h
    lea edx, [rcx-588A7795h]
    mov r8d, edx
    xor r8d, 5C8FDA7Dh
    lea r9d, [r8+66B50AA9h]
    xor eax, r8d
    xor eax, r9d
    xor eax, ecx
    xor eax, 46D66FEDh
    sub eax, ecx
    sub eax, r8d
    sub eax, edx
    add eax, 58B7E299h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A068C2:
    mov eax, dword ptr [dword_7FF8572429B4]
    lea ecx, [rax-75D06770h]
    lea edx, [rax+583CF329h]
    lea r8d, [rax-5F816630h]
    xor r8d, ecx
    add r8d, eax
    lea ecx, [rax+r8]
    add ecx, -0F4BC95Fh
    xor ecx, edx
    loc_7FF856A068ED:
    sub ecx, eax
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF856A068FA:
    mov rcx, qword ptr [rbp+300h]
    mov rdx, qword ptr [rbp+310h]
    add rdx, rcx
    mov r8, qword ptr [rbp+5E8h]
    call memcpy
    loc_7FF856A06917:
    movzx ecx, byte ptr [byte_7FF8571CF9E8]
    lea eax, [rcx-5Fh]
    mov edx, eax
    not dl
    mov r8d, edx
    and r8b, 76h
    add r8b, r8b
    add dl, dl
    or dl, 0ECh
    mov r9d, eax
    xor r9b, 89h
    sub dl, r9b
    sub dl, r8b
    lea r9d, [rdx+60h]
    add dl, 45h
    mov r10d, edx
    not r10b
    lea r11d, [r10+r10]
    mov ebx, r10d
    and bl, 3Bh
    and r10b, 44h
    add r10b, r10b
    mov r8d, edx
    and r8b, 0C4h
    add r8b, bl
    add r8b, r10b
    sub r8b, r11b
    lea r11d, [r8+9]
    mov r10d, r11d
    or r10b, r9b
    mov ebx, r9d
    not bl
    mov edi, r11d
    or dil, bl
    mov r14d, r11d
    xor r14b, r9b
    and bl, r11b
    and r11b, r9b
    movzx edi, dil
    movzx r9d, bl
    add r9d, r9d
    lea r9d, [r9+r9*2]
    movzx r11d, r11b
    add r11d, r11d
    lea r11d, [r11+r11*2]
    add r11b, r9b
    mov r9, qword ptr [rbp+4E8h]
    add edi, edi
    lea edi, [rdi+rdi*2]
    add r11b, r14b
    sub r11b, dil
    mov rdi, qword ptr [rbp+5E8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add r10d, r10d
    lea r10d, [r10+r10*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r11b, r10b
    xor al, cl
    xor al, r11b
    sub al, dl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub al, r8b
    add al, 0CDh
    mov byte ptr [r9+rdi], al
    mov rax, qword ptr [rbp+5C8h]
    mov rcx, qword ptr [rbp+5E8h]
    mov qword ptr [rax], rcx
    mov rdx, qword ptr [qword_7FF8571CF9F0]
    mov rax, -4056B8628FAE20A4h
    add rax, rdx
    mov r8, rax
    mov rcx, 76098A0726F2652Ah
    xor r8, rcx
    mov r9, rax
    mov rcx, -376E58C58635D339h
    xor r9, rcx
    mov rcx, -2BCB48EB230CB98Bh
    add rcx, r9
    add r9, r9
    add r9, rcx
    sub r9, rdx
    mov rdx, 77FFA5EC67360CC5h
    add r9, rdx
    mov rdx, r9
    mov r11, rax
    mov r10, -76098A0726F2652Bh
    xor r11, r10
    mov r10, r9
    or r10, r11
    mov rdi, r9
    or rdi, r8
    and r11, r9
    and r9, r8
    lea r8, [r9+r9*4]
    lea r8, [r9+r8*2]
    add r8, r11
    not r11
    lea r9, [r11+r11*4]
    lea r9, [r11+r9*2]
    sub r8, r9
    not rdi
    lea r9, [rdi+rdi*4]
    lea r8, [r8+r9*2]
    not rdx
    not r10
    lea r9, [r10+r10*8]
    add r9, rdx
    add r9, r8
    xor r9, rax
    mov rax, -7FC785B6BEAE2CF2h
    xor rcx, rax
    sub r9, rcx
    mov rax, qword ptr [rbp+5D0h]
    mov rax, qword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp rax, r9
    jle loc_7FF856A07059
    mov eax, dword ptr [dword_7FF857242B00]
    lea ecx, [rax-68487A41h]
    mov edx, eax
    sub edx, ecx
    add edx, 5F45328Dh
    xor edx, ecx
    sub edx, eax
    jmp loc_7FF8569F05F9
    loc_7FF856A07059:
    mov eax, dword ptr [dword_7FF857242AFC]
    mov ecx, -18BA18D4h
    add eax, ecx
    mov ecx, eax
    xor ecx, -603E38D7h
    xor eax, -62733997h
    loc_7FF856A07073:
    sub eax, ecx
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A07080:
    mov eax, dword ptr [dword_7FF857242954]
    lea ecx, [rax+43B223E1h]
    mov edx, ecx
    xor edx, 5F95236Ch
    lea r8d, [rdx-4BFDE871h]
    xor r8d, 0FD27AF1h
    xor ecx, 7D3B27E4h
    sub ecx, r8d
    add ecx, edx
    add r8d, 58F88C4Bh
    sub ecx, r8d
    xor r8d, 0E31A91Bh
    add r8d, eax
    add r8d, ecx
    lea eax, [rdx+r8]
    add eax, -320921B8h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A070D8:
    mov rax, qword ptr [rbp+450h]
    jmp loc_7FF856A071CD
    loc_7FF856A070E4:
    mov eax, dword ptr [dword_7FF857242A48]
    lea ecx, [rax+62CC9610h]
    lea edx, [rax-1A1A718h]
    lea r8d, [rax-1EB2CA5Eh]
    xor r8d, -626818B6h
    xor edx, 24D0D6CDh
    add edx, eax
    add edx, 574E1686h
    add edx, r8d
    xor edx, ecx
    sub edx, eax
    sub edx, eax
    add eax, edx
    add eax, 12066B29h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A0712D:
    mov rdx, qword ptr [rbp+0C0h]
    mov rcx, qword ptr [rbp+438h]
    call memcpy
    loc_7FF856A07140:
    mov rax, qword ptr [rbp+5B8h]
    mov rax, qword ptr [rax]
    test rax, rax
    js loc_7FF856A0719D
    mov eax, dword ptr [dword_7FF857242AF0]
    mov ecx, eax
    xor ecx, -378C40D8h
    lea edx, [rcx-0D4EA801h]
    mov r8d, edx
    xor r8d, -2E52B123h
    mov r9d, edx
    xor r9d, -0A4F8974h
    sub r9d, ecx
    sub r9d, eax
    add r8d, ecx
    add r8d, r9d
    xor edx, -62901722h
    lea eax, [rdx+r8]
    add eax, 0D3033Eh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A0719D:
    mov qword ptr [rbp+1A8h], rax
    mov rax, qword ptr [rbp+438h]
    mov qword ptr [rbp+0C0h], rax
    mov rax, qword ptr [rbp+1A8h]
    and rax, r13
    mov rcx, qword ptr [rbp+5B8h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+438h]
    loc_7FF856A071CD:
    mov qword ptr [rbp+1E8h], rax
    mov rcx, qword ptr [rbp+1E8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, qword ptr [rbp+5F8h]
    mov rdx, qword ptr [rbp+18h]
    call memcpy
    mov rax, qword ptr [rbp+0C0h]
    mov qword ptr [rbp+1E0h], rax
    loc_7FF856A0725D:
    mov rax, qword ptr [rbp+1E0h]
    mov rcx, qword ptr [rbp+5F8h]
    mov byte ptr [rax+rcx], 0
    mov rax, qword ptr [rbp+5F8h]
    mov rcx, qword ptr [rbp+4C8h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+5B8h]
    mov rax, qword ptr [rax]
    mov qword ptr [rbp+10h], rax
    test rax, rax
    js loc_7FF856A072F0
    mov eax, dword ptr [dword_7FF857242AAC]
    mov ecx, eax
    xor ecx, -6E7525EFh
    mov edx, eax
    xor edx, 0F3929F8h
    add edx, -3168234h
    mov r8d, edx
    xor r8d, 6464718Dh
    add r8d, -28E8BD37h
    xor r8d, -55262697h
    mov r9d, eax
    xor r9d, -199E09A4h
    sub r9d, r8d
    sub r9d, ecx
    sub r9d, eax
    xor r9d, edx
    add r9d, -28E8BD37h
    mov dword ptr [rbp+63Ch], r9d
    jmp loc_7FF8569F0600
    loc_7FF856A072F0:
    mov eax, -446D15Dh
    sub eax, dword ptr [dword_7FF857242AC4]
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A07306:
    mov eax, dword ptr [dword_7FF857242B08]
    mov ecx, 68238B41h
    jmp loc_7FF856A0521B
    loc_7FF856A07316:
    mov rax, qword ptr [rbp+5A0h]
    mov rdx, qword ptr [rax]
    mov rcx, qword ptr [rbp+488h]
    call memcpy
    mov r13, 7FFFFFFFFFFFFFFFh
    mov r12, rsi
    loc_7FF856A07339:
    mov rax, qword ptr [rbp+4D0h]
    mov rax, qword ptr [rax]
    mov qword ptr [rbp+398h], rax
    mov rdx, qword ptr [qword_7FF8571CFC08]
    mov rax, 0AE8290F987CD995h
    add rax, rdx
    mov rcx, 4278FCD0741B6941h
    add rcx, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, -2C4AA0FE207B86B9h
    xor rcx, r8
    sub rcx, rdx
    mov r8, 4BD73342BC031244h
    add rdx, r8
    mov r8, rdx
    not r8
    mov r9, rcx
    or r9, r8
    not r9
    mov r10, rcx
    or r10, rdx
    not r10
    add r10, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11, rcx
    and r11, r8
    xor r8, rcx
    and rdx, rcx
    lea rdx, [rdx+r11*2]
    sub rdx, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    sub rcx, r10
    add rcx, r9
    xor rcx, rax
    cmp qword ptr [rbp+398h], rcx
    jle loc_7FF856A07AA9
    mov rax, qword ptr [rbp+5A0h]
    mov rdx, qword ptr [rax]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF856A074E9:
    mov rcx, r12
    call qword ptr [rax+30h]
    loc_7FF856A074EF:
    mov rax, qword ptr [rbp+4D0h]
    mov rax, qword ptr [rax]
    loc_7FF856A074F9:
    mov qword ptr [rbp+240h], rax
    mov rax, qword ptr [rbp+240h]
    mov rcx, qword ptr [rbp+5A0h]
    mov rdx, qword ptr [rbp+488h]
    mov qword ptr [rcx], rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, qword ptr [qword_7FF8571CFC10]
    mov rcx, 796DD5A227FCB06Dh
    lea r9, [r8+rcx]
    mov rcx, -79F362F852D47058h
    lea rdx, [r8+rcx]
    mov rcx, -364B3B1C8B4F7DDDh
    add rcx, r8
    mov r10, 3DD91A4F342B8005h
    xor rcx, r10
    mov r10, 585D9D019065E1B6h
    add r10, rcx
    mov r11, 3BF91856F3AD3CD0h
    sub r11, r8
    xor r11, r8
    xor r11, r9
    xor r11, r10
    mov r8, rdx
    not r8
    mov r9, r11
    or r9, r8
    mov r10, r11
    or r10, rdx
    and rdx, r11
    and r8, r11
    not r10
    add r8, r8
    lea r8, [r8+rdx*2]
    not rdx
    add rdx, r10
    add r8, rdx
    not r9
    lea rdx, [r8+r9*2]
    add rdx, 2
    xor rdx, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and rdx, rax
    mov rax, qword ptr [rbp+4D0h]
    mov qword ptr [rax], rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rbp+488h]
    loc_7FF856A07751:
    mov qword ptr [rbp+248h], rax
    mov rax, qword ptr [rbp+248h]
    mov qword ptr [rbp+3A8h], rax
    mov rax, qword ptr [rbp+5A0h]
    add rax, 8
    mov qword ptr [rbp+3A0h], rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [qword_7FF8571CFC18]
    mov rcx, rax
    not rcx
    mov rdx, rcx
    mov r10, 61B3E4924FA5885Bh
    and rdx, r10
    lea rdx, [rdx+rdx*2]
    mov r8, -61B3E4924FA5885Ch
    and rcx, r8
    lea r8, [rcx+rcx*4]
    mov r9, rax
    xor r9, r10
    add r9, r9
    mov rcx, rax
    mov r10, 1E4C1B6DB05A77A4h
    and rcx, r10
    shl rcx, 3
    sub rcx, r9
    add rcx, r8
    add rcx, rdx
    mov rdx, -177C892471C45634h
    add rdx, rcx
    mov r8, -5D6137B79EB9D6C7h
    add rcx, r8
    mov r8, rcx
    not r8
    mov r11, 14AF72CFC006577Ch
    and r8, r11
    lea r9, [r8*8]
    sub r9, r8
    mov r8, rcx
    mov r10, 6B508D303FF9A883h
    and r8, r10
    lea r8, [r8+r8*2]
    mov r10, rcx
    and r10, r11
    lea r8, [r10+r8*2]
    mov r10, rcx
    xor r10, r11
    lea r10, [r10+r10*4]
    sub r8, r10
    add r8, r9
    add rcx, rax
    mov rax, 2A9F5DBE77DBE8C9h
    sub rax, rcx
    mov rcx, qword ptr [rbp+3A0h]
    xor rax, rdx
    mov rdx, qword ptr [rbp+3B0h]
    mov r9, qword ptr [rcx]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, -14AF72CFC006577Ch
    add r8, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor rax, r8
    mov rcx, qword ptr [rbp+598h]
    cmp rdx, r9
    jnb loc_7FF856A07A62
    cmp rcx, rax
    jnz loc_7FF856A07ABF
    mov eax, dword ptr [dword_7FF8572429D0]
    mov ecx, eax
    xor ecx, -3711416Dh
    lea edx, [rcx-63A514EEh]
    lea r8d, [rcx+6273E24Bh]
    xor r8d, -0FCCED04h
    xor edx, 13D294BDh
    sub edx, ecx
    add edx, eax
    sub edx, r8d
    lea eax, [rdx+rcx]
    add eax, 6273E24Bh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A07A62:
    cmp rcx, rax
    jnz loc_7FF856A07E87
    mov eax, dword ptr [dword_7FF857242A28]
    lea ecx, [rax+2B720D78h]
    mov edx, ecx
    xor edx, 19D8D8C2h
    xor ecx, -2811DAE5h
    sub edx, ecx
    add ecx, -60824A19h
    sub edx, eax
    add edx, -17B7BE9Bh
    xor edx, ecx
    add eax, edx
    add eax, 2B720D78h
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A07AA9:
    mov eax, -170CA845h
    sub eax, dword ptr [dword_7FF857242A2C]
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A07ABF:
    mov rcx, qword ptr [rbp+3A8h]
    mov rdx, qword ptr [rbp+3B0h]
    add rdx, rcx
    mov r8, qword ptr [rbp+598h]
    call memcpy
    loc_7FF856A07ADC:
    mov rax, qword ptr [rbp+5A0h]
    mov rax, qword ptr [rax]
    mov rcx, qword ptr [rbp+598h]
    movzx edx, byte ptr [byte_7FF8571CFC20]
    mov r8d, edx
    xor r8b, 62h
    xor dl, 6Ch
    lea r11d, [rdx+1Ch]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9d, r11d
    xor r9b, 65h
    lea r10d, [r9-0Ah]
    mov ebx, r10d
    not bl
    mov edi, r10d
    or dil, 2Bh
    and bl, 2Bh
    add bl, dil
    lea edi, [r10+r10]
    mov r14d, r10d
    and r14b, 54h
    add r14b, r14b
    sub dil, r14b
    add dil, bl
    add dil, 0D6h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r10b, r11b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r10b, 7Dh
    xor r10b, r9b
    xor r10b, dil
    add r10b, r8b
    sub r10b, dl
    add r10b, r9b
    mov byte ptr [rax+rcx], r10b
    mov rax, qword ptr [rbp+598h]
    mov rcx, qword ptr [rbp+3A0h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+550h]
    mov rcx, qword ptr [rbp+608h]
    mov rcx, qword ptr [rcx]
    loc_7FF856A07C99:
    mov qword ptr [rbp+520h], rcx
    loc_7FF856A07CA0:
    mov qword ptr [rbp+518h], rax
    loc_7FF856A07CA7:
    mov rax, qword ptr [rbp+518h]
    mov rcx, qword ptr [rbp+520h]
    loc_7FF856A07CB5:
    mov qword ptr [rsp+28h], rcx
    mov qword ptr [rsp+20h], rax
    mov edx, 0Ah
    mov r8d, 50h
    mov r9d, 63h
    lea rcx, [rbp+0A0h]
    call sub_7FF85702AFE0
    loc_7FF856A07CDC:
    mov rax, qword ptr [rbp+0A8h]
    mov qword ptr [rbp+400h], rax
    cmp rax, 2
    setnb byte ptr [rbp+63Bh]
    mov rax, qword ptr [qword_7FF8571CFC38]
    mov rcx, rax
    mov rdx, 64F04A9BB64B620Ch
    xor rcx, rdx
    mov rdx, 30DE2D2D0F17A68h
    add rdx, rcx
    mov r8, rdx
    mov r9, 2A9BCF86FA00CFCFh
    xor r8, r9
    mov r9, 6ED15B1B244A607h
    sub r9, rcx
    mov rcx, 1FDF77C44B1AE62Ah
    add rcx, r8
    xor r9, rcx
    add r9, r8
    mov rcx, -4A056E3553116DD2h
    add rcx, r8
    mov r10, -7B8A225D3109B044h
    xor rcx, r10
    sub r9, rcx
    mov rcx, 18C9DD5D45C5B57h
    add r9, rcx
    xor r9, r8
    sub r9, rdx
    sub r9, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rbp+400h], r9
    jnz loc_7FF856A07E41
    mov eax, dword ptr [dword_7FF8572429FC]
    mov ecx, eax
    xor ecx, -7C61DF7Dh
    lea edx, [rcx+36A6B94h]
    mov r8d, edx
    xor r8d, 6DDFA204h
    add r8d, -39E05C65h
    xor r8d, eax
    xor r8d, -24D906BBh
    add r8d, ecx
    sub r8d, edx
    loc_7FF856A07E32:
    sub r8d, eax
    mov dword ptr [rbp+63Ch], r8d
    jmp loc_7FF8569F0600
    loc_7FF856A07E41:
    mov eax, dword ptr [dword_7FF857242958]
    lea ecx, [rax-3894F541h]
    lea edx, [rax-3A649A91h]
    lea r8d, [rax+0AFAE46Ch]
    xor r8d, 1CAD111Fh
    add r8d, eax
    add r8d, 768D6A18h
    xor r8d, ecx
    sub r8d, eax
    add r8d, 7459A37h
    xor r8d, edx
    mov dword ptr [rbp+63Ch], r8d
    jmp loc_7FF8569F0600
    loc_7FF856A07E87:
    mov eax, dword ptr [dword_7FF857242A20]
    mov ecx, eax
    xor ecx, -583EAE66h
    lea edx, [rcx+2B2124Ch]
    sub eax, edx
    xor edx, -6A53A722h
    lea r8d, [rdx-45A031E0h]
    add eax, -1EA63DC6h
    xor eax, r8d
    xor r8d, -407EFF72h
    sub eax, ecx
    xor eax, r8d
    sub eax, edx
    xor eax, r8d
    xor eax, -480470DDh
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A07ED3:
    mov eax, dword ptr [dword_7FF85724296C]
    mov ecx, eax
    xor ecx, 95DBCFCh
    lea edx, [rcx+73F446EAh]
    mov r8d, edx
    xor r8d, 0AA74400h
    sub edx, eax
    add edx, ecx
    sub edx, r8d
    add edx, 7B48C10Ch
    jmp loc_7FF8569F05F9
    loc_7FF856A07F03:
    mov eax, dword ptr [dword_7FF857242A8C]
    lea ecx, [rax-13D29108h]
    xor ecx, -3DFAA7C9h
    xor eax, -49CEA398h
    sub eax, ecx
    add eax, 9B43C05h
    xor eax, ecx
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A07F2E:
    mov eax, dword ptr [dword_7FF8572429AC]
    lea ecx, [rax-4F1FAB4Ah]
    xor ecx, 787CDD18h
    lea edx, [rcx+56E3E367h]
    xor edx, -6E56BC74h
    lea r8d, [rcx+6EEF2257h]
    xor r8d, ecx
    xor r8d, 528EA4C0h
    sub r8d, edx
    loc_7FF856A07F60:
    sub r8d, eax
    mov dword ptr [rbp+63Ch], r8d
    jmp loc_7FF8569F0600
    loc_7FF856A07F6F:
    mov eax, dword ptr [dword_7FF857242B2C]
    mov ecx, eax
    xor ecx, 12BE6AA4h
    add ecx, eax
    add eax, 7A72DE00h
    mov edx, eax
    xor edx, 3137D163h
    add ecx, edx
    add ecx, 1FE6F683h
    xor ecx, eax
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF856A07FA1:
    mov eax, dword ptr [dword_7FF857242AA0]
    mov ecx, eax
    xor ecx, 4E4D6A55h
    mov edx, eax
    xor edx, 48E8C095h
    lea r8d, [rdx-7A235382h]
    add eax, 73CCEF4Eh
    xor eax, r8d
    xor r8d, -4EFC194Bh
    sub eax, r8d
    add eax, ecx
    loc_7FF856A07FD2:
    sub eax, edx
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A07FDF:
    mov eax, dword ptr [dword_7FF857242B28]
    lea ecx, [rax+7ADE3DBh]
    mov edx, ecx
    xor edx, -79B5C5C4h
    lea r8d, [rdx+44B4987Dh]
    sub edx, ecx
    sub edx, eax
    add edx, -403D7742h
    xor r8d, ecx
    xor r8d, edx
    xor r8d, -1DAA66DEh
    mov dword ptr [rbp+63Ch], r8d
    jmp loc_7FF8569F0600
    loc_7FF856A0801D:
    mov eax, dword ptr [dword_7FF857242B1C]
    mov ecx, 2C9BC4A4h
    add eax, ecx
    xor eax, 687032C8h
    lea ecx, [rax-6E39C73Fh]
    xor ecx, -4A05A47Ah
    add ecx, -3E43146h
    loc_7FF856A08041:
    xor ecx, eax
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF856A0804E:
    mov rax, qword ptr [rbp+5E0h]
    mov rcx, qword ptr [rbp+538h]
    mov qword ptr [rbp+418h], rcx
    mov qword ptr [rbp+410h], rax
    mov eax, dword ptr [dword_7FF857242914]
    mov ecx, eax
    xor ecx, -284F6B18h
    lea edx, [rcx+500A8976h]
    mov r8d, 1E40E39Bh
    sub r8d, ecx
    add ecx, -28B9BD6h
    xor r8d, edx
    xor r8d, ecx
    jmp loc_7FF856A07E32
    loc_7FF856A08098:
    mov rdx, qword ptr [rbp+138h]
    mov rcx, qword ptr [rbp+468h]
    call memcpy
    jmp loc_7FF8569F065E
    loc_7FF856A080B0:
    mov eax, dword ptr [dword_7FF8572429C8]
    lea ecx, [rax-220B4F45h]
    mov edx, ecx
    xor edx, 28A18526h
    mov r8d, ecx
    xor r8d, 5174AE7Ah
    lea r9d, [r8-2319F2D3h]
    add r8d, 2E80D315h
    xor r8d, r9d
    sub r8d, edx
    xor ecx, r9d
    xor ecx, eax
    xor ecx, r8d
    xor ecx, -194C090Ah
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF856A080FB:
    mov rdx, qword ptr [rbp+550h]
    mov rcx, qword ptr [rbp+480h]
    call memcpy
    loc_7FF856A0810E:
    mov rax, qword ptr [rbp+628h]
    mov rax, qword ptr [rax]
    test rax, rax
    js loc_7FF856A081B0
    mov rdx, qword ptr [rbp+550h]
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF856A0812F:
    mov rcx, r12
    call qword ptr [rax+30h]
    mov rax, qword ptr [rbp+628h]
    mov rax, qword ptr [rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FF856A081B0:
    mov qword ptr [rbp+230h], rax
    mov rax, qword ptr [rbp+480h]
    mov qword ptr [rbp+550h], rax
    mov rax, qword ptr [qword_7FF8571CFBA0]
    mov rcx, -27837A0E76361E11h
    add rax, rcx
    mov rcx, 5242EE1FB8DC3B6Bh
    xor rax, rcx
    mov rcx, 22E0ADEB0A81FE90h
    add rax, rcx
    and rax, qword ptr [rbp+230h]
    mov rcx, qword ptr [rbp+628h]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [rbp+480h]
    mov qword ptr [rbp+238h], rax
    loc_7FF856A08212:
    mov rax, qword ptr [rbp+238h]
    mov qword ptr [rbp+388h], rax
    mov rcx, qword ptr [rbp+608h]
    mov rdx, qword ptr [rbp+390h]
    mov rax, qword ptr [rbp+600h]
    cmp rdx, qword ptr [rcx]
    jnb loc_7FF856A08296
    test rax, rax
    jz loc_7FF856A082EA
    mov eax, dword ptr [dword_7FF857242A3C]
    lea ecx, [rax+1B18E795h]
    lea edx, [rax+2C72D577h]
    mov r8d, edx
    xor r8d, -3AA31812h
    lea r9d, [r8-423D4590h]
    mov r10d, r9d
    xor r10d, -3FF1D75h
    xor ecx, -239F7494h
    add ecx, r8d
    xor ecx, edx
    add ecx, r10d
    xor ecx, eax
    add ecx, eax
    sub ecx, r9d
    add ecx, -4E402E74h
    mov dword ptr [rbp+63Ch], ecx
    jmp loc_7FF8569F0600
    loc_7FF856A08296:
    test rax, rax
    jz loc_7FF856A0830C
    mov eax, dword ptr [dword_7FF8572429B8]
    mov ecx, 579AB692h
    add eax, ecx
    xor eax, 0EEBE410h
    lea ecx, [rax+627EB94Eh]
    mov edx, ecx
    xor edx, 2363524Dh
    lea r8d, [rdx+8B1BFAFh]
    xor r8d, 5F8C7464h
    sub r8d, ecx
    lea ecx, [rdx+r8]
    add ecx, 8B1BFAFh
    add eax, ecx
    add eax, -7391B0F3h
    loc_7FF856A082DD:
    xor eax, edx
    mov dword ptr [rbp+63Ch], eax
    jmp loc_7FF8569F0600
    loc_7FF856A082EA:
    mov eax, dword ptr [dword_7FF857242A40]
    lea ecx, [rax+13DFDB15h]
    mov edx, -4779DFCCh
    sub edx, eax
    xor edx, ecx
    sub edx, eax
    add edx, -7C1E495h
    jmp loc_7FF8569F05F9
    loc_7FF856A0830C:
    mov eax, dword ptr [dword_7FF857242A38]
    lea ecx, [rax-1EA29494h]
    mov edx, -6F674CCh
    sub edx, eax
    add eax, 5A01693Bh
    xor edx, ecx
    xor edx, eax
    jmp loc_7FF8569F05F9
    loc_7FF856A0832D:
    mov rdx, qword ptr [rbp+0E8h]
    lea rcx, off_7FF8571A2640
    mov rax, qword ptr [off_7FF8571A2640]
    loc_7FF856A08342:
    call qword ptr [rax+30h]
    loc_7FF856A08345:
    movzx eax, byte ptr [rbp+61Eh]
    add rsp, 6C8h
    pop rbx
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    pop rbp
    ret
_TEXT ENDS
END

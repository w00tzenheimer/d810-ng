; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64
; Function: sub_7FF8568132D0  @ 0x7ff8568132d0
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN Eidolon_ForwardDynamicKeyToProtectionEvent:PROC
EXTERN Eidolon_UpdateSharedStateIfSentinelMatches:PROC
EXTERN VirtualProtect:PROC
EXTERN __imp_RtlAcquireSRWLockExclusive:PROC
EXTERN __imp_RtlReleaseSRWLockExclusive:PROC
EXTERN sub_7FF85668BFB0:PROC

CONST SEGMENT
eidolon_sbox db 0EBh
db 2Fh
db 94h
db 5Eh
db 0ADh
db 5Bh
db 52h
db 19h
db 9Eh
db 1Dh
db 0Dh
db 0C5h
db 0AEh
db 6Bh
db 16h
db 7Ah
db 0A5h
db 8Eh
db 4Bh
db 47h
db 11h
db 59h
db 5
db 4
db 0EEh
db 0DCh
db 61h
db 41h
db 0E7h
db 0E7h
db 3Bh
db 0C5h
db 4Ah
db 0ACh
db 0CCh
db 0DAh
db 2Ah
db 0BCh
db 0A0h
db 5Ah
db 0A9h
db 98h
db 0D7h
db 44h
db 0FFh
db 2Ah
db 0BEh
db 79h
db 43h
db 0FEh
db 95h
db 1
db 0DEh
db 28h
db 0ABh
db 0DFh
db 71h
db 97h
db 3Eh
db 0D8h
db 0D7h
db 0DCh
db 0BCh
db 0FAh
db 27h
db 0D3h
db 0Fh
db 77h
db 65h
db 0C2h
db 0EDh
db 0B5h
db 5Bh
db 0C3h
db 8Ah
db 0D2h
db 5
db 0D9h
db 38h
db 91h
db 83h
db 0ABh
db 7Ah
db 15h
db 0F4h
db 0C7h
db 1Dh
db 4
db 9
db 0D7h
db 8Eh
db 38h
db 30h
db 84h
db 66h
db 3Dh
db 93h
db 0CCh
db 85h
db 4Fh
db 60h
db 0E9h
db 56h
db 1
db 43h
db 65h
db 42h
db 48h
db 9
db 38h
db 0BAh
db 0D6h
db 0F3h
db 0D3h
db 3Ah
db 0A0h
db 0FFh
db 7Eh
db 0D6h
db 0CBh
db 0B9h
db 0C4h
db 0E4h
db 9Fh
db 2Bh
db 0C4h
db 12h
db 0Fh
db 0Ch
db 39h
db 0Ch
db 8Eh
db 11h
db 6Dh
db 0BCh
db 26h
db 0D2h
db 5Eh
db 4Eh
db 0C0h
db 1Fh
db 0DEh
db 30h
db 68h
db 15h
db 1Bh
db 0B9h
db 79h
db 0
db 9Eh
db 4Dh
db 8Ah
db 89h
db 0EDh
db 0DCh
db 3Bh
db 88h
db 0F1h
db 87h
db 0AAh
db 7Dh
db 0Bh
db 22h
db 22h
db 0BBh
db 1Eh
db 7Bh
db 23h
db 45h
db 0ADh
db 82h
db 9Dh
db 4Bh
db 62h
db 0BEh
db 17h
db 0E8h
db 10h
db 0B0h
db 66h
db 9Ch
db 0B6h
db 62h
db 2Fh
db 0BDh
db 0Bh
db 0A9h
db 39h
db 21h
db 0F9h
db 0D6h
db 54h
db 77h
db 8Ah
db 28h
db 7Ch
db 0D0h
db 0B1h
db 22h
db 0A4h
db 3
db 0BCh
db 1Bh
db 0B9h
db 63h
db 0B6h
db 8Fh
db 0CBh
db 68h
db 7Bh
db 0D4h
db 0FBh
db 36h
db 0A8h
db 26h
db 2Dh
db 0EBh
db 0DDh
db 85h
db 9Fh
db 0A8h
db 7Bh
db 0ECh
db 0DFh
db 0B3h
db 10h
db 83h
db 9Dh
db 56h
db 0D7h
db 4
db 8Fh
db 82h
db 0C3h
db 6Bh
db 0EFh
db 8Ch
db 0F2h
db 13h
db 0B6h
db 0Eh
db 0B1h
db 7Bh
db 0A1h
db 0A5h
db 19h
db 26h
db 0Ah
db 9Bh
db 63h
db 0B4h
db 0BEh
db 0C1h
db 3
db 0D4h
db 0B6h
db 1Dh
db 4Eh
db 8Ah
db 0Ah
db 0F8h
db 2Ch
db 3Fh
db 1
db 0EEh
db 0A8h
db 0B1h
db 8Fh
db 0C6h
db 0C7h
db 5Ch
db 52h
db 6Ah
db 0B0h
db 39h
db 9Eh
db 0D0h
db 38h
db 69h
db 8Fh
db 0FEh
db 0AAh
db 2Eh
db 0AFh
db 90h
db 0B2h
db 9Bh
db 0C5h
db 54h
db 6Ch
db 7Bh
db 0BEh
db 0CFh
db 0FDh
db 33h
db 4Ah
db 5Bh
db 20h
db 10h
db 0A6h
db 79h
db 0BEh
db 0A3h
db 42h
db 38h
db 0C6h
db 0C8h
db 0C9h
db 0A6h
db 1Ah
db 9Ah
db 0Dh
db 8
db 0DDh
db 84h
db 0DFh
db 1Dh
db 0D2h
db 43h
db 0C5h
db 56h
db 0ACh
db 0BAh
db 4Ah
db 2Eh
db 0FDh
db 0BCh
db 0Dh
db 0C6h
db 0E0h
db 57h
db 51h
db 8Dh
db 86h
db 0DBh
db 26h
db 43h
db 0ACh
db 1Fh
db 0CCh
db 9Fh
db 71h
db 8Dh
db 0E8h
db 0B4h
db 0E5h
db 0BEh
db 0F0h
db 8Eh
db 19h
db 0CFh
db 7Fh
db 2Bh
db 0C4h
db 93h
db 87h
db 0E8h
db 13h
db 8Ah
db 0D9h
db 0ACh
db 0AAh
db 0E9h
db 48h
db 7
db 1Bh
db 77h
db 0DEh
db 69h
db 0DDh
db 0Ch
db 0E7h
db 0CFh
db 0A8h
db 52h
db 35h
db 0EEh
db 0B9h
db 0FCh
db 5Dh
db 1Fh
db 0Ah
db 98h
db 85h
db 9Eh
db 79h
db 90h
db 17h
db 48h
db 61h
db 0CFh
db 96h
db 63h
db 44h
db 13h
db 0D9h
db 10h
db 19h
db 64h
db 0DDh
db 0F0h
db 0D1h
db 47h
db 0A3h
db 0F8h
db 3Fh
db 80h
db 0D3h
db 8Bh
db 98h
db 96h
db 7Dh
db 4
db 7
db 4Bh
db 2Ah
db 0F2h
db 2Eh
db 0EAh
db 7Dh
db 86h
db 8Bh
db 52h
db 0F4h
db 19h
db 0CEh
db 0Bh
db 0AEh
db 8Fh
db 0A7h
db 0C5h
db 0EBh
db 0C0h
db 9Bh
db 91h
db 76h
db 73h
db 0DFh
db 50h
db 0D2h
db 0FFh
db 79h
db 0BAh
db 80h
db 83h
db 0F0h
db 0D4h
db 0CFh
db 0D3h
db 0E8h
db 1Eh
db 0D5h
db 0AFh
db 32h
db 0AEh
db 8Ah
db 0CFh
db 0F5h
db 48h
db 64h
db 59h
db 23h
db 8Ch
db 91h
db 0EAh
db 25h
db 0A1h
db 74h
db 0E5h
db 0BFh
db 0D3h
db 0CDh
db 9Fh
db 0BFh
db 1Dh
db 6Ah
db 7Bh
db 0Bh
db 0C3h
db 9Dh
db 13h
db 0A2h
db 0Dh
db 0D4h
db 3Ah
db 21h
db 4Ch
db 0Eh
db 0B6h
db 6Ah
db 0Fh
db 0B6h
db 0DCh
db 44h
db 88h
db 85h
db 3Eh
db 0C5h
db 99h
db 31h
db 59h
db 0E0h
db 0BFh
db 93h
db 39h
db 7
db 6Ah
db 2Fh
db 98h
db 0C1h
db 0FFh
db 2Ah
db 0FDh
db 71h
db 0E1h
db 0C5h
db 0A4h
db 0FBh
db 0F6h
db 0DCh
db 0FBh
db 0A3h
db 16h
db 39h
db 94h
db 0D8h
db 7
db 0A8h
db 0A1h
db 0DAh
db 71h
db 0B4h
db 0A9h
db 0A4h
db 93h
db 1Fh
db 62h
db 29h
db 11h
db 9Ah
db 0C2h
db 0D8h
db 0F4h
db 0B9h
db 0B2h
db 4Dh
db 13h
db 0A6h
db 0E4h
db 90h
db 0C8h
db 6
db 59h
db 69h
db 0D7h
db 2Ch
db 78h
db 54h
db 0B1h
db 2Ch
db 38h
db 6Fh
db 0EDh
db 0A7h
db 0D4h
db 0A0h
db 72h
db 0C0h
db 0EEh
db 0AAh
db 23h
db 0CEh
db 0C2h
db 0C9h
db 45h
db 9
db 0F8h
db 8Ah
db 0CCh
db 60h
db 0Fh
db 0BEh
db 0F7h
db 0A8h
db 0ACh
db 0D1h
db 0D3h
db 3Ah
db 38h
db 4Ch
db 64h
db 52h
db 34h
db 0A0h
db 99h
db 4Dh
db 0A6h
db 0C0h
db 0FFh
db 64h
db 6
db 64h
db 3Fh
db 3
db 21h
db 3Eh
db 15h
db 0C6h
db 55h
db 0D7h
db 0Ah
db 0CCh
db 27h
db 0F1h
db 8Ah
db 2Bh
db 5
db 0C1h
db 0AAh
db 6Ch
db 5Bh
db 0A4h
db 93h
db 74h
db 0Dh
db 76h
db 0Bh
db 0A4h
db 0E0h
db 0EDh
db 17h
db 78h
db 0B5h
db 0Dh
db 0EBh
db 0D0h
db 2Fh
db 42h
db 0E0h
db 0C1h
db 8Ah
db 35h
db 0B7h
db 36h
db 0A3h
db 6Fh
db 2
db 0FBh
db 0CDh
db 0C5h
db 0FDh
db 0FBh
db 87h
db 0DDh
db 83h
db 0DBh
db 83h
db 33h
db 7Ah
db 6Eh
db 3Fh
db 0F3h
db 40h
db 40h
db 2Dh
db 0A1h
db 1Ch
db 0EAh
db 0B5h
db 0CCh
db 13h
db 8Bh
db 0B0h
db 0FFh
db 48h
db 0ACh
db 65h
db 0E5h
db 0F4h
db 0DBh
db 96h
db 15h
db 6Ah
db 9Bh
db 56h
db 3Ch
db 98h
db 0CEh
db 0D5h
db 6Ch
db 43h
db 0DEh
db 44h
db 0A3h
db 8Fh
db 5Bh
db 0CBh
db 0A7h
db 6
db 3Bh
db 32h
db 0F5h
db 0E4h
db 58h
db 0B7h
db 45h
db 0EAh
db 0F1h
db 5Fh
db 0C9h
db 0E0h
db 93h
db 37h
db 41h
db 0C1h
db 0C3h
db 0B8h
db 3Dh
db 0C6h
db 0C7h
db 0A2h
db 0Dh
db 88h
db 1Dh
db 53h
db 85h
db 0FDh
db 67h
db 4Eh
db 0B3h
db 94h
db 73h
db 28h
db 6Bh
db 32h
db 98h
db 0CAh
db 0F6h
db 0B3h
db 0B2h
db 0E1h
db 0A1h
db 0E5h
db 0A5h
db 2Bh
db 0EDh
db 7Fh
db 3Ch
db 48h
db 0ABh
db 73h
db 0D8h
db 0B8h
db 0CCh
db 1Bh
db 0Dh
db 72h
db 87h
db 0ABh
db 0D5h
db 0FBh
db 92h
db 0A5h
db 97h
db 0A7h
db 63h
db 0EEh
db 5
db 90h
db 60h
db 0E7h
db 54h
db 4Fh
db 0D4h
db 3
db 4
db 40h
db 0BBh
db 0A4h
db 0B5h
db 91h
db 56h
db 0D8h
db 0E7h
db 3Ah
db 0ADh
db 0D7h
db 7Dh
db 7Bh
db 6
db 2Ah
db 0B3h
db 0E7h
db 0A4h
db 0DCh
db 37h
db 32h
db 6Ah
db 2Ch
db 7Eh
db 32h
db 0C9h
db 56h
db 41h
db 65h
db 0CBh
db 48h
db 96h
db 0DBh
db 7Dh
db 0E2h
db 74h
db 50h
db 51h
db 0A3h
db 5Ch
db 34h
db 86h
db 48h
db 49h
db 4Eh
db 0Ah
db 0BDh
db 0B3h
db 0E3h
db 0DEh
db 8
db 7Fh
db 0A7h
db 64h
db 33h
db 64h
db 3Ch
db 0BBh
db 0Ch
db 43h
db 7Eh
db 0D8h
db 2Fh
db 0F4h
db 83h
db 59h
db 99h
db 0AFh
db 0C0h
db 0D5h
db 7Fh
db 53h
db 0BAh
db 73h
db 2Bh
db 71h
db 79h
db 35h
db 0C8h
db 92h
db 0Bh
db 60h
db 8Fh
db 94h
db 3Dh
db 0Ch
db 2
db 81h
db 0A0h
db 0BEh
db 0AAh
db 91h
db 79h
db 0E5h
db 0C1h
db 0EDh
db 0Ch
db 0B7h
db 0F3h
db 5
db 0CAh
db 7Dh
db 90h
db 7Fh
db 76h
db 8Eh
db 75h
db 0DAh
db 4
db 90h
db 80h
db 88h
db 0D5h
db 33h
db 70h
db 3Ah
db 1Eh
db 0F6h
db 69h
db 0E7h
db 0E0h
db 88h
db 34h
db 0DAh
db 0A1h
db 13h
db 37h
db 72h
db 98h
db 0C5h
db 0B3h
db 64h
db 8Eh
db 0D2h
db 84h
db 18h
db 87h
db 52h
db 0FEh
db 5Dh
db 50h
db 3Dh
db 7Ch
db 0Ah
db 0D8h
db 51h
db 0A4h
db 1Ah
db 0CDh
db 0CAh
db 0A2h
db 0D9h
db 87h
db 3Dh
db 7Dh
db 0A8h
db 6Bh
db 0FBh
db 0
db 6
db 20h
db 84h
db 0F2h
db 0A9h
db 70h
db 90h
db 0F2h
db 56h
db 37h
db 0CFh
db 0CBh
db 0E7h
db 1Dh
db 0F2h
db 0CDh
db 0A8h
db 0C0h
db 54h
db 5
db 0F8h
db 0B4h
db 25h
db 0BBh
db 0C3h
db 92h
db 68h
db 0F3h
db 2Bh
db 0F1h
db 0CEh
db 7Ch
db 3Bh
db 5
db 0B4h
db 0EFh
db 0Dh
db 56h
db 0A9h
db 0D3h
db 4Dh
db 35h
db 0C3h
db 2Ch
db 0B9h
db 99h
db 0B1h
db 0FEh
db 0CEh
db 4Ch
db 33h
db 9Eh
db 0E0h
db 0CDh
db 50h
db 0C2h
db 64h
db 40h
db 32h
db 24h
db 0D0h
db 7Eh
db 22h
db 1Bh
db 60h
db 0ABh
db 61h
db 8Ch
db 0A4h
db 8Ch
db 8Ch
db 48h
db 22h
db 69h
db 11h
db 99h
db 0ABh
db 0F1h
db 61h
db 74h
db 70h
db 3Dh
db 0C1h
db 6Ah
db 83h
db 43h
db 93h
db 0D5h
db 65h
db 6
db 0A2h
db 49h
db 0A1h
db 98h
db 0C4h
db 7Bh
db 0C4h
db 0A3h
db 6
db 40h
db 34h
db 3Eh
db 6Ch
db 4Eh
db 0AEh
db 0A0h
db 21h
db 0D6h
db 5Ah
db 33h
db 9Fh
db 0A6h
db 2
db 7Dh
db 0FAh
db 3Bh
db 27h
db 0A5h
db 65h
db 25h
db 0ABh
db 0CFh
db 58h
db 82h
db 86h
db 0AFh
db 29h
db 90h
db 0F9h
db 0A8h
db 2Fh
db 8
db 35h
db 5Ah
db 0BEh
db 0FBh
db 16h
db 0A3h
db 0D3h
db 3Dh
db 3Bh
db 0
db 38h
db 98h
db 0E7h
db 55h
db 0F8h
db 0E7h
db 5Dh
db 7Fh
db 13h
db 0EEh
db 0B6h
db 0FEh
db 41h
db 5Ah
db 82h
db 6Ah
db 9Ah
db 18h
db 73h
db 1Dh
db 0F2h
db 94h
db 0E4h
db 0C3h
db 2Fh
db 0E9h
db 71h
db 29h
db 0D5h
db 0ECh
db 65h
db 23h
db 3Dh
db 6Bh
db 68h
db 0FBh
db 0EDh
db 88h
db 31h
db 70h
db 0BFh
db 0FFh
db 7Ch
db 0C4h
db 9Bh
db 38h
db 0CFh
db 6Ch
db 6Fh
db 11h
db 0C3h
db 35h
db 21h
db 99h
db 23h
db 6Ch
db 44h
db 0B4h
db 0A3h
db 5Bh
db 11h
db 72h
db 53h
db 35h
db 0Ch
db 4
db 23h
db 16h
db 1Dh
db 51h
db 0B5h
db 0DDh
db 0BEh
db 36h
db 42h
db 0CCh
db 89h
db 34h
db 59h
db 6Ah
db 0CCh
db 96h
db 0D9h
db 0F1h
db 0ACh
db 5Fh
db 0E8h
db 8Eh
db 0CFh
db 22h
db 0A1h
db 56h
db 0CDh
db 2Fh
db 8
db 7Ah
db 13h
db 0D3h
db 25h
db 1Ch
db 0BBh
db 93h
db 75h
db 2Dh
db 0D3h
db 0DBh
db 7Ch
db 0A2h
db 53h
db 0B2h
db 0Dh
db 1Bh
db 47h
db 0E5h
db 28h
db 0DBh
db 0ABh
db 8Bh
db 0DCh
db 66h
db 31h
db 1Ch
db 0D6h
db 79h
db 20h
db 8Ah
db 23h
db 68h
db 6Ah
db 5Fh
db 6
db 6Ah
db 5Fh
db 87h
db 13h
db 0E7h
db 85h
db 56h
db 47h
db 2Dh
db 41h
db 9Bh
db 0F2h
db 0D8h
db 0A7h
db 1Dh
db 0D2h
db 69h
db 6Ah
db 0C0h
db 60h
db 9Ch
db 47h
db 99h
db 0C8h
db 39h
db 9Dh
db 0Ch
db 0D3h
db 18h
db 8
db 46h
db 31h
db 48h
db 0F0h
db 84h
db 1Eh
db 4Fh
db 36h
db 6Ah
db 5Dh
db 82h
db 0ECh
db 0F9h
db 0CFh
db 28h
db 9Bh
db 0ACh
db 0CBh
db 93h
db 49h
db 2Eh
db 25h
db 0BDh
db 50h
db 2Bh
db 45h
db 97h
db 0BAh
db 0A0h
db 63h
db 0C3h
db 0BEh
db 62h
db 48h
db 1
db 0C7h
db 4Bh
db 41h
db 70h
db 9Fh
db 17h
db 0F8h
db 21h
db 0B1h
db 0BDh
db 0FEh
db 90h
db 0E5h
db 3Ch
db 0Ah
db 85h
db 0A7h
db 5Ch
db 0C0h
db 0BFh
db 0DBh
db 61h
db 0AAh
db 0D1h
db 49h
db 80h
db 8Dh
db 44h
db 27h
db 1Fh
db 46h
db 6Bh
db 0A9h
db 41h
db 72h
db 29h
db 22h
db 0C4h
db 5
db 0F3h
db 8Ah
db 12h
db 35h
db 23h
db 13h
db 32h
db 0DDh
db 43h
db 3Eh
db 0BDh
db 0F3h
db 64h
db 6Bh
db 2Ch
db 0C7h
db 0B8h
db 57h
db 75h
db 0D5h
db 0Bh
db 0ACh
db 90h
db 0DEh
db 0ACh
db 3Ch
db 0A2h
db 30h
db 0A0h
db 8Ch
db 56h
db 0C5h
db 0Ch
db 56h
db 85h
db 1Eh
db 0DCh
db 0E5h
db 0DDh
db 0C3h
db 0D4h
db 0D4h
db 34h
db 2Fh
db 8
db 0F2h
db 0EBh
db 0A6h
db 82h
db 19h
db 4Eh
db 0CCh
db 9
db 15h
db 6Fh
db 13h
db 5
db 0C2h
db 89h
db 3Bh
db 47h
db 0B1h
db 34h
db 79h
db 0D1h
db 10h
db 29h
db 3Bh
db 39h
db 26h
db 41h
db 0ABh
db 23h
db 9Fh
db 0A2h
db 19h
db 87h
db 48h
db 0A6h
db 39h
db 29h
db 9Bh
db 18h
db 0B3h
db 0D5h
db 96h
db 22h
db 0F8h
db 67h
db 11h
db 58h
db 0CBh
db 8Dh
db 98h
db 0C2h
db 0E6h
db 6Ch
db 0B1h
db 52h
db 0D7h
db 1Eh
db 7Dh
db 0A2h
db 0DFh
db 0A0h
db 0F8h
db 91h
db 0A1h
db 6
db 80h
db 1Ah
db 6Ah
db 0C8h
db 14h
db 0D2h
db 82h
db 63h
db 27h
db 7Fh
db 79h
db 0B7h
db 0F9h
db 2Bh
db 6
db 4Ch
db 0C1h
db 33h
db 5Eh
db 5Ch
db 62h
db 10h
db 0ADh
db 0E0h
db 0A9h
db 7
db 56h
db 7Eh
db 0B5h
db 6Ah
db 53h
db 4Ah
db 0ACh
db 26h
db 95h
db 0EFh
db 0CDh
db 0C4h
db 2Bh
db 42h
db 0E3h
db 0D9h
db 0F0h
db 88h
db 6Ah
db 3Fh
db 0C8h
db 0E8h
db 68h
db 0B2h
db 0BCh
db 94h
db 23h
db 0B1h
db 3
db 8
db 29h
db 57h
db 6Bh
db 0BDh
db 5Dh
db 64h
db 51h
db 90h
db 77h
db 4
db 0CCh
db 0D5h
db 0A2h
db 1Bh
db 9Fh
db 82h
db 58h
db 2Fh
db 0F2h
db 5
db 0D9h
db 0A4h
db 0DEh
db 56h
db 5
db 2Eh
db 79h
db 50h
db 6Dh
db 77h
db 0ADh
db 0E6h
db 4Fh
db 7Ah
db 0DEh
db 0F6h
db 0FBh
db 54h
db 12h
db 0F0h
db 0D3h
db 4Eh
db 0F1h
db 0AFh
db 80h
db 49h
db 49h
db 0Ch
db 0A4h
db 0A5h
db 84h
db 1Ch
db 37h
db 63h
db 0FBh
db 0EFh
db 5Fh
db 29h
db 0B2h
db 82h
db 14h
db 62h
db 0Bh
db 5Eh
db 0C3h
db 0C4h
db 82h
db 0CCh
db 0F3h
db 70h
db 0BBh
db 0D1h
db 62h
db 0F5h
db 4Eh
db 0C7h
db 0ECh
db 98h
db 0DAh
db 0F0h
db 5Dh
db 8Dh
db 0FCh
db 5Eh
db 8Ah
db 9Fh
db 10h
db 0E5h
db 7Ah
db 9Eh
db 0F3h
db 12h
db 0C4h
db 74h
db 71h
db 5Bh
db 0C0h
db 62h
db 24h
db 0FAh
db 5Ah
db 0B6h
db 97h
db 1Bh
db 0FCh
db 6Fh
db 0F9h
db 0C8h
db 1Fh
db 43h
db 0ABh
db 0E6h
db 21h
db 0E1h
db 7Eh
db 10h
db 0E1h
db 1Eh
db 8Ah
db 43h
db 26h
db 0CFh
db 6Ch
db 0F9h
db 0DCh
db 27h
db 0F3h
db 0F7h
db 26h
db 0Ch
db 3Bh
db 3Fh
db 38h
db 0E0h
db 2Eh
db 0BCh
db 0E8h
db 0AEh
db 0BFh
db 0D6h
db 0A5h
db 1
db 76h
db 7Fh
db 50h
db 55h
db 1Ah
db 84h
db 3Eh
db 57h
db 77h
db 0C2h
db 0DDh
db 57h
db 0F1h
db 48h
db 0CBh
db 0BAh
db 0E6h
db 90h
db 84h
db 0D9h
db 12h
db 19h
db 45h
db 0F6h
db 0C7h
db 0A7h
db 95h
db 5Fh
db 0D4h
db 9Ah
db 0A7h
db 6Ah
db 5Ch
db 0DAh
db 0DFh
db 28h
db 0BEh
db 0A5h
db 5Eh
db 0C6h
db 47h
db 7Eh
db 0ACh
db 0F3h
db 75h
db 91h
db 0ABh
db 21h
db 0C7h
db 0DCh
db 65h
db 8Fh
db 0CAh
db 27h
db 6Fh
db 46h
db 0B2h
db 89h
db 88h
db 0AEh
db 65h
db 0B9h
db 0A9h
db 0ECh
db 52h
db 0Fh
db 0B6h
db 64h
db 0F7h
db 0D7h
db 87h
db 55h
db 10h
db 0B4h
db 0F4h
db 36h
db 18h
db 0ABh
db 22h
db 96h
db 3Ch
db 1Ch
db 7Bh
db 9Ah
db 9Ch
db 6Bh
db 4Bh
db 0DDh
db 0EEh
db 35h
db 35h
db 32h
db 5Ch
db 33h
db 48h
db 0C7h
db 33h
db 0EAh
db 4Bh
db 11h
db 2
db 43h
db 6
db 0E6h
db 0DAh
db 12h
db 49h
db 28h
db 0EAh
db 30h
db 27h
db 9Ch
db 30h
db 9Ah
db 53h
db 0A6h
db 0Eh
db 11h
db 21h
db 8Dh
db 0ABh
db 0Ch
db 9Ch
db 0Bh
db 0Dh
db 0CDh
db 6
db 76h
db 0E6h
db 0Fh
db 0Ch
db 4Ch
db 6Dh
db 88h
db 0Eh
db 12h
db 41h
db 0Fh
db 0C6h
db 0B9h
db 0D0h
db 55h
db 9
db 0FBh
db 85h
db 6Bh
db 18h
db 31h
db 20h
db 9Eh
db 64h
db 0C1h
db 32h
db 0ADh
db 78h
db 0A6h
db 84h
db 46h
db 7Fh
db 75h
db 0F1h
db 0C0h
db 0B9h
db 74h
db 96h
db 99h
db 89h
db 70h
db 81h
db 0E5h
db 0CBh
db 4Fh
db 0F0h
db 44h
db 61h
db 8Dh
db 64h
db 90h
db 0F1h
db 0CCh
db 80h
db 2Fh
db 0A7h
db 13h
db 0C9h
db 2Ch
db 0Bh
db 35h
db 0A2h
db 0D2h
db 0Ch
db 37h
db 0CAh
db 75h
db 0BDh
db 0C9h
db 2Eh
db 0E1h
db 53h
db 6
db 57h
db 40h
db 27h
db 0A9h
db 22h
db 8Fh
db 62h
db 0DEh
db 70h
db 81h
db 0Dh
db 2Fh
db 0F6h
db 66h
db 1Eh
db 0EAh
db 3Bh
db 57h
db 7Eh
db 42h
db 0D7h
db 90h
db 1Eh
db 97h
db 8Ch
db 79h
db 0A1h
db 0F1h
db 0AAh
db 14h
db 7Eh
db 78h
db 5
db 0CDh
db 85h
db 59h
db 0F1h
db 0E5h
db 0C1h
db 0EEh
db 6Bh
db 46h
db 92h
db 0ECh
db 74h
db 0C7h
db 3Eh
db 6
db 0DBh
db 0DAh
db 6Eh
db 6Bh
db 66h
db 26h
db 99h
db 3Fh
db 0EAh
db 0B1h
db 59h
db 6Eh
db 0Dh
db 2
db 8Ah
db 79h
db 50h
db 0CDh
db 0D3h
db 0E0h
db 0CFh
db 70h
db 93h
db 0A3h
db 91h
db 5Bh
db 0BBh
db 5Ah
db 0DAh
db 0C1h
db 0E0h
db 0FEh
db 16h
db 52h
db 23h
db 87h
db 28h
db 3Ah
db 0C8h
db 58h
db 0FEh
db 0Dh
db 0AFh
db 0CAh
db 44h
db 0BBh
db 5Ah
db 0B7h
db 1Fh
db 0E9h
db 6Bh
db 9Ah
db 52h
db 5Eh
db 0ACh
db 0DCh
db 8Dh
db 6Fh
db 0Ch
db 0BCh
db 6Bh
db 0FCh
db 62h
db 51h
db 2Ah
db 0B2h
db 0AAh
db 73h
db 0ABh
db 0CCh
db 6
db 80h
db 2Ch
db 73h
db 6Ch
db 43h
db 3Bh
db 6
db 0C9h
db 9Fh
db 0E6h
db 3Eh
db 0DFh
db 4Dh
db 0BAh
db 0BBh
db 3Eh
db 0C7h
db 0C8h
db 37h
db 0ECh
db 79h
db 38h
db 0CBh
db 0Bh
db 0B6h
db 5Dh
db 2
db 9Fh
db 9Ah
db 0B8h
db 31h
db 0F9h
db 0EEh
db 9Fh
db 51h
db 8Bh
db 8Eh
db 9Fh
db 5Eh
db 0F4h
db 86h
db 24h
db 9Fh
db 69h
db 0AEh
db 3
db 6Ch
db 5Ch
db 83h
db 0
db 59h
db 2Bh
db 0F6h
db 34h
db 0A1h
db 0E5h
db 1Fh
db 6Dh
db 22h
db 0B8h
db 82h
db 51h
db 85h
db 48h
db 0DAh
db 71h
db 0C6h
db 0BCh
db 4Bh
db 0Dh
db 1Fh
db 69h
db 0ECh
db 1Ah
db 43h
db 0CEh
db 82h
db 77h
db 0BEh
db 1Fh
db 0DDh
db 94h
db 63h
db 0B1h
db 0EBh
db 0ECh
db 65h
db 19h
db 0AFh
db 18h
db 0C1h
db 29h
db 30h
db 81h
db 0E4h
db 27h
db 8Bh
db 5Eh
db 0ACh
db 0EAh
db 91h
db 0E8h
db 19h
db 0C9h
db 6Ah
db 0Dh
db 0F3h
db 0E0h
db 0D6h
db 2
db 0E6h
db 56h
db 2Ch
db 55h
db 9Ah
db 0C7h
db 0Fh
db 0F2h
db 4Bh
db 3
db 0DCh
db 0BAh
db 2Dh
db 0Bh
db 60h
db 3Eh
db 0BDh
db 8
db 8Ch
db 0CFh
db 47h
db 69h
db 0E1h
db 54h
db 0EAh
db 6Eh
db 6Fh
db 0FBh
db 31h
db 0DEh
db 0C7h
db 0C9h
db 0C5h
db 83h
db 0Fh
db 3Fh
db 0F3h
db 0CCh
db 28h
db 86h
db 8Bh
db 45h
db 0A4h
db 96h
db 0CEh
db 44h
db 0F3h
db 7Eh
db 0C4h
db 0AAh
db 1
db 60h
db 0C8h
db 0B0h
db 0FFh
db 34h
db 0CFh
db 0Ah
db 0FCh
db 40h
db 40h
db 85h
db 0F7h
db 92h
db 44h
db 7
db 0CBh
db 7Dh
db 0DBh
db 0F3h
db 7Fh
db 0E7h
db 0A5h
db 68h
db 90h
db 68h
db 0D8h
db 1Bh
db 76h
db 8
db 71h
db 2Eh
db 0Ah
db 0FAh
db 0Fh
db 0EBh
db 16h
db 8
db 0ABh
db 2Ah
db 39h
db 0F5h
db 3Ah
db 3
db 20h
db 0EDh
db 7Ah
db 88h
db 0A4h
db 9Dh
db 0ADh
db 75h
db 0DBh
db 3Ah
db 0
db 72h
db 45h
db 4Ah
db 0B2h
db 0C2h
db 21h
db 0A7h
db 0BBh
db 8
db 6Dh
db 93h
db 0EEh
db 0E8h
db 0B7h
db 0B8h
db 64h
db 60h
db 0F0h
db 0E3h
db 90h
db 0F0h
db 16h
db 99h
db 0ECh
db 0AEh
db 39h
db 0B3h
db 0BEh
db 6Fh
db 0D3h
db 0C4h
db 9Eh
db 71h
db 0F1h
db 0D2h
db 1Bh
db 58h
db 64h
db 62h
db 71h
db 0A1h
db 57h
db 0C2h
db 0AEh
db 50h
db 8Ah
db 0CCh
db 4Ch
db 1Ah
db 0ECh
db 94h
db 50h
db 81h
db 16h
db 6Ch
db 87h
db 0F3h
db 0F9h
db 77h
db 52h
db 7Fh
db 0A7h
db 82h
db 73h
db 0E6h
db 0F7h
db 5Bh
db 0CEh
db 0ECh
db 9Eh
db 23h
db 5Fh
db 0BCh
db 0B4h
db 46h
db 18h
db 8Ch
db 6
db 0FDh
db 76h
db 22h
db 82h
db 78h
db 3Ah
db 59h
db 90h
db 0E2h
db 83h
db 0EBh
db 0DFh
db 7Eh
db 23h
db 2Ah
db 9Dh
db 0A7h
db 0E4h
db 54h
db 0BBh
db 2Dh
db 0B9h
db 0FEh
db 3Dh
db 48h
db 0AAh
db 0D6h
db 0B8h
db 5Dh
db 0DFh
db 81h
db 0E9h
db 9Bh
db 92h
db 67h
db 2Ch
db 9Dh
db 19h
db 15h
db 2Dh
db 13h
db 0FCh
db 0A6h
db 0Fh
db 0B6h
db 0D6h
db 55h
db 86h
db 72h
db 7Ch
db 65h
db 1Bh
db 75h
db 0A2h
db 0F1h
db 33h
db 3Bh
db 20h
db 0AAh
db 71h
db 0ECh
db 4Ah
db 0C7h
db 0A8h
db 0C2h
db 73h
db 0BAh
db 29h
db 63h
db 0Ch
db 0F7h
db 41h
db 0DBh
db 0A3h
db 7Ah
db 63h
db 0A7h
db 0D9h
db 46h
db 86h
db 0FCh
db 33h
db 0F6h
db 0B7h
db 9Fh
db 42h
db 25h
db 3Ch
db 9
db 4Ah
db 0ADh
db 89h
db 16h
db 0A0h
db 0ABh
db 0C9h
db 52h
db 0F8h
db 31h
db 0DDh
db 0EEh
db 3
db 55h
db 0F5h
db 90h
db 65h
db 59h
db 38h
db 26h
db 22h
db 0EDh
db 77h
db 0F2h
db 75h
db 77h
db 19h
db 7Bh
db 97h
db 3Ch
db 0EBh
db 94h
db 0CFh
db 3Bh
db 69h
db 1Eh
db 4Bh
db 3Fh
db 39h
db 0B0h
db 94h
db 9Dh
db 86h
db 0B3h
db 5Ch
db 87h
db 14h
db 48h
db 87h
db 0BFh
db 2Fh
db 6Ch
db 78h
db 0F9h
db 0D0h
db 9Dh
db 98h
db 90h
db 3Ch
db 0A9h
db 0B8h
db 0E6h
db 9
db 3Dh
db 11h
db 0B9h
db 0F8h
db 8Bh
db 36h
db 4Fh
db 89h
db 18h
db 70h
db 15h
db 0E9h
db 75h
db 33h
db 27h
db 0Bh
db 0BAh
db 69h
db 0FEh
db 92h
db 9Ah
db 0EBh
db 0DBh
db 6Bh
db 45h
db 0AFh
db 0BEh
db 0F3h
db 65h
db 0
db 6Fh
db 0A5h
db 0F2h
db 0F9h
db 0B1h
db 52h
db 19h
db 5Ah
db 76h
db 0A3h
db 0BCh
db 8Dh
db 6
db 0C9h
db 85h
db 71h
db 5Bh
db 0E4h
db 0B0h
db 9
db 99h
db 78h
db 0EEh
db 0A0h
db 1Dh
db 0DEh
db 1Dh
db 0D6h
db 4Eh
db 9Bh
db 47h
db 61h
db 0D2h
db 0C7h
db 0A6h
db 0B7h
db 83h
db 3Ah
db 0B2h
db 54h
db 0AFh
db 19h
db 0E7h
db 42h
db 16h
db 76h
db 0BEh
db 57h
db 74h
db 49h
db 49h
db 23h
db 5Fh
db 0Ch
db 9Dh
db 54h
db 9Ah
db 0C4h
db 51h
db 0Ah
db 52h
db 0F5h
db 0C6h
db 2
db 0BBh
db 0E7h
db 3Ch
db 5
db 0C6h
db 0DDh
db 0AAh
db 0D0h
db 0C0h
db 8Ch
db 0A9h
db 0Ch
db 0ECh
db 36h
db 0C4h
db 2Eh
db 0AEh
db 0BBh
db 0Eh
db 0B6h
db 2
db 4Dh
db 0Fh
db 1
db 72h
db 66h
db 0C7h
db 0DDh
db 74h
db 38h
db 0D4h
db 9Bh
db 0C1h
db 81h
db 0CAh
db 0AAh
db 0DBh
db 0E9h
db 0ECh
db 2Dh
db 0EDh
db 6Eh
db 58h
db 1
db 9Bh
db 73h
db 0A4h
db 98h
db 53h
db 50h
db 9Bh
db 0F4h
db 86h
db 63h
db 27h
db 69h
db 9Bh
db 0ECh
db 0E5h
db 0FDh
db 0E3h
db 91h
db 0DEh
db 47h
db 8Ch
db 0C0h
db 0F9h
db 19h
db 7Ch
db 0D2h
db 82h
db 22h
db 19h
db 90h
db 8Ch
db 3Bh
db 1Bh
db 4Bh
db 59h
db 54h
db 0EFh
db 0ABh
db 0EEh
db 79h
db 0E7h
db 72h
db 0A8h
db 0D8h
db 0C3h
db 0FFh
db 73h
db 0CDh
db 29h
db 17h
db 2Bh
db 2
db 0A6h
db 0AFh
db 72h
db 0D4h
db 91h
db 19h
db 0B4h
db 32h
db 67h
db 0E5h
db 0E4h
db 0F0h
db 0B9h
db 1Ah
db 56h
db 8
db 0F0h
db 28h
db 0A8h
db 65h
db 0CDh
db 0ADh
db 0E2h
db 41h
db 96h
db 0DFh
db 6Ah
db 37h
db 17h
db 9Eh
db 0FFh
db 0A6h
db 85h
db 0A6h
db 7Ah
db 0D8h
db 3Fh
db 0CAh
db 0FEh
db 0E2h
db 6Dh
db 0FAh
db 96h
db 5Bh
db 61h
db 91h
db 5Ch
db 49h
db 19h
db 0B3h
db 0A9h
db 0B3h
db 0ACh
db 0CFh
db 0CCh
db 0CFh
db 36h
db 2Bh
db 9Eh
db 0C9h
db 43h
db 0B5h
db 47h
db 0DCh
db 8Ch
db 8
db 0F8h
db 6Fh
db 12h
db 1Dh
db 0DBh
db 56h
db 9
db 0E1h
db 0E9h
db 66h
db 2
db 9Dh
db 2Fh
db 89h
db 8Eh
db 0E8h
db 0EFh
db 93h
db 3Dh
db 0Eh
db 92h
db 52h
db 45h
db 41h
db 0D4h
db 1Bh
db 4Ch
db 0CFh
db 16h
db 80h
db 93h
db 65h
db 0C8h
db 0C2h
db 0F5h
db 0CDh
db 0D9h
db 3
db 0CCh
db 2Fh
db 55h
db 0B3h
db 1Eh
db 0B9h
db 24h
db 43h
db 0C7h
db 38h
db 6Ah
db 75h
db 8
db 0F0h
db 45h
db 0E5h
db 82h
db 0FCh
db 2Eh
db 1
db 31h
db 9Ch
db 97h
db 0C9h
db 64h
db 0D9h
db 0A8h
db 5Ah
db 0Ah
db 0F9h
db 40h
db 9Eh
db 9Fh
db 51h
db 0ADh
db 27h
db 0D2h
db 8Eh
db 0DBh
db 0CCh
db 58h
db 64h
db 0Bh
db 0ADh
db 82h
db 0
db 15h
db 0A5h
db 0D3h
db 96h
db 0BEh
db 4Fh
db 0D2h
db 7Eh
db 4Eh
db 0D9h
db 0CDh
db 7Ch
db 0BAh
db 77h
db 2Dh
db 59h
db 1Bh
db 88h
db 6Ah
db 0A2h
db 6Fh
db 7Bh
db 43h
db 47h
db 2Fh
db 0C9h
db 22h
db 0A8h
db 61h
db 0C4h
db 0A9h
db 63h
db 8Ah
db 1Fh
db 0ABh
db 0FAh
db 8Ch
db 1Bh
db 51h
db 36h
db 0E8h
db 86h
db 4Fh
db 55h
db 76h
db 16h
db 23h
db 95h
db 3Bh
db 0F7h
db 0B8h
db 2Ah
db 0CAh
db 27h
db 0CDh
db 57h
db 0C8h
db 0C4h
db 0B1h
db 5Ah
db 6Dh
db 78h
db 0E3h
db 8Eh
db 0A7h
db 5Bh
db 0
db 0B1h
db 0Ch
db 0C9h
db 0F2h
db 6Dh
db 8Eh
db 0FCh
db 0FCh
db 0B5h
db 0C1h
db 3Ch
db 4Bh
db 48h
db 11h
db 77h
db 0F3h
db 67h
db 38h
db 0FFh
db 0E9h
db 77h
db 0E1h
db 5Fh
db 5Dh
db 0F8h
db 47h
db 0ECh
db 12h
db 0F3h
db 24h
db 1
db 0C9h
db 9Bh
db 3
db 72h
db 32h
db 76h
db 19h
db 45h
db 0F2h
db 12h
db 0Ah
db 0AAh
db 2Dh
db 2Dh
db 8Ah
db 34h
db 0DEh
db 0C0h
db 75h
db 95h
db 4Fh
db 0A1h
db 51h
db 84h
db 92h
db 88h
db 32h
db 5Dh
db 0B3h
db 0Fh
db 3Ch
db 0DEh
db 0CFh
db 0Eh
db 0C9h
db 38h
db 0ABh
db 0E6h
db 0D3h
db 54h
db 45h
db 38h
db 0D2h
db 7Eh
db 1Dh
db 2Ah
db 8Ch
db 63h
db 2Ah
db 31h
db 71h
db 0D1h
db 63h
db 0B4h
db 0B7h
db 14h
db 0D3h
db 98h
db 0A2h
db 20h
db 0E7h
db 0F5h
db 0A0h
db 53h
db 68h
db 0DFh
db 76h
db 0FBh
db 76h
db 0D6h
db 33h
db 4Dh
db 7Ch
db 54h
db 0D3h
db 53h
db 24h
db 98h
db 19h
db 93h
db 77h
db 0F8h
db 9Eh
db 58h
db 0F2h
db 0A6h
db 0C1h
db 3Eh
db 1Dh
db 67h
db 0ABh
db 72h
db 0D2h
db 0B9h
db 0F6h
db 21h
db 0DCh
db 5
db 14h
db 0DFh
db 1Dh
db 0A1h
db 0DFh
db 54h
db 0C5h
db 97h
db 32h
db 9Ch
db 1Ch
db 53h
db 0AEh
db 3Dh
db 1Bh
db 97h
db 39h
db 5
db 0F8h
db 3Ah
db 0D2h
db 6Bh
db 75h
db 23h
db 0CAh
db 21h
db 0FAh
db 1Bh
db 0EFh
db 0C6h
db 7Ah
db 0BEh
db 0A4h
db 0CCh
db 0CCh
db 99h
db 50h
db 60h
db 2Eh
db 5Bh
db 7
db 0A5h
db 0DEh
db 26h
db 3Bh
db 84h
db 1Eh
db 32h
db 90h
db 0CBh
db 87h
db 0E4h
db 0F8h
db 1Eh
db 0DDh
db 0ACh
db 60h
db 67h
db 89h
db 76h
db 71h
db 39h
db 6Eh
db 3Ch
db 0E9h
db 3Dh
db 63h
db 7Bh
db 46h
db 0C1h
db 0D5h
db 95h
db 75h
db 0C4h
db 0A5h
db 0Dh
db 36h
db 64h
db 2Eh
db 0EBh
db 6
db 0D3h
db 38h
db 47h
db 0B1h
db 75h
db 0E4h
db 87h
db 0E5h
db 0B8h
db 9
db 0C7h
db 44h
db 0F6h
db 0F3h
db 0AFh
db 51h
db 2Dh
db 6Eh
db 0A8h
db 47h
db 9Eh
db 6Eh
db 14h
db 0A1h
db 12h
db 16h
db 0C2h
db 0BDh
db 0
db 0C2h
db 67h
db 87h
db 92h
db 0E4h
db 0D6h
db 0A7h
db 43h
db 6Ah
db 0FFh
db 5Eh
db 0Fh
db 8Eh
db 11h
db 35h
db 58h
db 0D5h
db 0D5h
db 0
db 18h
db 0C2h
db 14h
db 0B8h
db 9Ah
db 8Bh
db 57h
db 11h
db 0F0h
db 0B2h
db 95h
db 0E2h
db 56h
db 74h
db 0E7h
db 0F3h
db 22h
db 3Fh
db 0B0h
db 0C4h
db 2
db 45h
db 45h
db 0D8h
db 20h
db 48h
db 0E8h
db 9Ch
db 0ABh
db 3Bh
db 44h
db 71h
db 8Ah
db 0F4h
db 0AFh
db 79h
db 9Ch
db 46h
db 99h
db 0FDh
db 0Dh
db 0C9h
db 0BCh
db 0C3h
db 0E4h
db 8Dh
db 72h
db 0A7h
db 0EFh
db 0A8h
db 0F6h
db 0A4h
db 0C7h
db 0
db 0
db 0C8h
db 0Ch
db 0F7h
db 3Ch
db 2Eh
db 0FCh
db 9Ah
db 0A5h
db 9Dh
db 0E9h
db 0CDh
db 23h
db 3Ch
db 12h
db 5
db 5Ch
db 32h
db 0Dh
db 46h
db 9Fh
db 3Ch
db 29h
db 4Ch
db 27h
db 0Fh
db 64h
db 0ABh
db 4Fh
db 7Eh
db 26h
db 0A4h
db 0E0h
db 2Ch
db 58h
db 0E1h
db 44h
db 93h
db 27h
db 4Fh
db 0Fh
db 2Eh
db 54h
db 62h
db 41h
db 0FBh
db 43h
db 0D4h
db 0CCh
db 0B1h
db 1Eh
db 0F2h
db 69h
db 17h
db 0B9h
db 0E3h
db 0F4h
db 1Ah
db 91h
db 46h
db 0CFh
db 2Ah
db 22h
db 0F8h
db 6Ah
db 0CDh
db 0BAh
db 0C5h
db 0CCh
db 70h
db 0DCh
db 92h
db 0EAh
db 0C5h
db 0C7h
db 6Fh
db 1Dh
db 0A8h
db 67h
db 0EDh
db 8Fh
db 3Bh
db 3Ch
db 8Bh
db 86h
db 0EBh
db 5Dh
db 6
db 0C0h
db 0F5h
db 0CDh
db 0F9h
db 73h
db 0A9h
db 0CFh
db 7Ch
db 6Dh
db 0FCh
db 0FFh
db 49h
db 0FEh
db 94h
db 44h
db 1Ch
db 85h
db 0CEh
db 50h
db 0A3h
db 0F7h
db 0E0h
db 57h
db 11h
db 0EFh
db 0FBh
db 9
db 0EBh
db 0F8h
db 0FDh
db 5Ch
db 0C0h
db 10h
db 19h
db 5
db 5Dh
db 28h
db 0E2h
db 69h
db 13h
db 0D7h
db 0Eh
db 0B3h
db 74h
db 0AAh
db 0F5h
db 71h
db 0AFh
db 0BCh
db 0FBh
db 0D3h
db 80h
db 0CEh
db 0C0h
db 84h
db 26h
db 0D5h
db 1Bh
db 72h
db 84h
db 64h
db 0CCh
db 7Ah
db 1Ah
db 57h
db 0A2h
db 0EBh
db 0DAh
db 92h
db 4
db 0D4h
db 0A9h
db 0C4h
db 28h
db 0B2h
db 0D2h
db 37h
db 5Fh
db 7Bh
db 0A5h
db 2
db 6
db 52h
db 0A2h
db 4Eh
db 0C7h
db 44h
db 0DAh
db 0ACh
db 49h
db 0DAh
db 85h
db 0E2h
db 0CAh
db 10h
db 25h
db 48h
db 62h
db 6Fh
db 0E6h
db 92h
db 0EBh
db 0Eh
db 0D6h
db 0D8h
db 89h
db 0A9h
db 2
db 5Bh
db 0A7h
db 3Fh
db 0FCh
db 0F0h
db 68h
db 0B8h
db 2Eh
db 7Bh
db 9Fh
db 0Bh
db 1Ch
db 12h
db 59h
db 68h
db 8
db 0CEh
db 0AFh
db 0D4h
db 0A9h
db 82h
db 0FCh
db 0D2h
db 0A6h
db 9Dh
db 0E0h
db 10h
db 0FEh
db 96h
db 4
db 93h
db 0F0h
db 0C7h
db 3Ah
db 0B5h
db 0ECh
db 32h
db 36h
db 0C5h
db 0A0h
db 8Dh
db 89h
db 91h
db 7Eh
db 0FFh
db 0BCh
db 5
db 79h
db 63h
db 70h
db 6
db 4Dh
db 0AAh
db 0BFh
db 0B4h
db 0D1h
db 23h
db 78h
db 9Bh
db 44h
db 0A7h
db 5Dh
db 0A6h
db 70h
db 53h
db 0DBh
db 6Eh
db 0DEh
db 19h
db 8Dh
db 0F8h
db 25h
db 90h
db 7Ch
db 0F3h
db 1Ch
db 76h
db 16h
db 0EBh
db 0A1h
db 32h
db 33h
db 0E6h
db 26h
db 64h
db 0CCh
db 6Ah
db 40h
db 95h
db 0E7h
db 0EDh
db 6Ch
db 72h
db 0D4h
db 15h
db 9Bh
db 0EDh
db 0FAh
db 3Ch
db 0DAh
db 58h
db 0F0h
db 1
db 0D1h
db 39h
db 4Bh
db 7Ah
db 0DBh
db 65h
db 1Ch
db 77h
db 0A0h
db 0F2h
db 0BBh
db 86h
db 8Eh
db 87h
db 0Eh
db 17h
db 0CBh
db 43h
db 0A0h
db 58h
db 3Bh
db 1Bh
db 0B8h
db 0C3h
db 11h
db 16h
db 6Ah
db 0E0h
db 54h
db 0E6h
db 66h
db 4Ch
db 7
db 5Fh
db 14h
db 1Ch
db 34h
db 2
db 14h
db 0FAh
db 0E7h
db 4Fh
db 0
db 4Eh
db 9Ch
db 7
db 7Fh
db 14h
db 68h
db 0C0h
db 0A1h
db 3Ah
db 0EFh
db 1Fh
db 0ECh
db 0EEh
db 4Bh
db 0C7h
db 64h
db 0BAh
db 6Bh
db 0CFh
db 0F8h
db 0A0h
db 0B3h
db 0CCh
db 0C7h
db 0EEh
db 7
db 4Eh
db 0EBh
db 19h
db 29h
db 0D5h
db 61h
db 0BEh
db 75h
db 8Dh
db 56h
db 31h
db 4
db 5Ah
db 0Bh
db 0B3h
db 0EFh
db 0B3h
db 0Fh
db 0E2h
db 0FEh
db 8Bh
db 4Bh
db 65h
db 3Bh
db 36h
db 0Bh
db 8Fh
db 0DBh
db 90h
db 75h
db 5Eh
db 0BDh
db 0E6h
db 2Ah
db 32h
db 4Bh
db 8Dh
db 3Dh
db 6Ch
db 69h
db 4Dh
db 14h
db 0EDh
db 79h
db 41h
db 0Ch
db 0DDh
db 0EBh
db 0D1h
db 47h
db 0EDh
db 2Bh
db 7Ah
db 85h
db 0A8h
db 7Fh
db 2Eh
db 36h
db 0BFh
db 8Ch
db 0B9h
db 0E6h
db 0C9h
db 6Bh
db 0DBh
db 60h
db 44h
db 5
db 80h
db 74h
db 7Ah
db 12h
db 0DEh
db 7
db 0FEh
db 8Ch
db 74h
db 0B9h
db 3Ch
db 67h
db 0A4h
db 0CDh
db 43h
db 0F5h
db 74h
db 0A8h
db 44h
db 0CEh
db 0C9h
db 14h
db 2Eh
db 8
db 36h
db 0F2h
db 19h
db 69h
db 0DDh
db 7Dh
db 67h
db 0CFh
db 3Dh
db 0DFh
db 0C5h
db 71h
db 8Ch
db 0BBh
db 0EFh
db 9Ch
db 26h
db 99h
db 7Ch
db 0B7h
db 7Ch
db 79h
db 0E2h
db 0DEh
db 79h
db 7
db 1Dh
db 10h
db 92h
db 0BFh
db 5Fh
db 4Dh
db 0ECh
db 5Eh
db 0B5h
db 0A5h
db 73h
db 5Ah
db 0A9h
db 0A0h
db 26h
db 2Bh
db 68h
db 0A0h
db 0F2h
db 5
db 6Eh
db 0Ch
db 51h
db 2
db 6Dh
db 18h
db 63h
db 0B7h
db 0C5h
db 0CCh
db 0BDh
db 59h
db 63h
db 0B5h
db 9Eh
db 0D7h
db 2Dh
db 5Ch
db 18h
db 0C1h
db 0E6h
db 0AFh
db 0E5h
db 0B9h
db 73h
db 68h
db 2Dh
db 53h
db 9Dh
db 0D5h
db 65h
db 0ABh
db 71h
db 0CEh
db 0CCh
db 0D3h
db 0E6h
db 0F2h
db 7Ah
db 85h
db 0A4h
db 0FCh
db 0D6h
db 8Ah
db 8
db 0BBh
db 26h
db 7Ch
db 8Eh
db 7Eh
db 0F8h
db 2Fh
db 72h
db 44h
db 7Dh
db 62h
db 86h
db 0AAh
db 7Dh
db 43h
db 6Eh
db 23h
db 0CDh
db 7Ah
db 2Fh
db 0B1h
db 95h
db 3Bh
db 90h
db 0BFh
db 0B3h
db 85h
db 64h
db 5Fh
db 3Ch
db 9Dh
db 0F6h
db 0CAh
db 0FFh
db 11h
db 2
db 0C6h
db 44h
db 0DFh
db 0E6h
db 0F1h
db 38h
db 28h
db 81h
db 7Fh
db 0D4h
db 0FAh
db 0F7h
db 52h
db 0FBh
db 0D5h
db 0Eh
db 42h
db 0ABh
db 26h
db 14h
db 1Ch
db 0FCh
db 0Eh
db 0Bh
db 36h
db 15h
db 4Bh
db 9Ah
db 0F3h
db 39h
db 0F0h
db 4Ch
db 37h
db 0A4h
db 0D2h
db 0A6h
db 96h
db 21h
db 2Ch
db 32h
db 8Dh
db 87h
db 0F0h
db 0B0h
db 0E1h
db 7Ah
db 33h
db 0A3h
db 0EFh
db 31h
db 0F2h
db 6Bh
db 0CEh
db 33h
db 0A6h
db 0CCh
db 5Dh
db 0BCh
db 0FCh
db 0B0h
db 0CDh
db 0A3h
db 0E1h
db 0B8h
db 72h
db 0FFh
db 9Dh
db 0DFh
db 7Fh
db 0A0h
db 0D1h
db 1
db 4Bh
db 15h
db 44h
db 2Eh
db 59h
db 55h
db 0C7h
db 51h
db 5Eh
db 5
db 0B2h
db 6Dh
db 0C8h
db 8Ah
db 0A0h
db 0EFh
db 0FEh
db 0BBh
db 69h
db 0CFh
db 56h
db 2Eh
db 14h
db 83h
db 0Ah
db 21h
db 0A8h
db 0F9h
db 6Ch
db 26h
db 0Dh
db 0D2h
db 73h
db 16h
db 0D7h
db 8Bh
db 68h
db 74h
db 0FBh
db 2Fh
db 32h
db 35h
db 88h
db 62h
db 36h
db 67h
db 0DAh
db 0A9h
db 42h
db 99h
db 0C4h
db 90h
db 0FFh
db 0E0h
db 2Eh
db 0AAh
db 0F5h
db 6Ch
db 0CBh
db 0CAh
db 2Bh
db 62h
db 0ADh
db 0B8h
db 3Bh
db 0F2h
db 0D0h
db 68h
db 54h
db 0E7h
db 0CEh
db 71h
db 56h
db 0EAh
db 9Fh
db 5
db 0F0h
db 77h
db 90h
db 0F1h
db 11h
db 0C4h
db 0AEh
db 8Eh
db 81h
db 6Ch
db 5Fh
db 3Bh
db 0BDh
db 5Ch
db 0AAh
db 0BFh
db 51h
db 0D2h
db 0EEh
db 0FDh
db 46h
db 0AAh
db 0F3h
db 21h
db 74h
db 0B2h
db 7Dh
db 99h
db 0F1h
db 51h
db 0C0h
db 7
db 79h
db 0CDh
db 25h
db 2Ch
db 0E0h
db 0FFh
db 0A1h
db 0D0h
db 6Ah
db 0A6h
db 44h
db 0A7h
db 0BCh
db 0D3h
db 95h
db 0DCh
db 19h
db 61h
db 3Dh
db 3Ch
db 0A7h
db 96h
db 0CDh
db 7Eh
db 0ABh
db 17h
db 0Dh
db 0BDh
db 0BFh
db 47h
db 26h
db 97h
db 0BEh
db 38h
db 8Eh
db 0BBh
db 0CEh
db 0Fh
db 6Ch
db 4Fh
db 8Dh
db 3Dh
db 1Dh
db 0D9h
db 0ECh
db 6Dh
db 0D7h
db 0EFh
db 0F8h
db 4Bh
db 0E2h
db 8Dh
db 72h
db 0ABh
db 0AAh
db 33h
db 8Ah
db 0B7h
db 0F8h
db 22h
db 2Bh
db 5Eh
db 8
db 2Dh
db 8
db 48h
db 10h
db 52h
db 4Dh
db 0E4h
db 32h
db 2Fh
db 0A0h
db 59h
db 92h
db 1Ah
db 0BCh
db 3Ah
db 26h
db 0B9h
db 8Fh
db 7Bh
db 0B8h
db 0FEh
db 0C7h
db 0CFh
db 42h
db 0EAh
db 0A0h
db 89h
db 0B3h
db 0E2h
db 25h
db 3Eh
db 0DFh
db 23h
db 8Dh
db 4Eh
db 0DEh
db 98h
db 0D4h
db 5Ah
db 42h
db 0D8h
db 10h
db 0DFh
db 0F3h
db 0FAh
db 9Eh
db 0BEh
db 9Eh
db 42h
db 8Ah
db 32h
db 0E7h
db 0AFh
db 3Dh
db 69h
db 0FBh
db 71h
db 0FEh
db 0BFh
db 0A3h
db 30h
db 0E1h
db 1Eh
db 91h
db 3Eh
db 18h
db 6Ah
db 36h
db 0C7h
db 1Fh
db 87h
db 0C3h
db 0CAh
db 8
db 0D1h
db 7Bh
db 4
db 0DCh
db 3Ah
db 0ABh
db 0CDh
db 0D0h
db 0EAh
db 0AAh
db 46h
db 0BEh
db 18h
db 42h
db 8Ah
db 37h
db 0DBh
db 0BAh
db 0ACh
db 0FBh
db 12h
db 57h
db 0D8h
db 0FAh
db 37h
db 63h
db 0E2h
db 17h
db 0B5h
db 0F5h
db 98h
db 14h
db 0BFh
db 0A1h
db 0CEh
db 0B0h
db 72h
db 21h
db 0E6h
db 6Fh
db 0DCh
db 84h
db 87h
db 3Eh
db 0FEh
db 9
db 5
db 0D6h
db 0D5h
db 42h
db 7Ch
db 43h
db 0ABh
db 5Bh
db 97h
db 18h
db 58h
db 14h
db 58h
db 99h
db 0D7h
db 0D0h
db 42h
db 5Ah
db 60h
db 14h
db 0AEh
db 0FBh
db 0F9h
db 23h
db 8Fh
db 0B0h
db 21h
db 80h
db 3
db 7Eh
db 0A3h
db 57h
db 39h
db 1Dh
db 55h
db 11h
db 32h
db 4
db 0
db 1Fh
db 0BAh
db 7Dh
db 3Ah
db 44h
db 0ABh
db 43h
db 86h
db 57h
db 0Bh
db 9Eh
db 5Fh
db 76h
db 0A9h
db 1
db 0CBh
db 48h
db 5Ch
db 0EBh
db 1Ah
db 0A9h
db 0DBh
db 7Eh
db 4Eh
db 30h
db 17h
db 0DBh
db 95h
db 59h
db 0D8h
db 7Ch
db 0C9h
db 39h
db 95h
db 90h
db 98h
db 0BFh
db 19h
db 77h
db 0CBh
db 52h
db 72h
db 4Fh
db 0AAh
db 71h
db 9
db 52h
db 0D7h
db 1Ah
db 2Bh
db 0E2h
db 0D9h
db 11h
db 2Ah
db 0ACh
db 54h
db 79h
db 0B3h
db 0AEh
db 71h
db 0A4h
db 0D0h
db 1Bh
db 75h
db 0Fh
db 0FCh
db 80h
db 0E6h
db 0A4h
db 32h
db 0B0h
db 4Fh
db 0DAh
db 9Bh
db 47h
db 0BFh
db 45h
db 15h
db 0F3h
db 0B1h
db 60h
db 8Fh
db 74h
db 3Bh
db 9Fh
db 5Dh
db 0F8h
db 0ADh
db 0D4h
db 0DDh
db 0DBh
db 48h
db 2Ch
db 0B9h
db 0FFh
db 85h
db 0E9h
db 8Eh
db 6Bh
db 71h
db 2Dh
db 0C0h
db 6
db 79h
db 0C8h
db 0BAh
db 0C5h
db 49h
db 16h
db 45h
db 0Eh
db 89h
db 13h
db 0ADh
db 0A0h
db 62h
db 0F1h
db 0B0h
db 78h
db 78h
db 4Ch
db 0D2h
db 21h
db 0A5h
db 0C7h
db 9Eh
db 6Bh
db 0BEh
db 0A7h
db 3Eh
db 1Ch
db 46h
db 40h
db 84h
db 0BBh
db 20h
db 32h
db 0F7h
db 88h
db 77h
db 0B6h
db 0Fh
db 0FAh
db 0E6h
db 24h
db 8Eh
db 8
db 46h
db 0C1h
db 46h
db 0C5h
db 27h
db 0F7h
db 17h
db 3Dh
db 0BBh
db 50h
db 0C1h
db 0C6h
db 71h
db 0A4h
db 90h
db 0BCh
db 0Fh
db 0D6h
db 0E3h
db 85h
db 0C7h
db 71h
db 0B6h
db 97h
db 7Ah
db 4Dh
db 21h
db 28h
db 10h
db 90h
db 0D5h
db 0BBh
db 7Ah
db 0F0h
db 0E0h
db 44h
db 62h
db 0F5h
db 0E6h
db 97h
db 82h
db 0
db 2Ch
db 99h
db 17h
db 0CAh
db 6Ah
db 80h
db 55h
db 4Eh
db 9
db 82h
db 5Bh
db 0Eh
db 0Ch
db 89h
db 48h
db 0DDh
db 80h
db 0F0h
db 0DAh
db 0F8h
db 48h
db 10h
db 22h
db 0B8h
db 0E2h
db 0B6h
db 11h
db 0ACh
db 47h
db 93h
db 0E9h
db 0CDh
db 0E3h
db 79h
db 0D6h
db 86h
db 3Dh
db 0E2h
db 7Dh
db 0E7h
db 0BAh
db 9Ch
db 89h
db 98h
db 0FCh
db 3Eh
db 0C6h
db 21h
db 79h
db 20h
db 15h
db 51h
db 0F1h
db 0B8h
db 44h
db 8Ah
db 0A1h
db 0DFh
db 89h
db 87h
db 0B1h
db 0BCh
db 8Dh
db 3
db 3
db 0DFh
db 0EDh
db 64h
db 0F1h
db 0C2h
db 56h
db 0EDh
db 0DDh
db 0BFh
db 7Ah
db 53h
db 24h
db 0DCh
db 0FEh
db 0Dh
db 83h
db 31h
db 0A1h
db 0DFh
db 9Eh
db 5Ah
db 4Eh
db 3Bh
db 8Fh
db 0C0h
db 87h
db 0B4h
db 0B0h
db 60h
db 65h
db 0B0h
db 0D4h
db 0AEh
db 0B3h
db 38h
db 10h
db 0E6h
db 8Bh
db 9
db 0A7h
db 96h
db 0E7h
db 1Dh
db 86h
db 45h
db 0EFh
db 18h
db 63h
db 0F9h
db 24h
db 0C2h
db 0A5h
db 0BBh
db 9Dh
db 6Ah
db 32h
db 2Fh
db 4Eh
db 56h
db 0BAh
db 0E6h
db 4Ah
db 0D9h
db 0A3h
db 3Eh
db 0DAh
db 39h
db 50h
db 92h
db 0BCh
db 82h
db 53h
db 0C3h
db 70h
db 0E4h
db 78h
db 93h
db 0DCh
db 1Bh
db 99h
db 3Ch
db 0E6h
db 3Fh
db 3Ah
db 5Eh
db 2Dh
db 9Eh
db 0DFh
db 24h
db 80h
db 0B7h
db 2Eh
db 82h
db 15h
db 30h
db 9Bh
db 0FFh
db 92h
db 0B6h
db 50h
db 6
db 4
db 2Ch
db 0B0h
db 21h
db 0A6h
db 3Bh
db 55h
db 49h
db 3Ah
db 83h
db 0E9h
db 15h
db 0A9h
db 44h
db 3Ah
db 60h
db 59h
db 6Eh
db 73h
db 6Ah
db 0F9h
db 9Ah
db 3Ch
db 6Ch
db 42h
db 0E2h
db 7
db 96h
db 0CEh
db 90h
db 8Ch
db 7Ah
db 0C5h
db 8Eh
db 0D1h
db 0AFh
db 19h
db 48h
db 0B6h
db 78h
db 65h
db 4Ch
db 83h
db 71h
db 0
db 9Ah
db 0C0h
db 9Fh
db 59h
db 82h
db 0E7h
db 1Ah
db 88h
db 9Eh
db 0DDh
db 0Eh
db 95h
db 34h
db 75h
db 56h
db 20h
db 7Dh
db 0E2h
db 0C6h
db 96h
db 1
db 8Fh
db 55h
db 31h
db 76h
db 84h
db 54h
db 5Ah
db 94h
db 3Ch
db 2Eh
db 9Dh
db 60h
db 9Ch
db 0DBh
db 9Eh
db 9Ch
db 48h
db 8Eh
db 2Fh
db 0FAh
db 0FBh
db 6Dh
db 8Fh
db 9Ch
db 78h
db 7Fh
db 30h
db 3Dh
db 98h
db 1Dh
db 0CBh
db 0CCh
db 3Dh
db 0C4h
db 76h
db 91h
db 95h
db 3Fh
db 29h
db 9Ch
db 0BCh
db 66h
db 0BFh
db 0D0h
db 59h
db 0E5h
db 38h
db 53h
db 15h
db 0D8h
db 0C4h
db 45h
db 0AEh
db 95h
db 3Ch
db 2Ah
db 2
db 0BEh
db 0CFh
db 0FDh
db 85h
db 96h
db 0EEh
db 0BAh
db 8Ch
db 3Ch
db 0F8h
db 0E9h
db 0BCh
db 26h
db 86h
db 0E3h
db 6Bh
db 0A1h
db 17h
db 18h
db 10h
db 6Fh
db 0C9h
db 2Ch
db 24h
db 23h
db 97h
db 0FAh
db 96h
db 0BBh
db 0E1h
db 0F6h
db 2
db 97h
db 0B1h
db 53h
db 69h
db 5Bh
db 0EEh
db 0Bh
db 0A9h
db 28h
db 0A2h
db 53h
db 8Fh
db 82h
db 37h
db 91h
db 0DFh
db 3Dh
db 8Ah
db 0BAh
db 34h
db 0DBh
db 6Ch
db 9Ch
db 0ABh
db 0F5h
db 1
db 4
db 8Ah
db 0FFh
db 96h
db 0AAh
db 8
db 95h
db 88h
db 79h
db 0D9h
db 0D5h
db 0BDh
db 30h
db 52h
db 44h
db 0B5h
db 1Fh
db 0C8h
db 6Fh
db 1
db 33h
db 60h
db 46h
db 0CFh
db 99h
db 0A7h
db 0ECh
db 6Ah
db 12h
db 47h
db 0A5h
db 9Fh
db 0ECh
db 0F3h
db 5Bh
db 87h
db 6Bh
db 5Bh
db 0Eh
db 54h
db 0BBh
db 0DAh
db 0FDh
db 0CFh
db 0F5h
db 3
db 9
db 0FFh
db 90h
db 0B0h
db 1Ah
db 0FAh
db 0F8h
db 0D4h
db 9Ch
db 61h
db 69h
db 0E9h
db 71h
db 12h
db 0BFh
db 0
db 0F6h
db 1Ah
db 0A9h
db 1
db 0CDh
db 0A4h
db 0Eh
db 1Fh
db 99h
db 5Bh
db 0A0h
db 0BCh
db 74h
db 0A2h
db 0D8h
db 0E1h
db 65h
db 7Bh
db 8Bh
db 55h
db 8Dh
db 0F8h
db 0BEh
db 31h
db 66h
db 47h
db 0EEh
db 0A1h
db 6Ah
db 0AFh
db 0DFh
db 0AAh
db 0FEh
db 51h
db 0BDh
db 16h
db 0EAh
db 0A2h
db 12h
db 0FFh
db 0B2h
db 4Eh
db 3Eh
db 0D4h
db 0D2h
db 1Fh
db 72h
db 0E5h
db 3Eh
db 0BCh
db 6Bh
db 0E9h
db 0E6h
db 0DDh
db 4Bh
db 34h
db 0DEh
db 0B0h
db 0F9h
db 72h
db 65h
db 8Bh
db 0EFh
db 3Ah
db 25h
db 28h
db 0CCh
db 0F6h
db 27h
db 1Ch
db 35h
db 67h
db 0F8h
db 80h
db 0FCh
db 1Ah
db 0A6h
db 43h
db 8Bh
db 32h
db 36h
db 0F4h
db 23h
db 0E5h
db 9Ch
db 53h
db 0AAh
db 27h
db 26h
db 0B6h
db 0AFh
db 0F1h
db 1Dh
db 65h
db 0F3h
db 0F9h
db 3Ch
db 29h
db 0Eh
db 51h
db 0CCh
db 80h
db 13h
db 93h
db 0C1h
db 17h
db 2Bh
db 0CBh
db 0Dh
db 8
db 5Eh
db 0A2h
db 0C1h
db 56h
db 0E9h
db 0BFh
db 44h
db 83h
db 0D4h
db 0AAh
db 1
db 92h
db 0DDh
db 0DDh
db 0FAh
db 0Eh
db 7Bh
db 44h
db 0B5h
db 10h
db 48h
db 0B2h
db 3Ah
db 6
db 0C7h
db 7
db 7Ah
db 0Dh
db 0FDh
db 0ECh
db 9Fh
db 25h
db 0BCh
db 0Eh
db 35h
db 0Ah
db 0BBh
db 0CDh
db 25h
db 4Bh
db 4Bh
db 24h
db 0E8h
db 0E2h
db 5Dh
db 5
db 0CBh
db 57h
db 34h
db 7Fh
db 0B3h
db 33h
db 0Fh
db 26h
db 77h
db 76h
db 47h
db 0A9h
db 0DCh
db 45h
db 0A7h
db 0D4h
db 1Fh
db 45h
db 0ACh
db 0B1h
db 0EBh
db 94h
db 4Dh
db 91h
db 10h
db 8
db 2
db 1Eh
db 12h
db 27h
db 86h
db 0Eh
db 0E3h
db 4Bh
db 0CEh
db 4Fh
db 0Bh
db 1Dh
db 88h
db 0EAh
db 11h
db 82h
db 63h
db 2Ah
db 0F6h
db 7
db 0F4h
db 3Ah
db 89h
db 29h
db 75h
db 1Eh
db 6
db 3
db 0Dh
db 8Dh
db 0D2h
db 0DCh
db 16h
db 9Ah
db 0E2h
db 8Dh
db 0D0h
db 89h
db 0FBh
db 8Dh
db 9Fh
db 0E6h
db 63h
db 0F0h
db 0FCh
db 0B2h
db 0B1h
db 3Ch
db 0E4h
db 0ACh
db 36h
db 0CCh
db 0Ch
db 7Bh
db 24h
db 0D3h
db 24h
db 0AEh
db 0D0h
db 3Dh
db 9Bh
db 2Ah
db 0B9h
db 7Ch
db 0
db 8Bh
db 70h
db 5Fh
db 45h
db 73h
db 1Eh
db 87h
db 70h
db 0D4h
db 8Ch
db 90h
db 0B0h
db 4Ch
db 3Dh
db 1Dh
db 0FDh
db 0D7h
db 0C1h
db 0
db 52h
db 2Bh
db 3Fh
db 5Eh
db 0EFh
db 7Eh
db 7Ah
db 49h
db 3Eh
db 85h
db 0FFh
db 0DAh
db 27h
db 3Fh
db 0C0h
db 78h
db 0F9h
db 0FAh
db 0Ah
db 0AFh
db 31h
db 98h
db 68h
db 19h
db 2Bh
db 0EBh
db 0BAh
db 3Dh
db 0CCh
db 6Ch
db 0E4h
db 9Eh
db 57h
db 0D4h
db 2Ch
db 73h
db 56h
db 75h
db 91h
db 1Bh
db 0D7h
db 2
db 5
db 2
db 5
db 0Bh
db 23h
db 74h
db 0F3h
db 0F9h
db 71h
db 3Ch
db 51h
db 0A1h
db 33h
db 94h
db 76h
db 51h
db 33h
db 0BFh
db 80h
db 89h
db 0Eh
db 17h
db 0
db 8Bh
db 2Eh
db 0E7h
db 0DEh
db 0B2h
db 0AAh
db 9
db 0A0h
db 5Fh
db 0D2h
db 42h
db 0B5h
db 71h
db 4Dh
db 37h
db 0BAh
db 5Ah
db 47h
db 44h
db 22h
db 0AFh
db 0B2h
db 0EDh
db 22h
db 0A5h
db 0FAh
db 0CCh
db 0EEh
db 0A9h
db 0B9h
db 0DCh
db 6
db 0B5h
db 0F5h
db 49h
db 15h
db 14h
db 9Fh
db 77h
db 7Eh
db 57h
db 8Bh
db 4Fh
db 69h
db 28h
db 3Ch
db 5
db 51h
db 8Bh
db 24h
db 7Bh
db 7Bh
db 0C8h
db 9Bh
db 5Bh
db 92h
db 55h
db 1
db 26h
db 8Ah
db 6Ah
db 78h
db 91h
db 1Eh
db 57h
db 0A2h
db 88h
db 0DFh
db 2Ah
db 5Dh
db 0FDh
db 0C6h
db 0C0h
db 17h
db 86h
db 89h
db 38h
db 7
db 14h
db 0CDh
db 9Ch
db 45h
db 21h
db 0Ch
db 0D6h
db 96h
db 0D3h
db 0E7h
db 0C9h
db 62h
db 59h
db 0C0h
db 0A1h
db 44h
db 65h
db 0C4h
db 23h
db 9Bh
db 0CCh
db 0E6h
db 89h
db 0B0h
db 29h
db 0B7h
db 63h
db 80h
db 0Bh
db 0B2h
db 75h
db 46h
db 3Ch
db 0E1h
db 82h
db 72h
db 0BBh
db 8Dh
db 3Ah
db 0E0h
db 0E5h
db 8Fh
db 0BAh
db 20h
db 0ACh
db 80h
db 81h
db 4Eh
db 4Fh
db 0BFh
db 0A3h
db 0D9h
db 0AFh
db 88h
db 92h
db 0C5h
db 9Ch
db 0B2h
db 0C7h
db 13h
db 0ADh
db 3Eh
db 0C9h
db 0E9h
db 0C6h
db 60h
db 0D9h
db 72h
db 0DCh
db 3Eh
db 4Dh
db 0E2h
db 4Bh
db 0B1h
db 0A2h
db 0C9h
db 0FCh
db 0DEh
db 0D4h
db 69h
db 0DFh
db 12h
db 66h
db 77h
db 0B5h
db 19h
db 0DBh
db 0DEh
db 4Ch
db 0ACh
db 22h
db 38h
db 94h
db 0A7h
db 85h
db 0C3h
db 4Eh
db 0DCh
db 7Bh
db 44h
db 50h
db 0F7h
db 47h
db 45h
db 0CAh
db 0D3h
db 56h
db 0Bh
db 0AFh
db 7Eh
db 97h
db 3Ch
db 0C3h
db 0C8h
db 0A0h
db 61h
db 29h
db 30h
db 98h
db 76h
db 0DFh
db 1Fh
db 32h
db 83h
db 0CEh
db 0FCh
db 3Ah
db 61h
db 7Bh
db 34h
db 2Dh
db 97h
db 0DBh
db 9
db 0E4h
db 7Fh
db 7Eh
db 0D3h
db 3Dh
db 1Bh
db 0A9h
db 0E2h
db 0BCh
db 0C7h
db 39h
db 51h
db 0CEh
db 0B7h
db 3Ah
db 1
db 75h
db 4Dh
db 87h
db 0E1h
db 9Ah
db 0ECh
db 0EDh
db 9Dh
db 12h
db 3Bh
db 7Dh
db 45h
db 43h
db 3Eh
db 3Eh
db 0BAh
db 0FBh
db 14h
db 7Dh
db 0Eh
db 32h
db 89h
db 70h
db 5Dh
db 13h
db 5Fh
db 0DEh
db 4Eh
db 0F0h
db 0C8h
db 66h
db 3Fh
db 5Ah
db 0A0h
db 0C3h
db 44h
db 90h
db 4Bh
db 2Bh
db 93h
db 1Ch
db 0EAh
db 77h
db 0
db 71h
db 9Dh
db 0EDh
db 0E7h
db 0D4h
db 0CCh
db 53h
db 0Ah
db 6Dh
db 3
db 0E0h
db 61h
db 4Eh
db 0CCh
db 0EDh
db 0F3h
db 2Eh
db 0FCh
db 1Fh
db 25h
db 87h
db 2Ah
db 3Dh
db 42h
db 0AFh
db 9Dh
db 0B8h
db 0FDh
db 54h
db 0F0h
db 0A7h
db 7Dh
db 70h
db 64h
db 0D4h
db 0F3h
db 13h
db 65h
db 5Ch
db 8Dh
db 68h
db 0F9h
db 9Dh
db 4Eh
db 1Bh
db 76h
db 7Ah
db 0D9h
db 23h
db 0AAh
db 96h
db 60h
db 0B9h
db 84h
db 6
db 44h
db 78h
db 32h
db 4Ch
db 5Ah
db 68h
db 1Ah
db 71h
db 3
db 83h
db 0E2h
db 91h
db 0C2h
db 4
db 52h
db 29h
db 0F3h
db 0EDh
db 0DCh
db 4Ch
db 0EDh
db 81h
db 0B8h
db 3
db 2Eh
db 73h
db 0DFh
db 0D0h
db 53h
db 42h
db 0CAh
db 0B9h
db 0B8h
db 83h
db 1Ch
db 0Ch
db 80h
db 0E6h
db 57h
db 0F3h
db 56h
db 0E1h
db 88h
db 8Eh
db 0C5h
db 22h
db 0B2h
db 0BEh
db 7Ah
db 83h
db 0E3h
db 93h
db 9Eh
db 73h
db 8Ch
db 71h
db 7
db 0EEh
db 8Ah
db 0D0h
db 5Dh
db 4Eh
db 90h
db 0C9h
db 0A4h
db 0D3h
db 3Dh
db 0F4h
db 56h
db 81h
db 13h
db 2Bh
db 2Ch
db 0B9h
db 0B1h
db 54h
db 0F3h
db 3Dh
db 0A2h
db 0Dh
db 4Eh
db 0ECh
db 0CDh
db 0DAh
db 0B4h
db 0B8h
db 0D6h
db 0E6h
db 0B2h
db 0FFh
db 0FEh
db 2Eh
db 0EAh
db 73h
db 57h
db 9Dh
db 18h
db 0D6h
db 0EDh
db 14h
db 20h
db 0C6h
db 0B6h
db 0C6h
db 0E4h
db 0DDh
db 0BDh
db 0ABh
db 34h
db 0CCh
db 0Eh
db 0EDh
db 72h
db 23h
db 98h
db 7Fh
db 3Dh
db 83h
db 0CAh
db 6Ah
db 22h
db 0FBh
db 0C0h
db 0F0h
db 1
db 0E2h
db 0DBh
db 92h
db 5Bh
db 0E3h
db 5Eh
db 0Dh
db 0CDh
db 90h
db 0BEh
db 0C2h
db 0D1h
db 0ABh
db 0EBh
db 2Fh
db 78h
db 3Bh
db 0B5h
db 0FEh
db 0C9h
db 30h
db 0B4h
db 0E6h
db 0F8h
db 0F2h
db 41h
db 55h
db 0B5h
db 0BDh
db 56h
db 0Ch
db 0F9h
db 0Fh
db 0E7h
db 8Ch
db 0Bh
db 0A5h
db 19h
db 31h
db 43h
db 0C4h
db 49h
db 97h
db 0C2h
db 4Ch
db 5Bh
db 56h
db 20h
db 64h
db 65h
db 49h
db 39h
db 92h
db 0D6h
db 0D0h
db 99h
db 0D3h
db 0DEh
db 47h
db 0F8h
db 69h
db 16h
db 62h
db 0ECh
db 8Ah
db 38h
db 0AFh
db 0A7h
db 0C7h
db 0AEh
db 89h
db 0FBh
db 0CDh
db 72h
db 0A4h
db 51h
db 6Ch
db 77h
db 38h
db 3Ah
db 0CBh
db 0EAh
db 50h
db 0Fh
db 81h
db 0ADh
db 48h
db 2
db 54h
db 1Ch
db 3Ch
db 0A2h
db 3Fh
db 0CFh
db 8Ch
db 6Bh
db 61h
db 1Dh
db 0Ah
db 0D8h
db 9
db 47h
db 2Ah
db 1Fh
db 21h
db 0C6h
db 0C5h
db 0E7h
db 0FDh
db 0DDh
db 2Dh
db 0B7h
db 8Dh
db 0A0h
db 55h
db 28h
db 0FCh
db 0ECh
db 69h
db 24h
db 0E1h
db 0F2h
db 47h
db 7Bh
db 0A9h
db 0E3h
db 0BAh
db 49h
db 84h
db 2Eh
db 3Ch
db 5Eh
db 92h
db 6Ah
db 0FEh
db 0A8h
db 71h
db 8Fh
db 69h
db 73h
db 4Ah
db 5Fh
db 0FBh
db 37h
db 93h
db 4Dh
db 0FAh
db 57h
db 77h
db 37h
db 0B2h
db 0D5h
db 68h
db 7Fh
db 1Ah
db 0FCh
db 31h
db 6Ah
db 0C0h
db 43h
db 6Ch
db 0Dh
db 0F2h
db 88h
db 0C5h
db 2Fh
db 91h
db 0BDh
db 3Ah
db 0B8h
db 72h
db 5Dh
db 75h
db 0B7h
db 1
db 7Fh
db 5
db 2Fh
db 0ECh
db 5Eh
db 0B2h
db 4Fh
db 0Ah
db 0B5h
db 39h
db 0C2h
db 5Dh
db 0A8h
db 4Bh
db 2Ah
db 9Dh
db 0A2h
db 64h
db 99h
db 30h
db 15h
db 5
db 0D2h
db 4Ch
db 0BBh
db 0DAh
db 78h
db 0DDh
db 0FCh
db 2Bh
db 69h
db 5
db 98h
db 0F8h
db 0A9h
db 22h
db 1Eh
db 0A5h
db 0F9h
db 0C7h
db 5Eh
db 0CEh
db 12h
db 31h
db 82h
db 0CEh
db 41h
db 90h
db 7Eh
db 50h
db 3Ah
db 68h
db 0CDh
db 65h
db 72h
db 56h
db 12h
db 0BBh
db 0CCh
db 0A3h
db 82h
db 0F7h
db 20h
db 0Ah
db 4
db 80h
db 46h
db 3Eh
db 66h
db 7Ah
db 2Fh
db 0ADh
db 0B5h
db 64h
db 2Bh
db 7Ah
db 0E9h
db 7Fh
db 0A9h
db 0A3h
db 34h
db 0E4h
db 0F5h
db 0C5h
db 50h
db 0F2h
db 2Eh
db 4Ah
db 0F4h
db 83h
db 0BFh
db 0ABh
db 0ECh
db 94h
db 0B6h
db 4Dh
db 2Ah
db 0E1h
db 0C7h
db 6Ah
db 4Ch
db 7Bh
db 8Fh
db 0DEh
db 8Eh
db 1Bh
db 0DFh
db 7Dh
db 65h
db 0AAh
db 5Ah
db 73h
db 0C1h
db 3Dh
db 0D7h
db 67h
db 0C5h
db 0DCh
db 0DDh
db 0F2h
db 0AFh
db 0E1h
db 0B8h
db 0A1h
db 2Eh
db 27h
db 99h
db 94h
db 59h
db 0DBh
db 5Ah
db 98h
db 2Eh
db 0D4h
db 0A1h
db 0F7h
db 5
db 0ACh
db 0A3h
db 5Bh
db 0FDh
db 39h
db 1
db 74h
db 31h
db 0FEh
db 0B0h
db 11h
db 6Bh
db 71h
db 26h
db 7Dh
db 55h
db 5Ch
db 21h
db 0BAh
db 0C2h
db 3Ch
db 0B9h
db 0Dh
db 0A9h
db 31h
db 54h
db 0Bh
db 5
db 0B2h
db 76h
db 2Ch
db 20h
db 37h
db 90h
db 3Ah
db 44h
db 0B2h
db 95h
db 0A7h
db 0D0h
db 0B0h
db 0AAh
db 9
db 82h
db 92h
db 4Fh
db 0A9h
db 82h
db 63h
db 0CFh
db 50h
db 69h
db 39h
db 1Ah
db 0D8h
db 70h
db 0EAh
db 0DFh
db 0F0h
db 47h
db 0F3h
db 0B2h
db 29h
db 0E6h
db 0E6h
db 5Ah
db 17h
db 93h
db 9Eh
db 37h
db 0DEh
db 0A2h
db 4
db 14h
db 81h
db 0EFh
db 14h
db 0E9h
db 89h
db 7Bh
db 5Fh
db 5Eh
db 37h
db 8Ah
db 0B9h
db 0E7h
db 9Dh
db 0B5h
db 5Dh
db 1
db 3Ch
db 6Eh
db 0E7h
db 2
db 0C7h
db 11h
db 7
db 4Fh
db 0DDh
db 59h
db 3Bh
db 0B0h
db 9Eh
db 55h
db 0D7h
db 56h
db 91h
db 8Ah
db 0A2h
db 0A2h
db 0CAh
db 0CEh
db 0BFh
db 0DFh
db 7Fh
db 8Bh
db 99h
db 1Eh
db 51h
db 94h
db 0Fh
db 0BFh
db 17h
db 5Fh
db 8Bh
db 0A5h
db 90h
db 0DFh
db 89h
db 27h
db 0ABh
db 0A0h
db 59h
db 94h
db 0DCh
db 88h
db 0A9h
db 42h
db 71h
db 9Bh
db 0FBh
db 6Ah
db 4Ch
db 5Eh
db 0A5h
db 0E0h
db 3Fh
db 0CDh
db 0Ch
db 1Fh
db 1Dh
db 0B0h
db 7
db 0C0h
db 26h
db 98h
db 0Eh
db 0A2h
db 20h
db 67h
db 31h
db 54h
db 51h
db 0
db 0A6h
db 0C1h
db 0C9h
db 0BEh
db 1Ch
db 0FEh
db 0EDh
db 9Ah
db 50h
db 0F1h
db 53h
db 2Fh
db 78h
db 3Fh
db 15h
db 0B4h
db 64h
db 5Fh
db 3
db 94h
db 0D0h
db 79h
db 2Dh
db 55h
db 0A9h
db 0B1h
db 5Fh
db 0D7h
db 0CAh
db 0BEh
db 0FAh
db 16h
db 61h
db 0C7h
db 73h
db 4Ch
db 0CEh
db 39h
db 0FEh
db 0C1h
db 82h
db 86h
db 0AFh
db 93h
db 0Ch
db 57h
db 81h
db 5Bh
db 71h
db 0Dh
db 6Eh
db 0C5h
db 0E6h
db 0A2h
db 6Fh
db 48h
db 33h
db 85h
db 0CCh
db 0BDh
db 80h
db 0F4h
db 0C6h
db 99h
db 76h
db 64h
db 13h
db 9Bh
db 0BAh
db 0AAh
db 6Bh
db 3Dh
db 89h
db 6Fh
db 0E5h
db 5Fh
db 0A1h
db 46h
db 0Bh
db 36h
db 16h
db 0FEh
db 4Dh
db 0B0h
db 63h
db 4Ah
db 25h
db 53h
db 92h
db 0B6h
db 91h
db 0AAh
db 85h
db 0C7h
db 6Ah
db 0A0h
db 2Ch
db 55h
db 83h
db 7
db 0B0h
db 78h
db 72h
db 6Eh
db 1Bh
db 0E8h
db 0C1h
db 0BDh
db 0BBh
db 72h
db 87h
db 38h
db 0BAh
db 0E4h
db 35h
db 40h
db 3Fh
db 0EBh
db 22h
db 34h
db 3
db 0F0h
db 63h
db 0
db 1Fh
db 0C6h
db 43h
db 0B5h
db 82h
db 2Ch
db 0BAh
db 0EFh
db 84h
db 0C3h
db 0AFh
db 0EEh
db 63h
db 0BFh
db 43h
db 0BCh
db 0DEh
db 0F9h
db 61h
db 0E5h
db 2Fh
db 0E1h
db 0Dh
db 0E2h
db 85h
db 0AEh
db 73h
db 39h
db 36h
db 78h
db 47h
db 9Bh
db 0C3h
db 0B8h
db 84h
db 0Dh
db 0BFh
db 45h
db 13h
db 0E7h
db 57h
db 76h
db 0EAh
db 95h
db 60h
db 24h
db 0F5h
db 0EDh
db 2Fh
db 7Dh
db 1Ch
db 63h
db 0EEh
db 0F4h
db 57h
db 42h
db 7
db 4Dh
db 4Dh
db 13h
db 0C5h
db 0E4h
db 82h
db 5Ch
db 59h
db 0A6h
db 56h
db 0A0h
db 0A0h
db 1Bh
db 0D3h
db 27h
db 0EDh
db 0Ch
db 0A8h
db 3
db 1Ch
db 70h
db 0FDh
db 94h
db 83h
db 0ABh
db 0A0h
db 49h
db 0D0h
db 73h
db 0EAh
db 69h
db 3Fh
db 27h
db 65h
db 12h
db 37h
db 0EAh
db 0A4h
db 1Eh
db 0EAh
db 0FBh
db 81h
db 0BEh
db 5Ah
db 25h
db 89h
db 0B2h
db 0B1h
db 19h
db 97h
db 20h
db 0A6h
db 0B5h
db 0C4h
db 0B1h
db 0A5h
db 4Eh
db 0Eh
db 0A8h
db 7Dh
db 86h
db 4Bh
db 69h
db 28h
db 0FEh
db 6Ah
db 6Dh
db 87h
db 64h
db 8Eh
db 2Dh
db 50h
db 0ECh
db 5Bh
db 0E8h
db 0B0h
db 0C6h
db 68h
db 0A1h
db 0DEh
db 43h
db 1Eh
db 0B8h
db 2
db 0Ch
db 4Ah
db 91h
db 0F6h
db 9Ah
db 0C7h
db 9Bh
db 5Fh
db 0A1h
db 0F8h
db 5Ch
db 0Bh
db 16h
db 55h
db 64h
db 0D1h
db 2
db 0C6h
db 0BBh
db 0AEh
db 92h
db 3Bh
db 46h
db 1Eh
db 24h
db 0A2h
db 6Fh
db 0A1h
db 0C2h
db 1
db 0F2h
db 84h
db 3Ah
db 6Eh
db 99h
db 8Fh
db 3Ch
db 1Bh
db 6Fh
db 0CDh
db 62h
db 46h
db 78h
db 7Bh
db 0BAh
db 97h
db 0B0h
db 10h
db 8Ch
db 3Bh
db 0E8h
db 55h
db 69h
db 0FFh
db 0CCh
db 85h
db 0Eh
db 0AFh
db 0D2h
db 5Eh
db 16h
db 0B7h
db 74h
db 1Ah
db 7Fh
db 40h
db 0A6h
db 35h
db 5Dh
db 0F0h
db 0F1h
db 2
db 7Bh
db 0FCh
db 0Bh
db 44h
db 0DCh
db 0C8h
db 10h
db 36h
db 50h
db 0CDh
db 0B3h
db 71h
db 0D2h
db 0C8h
db 0D9h
db 77h
db 0A6h
db 7Ch
db 9Dh
db 0EAh
db 0CBh
db 17h
db 8Ah
db 0C5h
db 0E8h
db 0C8h
db 4Ch
db 76h
db 28h
db 49h
db 61h
db 0C0h
db 36h
db 59h
db 3
db 4Dh
db 0EEh
db 0DEh
db 0ECh
db 9Dh
db 0C8h
db 9Dh
db 25h
db 0E8h
db 35h
db 5Bh
db 6
db 0E1h
db 5Dh
db 18h
db 19h
db 35h
db 4
db 3Bh
db 14h
db 62h
db 4Dh
db 0E4h
db 0E6h
db 0BFh
db 0CAh
db 0B2h
db 0D7h
db 6Bh
db 0CFh
db 56h
db 9Bh
db 0B6h
db 0EEh
db 0Fh
db 2Ah
db 7Dh
db 41h
db 4Dh
db 5Eh
db 9Bh
db 5Bh
db 5Eh
db 0Bh
db 3Fh
db 0A2h
db 0A2h
db 4Ah
db 0B9h
db 0ECh
db 73h
db 4Fh
db 16h
db 28h
db 27h
db 28h
db 53h
db 64h
db 0E6h
db 0ABh
db 0A6h
db 53h
db 9Eh
db 0EEh
db 41h
db 0EFh
db 0A4h
db 0BEh
db 36h
db 57h
db 29h
db 0A1h
db 90h
db 8Ah
db 7Ah
db 55h
db 64h
db 62h
db 25h
db 55h
db 0F2h
db 18h
db 0B8h
db 0BEh
db 39h
db 42h
db 39h
db 0DEh
db 7Dh
db 13h
db 68h
db 92h
db 59h
db 0ADh
db 0C4h
db 4
db 7Bh
db 0F8h
db 11h
db 5Ah
db 79h
db 48h
db 90h
db 34h
db 24h
db 0BDh
db 0EFh
db 52h
db 0DEh
db 77h
db 43h
db 9Ah
db 13h
db 48h
db 0A9h
db 0F7h
db 61h
db 0E0h
db 6Ch
db 7
db 0EDh
db 3Ah
db 64h
db 0BAh
db 0D8h
db 32h
db 95h
db 73h
db 91h
db 0A1h
db 60h
db 8Ah
db 0D2h
db 0CFh
db 9Bh
db 0AAh
db 0Bh
db 0BCh
db 0E1h
db 0ACh
db 0DFh
db 5Bh
db 28h
db 4Fh
db 7Dh
db 0A9h
db 0EDh
db 7Eh
db 56h
db 10h
db 0DFh
db 0EDh
db 8Bh
db 87h
db 76h
db 14h
db 0CFh
db 4Dh
db 7Bh
db 0C5h
db 0A2h
db 1Ah
db 0B1h
db 5
db 0BAh
db 0C9h
db 1Dh
db 51h
db 0E0h
db 0D3h
db 0F3h
db 2
db 4Bh
db 0FDh
db 0F6h
db 0CFh
db 0B2h
db 9Ch
db 0A0h
db 0F7h
db 6
db 9Bh
db 0D0h
db 85h
db 9Ah
db 2Dh
db 1Dh
db 0D4h
db 64h
db 6Fh
db 0B8h
db 0B1h
db 2Eh
db 0B8h
db 21h
db 8Ch
db 97h
db 14h
db 19h
db 0F7h
db 0C0h
db 3Ah
db 0DCh
db 74h
db 3
db 0A9h
db 0EAh
db 0EFh
db 0BAh
db 0ECh
db 55h
db 92h
db 1Ah
db 5Ch
db 0EAh
db 0E0h
db 0C8h
db 94h
db 36h
db 0Bh
db 0EBh
db 0A2h
db 0BEh
db 0B6h
db 92h
db 84h
db 0AEh
db 0C5h
db 16h
db 3Ah
db 0E6h
db 71h
db 0FAh
db 86h
db 5Dh
db 96h
db 0B2h
db 0CBh
db 39h
db 18h
db 9
db 31h
db 76h
db 18h
db 1
db 89h
db 7Fh
db 45h
db 0F2h
db 86h
db 86h
db 2Ch
db 38h
db 7Ah
db 3Ah
db 4Ch
db 16h
db 17h
db 20h
db 0C0h
db 3Bh
db 24h
db 0BFh
db 92h
db 0Ah
db 70h
db 3Eh
db 0AAh
db 28h
db 33h
db 82h
db 27h
db 3Ch
db 4Bh
db 0AFh
db 60h
db 72h
db 4Ch
db 5Bh
db 0A9h
db 7Ch
db 69h
db 90h
db 0CCh
db 13h
db 4Fh
db 22h
db 0FEh
db 0BBh
db 0A4h
db 4Ch
db 6Eh
db 99h
db 2Eh
db 0Ah
db 64h
db 0DAh
db 85h
db 63h
db 28h
db 3Bh
db 7Eh
db 6Ah
db 10h
db 45h
db 21h
db 2Bh
db 98h
db 99h
db 62h
db 0A0h
db 0EEh
db 0A4h
db 0A6h
db 91h
db 74h
db 9
db 8Ch
db 52h
db 5
db 94h
db 0DEh
db 3Fh
db 5
db 5
db 0A7h
db 0D2h
db 0ACh
db 0EFh
db 0BDh
db 4
db 12h
db 0
db 29h
db 5Ah
db 4Eh
db 66h
db 0B3h
db 5Dh
db 0BFh
db 0A6h
db 0F7h
db 14h
db 0E4h
db 13h
db 17h
db 0C2h
db 34h
db 39h
db 99h
db 0A2h
db 64h
db 40h
db 14h
db 4Ch
db 0BBh
db 0AEh
db 9Ch
db 42h
db 58h
db 0A4h
db 0C0h
db 0C8h
db 0EAh
db 0BEh
db 13h
db 9Ch
db 48h
db 0C7h
db 2Ah
db 0E6h
db 74h
db 19h
db 0BCh
db 4
db 6Eh
db 2Dh
db 85h
db 0A2h
db 1Eh
db 33h
db 0EBh
db 59h
db 0C8h
db 48h
db 86h
db 81h
db 0DFh
db 6Fh
db 0A8h
db 7Bh
db 2Fh
db 0BFh
db 71h
db 47h
db 23h
db 0FFh
db 0EBh
db 19h
db 0ECh
db 0E9h
db 7Bh
db 36h
db 0C0h
db 0AEh
db 0C7h
db 0BCh
db 0CAh
db 27h
db 27h
db 1Fh
db 0CFh
db 0A0h
db 36h
db 9Dh
db 2Fh
db 9Ch
db 0CAh
db 0BCh
db 0B2h
db 62h
db 0D8h
db 6Ch
db 38h
db 93h
db 0E1h
db 27h
db 16h
db 2Fh
db 0A2h
db 74h
db 68h
db 0D1h
db 4Ah
db 1Dh
db 0CDh
db 75h
db 0B7h
db 5Dh
db 0A0h
db 0FCh
db 80h
db 1Ch
db 0C3h
db 75h
db 35h
db 66h
db 35h
db 0F6h
db 17h
db 0AEh
db 0D7h
db 0E1h
db 0AAh
db 0B9h
db 0BAh
db 80h
db 1Bh
db 0EBh
db 77h
db 0F9h
db 0EDh
db 21h
db 69h
db 0CAh
db 0C5h
db 0D8h
db 0C7h
db 41h
db 5Bh
db 0C5h
db 0BEh
db 45h
db 0CEh
db 0E2h
db 59h
db 0FAh
db 4Eh
db 12h
db 12h
db 0EDh
db 24h
db 59h
db 0DCh
db 0F6h
db 0A8h
db 89h
db 3Ah
db 0CCh
db 23h
db 7Ch
db 0E6h
db 0D1h
db 53h
db 43h
db 9Ch
db 0F9h
db 0B0h
db 3Ch
db 0B0h
db 0D1h
db 60h
db 0CBh
db 0DCh
db 0Bh
db 0C1h
db 21h
db 0BCh
db 37h
db 0AAh
db 27h
db 44h
db 2Eh
db 5Eh
db 95h
db 47h
db 1Ah
db 0C7h
db 44h
db 2Dh
db 0D7h
db 2Dh
db 0CCh
db 0A4h
db 50h
db 0DAh
db 0E9h
db 0DBh
db 0Eh
db 17h
db 9
db 0A4h
db 0FAh
db 0A9h
db 0BDh
db 4Eh
db 0CEh
db 25h
db 0DFh
db 0Bh
db 0Ch
db 6Eh
db 0ABh
db 0FDh
db 0E1h
db 0D3h
db 0FBh
db 0BFh
db 0ECh
db 0ADh
db 34h
db 0B0h
db 12h
db 7Bh
db 35h
db 15h
db 0DAh
db 0C2h
db 21h
db 80h
db 14h
db 72h
db 18h
db 66h
db 0EDh
db 0D9h
db 0D4h
db 3Fh
db 0C1h
db 0CAh
db 76h
db 65h
db 0A3h
db 37h
db 89h
db 0AEh
db 0ECh
db 0Dh
db 31h
db 61h
db 0E8h
db 66h
db 15h
db 11h
db 0C0h
db 6Ch
db 7Fh
db 8
db 1Ah
db 85h
db 29h
db 3Ch
db 0D0h
db 0ABh
db 68h
db 4
db 0EDh
db 0CDh
db 0F3h
db 48h
db 0D4h
db 38h
db 1Eh
db 0C4h
db 48h
db 59h
db 2Ch
db 0A7h
db 3Ch
db 44h
db 9Fh
db 0FAh
db 87h
db 43h
db 1Ch
db 0FCh
db 19h
db 6Eh
db 1Dh
db 0A3h
db 91h
db 51h
db 0B2h
db 0D7h
db 68h
db 7Bh
db 28h
db 0AEh
db 8
db 92h
db 82h
db 1
db 22h
db 56h
db 97h
db 33h
db 0B9h
db 14h
db 0AEh
db 52h
db 36h
db 0D6h
db 54h
db 63h
db 0B5h
db 66h
db 1Ah
db 9Fh
db 0C9h
db 8Bh
db 90h
db 0E1h
db 0C0h
db 0D5h
db 35h
db 12h
db 0B4h
db 0BBh
db 0D5h
db 97h
db 7
db 96h
db 0D0h
db 0CEh
db 93h
db 0A5h
db 1Ch
db 0EDh
db 76h
db 9Dh
db 0D9h
db 5Ah
db 0DBh
db 8Dh
db 39h
db 6Ch
db 17h
db 0D7h
db 68h
db 4Ch
db 54h
db 0A1h
db 7Ch
db 83h
db 31h
db 0C5h
db 8Bh
db 8Fh
db 47h
db 54h
db 88h
db 0F5h
db 0F4h
db 9Bh
db 0B6h
db 0E9h
db 4Bh
db 0FBh
db 73h
db 80h
db 0C3h
db 0F3h
db 0A6h
db 0EFh
db 60h
db 0E2h
db 0A4h
db 96h
db 15h
db 5
db 0EBh
db 81h
db 5Dh
db 0EBh
db 0D2h
db 0FAh
db 3Ah
db 0B8h
db 0CFh
db 79h
db 7Dh
db 9Fh
db 0Eh
db 0Fh
db 0B7h
db 4Dh
db 0B1h
db 0A6h
db 0F4h
db 0E4h
db 0D5h
db 0C3h
db 0A9h
db 8Eh
db 60h
db 0B2h
db 0Ah
db 2Ah
db 4Fh
db 0AAh
db 96h
db 0DCh
db 5
db 0D0h
db 7Ah
db 26h
db 7Ah
db 0C1h
db 0B4h
db 22h
db 9Dh
db 8Fh
db 0BBh
db 0DAh
db 0A2h
db 0AFh
db 0ECh
db 0D5h
db 95h
db 14h
db 0C1h
db 42h
db 37h
db 4Bh
db 33h
db 4Ch
db 18h
db 0E5h
db 0B6h
db 0AAh
db 0B5h
db 0F6h
db 79h
db 0EEh
db 0B1h
db 0ABh
db 0AFh
db 0FEh
db 0C3h
db 6Ch
db 0B9h
db 2Dh
db 79h
db 0D9h
db 0E0h
db 0CEh
db 55h
db 9Bh
db 0E2h
db 0EAh
db 4Ch
db 0DEh
db 5Ah
db 0F4h
db 1
db 30h
db 13h
db 8
db 8Bh
db 17h
db 93h
db 2Fh
db 0A3h
db 0A0h
db 0B8h
db 13h
db 0A0h
db 7Dh
db 88h
db 0AAh
db 99h
db 0E2h
db 0B4h
db 0F6h
db 5Dh
db 65h
db 0E9h
db 36h
db 65h
db 15h
db 1Bh
db 0D6h
db 8Dh
db 0FCh
db 44h
db 48h
db 86h
db 20h
db 0B7h
db 98h
db 78h
db 0B3h
db 4
db 0C2h
db 37h
db 2Eh
db 0A0h
db 0D3h
db 4Ah
db 0CEh
db 0C5h
db 1Eh
db 60h
db 28h
db 30h
db 0DCh
db 4Fh
db 92h
db 0DFh
db 62h
db 25h
db 32h
db 0EAh
db 67h
db 0ABh
db 7
db 97h
db 46h
db 98h
db 0B7h
db 82h
db 54h
db 0D1h
db 3Fh
db 53h
db 0F0h
db 6Bh
db 0A3h
db 28h
db 0ACh
db 5Fh
db 0FDh
db 0B8h
db 12h
db 0E2h
db 46h
db 0F7h
db 0CAh
db 80h
db 68h
db 0F2h
db 0EBh
db 0A4h
db 11h
db 46h
db 0E2h
db 0ECh
db 98h
db 65h
db 0A9h
db 3Ah
db 30h
db 0F2h
db 0B3h
db 4Fh
db 6Dh
db 7Bh
db 0B4h
db 0E9h
db 0C1h
db 0DCh
db 12h
db 0F6h
db 5Ch
db 86h
db 85h
db 7Eh
db 0D2h
db 0B1h
db 23h
db 24h
db 0F3h
db 73h
db 61h
db 6Eh
db 0EDh
db 0C5h
db 55h
db 54h
db 0BEh
db 45h
db 5Ah
db 0FFh
db 99h
db 6Dh
db 12h
db 0DAh
db 0C9h
db 0F0h
db 0F3h
db 0C0h
db 0DAh
db 3Eh
db 0D9h
db 42h
db 0BFh
db 8Bh
db 97h
db 0B7h
db 1Ch
db 16h
db 0D0h
db 0EBh
db 3Fh
db 0Dh
db 38h
db 4Ch
db 0DFh
db 63h
db 2Bh
db 0BBh
db 7Bh
db 63h
db 16h
db 0D5h
db 0B5h
db 1Ch
db 0D3h
db 29h
db 0CBh
db 0A3h
db 93h
db 0Fh
db 36h
db 91h
db 36h
db 0F3h
db 5Ah
db 0A9h
db 13h
db 0E5h
db 31h
db 93h
db 5Fh
db 3Bh
db 6Dh
db 19h
db 46h
db 56h
db 0BDh
db 52h
db 19h
db 73h
db 18h
db 6
db 0FFh
db 9
db 5
db 0E5h
db 93h
db 80h
db 17h
db 0FFh
db 0FEh
db 7Eh
db 7Dh
db 0B7h
db 32h
db 7Ch
db 70h
db 17h
db 3Bh
db 7
db 0D4h
db 0AEh
db 0C2h
db 7Ah
db 49h
db 2Dh
db 40h
db 0EAh
db 0FDh
db 71h
db 52h
db 0A6h
db 2Ch
db 0F7h
db 99h
db 0F5h
db 1Ah
db 0F7h
db 51h
db 51h
db 39h
db 59h
db 77h
db 8Ch
db 4
db 87h
db 58h
db 0Dh
db 28h
db 0F5h
db 0E8h
db 58h
db 66h
db 0EDh
db 0A7h
db 0B4h
db 0E9h
db 2Fh
db 0D3h
db 77h
db 2Ah
db 0ADh
db 0D6h
db 8Eh
db 0ADh
db 2Bh
db 0CBh
db 0C1h
db 38h
db 0A1h
db 1Fh
db 62h
db 6Fh
db 0F0h
db 8Eh
db 0A5h
db 36h
db 45h
db 9Bh
db 0A4h
db 0CCh
db 0F9h
db 45h
db 6Bh
db 0FAh
db 1Dh
db 34h
db 71h
db 55h
db 0DCh
db 6Bh
db 0F6h
db 0E4h
db 0FBh
db 7Dh
db 0D1h
db 0E5h
db 4Bh
db 6Ah
db 3
db 93h
db 30h
db 0C6h
db 8
db 4Ah
db 89h
db 42h
db 12h
db 5Bh
db 0BDh
db 0A4h
db 10h
db 59h
db 1Fh
db 0C0h
db 2Eh
db 57h
db 73h
db 0FAh
db 34h
db 71h
db 63h
db 40h
db 72h
db 8
db 8Eh
db 6Bh
db 0AFh
db 55h
db 8Fh
db 0E6h
db 0DAh
db 97h
db 0D2h
db 57h
db 20h
db 7Dh
db 0F0h
db 74h
db 0A9h
db 3Fh
db 0F9h
db 2Eh
db 94h
db 82h
db 34h
db 63h
db 0EAh
db 0E8h
db 91h
db 6Bh
db 2Fh
db 0DFh
db 56h
db 5Ch
db 94h
db 65h
db 4Ch
db 0E5h
db 0FAh
db 2Dh
db 22h
db 97h
db 1Dh
db 0EEh
db 0B4h
db 0A2h
db 0C7h
db 61h
db 3Bh
db 0EDh
db 0AAh
db 90h
db 0BEh
db 7Ah
db 92h
db 0FEh
db 13h
db 9Ah
db 0BEh
db 14h
db 0F2h
db 13h
db 33h
db 63h
db 0DFh
db 93h
db 1Ah
db 0D6h
db 9Ah
db 0B0h
db 51h
db 0B7h
db 26h
db 0FCh
db 0EAh
db 21h
db 9
db 3Ah
db 0D1h
db 10h
db 0
db 0A4h
db 0C2h
db 56h
db 53h
db 0DAh
db 66h
db 14h
db 2Ah
db 0C4h
db 62h
db 19h
db 1Eh
db 96h
db 4Eh
db 0AAh
db 74h
db 58h
db 0F7h
db 0ADh
db 0A7h
db 31h
db 21h
db 16h
db 0F7h
db 0A9h
db 5Bh
db 0FFh
db 75h
db 42h
db 77h
db 27h
db 83h
db 0ACh
db 32h
db 0D3h
db 22h
db 7Fh
db 27h
db 0D4h
db 0E9h
db 80h
db 0B9h
db 66h
db 6
db 0CEh
db 0AAh
db 91h
db 46h
db 0CBh
db 41h
db 17h
db 0C8h
db 13h
db 37h
db 15h
db 0B0h
db 40h
db 46h
db 9Eh
db 45h
db 41h
db 0B1h
db 71h
db 43h
db 6Dh
db 0A9h
db 0Bh
db 23h
db 6Ch
db 0B8h
db 3Ch
db 0A3h
db 96h
db 0E0h
db 0C9h
db 0DAh
db 1Ah
db 0A5h
db 34h
db 0D2h
db 0D4h
db 95h
db 85h
db 13h
db 87h
db 0
db 0Fh
db 15h
db 33h
db 28h
db 7Dh
db 71h
db 87h
db 1Ch
db 55h
db 0D6h
db 66h
db 0ACh
db 1
db 0D4h
db 0D9h
db 9Eh
db 0FAh
db 0CDh
db 73h
db 1Ch
db 26h
db 0DFh
db 82h
db 0E0h
db 98h
db 8Dh
db 0E1h
db 6Ch
db 80h
db 9Fh
db 3Dh
db 41h
db 58h
db 23h
db 68h
db 68h
db 1Bh
db 59h
db 93h
db 96h
db 14h
db 0CBh
db 0D3h
db 69h
db 8Ch
db 2Fh
db 98h
db 57h
db 0EBh
db 98h
db 0FDh
db 0C5h
db 0FBh
db 0F0h
db 70h
db 98h
db 0DFh
db 0Eh
db 0FEh
db 9Dh
db 5Ch
db 83h
db 0F6h
db 41h
db 98h
db 0B0h
db 0CEh
db 8
db 14h
db 88h
db 7Dh
db 0E6h
db 7Bh
db 7Fh
db 2Bh
db 15h
db 8Ch
db 0C0h
db 0
db 4Dh
db 4Bh
db 0Bh
db 0C5h
db 2Bh
db 0B7h
db 0B5h
db 0CDh
db 55h
db 0C3h
db 24h
db 2Bh
db 0F1h
db 0FEh
db 30h
db 52h
db 0B8h
db 0D1h
db 9Bh
db 56h
db 0Bh
db 61h
db 0A3h
db 8Bh
db 0DFh
db 0EAh
db 1Bh
db 18h
db 36h
db 0EBh
db 0F6h
db 3Fh
db 16h
db 5Eh
db 53h
db 52h
db 52h
db 93h
db 0C4h
db 4Bh
db 30h
db 0
db 4Bh
db 45h
db 0Fh
db 8Bh
db 29h
db 45h
db 0Ch
db 0EEh
db 76h
db 35h
db 93h
db 0FDh
db 0F0h
db 1Ch
db 82h
db 0C2h
db 0Eh
db 0F9h
db 0FCh
db 4Ch
db 78h
db 0ECh
db 62h
db 82h
db 0D7h
db 0BBh
db 79h
db 0D1h
db 0E4h
db 11h
db 7
db 0B0h
db 97h
db 0A0h
db 2
db 0C5h
db 66h
db 4Bh
db 76h
db 0D6h
db 46h
db 99h
db 0BAh
db 75h
db 0ACh
db 6Ah
db 0C6h
db 37h
db 25h
db 16h
db 0C1h
db 0BAh
db 0A9h
db 0E4h
db 7Eh
db 16h
db 0D5h
db 86h
db 24h
db 1Ah
db 0FDh
db 58h
db 0CCh
db 0B0h
db 72h
db 25h
db 0D6h
db 0ACh
db 0BDh
db 0FEh
db 0E1h
db 0FDh
db 5Ah
db 0C2h
db 7Bh
db 0E4h
db 6Dh
db 0EFh
db 0D5h
db 0A1h
db 9Ah
db 0DFh
db 0FBh
db 1Fh
db 59h
db 6
db 2Eh
db 0D9h
db 28h
db 0D9h
db 0EFh
db 52h
db 0C9h
db 0F5h
db 0AAh
db 69h
db 12h
db 27h
db 0BDh
db 78h
db 0B5h
db 0Eh
db 17h
db 8Ch
db 7Dh
db 23h
db 0B0h
db 0ABh
db 19h
db 55h
db 3Bh
db 25h
db 45h
db 2Fh
db 8Ch
db 1Dh
db 29h
db 0BEh
db 6Fh
db 0BDh
db 9Ah
db 2Eh
db 12h
db 0F7h
db 0C1h
db 69h
db 34h
db 24h
db 0D2h
db 0B1h
db 5Ah
db 6Eh
db 60h
db 77h
db 2Ah
db 0FDh
db 96h
db 0A2h
db 2Fh
db 4Dh
db 0DBh
db 0B4h
db 0E3h
db 95h
db 27h
db 92h
db 0AEh
db 0D3h
db 5Eh
db 55h
db 46h
db 8Bh
db 0A6h
db 0CCh
db 4Fh
db 3Eh
db 4Dh
db 5Ch
db 0C6h
db 29h
db 8Dh
db 22h
db 45h
db 0Fh
db 2Ch
db 8Fh
db 54h
db 1
db 10h
db 0A2h
db 28h
db 38h
db 0F9h
db 8
db 4Dh
db 83h
db 2Bh
db 9Ch
db 17h
db 0FDh
db 0B6h
db 92h
db 97h
db 0EAh
db 6Bh
db 8
db 99h
db 0FBh
db 7Ah
db 94h
db 0
db 0AFh
db 5Ah
db 21h
db 90h
db 0BBh
db 0A5h
db 0A2h
db 0B0h
db 5Dh
db 0EAh
db 0A1h
db 2
db 0AAh
db 8Eh
db 70h
db 87h
db 97h
db 0DDh
db 8Ch
db 7Bh
db 54h
db 8Eh
db 0FFh
db 66h
db 58h
db 0D3h
db 0B7h
db 0A2h
db 0B6h
db 0D6h
db 2
db 0C6h
db 13h
db 0BBh
db 69h
db 28h
db 86h
db 0DEh
db 66h
db 2Ch
db 44h
db 0E4h
db 0
db 0DFh
db 22h
db 8
db 6
db 6
db 0AEh
db 3Ah
db 0B0h
db 2Fh
db 78h
db 56h
db 3Dh
db 7Ah
db 0ADh
db 0B9h
db 0F3h
db 0BCh
db 0F8h
db 8
db 57h
db 74h
db 0Eh
db 0BDh
db 92h
db 42h
db 0E3h
db 0C1h
db 84h
db 0ECh
db 41h
db 29h
db 14h
db 8Ah
db 0F3h
db 0B2h
db 26h
db 0BAh
db 20h
db 8Eh
db 0F0h
db 7Bh
db 54h
db 26h
db 0CDh
db 11h
db 5
db 33h
db 0E1h
db 2Fh
db 0B0h
db 31h
db 61h
db 71h
db 5Eh
db 2Dh
db 4
db 0DDh
db 0F7h
db 0C9h
db 49h
db 0D1h
db 0ADh
db 0ECh
db 0DAh
db 4Eh
db 0A9h
db 97h
db 0ECh
db 5Bh
db 90h
db 0F2h
db 0A9h
db 0FBh
db 0BFh
db 69h
db 76h
db 0A4h
db 95h
db 96h
db 74h
db 0F0h
db 2Dh
db 6Fh
db 0E0h
db 0DBh
db 29h
db 77h
db 97h
db 1Eh
db 4Fh
db 25h
db 58h
db 39h
db 0Dh
db 0FCh
db 0AFh
db 1Dh
db 0F6h
db 71h
db 1Dh
db 0D5h
db 0BCh
db 24h
db 1Bh
db 64h
db 0CFh
db 0DAh
db 51h
db 80h
db 15h
db 60h
db 44h
db 0AAh
db 0Ch
db 4Fh
db 9Ch
db 0CEh
db 2Bh
db 0FDh
db 2Eh
db 44h
db 47h
db 4
db 53h
db 33h
db 50h
db 70h
db 45h
db 0C7h
db 0A3h
db 0F4h
db 90h
db 56h
db 0E5h
db 56h
db 0BCh
db 0B7h
db 7Bh
db 0F2h
db 47h
db 0Ch
db 2Ah
db 26h
db 3Bh
db 37h
db 0A2h
db 0BEh
db 4Ch
db 0B8h
db 1Ah
db 0B8h
db 5Fh
db 5
db 26h
db 0CDh
db 7Ah
db 75h
db 95h
db 0B9h
db 84h
db 4Fh
db 1Bh
db 31h
db 92h
db 79h
db 34h
db 0C8h
db 94h
db 7
db 0ADh
db 48h
db 0C6h
db 8Bh
db 54h
db 0C1h
db 0F8h
db 0BBh
db 4Dh
db 0E3h
db 29h
db 5Eh
db 57h
db 0EDh
db 1Eh
db 3Fh
db 55h
db 4
db 7Fh
db 6Bh
db 3Dh
db 34h
db 1
db 0CBh
db 0C4h
db 80h
db 0C4h
db 83h
db 49h
db 0D5h
db 0BFh
db 0F5h
db 67h
db 8Eh
db 53h
db 63h
db 3Dh
db 81h
db 0C9h
db 8
db 2Eh
db 6
db 0A3h
db 99h
db 93h
db 4Eh
db 6Ch
db 0B3h
db 0DFh
db 10h
db 0EDh
db 0A7h
db 47h
db 2Ah
db 0B1h
db 0A6h
db 0DEh
db 3Ch
db 2Bh
db 5
db 43h
db 1Ch
db 3
db 2Ch
db 0B3h
db 27h
db 5Dh
db 0DEh
db 53h
db 0F3h
db 0CAh
db 6Ah
db 0DCh
db 0C4h
db 33h
db 0A4h
db 59h
db 6Bh
db 72h
db 11h
db 8Eh
db 0DBh
db 8Eh
db 0Eh
db 7Bh
db 8Bh
db 0FBh
db 34h
db 13h
db 3Dh
db 0F2h
db 57h
db 9Ch
db 79h
db 67h
db 6Ah
db 0FCh
db 5Fh
db 7Ch
db 60h
db 0F9h
db 0B7h
db 0
db 26h
db 0BEh
db 0A4h
db 0E8h
db 9Eh
db 93h
db 8Fh
db 0A6h
db 30h
db 0CEh
db 0B5h
db 97h
db 95h
db 9Dh
db 15h
db 21h
db 0Eh
db 15h
db 8Bh
db 9Eh
db 6Bh
db 3Fh
db 0E1h
db 26h
db 1Eh
db 71h
db 7Bh
db 18h
db 6Fh
db 84h
db 3Eh
db 0EEh
db 0Fh
db 7Ah
db 63h
db 4Ah
db 5
db 0C8h
db 1Eh
db 2Bh
db 4Ch
db 0FEh
db 4Ah
db 67h
db 65h
db 0C1h
db 0D3h
db 3Bh
db 0F5h
db 0B7h
db 2Dh
db 17h
db 0DCh
db 0F0h
db 89h
db 42h
db 90h
db 9Dh
db 0F7h
db 16h
db 94h
db 0DCh
db 72h
db 17h
db 91h
db 3
db 76h
db 0ECh
db 0AFh
db 7Fh
db 0BBh
db 0E3h
db 0A7h
db 2Bh
db 11h
db 21h
db 47h
db 3Fh
db 0EBh
db 0A1h
db 0D5h
db 93h
db 0B8h
db 4Eh
db 0CAh
db 0F6h
db 41h
db 0ADh
db 82h
db 14h
db 8Eh
db 3Bh
db 0B6h
db 8Ch
db 5Fh
db 4Eh
db 42h
db 0E1h
db 41h
db 0A1h
db 1Dh
db 20h
db 1
db 33h
db 0A6h
db 8Dh
db 14h
db 0E6h
db 3Fh
db 0F6h
db 4Ah
db 0F3h
db 41h
db 9Ah
db 28h
db 0D1h
db 5Eh
db 0DCh
db 24h
db 0F9h
db 7Ah
db 0BCh
db 33h
db 66h
db 0D5h
db 0Ah
db 0Bh
db 0E9h
db 16h
db 0ABh
db 0B4h
db 0FBh
db 40h
db 0EDh
db 85h
db 58h
db 81h
db 1Dh
db 0C6h
db 68h
db 1Dh
db 52h
db 0C3h
db 0E0h
db 0B0h
db 0E3h
db 0Ch
db 84h
db 83h
db 0DDh
db 30h
db 79h
db 19h
db 0AEh
db 0Ah
db 4Bh
db 90h
db 4Ah
db 1Bh
db 0DDh
db 9Eh
db 4Ch
db 73h
db 0FDh
db 42h
db 0EBh
db 59h
db 9Eh
db 40h
db 0C4h
db 0ABh
db 29h
db 0C3h
db 0E5h
db 16h
db 3Ch
db 0DCh
db 28h
db 3Ch
db 0B8h
db 0CAh
db 0F8h
db 36h
db 0E8h
db 3Dh
db 98h
db 5Bh
db 32h
db 58h
db 93h
db 16h
db 23h
db 53h
db 94h
db 0B9h
db 2Ah
db 2Dh
db 95h
db 70h
db 92h
db 37h
db 0AAh
db 75h
db 0A5h
db 0DFh
db 0E0h
db 60h
db 31h
db 74h
db 21h
db 83h
db 41h
db 0C8h
db 0DEh
db 0C2h
db 0DAh
db 89h
db 0DCh
db 9Dh
db 7Fh
db 0AAh
db 41h
db 75h
db 3Ch
db 0A8h
db 67h
db 47h
db 70h
db 4Fh
db 0D7h
db 0F4h
db 76h
db 71h
db 8Ch
db 2Ah
db 51h
db 5Ah
db 74h
db 0F5h
db 22h
db 17h
db 45h
db 90h
db 0A7h
db 0C8h
db 0CBh
db 0EBh
db 19h
db 45h
db 6Fh
db 0E3h
db 21h
db 19h
db 0B4h
db 47h
db 0DAh
db 39h
db 81h
db 6Fh
db 3
db 1Bh
db 0E4h
db 0BEh
db 0BEh
db 76h
db 96h
db 8Bh
db 0B3h
db 7Dh
db 70h
db 9Bh
db 0DFh
db 38h
db 1Fh
db 0C6h
db 0F1h
db 6Bh
db 0C9h
db 2Fh
db 0A6h
db 0A3h
db 0E6h
db 60h
db 4Ch
db 81h
db 0
db 0A5h
db 0AEh
db 1Ch
db 88h
db 0A9h
db 8Bh
db 4Dh
db 0C5h
db 60h
db 71h
db 0E1h
db 0C3h
db 13h
db 2Bh
db 75h
db 59h
db 25h
db 40h
db 98h
db 9Dh
db 0EAh
db 0EAh
db 0E1h
db 0E2h
db 54h
db 99h
db 7Fh
db 0DAh
db 0FDh
db 0B0h
db 0BFh
db 38h
db 78h
db 75h
db 0F1h
db 0CBh
db 0B9h
db 0F3h
db 2Ah
db 97h
db 59h
db 0B1h
db 0C8h
db 6Eh
db 3
db 23h
db 5Ah
db 78h
db 0DCh
db 51h
db 39h
db 99h
db 9
db 7Ch
db 9Ah
db 0E9h
db 2Fh
db 0EAh
db 5Bh
db 0FDh
db 68h
db 8Bh
db 0CEh
db 0
db 32h
db 0A7h
db 99h
db 0DDh
db 0EAh
db 2Ch
db 5Ch
db 87h
db 88h
db 83h
db 90h
db 43h
db 98h
db 7Ah
db 7Ch
db 0DFh
db 0A0h
db 0E9h
db 41h
db 0F4h
db 7
db 0FBh
db 0C1h
db 0ABh
db 10h
db 7Ch
db 87h
db 0CCh
db 5Ah
db 25h
db 0EBh
db 72h
db 0D7h
db 79h
db 0A3h
db 72h
db 0FBh
db 99h
db 2Fh
db 8Bh
db 0E0h
db 1
db 0F0h
db 43h
db 5
db 4
db 13h
db 0C1h
db 0E4h
db 59h
db 92h
db 0ADh
db 97h
db 0Fh
db 8Bh
db 32h
db 96h
db 80h
db 17h
db 0EAh
db 93h
db 6Ah
db 0FDh
db 0B3h
db 0C6h
db 0B3h
db 0Dh
db 1Fh
db 0C3h
db 0E7h
db 0ADh
db 0FAh
db 74h
db 4Eh
db 0C8h
db 3Eh
db 6
db 43h
db 58h
db 8Ch
db 0F9h
db 38h
db 0D3h
db 0Fh
db 69h
db 48h
db 0B9h
db 66h
db 6
db 0BDh
db 6Dh
db 1Ah
db 15h
db 2Bh
db 3Eh
db 23h
db 29h
db 0C0h
db 48h
db 2Bh
db 0C4h
db 0Ah
db 0E3h
db 0C7h
db 26h
db 7Ah
db 2Fh
db 41h
db 0EBh
db 8Eh
db 82h
db 0C8h
db 0D8h
db 0DDh
db 0C6h
db 47h
db 24h
db 0Fh
db 0Fh
db 83h
db 51h
db 27h
db 0Dh
db 29h
db 0F1h
db 81h
db 0CFh
db 5
db 1Bh
db 97h
db 0D3h
db 32h
db 6Dh
db 3Bh
db 5Bh
db 80h
db 3Dh
db 0C7h
db 0
db 56h
db 56h
db 12h
db 14h
db 63h
db 0C5h
db 0C4h
db 57h
db 0D9h
db 0F9h
db 0C0h
db 0A4h
db 17h
db 6Bh
db 0FBh
db 23h
db 0B9h
db 52h
db 0B5h
db 0A5h
db 1Bh
db 6Ch
db 0B0h
db 6Fh
db 0FAh
db 6Eh
db 0EEh
db 0FEh
db 0B5h
db 0E9h
db 2Ah
db 6Eh
db 49h
db 0EEh
db 4Eh
db 5Eh
db 4Dh
db 0B5h
db 12h
db 9Eh
db 0B9h
db 45h
db 0F2h
db 4Ch
db 0F0h
db 0A3h
db 0B3h
db 25h
db 4
db 0E9h
db 0EEh
db 0F0h
db 0FEh
db 39h
db 0A3h
db 0Dh
db 3Eh
db 0C2h
db 5Fh
db 84h
db 0B9h
db 35h
db 0E2h
db 85h
db 0B3h
db 0D3h
db 7
db 93h
db 0ABh
db 0B1h
db 4Bh
db 8Ch
db 58h
db 0B3h
db 0AEh
db 0CEh
db 69h
db 0C8h
db 8Ch
db 24h
db 8
db 20h
db 0F1h
db 7Eh
db 68h
db 23h
db 8Fh
db 1Ch
db 5Ch
db 0D0h
db 8Eh
db 43h
db 4Ch
db 54h
db 65h
db 27h
db 5Ah
db 68h
db 0Bh
db 2Bh
db 4Ah
db 33h
db 0ACh
db 88h
db 2Eh
db 0BDh
db 10h
db 8Fh
db 0A3h
db 0FEh
db 0C3h
db 0ADh
db 27h
db 0EAh
db 63h
db 1Ch
db 11h
db 78h
db 2
db 0Fh
db 0DDh
db 81h
db 0A7h
db 0Fh
db 29h
db 8Fh
db 5Fh
db 0B8h
db 10h
db 94h
db 0FDh
db 28h
db 0E3h
db 21h
db 40h
db 0BCh
db 24h
db 7Bh
db 55h
db 6Bh
db 3Dh
db 0ADh
db 0A6h
db 0F4h
db 0Bh
db 5Bh
db 7
db 0FEh
db 0BAh
db 0CDh
db 0AFh
db 63h
db 0A4h
db 3Eh
db 0Ch
db 0C3h
db 0DFh
db 0D6h
db 5Ch
db 7Ah
db 0D1h
db 33h
db 0BFh
db 0E6h
db 0BEh
db 0ADh
db 0CCh
db 30h
db 0D0h
db 89h
db 0D7h
db 89h
db 0B8h
db 0CDh
db 70h
db 9Eh
db 0E7h
db 59h
db 99h
db 0E0h
db 85h
db 0D8h
db 75h
db 5Ch
db 8
db 99h
db 46h
db 8Eh
db 46h
db 15h
db 3Dh
db 0ABh
db 28h
db 0Bh
db 0DAh
db 0A9h
db 0E8h
db 54h
db 9Bh
db 46h
db 0C5h
db 6Dh
db 8Dh
db 0DDh
db 0EEh
db 0A7h
db 0F6h
db 62h
db 56h
db 79h
db 0BCh
db 0CFh
db 0B7h
db 0DAh
db 3Bh
db 19h
db 14h
db 0B0h
db 86h
db 68h
db 0BAh
db 99h
db 0ACh
db 4Ah
db 81h
db 0
db 54h
db 21h
db 88h
db 16h
db 6Ah
db 5Ah
db 70h
db 0FCh
db 22h
db 0E6h
db 7
db 0C0h
db 0A0h
db 36h
db 62h
db 0A7h
db 0C0h
db 98h
db 8Dh
db 0B1h
db 0EEh
db 88h
db 7Ah
db 42h
db 64h
db 0FCh
db 94h
db 0DBh
db 0D2h
db 44h
db 0D3h
db 91h
db 0Eh
db 0D3h
db 92h
db 0E5h
db 0CBh
db 7Ah
db 0DFh
db 0B6h
db 0F0h
db 18h
db 8Bh
db 0F9h
db 56h
db 75h
db 0Ah
db 0A1h
db 0E6h
db 5Ch
db 2Fh
db 40h
db 63h
db 10h
db 0CAh
db 0D6h
db 3Bh
db 0ABh
db 0FDh
db 0B5h
db 0ABh
db 0BFh
db 0CEh
db 0E2h
db 15h
db 9Ah
db 0BBh
db 57h
db 48h
db 0D8h
db 0ABh
db 0B2h
db 38h
db 0E6h
db 34h
db 9Dh
db 26h
db 0C2h
db 0C9h
db 7Bh
db 46h
db 0E1h
db 74h
db 70h
db 8
db 0A6h
db 57h
db 0E3h
db 72h
db 87h
db 0BCh
db 82h
db 0DAh
db 5Dh
db 9Ah
db 0A9h
db 0C8h
db 0CEh
db 50h
db 2Fh
db 0ADh
db 0C4h
db 90h
db 7Fh
db 8Ah
db 3Dh
db 46h
db 93h
db 0BEh
db 0BEh
db 22h
db 32h
db 7Dh
db 48h
db 8
db 0E7h
db 59h
db 0B2h
db 0D3h
db 0C8h
db 2
db 85h
db 0C2h
db 0DFh
db 39h
db 18h
db 4Eh
db 59h
db 7Ah
db 65h
db 73h
db 8Ah
db 3Ah
db 0D4h
db 0ACh
db 3
db 98h
db 59h
db 2Eh
db 65h
db 99h
db 0D4h
db 0Ah
db 7Bh
db 81h
db 0BFh
db 72h
db 24h
db 6Ch
db 2Dh
db 0F7h
db 31h
db 0D8h
db 0F4h
db 4Dh
db 61h
db 74h
db 59h
db 38h
db 0DAh
db 67h
db 0D3h
db 0B7h
db 0F0h
db 0B0h
db 21h
db 0D5h
db 0CEh
db 0ECh
db 70h
db 3Eh
db 0CFh
db 32h
db 45h
db 18h
db 5Ch
db 15h
db 0FDh
db 0CDh
db 91h
db 3Dh
db 0C8h
db 65h
db 0AFh
db 0C8h
db 1Ah
db 0CBh
db 0AEh
db 8Eh
db 69h
db 7
db 36h
db 0D0h
db 60h
db 23h
db 0FAh
db 65h
db 4Ch
db 4Dh
db 8Eh
db 1Fh
db 0EEh
db 17h
db 78h
db 55h
db 36h
db 77h
db 81h
db 0F2h
db 0F7h
db 5Eh
db 33h
db 9Eh
db 97h
db 0E9h
db 0C3h
db 0B3h
db 6Eh
db 0E2h
db 69h
db 95h
db 0DEh
db 0A1h
db 0Ah
db 0B3h
db 11h
db 0BCh
db 0D6h
db 11h
db 0Eh
db 65h
db 84h
db 33h
db 2Fh
db 0BDh
db 30h
db 70h
db 3Ah
db 13h
db 0B3h
db 0D9h
db 0DAh
db 0DBh
db 8Fh
db 0EDh
db 78h
db 30h
db 0F1h
db 0C9h
db 14h
db 65h
db 71h
db 37h
db 39h
db 0FAh
db 0D0h
db 0F5h
db 9Bh
db 6Fh
db 0A0h
db 1Bh
db 2Fh
db 20h
db 0Fh
db 71h
db 31h
db 78h
db 36h
db 20h
db 78h
db 0A4h
db 0A6h
db 0EBh
db 0C6h
db 0F8h
db 1
db 0B9h
db 0DCh
db 55h
db 9
db 2Bh
db 0ADh
db 0C6h
db 8
db 0B0h
db 0E3h
db 3Bh
db 66h
db 0BAh
db 81h
db 7Ch
db 0E6h
db 43h
db 9Bh
db 1Fh
db 89h
db 0CDh
db 96h
db 92h
db 14h
db 0F2h
db 0BCh
db 0D7h
db 3Dh
db 8Eh
db 0C1h
db 99h
db 45h
db 0F2h
db 0EAh
db 3Dh
db 0C6h
db 63h
db 0EAh
db 8Ch
db 0D9h
db 0C1h
db 94h
db 7Bh
db 4Dh
db 0F9h
db 72h
db 55h
db 67h
db 13h
db 72h
db 79h
db 12h
db 8Fh
db 0A1h
db 0B1h
db 0BAh
db 22h
db 0C5h
db 0D4h
db 0F9h
db 20h
db 38h
db 0C3h
db 7Bh
db 9Fh
db 73h
db 9Ch
db 0B5h
db 95h
db 0FFh
db 0Ch
db 0AEh
db 0CCh
db 67h
db 0ADh
db 57h
db 0FDh
db 0Eh
db 0B9h
db 51h
db 36h
db 4Fh
db 0CAh
db 66h
db 0F2h
db 0F5h
db 0D8h
db 0E3h
db 8Fh
db 3
db 4Eh
db 1Bh
db 78h
db 0CDh
db 0E9h
db 0E7h
db 2
db 0DFh
db 31h
db 0CBh
db 0DAh
db 0Ah
db 7Ah
db 0Dh
db 93h
db 14h
db 14h
db 34h
db 46h
db 0E0h
db 0Dh
db 0CCh
db 3Eh
db 32h
db 0ABh
db 93h
db 6Ch
db 19h
db 0F0h
db 0BDh
db 2
db 0F2h
db 6Ah
db 3
db 0FEh
db 95h
db 0D1h
db 23h
db 0F9h
db 34h
db 42h
db 9Ah
db 1
db 4Dh
db 42h
db 58h
db 0D3h
db 0E2h
db 0C2h
db 58h
db 0D9h
db 0CEh
db 74h
db 84h
db 0C2h
db 25h
db 72h
db 0E9h
db 7Dh
db 0C8h
db 97h
db 0
db 86h
db 78h
db 42h
db 26h
db 0CAh
db 65h
db 0Ch
db 5Ah
db 0FDh
db 0EEh
db 0E3h
db 34h
db 52h
db 0A5h
db 0A5h
db 20h
db 54h
db 0E5h
db 18h
db 1Fh
db 0EFh
db 0C0h
db 0AEh
db 18h
db 1Dh
db 95h
db 7Bh
db 13h
db 7Dh
db 31h
db 0E2h
db 57h
db 0D2h
db 96h
db 89h
db 0F8h
db 0B4h
db 38h
db 83h
db 0B2h
db 16h
db 0C1h
db 1Ch
db 0DBh
db 0D1h
db 6Bh
db 42h
db 7Ch
db 9Fh
db 0AFh
db 9Eh
db 82h
db 0ACh
db 3Ch
db 2Ah
db 0Ah
db 0BBh
db 0CCh
db 54h
db 0F9h
db 52h
db 56h
db 6Ch
db 0A5h
db 16h
db 0BCh
db 0C8h
db 4
db 26h
db 0C4h
db 89h
db 0BEh
db 0E5h
db 0EEh
db 8Fh
db 0Ch
db 93h
db 5Ch
db 0BEh
db 1Ch
db 0E8h
db 80h
db 0CEh
db 10h
db 0DBh
db 0BCh
db 0FBh
db 1Bh
db 4Bh
db 11h
db 0F3h
db 85h
db 5Ch
db 6
db 0C1h
db 0Bh
db 65h
db 42h
db 94h
db 1
db 0CEh
db 0AFh
db 68h
db 1Eh
db 3
db 0BFh
db 6Dh
db 2Ch
db 0D2h
db 50h
db 7
db 0D4h
db 0B0h
db 0F1h
db 0ABh
db 63h
db 8Ch
db 0A9h
db 73h
db 0C4h
db 31h
db 89h
db 65h
db 2Ch
db 92h
db 0E3h
db 7Ah
db 36h
db 0A6h
db 97h
db 3Ch
db 0D4h
db 46h
db 3Fh
db 59h
db 0F1h
db 42h
db 4Bh
db 34h
db 65h
db 17h
db 13h
db 0ABh
db 0CFh
db 0BFh
db 1Ah
db 0C7h
db 0B1h
db 0E6h
db 76h
db 15h
db 34h
db 8Bh
db 0B7h
db 57h
db 0CAh
db 0A3h
db 51h
db 91h
db 82h
db 3Bh
db 17h
db 0Dh
db 37h
db 1Ch
db 0B0h
db 4Ch
db 90h
db 80h
db 27h
db 22h
db 0FFh
db 7Ah
db 49h
db 3Ah
db 5Dh
db 4
db 0A3h
db 0C5h
db 28h
db 1Ah
db 0A8h
db 4Eh
db 2Dh
db 0D5h
db 0Fh
db 6Fh
db 0BEh
db 9Bh
db 9Ch
db 0BFh
db 0ACh
db 0E4h
db 2Eh
db 0Eh
db 6Dh
db 0EFh
db 8Ah
db 0BFh
db 0A7h
db 0D9h
db 0B0h
db 91h
db 2Eh
db 62h
db 86h
db 0D0h
db 0AAh
db 27h
db 62h
db 94h
db 5Ch
db 0EEh
db 0Ah
db 0B2h
db 0B4h
db 61h
db 0E1h
db 95h
db 21h
db 0E3h
db 65h
db 3
db 0D0h
db 82h
db 9Dh
db 0B5h
db 0FAh
db 90h
db 75h
db 20h
db 70h
db 0DCh
db 8
db 8
db 0E6h
db 3Eh
db 69h
db 0CEh
db 9Bh
db 7Ch
db 0D0h
db 0D4h
db 7Fh
db 9Dh
db 0B9h
db 0ECh
db 19h
db 0FBh
db 0A4h
db 0E6h
db 7Ah
db 80h
db 35h
db 0EAh
db 68h
db 1Ah
db 9Ch
db 5Dh
db 8
db 39h
db 4Dh
db 3Eh
db 7Ch
db 2Ah
db 19h
db 8
db 0E4h
db 70h
db 39h
db 4Ah
db 71h
db 5Dh
db 20h
db 21h
db 0Ah
db 0F4h
db 1Ah
db 94h
db 0B9h
db 1Eh
db 8Dh
db 6Dh
db 6Dh
db 71h
db 98h
db 38h
db 63h
db 0DEh
db 76h
db 17h
db 95h
db 67h
db 0F7h
db 0A7h
db 7
db 0CAh
db 0F0h
db 5Dh
db 7Dh
db 98h
db 3Fh
db 10h
db 1Bh
db 6Fh
db 20h
db 0EFh
db 3
db 5Dh
db 27h
db 0C2h
db 0BDh
db 86h
db 0C2h
db 0C4h
db 0B4h
db 34h
db 0FFh
db 0D0h
db 0DBh
db 50h
db 0A9h
db 2Ah
db 1Fh
db 41h
db 1Eh
db 60h
db 96h
db 37h
db 0B2h
db 0FDh
db 2Ch
db 0EDh
db 9Fh
db 0B7h
db 0E0h
db 0FEh
db 4Eh
db 96h
db 2Fh
db 0D7h
db 0DDh
db 0B4h
db 39h
db 0DFh
db 0BAh
db 0BCh
db 7Bh
db 7Ch
db 0D1h
db 2Bh
db 0F0h
db 61h
db 0
db 0DCh
db 0E3h
db 0Dh
db 0A8h
db 4Dh
db 38h
db 0E3h
db 0B0h
db 0C0h
db 0BBh
db 9Fh
db 27h
db 0B4h
db 4Fh
db 74h
db 6Ch
db 78h
db 64h
db 61h
db 0F1h
db 0A9h
db 0CDh
db 6Ah
db 50h
db 4Dh
db 8Ch
db 1Ah
db 0E9h
db 0C8h
db 5Ch
db 0Ah
db 27h
db 72h
db 9Dh
db 5Ah
db 0EAh
db 0DCh
db 11h
db 5Bh
db 1Ah
db 4Ch
db 18h
db 9Ah
db 74h
db 4Ch
db 0Fh
db 14h
db 47h
db 0A1h
db 0EFh
db 0E5h
db 2
db 15h
db 6Ah
db 0FFh
db 0A7h
db 0CFh
db 67h
db 94h
db 0D4h
db 43h
db 1Bh
db 9
db 0D2h
db 0CDh
db 0A0h
db 8Bh
db 0C1h
db 5
db 2
db 0ACh
db 0BBh
db 0A8h
db 20h
db 0DEh
db 8
db 0C2h
db 0C8h
db 0BBh
db 35h
db 0E7h
db 2
db 0D2h
db 8Bh
db 50h
db 67h
db 0BFh
db 0A0h
db 36h
db 93h
db 30h
db 0F2h
db 7Fh
db 5Ah
db 0D5h
db 0A8h
db 49h
db 0B0h
db 0EEh
db 12h
db 0A9h
db 7
db 9
db 2Ah
db 18h
db 9Ah
db 6Bh
db 61h
db 0A4h
db 6Fh
db 8Fh
db 1Fh
db 94h
db 0C8h
db 0EEh
db 6Bh
db 70h
db 2
db 42h
db 0F8h
db 39h
db 5Eh
db 0C4h
db 0F4h
db 9Ah
db 0C2h
db 66h
db 0FEh
db 9Fh
db 22h
db 1Dh
db 87h
db 4Fh
db 0A4h
db 9Eh
db 9Eh
db 0A7h
db 0F8h
db 0Bh
db 6Fh
db 3Eh
db 0C4h
db 64h
db 0FDh
db 0EAh
db 0AEh
db 6Ch
db 0E5h
db 0DCh
db 33h
db 0E2h
db 55h
db 1Ah
db 97h
db 87h
db 0EFh
db 23h
db 0F0h
db 60h
db 50h
db 0C9h
db 0F4h
db 0B7h
db 60h
db 34h
db 8Bh
db 8Ch
db 97h
db 59h
db 7Bh
db 79h
db 8Ch
db 0E3h
db 0B6h
db 0CFh
db 0C7h
db 0F3h
db 5Ah
db 16h
db 0F2h
db 9Eh
db 74h
db 0CBh
db 0F4h
db 7Fh
db 0FAh
db 0D9h
db 48h
db 1Ch
db 0D9h
db 74h
db 0ABh
db 3Bh
db 99h
db 0D7h
db 0DDh
db 1
db 96h
db 98h
db 4Fh
db 58h
db 47h
db 77h
db 0EBh
db 0A5h
db 0CBh
db 77h
db 0F2h
db 0AAh
db 5Dh
db 75h
db 74h
db 0C3h
db 0E5h
db 39h
db 75h
db 83h
db 0C9h
db 96h
db 88h
db 0FCh
db 12h
db 0Dh
db 0D9h
db 23h
db 0EDh
db 98h
db 2Eh
db 4Ah
db 0BBh
db 0F1h
db 0C8h
db 5Ch
db 0C5h
db 1
db 76h
db 57h
db 0A3h
db 0BDh
db 12h
db 1
db 3
db 0EDh
db 0B5h
db 0A2h
db 22h
db 0BBh
db 0A9h
db 9Bh
db 7Ah
db 0F4h
db 84h
db 9Fh
db 3Dh
db 58h
db 40h
db 74h
db 60h
db 94h
db 0E3h
db 37h
db 0B1h
db 27h
db 0C2h
db 0EEh
db 0Eh
db 20h
db 21h
db 0F1h
db 7Fh
db 0D5h
db 79h
db 1Fh
db 0CBh
db 0A3h
db 0BBh
db 0C0h
db 6Ah
db 0CDh
db 5Eh
db 0C3h
db 3Dh
db 0ECh
db 81h
db 7Eh
db 86h
db 0E5h
db 0FDh
db 64h
db 2Ch
db 9Ch
db 0E4h
db 0A3h
db 0BFh
db 8Eh
db 86h
db 2Bh
db 1Eh
db 0F7h
db 5Ch
db 65h
db 67h
db 0Bh
db 0A8h
db 0A9h
db 1Eh
db 0D9h
db 84h
db 0F4h
db 97h
db 0DDh
db 0AFh
db 13h
db 9Eh
db 6Eh
db 6
db 19h
db 62h
db 0CBh
db 0DCh
db 4Bh
db 0C7h
db 0B3h
db 6Eh
db 0C0h
db 0FAh
db 58h
db 8Eh
db 0B3h
db 62h
db 0C3h
db 52h
db 0F0h
db 2Bh
db 9Bh
db 0D7h
db 0E2h
db 0A8h
db 5Ch
db 86h
db 0DCh
db 50h
db 13h
db 9Fh
db 40h
db 4
db 26h
db 9Fh
db 13h
db 27h
db 0Ah
db 4Fh
db 36h
db 0B5h
db 0B1h
db 3Ah
db 0A9h
db 53h
db 26h
db 2Ch
db 0CCh
db 8
db 0E3h
db 37h
db 0C6h
db 2Fh
db 4Bh
db 80h
db 0Bh
db 0D5h
db 59h
db 61h
db 0D6h
db 0DAh
db 90h
db 6Eh
db 56h
db 0AAh
db 7Dh
db 0E5h
db 97h
db 4Ah
db 6
db 0CBh
db 0F3h
db 0DAh
db 7
db 47h
db 5Ch
db 0B2h
db 4Dh
db 76h
db 5Dh
db 50h
db 71h
db 6Fh
db 0C3h
db 59h
db 0DCh
db 2Dh
db 0AFh
db 85h
db 98h
db 32h
db 0BBh
db 0DAh
db 5Bh
db 0F5h
db 68h
db 4Ah
db 49h
db 9Ch
db 0F1h
db 79h
db 0DBh
db 71h
db 34h
db 6
db 5Eh
db 0B8h
db 75h
db 5Ch
db 5Ah
db 4
db 54h
db 94h
db 0E0h
db 0C1h
db 4Ch
db 27h
db 93h
db 25h
db 78h
db 0E3h
db 9Ch
db 5
db 8Dh
db 9
db 9Ah
db 0FBh
db 55h
db 0F4h
db 17h
db 38h
db 38h
db 0C7h
db 0E4h
db 0DDh
db 34h
db 0E2h
db 0E4h
db 0D5h
db 99h
db 77h
db 24h
db 5Ch
db 22h
db 0E1h
db 80h
db 0A9h
db 0F2h
db 43h
db 3Bh
db 8
db 7
db 29h
db 0A3h
db 89h
db 91h
db 62h
db 77h
db 2Dh
db 70h
db 3Bh
db 0ACh
db 7Ah
db 0BBh
db 27h
db 68h
db 2Ch
db 0ECh
db 3Ah
db 0D2h
db 95h
db 0E4h
db 9Fh
db 0EDh
db 41h
db 5Bh
db 0C1h
db 32h
db 64h
db 23h
db 78h
db 0E2h
db 0E1h
db 58h
db 0C0h
db 0A6h
db 84h
db 47h
db 45h
db 5Fh
db 0D7h
db 42h
db 0DCh
db 0FAh
db 0EBh
db 0DEh
db 71h
db 3Fh
db 1Ah
db 1Ah
db 3Ah
db 50h
db 2Bh
db 31h
db 0CCh
db 3Bh
db 0C3h
db 8Dh
db 0Bh
db 0B3h
db 3Eh
db 0F5h
db 0FCh
db 5Dh
db 79h
db 4Ah
db 68h
db 7Ah
db 28h
db 9Ch
db 55h
db 3Eh
db 94h
db 2Fh
db 5Fh
db 0A6h
db 58h
db 84h
db 0CFh
db 0F5h
db 0ECh
db 0Eh
db 86h
db 0C2h
db 4Ah
db 0C2h
db 8Ah
db 5Ah
db 2Ah
db 0DBh
db 5Bh
db 7Ch
db 0FCh
db 9Ch
db 0EDh
db 0A6h
db 0D4h
db 0
db 0C1h
db 53h
db 5Eh
db 0A1h
db 29h
db 81h
db 52h
db 3Ah
db 5Fh
db 1Dh
db 0C7h
db 37h
db 0B5h
db 10h
db 35h
db 0C7h
db 0EAh
db 3Ch
db 39h
db 1Ah
db 2Bh
db 49h
db 0DAh
db 0DBh
db 0
db 3Dh
db 25h
db 0E6h
db 17h
db 0B0h
db 61h
db 0Bh
db 22h
db 0A4h
db 67h
db 0A7h
db 9Fh
db 0B4h
db 14h
db 9
db 2Fh
db 33h
db 0EEh
db 42h
db 51h
db 2Bh
db 77h
db 0BAh
db 0EFh
db 50h
db 0A9h
db 0BEh
db 0BFh
db 0
db 0D3h
db 5Ah
db 0DFh
db 2Bh
db 0DAh
db 0EEh
db 87h
db 93h
db 82h
db 0B3h
db 97h
db 0A6h
db 5Ah
db 7
db 13h
db 0A3h
db 73h
db 0B8h
db 0E6h
db 0F1h
db 0ABh
db 93h
db 0D0h
db 56h
db 0BDh
db 1Dh
db 65h
db 0BFh
db 35h
db 72h
db 31h
db 0F4h
db 0DCh
db 86h
db 0F0h
db 1Eh
db 0C9h
db 0F4h
db 0ABh
db 91h
db 0A7h
db 0BAh
db 0D8h
db 0DCh
db 1Ch
db 0B1h
db 5Bh
db 59h
db 1Ch
db 0DDh
db 0F1h
db 24h
db 0B4h
db 8Ah
db 0CCh
db 2Bh
db 0A9h
db 0CDh
db 3Ah
db 46h
db 9Dh
db 34h
db 67h
db 95h
db 3
db 15h
db 46h
db 52h
db 0Bh
db 64h
db 0ACh
db 0AEh
db 0C2h
db 73h
db 6
db 91h
db 0AEh
db 1Fh
db 34h
db 0FCh
db 90h
db 97h
db 84h
db 86h
db 5Fh
db 1Bh
db 21h
db 0CFh
db 0DCh
db 0D5h
db 66h
db 0F5h
db 45h
db 0Ch
db 96h
db 33h
db 0B2h
db 95h
db 0C0h
db 55h
db 0BBh
db 0A7h
db 0C7h
db 0E6h
db 78h
db 0A5h
db 22h
db 4Dh
db 54h
db 0D7h
db 0DBh
db 6Fh
db 5Dh
db 0BAh
db 0E6h
db 0D5h
db 1Ah
db 6Bh
db 58h
db 41h
db 0DAh
db 2Ah
db 24h
db 0B0h
db 0F2h
db 2Dh
db 2Fh
db 0
db 1Eh
db 25h
db 7Bh
db 0AAh
db 0EAh
db 3Eh
db 1Fh
db 24h
db 52h
db 0DAh
db 58h
db 1Fh
db 0AEh
db 0C8h
db 0C6h
db 0F4h
db 7
db 0D8h
db 0E2h
db 0B0h
db 55h
db 54h
db 83h
db 0C8h
db 0ABh
db 0D5h
db 0Fh
db 20h
db 0DAh
db 0Fh
db 0D3h
db 0DCh
db 0B8h
db 52h
db 0BBh
db 68h
db 0DDh
db 0A1h
db 0ADh
db 38h
db 32h
db 74h
db 30h
db 2Ch
db 0EEh
db 9Fh
db 0FCh
db 0C0h
db 0BAh
db 0BDh
db 66h
db 53h
db 0CFh
db 17h
db 69h
db 0A7h
db 98h
db 12h
db 21h
db 45h
db 7Bh
db 0BEh
db 34h
db 0A4h
db 96h
db 0DBh
db 0A6h
db 4Ah
db 4Bh
db 23h
db 0FBh
db 0C1h
db 9Fh
db 49h
db 83h
db 0FAh
db 85h
db 2Fh
db 0FBh
db 0FFh
db 0DDh
db 0F3h
db 71h
db 0E3h
db 78h
db 0Eh
db 0A9h
db 0C6h
db 0C9h
db 0C1h
db 98h
db 0EFh
db 9Dh
db 19h
db 92h
db 0F1h
db 0DDh
db 17h
db 3Bh
db 0D5h
db 74h
db 6Ah
db 0F4h
db 0C7h
db 11h
db 38h
db 0B4h
db 9Fh
db 0DEh
db 5Bh
db 0D5h
db 0D4h
db 0E4h
db 54h
db 0CFh
db 84h
db 0DCh
db 62h
db 3Eh
db 57h
db 24h
db 0C1h
db 9Fh
db 5
db 0DBh
db 18h
db 0CEh
db 61h
db 0A2h
db 22h
db 29h
db 50h
db 24h
db 6Dh
db 17h
db 0CAh
db 4Ah
db 42h
db 5Dh
db 0AAh
db 10h
db 13h
db 8Bh
db 1Dh
db 0C3h
db 10h
db 46h
db 60h
db 0A9h
db 60h
db 0D3h
db 84h
db 0F7h
db 0AEh
db 4Fh
db 7Bh
db 49h
db 19h
db 95h
db 99h
db 0CEh
db 91h
db 0AFh
db 42h
db 56h
db 12h
db 9Eh
db 78h
db 0FFh
db 0DBh
db 0F6h
db 0E9h
db 0B3h
db 0CCh
db 4Fh
db 0E0h
db 7
db 7Ah
db 0F4h
db 0F6h
db 37h
db 2Bh
db 0BFh
db 87h
db 0DCh
db 6Eh
db 6Dh
db 46h
db 9Ch
db 16h
db 9
db 0E9h
db 0Ch
db 7Eh
db 0A0h
db 43h
db 14h
db 0DFh
db 25h
db 0A3h
db 0Dh
db 51h
db 29h
db 0C0h
db 22h
db 0EDh
db 47h
db 6
db 0D5h
db 7
db 3Bh
db 0E5h
db 65h
db 32h
db 6Eh
db 0FBh
db 0E4h
db 77h
db 24h
db 40h
db 3Ah
db 1
db 45h
db 60h
db 0C8h
db 98h
db 7Ah
db 0BBh
db 4Ch
db 8Eh
db 66h
db 0A1h
db 0DAh
db 0B1h
db 2Eh
db 0C7h
db 0CBh
db 1Fh
db 9Ch
db 4
db 89h
db 5Ch
db 12h
db 0A5h
db 0ECh
db 5
db 0ADh
db 92h
db 0D9h
db 52h
db 0ACh
db 69h
db 0A9h
db 6
db 24h
db 51h
db 0CCh
db 0ADh
db 2Bh
db 55h
db 98h
db 73h
db 47h
db 85h
db 0F0h
db 5Fh
db 0C2h
db 56h
db 6Bh
db 0CCh
db 88h
db 24h
db 68h
db 68h
db 6Eh
db 17h
db 9Bh
db 63h
db 19h
db 90h
db 58h
db 58h
db 38h
db 10h
db 94h
db 0Ah
db 22h
db 0CAh
db 48h
db 9Bh
db 0B8h
db 0A3h
db 0FCh
db 7Ch
db 0E7h
db 0A8h
db 40h
db 8Eh
db 71h
db 14h
db 0ADh
db 0E3h
db 0A9h
db 0CEh
db 31h
db 0ACh
db 69h
db 0F3h
db 0A0h
db 0A4h
db 85h
db 8Ah
db 6Ch
db 14h
db 58h
db 5
db 0C5h
db 65h
db 0C3h
db 58h
db 0E2h
db 9Bh
db 3Dh
db 0Fh
db 45h
db 12h
db 52h
db 71h
db 0AEh
db 0C1h
db 0B5h
db 0AAh
db 0D6h
db 0DDh
db 35h
db 61h
db 14h
db 0D1h
db 87h
db 20h
db 5
db 72h
db 8Bh
db 27h
db 0ADh
db 0D9h
db 1Bh
db 18h
db 0DEh
db 24h
db 1Ch
db 3Ch
db 5Ah
db 9Eh
db 25h
db 0D5h
db 6
db 0F0h
db 0F0h
db 8Ah
db 1Eh
db 89h
db 67h
db 1Ch
db 36h
db 0E2h
db 78h
db 69h
db 33h
db 0B9h
db 11h
db 26h
db 0B3h
db 0E5h
db 0A9h
db 0Eh
db 0E1h
db 4Bh
db 88h
db 0DFh
db 0D0h
db 0AAh
db 96h
db 98h
db 61h
db 0EFh
db 7
db 0Dh
db 79h
db 0D8h
db 0BFh
db 0B7h
db 0A1h
db 8Ch
db 3Bh
db 0C7h
db 0A1h
db 30h
db 56h
db 62h
db 90h
db 1
db 0C8h
db 81h
db 0D4h
db 0F3h
db 62h
db 3
db 0D8h
db 0D0h
db 4
db 0A7h
db 6Ch
db 9Ah
db 6Dh
db 0B5h
db 0F8h
db 1Eh
db 8Ch
db 42h
db 0FCh
db 96h
db 6
db 0A7h
db 84h
db 0B8h
db 1
db 0ADh
db 1Ch
db 72h
db 9Ah
db 0E7h
db 0D3h
db 2Dh
db 0AEh
db 76h
db 79h
db 0Bh
db 22h
db 0D3h
db 3Fh
db 0E9h
db 17h
db 2Fh
db 3
db 0DEh
db 15h
db 29h
db 0BBh
db 7
db 0B7h
db 19h
db 0DCh
db 4Eh
db 0DBh
db 20h
db 92h
db 0FEh
db 12h
db 0D4h
db 0EDh
db 3Bh
db 0CAh
db 1Dh
db 0F2h
db 3Bh
db 0B1h
db 8Eh
db 85h
db 65h
db 0Ah
db 9Ch
db 5Dh
db 0FCh
db 0A1h
db 0D2h
db 7Eh
db 0E1h
db 0EDh
db 1Ah
db 60h
db 0B4h
db 32h
db 15h
db 0D3h
db 0ECh
db 0C5h
db 0F0h
db 0AEh
db 7Bh
db 1Dh
db 7Eh
db 47h
db 4Dh
db 0A4h
db 0B8h
db 18h
db 0AEh
db 89h
db 25h
db 4Eh
db 1Ch
db 0E4h
db 23h
db 0BEh
db 3Fh
db 70h
db 63h
db 39h
db 0FCh
db 13h
db 78h
db 8Ah
db 79h
db 7Ah
db 0DBh
db 99h
db 97h
db 96h
db 54h
db 4Ch
db 0B1h
db 2Eh
db 0C8h
db 1Ah
db 4
db 5Fh
db 40h
db 2Eh
db 0BDh
db 0D1h
db 0DFh
db 0DFh
db 64h
db 9Eh
db 0F0h
db 52h
db 2Ah
db 0A5h
db 5Fh
db 8Ah
db 0D2h
db 61h
db 8Bh
db 39h
db 0AEh
db 0BAh
db 79h
db 7Bh
db 47h
db 11h
db 0DBh
db 3
db 5Eh
db 0E9h
db 0E6h
db 2Fh
db 0C8h
db 6
db 0B2h
db 61h
db 0CCh
db 21h
db 17h
db 0BEh
db 1Dh
db 4Bh
db 0C3h
db 7Dh
db 0A6h
db 83h
db 0B6h
db 20h
db 43h
db 16h
db 5Bh
db 63h
db 0F1h
db 1
db 24h
db 9Ah
db 67h
db 8Ah
db 0FDh
db 2Fh
db 8Eh
db 61h
db 0ACh
db 0DCh
db 0A0h
db 0D4h
db 20h
db 12h
db 0C8h
db 70h
db 57h
db 7Ah
db 9Dh
db 53h
db 2Ch
db 9Bh
db 0D2h
db 71h
db 0A7h
db 0D7h
db 5
db 0DDh
db 53h
db 86h
db 8Fh
db 7Bh
db 71h
db 5Eh
db 24h
db 96h
db 0DDh
db 1
db 5
db 0F8h
db 0C9h
db 0E0h
db 0A4h
db 18h
db 23h
db 14h
db 3Ch
db 4Eh
db 7Ah
db 29h
db 89h
db 0B8h
db 9Bh
db 5Fh
db 2Dh
db 0A9h
db 41h
db 2Bh
db 9
db 0BEh
db 30h
db 0BBh
db 0EEh
db 21h
db 0EEh
db 0C7h
db 60h
db 1Dh
db 0DBh
db 82h
db 11h
db 77h
db 76h
db 7Eh
db 0CCh
db 6Ah
db 50h
db 55h
db 0C7h
db 42h
db 0D6h
db 24h
db 0E2h
db 7Fh
db 57h
db 0C9h
db 0C2h
db 0D1h
db 0B6h
db 85h
db 0D5h
db 0D4h
db 0ECh
db 3Dh
db 36h
db 4Bh
db 13h
db 0A4h
db 0CFh
db 0B4h
db 1
db 4Ch
db 5Bh
db 0CAh
db 89h
db 0D6h
db 67h
db 99h
db 4Ah
db 0A8h
db 69h
db 1
db 4
db 50h
db 0A5h
db 5Ch
db 0CFh
db 68h
db 1Ch
db 0A7h
db 9Eh
db 0C6h
db 0AEh
db 63h
db 77h
db 0FEh
db 0Eh
db 2
db 22h
db 0E0h
db 6Dh
db 0D2h
db 33h
db 0Bh
db 0F3h
db 88h
db 0F5h
db 8Ah
db 0D8h
db 0B2h
db 0F9h
db 7Dh
db 8Ah
db 8Bh
db 93h
db 7Bh
db 1Ah
db 0A5h
db 0FFh
db 0E1h
db 31h
db 3
db 0EDh
db 0ECh
db 0BBh
db 9Ch
db 6Ch
db 3Fh
db 1Bh
db 8Bh
db 0D5h
db 0FBh
db 9Ch
db 2Fh
db 54h
db 0DEh
db 0BAh
db 0A6h
db 0B1h
db 0E5h
db 9
db 0FEh
db 0B0h
db 2Ah
db 0A6h
db 14h
db 0DBh
db 75h
db 0A6h
db 70h
db 0BCh
db 9Eh
db 0FDh
db 0F6h
db 66h
db 97h
db 0DCh
db 0E6h
db 72h
db 49h
db 0C7h
db 0F0h
db 0DFh
db 37h
db 0ECh
db 94h
db 0E3h
db 0FEh
db 0B4h
db 28h
db 23h
db 2Fh
db 88h
db 0DCh
db 1Ah
db 0F2h
db 7Eh
db 6Fh
db 0B1h
db 6
db 58h
db 1Eh
db 72h
db 0C2h
db 0B9h
db 0F7h
db 0CAh
db 0DEh
db 23h
db 0EDh
db 6Bh
db 0BEh
db 0CEh
db 0
db 0E5h
db 0BEh
db 4
db 7
db 0ABh
db 41h
db 7Bh
db 0EAh
db 0C7h
db 4Ch
db 0D1h
db 0D8h
db 36h
db 92h
db 74h
db 93h
db 1Fh
db 0ABh
db 0E9h
db 42h
db 0F5h
db 52h
db 27h
db 9Eh
db 23h
db 0E7h
db 74h
db 28h
db 0CEh
db 4Ah
db 0DBh
db 87h
db 6Dh
db 0A5h
db 24h
db 0BEh
db 25h
db 74h
db 0ABh
db 6Dh
db 4Eh
db 0D5h
db 0BCh
db 47h
db 9Fh
db 0B7h
db 75h
db 96h
db 0EDh
db 29h
db 47h
db 0F9h
db 63h
db 4Fh
db 0DBh
db 0F7h
db 0Ah
db 0B2h
db 0
db 0F1h
db 0A0h
db 0CDh
db 3Dh
db 1Dh
db 8
db 0CAh
db 0C1h
db 22h
db 43h
db 8Bh
db 5Dh
db 28h
db 0DCh
db 73h
db 5Fh
db 29h
db 45h
db 0BBh
db 0F4h
db 0A6h
db 16h
db 0D4h
db 77h
db 0B4h
db 0EEh
db 35h
db 39h
db 15h
db 8Ch
db 0D3h
db 2
db 6Eh
db 60h
db 0BEh
db 0CCh
db 0DFh
db 4Ah
db 0F6h
db 10h
db 31h
db 0F8h
db 29h
db 0D0h
db 41h
db 56h
db 24h
db 0D4h
db 0D7h
db 0EFh
db 0DCh
db 24h
db 0E1h
db 0C1h
db 92h
db 4Ch
db 0EAh
db 89h
db 0EFh
db 0DAh
db 16h
db 3Ch
db 0DBh
db 41h
db 24h
db 4Ch
db 0EBh
db 92h
db 0D6h
db 87h
db 0E8h
db 76h
db 53h
db 2Dh
db 18h
db 7Eh
db 6Ch
db 0A7h
db 93h
db 0BAh
db 36h
db 0E8h
db 0BDh
db 0C4h
db 56h
db 50h
db 85h
db 2Fh
db 0F6h
db 61h
db 0DAh
db 67h
db 73h
db 0A8h
db 0ADh
db 0F2h
db 0A3h
db 0F3h
db 0E8h
db 0CDh
db 3Eh
db 7
db 0F4h
db 40h
db 2Fh
db 7Ah
db 58h
db 0CFh
db 38h
db 0DDh
db 80h
db 3Eh
db 17h
db 96h
db 30h
db 0Fh
db 34h
db 0B5h
db 7
db 89h
db 7Bh
db 0B3h
db 7Eh
db 93h
db 0D2h
db 58h
db 9Fh
db 20h
db 70h
db 13h
db 0E8h
db 84h
db 97h
db 4
db 6Bh
db 3Ah
db 0D1h
db 46h
db 8Bh
db 1Ch
db 0F8h
db 0A4h
db 1Dh
db 42h
db 1Dh
db 2Ch
db 6Dh
db 7
db 9Ch
db 5Fh
db 0C8h
db 5Dh
db 9Fh
db 7
db 24h
db 0E2h
db 61h
db 12h
db 4Bh
db 52h
db 0BEh
db 0F6h
db 0CEh
db 0B6h
db 0E8h
db 10h
db 71h
db 7Bh
db 4Dh
db 0F4h
db 74h
db 9Fh
db 0AAh
db 12h
db 0D8h
db 31h
db 0C3h
db 0B9h
db 9Fh
db 0F7h
db 3Dh
db 69h
db 0EAh
db 59h
db 0BFh
db 0D3h
db 0CCh
db 15h
db 0E3h
db 2Bh
db 1
db 44h
db 0B1h
db 97h
db 21h
db 0A9h
db 97h
db 4Bh
db 0FFh
db 0E1h
db 78h
db 0B0h
db 70h
db 0D4h
db 8Dh
db 0E4h
db 5
db 0A8h
db 40h
db 0DFh
db 0A6h
db 6Fh
db 5Ch
db 85h
db 4Ah
db 0C8h
db 0A0h
db 64h
db 0A7h
db 0E2h
db 4Dh
db 68h
db 0A8h
db 39h
db 0EBh
db 38h
db 0EAh
db 0C4h
db 89h
db 66h
db 0Bh
db 70h
db 0D9h
db 0F0h
db 70h
db 6Fh
db 0A5h
db 0E5h
db 70h
db 8Bh
db 2Ch
db 40h
db 7Ch
db 0D3h
db 0
db 0D5h
db 89h
db 89h
db 47h
db 7Ch
db 64h
db 0E4h
db 0Eh
db 0A6h
db 4Ah
db 0E8h
db 34h
db 0D1h
db 18h
db 31h
db 50h
db 2Fh
db 84h
db 0BFh
db 9Bh
db 45h
db 14h
db 7Dh
db 0A3h
db 11h
db 0Eh
db 11h
db 40h
db 1Fh
db 5Dh
db 9Eh
db 1Ch
db 0FCh
db 6Ch
db 68h
db 0B1h
db 74h
db 6Dh
db 30h
db 0BCh
db 0B2h
db 0AEh
db 0D4h
db 0EAh
db 62h
db 0F3h
db 75h
db 6Dh
db 21h
db 5Dh
db 0E5h
db 52h
db 0B7h
db 4Ch
db 1Eh
db 1Fh
db 44h
db 54h
db 0D9h
db 0B4h
db 0CFh
db 2Ch
db 0DFh
db 0E3h
db 9Dh
db 67h
db 41h
db 0D3h
db 0AEh
db 9Eh
db 0ACh
db 86h
db 61h
db 99h
db 3Ah
db 2Fh
db 3Ah
db 0E0h
db 0DDh
db 48h
db 7Bh
db 28h
db 1Ch
db 49h
db 19h
db 17h
db 50h
db 86h
db 0F2h
db 0DCh
db 0AFh
db 61h
db 36h
db 14h
db 5Bh
db 0E9h
db 50h
db 24h
db 3Bh
db 0A2h
db 0EEh
db 0FFh
db 89h
db 25h
db 43h
db 0ACh
db 70h
db 0Dh
db 0BCh
db 77h
db 38h
db 35h
db 0B4h
db 74h
db 1Bh
db 0Ch
db 0F7h
db 66h
db 0D2h
db 30h
db 53h
db 4Ch
db 0C5h
db 15h
db 0B7h
db 2Fh
db 36h
db 47h
db 67h
db 90h
db 0ACh
db 0DBh
db 8Eh
db 0A7h
db 1
db 10h
db 63h
db 0E6h
db 3Eh
db 6Eh
db 0D2h
db 84h
db 51h
db 0FDh
db 0FBh
db 15h
db 24h
db 64h
db 0FDh
db 0C4h
db 0F5h
db 9
db 50h
db 24h
db 9
db 70h
db 0C5h
db 0DAh
db 2Ah
db 5Ah
db 0BBh
db 0E6h
db 0EAh
db 91h
db 9Ah
db 8
db 5Ch
db 0D2h
db 7Dh
db 79h
db 0F1h
db 2Eh
db 5Ah
db 62h
db 0B8h
db 1Ah
db 40h
db 2Eh
db 7Ch
db 5Eh
db 0EBh
db 62h
db 0EEh
db 6Bh
db 37h
db 79h
db 0E4h
db 9Ch
db 66h
db 5Fh
db 0CFh
db 0BAh
db 38h
db 0B5h
db 0CDh
db 4Ah
db 0B5h
db 10h
db 1Bh
db 3Dh
db 70h
db 0C0h
db 3Bh
db 0A8h
db 0C1h
db 0C7h
db 0A1h
db 19h
db 1Dh
db 0D6h
db 0BCh
db 8Ch
db 0CAh
db 0C6h
db 54h
db 0Ah
db 6Dh
db 3
db 0B3h
db 3Dh
db 2Eh
db 21h
db 0ACh
db 3Ch
db 12h
db 65h
db 0A4h
db 0E0h
db 59h
db 0E1h
db 73h
db 0C1h
db 79h
db 9Fh
db 0A1h
db 14h
db 7Fh
db 0FAh
db 31h
db 44h
db 57h
db 21h
db 79h
db 1Ch
db 7Eh
db 1Eh
db 4Dh
db 93h
db 32h
db 71h
db 0A6h
db 0E9h
db 15h
db 0DEh
db 0FEh
db 9Fh
db 0FEh
db 0Ch
db 7Bh
db 2Ch
db 77h
db 0EDh
db 66h
db 0D5h
db 3Ch
db 0C1h
db 56h
db 0FDh
db 75h
db 7
db 6Ch
db 0B2h
db 37h
db 0C1h
db 1Dh
db 6Ch
db 45h
db 30h
db 8Ch
db 7
db 3Dh
db 2Eh
db 26h
db 2
db 26h
db 4Fh
db 87h
db 0E2h
db 56h
db 87h
db 0A2h
db 31h
db 5Dh
db 0FEh
db 0Bh
db 47h
db 81h
db 34h
db 0FBh
db 7Ch
db 0FEh
db 0EDh
db 5Dh
db 83h
db 0DAh
db 0
db 73h
db 13h
db 0F2h
db 0EFh
db 57h
db 0F7h
db 8
db 83h
db 86h
db 0Ah
db 7Ch
db 0D6h
db 86h
db 94h
db 18h
db 0Ah
db 9Fh
db 0DAh
db 0A4h
db 0DEh
db 0EAh
db 41h
db 6
db 0B8h
db 7Ch
db 0A7h
db 0FEh
db 0AAh
db 0B3h
db 4Ch
db 88h
db 0C1h
db 25h
db 66h
db 47h
db 59h
db 0Bh
db 0FAh
db 5Bh
db 1Dh
db 0E0h
db 0D9h
db 0E6h
db 0AFh
db 76h
db 0CAh
db 71h
db 0C2h
db 21h
db 7Fh
db 98h
db 0F4h
db 0Eh
db 5Ah
db 38h
db 0F2h
db 0CDh
db 4Fh
db 2Eh
db 73h
db 31h
db 63h
db 0B3h
db 11h
db 46h
db 7Eh
db 2Dh
db 4Bh
db 27h
db 65h
db 98h
db 0A2h
db 0D5h
db 0B5h
db 0C8h
db 0B0h
db 1Dh
db 4Eh
db 9
db 2Bh
db 28h
db 9
db 41h
db 30h
db 7Bh
db 5Eh
db 3
db 55h
db 0BAh
db 25h
db 0D3h
db 83h
db 0Eh
db 80h
db 3Dh
db 77h
db 0C1h
db 0A4h
db 4
db 5Eh
db 0E8h
db 57h
db 34h
db 37h
db 0BDh
db 2Dh
db 4Ah
db 0F6h
db 65h
db 12h
db 8Fh
db 47h
db 0FFh
db 0ADh
db 53h
db 0D7h
db 0DAh
db 31h
db 0E4h
db 91h
db 48h
db 55h
db 5Bh
db 57h
db 0B0h
db 0B1h
db 42h
db 31h
db 39h
db 17h
db 0A9h
db 18h
db 74h
db 3
db 65h
db 37h
db 0AFh
db 0D9h
db 0EBh
db 1Eh
db 0B8h
db 8
db 9Fh
db 6Fh
db 24h
db 0DDh
db 38h
db 52h
db 0D5h
db 96h
db 18h
db 29h
db 1Ch
db 0D7h
db 84h
db 33h
db 9Dh
db 0D6h
db 0AEh
db 78h
db 0E4h
db 47h
db 0A2h
db 84h
db 48h
db 0F8h
db 0BDh
db 0AEh
db 0D7h
db 0D1h
db 0D8h
db 0D0h
db 0FBh
db 56h
db 20h
db 0A6h
db 51h
db 6Fh
db 0Ah
db 5Dh
db 98h
db 0ACh
db 0A9h
db 8Dh
db 73h
db 0C6h
db 25h
db 0B2h
db 0B8h
db 0B0h
db 0A7h
db 4Ch
db 36h
db 0EAh
db 6Bh
db 75h
db 0D9h
db 17h
db 0DEh
db 0BBh
db 0BCh
db 0CDh
db 81h
db 86h
db 96h
db 90h
db 0Ch
db 0B4h
db 0C0h
db 80h
db 40h
db 60h
db 7Fh
db 5Fh
db 0DEh
db 84h
db 2Fh
db 9Ch
db 0B7h
db 0CBh
db 0C6h
db 0Eh
db 10h
db 79h
db 59h
db 6Fh
db 0A0h
db 16h
db 97h
db 78h
db 0ADh
db 6Dh
db 84h
db 0Fh
db 9Ch
db 6Ch
db 44h
db 0D5h
db 9Ch
db 90h
db 80h
db 0F0h
db 38h
db 5Ah
db 13h
db 0B7h
db 8
db 81h
db 0DFh
db 0BDh
db 23h
db 0CFh
db 0E6h
db 0D2h
db 0E1h
db 37h
db 0FFh
db 52h
db 0A1h
db 31h
db 8Bh
db 0EFh
db 4Ch
db 29h
db 74h
db 0DAh
db 22h
db 6Dh
db 49h
db 0E2h
db 0CDh
db 0A2h
db 0A0h
db 0D7h
db 0BAh
db 0D4h
db 3Ch
db 0BFh
db 9Fh
db 41h
db 6Eh
db 0BEh
db 0F4h
db 40h
db 5Fh
db 0ECh
db 9Fh
db 88h
db 0E3h
db 8Fh
db 4Ah
db 13h
db 83h
db 0CFh
db 0B1h
db 91h
db 0E4h
db 0BCh
db 23h
db 0D1h
db 0AAh
db 88h
db 0D5h
db 11h
db 8
db 0A1h
db 0CAh
db 2Bh
db 67h
db 0B1h
db 44h
db 43h
db 51h
db 0B1h
db 0F1h
db 17h
db 0FFh
db 0A5h
db 4Eh
db 30h
db 5Dh
db 66h
db 93h
db 15h
db 97h
db 1Fh
db 68h
db 49h
db 32h
db 0ECh
db 0ACh
db 0CCh
db 8Fh
db 2Dh
db 0CFh
db 1Bh
db 0C2h
db 0BAh
db 0EBh
db 5Dh
db 7
db 0D9h
db 13h
db 6Ch
db 8Ch
db 37h
db 0A8h
db 3Dh
db 1Dh
db 3Eh
db 0ABh
db 0EEh
db 7Dh
db 0DFh
db 55h
db 5Fh
db 4Fh
db 0BFh
db 0B2h
db 0DCh
db 9
db 89h
db 51h
db 0B2h
db 66h
db 0ABh
db 0E7h
db 7Eh
db 4Ah
db 6Fh
db 42h
db 0B0h
db 0E4h
db 49h
db 0F0h
db 6Eh
db 66h
db 0F7h
db 0Dh
db 27h
db 3Eh
db 0E0h
db 3Ah
db 0ABh
db 90h
db 18h
db 0C4h
db 0A3h
db 5Dh
db 0CCh
db 0Dh
db 93h
db 0F2h
db 7Eh
db 69h
db 0B6h
db 40h
db 0
db 0D5h
db 7Dh
db 0D3h
db 27h
db 16h
db 32h
db 3Dh
db 0B7h
db 0AFh
db 0D5h
db 44h
db 6Bh
db 50h
db 23h
db 53h
db 6Ch
db 7Ch
db 0BAh
db 7Bh
db 1Bh
db 43h
db 0Ah
db 82h
db 28h
db 0E2h
db 0DDh
db 3Eh
db 0D3h
db 6
db 0BAh
db 7Ah
db 4
db 66h
db 5Ah
db 53h
db 72h
db 0EEh
db 0A3h
db 94h
db 0ABh
db 0DEh
db 0FBh
db 1Ch
db 0A9h
db 55h
db 29h
db 0CDh
db 0F6h
db 6Bh
db 44h
db 0Ah
db 4Eh
db 33h
db 0FFh
db 66h
db 0E8h
db 0D0h
db 0B2h
db 0FDh
db 38h
db 0A0h
db 4Fh
db 0Ch
db 73h
db 96h
db 91h
db 0DDh
db 0D0h
db 0F2h
db 0C7h
db 47h
db 56h
db 90h
db 0CFh
db 0E9h
db 16h
db 2Fh
db 39h
db 0A0h
db 0D6h
db 0BEh
db 88h
db 12h
db 0ABh
db 0E2h
db 2Eh
db 0CBh
db 0B6h
db 0D8h
db 0C2h
db 20h
db 95h
db 0FBh
db 86h
db 85h
db 0FEh
db 0C3h
db 0DDh
db 0C3h
db 0Eh
db 7Fh
db 0BBh
db 53h
db 7
db 38h
db 0E8h
db 15h
db 45h
db 0D6h
db 3Dh
db 85h
db 61h
db 0ABh
db 58h
db 1Ch
db 4Ah
db 0B6h
db 8Ch
db 64h
db 80h
db 0BAh
db 0BBh
db 0BEh
db 0Dh
db 0DEh
db 0CFh
db 0Bh
db 0F8h
db 37h
db 85h
db 17h
db 58h
db 33h
db 14h
db 0F2h
db 4
db 8Eh
db 0EDh
db 3Dh
db 0F3h
db 0D4h
db 53h
db 0B1h
db 0A0h
db 3
db 46h
db 0BEh
db 1Eh
db 0F5h
db 7
db 67h
db 6Eh
db 30h
db 45h
db 2Ah
db 83h
db 9Ch
db 0F2h
db 0DFh
db 5Dh
db 0F8h
db 1Ah
db 0B4h
db 5Ah
db 7Ch
db 0B0h
db 0E8h
db 0BFh
db 90h
db 7
db 8Eh
db 59h
db 0C3h
db 8Fh
db 83h
db 0E1h
db 49h
db 0F2h
db 7Dh
db 4Dh
db 0D1h
db 56h
db 32h
db 0A4h
db 0DFh
db 6Ah
db 45h
db 77h
db 0
db 78h
db 0F9h
db 55h
db 2Ch
db 0F0h
db 61h
db 0BAh
db 64h
db 9Eh
db 5Ch
db 18h
db 53h
db 63h
db 0C5h
db 30h
db 0D9h
db 9
db 4Fh
db 69h
db 2Dh
db 42h
db 2Eh
db 0B4h
db 0A9h
db 42h
db 54h
db 0Fh
db 5Ch
db 99h
db 76h
db 8
db 0Dh
db 2Eh
db 0D1h
db 35h
db 48h
db 4Ah
db 0C8h
db 21h
db 0BDh
db 3Fh
db 0A0h
db 55h
db 77h
db 2Eh
db 83h
db 7
db 33h
db 4
db 0FEh
db 0EEh
db 6Ch
db 0Ch
db 0E4h
db 91h
db 0C8h
db 4Dh
db 0AAh
db 3Fh
db 66h
db 0D0h
db 47h
db 4Ch
db 0A6h
db 83h
db 0F1h
db 0AFh
db 0A2h
db 5Bh
db 2Ah
db 28h
db 0Ch
db 0D2h
db 0FDh
db 95h
db 0BEh
db 0DAh
db 0E2h
db 20h
db 0F1h
db 9Ah
db 19h
db 0F3h
db 11h
db 1Bh
db 0FBh
db 0
db 72h
db 3Dh
db 97h
db 0D5h
db 59h
db 84h
db 8Ah
db 0Ch
db 1Bh
db 6Dh
db 71h
db 5Ch
db 97h
db 0A4h
db 0C3h
db 0BCh
db 4Bh
db 0BEh
db 68h
db 85h
db 7Dh
db 9Ch
db 2
db 11h
db 56h
db 14h
db 3Ah
db 0B7h
db 7Bh
db 27h
db 0FEh
db 57h
db 0D0h
db 0D6h
db 0FAh
db 0C8h
db 0E2h
db 9Bh
db 28h
db 66h
db 9Fh
db 0BAh
db 3Bh
db 5Ch
db 3Dh
db 6Ah
db 0F1h
db 5Dh
db 25h
db 0Dh
db 30h
db 4Ah
db 79h
db 18h
db 7
db 58h
db 8Fh
db 50h
db 0
db 4Eh
db 0A4h
db 0CFh
db 0A8h
db 86h
db 0E8h
db 66h
db 0CAh
db 0ACh
db 8Dh
db 3Fh
db 0A8h
db 0D4h
db 34h
db 0E7h
db 41h
db 3Fh
db 45h
db 0E2h
db 65h
db 4Ah
db 0FDh
db 0B7h
db 0C4h
db 0E3h
db 0DFh
db 0F4h
db 99h
db 0A4h
db 0C8h
db 98h
db 5Ch
db 33h
db 76h
db 0A7h
db 24h
db 65h
db 92h
db 0C7h
db 0B3h
db 10h
db 0B5h
db 0Fh
db 0B9h
db 0EDh
db 15h
db 0D1h
db 93h
db 0A5h
db 7
db 0FCh
db 0C7h
db 26h
db 0A7h
db 4Eh
db 38h
db 0Dh
db 0Dh
db 2Dh
db 81h
db 0E3h
db 0BFh
db 96h
db 7Fh
db 0B2h
db 44h
db 6Dh
db 6Fh
db 82h
db 0CDh
db 0Ch
db 2Bh
db 0D0h
db 0BFh
db 4Ah
db 0BAh
db 0BEh
db 79h
db 6Ah
db 0E3h
db 0BDh
db 54h
db 0C3h
db 0C6h
db 0FEh
db 7Eh
db 74h
db 66h
db 45h
db 0F2h
db 5Fh
db 0E1h
db 0E1h
db 4Eh
db 62h
db 0
db 0EFh
db 0D6h
db 51h
db 89h
db 54h
db 70h
db 13h
db 28h
db 95h
db 2Ch
db 14h
db 16h
db 2Ah
db 0C5h
db 7
db 64h
db 1Fh
db 71h
db 0C9h
db 0E2h
db 0B5h
db 0A7h
db 0E4h
db 0Dh
db 3Ah
db 25h
db 0BEh
db 27h
db 68h
db 46h
db 0E6h
db 4Ah
db 0DAh
db 8Ch
db 2Bh
db 42h
db 2
db 0EBh
db 0EFh
db 8Dh
db 0A8h
db 41h
db 0C7h
db 3Dh
db 0E7h
db 9Dh
db 22h
db 0EBh
db 1Ch
db 0Bh
db 0CDh
db 19h
db 0E8h
db 88h
db 0E5h
db 1
db 0F3h
db 50h
db 0CAh
db 57h
db 6Ah
db 48h
db 6Ch
db 1Ah
db 70h
db 0BDh
db 2Bh
db 0D9h
db 12h
db 34h
db 40h
db 0Eh
db 51h
db 0E6h
db 5Bh
db 0EAh
db 0A6h
db 0D8h
db 0DDh
db 8Ch
db 0D3h
db 0FFh
db 74h
db 0ADh
db 0AEh
db 0BCh
db 2Fh
db 0FEh
db 0EEh
db 82h
db 0B7h
db 81h
db 38h
db 63h
db 0A5h
db 28h
db 3Fh
db 0DFh
db 0FFh
db 0C1h
db 0BDh
db 3Dh
db 0A3h
db 0F1h
db 65h
db 0DEh
db 0F0h
db 0C6h
db 8Eh
db 0ECh
db 80h
db 0C7h
db 0E8h
db 0Eh
db 0D3h
db 0D5h
db 0E6h
db 5Dh
db 79h
db 16h
db 0AAh
db 41h
db 0E5h
db 0BBh
db 32h
db 49h
db 38h
db 0ABh
db 1Ch
db 4Ah
db 14h
db 83h
db 18h
db 1Bh
db 9Ah
db 7Dh
db 1Ah
db 61h
db 86h
db 25h
db 53h
db 0C3h
db 0BCh
db 0BFh
db 21h
db 35h
db 0C5h
db 96h
db 40h
db 7
db 0B4h
db 1Fh
db 0EAh
db 36h
db 48h
db 92h
db 35h
db 8Dh
db 0DDh
db 9Ah
db 75h
db 7
db 0CDh
db 82h
db 0B5h
db 0
db 82h
db 0D9h
db 3Dh
db 0DDh
db 6Bh
db 96h
db 70h
db 0Eh
db 0CFh
db 50h
db 0D5h
db 0CBh
db 77h
db 0F6h
db 0BEh
db 0B8h
db 25h
db 1Dh
db 79h
db 81h
db 0D1h
db 0AAh
db 0F8h
db 0F7h
db 87h
db 53h
db 0BDh
db 0F9h
db 0C0h
db 0FDh
db 0A8h
db 54h
db 7Fh
db 0DFh
db 0A6h
db 0C0h
db 1Dh
db 0C7h
db 9Fh
db 5Eh
db 42h
db 9Ch
db 0C2h
db 8Dh
db 0C9h
db 19h
db 12h
db 8
db 26h
db 72h
db 91h
db 0Bh
db 0D1h
db 0B8h
db 0Eh
db 16h
db 0E2h
db 0C7h
db 0FEh
db 0E9h
db 11h
db 4Ah
db 0FAh
db 25h
db 0Dh
db 36h
db 8
db 0BFh
db 0Ah
db 65h
db 21h
db 32h
db 0CBh
db 9
db 15h
db 43h
db 21h
db 3Dh
db 61h
db 49h
db 14h
db 62h
db 0BBh
db 9Fh
db 0A8h
db 60h
db 0E9h
db 0F7h
db 19h
db 40h
db 0A1h
db 45h
db 66h
db 6Eh
db 0A8h
db 2Ch
db 49h
db 2Ah
db 3Eh
db 7
db 12h
db 0F4h
db 0DCh
db 67h
db 0D3h
db 60h
db 0C3h
db 0CCh
db 99h
db 5Fh
db 8
db 0Fh
db 0C3h
db 1Ah
db 60h
db 7Dh
db 41h
db 59h
db 0ECh
db 67h
db 4Ah
db 68h
db 0Fh
db 77h
db 8Dh
db 13h
db 98h
db 41h
db 0Bh
db 64h
db 0C7h
db 0F5h
db 0E3h
db 0CBh
db 5
db 37h
db 51h
db 0DEh
db 81h
db 5Fh
db 0A3h
db 83h
db 75h
db 16h
db 0DDh
db 0F3h
db 1Bh
db 95h
db 7Eh
db 0BAh
db 11h
db 3Ah
db 4Eh
db 0C2h
db 0EEh
db 62h
db 0C9h
db 0EBh
db 0Eh
db 0EFh
db 0EFh
db 53h
db 31h
db 38h
db 7Ah
db 4Dh
db 0F3h
db 5Ch
db 27h
db 0C9h
db 12h
db 8Ah
db 71h
db 85h
db 55h
db 0C2h
db 1Ch
db 0FFh
db 9Eh
db 58h
db 74h
db 0B4h
db 0ADh
db 35h
db 5Bh
db 0BEh
db 0D5h
db 0C5h
db 7Ch
db 0C1h
db 7Eh
db 4
db 0EEh
db 0D3h
db 0DDh
db 58h
db 0C7h
db 2Eh
db 81h
db 0B0h
db 5Ch
db 0FAh
db 54h
db 2Fh
db 40h
db 0B9h
db 25h
db 5Bh
db 99h
db 0BBh
db 44h
db 0C8h
db 0A3h
db 20h
db 9Fh
db 97h
db 3Bh
db 0E9h
db 0F4h
db 2Ah
db 3Ch
db 87h
db 7Eh
db 28h
db 0B1h
db 88h
db 72h
db 43h
db 0B7h
db 0EDh
db 0C8h
db 60h
db 1Ah
db 6Dh
db 0F3h
db 66h
db 12h
db 35h
db 40h
db 57h
db 0BBh
db 0EFh
db 0F4h
db 48h
db 0E4h
db 8Dh
db 58h
db 57h
db 0C1h
db 0AAh
db 2Bh
db 2Dh
db 19h
db 56h
db 5Eh
db 8Dh
db 0B1h
db 0F3h
db 85h
db 0BAh
db 7Dh
db 94h
db 38h
db 0B8h
db 7Eh
db 8Ch
db 3Ch
db 0D0h
db 31h
db 0F5h
db 8Eh
db 87h
db 0FDh
db 17h
db 97h
db 17h
db 0BFh
db 8Bh
db 87h
db 0Ah
db 27h
db 0C2h
db 61h
db 0F0h
db 0C6h
db 77h
db 68h
db 0FBh
db 4Fh
db 0FAh
db 76h
db 0FDh
db 0Bh
db 0DDh
db 0C5h
db 65h
db 68h
db 0E3h
db 0EAh
db 61h
db 0BCh
db 7Ch
db 48h
db 66h
db 0BCh
db 4
db 5Ch
db 42h
db 0C2h
db 2Eh
db 1Dh
db 0B3h
db 98h
db 0F9h
db 17h
db 0E9h
db 8Bh
db 20h
db 0E9h
db 0E8h
db 2
db 0EEh
db 54h
db 2Ch
db 33h
db 37h
db 57h
db 0C8h
db 51h
db 3Eh
db 4
db 68h
db 0DAh
db 6Eh
db 6Fh
db 7
db 55h
db 57h
db 0AFh
db 20h
db 0C6h
db 62h
db 0F4h
db 71h
db 32h
db 19h
db 0ADh
db 0E4h
db 0EBh
db 0A7h
db 25h
db 0C7h
db 13h
db 0C0h
db 0EFh
db 0FAh
db 47h
db 7Ch
db 94h
db 0D0h
db 38h
db 58h
db 85h
db 83h
db 0AAh
db 0B0h
db 6Bh
db 5Fh
db 0F0h
db 2Ch
db 9
db 32h
db 0A0h
db 0B6h
db 0BCh
db 74h
db 0C3h
db 6
db 0D6h
db 6Ah
db 0F0h
db 0FEh
db 0F1h
db 0CFh
db 0C2h
db 0D3h
db 0CFh
db 6Fh
db 36h
db 2Eh
db 6Eh
db 0BDh
db 0FAh
db 0EFh
db 6Fh
db 0Bh
db 3Eh
db 0B3h
db 0BAh
db 0E6h
db 79h
db 18h
db 71h
db 0F4h
db 76h
db 0C6h
db 8Ah
db 9Bh
db 0B6h
db 3
db 22h
db 0EEh
db 0CEh
db 25h
db 50h
db 81h
db 41h
db 0ADh
db 0B2h
db 65h
db 4Fh
db 3Ch
db 33h
db 7Bh
db 1Dh
db 0Bh
db 16h
db 0B1h
db 28h
db 0C7h
db 69h
db 82h
db 55h
db 34h
db 45h
db 90h
db 19h
db 5Bh
db 9Bh
db 55h
db 5Ch
db 16h
db 9Fh
db 63h
db 13h
db 0C5h
db 0F5h
db 68h
db 0EAh
db 0B1h
db 2Bh
db 0B2h
db 6Eh
db 9Eh
db 79h
db 0B4h
db 99h
db 7Ah
db 2Fh
db 9Eh
db 0A7h
db 31h
db 68h
db 62h
db 11h
db 28h
db 0F8h
db 9Bh
db 7Fh
db 2Fh
db 74h
db 67h
db 0FAh
db 36h
db 86h
db 7Fh
db 71h
db 42h
db 0A4h
db 14h
db 0E8h
db 41h
db 0FCh
db 0Bh
db 5
db 8Ah
db 0BDh
db 0C1h
db 82h
db 57h
db 0F4h
db 0C1h
db 43h
db 24h
db 0Fh
db 63h
db 29h
db 0A4h
db 0D8h
db 3Ch
db 9Ah
db 21h
db 35h
db 34h
db 7Ah
db 8Ah
db 2Ah
db 1Eh
db 3Fh
db 24h
db 69h
db 80h
db 65h
db 0Ch
db 0D5h
db 4Fh
db 32h
db 8Ah
db 65h
db 35h
db 0E3h
db 94h
db 0A9h
db 9Fh
db 0DAh
db 0C7h
db 12h
db 8Dh
db 8Bh
db 9Fh
db 75h
db 3Ch
db 3Bh
db 0B5h
db 0F7h
db 0DDh
db 0E0h
db 0BDh
db 6Bh
db 3Bh
db 91h
db 0EEh
db 32h
db 31h
db 78h
db 62h
db 0F5h
db 87h
db 0DDh
db 4Dh
db 77h
db 7
db 0D1h
db 0Fh
db 0D0h
db 34h
db 0C5h
db 0ACh
db 0D4h
db 0E1h
db 11h
db 0F9h
db 3Bh
db 5Bh
db 0B8h
db 3Dh
db 26h
db 0FDh
db 10h
db 84h
db 2Dh
db 0FEh
db 0E4h
db 0D4h
db 97h
db 0E2h
db 0E3h
db 0D6h
db 65h
db 0E2h
db 67h
db 15h
db 0F1h
db 0D9h
db 72h
db 0B9h
db 2Eh
db 0DCh
db 7Fh
db 0CBh
db 27h
db 9Dh
db 7
db 0ECh
db 24h
db 9Ch
db 0BEh
db 68h
db 0C4h
db 34h
db 62h
db 0C6h
db 45h
db 0D1h
db 0EAh
db 8Fh
db 6Eh
db 0F1h
db 0E0h
db 92h
db 34h
db 1Ah
db 0B6h
db 36h
db 70h
db 0C3h
db 0C1h
db 7
db 0E4h
db 24h
db 0DAh
db 0A9h
db 5Fh
db 4Ah
db 0E4h
db 8Ch
db 41h
db 0C0h
db 0A4h
db 3Fh
db 73h
db 1Bh
db 23h
db 0F5h
db 51h
db 45h
db 80h
db 52h
db 4
db 0EAh
db 3Eh
db 96h
db 0ECh
db 26h
db 0F9h
db 3Fh
db 14h
db 0FEh
db 10h
db 85h
db 93h
db 9Fh
db 83h
db 2
db 6
db 17h
db 41h
db 53h
db 0DEh
db 0A0h
db 27h
db 44h
db 44h
db 50h
db 84h
db 0F8h
db 0D8h
db 80h
db 55h
db 38h
db 0D8h
db 0C7h
db 1Ch
db 81h
db 0D7h
db 7Bh
db 59h
db 97h
db 0F8h
db 55h
db 0A4h
db 0CBh
db 46h
db 43h
db 2Bh
db 2Fh
db 6Eh
db 64h
db 0E3h
db 0FCh
db 4Ch
db 5Ah
db 0C5h
db 38h
db 33h
db 4Ch
db 0BBh
db 0BEh
db 50h
db 7Ch
db 1Fh
db 0D0h
db 0F3h
db 0B2h
db 0ACh
db 93h
db 3Bh
db 57h
db 84h
db 0F5h
db 0C2h
db 6Eh
db 0B5h
db 1Fh
db 0E2h
db 38h
db 0C2h
db 1Bh
db 0D4h
db 0B8h
db 82h
db 4Ah
db 2Eh
db 6Ch
db 0Bh
db 5Ah
db 5
db 0C3h
db 1Ch
db 0A8h
db 0F1h
db 0BCh
db 0B1h
db 3Fh
db 72h
db 73h
db 0C6h
db 0D8h
db 1Dh
db 0DBh
db 66h
db 84h
db 66h
db 0C5h
db 45h
db 7Bh
db 95h
db 29h
db 2
db 0E6h
db 58h
db 81h
db 7
db 3
db 0D6h
db 7Ah
db 0C5h
db 16h
db 0C4h
db 0Bh
db 83h
db 70h
db 0B9h
db 0BDh
db 0ACh
db 51h
db 13h
db 0FEh
db 0B6h
db 5Ah
db 0DCh
db 52h
db 89h
db 8Dh
db 7Dh
db 5Ch
db 0FDh
db 8Ch
db 14h
db 9Bh
db 0A3h
db 94h
db 0E6h
db 85h
db 7Fh
db 3
db 64h
db 49h
db 3
db 0DFh
db 0BFh
db 0C0h
db 0F3h
db 0B8h
db 59h
db 25h
db 60h
db 58h
db 0CBh
db 0
db 60h
db 68h
db 0F7h
db 3Ch
db 6Ah
db 0BCh
db 65h
db 53h
db 0D7h
db 34h
db 0ECh
db 0ABh
db 0F4h
db 0B6h
db 49h
db 0CBh
db 0ECh
db 0BCh
db 2Ah
db 98h
db 0A7h
db 7Ch
db 0E4h
db 0B2h
db 0F0h
db 0C5h
db 39h
db 0Ch
db 0BBh
db 43h
db 0D4h
db 85h
db 69h
db 83h
db 3Ch
db 0F2h
db 48h
db 80h
db 9Dh
db 40h
db 6Ah
db 3
db 0EAh
db 3Fh
db 33h
db 24h
db 2Bh
db 52h
db 0D1h
db 0D7h
db 1Eh
db 49h
db 6Fh
db 0BFh
db 6Ch
db 0B2h
db 83h
db 9Dh
db 0E6h
db 47h
db 32h
db 0DDh
db 58h
db 0D8h
db 90h
db 8Ch
db 0A6h
db 0A1h
db 30h
db 0F6h
db 20h
db 42h
db 0C0h
db 9Eh
db 96h
db 76h
db 0C6h
db 78h
db 16h
db 6Bh
db 8
db 77h
db 0A9h
db 0F3h
db 0A5h
db 3Dh
db 40h
db 97h
db 85h
db 22h
db 0F7h
db 0AAh
db 9Bh
db 42h
db 0A4h
db 0AEh
db 44h
db 5Ah
db 89h
db 4Ch
db 9Dh
db 69h
db 0A4h
db 0DBh
db 0FEh
db 0Dh
db 56h
db 0Dh
db 0C1h
db 0C8h
db 0B8h
db 0C0h
db 0EEh
db 9Ah
db 0D8h
db 0AEh
db 54h
db 16h
db 0F2h
db 0ACh
db 0F7h
db 27h
db 6Eh
db 1Eh
db 0BFh
db 6Ch
db 0EAh
db 8
db 5
db 95h
db 7Fh
db 11h
db 0D7h
db 7Eh
db 0Ch
db 95h
db 8Eh
db 88h
db 60h
db 0B2h
db 0EEh
db 0C4h
db 3Fh
db 2Dh
db 1Eh
db 0CBh
db 0A1h
db 9Dh
db 0DDh
db 4Dh
db 8
db 2Ah
db 6Eh
db 51h
db 0AFh
db 31h
db 0EAh
db 50h
db 0F6h
db 81h
db 24h
db 0D2h
db 0F6h
db 93h
db 0D6h
db 59h
db 8
db 6Bh
db 0A4h
db 40h
db 41h
db 0FAh
db 2Ch
db 8Ah
db 2Fh
db 0E3h
db 0DEh
db 0B5h
db 0C5h
db 0DBh
db 0Dh
db 40h
db 69h
db 85h
db 74h
db 8Bh
db 89h
db 0D2h
db 36h
db 0B3h
db 0EAh
db 96h
db 8Bh
db 51h
db 0B9h
db 64h
db 9Ah
db 79h
db 17h
db 0FFh
db 0B2h
db 8Bh
db 0B3h
db 2Fh
db 6Fh
db 6Bh
db 25h
db 0EBh
db 8Bh
db 37h
db 0CCh
db 93h
db 0A1h
db 0F0h
db 1Fh
db 1Ch
db 0C8h
db 67h
db 69h
db 63h
db 4Eh
db 52h
db 67h
db 99h
db 2Eh
db 0B9h
db 68h
db 25h
db 0B6h
db 0F8h
db 91h
db 0E1h
db 16h
db 99h
db 21h
db 0E1h
db 84h
db 15h
db 0D3h
db 68h
db 32h
db 0FBh
db 0EAh
db 0F5h
db 0ADh
db 24h
db 0E2h
db 0D9h
db 72h
db 9Ch
db 0EFh
db 27h
db 60h
db 98h
db 0FCh
db 0D0h
db 36h
db 0AAh
db 0B5h
db 0D2h
db 0E7h
db 7Ch
db 93h
db 58h
db 3Ah
db 22h
db 56h
db 0
db 56h
db 0C8h
db 0BAh
db 0DCh
db 28h
db 58h
db 3
db 76h
db 6Bh
db 0DEh
db 23h
db 5Fh
db 89h
db 5Dh
db 0B3h
db 5Dh
db 0EDh
db 98h
db 0CAh
db 31h
db 0Ch
db 0E8h
db 0C7h
db 2Fh
db 22h
db 64h
db 3Dh
db 66h
db 9
db 0E4h
db 86h
db 7Ch
db 30h
db 0CAh
db 0A6h
db 0FDh
db 29h
db 41h
db 0BFh
db 0D6h
db 13h
db 7Dh
db 0B4h
db 17h
db 0CAh
db 94h
db 21h
db 29h
db 63h
db 9Ch
db 0A4h
db 90h
db 5Eh
db 0A6h
db 26h
db 50h
db 0D3h
db 0D4h
db 0F4h
db 4Fh
db 46h
db 2Ch
db 3Ch
db 0C0h
db 0Eh
db 44h
db 6Ah
db 0E3h
db 77h
db 5
db 0C8h
db 0E1h
db 56h
db 27h
db 0D3h
db 0
db 0FFh
db 2Bh
db 0D9h
db 27h
db 64h
db 0F8h
db 0A9h
db 8Eh
db 0CDh
db 0FDh
db 0FEh
db 86h
db 40h
db 1Ch
db 44h
db 11h
db 0A6h
db 55h
db 56h
db 0BCh
db 56h
db 6Fh
db 23h
db 0B5h
db 0A7h
db 7Fh
db 0B5h
db 41h
db 89h
db 0C3h
db 66h
db 0B4h
db 5Fh
db 2Bh
db 0Bh
db 3Ah
db 0E1h
db 58h
db 0AAh
db 9Bh
db 96h
db 53h
db 7Ch
db 3Fh
db 0C3h
db 45h
db 0EFh
db 64h
db 65h
db 25h
db 3
db 0EDh
db 0E9h
db 0E6h
db 9
db 0F1h
db 0F4h
db 29h
db 31h
db 3Dh
db 79h
db 9Bh
db 0B2h
db 6Eh
db 5Bh
db 0D3h
db 59h
db 4Ah
db 41h
db 5Ch
db 0B5h
db 1Fh
db 0BFh
db 52h
db 0E5h
db 57h
db 0D3h
db 4Dh
db 10h
db 0C9h
db 31h
db 52h
db 75h
db 89h
db 0DAh
db 49h
db 9Ah
db 0DAh
db 0Dh
db 65h
db 92h
db 9Ah
db 0D2h
db 49h
db 74h
db 2Bh
db 60h
db 0F5h
db 85h
db 0C1h
db 4Ch
db 30h
db 74h
db 6Dh
db 79h
db 0CAh
db 0DBh
db 0BEh
db 1Ah
db 21h
db 3Eh
db 79h
db 0Ah
db 7
db 2Ah
db 0Ch
db 0D4h
db 3Ch
db 0CAh
db 2Bh
db 0E9h
db 69h
db 0F1h
db 0E0h
db 0A8h
db 0DEh
db 0C9h
db 9Bh
db 0F7h
db 8Ah
db 0Bh
db 8
db 67h
db 47h
db 32h
db 41h
db 6Ch
db 62h
db 0B2h
db 25h
db 2Ah
db 99h
db 45h
db 0C3h
db 0E7h
db 0Eh
db 0AAh
db 94h
db 92h
db 0BCh
db 0B6h
db 4Ah
db 95h
db 7Ah
db 13h
db 2Dh
db 5Dh
db 0E9h
db 44h
db 4Ch
db 9Fh
db 66h
db 15h
db 40h
db 0B1h
db 77h
db 0C7h
db 7Fh
db 0FBh
db 6Dh
db 52h
db 6Eh
db 0EAh
db 6Fh
db 92h
db 97h
db 0F8h
db 54h
db 0D4h
db 0B1h
db 42h
db 34h
db 50h
db 7Eh
db 1Ah
db 64h
db 16h
db 0C0h
db 2Ch
db 0ECh
db 3Fh
db 0AFh
db 0
db 2Bh
db 0DEh
db 7
db 3Fh
db 0C8h
db 3Bh
db 80h
db 0B4h
db 45h
db 33h
db 69h
db 0FAh
db 0D1h
db 0A3h
db 68h
db 0DAh
db 1Eh
db 86h
db 0B5h
db 43h
db 45h
db 19h
db 0D1h
db 34h
db 0E2h
db 62h
db 8Ch
db 45h
db 0E6h
db 6Fh
db 0C0h
db 0D6h
db 0C2h
db 0A1h
db 32h
db 0CDh
db 43h
db 0C8h
db 5Ch
db 57h
db 5
db 93h
db 48h
db 63h
db 90h
db 0D9h
db 0B1h
db 0A3h
db 0DEh
db 2Fh
db 0C4h
db 0BDh
db 49h
db 21h
db 23h
db 93h
db 0C2h
db 0EFh
db 29h
db 2Fh
db 92h
db 94h
db 0E7h
db 7
db 9Fh
db 51h
db 9Ch
db 18h
db 0D9h
db 44h
db 0CAh
db 4Bh
db 6Eh
db 41h
db 32h
db 9Dh
db 0BBh
db 7Ah
db 0AAh
db 34h
db 0EBh
db 0D6h
db 0CDh
db 0DDh
db 0ADh
db 0C3h
db 95h
db 4Ah
db 0F7h
db 95h
db 0A5h
db 2
db 24h
db 0CEh
db 34h
db 0D6h
db 0DFh
db 61h
db 11h
db 0FFh
db 2Ah
db 0F4h
db 8Ch
db 38h
db 0E3h
db 71h
db 0FDh
db 0C1h
db 26h
db 3
db 0D0h
db 0B7h
db 49h
db 6Ah
db 3Eh
db 5Eh
db 0Ch
db 0AAh
db 7Bh
db 72h
db 0B4h
db 9Ch
db 0EBh
db 0FEh
db 2Fh
db 0F7h
db 72h
db 1
db 4Bh
db 6Ch
db 35h
db 0CAh
db 41h
db 0BEh
db 99h
db 7Dh
db 9Ah
db 0CAh
db 61h
db 33h
db 99h
db 0DDh
db 72h
db 0Ch
db 0F1h
db 49h
db 1Fh
db 0C2h
db 57h
db 0C7h
db 0BDh
db 96h
db 68h
db 45h
db 8Ah
db 94h
db 13h
db 0E4h
db 95h
db 0EBh
db 28h
db 0FCh
db 10h
db 0CBh
db 7Eh
db 0F7h
db 0DEh
db 34h
db 96h
db 0B1h
db 2Fh
db 3
db 76h
db 24h
db 72h
db 38h
db 0B6h
db 2
db 46h
db 89h
db 4
db 0F0h
db 62h
db 7
db 51h
db 78h
db 2Fh
db 0D4h
db 0Ch
db 0CDh
db 35h
db 0A0h
db 78h
db 25h
db 0E9h
db 78h
db 0BEh
db 44h
db 0CFh
db 0C0h
db 68h
db 7Ah
db 0C8h
db 5Eh
db 0B4h
db 73h
db 57h
db 23h
db 57h
db 3Ch
db 0F9h
db 0CCh
db 0A6h
db 74h
db 50h
db 0Ch
db 0Dh
db 0FFh
db 8Fh
db 72h
db 32h
db 0C3h
db 0B3h
db 14h
db 96h
db 3Fh
db 94h
db 0E4h
db 88h
db 3Dh
db 0DAh
db 1Ch
db 8Bh
db 0Dh
db 0E9h
db 86h
db 65h
db 54h
db 0E8h
db 8Ch
db 0E0h
db 60h
db 41h
db 0CAh
db 0E0h
db 5Ah
db 0A5h
db 34h
db 0C0h
db 48h
db 5Fh
db 0AEh
db 53h
db 0F4h
db 6
db 22h
db 81h
db 26h
db 0Ah
db 64h
db 2Ch
db 0CAh
db 0DBh
db 0CFh
db 0D3h
db 0C8h
db 0B0h
db 39h
db 43h
db 0EBh
db 0F1h
db 3Ah
db 0B3h
db 5Ah
db 4Dh
db 72h
db 64h
db 0B3h
db 0C6h
db 0B7h
db 80h
db 0D8h
db 0D4h
db 59h
db 19h
db 0EDh
db 6Bh
db 0CFh
db 43h
db 81h
db 0D4h
db 7
db 0AAh
db 0DEh
db 47h
db 8Ah
db 9Ch
db 7
db 18h
db 84h
db 0D6h
db 0C7h
db 85h
db 59h
db 0F7h
db 0A3h
db 25h
db 47h
db 0A0h
db 0ABh
db 0FAh
db 57h
db 41h
db 0FAh
db 40h
db 6Ch
db 45h
db 69h
db 4Bh
db 4Dh
db 92h
db 5
db 8Fh
db 5Ch
db 0B9h
db 19h
db 57h
db 0CDh
db 48h
db 94h
db 0D6h
db 0A5h
db 0C2h
db 0EAh
db 0CEh
db 9
db 5Dh
db 9Fh
db 0A7h
db 64h
db 0D2h
db 0B5h
db 6Ch
db 22h
db 4Eh
db 0E4h
db 0ACh
db 10h
db 0C0h
db 1Ah
db 3
db 7
db 0E7h
db 48h
db 0C3h
db 65h
db 0A7h
db 0DEh
db 0CFh
db 7Dh
db 11h
db 26h
db 0B7h
db 9
db 3Fh
db 8Ah
db 0D7h
db 18h
db 5Ch
db 5Bh
db 91h
db 0DBh
db 0A5h
db 27h
db 1Dh
db 0CDh
db 0F7h
db 0B9h
db 84h
db 7Ah
db 75h
db 3Dh
db 0CDh
db 64h
db 0D8h
db 72h
db 0CDh
db 0DAh
db 2
db 9Ch
db 8
db 21h
db 98h
db 4
db 6Fh
db 0BFh
db 0F2h
db 7Eh
db 3Dh
db 9Eh
db 3Dh
db 0Bh
db 7Ah
db 79h
db 34h
db 24h
db 35h
db 9Eh
db 45h
db 7Bh
db 20h
db 88h
db 6
db 99h
db 0DCh
db 9Dh
db 0E5h
db 18h
db 0ADh
db 17h
db 6Bh
db 0E5h
db 94h
db 0BAh
db 94h
db 0EEh
db 85h
db 0A6h
db 0D8h
db 24h
db 8Ah
db 0EAh
db 41h
db 0E4h
db 52h
db 7Fh
db 0EEh
db 33h
db 9Eh
db 5Dh
db 0E9h
db 0D7h
db 3Ah
db 0F2h
db 69h
db 2Ah
db 83h
db 9Dh
db 43h
db 0F0h
db 0E3h
db 9Eh
db 33h
db 9Fh
db 86h
db 0B5h
db 83h
db 90h
db 3Bh
db 74h
db 0C3h
db 70h
db 32h
db 5Ah
db 0A3h
db 65h
db 0Eh
db 0CFh
db 81h
db 0AFh
db 38h
db 0F8h
db 0F1h
db 0A5h
db 0F3h
db 63h
db 10h
db 22h
db 0CEh
db 2Ah
db 7Ch
db 0A1h
db 7Dh
db 55h
db 81h
db 0C5h
db 33h
db 0A2h
db 0F1h
db 64h
db 0D2h
db 0DCh
db 82h
db 0FBh
db 0F4h
db 5
db 89h
db 1Fh
db 19h
db 0DDh
db 7Eh
db 62h
db 4Ah
db 3Fh
db 0AEh
db 25h
db 0DFh
db 32h
db 0FAh
db 90h
db 0B4h
db 0DDh
db 11h
db 0A1h
db 0ACh
db 71h
db 3Eh
db 4Dh
db 0D3h
db 6Fh
db 0Fh
db 7Eh
db 62h
db 80h
db 0ECh
db 0CCh
db 0FEh
db 0Dh
db 4Ch
db 8Dh
db 0FAh
db 46h
db 2Eh
db 57h
db 0B3h
db 44h
db 0C0h
db 0B3h
db 70h
db 8Eh
db 2
db 0DEh
db 0E2h
db 7Bh
db 45h
db 0BBh
db 0C1h
db 94h
db 0A4h
db 0A5h
db 1Fh
db 28h
db 69h
db 0A5h
db 2
db 6Dh
db 9Eh
db 0DCh
db 0D4h
db 79h
db 79h
db 0D7h
db 13h
db 90h
db 0BDh
db 0F4h
db 73h
db 0C1h
db 9Dh
db 0C9h
db 64h
db 1
db 0C8h
db 22h
db 66h
db 0EBh
db 6Eh
db 37h
db 54h
db 9Ch
db 0Eh
db 1Fh
db 0A6h
db 67h
db 0A9h
db 0AFh
db 0E4h
db 0AFh
db 0FEh
db 0DCh
db 61h
db 9Fh
db 21h
db 43h
db 47h
db 0C3h
db 0ACh
db 37h
db 33h
db 0BBh
db 0E3h
db 8
db 0C0h
db 0C2h
db 0E4h
db 71h
db 0EAh
db 0F9h
db 0E7h
db 64h
db 0DEh
db 6Fh
db 9Fh
db 52h
db 69h
db 0B1h
db 55h
db 0B7h
db 0DEh
db 7Dh
db 0B3h
db 28h
db 0F4h
db 21h
db 8Dh
db 9Ch
db 8Bh
db 8
db 7Eh
db 78h
db 12h
db 0B1h
db 0DFh
db 9Dh
db 6Bh
db 9Dh
db 78h
db 0FFh
db 60h
db 99h
db 0B9h
db 8Eh
db 28h
db 0D4h
db 0A3h
db 1
db 7Eh
db 22h
db 60h
db 3Fh
db 1Ch
db 14h
db 53h
db 26h
db 0E0h
db 0ABh
db 93h
db 9Ch
db 2Fh
db 16h
db 0FBh
db 25h
db 2Fh
db 0CAh
db 10h
db 0C1h
db 33h
db 1
db 53h
db 0D9h
db 85h
db 0DCh
db 0EFh
db 0D9h
db 23h
db 53h
db 0BDh
db 0FEh
db 6Fh
db 0A3h
db 0DFh
db 77h
db 18h
db 0DBh
db 2
db 0B0h
db 0CDh
db 0C7h
db 73h
db 0B2h
db 0F5h
db 5Ah
db 0DAh
db 0
db 2Fh
db 8Bh
db 4Fh
db 39h
db 0F0h
db 0A9h
db 74h
db 0Ch
db 0FAh
db 69h
db 4Bh
db 52h
db 0E3h
db 7Ch
db 73h
db 7Ah
db 6Bh
db 81h
db 0CEh
db 0E6h
db 98h
db 60h
db 0F5h
db 39h
db 0E1h
db 0CCh
db 7
db 81h
db 4Eh
db 0EFh
db 48h
db 0AEh
db 11h
db 3Ah
db 51h
db 6Eh
db 8Eh
db 6Ah
db 6Bh
db 35h
db 71h
db 7Dh
db 0C6h
db 0D8h
db 2Fh
db 4Fh
db 8Dh
db 1Ah
db 2Ch
db 0D2h
db 0C2h
db 52h
db 0D8h
db 8Ch
db 40h
db 82h
db 2Eh
db 0BFh
db 73h
db 9Bh
db 63h
db 0D4h
db 1Ch
db 3Eh
db 5Bh
db 9Bh
db 0E7h
db 7Bh
db 0F8h
db 0E5h
db 0C0h
db 17h
db 0E6h
db 1Ch
db 1
db 99h
db 0EAh
db 97h
db 0D4h
db 5Ch
db 96h
db 0E0h
db 0F0h
db 0DDh
db 28h
db 55h
db 56h
db 6Ch
db 0C8h
db 6Ah
db 0DFh
db 57h
db 2Ah
db 0B0h
db 61h
db 0A0h
db 54h
db 24h
db 0E7h
db 3Eh
db 52h
db 6Eh
db 4Dh
db 21h
db 6Ch
db 76h
db 32h
db 35h
db 5
db 0B8h
db 8Ah
db 0FDh
db 17h
db 1Bh
db 0BEh
db 88h
db 11h
db 24h
db 1
db 59h
db 1
db 39h
db 0B7h
db 3Eh
db 87h
db 67h
db 8
db 0F4h
db 0B1h
db 2Ch
db 27h
db 0F8h
db 17h
db 34h
db 30h
db 51h
db 0F0h
db 6Ah
db 0B8h
db 0Dh
db 0BBh
db 9Bh
db 0CDh
db 97h
db 10h
db 0FEh
db 0CEh
db 86h
db 4Fh
db 0C9h
db 55h
db 0B0h
db 0AEh
db 46h
db 4Bh
db 0AFh
db 1
db 34h
db 0F6h
db 0B3h
db 53h
db 66h
db 0AFh
db 8
db 5Dh
db 37h
db 0A3h
db 4
db 0FEh
db 0E2h
db 0C5h
db 2Bh
db 0A7h
db 73h
db 8Dh
db 87h
db 6
db 6
db 83h
db 93h
db 41h
db 3
db 0ADh
db 0D5h
db 0ABh
db 9Dh
db 53h
db 34h
db 0D6h
db 42h
db 22h
db 65h
db 9
db 0E9h
db 89h
db 29h
db 10h
db 0F7h
db 6Ah
db 1Eh
db 0F7h
db 37h
db 0A2h
db 61h
db 0A3h
db 35h
db 0E6h
db 0C5h
db 2
db 0AEh
db 0B8h
db 0F7h
db 21h
db 41h
db 64h
db 0FDh
db 58h
db 57h
db 3Ch
db 0DEh
db 0D5h
db 0C8h
db 7Fh
db 9Dh
db 58h
db 0BFh
db 1Ch
db 0A0h
db 0ABh
db 61h
db 7Dh
db 9Eh
db 73h
db 72h
db 0B0h
db 22h
db 0F8h
db 0E8h
db 2Fh
db 52h
db 0F2h
db 77h
db 5Eh
db 0E6h
db 66h
db 0F5h
db 0EBh
db 21h
db 0E2h
db 0E2h
db 7Bh
db 96h
db 3Dh
db 0F5h
db 8
db 29h
db 20h
db 0BDh
db 87h
db 8Bh
db 87h
db 0D8h
db 0F5h
db 5
db 0B7h
db 0B4h
db 0Fh
db 36h
db 17h
db 9Ch
db 38h
db 0A9h
db 7Dh
db 40h
db 0B1h
db 6
db 42h
db 2Fh
db 33h
db 4Bh
db 24h
db 56h
db 0C4h
db 0DCh
db 2Dh
db 88h
db 0A3h
db 90h
db 47h
db 62h
db 3Ah
db 52h
db 60h
db 0Dh
db 9Dh
db 0C2h
db 9Dh
db 0B9h
db 3Eh
db 0D4h
db 5Bh
db 50h
db 8Bh
db 50h
db 0CFh
db 0A9h
db 3Eh
db 0C0h
db 2Dh
db 80h
db 0E8h
db 0A8h
db 0D3h
db 0AEh
db 88h
db 40h
db 51h
db 63h
db 73h
db 0C2h
db 0B8h
db 71h
db 4Dh
db 0E2h
db 0DAh
db 0DEh
db 25h
db 1Ch
db 1Fh
db 13h
db 0D7h
db 20h
db 0B2h
db 0CEh
db 0B9h
db 0B0h
db 0F8h
db 0EFh
db 89h
db 6Ch
db 21h
db 0D0h
db 9
db 4Ah
db 1
db 27h
db 0
db 53h
db 18h
db 0D8h
db 0CAh
db 72h
db 0B9h
db 7Fh
db 0B7h
db 2Ah
db 0CFh
db 91h
db 7Fh
db 0D9h
db 9
db 0Bh
db 5Ah
db 0C2h
db 0F5h
db 5Dh
db 4Fh
db 0E7h
db 55h
db 0D7h
db 0B4h
db 22h
db 0B2h
db 15h
db 0DEh
db 7Fh
db 7Bh
db 0Fh
db 0DBh
db 40h
db 4
db 86h
db 67h
db 0C2h
db 0F5h
db 8
db 0C0h
db 0B1h
db 0EBh
db 21h
db 46h
db 0CFh
db 83h
db 7Dh
db 0DAh
db 34h
db 93h
db 8
db 2Ch
db 3Bh
db 96h
db 0A2h
db 90h
db 0F9h
db 0D4h
db 99h
db 2Fh
db 24h
db 56h
db 79h
db 89h
db 0D1h
db 0EAh
db 39h
db 0FDh
db 17h
db 0D6h
db 0BEh
db 23h
db 0ADh
db 0B8h
db 49h
db 59h
db 9
db 8Dh
db 0BFh
db 0E7h
db 0F7h
db 20h
db 3Fh
db 81h
db 0C9h
db 22h
db 62h
db 0E4h
db 11h
db 88h
db 49h
db 3
db 0A1h
db 11h
db 4Ah
db 6Fh
db 0BFh
db 71h
db 0D5h
db 0CAh
db 40h
db 0CBh
db 0C6h
db 0B9h
db 0F3h
db 21h
db 43h
db 0E1h
db 8Fh
db 50h
db 0F0h
db 58h
db 14h
db 0C8h
db 7Ah
db 0E7h
db 41h
db 8Dh
db 72h
db 8Eh
db 8Bh
db 96h
db 0AEh
db 0D3h
db 3Eh
db 97h
db 70h
db 0Eh
db 0B5h
db 0F1h
db 60h
db 29h
db 59h
db 86h
db 9Fh
db 77h
db 1Ch
db 0F8h
db 0E9h
db 63h
db 0CAh
db 0E8h
db 0C6h
db 8Eh
db 90h
db 7Ah
db 0E3h
db 0E7h
db 25h
db 4
db 1
db 6Eh
db 0
db 4Fh
db 0A9h
db 3Dh
db 0DEh
db 3Dh
db 94h
db 0B5h
db 0F7h
db 0E5h
db 0A4h
db 1Fh
db 62h
db 0Dh
db 0D5h
db 7Fh
db 1Eh
db 0A8h
db 4Ah
db 66h
db 0D5h
db 1Ah
db 0C9h
db 46h
db 59h
db 5
db 0DCh
db 47h
db 71h
db 0DAh
db 75h
db 74h
db 65h
db 8
db 3Ah
db 0
db 0E9h
db 26h
db 44h
db 50h
db 9Ah
db 3Eh
db 95h
db 14h
db 4Ah
db 5Ah
db 5Ch
db 0DDh
db 1Ch
db 0A3h
db 0BAh
db 2Eh
db 93h
db 0E4h
db 0DDh
db 0E4h
db 0ECh
db 0B0h
db 0D0h
db 89h
db 21h
db 0B2h
db 0A7h
db 0A1h
db 56h
db 66h
db 0B3h
db 33h
db 7Dh
db 6Dh
db 30h
db 55h
db 6Dh
db 0EAh
db 56h
db 75h
db 0BAh
db 1Ah
db 0DFh
db 6Ah
db 71h
db 0C1h
db 80h
db 59h
db 6Dh
db 84h
db 0C2h
db 87h
db 0ABh
db 93h
db 0Eh
db 61h
db 0E2h
db 65h
db 97h
db 0E8h
db 65h
db 0BDh
db 0DCh
db 8Eh
db 0F2h
db 0E3h
db 92h
db 0C5h
db 0CCh
db 7Ah
db 8Ch
db 0CEh
db 0E8h
db 3Bh
db 47h
db 28h
db 79h
db 15h
db 95h
db 0DCh
db 3
db 0B3h
db 4Ch
db 79h
db 0E3h
db 0CFh
db 8Bh
db 52h
db 35h
db 0F3h
db 87h
db 65h
db 4Fh
db 8Ah
db 0C4h
db 0CAh
db 60h
db 0A5h
db 10h
db 8Ch
db 0A8h
db 0B1h
db 3Dh
db 0Bh
db 60h
db 21h
db 0A6h
db 45h
db 42h
db 8Ch
db 1Dh
db 4Ah
db 4Fh
db 0FCh
db 41h
db 0E7h
db 0Ah
db 8Fh
db 91h
db 0A0h
db 93h
db 94h
db 0B7h
db 5Ah
db 98h
db 3Dh
db 2Bh
db 0A3h
db 74h
db 8Eh
db 0F6h
db 18h
db 3Dh
db 8
db 0AFh
db 46h
db 87h
db 0D6h
db 7Dh
db 1Dh
db 88h
db 0DEh
db 94h
db 0B0h
db 15h
db 40h
db 57h
db 12h
db 73h
db 68h
db 0BEh
db 95h
db 93h
db 0F7h
db 0C6h
db 9Bh
db 4Bh
db 2
db 0Eh
db 0B5h
db 21h
db 73h
db 6Ch
db 16h
db 11h
db 0A7h
db 81h
db 0DFh
db 0D5h
db 0EDh
db 9
db 0A0h
db 36h
db 7Fh
db 0D5h
db 6Ah
db 6Fh
db 17h
db 43h
db 7Fh
db 74h
db 77h
db 0FBh
db 0D2h
db 0E1h
db 5Bh
db 89h
db 4Eh
db 0CAh
db 17h
db 22h
db 9Ch
db 0E2h
db 0C8h
db 7
db 2Eh
db 0DFh
db 7Bh
db 0D0h
db 6Eh
db 98h
db 6Dh
db 0B4h
db 6Ah
db 0A5h
db 0BFh
db 0C6h
db 0FFh
db 0C3h
db 0A8h
db 4Fh
db 7Dh
db 0C9h
db 50h
db 0BEh
db 0F7h
db 39h
db 57h
db 54h
db 25h
db 0C6h
db 0E5h
db 4Dh
db 99h
db 11h
db 10h
db 33h
db 75h
db 8Fh
db 0C4h
db 70h
db 96h
db 3Ah
db 8Bh
db 0B3h
db 9
db 0CBh
db 37h
db 0F2h
db 0ADh
db 3Bh
db 0C0h
db 2
db 0BFh
db 5Ch
db 6Ah
db 72h
db 2Bh
db 25h
db 68h
db 90h
db 68h
db 0C0h
db 21h
db 55h
db 1Fh
db 11h
db 72h
db 6Dh
db 0FDh
db 1Ch
db 9Bh
db 27h
db 41h
db 50h
db 5Ah
db 63h
db 9Eh
db 84h
db 5Ch
db 72h
db 58h
db 0F7h
db 20h
db 0C8h
db 0A5h
db 0F3h
db 0CFh
db 24h
db 5Ah
db 16h
db 0F8h
db 12h
db 53h
db 0FEh
db 5Dh
db 7
db 0B7h
db 86h
db 0EAh
db 20h
db 0BBh
db 0B9h
db 0B4h
db 2Fh
db 6Dh
db 0E1h
db 0E0h
db 0CEh
db 47h
db 4Ch
db 0B7h
db 0E3h
db 51h
db 0A6h
db 0EFh
db 1Dh
db 52h
db 4Dh
db 55h
db 19h
db 0A8h
db 67h
db 31h
db 78h
db 0C5h
db 0D0h
db 66h
db 0ACh
db 0A1h
db 3Bh
db 4Fh
db 0FFh
db 58h
db 0C4h
db 0A0h
db 9Bh
db 37h
db 81h
db 9Fh
db 0ECh
db 22h
db 6Fh
db 3Dh
db 0B2h
db 0E1h
db 45h
db 0A6h
db 0F2h
db 0C8h
db 0DCh
db 68h
db 0B2h
db 35h
db 4Bh
db 28h
db 0ECh
db 4Dh
db 6Ah
db 0A8h
db 48h
db 0E0h
db 0
db 59h
db 77h
db 28h
db 0A6h
db 6Bh
db 72h
db 1Bh
db 99h
db 97h
db 2Dh
db 0D9h
db 0C5h
db 5Ch
db 27h
db 86h
db 67h
db 19h
db 0E3h
db 0E4h
db 0E7h
db 0F8h
db 3Ch
db 8Dh
db 0DAh
db 9
db 5Fh
db 66h
db 72h
db 0C2h
db 74h
db 0C5h
db 1Dh
db 0FDh
db 84h
db 81h
db 38h
db 6Dh
db 2
db 53h
db 58h
db 4
db 0E1h
db 99h
db 34h
db 76h
db 62h
db 47h
db 0C2h
db 87h
db 65h
db 16h
db 0CAh
db 0Bh
db 0C1h
db 5Fh
db 3Eh
db 76h
db 5Fh
db 0E9h
db 3Eh
db 58h
db 0E7h
db 0DEh
db 0B1h
db 3Ch
db 40h
db 0AAh
db 2Ah
db 4Bh
db 32h
db 30h
db 4Eh
db 12h
db 0AEh
db 0F0h
db 6Ah
db 0DCh
db 81h
db 0E7h
db 0BEh
db 2Ch
db 0CDh
db 2Eh
db 0Bh
db 6Eh
db 0F6h
db 68h
db 34h
db 0ACh
db 0A1h
db 2Bh
db 52h
db 4Bh
db 5Dh
db 54h
db 0E5h
db 7Eh
db 0F2h
db 83h
db 83h
db 0FAh
db 0DEh
db 0BDh
db 0C7h
db 0E9h
db 1Bh
db 3Ah
db 39h
db 0EBh
db 5Dh
db 0F1h
db 1Fh
db 5Fh
db 0A2h
db 3Bh
db 0C1h
db 0E7h
db 0A7h
db 0Bh
db 4
db 3Ah
db 0FDh
db 0ADh
db 3Eh
db 3Eh
db 0EEh
db 0EAh
db 55h
db 3Ch
db 31h
db 20h
db 67h
db 2
db 4Dh
db 0D5h
db 0CDh
db 0F7h
db 7Ah
db 1
db 0DDh
db 0Fh
db 3Eh
db 56h
db 26h
db 0D0h
db 0F7h
db 2Ah
db 95h
db 0CEh
db 45h
db 39h
db 0B8h
db 9Ch
db 6Fh
db 0C4h
db 91h
db 14h
db 3Ah
db 93h
db 0BEh
db 85h
db 2Fh
db 0C1h
db 30h
db 31h
db 34h
db 0B2h
db 0F6h
db 0EBh
db 21h
db 83h
db 89h
db 3
db 2
db 0E4h
db 6Fh
db 1
db 0CAh
db 81h
db 0C5h
db 96h
db 82h
db 68h
db 0CEh
db 0C2h
db 0E8h
db 0EEh
db 34h
db 32h
db 2Fh
db 0B0h
db 0EFh
db 67h
db 2Eh
db 7Dh
db 96h
db 53h
db 0F8h
db 7Dh
db 0E0h
db 0B5h
db 6Fh
db 2Eh
db 4Bh
db 0E7h
db 0C0h
db 0D1h
db 9Fh
db 4Ch
db 78h
db 0B0h
db 35h
db 9Ch
db 9Bh
db 54h
db 71h
db 0E2h
db 4Eh
db 0CEh
db 96h
db 0F5h
db 0F4h
db 0C1h
db 8Eh
db 3Ah
db 0A4h
db 14h
db 37h
db 0F1h
db 74h
db 7Bh
db 0B5h
db 3Ch
db 0B0h
db 96h
db 6Dh
db 1Ah
db 0CCh
db 81h
db 0BBh
db 4
db 95h
db 58h
db 5Dh
db 0A0h
db 0E7h
db 0Ch
db 11h
db 0F6h
db 13h
db 51h
db 2Ah
db 0A9h
db 3Dh
db 9Bh
db 7
db 89h
db 0F6h
db 8Ch
db 6
db 71h
db 7Ch
db 0FCh
db 8Fh
db 0A7h
db 5
db 8
db 0F0h
db 24h
db 0D6h
db 0DBh
db 0C4h
db 0DDh
db 3Dh
db 63h
db 0D8h
db 76h
db 0F4h
db 93h
db 0CDh
db 40h
db 38h
db 83h
db 3Fh
db 78h
db 8Fh
db 0A4h
db 0F3h
db 97h
db 6Eh
db 50h
db 0CEh
db 3Dh
db 6Dh
db 0F6h
db 0A7h
db 0B9h
db 73h
db 0D0h
db 27h
db 0F2h
db 1Bh
db 0E1h
db 49h
db 0DFh
db 84h
db 2Fh
db 14h
db 46h
db 0CEh
db 0E4h
db 0B8h
db 0EFh
db 0ECh
db 46h
db 56h
db 10h
db 4
db 54h
db 2Ah
db 54h
db 4Ch
db 31h
db 90h
db 56h
db 0D9h
db 0A9h
db 9Ah
db 85h
db 9Eh
db 0D8h
db 0FEh
db 0D3h
db 34h
db 0EAh
db 91h
db 0FDh
db 0B5h
db 23h
db 79h
db 0B5h
db 9Dh
db 67h
db 23h
db 0D5h
db 77h
db 0FDh
db 7Ah
db 2Eh
db 0A6h
db 0E1h
db 8Ch
db 0CEh
db 0B8h
db 75h
db 0DFh
db 48h
db 79h
db 56h
db 89h
db 0DAh
db 0F1h
db 0E3h
db 0B7h
db 6Fh
db 95h
db 0ACh
db 50h
db 26h
db 65h
db 0FCh
db 12h
db 14h
db 9Ah
db 71h
db 51h
db 7Eh
db 43h
db 0B3h
db 77h
db 64h
db 8Eh
db 0D1h
db 7Fh
db 15h
db 77h
db 0DFh
db 43h
db 70h
db 2Dh
db 2Eh
db 0E1h
db 81h
db 57h
db 85h
db 8Bh
db 0D2h
db 0EEh
db 3
db 2Ah
db 0ACh
db 4Eh
db 0A4h
db 88h
db 25h
db 97h
db 0E0h
db 0CCh
db 93h
db 92h
db 0C5h
db 3
db 0EBh
db 0C4h
db 5Fh
db 0C9h
db 92h
db 0E6h
db 8
db 0D1h
db 16h
db 0ADh
db 1Ah
db 26h
db 0C1h
db 3Ch
db 0A5h
db 43h
db 66h
db 7Eh
db 0A9h
db 0AAh
db 1
db 4
db 0A3h
db 38h
db 2Bh
db 3
db 15h
db 0Dh
db 7Fh
db 39h
db 0EBh
db 9Ah
db 0ABh
db 9Fh
db 0E4h
db 0ACh
db 76h
db 2Fh
db 0A9h
db 0FCh
db 95h
db 4
db 1Ah
db 0D5h
db 82h
db 2Ch
db 8Dh
db 0ADh
db 0FAh
db 31h
db 0F2h
db 58h
db 3Eh
db 0E4h
db 0F7h
db 0CDh
db 54h
db 4Ah
db 31h
db 0D4h
db 34h
db 0DAh
db 35h
db 13h
db 98h
db 80h
db 0D1h
db 0E1h
db 0D2h
db 0C1h
db 7
db 74h
db 0A5h
db 32h
db 0D5h
db 0DFh
db 24h
db 0EBh
db 19h
db 5
db 88h
db 0A2h
db 2Fh
db 81h
db 90h
db 0F9h
db 0
db 7Eh
db 0A9h
db 1Ch
db 99h
db 0E3h
db 45h
db 0A4h
db 70h
db 0B7h
db 0C2h
db 39h
db 0DDh
db 0F3h
db 28h
db 1
db 0B1h
db 0F3h
db 84h
db 0E1h
db 37h
db 66h
db 74h
db 94h
db 97h
db 0ADh
db 9Ch
db 1
db 34h
db 0BBh
db 0CFh
db 2Eh
db 0E9h
db 5Bh
db 2Ah
db 0CBh
db 92h
db 0F4h
db 0A1h
db 0FAh
db 3
db 65h
db 0F7h
db 0DBh
db 5Ch
db 0C5h
db 0E4h
db 98h
db 0F6h
db 17h
db 7
db 0E3h
db 0D5h
db 73h
db 9Bh
db 87h
db 84h
db 3Ah
db 22h
db 0C9h
db 35h
db 93h
db 10h
db 0E9h
db 0BBh
db 0A5h
db 0E7h
db 0E5h
db 0D4h
db 27h
db 1Fh
db 7Eh
db 43h
db 36h
db 0D3h
db 93h
db 56h
db 30h
db 48h
db 37h
db 48h
db 0CFh
db 0AFh
db 7Dh
db 4Fh
db 83h
db 0A4h
db 11h
db 5Bh
db 83h
db 8
db 0F1h
db 49h
db 0FAh
db 1Ch
db 1Ch
db 28h
db 99h
db 42h
db 8Bh
db 24h
; These are relocatable jump-table deltas.  The original IDB export encoded
; deltas relative to the source image's absolute table addresses; retaining
; those constants in this standalone PE would jump outside the fixture after
; the linker moves CONST.  Keep the same computed-dispatch topology, but make
; each entry relative to the local table base.
jpt_7FF856815E62 dd loc_7FF856815E64 - jpt_7FF856815E62
dd loc_7FF85682A5AD - jpt_7FF856815E62
dd loc_7FF856829799 - jpt_7FF856815E62
dd loc_7FF8568297C6 - jpt_7FF856815E62
jpt_7FF85681D630 dd loc_7FF85681D632 - jpt_7FF85681D630
dd loc_7FF856829722 - jpt_7FF85681D630
dd loc_7FF856829083 - jpt_7FF85681D630
dd loc_7FF8568290C1 - jpt_7FF85681D630
dword_7FF8571CC650 dd 13913EEh
dword_7FF8571CC654 dd 5AA39D0h
dword_7FF8571CC658 dd 0D2D797A2h
dword_7FF8571CC660 dd 93128169h
qword_7FF8571CC668 dq 49CEC7CBBE4D1787h
dword_7FF8571CC670 dd 89294A80h
dword_7FF8571CC678 dd 28DD419h
dword_7FF8571CC67C dd 5ACA0673h
qword_7FF8571CC680 dq -1E8C55727B57B5BFh
dword_7FF8571CC688 dd 7903B5ABh
dword_7FF8571CC68C dd 86852894h
dword_7FF8571CC690 dd 5FDEEF08h
qword_7FF8571CC698 dq 459B252C9C069ABBh
dword_7FF8571CC6A0 dd 0BC66D96Ch
dword_7FF8571CC6A8 dd 415F1D7Dh
qword_7FF8571CC6B0 dq -70026A4C7E63700Dh
dword_7FF8571CC6B8 dd 9F7BDC42h
qword_7FF8571CC6C0 dq -30FE5C003677AA6Eh
qword_7FF8571CC6C8 dq -54470F54D8A7D616h
dword_7FF8571CC6D0 dd 0A601E5A3h
dword_7FF8571CC6D8 dd 1692D51Fh
dword_7FF8571CC6DC dd 0EE816B96h
dword_7FF8571CC6E0 dd 0F43AA478h
dword_7FF8571CC6E4 dd 0D9F1B772h
dword_7FF8571CC6E8 dd 1E991D6Bh
qword_7FF8571CC6F0 dq -5E8F63E59792BB81h
dword_7FF8571CC6F8 dd 0B83A46Fh
dword_7FF8571CC6FC dd 0A62AC6A3h
dword_7FF8571CC700 dd 7C748369h
dword_7FF8571CC704 dd 3BBD68E9h
dword_7FF8571CC708 dd 6C87B583h
dword_7FF8571CC70C dd 69D847CEh
dword_7FF8571CC710 dd 0CFE83D2Bh
qword_7FF8571CC718 dq 23C2BFAC00EFE201h
qword_7FF8571CC720 dq -52704652FB9A6C29h
qword_7FF8571CC728 dq -12C7AFD6C227895Dh
dword_7FF8571CC730 dd 559751Ah
dword_7FF8571CC734 dd 973FA510h
dword_7FF8571CC738 dd 7DEDA10Dh
dword_7FF8571CC740 dd 4E050DF9h
dword_7FF8571CC748 dd 5113135Bh
qword_7FF8571CC750 dq -50EF00FA3909C1E4h
qword_7FF8571CC758 dq -75B25A21EBA066E9h
qword_7FF8571CC760 dq 3CB995DC1ECF0FBCh
dword_7FF8571CC768 dd 24083A15h
qword_7FF8571CC770 dq 61410979B9535738h
qword_7FF8571CC778 dq 36FD79F90E7E888Eh
dword_7FF8571CC780 dd 0DD44A5B1h
dword_7FF8571CC784 dd 0F2D013B1h
dword_7FF8571CC788 dd 3B4E8DABh
dword_7FF8571CC78C dd 6B686A81h
dword_7FF8571CC790 dd 95336ACDh
dword_7FF8571CC794 dd 6A458110h
qword_7FF8571CC798 dq 3F4ECF6257A1589Ah
dword_7FF8571CC7A0 dd 0ECE741BEh
dword_7FF8571CC7A4 dd 0C525B691h
dword_7FF8571CC7A8 dd 85F6E2DAh
dword_7FF8571CC7AC dd 25585D2Eh
qword_7FF8571CC7B0 dq -5E2D8424926A4653h
qword_7FF8571CC7B8 dq -1088633A1093BDD7h
qword_7FF8571CC7C0 dq 2FA0F9B1B0C91B0Ch
qword_7FF8571CC7C8 dq -34499952D99FEE3h
dword_7FF8571CC7D0 dd 0D18B50C8h
dword_7FF8571CC7D4 dd 0A31BDCACh
dword_7FF8571CC7D8 dd 0F60292E7h
dword_7FF8571CC7DC dd 0EE1ED20Ah
dword_7FF8571CC7E0 dd 0B168B155h
dword_7FF8571CC7E8 dd 2BA8DE58h
dword_7FF8571CC7F0 dd 77F0C60Eh
qword_7FF8571CC7F8 dq 0BF77DEC7ECB4B7Ah
dword_7FF8571CC800 dd 0F4EEAAD6h
qword_7FF8571CC808 dq 686E882F1B2F4F14h
qword_7FF8571CC810 dq -3E5E4485E0DDB37Ah
dword_7FF8571CC818 dd 0A89E0D98h
dword_7FF8571CC81C dd 0F2B9C92h
qword_7FF8571CC820 dq -5BB1FE5F0A77D0A5h
dword_7FF8571CC828 dd 0C0AD708Ah
qword_7FF8571CC830 dq 78E131040580ECF7h
dword_7FF8571CC838 dd 0AA048EBFh
dword_7FF8571CC83C dd 9B6E1E55h
dword_7FF8571CC840 dd 7A467A82h
dword_7FF8571CC848 dd 0D6974534h
qword_7FF8571CC850 dq -80D3B0F2414060Dh
qword_7FF8571CC858 dq 646F0333448E9A36h
qword_7FF8571CC860 dq 6052AE1C37E94DBAh
dword_7FF8571CC868 dd 0B0DCCED1h
dword_7FF8571CC86C dd 0C3B9AB4Ch
dword_7FF8571CC870 dd 7DFA3F1h
dword_7FF8571CC874 dd 3BF9C3Ch
qword_7FF8571CC878 dq -224A51D3A6ABB690h
qword_7FF8571CC880 dq 420B97B84A103993h
dword_7FF8571CC888 dd 7036FEF0h
dword_7FF8571CC88C dd 60ED15D9h
dword_7FF8571CC890 dd 1E088BDh
dword_7FF8571CC894 dd 4B5C2449h
dword_7FF8571CC898 dd 1DA2B513h
qword_7FF8571CC8A0 dq 173E5074202D0539h
dword_7FF8571CC8A8 dd 1BC0293Bh
dword_7FF8571CC8AC dd 937840CEh
dword_7FF8571CC8B0 dd 0D0233CADh
dword_7FF8571CC8B4 dd 369B83B4h
dword_7FF8571CC8B8 dd 0B8D30A2Dh
dword_7FF8571CC8BC dd 8A44650Dh
dword_7FF8571CC8C0 dd 4F3A30BDh
qword_7FF8571CC8C8 dq -42E0E7935E94384Bh
dword_7FF8571CC8D0 dd 59FEBEE1h
qword_7FF8571CC8D8 dq -0FF7B54BEF195C17h
qword_7FF8571CC8E0 dq 1ADC56CA13280D1Fh
qword_7FF8571CC8E8 dq -76CE2700E21945Fh
qword_7FF8571CC8F0 dq -2509EA758164BE4Ah
dword_7FF8571CC8F8 dd 8ACF930Fh
dword_7FF8571CC8FC dd 3428B05Ch
qword_7FF8571CC900 dq -1A0EF9D3EB828238h
qword_7FF8571CC908 dq 7CEDC1BDEC731102h
dword_7FF8571CC910 dd 0D95F059Ch
dword_7FF8571CC918 dd 0B44DDBCDh
dword_7FF8571CC91C dd 38B3F0A2h
dword_7FF8571CC920 dd 0F5DEE4B9h
dword_7FF8571CC924 dd 73032430h
dword_7FF8571CC928 dd 96600411h
qword_7FF8571CC930 dq 92500F4032DEA96h
dword_7FF8571CC938 dd 0B5A97DE6h
qword_7FF8571CC940 dq -342A798B32B6F61Bh
dword_7FF8571CC948 dd 3244A4B1h
dword_7FF8571CC94C dd 70DE47A5h
dword_7FF8571CC950 dd 0E3409F17h
dword_7FF8571CC958 dd 15BCF30Ah
dword_7FF8571CC960 dd 0C6E3EABDh
qword_7FF8571CC968 dq -554B8166479C3691h
dword_7FF8571CC970 dd 2848D8EAh
qword_7FF8571CC978 dq 4F338C8DF2BEEF75h
qword_7FF8571CC980 dq -35CA49805BCA18h
dword_7FF8571CC988 dd 7D05FBB3h
qword_7FF8571CC990 dq -442E0F56BE94E918h
qword_7FF8571CC998 dq 2BBE44E107C2D5A5h
dword_7FF8571CC9A0 dd 59D76BC7h
qword_7FF8571CC9A8 dq -49A1FEEB74BD808Bh
qword_7FF8571CC9B0 dq -7F9E76CFCF5EC822h
dword_7FF8571CC9B8 dd 44C7498Fh
dword_7FF8571CC9BC dd 0D9513144h
dword_7FF8571CC9C0 dd 0BDAFB9D0h
dword_7FF85723A998 dd 8B907042h
dword_7FF85723A99C dd 4A4386EBh
dword_7FF85723A9A0 dd 95490568h
dword_7FF85723A9A4 dd 0C92C426h
dword_7FF85723A9A8 dd 95C9C62Eh
dword_7FF85723A9AC dd 799721CDh
dword_7FF85723A9B0 dd 0C6B9F0C1h
dword_7FF85723A9B4 dd 4AC0CCBAh
dword_7FF85723A9B8 dd 70D947ECh
dword_7FF85723A9BC dd 3D667659h
dword_7FF85723A9C0 dd 0F8CEAAEBh
dword_7FF85723A9C4 dd 0FFD0D7BFh
dword_7FF85723A9C8 dd 2144C627h
dword_7FF85723A9CC dd 0B521F2F7h
dword_7FF85723A9D0 dd 0C188E111h
dword_7FF85723A9D4 dd 0DD1E4606h
dword_7FF85723A9D8 dd 2D781A1Ah
dword_7FF85723A9DC dd 0B677E339h
dword_7FF85723A9E0 dd 3651E54h
dword_7FF85723A9E4 dd 19981CBh
dword_7FF85723A9E8 dd 0E7B30596h
dword_7FF85723A9EC dd 0BBC482DCh
dword_7FF85723A9F0 dd 767F85Dh
dword_7FF85723A9F4 dd 71768D14h
dword_7FF85723A9F8 dd 0A6F01B6Eh
dword_7FF85723A9FC dd 160049D4h
dword_7FF85723AA00 dd 979671A7h
dword_7FF85723AA04 dd 21E52FE2h
dword_7FF85723AA08 dd 2380ABDDh
dword_7FF85723AA0C dd 0A902BE8Fh
dword_7FF85723AA10 dd 651C089Dh
dword_7FF85723AA14 dd 91B975D7h
dword_7FF85723AA18 dd 8377D8F8h
dword_7FF85723AA1C dd 1201DC6Ah
dword_7FF85723AA20 dd 0F98A8D46h
dword_7FF85723AA24 dd 90F65272h
dword_7FF85723AA28 dd 34943688h
dword_7FF85723AA2C dd 7A791598h
dword_7FF85723AA30 dd 0CC4694EDh
dword_7FF85723AA34 dd 41A5D8BEh
dword_7FF85723AA38 dd 623D808Eh
dword_7FF85723AA3C dd 7BB781F6h
dword_7FF85723AA40 dd 0C59992E0h
dword_7FF85723AA44 dd 0A0E31BA1h
dword_7FF85723AA48 dd 2F9BA167h
dword_7FF85723AA4C dd 225B7E3Fh
dword_7FF85723AA50 dd 1CCAE57Bh
dword_7FF85723AA54 dd 0B9F4B05Eh
dword_7FF85723AA58 dd 976909AAh
dword_7FF85723AA5C dd 5E72B060h
dword_7FF85723AA60 dd 9046FFB5h
dword_7FF85723AA64 dd 8DE4F879h
dword_7FF85723AA68 dd 0CD6975FCh
dword_7FF85723AA6C dd 0BCF45B2Bh
dword_7FF85723AA70 dd 7BD7159Ch
dword_7FF85723AA74 dd 5159C8F4h
dword_7FF85723AA78 dd 0A00A75A7h
dword_7FF85723AA7C dd 0A4550530h
dword_7FF85723AA80 dd 0F98BC185h
dword_7FF85723AA84 dd 9585F77h
dword_7FF85723AA88 dd 0F8634521h
dword_7FF85723AA8C dd 0AC3588CBh
dword_7FF85723AA90 dd 0D4ACD37Ch
dword_7FF85723AA94 dd 0ADF5E0C3h
dword_7FF85723AA98 dd 7CFDF1BAh
dword_7FF85723AA9C dd 98674D66h
dword_7FF85723AAA0 dd 3E3BB026h
dword_7FF85723AAA4 dd 0F73A1050h
dword_7FF85723AAA8 dd 56ABA6CFh
dword_7FF85723AAAC dd 71736478h
dword_7FF85723AAB0 dd 0E07ABAAFh
dword_7FF85723AAB4 dd 0C47A4E31h
dword_7FF85723AAB8 dd 0ED08B148h
dword_7FF85723AABC dd 0E30223D5h
dword_7FF85723AAC0 dd 242640D8h
dword_7FF85723AAC4 dd 776752F1h
dword_7FF85723AAC8 dd 28C478A0h
dword_7FF85723AACC dd 24F584B7h
dword_7FF85723AAD0 dd 441E9D6Bh
dword_7FF85723AAD4 dd 41060151h
dword_7FF85723AAD8 dd 0CA5010FEh
dword_7FF85723AADC dd 4F1422E5h
dword_7FF85723AAE0 dd 0F22C392Eh
dword_7FF85723AAE4 dd 9F2EF1A4h
dword_7FF85723AAE8 dd 52F10E6h
dword_7FF85723AAEC dd 3147B91Bh
dword_7FF85723AAF0 dd 1225E6FDh
dword_7FF85723AAF4 dd 0BF53BB0Bh
dword_7FF85723AAF8 dd 0BE69A132h
dword_7FF85723AAFC dd 673EF6F8h
dword_7FF85723AB00 dd 0A840D81Dh
dword_7FF85723AB04 dd 0EEC7D052h
dword_7FF85723AB08 dd 4E6C9B10h
dword_7FF85723AB0C dd 5B3A9B00h
dword_7FF85723AB10 dd 9373678h
dword_7FF85723AB14 dd 0E8D3CD12h
dword_7FF85723AB18 dd 0A2C2F6FBh
dword_7FF85723AB1C dd 581F6EB9h
dword_7FF85723AB20 dd 9B4ACA6Ah
dword_7FF85723AB24 dd 4FBB898Eh
dword_7FF85723AB28 dd 9A33E796h
dword_7FF85723AB2C dd 43CFC4F1h
dword_7FF85723AB30 dd 5F3FB497h
dword_7FF85723AB34 dd 0B85686B5h
CONST ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC sub_7FF8568132D0
sub_7FF8568132D0:
    push r15
    push r14
    push r13
    push r12
    push rsi
    push rdi
    push rbp
    push rbx
    sub rsp, 8B8h
    mov r12, r8
    mov eax, dword ptr [dword_7FF85723A9A0]
    mov r9d, eax
    xor r9d, 649F3003h
    mov edx, eax
    xor edx, -21C9C57Eh
    add r9d, edx
    mov r8d, -4276BE97h
    sub r8d, r9d
    xor edx, eax
    xor edx, r8d
    xor eax, -64E6ED6Eh
    xor edx, 6940481Eh
    add edx, eax
    mov dword ptr [rsp+3Ch], edx
    lea r13, eidolon_sbox
    and ecx, 1
    mov dword ptr [rsp+424h], ecx
    mov qword ptr [rsp+328h], r12
    jmp loc_7FF856813884
    loc_7FF85681333E:
    mov edx, dword ptr [dword_7FF8571CC81C]
    mov ecx, edx
    xor ecx, 72AAB79h
    mov r8d, 288A3E04h
    sub r8d, edx
    xor r8d, edx
    mov eax, edx
    xor eax, 1E3087BAh
    add eax, 26E13CE8h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r8d, 2988511Fh
    xor edx, -72AAB7Ah
    lea r9d, [rdx+rdx*4]
    mov r10d, r8d
    or r10d, edx
    not r10d
    lea r10d, [r10+r10*2]
    mov r11d, r8d
    or r11d, ecx
    not r11d
    lea r11d, [r11+r11*4]
    xor ecx, r8d
    add ecx, ecx
    and edx, r8d
    shl edx, 3
    sub edx, ecx
    add edx, r11d
    add edx, r10d
    sub edx, r9d
    xor edx, eax
    mov ecx, 53h
    mov r8d, 60h
    mov r9d, 41h
    call Eidolon_UpdateSharedStateIfSentinelMatches
    loc_7FF856813423:
    mov eax, dword ptr [r12+40h]
    mov dword ptr [rsp+494h], eax
    lea rax, [r12+50h]
    mov qword ptr [rsp+7D0h], rax
    mov rax, qword ptr [qword_7FF8571CC820]
    mov rcx, -1B34F8E52059874Dh
    add rcx, rax
    mov rdx, 6E487B8008D288F5h
    xor rcx, rdx
    mov rdx, -713F5647055B2BC6h
    add rdx, rcx
    mov r8, 739829FC3BF4464Eh
    sub r8, rax
    xor r8, rdx
    sub r8, rcx
    xor r8, qword ptr [r12+50h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [r8+8]
    mov qword ptr [rsp+7D8h], rax
    mov rcx, qword ptr [r8]
    mov qword ptr [rsp+3C8h], rcx
    sub rax, rcx
    mov ecx, dword ptr [dword_7FF8571CC828]
    mov edx, ecx
    not edx
    and edx, 2E1347Ch
    lea r9d, [rdx+rdx*2]
    lea edx, [rcx+rcx]
    or edx, 5C268F8h
    lea edx, [rdx+rdx*2]
    mov r8d, ecx
    xor r8d, 7D1ECB83h
    mov r10d, ecx
    and r10d, 2E1347Ch
    lea r10d, [r10+r10*2]
    add r10d, r10d
    mov r11d, ecx
    and r11d, 7D1ECB83h
    lea r11d, [r11+r11*2]
    lea r10d, [r10+r11*2]
    add r10d, r8d
    sub r10d, edx
    lea r8d, [r10+r9*2]
    lea edx, [r10+r9*2]
    add edx, 54D4CD22h
    lea r9d, [r10+r9*2-185DEBDDh]
    mov r10d, r8d
    not r10d
    mov r11d, r10d
    mov esi, r10d
    and r10d, -51CFFC3Ah
    mov edi, r8d
    and edi, -51CFFC3Ah
    sub edi, r10d
    mov r10d, r8d
    xor r10d, -51CFFC3Ah
    lea r10d, [r10+r10*2]
    add edi, r10d
    or r11d, -51CFFC3Ah
    and esi, 51CFFC39h
    sub edi, r11d
    add edi, esi
    not r11d
    shl r11d, 2
    sub edi, r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor edi, r9d
    sub edi, r8d
    add ecx, edi
    add ecx, 4FB3A344h
    xor ecx, edx
    add ecx, 4AA19787h
    sar rax, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+3D0h], rax
    mov rax, qword ptr [r12]
    mov qword ptr [rsp+7E0h], rax
    mov rcx, qword ptr [qword_7FF8571CC830]
    mov rax, rcx
    mov rdx, -727BA2F43165C7CCh
    xor rax, rdx
    mov rdx, -5476391BB9F7FA5Fh
    add rdx, rax
    mov r8, rdx
    mov r11, -33ABCF3EE5DF468Fh
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
    mov r8, rcx
    mov r10, 1B9AA872290B6982h
    xor r8, r10
    add r8, rax
    mov r10, -54EEC3E0640B0626h
    add r8, r10
    xor r9, r8
    add r9, rcx
    sub r9, rdx
    add r9, rax
    mov qword ptr [rsp+7E8h], r9
    mov eax, dword ptr [dword_7FF85723AA7C]
    lea ecx, [rax+166C5E13h]
    xor ecx, -6FDFB115h
    lea edx, [rax+rcx]
    add edx, 60BBD9BBh
    xor edx, eax
    lea eax, [rcx+rdx]
    add eax, -72D21F0Dh
    add ecx, -73F1126h
    loc_7FF856813873:
    xor eax, ecx
    nop word ptr [rax+rax+00000000h]
    loc_7FF856813880:
    mov dword ptr [rsp+3Ch], eax
    loc_7FF856813884:
    mov eax, dword ptr [rsp+3Ch]
    cmp eax, 3819CDB6h
    jg loc_7FF8568138E0
    cmp eax, 19F75BC8h
    jg loc_7FF856813970
    cmp eax, 0FE2522Eh
    jle loc_7FF8568158D5
    cmp eax, 139254EAh
    jle loc_7FF856816EBF
    cmp eax, 167D8484h
    jle loc_7FF8568197D3
    cmp eax, 182E4829h
    jg loc_7FF85681A9F2
    cmp eax, 167D8485h
    jnz loc_7FF85681742A
    jmp loc_7FF8568281AA
    loc_7FF8568138E0:
    cmp eax, 607A89A9h
    jg loc_7FF856813DC0
    cmp eax, 46DC5076h
    jle loc_7FF856815872
    cmp eax, 560209ADh
    jle loc_7FF856815B46
    cmp eax, 5C7E8537h
    jle loc_7FF8568179C9
    cmp eax, 5DEAEA57h
    jg loc_7FF85681A971
    cmp eax, 5C7E8538h
    jnz loc_7FF856825E34
    cmp qword ptr [rsp+0F8h], 1
    jnz loc_7FF85681C48A
    loc_7FF856813931:
    mov eax, dword ptr [dword_7FF85723AAC0]
    lea ecx, [rax-0D83ADCDh]
    xor ecx, -2759986Ah
    lea edx, [rcx-757F8E1Ch]
    mov r8d, edx
    xor r8d, 17AA1270h
    lea r9d, [rcx+r8]
    sub r9d, edx
    add r9d, r8d
    sub r9d, eax
    lea eax, [r9+rcx]
    add eax, -52830221h
    jmp loc_7FF856813880
    loc_7FF856813970:
    cmp eax, 27C4381Dh
    jg loc_7FF856815964
    cmp eax, 23723636h
    jle loc_7FF856817208
    cmp eax, 26546B5Fh
    jle loc_7FF8568198A3
    cmp eax, 274B54B2h
    jg loc_7FF85681AF02
    cmp eax, 26546B60h
    jnz loc_7FF856823C0F
    mov eax, dword ptr [dword_7FF8571CC6B8]
    mov ecx, -57615AC5h
    add eax, ecx
    mov edx, eax
    not edx
    mov ecx, eax
    mov r8d, eax
    xor r8d, 7D6C1B4Eh
    lea r9d, [r8+r8*4]
    and edx, 7D6C1B4Eh
    lea edx, [rdx+rdx*2]
    mov r8d, eax
    and r8d, 7D6C1B4Eh
    lea r8d, [r8+rdx*2]
    sub r8d, r9d
    sub r8d, eax
    xor eax, -78CD3676h
    lea r10d, [rax-664F629Eh]
    mov edx, r10d
    xor edx, 55D2B604h
    mov r11d, r10d
    xor r11d, -55D2B605h
    mov esi, r11d
    and esi, -4546B27Fh
    and r11d, 4546B27Eh
    add r11d, r11d
    mov r9d, r10d
    xor r9d, 1094047Ah
    mov edi, edx
    and edi, 4546B27Eh
    mov ebx, edx
    and ebx, -4546B27Fh
    lea edi, [rbx+rdi*2]
    sub edi, edx
    lea r9d, [rdi+r9*2]
    sub r9d, r11d
    add r9d, esi
    mov r11d, r9d
    not r11d
    mov esi, r11d
    mov edi, r11d
    or r11d, 4415736Bh
    lea ebx, [r9+r9]
    sub ebx, r11d
    and ecx, -7D6C1B4Fh
    lea r11d, [rcx*8]
    sub r11d, ecx
    add r8d, r11d
    and edi, 3BEA8C94h
    lea ecx, [rbx+rdi*4]
    and esi, 4415736Bh
    lea r11d, [rsi+rsi*2]
    add ecx, r11d
    add ecx, r8d
    add ecx, 3
    xor ecx, r10d
    add r9d, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor ecx, 0D2h
    add r9d, ecx
    lea ecx, [rax+r9]
    add ecx, -664F629Eh
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
    mov rax, qword ptr [rsp+78h]
    mov rdx, rax
    shr rdx, cl
    mov qword ptr [rsp+7C8h], rdx
    mov rcx, qword ptr [qword_7FF8571CC6C0]
    mov rdx, -2D8AA90805975C12h
    sub rdx, rcx
    mov r8, -54433D60282353A6h
    xor rcx, r8
    xor rdx, rcx
    mov r8, 3373CB07B2F64EA8h
    add rcx, r8
    add rcx, rdx
    cmp rax, rcx
    jnb loc_7FF856828182
    mov eax, dword ptr [dword_7FF85723AA64]
    mov ecx, eax
    xor ecx, -56252CA4h
    mov edx, eax
    xor edx, -4AD1A8F6h
    xor eax, 4F5474EEh
    lea r8d, [rax-0B1C093Dh]
    mov r9d, 283B8FD9h
    sub r9d, eax
    xor r9d, eax
    add r9d, ecx
    sub r9d, edx
    xor r9d, r8d
    mov dword ptr [rsp+3Ch], r9d
    jmp loc_7FF856813884
    loc_7FF856813DC0:
    cmp eax, 724AB512h
    jg loc_7FF8568140DE
    cmp eax, 6B3A29A1h
    jg loc_7FF856815C0C
    cmp eax, 6464627Ah
    jg loc_7FF856817414
    cmp eax, 61A7E64Ah
    jg loc_7FF85681B11A
    cmp eax, 607A89AAh
    jz loc_7FF856829142
    mov r8d, dword ptr [dword_7FF8571CC9BC]
    mov ecx, r8d
    xor ecx, -6D1F3564h
    mov dword ptr [rsp+4B0h], ecx
    lea eax, [rcx-25F0B5A3h]
    mov dword ptr [rsp+4B4h], eax
    add ecx, -165FB788h
    mov dword ptr [rsp+4B8h], ecx
    mov eax, ecx
    not eax
    mov edx, eax
    and edx, 187E9438h
    lea edx, [rdx+rdx*2]
    and eax, -187E9439h
    lea eax, [rax+rax*4]
    mov r9d, ecx
    xor r9d, 187E9438h
    add r9d, r9d
    and ecx, 7816BC7h
    shl ecx, 3
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub ecx, r9d
    add ecx, eax
    mov eax, 1DCD434Bh
    sub eax, ecx
    sub eax, edx
    add edx, ecx
    add edx, 7A78E51Dh
    xor edx, 48CA55B4h
    add edx, -54B4CF68h
    mov ecx, edx
    xor ecx, 16996D70h
    xor eax, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    xor edx, -16996D71h
    mov r8d, eax
    or r8d, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    lea r9d, [r8+r9*2]
    not r8d
    lea r10d, [r8*8]
    sub r10d, r8d
    mov dword ptr [rsp+4BCh], r10d
    mov r8d, eax
    or r8d, ecx
    not r8d
    mov r10d, r8d
    shl r10d, 4
    add r10d, r8d
    mov dword ptr [rsp+4C0h], r10d
    and edx, eax
    lea r8d, [rdx+rdx*2]
    not edx
    add edx, edx
    lea edx, [rdx+rdx*2]
    mov dword ptr [rsp+4C4h], edx
    mov dword ptr [rsp+4C8h], r9d
    and eax, ecx
    lea ecx, [rax+rax*8]
    lea eax, [rax+rcx*2]
    lea eax, [rax+r8*4]
    mov dword ptr [rsp+4CCh], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FF85723AAA4]
    lea ecx, [rax+241C95BEh]
    mov edx, ecx
    xor edx, -68F512F7h
    lea r8d, [rdx+3576C12Fh]
    xor ecx, -735001E9h
    sub ecx, eax
    add ecx, -43C46B4Fh
    xor ecx, r8d
    xor r8d, 33C50447h
    xor ecx, -36D023E2h
    add ecx, r8d
    xor ecx, eax
    lea eax, [rcx+rdx]
    add eax, 3576C12Fh
    jmp loc_7FF856813880
    loc_7FF8568140DE:
    cmp eax, 779F8617h
    jg loc_7FF856815E70
    cmp eax, 762F1CB3h
    jg loc_7FF85681743B
    cmp eax, 73AE1ED9h
    jle loc_7FF85681B188
    cmp eax, 73AE1EDAh
    jnz loc_7FF85681C639
    mov ecx, dword ptr [dword_7FF8571CC650]
    mov eax, ecx
    xor eax, 280618A1h
    mov edx, ecx
    xor edx, -68AEDAEAh
    mov r8d, edx
    or r8d, -55B8E75Bh
    and eax, 2A4718A5h
    shl eax, 2
    and edx, -55B8E75Bh
    mov r9d, edx
    not r9d
    add r9d, r9d
    sub r9d, edx
    sub r9d, eax
    add r8d, r9d
    add r8d, 548E314Bh
    mov eax, r8d
    not eax
    lea edx, [rax*8]
    sub edx, eax
    mov r9d, eax
    and r9d, 5BD83CE2h
    lea r9d, [r9+r9*8]
    mov r10d, eax
    and r10d, 2427C31Dh
    add r10d, r10d
    lea r10d, [r10+r10*4]
    mov r11d, r8d
    and r11d, 5BD83CE2h
    mov esi, r11d
    not esi
    lea esi, [rsi+rsi*2]
    mov edi, r8d
    and edi, 2427C31Dh
    add edi, edi
    add r11d, r11d
    sub r11d, edi
    add r11d, esi
    sub r11d, r10d
    sub r11d, r9d
    add edx, ecx
    add edx, r11d
    mov ecx, -437D1BDBh
    sub ecx, edx
    mov r9d, ecx
    or r9d, eax
    not r9d
    shl r9d, 2
    lea r10d, [r8+r8]
    mov edx, ecx
    or edx, r8d
    lea edx, [rdx+rdx*4]
    and eax, ecx
    and ecx, r8d
    lea ecx, [rcx+rcx*2]
    lea eax, [rcx+rax*4]
    sub edx, eax
    sub edx, r10d
    sub edx, r9d
    xor edx, dword ptr [r12+8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, dword ptr [dword_7FF8571CC654]
    mov ecx, r8d
    xor ecx, 401006F5h
    lea r9d, [rcx+2418E67Dh]
    lea r10d, [rcx-5784BB00h]
    mov eax, r9d
    not eax
    mov r11d, eax
    mov esi, eax
    mov edi, r9d
    and eax, 52299CC8h
    and r9d, 52299CC8h
    sub r9d, eax
    lea eax, [rcx-615C121Bh]
    or r11d, 52299CC8h
    xor edi, 52299CC8h
    lea edi, [rdi+rdi*2]
    add r9d, edi
    sub r9d, r11d
    not r11d
    shl r11d, 2
    and esi, -52299CC9h
    add r9d, esi
    sub r9d, r11d
    xor r9d, eax
    mov r11d, eax
    xor r11d, -46A5F387h
    sub r9d, ecx
    add r9d, 73E29A94h
    mov esi, r9d
    or esi, r10d
    not esi
    add esi, esi
    mov eax, r9d
    and eax, r10d
    not eax
    add eax, eax
    xor r9d, r10d
    sub eax, r9d
    sub eax, esi
    sub eax, r8d
    sub eax, ecx
    sub eax, r11d
    xor eax, dword ptr [r12+18h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [dword_7FF8571CC658]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r8d, [rcx+628963A3h]
    xor r8d, 5Ch
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ecx, 628963A3h[rcx*2]
    add ecx, r8d
    add ecx, 20h
    neg ecx
    mov r8, rax
    shl r8, cl
    or rdx, r8
    mov ecx, dword ptr [dword_7FF8571CC660]
    mov r8d, ecx
    or r8d, 0E6C16E6h
    lea r10d, [r8+r8*4]
    mov r9d, r8d
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    not r8d
    and r8d, 0E6C16E6h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11d, ecx
    xor r11d, 0E6C16E6h
    lea r11d, [r11+r11*2]
    mov esi, ecx
    and esi, 0E6C16E6h
    lea esi, [rsi+rsi*2]
    add esi, esi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edi, ecx
    and edi, 1193E919h
    lea esi, [rsi+rdi*8]
    sub esi, r10d
    sub esi, r11d
    lea r8d, [rsi+r8*8]
    add r8d, r9d
    mov r9d, r8d
    xor r9d, 300B1490h
    mov r10d, r9d
    mov esi, r8d
    xor esi, -300B1491h
    mov r11d, esi
    and esi, -14F3C837h
    and r9d, -14F3C837h
    lea edi, [r9+r9*4]
    lea edi, [r9+rdi*2]
    add edi, esi
    mov r9d, esi
    not r9d
    lea esi, [r9+r9*4]
    lea esi, [r9+rsi*2]
    mov r9d, r8d
    xor r9d, 0C95CB81h
    and r10d, 14F3C836h
    lea r10d, [r10+r10*8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r11d, 14F3C836h
    lea r11d, [r11+r11*4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub edi, esi
    lea r11d, [rdi+r11*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r10d, r11d
    add r10d, 14F3C836h
    xor r10d, ecx
    add r10d, r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r8d, -0C95CB82h
    mov ecx, r10d
    or ecx, r8d
    not ecx
    lea r11d, [rcx*8]
    sub r11d, ecx
    mov ecx, r10d
    xor ecx, r9d
    lea esi, [rcx+rcx*4]
    and r8d, r10d
    lea ecx, [r8+r8*2]
    and r10d, r9d
    lea ecx, [r10+rcx*2]
    sub ecx, esi
    sub ecx, r9d
    add ecx, r11d
    shr rax, cl
    xor rax, rdx
    mov r8, qword ptr [qword_7FF8571CC668]
    mov rcx, r8
    mov rdx, -7E483B1661D5A50h
    xor rcx, rdx
    mov r9, r8
    mov rdx, rcx
    mov r10, rcx
    sub rcx, r8
    mov r11, r8
    mov r8, 7C08380440C004Fh
    xor r11, r8
    mov r8, 24003122115A00h
    xor r9, r8
    mov rsi, -3FCB938CD40E01E0h
    and r9, rsi
    lea r9, [r9+r9*2]
    mov r8, 3FCB938CD40E01DFh
    and r11, r8
    add r11, r11
    and rdx, r8
    lea r8, [rdx+rdx*2]
    not rdx
    add rdx, rdx
    and r10, rsi
    mov rsi, r10
    not rsi
    add r10, r10
    sub r10, r8
    lea r8, [r10+rsi*4]
    sub r8, rdx
    sub r8, r11
    sub r8, r9
    mov rdx, r8
    mov r9, 1EF0A297A230800Ch
    xor rdx, r9
    mov r9, 6E4856BE32637944h
    add rdx, r9
    mov r9, rdx
    mov r10, 0C9388148E756576h
    xor r9, r10
    mov r10, -1D8E07657FBF5AC6h
    add rcx, r10
    xor rcx, r9
    mov r10, 1A51373280FA0443h
    add r9, r10
    mov r11, r9
    not r11
    mov rsi, rcx
    or rsi, r11
    mov r10, rcx
    or r10, r9
    mov rdi, rcx
    xor rdi, r9
    and r11, rcx
    and r9, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rcx, [rdi+rdi*2]
    sub r9, r11
    add r9, rcx
    sub r9, rsi
    not rsi
    shl rsi, 2
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9, r10
    sub r9, rsi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rdx, r8
    add rdx, r9
    imul rdx, rax
    mov eax, dword ptr [dword_7FF8571CC670]
    lea ecx, [rax+30820A48h]
    lea r8d, [rax-3D69B49h]
    not r8d
    mov r9d, r8d
    and r9d, 3F6770E1h
    mov r10d, r8d
    and r10d, -3F6770E2h
    or r8d, -3F6770E2h
    lea r8d, [r8+rax*2]
    add r8d, -7AD3692h
    add r8d, r10d
    lea r10d, [r8+r9*2]
    mov r11d, 2CCF3AB6h
    sub r11d, r10d
    lea r10d, [r8+r9*2]
    add r10d, 2
    xor r10d, ecx
    xor r10d, r11d
    lea ecx, [rax+r10]
    add ecx, -9BDB5E3h
    lea r8d, [r8+r9*2]
    add r8d, -1316EB8Bh
    xor r8d, 5ED39E67h
    add r8d, ecx
    add r8d, 0D2A503Dh
    mov ecx, eax
    not ecx
    mov r9d, r8d
    or r9d, ecx
    lea r10d, [r9+r9*4]
    lea r11d, [r9+r10*2]
    mov r10d, r9d
    not r10d
    lea r9d, [r10*8]
    sub r9d, r10d
    mov esi, r8d
    or esi, eax
    not esi
    mov r10d, esi
    shl r10d, 4
    add r10d, esi
    and ecx, r8d
    and r8d, eax
    lea esi, [r8+r8*8]
    lea r8d, [r8+rsi*2]
    lea esi, [rcx+rcx*2]
    lea r8d, [r8+rsi*4]
    sub r8d, r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add ecx, ecx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r8d, ecx
    add r10d, r9d
    add r10d, r8d
    lea ecx, [rax+r10]
    add ecx, -9BDB5E3h
    mov rax, rdx
    shr rax, cl
    xor rax, rdx
    mov rcx, -3B314601E57A13ADh
    imul rax, rcx
    mov rcx, rax
    shr rcx, 21h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov r8d, ecx
    or r8d, edx
    not r8d
    lea r8d, [r8+r8*4]
    lea r9d, [rax+rax]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r10d, ecx
    or r10d, eax
    lea r10d, [r10+r10*2]
    and edx, ecx
    and ecx, eax
    lea eax, [rcx+rcx*8]
    lea eax, [rax+rdx*4]
    sub eax, r10d
    sub eax, r9d
    lea eax, [rax+r8*2]
    mov dword ptr [rsp+64h], eax
    mov ecx, dword ptr [dword_7FF8571CC678]
    lea edx, [rcx+733419Ah]
    add ecx, 1CAB1E15h
    xor ecx, edx
    xor ecx, 279Eh
    add ecx, eax
    and ecx, 3FFCh
    mov dword ptr [rsp+68h], ecx
    mov eax, dword ptr [dword_7FF8571CC67C]
    mov ecx, eax
    not ecx
    mov edx, ecx
    and edx, 24CAD434h
    mov r8d, ecx
    and r8d, 5B352BCBh
    or ecx, 5B352BCBh
    lea eax, [rcx+rax*2]
    add eax, r8d
    lea r8d, [rax+rdx*2]
    lea r9d, [rax+rdx*2]
    add r9d, 2
    lea ecx, [rax+rdx*2]
    add ecx, -17F9EB7Bh
    lea eax, [rax+rdx*2]
    add eax, 3225DFDAh
    xor eax, -55E76B20h
    lea edx, [rax+13E062EEh]
    xor edx, r9d
    sub edx, eax
    lea eax, [rdx+r8]
    add eax, 3225DFDAh
    mov edx, ecx
    not edx
    mov r8d, eax
    or r8d, edx
    mov r9d, eax
    or r9d, ecx
    mov r10d, eax
    xor r10d, ecx
    and edx, eax
    and eax, ecx
    sub eax, edx
    lea ecx, [r10+r10*2]
    add eax, ecx
    not r9d
    sub eax, r8d
    add eax, r9d
    not r8d
    shl r8d, 2
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov dword ptr [rsp+60h], eax
    cmp byte ptr [rsp+41h], 0
    jz loc_7FF856827AB6
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp byte ptr [r12+1Ch], 0E0h
    jnz loc_7FF856829749
    mov eax, dword ptr [dword_7FF85723AB30]
    lea ecx, [rax+46F2E41Dh]
    lea edx, [rax-7B77090h]
    sub eax, edx
    add eax, 13B7D9A9h
    xor ecx, edx
    xor ecx, eax
    xor ecx, -714E0B0Fh
    mov dword ptr [rsp+3Ch], ecx
    jmp loc_7FF856813884
    loc_7FF856815872:
    cmp eax, 3DC2C761h
    jle loc_7FF856816E92
    cmp eax, 4593588Bh
    jg loc_7FF8568178DA
    cmp eax, 3F25220Ah
    jg loc_7FF85681B1A6
    cmp eax, 3DC2C762h
    jnz loc_7FF85681C86E
    mov rax, qword ptr [rsp+0F8h]
    mov qword ptr [rsp+6D8h], rax
    mov eax, dword ptr [dword_7FF85723AAAC]
    lea ecx, [rax-376AA41Bh]
    mov edx, ecx
    xor edx, 74007BA7h
    xor ecx, 45E1EDEBh
    add ecx, edx
    sub ecx, eax
    mov dword ptr [rsp+3Ch], ecx
    jmp loc_7FF856813884
    loc_7FF8568158D5:
    cmp eax, 6E2330Eh
    jg loc_7FF856817258
    cmp eax, 4767B92h
    jg loc_7FF856817A6C
    cmp eax, 3E29774h
    jle loc_7FF85681B1B6
    cmp eax, 3E29775h
    jnz loc_7FF85682426A
    mov rax, qword ptr [rsp+408h]
    lea rcx, [rax+rax]
    mov rdx, qword ptr [rsp+400h]
    mov r8, rdx
    not r8
    and r8, rax
    lea r8, [r8+r8*2]
    and rdx, rax
    lea rax, [rdx+rdx*2]
    add rax, r8
    sub rax, rcx
    add rax, qword ptr [rsp+888h]
    sub rax, qword ptr [rsp+880h]
    add rax, qword ptr [rsp+878h]
    sub rax, qword ptr [rsp+870h]
    add rax, qword ptr [rsp+360h]
    mov qword ptr [rsp+760h], rax
    jmp loc_7FF85681A91A
    loc_7FF856815964:
    cmp eax, 2B6CF093h
    jg loc_7FF8568170B2
    cmp eax, 2A469B63h
    jg loc_7FF85681992A
    cmp eax, 27C4381Eh
    jz loc_7FF85681D678
    cmp eax, 28B62468h
    jnz loc_7FF856824D14
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+840h]
    mov rcx, qword ptr [rsp+578h]
    add rcx, qword ptr [rax+8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+578h]
    mov rdx, qword ptr [rsp+340h]
    mov r8, qword ptr [rsp+3F0h]
    mov r9, rax
    sub r9, r8
    cmp rdx, rcx
    cmovb rcx, rdx
    loc_7FF856815A65:
    mov qword ptr [rsp+580h], rcx
    mov qword ptr [rsp+588h], r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    jbe loc_7FF856828C2A
    cmp qword ptr [rsp+588h], 0
    jz loc_7FF856828C2A
    mov eax, dword ptr [dword_7FF85723AAD4]
    mov ecx, -54172B7Ch
    xor eax, ecx
    lea ecx, [rax-31A72BA8h]
    mov edx, ecx
    xor edx, 144B6FD6h
    mov r8d, ecx
    xor r8d, 3ECAEEF6h
    xor ecx, 138AD83Dh
    add edx, eax
    add edx, eax
    add eax, edx
    add eax, -31A72BA8h
    add eax, r8d
    sub eax, ecx
    add eax, 0B2F0082h
    jmp loc_7FF856813880
    loc_7FF856815B46:
    cmp eax, 4F0BC85Ch
    jg loc_7FF856818DA6
    cmp eax, 46DC5077h
    jz loc_7FF856824FF2
    cmp eax, 4828FE81h
    jz loc_7FF85681333E
    mov rax, qword ptr [rsp+518h]
    mov ecx, dword ptr [rsp+154h]
    mov edx, dword ptr [rsp+158h]
    mov r8, qword ptr [rsp+540h]
    mov r9d, dword ptr [rsp+15Ch]
    mov r10, qword ptr [rsp+548h]
    mov r11d, dword ptr [rsp+160h]
    mov rsi, qword ptr [rsp+550h]
    mov dword ptr [rsp+210h], ecx
    mov dword ptr [rsp+214h], edx
    mov qword ptr [rsp+618h], r8
    mov dword ptr [rsp+218h], r9d
    mov qword ptr [rsp+620h], rsi
    mov dword ptr [rsp+21Ch], r11d
    mov qword ptr [rsp+628h], r10
    mov qword ptr [rsp+630h], rax
    mov eax, dword ptr [dword_7FF85723A9FC]
    mov ecx, eax
    xor ecx, -4FB96EC7h
    lea edx, [rcx-1CAF9274h]
    xor edx, -73F23657h
    sub edx, ecx
    add ecx, -757F80B2h
    add edx, eax
    jmp loc_7FF85682900C
    loc_7FF856815C0C:
    cmp eax, 707D44A1h
    jg loc_7FF856818FAC
    cmp eax, 6B3A29A2h
    jz loc_7FF856817A82
    cmp eax, 6C383442h
    jnz loc_7FF856827813
    mov rax, qword ptr [rsp+5A0h]
    mov rcx, rax
    not rcx
    mov rdx, qword ptr [rsp+858h]
    or rcx, rdx
    mov r8, rdx
    or r8, rax
    not r8
    add r8, rcx
    lea rcx, [rdx+rdx]
    and rdx, rax
    add rdx, rdx
    sub rcx, rdx
    add rcx, r8
    sub rcx, qword ptr [rsp+860h]
    inc rcx
    and rcx, qword ptr [rsp+48h]
    add rcx, qword ptr [rsp+100h]
    mov qword ptr [rsp+358h], rcx
    mov rcx, qword ptr [qword_7FF8571CC860]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, -22AB5C27AF6B00ECh
    lea rdx, [rcx+rax]
    mov rax, 3C8079FC76BD5783h
    xor rdx, rax
    mov rax, 7CFFB3981694AC2Fh
    add rax, rdx
    sub rdx, rcx
    mov r8, 7D9FFBD05BE4BD32h
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
    xor rax, rcx
    xor rax, rdx
    mov rcx, rax
    not rcx
    or rcx, qword ptr [rsp+48h]
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
    lea rdx, [rcx+rcx*4]
    lea rcx, [rcx+rdx*2]
    mov rdx, qword ptr [rsp+48h]
    lea r8, [rdx+rdx*4]
    lea r8, [rdx+r8*2]
    mov r9, rdx
    or r9, rax
    lea r10, [r9+r9*4]
    lea r9, [r9+r10*2]
    and rax, rdx
    sub rax, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rax, r8
    add rax, rcx
    mov qword ptr [rsp+360h], rax
    lea rcx, jpt_7FF856815E62
    movsxd rax, dword ptr [rcx+rax*4]
    add rax, rcx
    jmp rax
    loc_7FF856815E64:
    mov eax, dword ptr [rsp+194h]
    jmp loc_7FF856824FF9
    loc_7FF856815E70:
    cmp eax, 7976990Dh
    jg loc_7FF856819451
    cmp eax, 779F8618h
    jz loc_7FF85681BFF3
    cmp eax, 78BCE7DCh
    jnz loc_7FF8568222DD
    mov eax, dword ptr [rsp+1A0h]
    lea edx, [rax+45C8F6FBh]
    lea ecx, [rax-8276137h]
    mov r8d, eax
    not r8d
    mov r9d, ecx
    or r9d, r8d
    not r9d
    mov r10d, ecx
    or r10d, eax
    not r10d
    mov r11d, ecx
    and r11d, eax
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
    and r8d, ecx
    and ecx, dword ptr [rsp+1A0h]
    add r8d, r8d
    lea ecx, [r8+rcx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r11d, r10d
    add r11d, ecx
    lea ecx, [r11+r9*2]
    mov r8d, dword ptr [rsp+19Ch]
    add r8d, ecx
    add r8d, 2
    mov ecx, edx
    not ecx
    mov r9d, r8d
    or r9d, ecx
    not r9d
    lea r10d, [r9+r9*4]
    lea r9d, [r9+r10*2]
    mov r10d, r8d
    or r10d, edx
    lea r11d, [rdx+rdx*4]
    lea r11d, [rax+r11*2]
    add r11d, 45C8F6FBh
    and ecx, r8d
    and edx, r8d
    imul edx, 0F5h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add ecx, r11d
    add ecx, r10d
    add ecx, edx
    sub ecx, r9d
    sub ecx, r8d
    sub ecx, eax
    mov eax, dword ptr [rsp+4D4h]
    add cl, 0CFh
    mov edx, eax
    shr edx, cl
    xor edx, eax
    mov eax, dword ptr [dword_7FF8571CC8B8]
    lea ecx, [rax-57BB2524h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    xor r8d, 1B174C2Fh
    add r8d, -20333F15h
    mov r9d, r8d
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    and r10d, -112A1F01h
    lea r10d, [r10+r10*2]
    mov r11d, r9d
    and r11d, 2ED5E0FFh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    shl r11d, 2
    and r9d, 112A1F00h
    mov esi, r9d
    not esi
    add r9d, r9d
    and r8d, 112A1F00h
    lea r8d, [r9+r8*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    sub esi, r11d
    sub esi, r10d
    sub esi, ecx
    add eax, esi
    add eax, -3
    imul eax, edx
    mov r10d, dword ptr [dword_7FF8571CC8BC]
    mov r9d, r10d
    xor r9d, 4F9C75B9h
    lea edx, [r9+3E8B4AA2h]
    mov ecx, edx
    xor ecx, -3A551F55h
    mov r8d, ecx
    or r8d, 332F8D2Ah
    lea r11d, [r8+r8*2]
    not r8d
    lea esi, [r8*8]
    sub esi, r8d
    and ecx, 332F8D2Ah
    lea r11d, [rcx+r11*2]
    add r11d, r9d
    add r11d, esi
    mov r8d, edx
    xor r8d, 4C1C5A56h
    lea ecx, [r8-145A0B3Dh]
    neg r11d
    add r9d, r11d
    add r9d, 0A8EC838h
    xor r9d, edx
    add r9d, r10d
    xor edx, -4C1C5A57h
    mov r10d, r9d
    or r10d, edx
    not r10d
    lea r11d, [r10+r10*4]
    lea r10d, [r10+r11*4]
    mov esi, r9d
    or esi, r8d
    lea r11d, [rsi+rsi*4]
    lea r11d, [rsi+r11*2]
    not esi
    lea edi, [rsi+rsi*4]
    lea esi, [rsi+rdi*2]
    and r8d, r9d
    lea edi, [r8+r8*8]
    not r8d
    lea ebx, [r8+r8*4]
    lea r8d, [r8+rbx*2]
    and edx, r9d
    lea r9d, [rdx+rdx*4]
    lea edx, [rdx+r9*4]
    add edi, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r11d, edi
    add r11d, r8d
    sub r11d, esi
    sub r11d, r10d
    mov edx, ecx
    not edx
    mov r8d, r11d
    or r8d, edx
    mov r9d, r11d
    or r9d, ecx
    mov r10d, r11d
    and r10d, edx
    xor edx, r11d
    add edx, r9d
    lea r9d, [r11+r11]
    lea r10d, [r10+r10*2]
    and r11d, ecx
    lea ecx, [r11+r11*2]
    add ecx, r10d
    sub ecx, r9d
    add ecx, edx
    sub ecx, r8d
    mov edx, eax
    shr edx, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor edx, eax
    mov eax, dword ptr [rsp+4D0h]
    mov ecx, dword ptr [dword_7FF8571CC8C0]
    lea r8d, [rcx+3DC7A2D8h]
    xor r8d, -7F8F0EB3h
    lea r9d, [r8-3112D128h]
    mov r10d, r9d
    not r10d
    and r10d, 3E98122Bh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r11d, 0FFFFFFFF9DDA5DB0h[r8*2]
    or r11d, -2CFDBAAh
    mov esi, r9d
    xor esi, -167EDD5h
    mov edi, r9d
    and edi, 167EDD4h
    shl edi, 2
    and r9d, 7E98122Bh
    lea r9d, [rdi+r9*2]
    sub r9d, esi
    sub r9d, r11d
    lea r11d, [r9+r10*4]
    lea r9d, [r9+r10*4]
    add r9d, 748A68ADh
    xor r9d, -68AC15F4h
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
    mov r10d, r11d
    not r10d
    mov esi, r9d
    or esi, r10d
    not esi
    lea esi, [rsi+rsi*4]
    lea edi, [r11+r11]
    lea edi, [rdi+rdi*2]
    mov ebx, r9d
    or ebx, r11d
    lea ebx, [rbx+rbx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r10d, r9d
    and r9d, r11d
    lea r9d, [r9+r9*8]
    lea r9d, [r9+r10*4]
    sub r9d, ebx
    sub r9d, edi
    lea r9d, [r9+rsi*2]
    sub r9d, ecx
    add r8d, r9d
    add r8d, -3112D128h
    add ecx, r8d
    add ecx, 3DC7A2D8h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add cl, 0A1h
    mov r8, rax
    shl r8, cl
    mov r9, rdx
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
    mov rcx, r8
    or rcx, r9
    not rcx
    lea rcx, [rcx+rcx*2]
    mov r10, r8
    or r10, rdx
    not r10
    lea r11, [r10+r10*4]
    lea r10, [r10+r11*2]
    and r9, r8
    mov r11, r9
    not r11
    lea rsi, [r11+r11*4]
    lea r11, [r11+rsi*2]
    lea rsi, [r8*8]
    sub rsi, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9, r9
    lea r9, [r9+r9*2]
    and r8d, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rdx, [r8+r8*4]
    sub rdx, r9
    add rdx, rsi
    sub rdx, r11
    add rdx, r10
    lea rcx, [rdx+rcx*4]
    shr eax, 1
    xor rax, rcx
    mov rcx, qword ptr [qword_7FF8571CC8C8]
    mov rdx, 21F4C1A782BEE48Dh
    add rdx, rcx
    mov r8, rdx
    mov r9, rdx
    mov r10, 400B50780404280h
    xor r9, r10
    mov r11, rdx
    mov r10, 79FE08B079B6A473h
    xor r11, r10
    mov r10, r11
    mov rdi, r11
    add rdx, rcx
    add rdx, r11
    mov r14, 1C7CBD17D8C262C0h
    or r11, r14
    lea rsi, [r11+r11*4]
    lea rsi, [r11+rsi*2]
    not r11
    lea rbx, [r11*8]
    sub rbx, r11
    and r9, r14
    mov r11, r9
    shl r11, 4
    add r11, r9
    and r10, r14
    mov r9, -1C7CBD17D8C262C1h
    and rdi, r9
    lea r9, [rdi+rdi*8]
    lea r9, [rdi+r9*2]
    lea rdi, [r10+r10*2]
    lea r9, [r9+rdi*4]
    not r10
    add r10, r10
    lea r10, [r10+r10*2]
    sub r9, rsi
    sub r9, r10
    add r11, rbx
    add r11, r9
    mov r9, r11
    not r9
    mov rbx, -59534AF81070B8B0h
    and r9, rbx
    lea r10, [r9+r9*4]
    lea r9, [r9+r10*2]
    mov r10, r11
    or r10, rbx
    lea rsi, [r10+r10*4]
    lea r10, [r10+rsi*2]
    mov rsi, r11
    mov rdi, r11
    mov r14, 59534AF81070B8AFh
    and rdi, r14
    lea rdi, [rdi+rdi*8]
    and r11, rbx
    imul r11, 0F5h
    sub r11, rdi
    mov rdi, -1E051A969ECDB28Dh
    xor r8, rdi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor rsi, rbx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r11, rsi
    add r11, r10
    sub r11, r9
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
    sub rdx, rcx
    mov rcx, 56A2631D912B9909h
    add rdx, rcx
    add rdx, r11
    imul rdx, rax
    mov eax, dword ptr [dword_7FF8571CC8D0]
    lea r8d, [rax-6385B128h]
    lea r9d, [rax+44B642E2h]
    lea ecx, [rax+3CBC0633h]
    xor ecx, r8d
    xor ecx, r9d
    lea r8d, [rax-5F84509Bh]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor ecx, 0E8h
    add ecx, eax
    xor ecx, r8d
    mov rax, rdx
    shr rax, cl
    xor rax, rdx
    mov rcx, -3B314601E57A13ADh
    imul rax, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    shr rcx, 21h
    xor ecx, eax
    mov dword ptr [rsp+1A4h], ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+3F8h]
    add rax, qword ptr [rsp+598h]
    mov rcx, -1
    cmovb rax, rcx
    loc_7FF856816B32:
    mov rdx, qword ptr [qword_7FF8571CC8D8]
    mov r8, rdx
    mov rcx, -22BAEE124FE1F24Ch
    xor r8, rcx
    mov rcx, -7543787850B7BFF6h
    add rcx, r8
    mov r10, rcx
    mov r9, 1AFAB8D15A59019Eh
    xor r10, r9
    mov r9, r10
    sub r9, rdx
    mov r11, 155D0CFB0C2B042Ch
    add r9, r11
    xor r9, r10
    mov r10, 22BAEE124FE1F24Bh
    xor rdx, r10
    mov r10, r9
    or r10, rdx
    mov r11, r9
    or r11, r8
    mov rsi, r9
    and rsi, rdx
    xor rdx, r9
    and r9, r8
    not r11
    lea rdx, [rdx+rdx*2]
    lea r8, [rsi+rsi*2]
    add r8, r8
    lea r8, [r8+r9*8]
    lea r9, [r10+r10*4]
    not r10
    sub r8, r9
    sub r8, rdx
    lea rdx, [r8+r11*8]
    add rdx, r10
    mov r8, rcx
    not r8
    mov r9, rdx
    or r9, r8
    mov r10, rdx
    or r10, rcx
    mov r11, rdx
    xor r11, rcx
    and r8, rdx
    and rdx, rcx
    shl r8, 2
    lea rcx, [r8+rdx*2]
    sub rcx, r11
    add r10, r10
    sub rcx, r10
    not r9
    lea rcx, [rcx+r9*4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov ecx, 0
    cmovnz rcx, rax
    loc_7FF856816D89:
    mov qword ptr [rsp+5B0h], rcx
    mov rax, qword ptr [rsp+3F8h]
    mov rcx, qword ptr [rsp+48h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    jz loc_7FF856829017
    mov rcx, qword ptr [rsp+100h]
    add rcx, qword ptr [rsp+48h]
    mov edx, dword ptr [rsp+0C4h]
    mov r8, qword ptr [rsp+5A8h]
    mov r9d, dword ptr [rsp+198h]
    mov r10d, dword ptr [rsp+1A4h]
    mov r11, qword ptr [rsp+5B0h]
    mov dword ptr [rsp+2F0h], edx
    mov qword ptr [rsp+720h], r8
    mov dword ptr [rsp+2F4h], r9d
    mov dword ptr [rsp+2F8h], r10d
    mov qword ptr [rsp+728h], r11
    mov qword ptr [rsp+730h], rcx
    mov qword ptr [rsp+738h], rax
    mov eax, dword ptr [dword_7FF85723AAD8]
    lea ecx, [rax+5A1F64C0h]
    lea edx, [rax+1ECFE2B9h]
    lea r8d, [rax+2E7742A1h]
    xor r8d, ecx
    xor r8d, edx
    sub r8d, eax
    add r8d, -33CABA43h
    mov dword ptr [rsp+3Ch], r8d
    jmp loc_7FF856813884
    loc_7FF856816E92:
    cmp eax, 3BFD1C27h
    jg loc_7FF8568197EE
    cmp eax, 3819CDB7h
    jz loc_7FF85681C718
    cmp eax, 399DDDAAh
    jnz loc_7FF85681C1F7
    mov eax, dword ptr [rsp+124h]
    jmp loc_7FF856825DB9
    loc_7FF856816EBF:
    cmp eax, 119D5856h
    jg loc_7FF85681982C
    cmp eax, 0FE2522Fh
    jz loc_7FF85681B860
    cmp eax, 0FFAEAA6h
    jz loc_7FF856817D52
    mov rcx, qword ptr [rsp+778h]
    mov rdx, qword ptr [rsp+378h]
    mov r8d, dword ptr [dword_7FF8571CC6A8]
    lea r9d, [r8+105424ADh]
    lea eax, [r8+1FFDF3D7h]
    lea r10d, [r8+548FC1E1h]
    xor r10d, -4B4888F4h
    xor eax, r8d
    xor eax, r10d
    xor eax, r9d
    xor eax, 71B14E02h
    sub eax, r10d
    add eax, dword ptr [rsp+84h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, dword ptr [rsp+84h]
    mov r9d, r8d
    not r9d
    lea r10d, [r9*8]
    shl r8d, 2
    sub r10d, r9d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11d, dword ptr [rsp+84h]
    lea r10d, [r10+r11*2]
    sub r8d, r10d
    cmp rcx, rdx
    lea ecx, [r8+r9*8]
    cmova eax, dword ptr [rsp+450h]
    loc_7FF856817060:
    cmovbe ecx, dword ptr [rsp+44Ch]
    loc_7FF856817068:
    mov dword ptr [rsp+4F8h], eax
    cmp eax, ecx
    jle loc_7FF85682815D
    mov eax, dword ptr [dword_7FF85723A9D0]
    lea ecx, [rax-1F6B1DF8h]
    xor ecx, -23BF1FC4h
    lea edx, [rcx+76A9B073h]
    lea r8d, [rax-3D6E799Bh]
    xor r8d, edx
    xor edx, 6118362Eh
    add r8d, ecx
    sub r8d, edx
    add r8d, eax
    mov dword ptr [rsp+3Ch], r8d
    jmp loc_7FF856813884
    loc_7FF8568170B2:
    cmp eax, 318CB702h
    jg loc_7FF85681998E
    cmp eax, 2B6CF094h
    jz loc_7FF85681E056
    cmp eax, 2C62F10Fh
    jnz loc_7FF856819C89
    mov rax, qword ptr [rsp+830h]
    lea rcx, [rax+rax*4]
    lea rax, [rax+rcx*2]
    mov rcx, qword ptr [rsp+818h]
    mov rdx, qword ptr [rsp+820h]
    mov r8, rdx
    xor r8, rcx
    add r8, r8
    mov r9, rcx
    not r9
    and r9, rdx
    shl r9, 3
    and rdx, rcx
    imul rcx, rdx, 0F5h
    sub rcx, r9
    sub rcx, r8
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
    sub rcx, qword ptr [rsp+828h]
    sub rcx, qword ptr [rsp+808h]
    add rcx, qword ptr [rsp+810h]
    cmp qword ptr [rsp+570h], rcx
    jnz loc_7FF856828D9A
    mov eax, dword ptr [dword_7FF85723AABC]
    mov ecx, eax
    xor ecx, 0AC52678h
    lea edx, [rcx-4BD135Ah]
    mov r8d, edx
    xor r8d, 190E6D7Eh
    lea r9d, [r8-12E909FEh]
    mov r10d, r9d
    xor r10d, 68AC5F3Ch
    add r10d, 6C5C468Fh
    add eax, -5A8EF436h
    xor eax, ecx
    sub eax, r10d
    sub eax, r10d
    add eax, -56D7956Bh
    xor eax, r8d
    sub eax, edx
    sub eax, r9d
    jmp loc_7FF856813880
    loc_7FF856817208:
    cmp eax, 1F755B13h
    jg loc_7FF85681A649
    cmp eax, 19F75BC9h
    jz loc_7FF85681EFF9
    cmp eax, 1A360A75h
    jnz loc_7FF856825B99
    mov eax, dword ptr [rsp+88h]
    mov ecx, dword ptr [rsp+110h]
    mov edx, dword ptr [rsp+8Ch]
    mov dword ptr [rsp+1E8h], eax
    mov dword ptr [rsp+1ECh], ecx
    mov dword ptr [rsp+1F0h], edx
    jmp loc_7FF85681F15E
    loc_7FF856817258:
    cmp eax, 0E917F6Bh
    jg loc_7FF85681A8D1
    cmp eax, 6E2330Fh
    jz loc_7FF85681C4B4
    cmp eax, 0B9B5C7Ch
    jnz loc_7FF85681B20D
    mov rax, qword ptr [rsp+350h]
    add rax, qword ptr [rsp+7F8h]
    movzx eax, byte ptr [r13+rax+0]
    mov rcx, qword ptr [rsp+800h]
    xor byte ptr [rcx], al
    mov rax, qword ptr [rsp+350h]
    or rax, 1
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rsp+350h]
    mov rdx, rcx
    or rdx, -2
    mov r8, rcx
    xor r8, 1
    add r8, rdx
    lea rdx, [rcx+rcx]
    mov r9d, ecx
    and r9d, 1
    lea r9, [r9+r9*2]
    and rcx, -2
    lea rcx, [rcx+rcx*2]
    add rcx, r9
    sub rcx, rdx
    add rcx, r8
    sub rcx, rax
    mov qword ptr [rsp+570h], rcx
    mov rax, qword ptr [qword_7FF8571CC940]
    mov rcx, -18FDAD6AA4ACB11Bh
    add rcx, rax
    mov qword ptr [rsp+808h], rcx
    mov rdx, rcx
    mov r8, -142E95B00127F5F7h
    xor rdx, r8
    mov qword ptr [rsp+810h], rdx
    mov rdx, rcx
    mov r8, -256F035F746729B0h
    xor rdx, r8
    mov qword ptr [rsp+818h], rdx
    mov r8, -72122E1C3D5A617Ah
    sub r8, rax
    mov qword ptr [rsp+820h], r8
    mov rax, 256F035F746729AFh
    xor rcx, rax
    or rcx, r8
    not rcx
    add rcx, rcx
    lea rax, [rcx+rcx*4]
    mov qword ptr [rsp+828h], rax
    or r8, rdx
    mov qword ptr [rsp+830h], r8
    mov eax, dword ptr [dword_7FF85723AAB8]
    mov ecx, 39729FBBh
    add eax, ecx
    mov ecx, eax
    xor ecx, 51B00FC7h
    xor eax, 40A0D13Eh
    add eax, ecx
    mov ecx, 0B09D010h
    sub ecx, eax
    mov dword ptr [rsp+3Ch], ecx
    jmp loc_7FF856813884
    loc_7FF856817414:
    cmp eax, 6464627Bh
    jz loc_7FF856813423
    cmp eax, 65D16434h
    jnz loc_7FF85681B7EA
    loc_7FF85681742A:
    mov qword ptr [rsp+410h], 0
    jmp loc_7FF856825BA8
    loc_7FF85681743B:
    cmp eax, 762F1CB4h
    jz loc_7FF85681B7D9
    cmp eax, 76423155h
    jnz loc_7FF85681B804
    mov rax, qword ptr [rsp+3C0h]
    not rax
    or rax, qword ptr [rsp+78h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    lea rcx, [rax+rax*4]
    lea rax, [rax+rcx*2]
    mov rcx, qword ptr [rsp+78h]
    mov rdx, qword ptr [rsp+3C0h]
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
    imul rcx, 0F5h
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
    sub rcx, r9
    add rcx, r8
    sub rcx, rax
    mov rax, qword ptr [rsp+0E0h]
    mov rdx, qword ptr [rsp+3C0h]
    add rdx, qword ptr [rsp+3B8h]
    movzx edx, byte ptr [r13+rdx+0]
    xor byte ptr [rax+rcx], dl
    mov rdx, qword ptr [qword_7FF8571CC720]
    mov rax, -312D3E87738CF6DBh
    xor rdx, rax
    mov rax, 4260E7EEFADACE5Ah
    add rax, rdx
    mov rcx, 6DAF8663A9621B9Dh
    lea r8, [rdx+rcx]
    mov rcx, r8
    mov r9, 7D8FC23CFFA28A9h
    xor rcx, r9
    mov r9, r8
    mov r10, -5FDCFCBBEFFBAFBEh
    xor r9, r10
    mov r10, r8
    mov r11, 5804009820018714h
    xor r10, r11
    mov r11, 5E545C9963CB8FB5h
    and r10, r11
    or r9, r11
    lea r9, [r9+rcx*2]
    add r9, r10
    mov r10, -298ECB46AE4A909h
    sub r10, rdx
    xor r10, r8
    mov r11, 2023034410045042h
    xor r8, r11
    mov r11, 21ABA3669C34704Ah
    and r8, r11
    lea r9, [r9+r8*2]
    add r9, 2
    mov r8, -40B71B8001986B17h
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor rax, rdx
    xor rax, r10
    mov rdx, -3E3BD52D12DD959h
    xor rax, rdx
    mov r10, rax
    or r10, r9
    not r10
    add r10, r10
    mov rdx, rax
    and rdx, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    xor rax, r9
    sub rdx, rax
    sub rdx, r10
    add rdx, rcx
    xor rdx, r8
    mov rax, qword ptr [qword_7FF8571CC728]
    mov rcx, 1968FB1D5ABFF8F4h
    add rcx, rax
    mov r8, rcx
    lea r9, [rcx+rcx]
    mov r10, rcx
    mov r11, 6154D0E5B15116E2h
    and r10, r11
    mov r11, 1EAB2F1A4EAEE91Dh
    and rcx, r11
    lea rcx, [rcx+rcx*2]
    lea rcx, [rcx+r10*2]
    sub r9, rcx
    or r8, r11
    add r8, rax
    sub r9, r8
    add rdx, qword ptr [rsp+0E8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, 1284CA8A251FCF57h
    add r9, rax
    cmp rdx, r9
    jnz loc_7FF85682734E
    mov eax, dword ptr [dword_7FF85723AA5C]
    mov ecx, eax
    xor ecx, 29E1A18Fh
    lea edx, [rcx+7F05EA91h]
    xor edx, -6625115Eh
    add ecx, edx
    add ecx, 7F05EA91h
    add ecx, eax
    mov eax, -281FEC13h
    sub eax, ecx
    jmp loc_7FF856813880
    loc_7FF8568178DA:
    cmp eax, 4593588Ch
    jz loc_7FF8568194C7
    cmp eax, 4595D682h
    jnz loc_7FF85681BD95
    lea rcx, [r12+10h]
    mov qword ptr [rsp+500h], rcx
    call qword ptr [__imp_RtlAcquireSRWLockExclusive]
    mov eax, dword ptr [rsp+424h]
    mov byte ptr [rsp+41h], al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp byte ptr [r12+58h], 97h
    setnz al
    xor al, byte ptr [rsp+41h]
    test al, 1
    jz loc_7FF8568277CD
    mov eax, dword ptr [dword_7FF85723AB34]
    mov ecx, 7C9C147Ch
    xor eax, ecx
    lea ecx, [rax+489FDB51h]
    mov edx, ecx
    xor edx, 2582379Ch
    sub edx, eax
    sub edx, ecx
    add edx, 0AF48DA8h
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF8568179C9:
    cmp eax, 560209AEh
    jz loc_7FF85681A91A
    cmp eax, 5744A8A9h
    jz loc_7FF856828C76
    mov eax, dword ptr [rsp+144h]
    mov ecx, dword ptr [rsp+148h]
    mov rdx, qword ptr [rsp+530h]
    mov r8d, dword ptr [rsp+14Ch]
    mov r9d, dword ptr [rsp+150h]
    mov r10, qword ptr [rsp+538h]
    mov dword ptr [rsp+280h], eax
    mov dword ptr [rsp+284h], ecx
    mov qword ptr [rsp+680h], rdx
    mov dword ptr [rsp+288h], r8d
    mov qword ptr [rsp+688h], r10
    mov dword ptr [rsp+28Ch], r9d
    mov eax, dword ptr [dword_7FF85723AA2C]
    lea ecx, [rax+0FA2ED6Fh]
    lea edx, [rax-55234AEh]
    xor edx, 3E494C1Eh
    add edx, -1F1A2A12h
    xor ecx, eax
    xor ecx, edx
    xor ecx, -2C2D39AEh
    mov dword ptr [rsp+3Ch], ecx
    jmp loc_7FF856813884
    loc_7FF856817A6C:
    cmp eax, 4767B93h
    jz loc_7FF85681BCFE
    cmp eax, 491652Ch
    jnz loc_7FF85681D6A0
    loc_7FF856817A82:
    mov eax, dword ptr [rsp+184h]
    loc_7FF856817A89:
    mov dword ptr [rsp+0CCh], eax
    mov eax, dword ptr [rsp+0CCh]
    mov ecx, dword ptr [rsp+0ACh]
    add ecx, 4
    mov edx, dword ptr [dword_7FF8571CC938]
    lea r9d, [rdx+1B787985h]
    mov r8d, r9d
    not r8d
    mov r10d, r8d
    and r10d, 1C778CFEh
    mov r11d, r8d
    and r11d, 63887301h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov esi, r8d
    or esi, 63887301h
    lea esi, [rsi+rdx*2]
    add esi, 36F0F30Ah
    add esi, r11d
    lea r10d, [rsi+r10*2]
    sub r10d, edx
    add r10d, -4E5BAAC7h
    mov r11d, r10d
    or r11d, r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea esi, [r11+r11*4]
    lea r11d, [r11+rsi*2]
    mov esi, r10d
    or esi, r9d
    lea edi, [r9+r9*4]
    lea edi, [rdx+rdi*2]
    add edi, 1B787985h
    and r8d, r10d
    add r8d, edi
    add r8d, esi
    and r9d, r10d
    imul r9d, 0F5h
    add r9d, r8d
    sub r9d, r11d
    sub r9d, r10d
    add r9d, edx
    add r9d, -4E19E374h
    mov r11d, r9d
    not r11d
    mov edx, ecx
    or edx, r11d
    mov r8d, edx
    not r8d
    lea r8d, [r8+r8*2]
    mov r10d, ecx
    or r10d, r9d
    not r10d
    lea esi, [r10+r10*2]
    lea r10d, [r10+rsi*4]
    and r9d, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r11d, ecx
    lea ecx, [r11+r11*2]
    lea ecx, [r11+rcx*4]
    lea ecx, [rcx+r9*8]
    not r9d
    add r9d, r9d
    lea r9d, [r9+r9*2]
    lea r11d, [rdx*8]
    sub edx, r11d
    add edx, ecx
    sub edx, r9d
    add edx, r10d
    lea ecx, [rdx+r8*2]
    mov rdx, qword ptr [rsp+558h]
    add rdx, qword ptr [rsp+58h]
    mov dword ptr [rsp+2C4h], eax
    mov dword ptr [rsp+2C8h], eax
    mov qword ptr [rsp+6D0h], rdx
    mov dword ptr [rsp+2CCh], ecx
    loc_7FF856817D52:
    mov eax, dword ptr [rsp+2CCh]
    mov rdx, qword ptr [rsp+6D0h]
    mov r8d, dword ptr [rsp+2C8h]
    mov r9d, dword ptr [rsp+2C4h]
    mov r10d, edx
    xor r10d, r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11d, dword ptr [dword_7FF8571CC948]
    mov ecx, 1D2AED5Fh
    add r11d, ecx
    mov esi, r11d
    xor esi, 6CA464FFh
    lea ecx, [rsi-159D8CDCh]
    mov edi, ecx
    xor edi, 1Fh
    xor ecx, -77716A96h
    sub ecx, esi
    sub ecx, esi
    sub ecx, esi
    add ecx, -42CEF7A0h
    xor ecx, r11d
    sub ecx, edi
    mov r11d, r10d
    shr r11d, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r11d, r10d
    imul r10d, r11d, -7A143595h
    mov edi, dword ptr [dword_7FF8571CC94C]
    lea r11d, [rdi+7A92E062h]
    lea ecx, [rdi+66DCDB7Ch]
    mov esi, ecx
    or esi, 3A701F36h
    lea ebx, [rsi+rsi*2]
    not esi
    lea ebp, [rsi*8]
    sub ebp, esi
    and ecx, 36h
    lea ecx, [rcx+rbx*2]
    add ecx, ebp
    mov ebx, -7
    sub ebx, ecx
    xor edi, 766453B8h
    mov ecx, r11d
    not ecx
    lea esi, [rcx+rcx*4]
    mov r14d, edi
    or r14d, ecx
    not r14d
    lea ebp, [r14+r14*2]
    mov r14d, edi
    or r14d, r11d
    not r14d
    lea r14d, [r14+r14*4]
    xor r11d, edi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r11d, r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and ecx, edi
    shl ecx, 3
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub ecx, r11d
    add ecx, r14d
    add ecx, ebp
    sub ecx, esi
    xor ecx, ebx
    mov edi, r10d
    shr edi, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor edi, r10d
    mov r11d, dword ptr [dword_7FF8571CC950]
    mov r10d, r11d
    xor r10d, -3094865Fh
    lea esi, [r10-335B246Ah]
    mov ecx, esi
    not ecx
    and ecx, 11D4C5Bh
    lea ecx, [rcx+rcx*2]
    lea ebx, 0FFFFFFFF9949B72Ch[r10*2]
    or ebx, 23A98B6h
    lea ebx, [rbx+rbx*2]
    mov ebp, esi
    xor ebp, -11D4C5Ch
    mov r14d, esi
    and r14d, 11D4C5Bh
    lea r14d, [r14+r14*2]
    add r14d, r14d
    and esi, 7EE2B3A4h
    lea esi, [rsi+rsi*2]
    lea esi, [r14+rsi*2]
    add esi, ebp
    sub esi, ebx
    lea ebp, [rsi+rcx*2]
    mov ecx, ebp
    xor ecx, -3D144641h
    lea r13d, [rcx+2E375154h]
    mov esi, r13d
    not esi
    mov r14d, r13d
    and r14d, 1FE3DDB9h
    mov ebx, r13d
    and ebx, -1FE3DDBAh
    sub ebx, r14d
    mov r14d, r13d
    xor r14d, -1FE3DDBAh
    lea r14d, [r14+r14*2]
    add ebx, r14d
    mov r14d, r13d
    or r14d, 1FE3DDB9h
    sub ebx, r14d
    not r14d
    shl r14d, 2
    and esi, 1FE3DDB9h
    add ebx, esi
    sub ebx, r14d
    sub ecx, ebp
    add ecx, 1336166Eh
    mov r15d, ebx
    not r15d
    mov r14d, ecx
    or r14d, r15d
    mov ebp, ecx
    or ebp, ebx
    and ebx, ecx
    and r15d, ecx
    imul esi, edi, -3D4D51CBh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not r14d
    not ebp
    add r15d, r15d
    lea ecx, [r15+rbx*2]
    not ebx
    add ebx, ebp
    add ebx, ecx
    lea ecx, [rbx+r14*2]
    add ecx, r10d
    add ecx, -335B2468h
    xor ecx, r13d
    add ecx, r11d
    sub ecx, r10d
    mov r10d, esi
    shr r10d, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r10d, esi
    mov ecx, dword ptr [dword_7FF8571CC958]
    mov edi, ecx
    xor ecx, 2E0A4702h
    lea r13d, [rcx-7EB0825Bh]
    mov r11d, r13d
    not r11d
    mov esi, r11d
    mov ebx, r11d
    mov r14d, r13d
    and r11d, -42DB8601h
    and r13d, -42DB8601h
    sub r13d, r11d
    mov r11d, dword ptr [rsp+4ACh]
    xor edi, -326A07D1h
    or esi, -42DB8601h
    xor r14d, -42DB8601h
    lea ebp, [r14+r14*2]
    add r13d, ebp
    sub r13d, esi
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
    shl esi, 2
    and ebx, 42DB8600h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r13d, ebx
    sub r13d, esi
    sub r13d, ecx
    sub r13d, ecx
    add r13d, 7AE322C4h
    mov esi, r13d
    or esi, ecx
    lea ebx, [rsi+rsi*2]
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
    and r13d, ecx
    lea esi, [r13+rbx*2+0]
    add esi, ebp
    mov ebx, -7
    sub ebx, esi
    mov esi, ebx
    or esi, edi
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
    and ebx, edi
    lea esi, [rbx+r14*2]
    add esi, ecx
    add esi, ebp
    mov cl, 0F6h
    sub cl, sil
    mov rsi, r11
    shl rsi, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or r10, rsi
    mov ebx, dword ptr [dword_7FF8571CC960]
    mov ecx, ebx
    xor ecx, 5867F146h
    mov edi, ebx
    xor edi, -5867F147h
    mov esi, edi
    and esi, 193D174Fh
    lea esi, [rsi+rsi*2]
    mov r14d, ecx
    and r14d, 193D174Fh
    lea r14d, [r14+r14*2]
    add r14d, r14d
    mov r15d, ecx
    and r15d, 66C2E8B0h
    lea r15d, [r15+r15*2]
    lea r14d, [r14+r15*2]
    mov ebp, ebx
    xor ebp, 3EA519F6h
    add r14d, ebp
    lea r15d, [rcx+rcx]
    or r15d, 327A2E9Eh
    lea ebp, [r15+r15*2]
    sub r14d, ebp
    lea ebp, [r14+rsi*2]
    add ebp, -7B718962h
    lea esi, [r14+rsi*2]
    add esi, 7DDE692h
    xor esi, 603ED099h
    add ebp, ebp
    sub ebp, esi
    add ebp, -4128D94Dh
    xor ebp, ebx
    lea esi, [rdi+rdi*2]
    mov ebx, ebp
    or ebx, edi
    mov r14d, ebp
    or r14d, ecx
    and edi, ebp
    lea edi, [rdi+rdi*2]
    and ecx, ebp
    sub edi, ecx
    add edi, ebp
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not r14d
    lea ecx, [r14+r14*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add ecx, ebx
    add ecx, edi
    sub ecx, esi
    inc cl
    shr r11, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r11, r10
    mov rcx, -0AE502812AA7333h
    imul r11, rcx
    mov rcx, r11
    shr rcx, 21h
    xor rcx, r11
    mov r11, qword ptr [qword_7FF8571CC968]
    mov r10, 5C8293EB3615B1BCh
    lea rdi, [r11+r10]
    mov r10, rdi
    not r10
    mov rsi, r10
    mov r14, 495F44201BE9C95Fh
    or rsi, r14
    mov rbx, r10
    mov r15, -495F44201BE9C960h
    and rbx, r15
    add rbx, rsi
    and rdi, r14
    add rdi, rdi
    mov rsi, -6D4177BFC82C6D42h
    xor rdi, rsi
    add rdi, rbx
    mov rsi, 5DAC150C72495B45h
    add rsi, r11
    add r10, rsi
    sub rdi, r10
    mov r10, 12020897BAA1A3C0h
    add r10, r11
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rbx, 70A5420A21FB3A60h
    add rdi, rbx
    xor r10, r11
    xor r10, rdi
    add r10, rsi
    imul r10, rcx
    mov r11d, dword ptr [dword_7FF8571CC970]
    mov ecx, 56F3587Fh
    xor r11d, ecx
    lea ecx, [r11+34BF6F2Fh]
    lea esi, [r11-15ECE844h]
    mov edi, esi
    xor edi, 7CD4D8B1h
    sub edi, esi
    sub edi, r11d
    add edi, -79153815h
    mov r11d, edi
    or r11d, ecx
    not ecx
    mov esi, edi
    or esi, ecx
    and ecx, edi
    not edi
    add edi, edi
    not esi
    not r11d
    lea ecx, [rcx+r11*2]
    add ecx, esi
    sub ecx, edi
    mov r11, r10
    shr r11, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r11d, r10d
    mov r10, qword ptr [rsp+568h]
    add r10, qword ptr [rsp+560h]
    mov rcx, -1
    cmovb r10, rcx
    loc_7FF856818B95:
    mov dword ptr [rsp+180h], r11d
    mov rcx, qword ptr [qword_7FF8571CC978]
    mov r11, -24E89A35B0261C38h
    add r11, rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rsi, r11
    mov rdi, -0B259110857007C3h
    xor rsi, rdi
    mov rdi, 199C67A834422C5Dh
    sub rdi, rcx
    mov rcx, 19FC48392F56BEEAh
    add rcx, rsi
    xor rdi, rcx
    mov rcx, -3BB61BC763326AE5h
    lea rbx, [rsi+rcx]
    add rsi, r11
    mov rcx, rbx
    mov r11, -563619C5E917DB4Fh
    xor rcx, r11
    add rsi, rdi
    add rbx, rcx
    mov r11, 62BEB0160A9C6CAEh
    xor rcx, r11
    xor rcx, rsi
    add rcx, rbx
    cmp r10, -1
    cmovnz rcx, r10
    loc_7FF856818C5E:
    mov r10, qword ptr [qword_7FF8571CC980]
    mov r11, 50136734967A8AC8h
    add r10, r11
    mov r11, r10
    mov rbx, 6DACDAA50047E0B3h
    or r11, rbx
    mov rsi, r10
    and rsi, rbx
    lea rsi, [rsi+rsi*2]
    add rsi, rsi
    mov rdi, r10
    mov r14, 1253255AFFB81F4Ch
    and rdi, r14
    lea rsi, [rsi+rdi*8]
    lea rdi, [r11+r11*4]
    sub rsi, rdi
    mov rdi, r10
    xor rdi, rbx
    lea rdi, [rdi+rdi*2]
    sub rsi, rdi
    mov rdi, r10
    not rdi
    mov rbx, 0DACDAA50047E0B3h
    and rdi, rbx
    lea rsi, [rsi+rdi*8]
    not r11
    add rsi, r11
    mov rdi, rsi
    mov r11, -4DEAD8C3C6B52887h
    xor rdi, r11
    add rdi, rsi
    mov r11, 28DC45A63C884135h
    add rsi, r11
    sub rdi, rsi
    mov r11, 5F06329A7457B40Ch
    add rdi, r11
    xor rdi, r10
    mov r10, qword ptr [rsp+568h]
    mov r11, 138D17CEC7756525h
    xor rsi, r11
    add rdi, rsi
    mov r11, qword ptr [rsp+58h]
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
    cmp r10, rdi
    jnz loc_7FF85681AF3E
    mov eax, dword ptr [dword_7FF85723AA58]
    mov ecx, eax
    xor ecx, 76A023F1h
    mov edx, eax
    xor edx, 2AC95AB1h
    xor eax, 19F50502h
    sub ecx, eax
    sub ecx, eax
    sub ecx, edx
    add ecx, 0AAC9A67h
    mov dword ptr [rsp+3Ch], ecx
    lea r13, eidolon_sbox
    jmp loc_7FF856813884
    loc_7FF856818DA6:
    cmp eax, 4F0BC85Dh
    jz loc_7FF856818E6D
    cmp eax, 52415214h
    jnz loc_7FF85681C8EF
    mov eax, dword ptr [rsp+4F4h]
    add eax, dword ptr [rsp+4F0h]
    mov ecx, dword ptr [rsp+4ECh]
    sub ecx, eax
    add ecx, dword ptr [rsp+4E8h]
    add ecx, dword ptr [rsp+4DCh]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub ecx, dword ptr [rsp+4E4h]
    add ecx, dword ptr [rsp+4E0h]
    mov eax, dword ptr [rsp+4D8h]
    add cl, 2Ch
    shl eax, cl
    mov dword ptr [rsp+324h], eax
    loc_7FF856818E6D:
    mov eax, dword ptr [rsp+324h]
    mov rcx, qword ptr [rsp+358h]
    movzx r8d, byte ptr [rcx+1]
    imul ecx, r8d, 700h
    shl r8d, 8
    mov r9d, eax
    not r9d
    mov edx, r8d
    or edx, r9d
    not edx
    lea edx, [rdx+rdx*2]
    mov r10d, r8d
    or r10d, eax
    not r10d
    lea r11d, [r10+r10*4]
    lea r10d, [r10+r11*2]
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
    nop
    mov r11d, r9d
    not r11d
    lea esi, [r11+r11*4]
    lea r11d, [r11+rsi*2]
    add r9d, r9d
    lea r9d, [r9+r9*2]
    and r8d, eax
    lea eax, [r8+r8*4]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    sub eax, r11d
    add eax, r10d
    lea eax, [rax+rdx*4]
    mov dword ptr [rsp+320h], eax
    jmp loc_7FF85681A9FD
    loc_7FF856818FAC:
    cmp eax, 707D44A2h
    jz loc_7FF85681C3EF
    cmp eax, 71584333h
    jnz loc_7FF856821728
    mov rax, qword ptr [qword_7FF8571CC760]
    mov rcx, rax
    not rcx
    mov r9, rax
    mov r8, -6F73ACA66B8BFE21h
    or r9, r8
    mov rdx, 108C5359947401DFh
    and rcx, rdx
    shl rcx, 2
    mov rdx, rax
    and rdx, r8
    mov r8, rdx
    not r8
    add r8, r8
    sub r8, rdx
    sub r8, rcx
    lea rdx, [r8+r9]
    inc rdx
    add r8, r9
    mov rcx, -67E53885389E6B22h
    add rcx, r8
    mov r9, rcx
    not r9
    mov r10, rcx
    mov rdi, -0ED0ADF3B192F511h
    or r10, rdi
    lea r11, [r10+r10*4]
    lea r11, [r10+r11*2]
    not r10
    lea rsi, [r10*8]
    sub rsi, r10
    and r9, rdi
    mov r10, r9
    shl r10, 4
    add r10, r9
    add r10, rsi
    mov r9, rcx
    and r9, rdi
    lea rsi, [r9+r9*2]
    not r9
    add r9, r9
    lea rdi, [r9+r9*2]
    mov r9, rcx
    mov rbx, 0ED0ADF3B192F510h
    and r9, rbx
    lea rbx, [r9+r9*8]
    lea r9, [r9+rbx*2]
    lea r9, [r9+rsi*4]
    sub r9, r11
    sub r9, rdi
    add r9, r10
    mov r10, r9
    not r10
    mov r11, r9
    mov rbx, -7F2AA4C2C93F7629h
    or r11, rbx
    lea rsi, [r11+r11*4]
    lea rsi, [r11+rsi*2]
    not r11
    lea rdi, [r11*8]
    sub rdi, r11
    and r10, rbx
    mov r11, r10
    shl r11, 4
    add r11, r10
    add r11, rdi
    mov r10, r9
    and r10, rbx
    mov rdi, r9
    mov rbx, 7F2AA4C2C93F7628h
    and rdi, rbx
    lea rbx, [rdi+rdi*8]
    lea rdi, [rdi+rbx*2]
    lea rbx, [r10+r10*2]
    lea rdi, [rdi+rbx*4]
    sub rdi, rsi
    mov rsi, -769229E4A91113ACh
    add r11, rsi
    not r10
    add r10, r10
    lea r10, [r10+r10*2]
    sub rdi, r10
    add rdi, r11
    mov r10, 2A7BD2414D6C21CCh
    add r8, r10
    mov r10, r8
    or r10, rdi
    not rdi
    mov r11, r8
    or r11, rdi
    not r10
    and rdi, r8
    lea r10, [rdi+r10*2]
    not r11
    add r10, r11
    not r8
    add r8, r8
    sub r10, r8
    sub r10, r9
    add rax, rdx
    add rax, rdx
    mov rdx, 40F5FE841B949BB5h
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rsp+380h], rax
    jnz loc_7FF856827AF5
    mov eax, dword ptr [rsp+88h]
    mov ecx, dword ptr [rsp+110h]
    mov rdx, qword ptr [rsp+508h]
    mov r8d, dword ptr [rsp+8Ch]
    mov dword ptr [rsp+204h], eax
    mov dword ptr [rsp+208h], ecx
    mov qword ptr [rsp+610h], rdx
    mov dword ptr [rsp+20Ch], r8d
    jmp loc_7FF85681FA60
    loc_7FF856819451:
    cmp eax, 7976990Eh
    jz loc_7FF85681C59D
    cmp eax, 79A22821h
    jz loc_7FF856825C51
    mov eax, dword ptr [rsp+64h]
    mov ecx, dword ptr [rsp+68h]
    mov rdx, qword ptr [rsp+378h]
    mov r8, qword ptr [rsp+780h]
    mov dword ptr [rsp+210h], eax
    mov dword ptr [rsp+214h], eax
    mov qword ptr [rsp+618h], 0
    mov dword ptr [rsp+218h], ecx
    mov qword ptr [rsp+620h], r8
    mov dword ptr [rsp+21Ch], 0
    mov qword ptr [rsp+628h], 0
    mov qword ptr [rsp+630h], rdx
    loc_7FF8568194C7:
    mov rax, qword ptr [rsp+630h]
    mov rcx, qword ptr [rsp+628h]
    mov edx, dword ptr [rsp+21Ch]
    mov r8, qword ptr [rsp+620h]
    mov r9d, dword ptr [rsp+218h]
    mov r10, qword ptr [rsp+618h]
    mov r11d, dword ptr [rsp+214h]
    mov esi, dword ptr [rsp+210h]
    mov qword ptr [rsp+3A8h], rax
    mov qword ptr [rsp+3A0h], rcx
    mov dword ptr [rsp+9Ch], edx
    mov qword ptr [rsp+510h], r8
    mov dword ptr [rsp+98h], r9d
    mov qword ptr [rsp+398h], r10
    mov dword ptr [rsp+94h], r11d
    mov dword ptr [rsp+90h], esi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rsp+368h]
    mov rdx, qword ptr [rsp+510h]
    shl rdx, 4
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rcx+rdx]
    cmp rax, qword ptr [rsp+330h]
    jnb loc_7FF85681BECB
    add rcx, rdx
    mov rdx, qword ptr [rcx+8]
    add rdx, rax
    mov rcx, qword ptr [rsp+330h]
    cmp rcx, rdx
    cmovb rdx, rcx
    loc_7FF856819640:
    mov rcx, qword ptr [rsp+3A8h]
    mov qword ptr [rsp+518h], rdx
    mov r8, rcx
    not r8
    mov r9, rax
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
    mov rdx, rax
    xor rdx, rcx
    lea r10, [rdx+rdx*2]
    and r8, rax
    mov rdx, rax
    and rdx, rcx
    sub rdx, r8
    add rdx, r10
    sub rdx, r9
    not r9
    shl r9, 2
    mov r8, rax
    or r8, rcx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rdx, r8
    sub rdx, r9
    mov qword ptr [rsp+7C0h], rdx
    cmp rax, rcx
    jbe loc_7FF8568277A5
    test rdx, rdx
    jz loc_7FF8568277A5
    mov eax, dword ptr [dword_7FF85723AA30]
    mov ecx, 344209D5h
    add eax, ecx
    xor eax, 26E7B782h
    add eax, 3ED33FAh
    jmp loc_7FF856813880
    loc_7FF8568197D3:
    cmp eax, 139254EBh
    jz loc_7FF85681C60F
    cmp eax, 150ABD42h
    jnz loc_7FF856821E21
    jmp loc_7FF856824E40
    loc_7FF8568197EE:
    cmp eax, 3BFD1C28h
    jz loc_7FF85681C793
    cmp eax, 3C55965Bh
    jnz loc_7FF856822EE1
    mov eax, dword ptr [rsp+370h]
    test eax, eax
    jle loc_7FF856829057
    dec eax
    mov dword ptr [rsp+1B8h], eax
    mov dword ptr [rsp+1BCh], 0
    jmp loc_7FF85681AFD7
    loc_7FF85681982C:
    cmp eax, 119D5857h
    jz loc_7FF85681C83B
    cmp eax, 12373CFEh
    jnz loc_7FF85681AFD7
    mov eax, dword ptr [rsp+128h]
    mov ecx, dword ptr [rsp+12Ch]
    mov edx, dword ptr [rsp+0A0h]
    mov r8, qword ptr [rsp+520h]
    mov r9d, dword ptr [rsp+0A4h]
    mov dword ptr [rsp+270h], eax
    mov dword ptr [rsp+274h], ecx
    mov dword ptr [rsp+278h], edx
    mov qword ptr [rsp+678h], r8
    mov dword ptr [rsp+27Ch], r9d
    mov eax, dword ptr [dword_7FF85723A9E4]
    mov ecx, -148635E8h
    xor eax, ecx
    add eax, -71BDE90Bh
    jmp loc_7FF856813880
    loc_7FF8568198A3:
    cmp eax, 23723637h
    jz loc_7FF8568276C0
    cmp eax, 2420EF1Fh
    jnz loc_7FF8568233A0
    mov eax, dword ptr [rsp+0B0h]
    mov rcx, qword ptr [rsp+3E0h]
    mov edx, dword ptr [rsp+0B4h]
    mov r8d, dword ptr [rsp+0B8h]
    mov r9, qword ptr [rsp+3E8h]
    mov r10, qword ptr [rsp+3F0h]
    mov r11, qword ptr [rsp+588h]
    mov dword ptr [rsp+2F0h], eax
    mov qword ptr [rsp+720h], rcx
    mov dword ptr [rsp+2F4h], edx
    mov dword ptr [rsp+2F8h], r8d
    mov qword ptr [rsp+728h], r9
    mov qword ptr [rsp+730h], r10
    mov qword ptr [rsp+738h], r11
    jmp loc_7FF85681EB46
    loc_7FF85681992A:
    cmp eax, 2A469B64h
    jz loc_7FF85681E8FC
    cmp eax, 2A492993h
    jnz loc_7FF856825869
    mov eax, dword ptr [rsp+64h]
    mov ecx, dword ptr [rsp+68h]
    mov rdx, qword ptr [rsp+3D8h]
    mov dword ptr [rsp+298h], eax
    mov qword ptr [rsp+690h], 0
    mov dword ptr [rsp+29Ch], ecx
    mov dword ptr [rsp+2A0h], 0
    mov qword ptr [rsp+698h], 0
    mov qword ptr [rsp+6A0h], rdx
    jmp loc_7FF85681C9C7
    loc_7FF85681998E:
    cmp eax, 351C469Ah
    jg loc_7FF85681EB3B
    cmp eax, 318CB703h
    jnz loc_7FF85681CA93
    mov eax, dword ptr [dword_7FF8571CC988]
    lea edx, [rax-0D8C224Eh]
    lea ecx, [rax+2CC8179h]
    lea r10d, [rax-5B77A0F0h]
    mov r9d, r10d
    xor r9d, 71A070FFh
    mov r8d, r10d
    xor r8d, -71A07100h
    mov r11d, r8d
    and r11d, 8EA66BDh
    mov esi, r8d
    and esi, 17159942h
    shl esi, 2
    mov edi, r10d
    xor edi, -66B5E9BEh
    xor r10d, 26B5E9BDh
    lea ebx, [rdi*8]
    mov ebp, r9d
    and ebp, 17159942h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    shl ebp, 3
    mov r14d, r9d
    and r14d, 68EA66BDh
    add r14d, r14d
    sub ebp, r14d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub edi, ebx
    add edi, ebp
    lea r10d, [rdi+r10*4]
    sub r10d, esi
    lea r10d, [r10+r11*8]
    mov r11d, 0C4BFD35h
    sub r11d, r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r10d, r11d
    or r10d, r8d
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
    nop
    nop
    nop
    nop
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
    lea r10d, [r10+r10*4]
    mov esi, r11d
    or esi, r9d
    lea edi, [rsi+rsi*4]
    lea esi, [rsi+rdi*2]
    mov edi, r11d
    xor edi, r9d
    add edi, edi
    and r8d, r11d
    shl r8d, 3
    and r11d, r9d
    imul r9d, r11d, 0F5h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r9d, r8d
    sub r9d, edi
    add r9d, esi
    sub r9d, r10d
    lea r8d, [rax+r9]
    add r8d, 71B4CB12h
    xor ecx, edx
    xor ecx, r8d
    lea edx, [rcx+rax]
    add edx, -5B77A0F0h
    add edx, eax
    mov ecx, 1Ch
    mov r8d, 15h
    mov r9d, 47h
    call Eidolon_UpdateSharedStateIfSentinelMatches
    loc_7FF856819C89:
    mov rax, qword ptr [qword_7FF8571CC990]
    mov rdx, rax
    mov rcx, 37A1FD55727833F3h
    xor rdx, rcx
    mov rcx, rax
    mov r8, 852002A0D84CC04h
    xor rcx, r8
    mov r11, 28F3A06F7DE4DC85h
    and rcx, r11
    lea rcx, [rcx+rcx*2]
    lea r8, [rdx+rdx]
    mov r9, 51E740DEFBC9B90Ah
    or r8, r9
    lea r8, [r8+r8*2]
    mov r9, rax
    mov r10, -1F525D3A0F9CEF77h
    xor r9, r10
    mov r10, rdx
    and r10, r11
    lea r10, [r10+r10*2]
    add r10, r10
    mov r11, rdx
    mov rsi, 570C5F90821B237Ah
    and r11, rsi
    lea r11, [r11+r11*2]
    lea r10, [r10+r11*2]
    add r10, r9
    sub r10, r8
    lea r9, [r10+rcx*2]
    mov rcx, r9
    mov r8, -5F14C2414DCCDF60h
    xor rcx, r8
    mov r10, rcx
    mov r8, rcx
    mov r11, rcx
    mov rsi, 8958F1C1E6BC2EBh
    add rcx, rsi
    xor rcx, rdx
    add rcx, r9
    mov rdx, 51100201448C0005h
    xor r9, rdx
    mov rdi, 51980333C4BD2025h
    or r10, rdi
    lea rdx, [r10+r10*4]
    lea rdx, [r10+rdx*2]
    not r10
    lea rsi, [r10*8]
    sub rsi, r10
    and r9, rdi
    mov r10, r9
    shl r10, 4
    add r10, r9
    add r10, rsi
    and r8, rdi
    mov r9, -51980333C4BD2026h
    and r11, r9
    lea r9, [r11+r11*8]
    lea r9, [r11+r9*2]
    lea r11, [r8+r8*2]
    lea r9, [r9+r11*4]
    sub r9, rdx
    not r8
    add r8, r8
    lea rdx, [r8+r8*2]
    sub r9, rdx
    add r9, r10
    add rcx, r9
    mov rdx, qword ptr [rsp+7D0h]
    sub rcx, rax
    xor rcx, qword ptr [rdx]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rcx+8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, qword ptr [rcx]
    sub rax, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sar rax, 4
    mov rcx, qword ptr [r12]
    mov rdx, 3CA0ADB058121E5Dh
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
    mov qword ptr [rsp+28h], rcx
    mov qword ptr [rsp+20h], rax
    mov qword ptr [rsp+30h], 4Dh
    mov ecx, 3Eh
    mov r9d, 3Dh
    lea rdx, [rsp+8A8h]
    call sub_7FF85668BFB0
    mov r8, qword ptr [qword_7FF8571CC998]
    mov rax, -16FAA377BA52BB5Ah
    add rax, r8
    mov rcx, rax
    mov rdx, 150A00008020F2D9h
    xor rcx, rdx
    mov rdx, rax
    mov r9, -15BF0484AC39FFDAh
    xor rdx, r9
    mov r9, rdx
    mov rdi, 150A0A08C2A4F2FFh
    or r9, rdi
    and rcx, rdi
    mov r10, rax
    mov r11, -0B50E8C6E9D0D27h
    xor r10, r11
    lea r10, [r10+r10*2]
    lea r11, [r9+r9*4]
    not r9
    mov rsi, rdx
    and rsi, rdi
    lea rsi, [rsi+rsi*2]
    add rsi, rsi
    mov rdi, rdx
    mov rbx, 0AF5F5F73D5B0D00h
    and rdi, rbx
    lea rsi, [rsi+rdi*8]
    sub rsi, r11
    sub rsi, r10
    lea rcx, [rsi+rcx*8]
    add rcx, r9
    mov r9, rcx
    mov r10, 1DDD7C4F3CAE93B3h
    xor r9, r10
    add rdx, r8
    add rdx, r8
    mov r8, 47E956401CA39FEBh
    add rdx, r8
    add rdx, r9
    mov r8, rcx
    mov r10, -1DDD7C4F3CAE93B4h
    xor r8, r10
    lea r10, [r8+r8]
    mov r11, rdx
    or r11, r8
    mov rsi, rdx
    or rsi, r9
    lea rdi, [rdx+rdx*2]
    and r8, rdx
    and rdx, r9
    shl r8, 2
    lea rdx, [rdx+rdx*2]
    sub r8, rdx
    add r8, rdi
    not rsi
    lea rdx, [rsi+rsi*2]
    lea rdx, [r8+rdx*2]
    lea r8, [r10+r10*2]
    add rdx, r11
    sub rdx, r8
    inc rdx
    xor rdx, rax
    mov r8, rcx
    not r8
    mov rax, rdx
    or rax, r8
    mov r9, rdx
    or r9, rcx
    and r8, rdx
    and rdx, rcx
    mov rcx, r8
    add r8, r8
    lea rdx, [r8+rdx*2]
    not rcx
    sub rcx, rdx
    not r9
    shl r9, 2
    sub rcx, r9
    not rax
    lea rax, [rax+rax*2]
    sub rcx, rax
    mov rax, qword ptr [rsp+8A8h]
    xor rax, qword ptr [r12+30h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    cmp rax, rcx
    jnz loc_7FF856823D94
    mov rax, qword ptr [r12+38h]
    xor rax, qword ptr [rsp+8B0h]
    mov rcx, 5346BCC24FBB0D7h
    cmp rax, rcx
    jnz loc_7FF856823D94
    mov eax, dword ptr [dword_7FF85723AA1C]
    lea ecx, [rax-0DBFEF1Fh]
    xor ecx, 639EB9F6h
    lea edx, [rcx+rcx]
    lea r8d, [rcx-6D4770E9h]
    add edx, ecx
    neg edx
    add edx, ecx
    add edx, -6D4770E9h
    add ecx, -0EBA2516h
    sub edx, eax
    lea eax, [rdx+r8]
    add eax, -50CCEDE4h
    jmp loc_7FF856813873
    loc_7FF85681A649:
    cmp eax, 1F755B14h
    jz loc_7FF85681F13B
    cmp eax, 2208684Ch
    jnz loc_7FF856825D6C
    mov eax, dword ptr [rsp+490h]
    not eax
    mov ecx, dword ptr [rsp+168h]
    mov edx, 2B8581F5h
    or ecx, edx
    lea ecx, [rcx+rcx*4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edx, dword ptr [rsp+168h]
    mov r8d, edx
    and r8d, 147A7E0Ah
    mov r9d, edx
    and r9d, 2B8581F5h
    lea r9d, [r9+r9*2]
    lea r8d, [r9+r8*4]
    xor edx, -4F3EBCE8h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r8d, ecx
    lea eax, [r8+rax*4]
    add eax, edx
    mov ecx, dword ptr [rsp+70h]
    add ecx, eax
    add ecx, 570B03EAh
    mov eax, dword ptr [rsp+164h]
    mov edx, eax
    not edx
    mov r8d, ecx
    or r8d, edx
    not r8d
    or eax, ecx
    not eax
    add eax, eax
    mov r9d, ecx
    and r9d, edx
    xor edx, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r10d, dword ptr [rsp+164h]
    and r10d, ecx
    lea r9d, [r10+r9*2]
    sub r9d, ecx
    lea edx, [r9+rdx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub edx, eax
    add edx, r8d
    mov ecx, 4Bh
    mov r8d, 56h
    mov r9d, 31h
    call Eidolon_UpdateSharedStateIfSentinelMatches
    jmp loc_7FF85681E5B6
    loc_7FF85681A8D1:
    cmp eax, 0E917F6Ch
    jz loc_7FF856821A9B
    cmp eax, 0EEB88BFh
    jnz loc_7FF85681BF37
    mov eax, dword ptr [rsp+74h]
    add rax, qword ptr [rsp+360h]
    mov qword ptr [rsp+868h], rax
    mov eax, dword ptr [dword_7FF85723AB0C]
    mov ecx, eax
    xor ecx, -16A251F6h
    xor eax, -8F43B23h
    add eax, ecx
    add eax, 1372B065h
    jmp loc_7FF856813880
    loc_7FF85681A91A:
    mov rax, qword ptr [rsp+760h]
    mov qword ptr [rsp+890h], rax
    cmp qword ptr [rsp+360h], 1
    jnz loc_7FF85681C6F3
    mov eax, dword ptr [dword_7FF85723AB1C]
    lea ecx, [rax+72D84652h]
    lea edx, [rax-1107F41Fh]
    mov r8d, edx
    xor r8d, 22CD314h
    xor edx, -4AB14ADEh
    xor ecx, 0C95D17Fh
    sub ecx, edx
    xor ecx, eax
    sub ecx, r8d
    mov dword ptr [rsp+3Ch], ecx
    jmp loc_7FF856813884
    loc_7FF85681A971:
    cmp eax, 5DEAEA58h
    jnz loc_7FF85681C7DD
    mov eax, dword ptr [rsp+18Ch]
    mov ecx, dword ptr [rsp+190h]
    mov rdx, qword ptr [rsp+850h]
    mov dword ptr [rsp+2FCh], eax
    mov dword ptr [rsp+300h], ecx
    mov qword ptr [rsp+740h], rdx
    mov eax, dword ptr [dword_7FF85723AAE0]
    lea ecx, [rax-1BC9BB9Dh]
    xor ecx, 256F3994h
    lea edx, [rcx+550093E6h]
    xor edx, -6BA7D7ACh
    lea r8d, [rdx+121DCE23h]
    lea r9d, [rcx+rax]
    add r9d, 3936D849h
    add r9d, ecx
    sub edx, r9d
    sub edx, eax
    add edx, 11FAC29Fh
    xor edx, r8d
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF85681A9F2:
    cmp eax, 182E482Ah
    jnz loc_7FF8568233DA
    loc_7FF85681A9FD:
    mov rax, qword ptr [rsp+358h]
    movzx ecx, byte ptr [rax]
    mov byte ptr [rsp+47h], cl
    xor ecx, dword ptr [rsp+320h]
    imul eax, ecx, -3361D2AFh
    mov r10d, dword ptr [dword_7FF8571CC86C]
    mov r9d, r10d
    xor r9d, 9423C96h
    lea r8d, [r9-1F78C05Eh]
    mov edx, r8d
    not edx
    and edx, 0FE3A979h
    lea r11d, 0FFFFFFFFC10E7F44h[r9*2]
    or r11d, -6038AD0Eh
    mov esi, r8d
    xor esi, 4FE3A979h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    and edi, 301C5686h
    shl edi, 2
    mov ebx, r8d
    and ebx, 4FE3A979h
    lea edi, [rdi+rbx*2]
    sub edi, esi
    sub edi, r11d
    lea r11d, [rdi+rdx*4]
    mov edi, r11d
    not edi
    mov edx, edi
    and edx, 16F69870h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and edi, 909678Fh
    shl edi, 2
    mov esi, r11d
    xor esi, 36F69870h
    mov ebx, r11d
    xor ebx, 909678Fh
    lea ebp, [rsi*8]
    mov r14d, r11d
    and r14d, 909678Fh
    shl r14d, 3
    mov r15d, r11d
    and r15d, 36F69870h
    add r15d, r15d
    sub r14d, r15d
    sub esi, ebp
    add esi, r14d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea esi, [rsi+rbx*4]
    sub esi, edi
    lea edi, [rsi+rdx*8]
    lea ebx, [rsi+rdx*8]
    add ebx, 59F18DBDh
    lea edx, [rsi+rdx*8]
    add edx, 5478F8FBh
    xor r11d, r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r11d, -4EAD0FC3h
    sub r11d, edi
    xor edx, ebx
    xor edx, r11d
    sub edx, r9d
    add edx, 267B4999h
    xor edx, r8d
    imul edx, ecx
    mov r8d, dword ptr [dword_7FF8571CC870]
    mov ecx, r8d
    xor ecx, 0A955B17h
    lea r10d, [rcx-19B608Ah]
    xor r10d, 45C65862h
    lea r9d, [r10-151E3B97h]
    mov esi, r9d
    not esi
    mov r11d, esi
    and r11d, 1A4E0E6h
    lea r11d, [r11+r11*8]
    add r11d, esi
    and esi, 7E5B1F19h
    lea esi, [rsi+rsi*4]
    mov edi, r9d
    and edi, -1A4E0E7h
    mov ebx, r9d
    and ebx, 1A4E0E6h
    lea r14d, [rbx+rbx*4]
    lea ebx, [rbx+r14*2]
    add ebx, edi
    not edi
    lea r14d, [rdi+rdi*4]
    lea edi, [rdi+r14*2]
    sub ebx, edi
    lea esi, [rbx+rsi*2]
    add r11d, esi
    mov esi, -3FB887A7h
    sub esi, r11d
    xor esi, ecx
    add esi, r10d
    xor esi, r11d
    lea ecx, [rsi+r11]
    add ecx, -5A301AB7h
    xor ecx, r9d
    add ecx, r8d
    shr eax, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or eax, edx
    mov ecx, dword ptr [dword_7FF8571CC874]
    lea edx, [rcx-4A921362h]
    mov r8d, 684D0EDh
    sub r8d, ecx
    xor r8d, edx
    add r8d, ecx
    add ecx, 63C3AF96h
    xor ecx, 532A2195h
    lea edx, [rcx-57FB215h]
    sub r8d, edx
    xor edx, -7F76C42Ah
    sub r8d, edx
    add ecx, r8d
    add ecx, 5FFAEBBh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    imul ecx, eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor ecx, dword ptr [rsp+194h]
    mov dword ptr [rsp+1B4h], ecx
    test byte ptr [rsp+48h], 1
    jnz loc_7FF85681B0FA
    mov eax, dword ptr [dword_7FF85723AB20]
    mov ecx, eax
    xor ecx, 6B642D85h
    lea edx, [rcx+91CF914h]
    xor edx, 57A9BEADh
    lea r8d, [rdx-7F5F107Bh]
    lea r9d, [rdx+rcx]
    add r9d, -76421767h
    mov r10d, 6E0ED211h
    sub r10d, r9d
    xor r10d, r8d
    xor r10d, -3DF0CA5Dh
    add edx, edx
    add edx, r10d
    sub edx, eax
    sub edx, ecx
    add edx, -1884F40h
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF85681AF02:
    cmp eax, 274B54B3h
    jnz loc_7FF856823C54
    mov eax, dword ptr [rsp+0BCh]
    mov rcx, qword ptr [rsp+590h]
    mov edx, dword ptr [rsp+0C0h]
    mov dword ptr [rsp+30Ch], eax
    mov qword ptr [rsp+748h], rcx
    mov dword ptr [rsp+310h], edx
    jmp loc_7FF8568251B3
    loc_7FF85681AF3E:
    add r11, qword ptr [rsp+0F0h]
    mov esi, dword ptr [rsp+180h]
    mov dword ptr [rsp+2A4h], r9d
    mov dword ptr [rsp+2A8h], r8d
    mov qword ptr [rsp+6A8h], rdx
    mov dword ptr [rsp+2ACh], eax
    mov dword ptr [rsp+2B0h], esi
    mov qword ptr [rsp+6B0h], rcx
    mov qword ptr [rsp+6B8h], r11
    mov qword ptr [rsp+6C0h], r10
    mov eax, dword ptr [dword_7FF85723AA8C]
    lea ecx, [rax-2B146441h]
    mov edx, ecx
    xor edx, -485E8DEAh
    mov r8d, ecx
    xor r8d, -13D6FFDAh
    lea r9d, [r8+465D1584h]
    xor r9d, 593BBF3Ch
    sub ecx, r8d
    add ecx, edx
    sub ecx, eax
    lea eax, [rcx+r9]
    add eax, -55D79283h
    mov dword ptr [rsp+3Ch], eax
    lea r13, eidolon_sbox
    jmp loc_7FF856813884
    loc_7FF85681AFD7:
    mov eax, dword ptr [rsp+1BCh]
    mov ecx, dword ptr [rsp+1B8h]
    mov dword ptr [rsp+450h], eax
    mov dword ptr [rsp+44Ch], ecx
    add eax, ecx
    shr eax, 1
    mov dword ptr [rsp+84h], eax
    mov rcx, qword ptr [rsp+368h]
    shl rax, 4
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, qword ptr [rcx+rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rdx, qword ptr [rcx+rax+8]
    mov qword ptr [rsp+778h], rdx
    mov eax, dword ptr [dword_7FF85723A9CC]
    mov ecx, eax
    xor ecx, -19A3FE2Dh
    lea edx, [rcx+3228C459h]
    mov r8d, -3898BE9Ch
    sub r8d, ecx
    xor r8d, ecx
    xor edx, eax
    jmp loc_7FF856825BF5
    loc_7FF85681B0FA:
    mov eax, dword ptr [dword_7FF85723AB04]
    lea ecx, [rax+4DD3A384h]
    xor ecx, -5DDEA6Fh
    neg ecx
    add eax, ecx
    add eax, -1922E14Ch
    jmp loc_7FF856813880
    loc_7FF85681B11A:
    cmp eax, 627664DCh
    jnz loc_7FF85682AC19
    mov rax, qword ptr [rsp+580h]
    mov ecx, dword ptr [rsp+1A8h]
    mov rdx, qword ptr [rsp+5B8h]
    mov r8d, dword ptr [rsp+1ACh]
    mov r9, qword ptr [rsp+5C0h]
    mov r10d, dword ptr [rsp+1B0h]
    mov dword ptr [rsp+2E4h], ecx
    mov qword ptr [rsp+708h], rdx
    mov dword ptr [rsp+2E8h], r8d
    mov qword ptr [rsp+710h], rax
    mov qword ptr [rsp+718h], r9
    mov dword ptr [rsp+2ECh], r10d
    jmp loc_7FF85681C94B
    loc_7FF85681B188:
    cmp eax, 724AB513h
    jnz loc_7FF85682A8BA
    mov eax, dword ptr [rsp+188h]
    mov dword ptr [rsp+0D0h], eax
    jmp loc_7FF856825E34
    loc_7FF85681B1A6:
    cmp eax, 44EA8CD3h
    jz loc_7FF85681C25E
    jmp loc_7FF85682A8AF
    loc_7FF85681B1B6:
    cmp eax, 2A93507h
    jnz loc_7FF85682A950
    mov dword ptr [rsp+1F4h], 0
    loc_7FF85681B1CC:
    mov eax, dword ptr [rsp+1F4h]
    mov rcx, qword ptr [rsp+390h]
    movzx edx, byte ptr [rcx+1]
    shl edx, 8
    mov r8d, eax
    not r8d
    or r8d, edx
    mov r9d, edx
    and r9d, eax
    add r9d, r9d
    sub edx, r9d
    lea eax, [rdx+rax*2]
    add eax, r8d
    inc eax
    movzx ecx, byte ptr [rcx]
    mov byte ptr [rsp+42h], cl
    mov dword ptr [rsp+1F8h], eax
    loc_7FF85681B20D:
    movzx ecx, byte ptr [rsp+42h]
    xor ecx, dword ptr [rsp+1F8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    imul eax, ecx, -3361D2AFh
    mov r8d, dword ptr [dword_7FF8571CC7A0]
    mov edx, r8d
    not edx
    mov r9d, r8d
    or r9d, 6DCF5868h
    and edx, 0DCF5868h
    mov r10d, r8d
    xor r10d, 6DCF5868h
    lea r10d, [r10+r10*2]
    lea r11d, [r9+r9*4]
    mov esi, r9d
    not esi
    mov r9d, r8d
    and r9d, 6DCF5868h
    lea r9d, [r9+r9*2]
    add r9d, r9d
    mov edi, r8d
    and edi, 1230A797h
    lea r9d, [r9+rdi*8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    sub r9d, r10d
    lea r9d, [r9+rdx*8]
    add r9d, esi
    mov r10d, r9d
    xor r10d, -3EA05A08h
    add r10d, 53FEEA90h
    mov r11d, r10d
    not r11d
    and r11d, 2C10BFEBh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea edx, [r10+r10]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or edx, 58217FD6h
    mov esi, r10d
    xor esi, 2C10BFEBh
    mov edi, r10d
    and edi, 13EF4014h
    shl edi, 2
    mov ebx, r10d
    and ebx, 2C10BFEBh
    lea edi, [rdi+rbx*2]
    sub edi, esi
    sub edi, edx
    lea esi, [rdi+r11*4]
    mov edx, -2BF64F14h
    sub edx, esi
    lea r11d, [rdi+r11*4]
    add r11d, -4A48FAE6h
    xor edx, r8d
    add edx, r9d
    sub edx, r10d
    xor edx, r11d
    imul edx, ecx
    mov ecx, dword ptr [dword_7FF8571CC7A4]
    mov r10d, ecx
    xor r10d, 4FDF5194h
    mov r11d, ecx
    xor r11d, 63330A75h
    mov esi, ecx
    xor esi, -78A64595h
    lea r8d, [rsi-14974CBCh]
    mov r9d, r8d
    xor r9d, 54C2FDA1h
    mov edi, ecx
    xor edi, 78A64594h
    lea ebx, [rdi+rdi]
    lea ebx, [rbx+rbx*2]
    mov ebp, edi
    or ebp, -4DA51F57h
    mov r14d, edi
    and r14d, 4DA51F56h
    lea r14d, [r14+r14*2]
    and edi, 325AE0A9h
    shl edi, 2
    and esi, -4DA51F57h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea esi, [rsi+rsi*2]
    sub edi, esi
    lea esi, [rdi+r14*2]
    add esi, ebp
    sub esi, ebx
    sub esi, r11d
    lea r11d, [rsi+1710A1FCh]
    mov edi, r11d
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
    lea esi, 2E2143F8h[rsi*2]
    xor ecx, 3020AE6Bh
    and ecx, r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r11d, r10d
    lea r10d, [r11+r11*2]
    lea ecx, [r10+rcx*2]
    sub ecx, esi
    add ecx, edi
    mov r10d, r8d
    xor r10d, -54C2FDA2h
    mov r11d, ecx
    or r11d, r10d
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
    lea esi, [r11*8]
    sub esi, r11d
    mov r11d, ecx
    xor r11d, r9d
    lea r11d, [r11+r11*4]
    and r10d, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    and ecx, r9d
    lea ecx, [rcx+r10*2]
    sub ecx, r11d
    sub ecx, r9d
    add ecx, esi
    sub ecx, r8d
    shr eax, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or eax, edx
    imul eax, 1B873593h
    xor eax, dword ptr [rsp+11Ch]
    mov dword ptr [rsp+1FCh], eax
    mov dword ptr [rsp+200h], eax
    jmp loc_7FF85681F5CC
    loc_7FF85681B7D9:
    mov qword ptr [rsp+418h], 0
    jmp loc_7FF85681C1F7
    loc_7FF85681B7EA:
    mov eax, dword ptr [rsp+174h]
    mov ecx, dword ptr [rsp+178h]
    mov dword ptr [rsp+2BCh], eax
    jmp loc_7FF85681CD37
    loc_7FF85681B804:
    mov eax, dword ptr [rsp+90h]
    mov ecx, dword ptr [rsp+94h]
    mov rdx, qword ptr [rsp+398h]
    mov r8d, dword ptr [rsp+98h]
    mov r9d, dword ptr [rsp+9Ch]
    mov r10, qword ptr [rsp+3A0h]
    mov dword ptr [rsp+280h], eax
    mov dword ptr [rsp+284h], ecx
    mov qword ptr [rsp+680h], rdx
    mov dword ptr [rsp+288h], r8d
    mov qword ptr [rsp+688h], r10
    mov dword ptr [rsp+28Ch], r9d
    loc_7FF85681B860:
    mov eax, dword ptr [rsp+28Ch]
    mov rcx, qword ptr [rsp+688h]
    mov edx, dword ptr [rsp+288h]
    mov r8, qword ptr [rsp+680h]
    mov r9d, dword ptr [rsp+284h]
    mov r10d, dword ptr [rsp+280h]
    mov dword ptr [rsp+160h], eax
    mov qword ptr [rsp+548h], rcx
    mov dword ptr [rsp+15Ch], edx
    mov qword ptr [rsp+540h], r8
    mov dword ptr [rsp+158h], r9d
    mov dword ptr [rsp+154h], r10d
    mov rax, qword ptr [qword_7FF8571CC750]
    mov rcx, rax
    mov rdx, 2D8886922FD87950h
    xor rcx, rdx
    mov rdx, -452BE14214AAE5EEh
    add rdx, rcx
    mov r9, rdx
    not r9
    lea r8, [r9+r9*2]
    mov r10, r9
    mov rdi, 59BCC90FEE54AE45h
    and r10, rdi
    lea r10, [r10+r10*2]
    mov r11, -59BCC90FEE54AE46h
    and r9, r11
    lea r9, [r9+r9*2]
    mov r11, rdx
    xor r11, rdi
    lea rsi, [r11*8]
    sub rsi, r11
    add rsi, r9
    mov r9, rdx
    mov r11, 264336F011AB51BAh
    and r9, r11
    add r9, r9
    lea r9, [r9+r9*2]
    and rdx, rdi
    add rdx, rdx
    sub rdx, r9
    add rdx, rsi
    sub rdx, r10
    sub rdx, r8
    mov r8, -2D7596EC8AD77D7Ah
    add r8, rdx
    mov r9, r8
    not r9
    mov r10, r8
    mov rdi, 722BE974B898A666h
    or r10, rdi
    mov r11, r8
    and r11, rdi
    lea r11, [r11+r11*2]
    add r11, r11
    mov rsi, r8
    mov rbx, 0DD4168B47675999h
    and rsi, rbx
    lea r11, [r11+rsi*8]
    lea rsi, [r10+r10*4]
    not r10
    mov rbx, 122BE974B898A666h
    and r9, rbx
    sub r11, rsi
    mov rsi, r8
    xor rsi, rdi
    lea rsi, [rsi+rsi*2]
    sub r11, rsi
    lea r9, [r11+r9*8]
    add r9, r10
    mov r10, rdx
    mov rdi, -21EDF47E54794C7Dh
    or r10, rdi
    lea r11, [r10+r10*2]
    not r10
    lea rsi, [r10*8]
    sub rsi, r10
    and rdx, rdi
    lea rdx, [rdx+r11*2]
    add rdx, rsi
    mov r10, -7
    sub r10, rdx
    xor r10, rcx
    add r8, rax
    add r8, r10
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8, qword ptr [rsp+510h]
    mov qword ptr [rsp+550h], r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+550h]
    cmp rax, qword ptr [rsp+370h]
    jnz loc_7FF85681C5E4
    mov rax, qword ptr [rsp+518h]
    mov ecx, dword ptr [rsp+154h]
    mov edx, dword ptr [rsp+158h]
    mov r8, qword ptr [rsp+540h]
    mov r9d, dword ptr [rsp+15Ch]
    mov r10, qword ptr [rsp+548h]
    mov r11d, dword ptr [rsp+160h]
    mov dword ptr [rsp+220h], ecx
    mov dword ptr [rsp+224h], edx
    mov qword ptr [rsp+638h], r8
    mov dword ptr [rsp+228h], r9d
    mov qword ptr [rsp+640h], rax
    mov qword ptr [rsp+648h], r10
    mov dword ptr [rsp+22Ch], r11d
    mov eax, dword ptr [dword_7FF85723AA18]
    mov ecx, eax
    xor ecx, -3C827D12h
    lea edx, [rcx-2B63D97Ch]
    lea r8d, [rcx+1572C226h]
    mov r9d, r8d
    xor r9d, -7888301Fh
    lea r10d, [r9-4DDEC5CBh]
    xor edx, eax
    xor edx, -1E4D86EAh
    sub edx, r9d
    add edx, -77DF4FCCh
    xor edx, r8d
    add r9d, ecx
    add r9d, edx
    xor r9d, r10d
    mov dword ptr [rsp+3Ch], r9d
    jmp loc_7FF856813884
    loc_7FF85681BCFE:
    mov eax, dword ptr [rsp+464h]
    mov ecx, dword ptr [rsp+468h]
    mov rdx, qword ptr [rsp+7A8h]
    mov r8d, dword ptr [rsp+46Ch]
    mov r9, qword ptr [rsp+7B0h]
    mov r10, qword ptr [rsp+7B8h]
    mov r11d, dword ptr [rsp+124h]
    mov dword ptr [rsp+1C0h], eax
    mov dword ptr [rsp+1C4h], ecx
    mov qword ptr [rsp+5D0h], rdx
    mov dword ptr [rsp+1C8h], r8d
    mov dword ptr [rsp+1CCh], r11d
    mov qword ptr [rsp+5D8h], r10
    mov qword ptr [rsp+5E0h], r9
    mov eax, dword ptr [dword_7FF85723A9D8]
    mov ecx, eax
    xor ecx, 7556AC24h
    add ecx, -1A704F11h
    xor ecx, -4A4ECD06h
    sub ecx, eax
    add ecx, 1F0AEC64h
    mov dword ptr [rsp+3Ch], ecx
    jmp loc_7FF856813884
    loc_7FF85681BD95:
    mov eax, dword ptr [rsp+3D0h]
    mov ecx, dword ptr [dword_7FF8571CC838]
    mov edx, ecx
    xor edx, 251FA4D0h
    mov r8d, ecx
    xor r8d, 52A01A2Ah
    mov r9d, ecx
    xor r9d, 8404105h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r9d, 94DC5C5h
    lea r9d, [r9+r9*2]
    and r8d, 76B23A3Ah
    add r8d, r8d
    mov r10d, edx
    and r10d, -94DC5C6h
    lea r11d, [r10+r10*2]
    not r10d
    add r10d, r10d
    mov esi, edx
    and esi, 94DC5C5h
    mov edi, esi
    not edi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add esi, esi
    sub esi, r11d
    lea r11d, [rsi+rdi*4]
    sub r11d, r10d
    sub r11d, r8d
    sub r11d, r9d
    add r11d, -0EF7AF0Fh
    add ecx, 4FCA112Ch
    xor ecx, r11d
    sub ecx, edx
    cmp eax, ecx
    jge loc_7FF8568277FF
    mov qword ptr [rsp+418h], 0
    mov eax, dword ptr [dword_7FF85723AA88]
    mov ecx, 414CDD57h
    add eax, ecx
    jmp loc_7FF856813880
    loc_7FF85681BECB:
    mov eax, dword ptr [rsp+90h]
    mov ecx, dword ptr [rsp+94h]
    mov rdx, qword ptr [rsp+398h]
    mov r8d, dword ptr [rsp+98h]
    mov r9d, dword ptr [rsp+9Ch]
    mov r10, qword ptr [rsp+3A0h]
    mov r11, qword ptr [rsp+3A8h]
    mov dword ptr [rsp+220h], eax
    mov dword ptr [rsp+224h], ecx
    mov qword ptr [rsp+638h], rdx
    mov dword ptr [rsp+228h], r8d
    mov qword ptr [rsp+640h], r11
    mov qword ptr [rsp+648h], r10
    mov dword ptr [rsp+22Ch], r9d
    loc_7FF85681BF37:
    mov eax, dword ptr [rsp+22Ch]
    mov rcx, qword ptr [rsp+648h]
    mov rdx, qword ptr [rsp+640h]
    mov r8d, dword ptr [rsp+228h]
    mov r9, qword ptr [rsp+638h]
    mov r10d, dword ptr [rsp+224h]
    mov r11d, dword ptr [rsp+220h]
    mov dword ptr [rsp+124h], eax
    mov qword ptr [rsp+7B8h], rcx
    mov qword ptr [rsp+7B0h], rdx
    mov dword ptr [rsp+46Ch], r8d
    mov qword ptr [rsp+7A8h], r9
    mov dword ptr [rsp+468h], r10d
    mov dword ptr [rsp+464h], r11d
    cmp rdx, qword ptr [rsp+330h]
    jnb loc_7FF856821A81
    mov eax, dword ptr [dword_7FF85723AA28]
    mov ecx, -3E62B9D0h
    add eax, ecx
    mov ecx, eax
    xor ecx, 43A9AE17h
    lea edx, [rcx+4E520C04h]
    xor edx, 397F3E7Dh
    add edx, 3101CE1Eh
    xor edx, -19FF65A1h
    xor eax, -2130146Ah
    sub eax, ecx
    add eax, edx
    add eax, 3798261h
    jmp loc_7FF856813880
    loc_7FF85681BFF3:
    mov ecx, dword ptr [rsp+170h]
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
    and ecx, 0D62A023h
    mov eax, dword ptr [rsp+170h]
    mov edx, eax
    xor edx, -529D5FDDh
    lea edx, [rdx+rdx*2]
    mov r8d, eax
    or r8d, -529D5FDDh
    lea r8d, [r8+r8*4]
    mov r9d, eax
    and r9d, 2D62A023h
    lea r9d, [r9+r9*2]
    add r9d, r9d
    mov r10d, eax
    and r10d, 129D5FDCh
    lea r9d, [r9+r10*8]
    sub r9d, r8d
    sub r9d, edx
    lea edx, [r9+rcx*8]
    mov r8d, dword ptr [rsp+4A8h]
    lea ecx, [r8+rdx]
    add ecx, 3A5231DDh
    lea r9d, [r8+rdx]
    add r9d, -33BC290Eh
    add edx, r8d
    add edx, -2AE8E899h
    xor r9d, dword ptr [rsp+4A4h]
    xor ecx, eax
    xor ecx, r9d
    xor ecx, -4BA98FEBh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add ecx, 1588AAE0h
    xor ecx, edx
    add ecx, dword ptr [rsp+16Ch]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp byte ptr [rsp+46h], 0
    lea rax, [rsp+4A0h]
    lea rdx, [rsp+49Ch]
    cmovnz rax, rdx
    loc_7FF85681C1CF:
    cmovz ecx, dword ptr [rsp+498h]
    loc_7FF85681C1D7:
    mov eax, dword ptr [rax]
    mov dword ptr [rsp+4FCh], eax
    cmp eax, ecx
    jle loc_7FF856827A7A
    mov eax, dword ptr [rsp+4FCh]
    mov qword ptr [rsp+418h], rax
    loc_7FF85681C1F7:
    mov rax, qword ptr [rsp+418h]
    cmp rax, qword ptr [rsp+3D0h]
    jnb loc_7FF85681C380
    mov ecx, dword ptr [rsp+64h]
    mov edx, dword ptr [rsp+68h]
    mov r8, qword ptr [rsp+3D8h]
    mov dword ptr [rsp+2D8h], ecx
    mov qword ptr [rsp+6E8h], 0
    mov dword ptr [rsp+2DCh], edx
    mov qword ptr [rsp+6F0h], rax
    mov dword ptr [rsp+2E0h], 0
    mov qword ptr [rsp+6F8h], 0
    mov qword ptr [rsp+700h], r8
    loc_7FF85681C25E:
    mov rax, qword ptr [rsp+700h]
    mov rcx, qword ptr [rsp+6F8h]
    mov edx, dword ptr [rsp+2E0h]
    mov r8, qword ptr [rsp+6F0h]
    mov r9d, dword ptr [rsp+2DCh]
    mov r10, qword ptr [rsp+6E8h]
    mov r11d, dword ptr [rsp+2D8h]
    mov qword ptr [rsp+3F0h], rax
    mov qword ptr [rsp+3E8h], rcx
    mov dword ptr [rsp+0B8h], edx
    mov qword ptr [rsp+838h], r8
    mov dword ptr [rsp+0B4h], r9d
    mov qword ptr [rsp+3E0h], r10
    mov dword ptr [rsp+0B0h], r11d
    mov rax, qword ptr [rsp+3C8h]
    shl r8, 4
    lea rcx, [rax+r8]
    mov qword ptr [rsp+840h], rcx
    mov rax, qword ptr [rax+r8]
    mov qword ptr [rsp+578h], rax
    mov rcx, qword ptr [rsp+340h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    jnb loc_7FF85681C3B3
    mov eax, dword ptr [dword_7FF85723A9B0]
    lea ecx, [rax-3CE178E6h]
    xor ecx, -51E00203h
    add ecx, -58CB9Dh
    xor ecx, 54096010h
    lea edx, [rcx-18BFEAD9h]
    xor edx, eax
    sub edx, ecx
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF85681C380:
    mov eax, dword ptr [dword_7FF85723AA74]
    mov ecx, eax
    xor ecx, 19240ECBh
    lea edx, [rcx-2A928D42h]
    xor edx, ecx
    xor edx, 27C89126h
    add edx, ecx
    add edx, 5AEDB547h
    add edx, eax
    lea eax, [rcx+rdx]
    add eax, 7AA7AEF6h
    jmp loc_7FF856813880
    loc_7FF85681C3B3:
    mov eax, dword ptr [dword_7FF85723AACC]
    lea ecx, [rax-233C63A2h]
    mov edx, ecx
    xor edx, -2867080Ah
    lea r8d, [rdx+2380835h]
    xor ecx, -37AD3CCBh
    add ecx, eax
    add ecx, -0D017BB2h
    xor ecx, r8d
    xor ecx, eax
    add eax, ecx
    add eax, 40BA1B16h
    xor eax, edx
    jmp loc_7FF856813880
    loc_7FF85681C3EF:
    mov eax, dword ptr [rsp+0ACh]
    add rax, qword ptr [rsp+0F8h]
    movzx eax, byte ptr [r13+rax+0]
    mov rcx, qword ptr [rsp+348h]
    xor byte ptr [rcx], al
    mov rax, qword ptr [rsp+0F8h]
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
    lea rax, [rax+rax*2]
    mov rcx, qword ptr [rsp+0F8h]
    add rcx, rcx
    not rax
    sub rax, rcx
    add rax, -3
    mov qword ptr [rsp+6D8h], rax
    cmp qword ptr [rsp+0F8h], 1
    jz loc_7FF856813931
    loc_7FF85681C48A:
    mov rax, qword ptr [rsp+6D8h]
    mov ecx, dword ptr [rsp+0ACh]
    mov qword ptr [rsp+7F0h], rcx
    dec rcx
    mov qword ptr [rsp+7F8h], rcx
    mov qword ptr [rsp+6E0h], rax
    loc_7FF85681C4B4:
    mov rax, qword ptr [rsp+6E0h]
    mov qword ptr [rsp+350h], rax
    mov rcx, qword ptr [rsp+58h]
    sub rcx, rax
    mov rdx, qword ptr [rsp+0F0h]
    add rax, qword ptr [rsp+7F0h]
    movzx eax, byte ptr [r13+rax+0]
    xor byte ptr [rdx+rcx], al
    mov rax, qword ptr [rsp+350h]
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
    add rax, qword ptr [rsp+58h]
    mov rcx, qword ptr [rsp+0F0h]
    add rax, rcx
    add rax, 2
    mov qword ptr [rsp+800h], rax
    mov eax, dword ptr [dword_7FF85723AAB4]
    lea ecx, 2A789DABh[rax*2]
    lea edx, [rax+750EEB8Bh]
    neg ecx
    add ecx, eax
    add ecx, 2A789DABh
    add ecx, 75237BB8h
    xor edx, eax
    xor edx, ecx
    xor edx, 46C10676h
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF85681C59D:
    mov rax, qword ptr [rsp+360h]
    mov qword ptr [rsp+760h], rax
    mov eax, dword ptr [dword_7FF85723AB08]
    lea ecx, [rax-18904934h]
    xor ecx, 473FE812h
    lea edx, [rcx+492EB320h]
    xor edx, 1140A0CFh
    sub edx, eax
    sub edx, eax
    add edx, -0A52CE5Eh
    xor edx, ecx
    lea eax, [rcx+rdx]
    add eax, 6E58D173h
    jmp loc_7FF856813880
    loc_7FF85681C5E4:
    mov eax, dword ptr [dword_7FF85723A998]
    lea ecx, [rax+33156D21h]
    lea edx, [rax+4BCB1E0Dh]
    xor edx, 67DDF1Bh
    xor eax, -15D5A6C2h
    add edx, edx
    sub eax, edx
    add eax, 33D1F55Ch
    jmp loc_7FF85682171D
    loc_7FF85681C60F:
    mov dword ptr [rsp+25Ch], 0
    mov eax, dword ptr [dword_7FF85723AA40]
    mov ecx, eax
    xor ecx, -4013B168h
    sub ecx, eax
    add ecx, 6E95EC9Fh
    mov dword ptr [rsp+3Ch], ecx
    jmp loc_7FF856813884
    loc_7FF85681C639:
    mov eax, dword ptr [rsp+434h]
    mov ecx, dword ptr [rsp+448h]
    and ecx, eax
    lea edx, [rcx+rcx*4]
    lea ecx, [rcx+rdx*4]
    and eax, dword ptr [rsp+80h]
    lea eax, [rax+rax*8]
    add eax, ecx
    mov r9d, dword ptr [rsp+444h]
    sub r9d, eax
    add r9d, dword ptr [rsp+440h]
    sub r9d, dword ptr [rsp+43Ch]
    sub r9d, dword ptr [rsp+438h]
    xor r9d, dword ptr [rsp+108h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, 46h
    mov edx, 2Ch
    mov r8d, 5Fh
    call Eidolon_ForwardDynamicKeyToProtectionEvent
    jmp loc_7FF85681E5C1
    loc_7FF85681C6F3:
    mov eax, dword ptr [dword_7FF85723AB14]
    mov ecx, eax
    xor ecx, 704883BDh
    mov edx, eax
    xor edx, 690D58A8h
    add edx, edx
    add ecx, edx
    add ecx, 24CFE034h
    jmp loc_7FF856825DF5
    loc_7FF85681C718:
    mov eax, dword ptr [rsp+0C4h]
    mov rcx, qword ptr [rsp+5A8h]
    mov edx, dword ptr [rsp+198h]
    mov r8d, dword ptr [rsp+1A4h]
    mov r9, qword ptr [rsp+5B0h]
    mov dword ptr [rsp+314h], eax
    mov qword ptr [rsp+750h], rcx
    mov dword ptr [rsp+318h], edx
    mov qword ptr [rsp+758h], r9
    mov dword ptr [rsp+31Ch], r8d
    mov eax, dword ptr [dword_7FF85723AAF8]
    mov ecx, 31D63876h
    xor eax, ecx
    lea ecx, [rax+1898B9ACh]
    lea edx, [rax-6C4E94C1h]
    xor ecx, -600D81FBh
    add ecx, eax
    add eax, ecx
    add eax, 1D0C4CADh
    xor eax, edx
    jmp loc_7FF856813880
    loc_7FF85681C793:
    mov eax, dword ptr [rsp+130h]
    mov ecx, dword ptr [rsp+134h]
    mov dword ptr [rsp+24Ch], ecx
    mov dword ptr [rsp+250h], ecx
    mov dword ptr [rsp+254h], ecx
    mov dword ptr [rsp+258h], eax
    mov eax, dword ptr [dword_7FF85723A9DC]
    lea ecx, [rax-5FB3D77Fh]
    xor ecx, 7DEB6297h
    add eax, ecx
    add eax, ecx
    add eax, 0B6A651Fh
    jmp loc_7FF856813880
    loc_7FF85681C7DD:
    mov rax, qword ptr [rsp+7E0h]
    xor rax, qword ptr [rsp+7E8h]
    mov qword ptr [rsp+3D8h], rax
    add rax, 1000h
    mov qword ptr [rsp+340h], rax
    mov rax, qword ptr [rsp+7D8h]
    cmp rax, qword ptr [rsp+3C8h]
    jz loc_7FF856828E29
    mov eax, dword ptr [dword_7FF85723AA20]
    lea ecx, [rax-4BFD9C7Dh]
    mov edx, ecx
    xor edx, 77442C0Eh
    sub edx, ecx
    add eax, edx
    add eax, 1F977996h
    jmp loc_7FF856813880
    loc_7FF85681C83B:
    mov eax, dword ptr [rsp+180h]
    mov dword ptr [rsp+0D0h], eax
    mov eax, dword ptr [dword_7FF85723AA94]
    lea ecx, [rax-22E69605h]
    lea edx, [rax+6D7AF53Eh]
    xor edx, ecx
    xor edx, eax
    xor edx, 60402620h
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF85681C86E:
    mov eax, dword ptr [rsp+454h]
    mov ecx, dword ptr [rsp+458h]
    mov rdx, qword ptr [rsp+788h]
    mov r8d, dword ptr [rsp+45Ch]
    mov r9d, dword ptr [rsp+10Ch]
    mov r10, qword ptr [rsp+790h]
    mov r11, qword ptr [rsp+798h]
    mov rsi, qword ptr [rsp+7A0h]
    mov dword ptr [rsp+1D0h], eax
    mov dword ptr [rsp+1D4h], ecx
    mov qword ptr [rsp+5E8h], rdx
    mov dword ptr [rsp+1D8h], r8d
    mov dword ptr [rsp+1DCh], r9d
    mov qword ptr [rsp+5F0h], r10
    mov qword ptr [rsp+5F8h], r11
    mov qword ptr [rsp+600h], rsi
    jmp loc_7FF8568213D4
    loc_7FF85681C8EF:
    mov eax, dword ptr [rsp+0B0h]
    mov rcx, qword ptr [rsp+3E0h]
    mov edx, dword ptr [rsp+0B4h]
    mov r8d, dword ptr [rsp+0B8h]
    mov r9, qword ptr [rsp+3E8h]
    mov r10, qword ptr [rsp+3F0h]
    mov dword ptr [rsp+2E4h], eax
    mov qword ptr [rsp+708h], rcx
    mov dword ptr [rsp+2E8h], edx
    mov qword ptr [rsp+710h], r10
    mov qword ptr [rsp+718h], r9
    mov dword ptr [rsp+2ECh], r8d
    loc_7FF85681C94B:
    mov r10d, dword ptr [rsp+2ECh]
    mov rax, qword ptr [rsp+718h]
    mov rcx, qword ptr [rsp+710h]
    mov edx, dword ptr [rsp+2E8h]
    mov r8, qword ptr [rsp+708h]
    mov r9d, dword ptr [rsp+2E4h]
    mov dword ptr [rsp+188h], r10d
    cmp rcx, qword ptr [rsp+340h]
    jnb loc_7FF85681D63E
    mov r10d, dword ptr [rsp+188h]
    mov dword ptr [rsp+298h], r9d
    mov qword ptr [rsp+690h], r8
    mov dword ptr [rsp+29Ch], edx
    mov dword ptr [rsp+2A0h], r10d
    mov qword ptr [rsp+698h], rax
    mov qword ptr [rsp+6A0h], rcx
    loc_7FF85681C9C7:
    mov rax, qword ptr [rsp+6A0h]
    mov edx, dword ptr [rsp+2A0h]
    mov rcx, qword ptr [rsp+340h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    jz loc_7FF856825E2D
    mov r8, qword ptr [rsp+698h]
    mov r9d, dword ptr [rsp+29Ch]
    mov r10, qword ptr [rsp+690h]
    mov r11d, dword ptr [rsp+298h]
    mov dword ptr [rsp+2A4h], r11d
    mov dword ptr [rsp+2A8h], r11d
    mov qword ptr [rsp+6A8h], r10
    mov dword ptr [rsp+2ACh], r9d
    mov dword ptr [rsp+2B0h], edx
    mov qword ptr [rsp+6B0h], r8
    mov qword ptr [rsp+6B8h], rax
    mov qword ptr [rsp+6C0h], rcx
    loc_7FF85681CA93:
    mov r8, qword ptr [rsp+6C0h]
    mov r9, qword ptr [rsp+6B8h]
    mov r10, qword ptr [rsp+6B0h]
    mov r11d, dword ptr [rsp+2B0h]
    mov ecx, dword ptr [rsp+2ACh]
    mov rsi, qword ptr [rsp+6A8h]
    mov eax, dword ptr [rsp+2A8h]
    mov edx, dword ptr [rsp+2A4h]
    mov qword ptr [rsp+568h], r8
    mov qword ptr [rsp+0F0h], r9
    mov qword ptr [rsp+560h], r10
    mov dword ptr [rsp+4ACh], r11d
    mov qword ptr [rsp+558h], rsi
    not r10
    cmp r8, r10
    cmovb r10, r8
    loc_7FF85681CB02:
    mov qword ptr [rsp+58h], r10
    mov r8, qword ptr [qword_7FF8571CC8E0]
    mov r9, -2AEB5AC8399123B6h
    add r9, r8
    mov r10, -4785249E36A33224h
    add r10, r8
    mov r11, -4E0B244F63BE44F0h
    xor r10, r11
    mov r11, 241EC1B79143AF3h
    add r11, r10
    mov rsi, -3CFBB8A63E5B899Ah
    sub rsi, r8
    xor rsi, r10
    xor rsi, r11
    xor rsi, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, 5BCAE5C1304420F9h
    add r10, r8
    add r10, rsi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rsp+560h], r10
    jnz loc_7FF85681CCB6
    mov r8, qword ptr [rsp+558h]
    mov dword ptr [rsp+2C4h], edx
    mov dword ptr [rsp+2C8h], eax
    mov qword ptr [rsp+6D0h], r8
    mov dword ptr [rsp+2CCh], ecx
    mov eax, dword ptr [dword_7FF85723A9D4]
    lea ecx, [rax-424981B8h]
    mov edx, ecx
    xor edx, 35176100h
    lea r8d, [rdx-59AEC102h]
    mov r9d, r8d
    xor r9d, 0F28518Eh
    sub ecx, r9d
    add edx, eax
    add edx, r9d
    add edx, ecx
    sub edx, r8d
    add eax, edx
    add eax, 613AD94Ah
    jmp loc_7FF856813880
    loc_7FF85681CCB6:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp qword ptr [rsp+58h], 4
    jnb loc_7FF856825FCD
    mov dword ptr [rsp+2BCh], edx
    loc_7FF85681CD37:
    mov dword ptr [rsp+2C0h], ecx
    mov eax, dword ptr [rsp+2C0h]
    mov ecx, dword ptr [rsp+2BCh]
    mov dword ptr [rsp+0ACh], eax
    mov dword ptr [rsp+17Ch], ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, qword ptr [qword_7FF8571CC8E8]
    mov r9, r8
    mov rdx, r8
    mov rax, -264A394DC7DEE93Fh
    add rax, r8
    mov rcx, rax
    mov r10, -459D98E0833F576Bh
    xor rcx, r10
    add rcx, r8
    not r8
    lea r10, [r8+r8*4]
    mov rsi, -3FBC21B7891E0074h
    and r9, rsi
    lea r9, [r9+r9*2]
    mov r11, r8
    and r11, rsi
    lea r11, [r11+r11*4]
    add r11, r9
    mov r9, 3FBC21B7891E0073h
    xor rdx, r9
    add rdx, rdx
    mov r9, 1FBC21B7891E0073h
    and r8, r9
    shl r8, 3
    sub r8, rdx
    add r8, r11
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
    mov rdx, -55A3F8E395DE800Ch
    add rcx, rdx
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
    mov rdx, rax
    not rdx
    mov r8, rcx
    or r8, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    lea r9, [r8+r8*4]
    lea r8, [r8+r9*2]
    mov r9, rcx
    or r9, rax
    lea r10, [r9+r9*4]
    lea r9, [r9+r10*2]
    mov r10, rcx
    xor r10, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and rdx, rcx
    lea rdx, [rdx+rdx*8]
    and rcx, rax
    imul rax, rcx, 0F5h
    sub rax, rdx
    sub rax, r10
    add rax, r9
    sub rax, r8
    and rax, qword ptr [rsp+58h]
    add rax, qword ptr [rsp+0F0h]
    mov qword ptr [rsp+348h], rax
    mov rdx, qword ptr [qword_7FF8571CC8F0]
    mov rax, -0E5C8395E26514D8h
    add rax, rdx
    mov r8, rax
    mov rcx, -48BB22A17475FEBCh
    xor r8, rcx
    mov r10, rax
    mov rcx, 48BB22A17475FEBBh
    xor r10, rcx
    lea r9, [r10+r10*2]
    mov r11, rax
    mov rcx, -3CE656CB3465E16Fh
    xor r11, rcx
    lea rcx, [r11*8]
    sub rcx, r11
    mov r11, r8
    mov rsi, 0BA28B95BFEFE02Ah
    and r11, rsi
    add r11, r11
    lea r11, [r11+r11*2]
    mov rsi, 745D746A40101FD5h
    and r8, rsi
    add r8, r8
    sub r8, r11
    mov r11, r10
    and r11, rsi
    lea r11, [r11+r11*2]
    mov rsi, -745D746A40101FD6h
    and r10, rsi
    lea r10, [r10+r10*2]
    add rcx, r10
    add rcx, r8
    sub rcx, r11
    sub rcx, r9
    mov r8, rdx
    not r8
    mov r9, rdx
    mov r10, -2424DA674B997141h
    and r9, r10
    lea r10, [r9+r9*4]
    lea r9, [r9+r10*2]
    mov r10, rdx
    mov rsi, 2424DA674B997140h
    or r10, rsi
    lea r11, [r10+r10*4]
    lea r10, [r10+r11*2]
    mov r11, rdx
    and r8, rsi
    lea r8, [r8+r8*8]
    and rdx, rsi
    imul rdx, 0F5h
    sub rdx, r8
    mov r8, -7C9532E830C802A9h
    add r8, rcx
    xor r11, rsi
    sub rdx, r11
    add rdx, r10
    sub rdx, r9
    mov r9, r8
    not r9
    mov r10, rdx
    or r10, r9
    mov r11, rdx
    or r11, r8
    and r9, rdx
    and rdx, r8
    mov r8, r9
    add r9, r9
    lea rdx, [r9+rdx*2]
    not r10
    lea r9, [r10+r10*2]
    not r11
    shl r11, 2
    not r8
    sub r8, rdx
    sub r8, r11
    sub r8, r9
    lea r9, [r8-3]
    mov r10, rax
    mov rdx, r9
    or rdx, rax
    lea r8, 0FFFFFFFFFFFFFFFAh[r8*2]
    and rax, r9
    add rax, rax
    sub r8, rax
    not r10
    or r9, r10
    not rdx
    add rdx, r9
    add rdx, r8
    sub rdx, r10
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc rdx
    and rdx, qword ptr [rsp+58h]
    mov qword ptr [rsp+0F8h], rdx
    cmp rdx, 3
    ja def_7FF85681D630
    lea rcx, jpt_7FF85681D630
    movsxd rax, dword ptr [rcx+rdx*4]
    add rax, rcx
    jmp rax
    loc_7FF85681D632:
    mov eax, dword ptr [rsp+17Ch]
    jmp loc_7FF856817A89
    loc_7FF85681D63E:
    mov eax, dword ptr [dword_7FF85723AAD0]
    mov ecx, -1EB5A979h
    add eax, ecx
    mov ecx, eax
    xor ecx, -5D296C00h
    mov edx, eax
    xor edx, 25973ADAh
    mov r8d, eax
    xor r8d, -5777BF7h
    sub r8d, edx
    sub r8d, ecx
    xor r8d, eax
    mov dword ptr [rsp+3Ch], r8d
    jmp loc_7FF856813884
    loc_7FF85681D678:
    mov eax, dword ptr [rsp+0BCh]
    mov ecx, dword ptr [rsp+0C0h]
    mov dword ptr [rsp+2FCh], eax
    mov dword ptr [rsp+300h], ecx
    mov qword ptr [rsp+740h], 0
    loc_7FF85681D6A0:
    mov rax, qword ptr [rsp+740h]
    mov ecx, dword ptr [rsp+300h]
    mov r9d, dword ptr [rsp+2FCh]
    mov rdx, qword ptr [rsp+100h]
    mov r8d, dword ptr [rdx+rax*4]
    imul r10d, r8d, -3361D2AFh
    mov r11d, dword ptr [dword_7FF8571CC888]
    mov esi, r11d
    xor esi, 2A1FDD98h
    lea edi, [rsi-3045BBDBh]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ebx, [rsi+69C24241h]
    mov ebp, ebx
    xor ebp, 2A0CF4A6h
    xor ebx, 3CD0AE8Dh
    sub ebx, ebp
    xor ebx, esi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    not esi
    mov r14d, ebx
    or r14d, esi
    not r14d
    mov ebp, ebx
    or ebp, edi
    not ebp
    and edi, ebx
    and esi, ebx
    add esi, esi
    lea esi, [rsi+rdi*2]
    not edi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add edi, ebp
    add edi, esi
    lea esi, [rdi+r14*2]
    add esi, 2
    xor esi, r11d
    imul esi, r8d
    shr r10d, 11h
    or r10d, esi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edi, dword ptr [dword_7FF8571CC88C]
    lea r11d, [rdi+46B5A81Bh]
    mov esi, r11d
    not esi
    lea ebx, [rsi+rsi*2]
    mov r14d, esi
    and esi, -7F5A4080h
    lea esi, [rsi+rsi*2]
    mov r15d, r11d
    xor r15d, 7F5A407Fh
    lea ebp, [r15*8]
    sub ebp, r15d
    add ebp, esi
    mov esi, r11d
    and esi, 0A5BF80h
    add esi, esi
    lea r15d, [rsi+rsi*2]
    mov esi, r11d
    and esi, 7F5A407Fh
    add esi, esi
    sub esi, r15d
    and r14d, 7F5A407Fh
    lea r14d, [r14+r14*2]
    add esi, ebp
    sub esi, r14d
    sub esi, ebx
    xor esi, 7DFFB761h
    lea ebx, [rsi-38DC37E0h]
    lea r14d, [rsi+218AFCB2h]
    xor r14d, edi
    xor r14d, 468EB3B4h
    sub r14d, esi
    lea ebp, [rsi+r14]
    add ebp, 3F10938Ch
    mov edi, ebx
    not edi
    mov esi, ebp
    or esi, ebx
    mov r14d, ebp
    and r14d, edi
    and ebx, ebp
    lea ebx, [rbx+r14*2]
    mov r14d, ebp
    or r14d, edi
    xor edi, ebp
    sub ebx, ebp
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not r14d
    not esi
    add esi, esi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea edi, [rbx+rdi*2]
    sub edi, esi
    add edi, r14d
    xor edi, r11d
    imul edi, r10d
    xor edi, r9d
    mov r9d, dword ptr [dword_7FF8571CC890]
    lea r10d, [r9+55DFF2C5h]
    mov esi, r9d
    xor esi, -981DB9Ch
    mov ebx, r10d
    not ebx
    mov r11d, esi
    or r11d, ebx
    mov r14d, esi
    and ebx, esi
    and esi, r10d
    lea esi, [rsi+rsi*2]
    lea esi, [rsi+rbx*4]
    or r14d, r10d
    lea ebx, [r14+r14*4]
    sub ebx, esi
    rol edi, 0Dh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    shl r11d, 2
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
    sub ebx, r10d
    sub ebx, r11d
    add r9d, ebx
    add r9d, 5E4145F1h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    imul r9d, edi
    mov r11d, dword ptr [dword_7FF8571CC894]
    mov r10d, r11d
    not r10d
    mov esi, r10d
    mov edi, r10d
    or r10d, -1893056Bh
    add r11d, r11d
    sub r10d, r11d
    and esi, -1893056Bh
    lea r11d, [rsi+rsi*2]
    and edi, 1893056Ah
    shl edi, 2
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    sub r10d, r11d
    lea r11d, 0FFFFFFFF81146A31h[r10*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r10d, r11d
    add r10d, -7EEB95CFh
    sub r9d, r10d
    add r9d, -7F276397h
    mov dword ptr [rsp+18Ch], r9d
    xor r8d, dword ptr [rcx+r13]
    mov dword ptr [rdx+rax*4], r8d
    mov edx, dword ptr [dword_7FF8571CC898]
    mov r8d, edx
    not r8d
    mov r9d, edx
    or r9d, -3AC1D874h
    and r8d, 453E278Ch
    lea r8d, [r8+r8*2]
    lea r10d, [rdx+rdx*2]
    mov r11d, edx
    and r11d, 53E278Ch
    shl r11d, 2
    mov esi, edx
    and esi, 3AC1D873h
    lea esi, [rsi+rsi*2]
    sub r11d, esi
    add r11d, r10d
    lea r10d, [r11+r8*2]
    lea r8d, [r9+r10]
    add r8d, 608B12B9h
    add r9d, r10d
    add r9d, -2F997A7Fh
    mov r10d, r9d
    xor r10d, 723CB92Dh
    add r10d, 6AB3034Fh
    xor r10d, r9d
    xor r10d, -26CDDF53h
    mov r9d, r8d
    not r9d
    mov r11d, r10d
    or r11d, r9d
    not r11d
    lea esi, [r11*8]
    sub esi, r11d
    mov r11d, r10d
    xor r11d, r8d
    lea r11d, [r11+r11*4]
    and r9d, r10d
    lea r9d, [r9+r9*2]
    and r10d, r8d
    lea r9d, [r10+r9*2]
    sub r9d, r11d
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
    nop
    nop
    nop
    nop
    add esi, edx
    add esi, r9d
    add esi, ecx
    and esi, 3FFFh
    mov dword ptr [rsp+190h], esi
    mov rcx, qword ptr [qword_7FF8571CC8A0]
    mov rdx, -1DBA2ACF6382F339h
    xor rcx, rdx
    mov rdx, -57E4BF410D98BB7Ch
    add rdx, rcx
    mov r8, rdx
    mov r9, -5031E0D81548E077h
    xor r8, r9
    mov r9, 1D4F8B2DAC1091B6h
    add r9, r8
    mov r10, r9
    mov r11, 7597459CA4E9B0D0h
    xor r10, r11
    mov r11, -1B222A896DF15AA6h
    add rcx, r11
    xor rcx, r8
    mov r8, rcx
    or r8, r10
    lea r11, [r8+r8*2]
    not r8
    lea rsi, [r8*8]
    sub rsi, r8
    and rcx, r10
    lea rcx, [rcx+r11*2]
    add rcx, rsi
    mov r8, -7
    sub r8, rcx
    xor r9, rdx
    xor r9, r8
    add r9, rax
    mov qword ptr [rsp+850h], r9
    cmp r9, qword ptr [rsp+848h]
    jnz loc_7FF85681E021
    mov eax, dword ptr [rsp+18Ch]
    mov ecx, dword ptr [rsp+190h]
    jmp loc_7FF85681ED77
    loc_7FF85681E021:
    mov eax, dword ptr [dword_7FF85723AAE4]
    lea ecx, [rax-425A85E4h]
    mov edx, ecx
    xor edx, 51C48A4Fh
    lea r8d, [rdx-5E815C24h]
    xor r8d, 3A334BC6h
    add r8d, edx
    xor r8d, ecx
    sub r8d, eax
    mov dword ptr [rsp+3Ch], r8d
    jmp loc_7FF856813884
    loc_7FF85681E056:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [qword_7FF8571CC680]
    mov rcx, -774295194464F43Ch
    lea rdx, [rax+rcx]
    mov rcx, rdx
    mov r8, 153CD57F7148F17Bh
    xor rcx, r8
    add rdx, rax
    add rdx, rcx
    mov eax, dword ptr [dword_7FF8571CC688]
    lea ecx, [rax-63443D89h]
    mov r8d, ecx
    not r8d
    mov r9d, r8d
    and r9d, 20EF744Ah
    mov r11d, r8d
    and r11d, 5F108BB5h
    or r8d, 5F108BB5h
    lea r10d, [r8+rcx*2]
    add r10d, r11d
    lea ecx, [r10+r9*2]
    add ecx, -73B768A3h
    mov r8d, ecx
    mov r11d, ecx
    and r11d, 0BB044C5h
    mov esi, ecx
    and esi, -0BB044C6h
    lea r11d, [rsi+r11*2]
    sub r11d, ecx
    not ecx
    mov esi, ecx
    and esi, -0BB044C6h
    and ecx, 0BB044C5h
    add ecx, ecx
    xor r8d, 0BB044C5h
    lea r11d, [r11+r8*2]
    sub r11d, ecx
    lea r8d, [r11+rsi]
    add r8d, 78A08C29h
    lea ecx, [r11+rsi]
    add ecx, -5ECDC25Eh
    add r11d, esi
    lea r10d, [r10+r9*2]
    add r10d, -9292F10h
    xor r10d, r11d
    mov r11d, eax
    not r11d
    mov esi, r10d
    or esi, r11d
    mov edi, r10d
    and r11d, r10d
    mov r9d, r11d
    add r11d, r11d
    and r10d, eax
    lea r10d, [r11+r10*2]
    not esi
    lea r11d, [rsi+rsi*2]
    or edi, eax
    not edi
    shl edi, 2
    not r9d
    sub r9d, r10d
    sub r9d, edi
    sub r9d, r11d
    add r9d, -3
    mov r10d, r9d
    or r10d, r8d
    not r8d
    mov r11d, r9d
    and r9d, r8d
    mov esi, r9d
    not esi
    add esi, esi
    sub esi, r9d
    or r11d, r8d
    not r10d
    shl r10d, 2
    sub esi, r10d
    add esi, r11d
    lea r8d, [rsi+r8*2]
    add r8d, eax
    add r8d, -63443D88h
    mov eax, r8d
    or eax, ecx
    mov r9d, ecx
    not r9d
    mov r10d, r8d
    or r10d, r9d
    mov r11d, r8d
    xor r11d, ecx
    and r9d, r8d
    and r8d, ecx
    lea ecx, [r9+r9*2]
    add ecx, ecx
    lea r8d, [r8+r8*2]
    lea ecx, [rcx+r8*2]
    add ecx, r11d
    add r10d, r10d
    lea r8d, [r10+r10*2]
    sub ecx, r8d
    not eax
    lea eax, [rax+rax*2]
    lea r8d, [rcx+rax*2]
    mov rcx, qword ptr [r12+48h]
    mov rax, -5A0C7EC67167AFAEh
    xor rcx, rax
    mov rax, 354D7FF30A08C83Ch
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r9, [rsp+60h]
    call qword ptr [VirtualProtect]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    jz loc_7FF856828E70
    loc_7FF85681E5B6:
    cmp dword ptr [rsp+60h], 20h
    jnz loc_7FF856825E00
    loc_7FF85681E5C1:
    mov rax, qword ptr [qword_7FF8571CC698]
    mov rcx, rax
    mov rdx, -25E2D6B6B9ACC7FFh
    xor rcx, rdx
    mov rdx, -0F26B6B8D6317A53h
    add rdx, rcx
    mov r8, -7C4D3A7005445D33h
    xor rcx, r8
    xor rcx, rdx
    add rcx, rax
    xor rcx, qword ptr [r12+50h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, qword ptr [rcx]
    mov rax, qword ptr [rcx+8]
    mov qword ptr [rsp+368h], r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, rax
    sub rdx, r8
    mov r8d, dword ptr [dword_7FF8571CC6A0]
    mov r9d, r8d
    not r9d
    mov r10d, r9d
    mov r11d, r9d
    and r9d, 626BFB9Dh
    mov ecx, r8d
    and ecx, 626BFB9Dh
    sub ecx, r9d
    mov r9d, r8d
    xor r9d, 626BFB9Dh
    lea r9d, [r9+r9*2]
    add ecx, r9d
    or r10d, 626BFB9Dh
    and r11d, -626BFB9Eh
    sub ecx, r10d
    add ecx, r11d
    not r10d
    shl r10d, 2
    sub ecx, r10d
    lea r9d, [r8-42B7075Eh]
    sub ecx, r9d
    sub ecx, r9d
    lea r9d, [r8+0ED1ADE5h]
    add ecx, -79574B80h
    xor ecx, r9d
    sub ecx, r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add cl, 0ACh
    sar rdx, cl
    mov qword ptr [rsp+370h], rdx
    mov rcx, qword ptr [r12]
    mov rdx, 3CA0ADB058121E5Dh
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
    mov qword ptr [rsp+378h], rcx
    add rcx, 1000h
    mov qword ptr [rsp+330h], rcx
    cmp rax, qword ptr [rsp+368h]
    jz loc_7FF856825F5A
    mov eax, dword ptr [dword_7FF85723A9C4]
    mov ecx, eax
    xor ecx, 4A7AA8Ah
    lea edx, [rcx-0AA430EAh]
    lea r8d, [rcx+3B6F05C8h]
    mov r9d, r8d
    xor r9d, 36ACBEBEh
    mov r10d, r8d
    xor r10d, 1F27062Bh
    xor r8d, eax
    xor r8d, 4B5F9681h
    lea eax, [r8+r10]
    add eax, -529F398Bh
    xor eax, edx
    add eax, r10d
    add eax, -529F398Bh
    sub eax, ecx
    sub eax, r9d
    add eax, -486A3EBDh
    jmp loc_7FF856813880
    loc_7FF85681E8FC:
    mov eax, dword ptr [rsp+140h]
    mov ecx, eax
    and ecx, 18B389E5h
    shl ecx, 3
    and eax, 274C761Ah
    imul eax, 0F5h
    sub eax, ecx
    sub eax, dword ptr [rsp+484h]
    add eax, dword ptr [rsp+480h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub eax, dword ptr [rsp+47Ch]
    mov dword ptr [rsp+6Ch], eax
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
    and eax, -42770EFDh
    mov ecx, dword ptr [rsp+6Ch]
    not ecx
    and ecx, 2770EFCh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edx, dword ptr [rsp+6Ch]
    mov r8d, edx
    xor r8d, 42770EFCh
    lea r8d, [r8+r8*2]
    mov r9d, edx
    or r9d, 42770EFCh
    lea r9d, [r9+r9*4]
    and edx, 42770EFCh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea edx, [rdx+rdx*2]
    add edx, edx
    mov r10d, dword ptr [rsp+6Ch]
    mov r11d, 1D88F103h
    and r10d, r11d
    lea edx, [rdx+r10*8]
    sub edx, r9d
    sub edx, r8d
    lea ecx, [rdx+rcx*8]
    lea edx, [rcx+rax]
    mov dword ptr [rsp+488h], edx
    add eax, ecx
    add eax, 4CCCC2EBh
    mov dword ptr [rsp+0A8h], eax
    not eax
    and eax, 5077CABCh
    add eax, eax
    lea eax, [rax+rax*4]
    mov dword ptr [rsp+48Ch], eax
    mov eax, dword ptr [dword_7FF85723A9B4]
    mov ecx, -3ACD1ABEh
    xor eax, ecx
    add eax, -75FACE2Fh
    jmp loc_7FF856813880
    loc_7FF85681EB3B:
    cmp eax, 379D0A55h
    jnz loc_7FF85682AC3B
    loc_7FF85681EB46:
    mov rax, qword ptr [rsp+738h]
    mov rcx, qword ptr [rsp+730h]
    mov rdx, qword ptr [rsp+728h]
    mov r8d, dword ptr [rsp+2F8h]
    mov r9d, dword ptr [rsp+2F4h]
    mov r10, qword ptr [rsp+720h]
    mov r11d, dword ptr [rsp+2F0h]
    mov qword ptr [rsp+3F8h], rax
    mov qword ptr [rsp+100h], rcx
    mov qword ptr [rsp+598h], rdx
    mov dword ptr [rsp+4D0h], r8d
    mov dword ptr [rsp+0C0h], r9d
    mov qword ptr [rsp+590h], r10
    mov dword ptr [rsp+0BCh], r11d
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
    mov rax, qword ptr [rsp+3F8h]
    cmp rax, rdx
    cmovb rdx, rax
    loc_7FF85681EC1C:
    mov qword ptr [rsp+48h], rdx
    cmp qword ptr [rsp+598h], -1
    jz loc_7FF856825F24
    mov ecx, dword ptr [dword_7FF8571CC848]
    mov eax, 3209B231h
    xor ecx, eax
    mov eax, 4F7182B6h
    sub eax, ecx
    add ecx, 3E0B137Eh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov rax, qword ptr [rsp+48h]
    xor cl, 30h
    mov rdx, rax
    shr rdx, cl
    mov qword ptr [rsp+848h], rdx
    mov rdx, qword ptr [qword_7FF8571CC850]
    mov rcx, -2B7B11F7C5D45B97h
    lea r8, [rdx+rcx]
    mov rcx, -4E1EBAA285829B76h
    lea r9, [rdx+rcx]
    mov rcx, 4BCFFAAE96F65950h
    xor r9, rcx
    mov rcx, 30E775F5952CD767h
    add rcx, rdx
    xor rcx, r8
    mov r8, 57BA3D07DA3BE38h
    add rdx, r8
    mov r8, rdx
    not r8
    mov r10, r9
    or r10, r8
    not r10
    lea r10, [r10+r10*2]
    mov r11, r9
    or r11, rdx
    not r11
    add r11, r11
    and r8, r9
    lea rsi, [r8+r8*2]
    not r8
    add r8, r8
    and rdx, r9
    mov r9, rdx
    not r9
    add rdx, rdx
    sub rdx, rsi
    lea rdx, [rdx+r9*4]
    sub rdx, r8
    sub rdx, r11
    sub rdx, r10
    xor rdx, rcx
    cmp rax, rdx
    jnb loc_7FF856825FAB
    mov eax, dword ptr [rsp+0BCh]
    mov ecx, dword ptr [rsp+0C0h]
    loc_7FF85681ED77:
    mov dword ptr [rsp+304h], eax
    mov dword ptr [rsp+308h], ecx
    mov eax, dword ptr [rsp+308h]
    mov ecx, dword ptr [rsp+304h]
    mov dword ptr [rsp+74h], eax
    mov dword ptr [rsp+194h], ecx
    mov rcx, qword ptr [qword_7FF8571CC858]
    mov rax, -214CBD056D54B6A1h
    lea rdx, [rcx+rax]
    mov r9, rdx
    mov rax, -6A0B61AFFEE344ACh
    xor r9, rax
    mov rax, -5FE0DA2C8201FA0Eh
    add rax, r9
    mov r8, 79AD6B84D58060C3h
    add r8, r9
    mov r10, rdx
    mov r11, 6A0B61AFFEE344ABh
    xor r10, r11
    mov r11, r10
    lea rsi, [r10+r10]
    mov rdi, 74F8B036BF3A3F17h
    and r10, rdi
    lea r10, [r10+r10*2]
    add r10, r10
    and r9, rdi
    lea r9, [r9+r9*2]
    lea r9, [r10+r9*2]
    mov r10, rdx
    mov rdi, 610C2E66BE268443h
    xor r10, rdi
    add r9, r10
    mov qword ptr [rsp+5A0h], r8
    mov r10, 0B074FC940C5C0E8h
    and r11, r10
    lea r10, [r11+r11*2]
    mov r11, -160E9F92818B81D2h
    or rsi, r11
    lea r11, [rsi+rsi*2]
    sub r9, r11
    lea r9, [r9+r10*2]
    sub r9, r8
    mov r8, 337AD905D4B88240h
    add rcx, r8
    add rcx, r9
    mov r9, rdx
    not r9
    mov r8, rcx
    or r8, r9
    mov r10, rcx
    or r10, rdx
    and r9, rcx
    lea r11, [r9+r9*2]
    and rcx, rdx
    mov rdx, rcx
    add rcx, rcx
    sub rcx, r11
    not rdx
    lea rcx, [rcx+rdx*4]
    not r9
    add r9, r9
    sub rcx, r9
    not r10
    add r10, r10
    sub rcx, r10
    not r8
    lea rdx, [r8+r8*2]
    sub rcx, rdx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov qword ptr [rsp+858h], rcx
    mov rax, qword ptr [rsp+5A0h]
    not rax
    mov qword ptr [rsp+860h], rax
    mov eax, dword ptr [dword_7FF85723AAE8]
    mov ecx, 6709235Ch
    add eax, ecx
    jmp loc_7FF856813880
    loc_7FF85681EFF9:
    mov eax, dword ptr [rsp+0A8h]
    mov ecx, 5077CABCh
    or eax, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov ecx, dword ptr [rsp+0A8h]
    mov edx, ecx
    and edx, 2F883543h
    and ecx, 5077CABCh
    lea ecx, [rcx+rcx*8]
    lea ecx, [rcx+rdx*4]
    sub ecx, eax
    mov eax, dword ptr [rsp+48Ch]
    add eax, ecx
    add eax, 1D313F98h
    mov edx, eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [rsp+140h]
    sub ecx, dword ptr [rsp+488h]
    xor edx, -2C46F893h
    sub ecx, edx
    sub ecx, dword ptr [rsp+0A8h]
    add ecx, edx
    sub ecx, dword ptr [rsp+6Ch]
    sub ecx, eax
    mov eax, dword ptr [rsp+478h]
    add cl, 5Ch
    shl eax, cl
    or eax, dword ptr [rsp+474h]
    mov rcx, qword ptr [rsp+338h]
    movzx ecx, byte ptr [rcx]
    mov byte ptr [rsp+43h], cl
    mov dword ptr [rsp+260h], eax
    jmp loc_7FF856821AAF
    loc_7FF85681F13B:
    mov eax, dword ptr [rsp+114h]
    mov ecx, dword ptr [rsp+118h]
    mov dword ptr [rsp+1E8h], ecx
    mov dword ptr [rsp+1ECh], ecx
    mov dword ptr [rsp+1F0h], eax
    loc_7FF85681F15E:
    mov eax, dword ptr [rsp+1F0h]
    mov ecx, dword ptr [rsp+1E8h]
    mov dword ptr [rsp+120h], eax
    mov dword ptr [rsp+11Ch], ecx
    mov rcx, qword ptr [qword_7FF8571CC770]
    mov rax, rcx
    not rax
    mov r11, 8CC347A1923C9A8h
    and rax, r11
    lea rdx, [rax+rax*4]
    lea rax, [rax+rdx*2]
    mov rdx, rcx
    or rdx, r11
    lea r8, [rdx+rdx*4]
    lea r8, [rdx+r8*2]
    mov r9, rcx
    xor r9, r11
    mov rdx, rcx
    mov r10, -8CC347A1923C9A9h
    and rdx, r10
    lea r10, [rdx+rdx*8]
    mov rdx, rcx
    and rdx, r11
    imul rdx, 0F5h
    sub rdx, r10
    sub rdx, r9
    add rdx, r8
    sub rdx, rax
    mov rax, -22FE5B35490674BCh
    lea r8, [rdx+rax]
    mov rax, r8
    not rax
    mov rdi, 4098924B6489C206h
    and rax, rdi
    add rax, rax
    lea r9, [rax+rax*4]
    mov rax, r8
    or rax, rdi
    lea r10, [rax+rax*4]
    lea r10, [rax+r10*2]
    mov r11, r8
    xor r11, rdi
    add r11, r11
    mov rsi, r8
    mov rax, 1F676DB49B763DF9h
    and rsi, rax
    shl rsi, 3
    mov rax, r8
    and rax, rdi
    imul rax, 0F5h
    sub rax, rsi
    sub rax, r11
    add rax, r10
    sub rax, r9
    mov r9, -0A534398315BA8Fh
    add r9, rax
    mov r10, r9
    not r10
    mov r11, r10
    mov rsi, r10
    mov rdi, r9
    mov rbx, -4E3FD72D596D795Dh
    and r10, rbx
    and r9, rbx
    sub r9, r10
    xor rdi, rbx
    lea r10, [rdi+rdi*2]
    add r9, r10
    or r11, rbx
    mov r10, 4E3FD72D596D795Ch
    and rsi, r10
    sub r9, r11
    add r9, rsi
    not r11
    shl r11, 2
    sub r9, r11
    xor r9, r8
    mov r8d, dword ptr [rsp+1ECh]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov rdx, -4EFD0E3DFE60F1F9h
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    xor rax, rdx
    xor rax, r9
    mov rcx, qword ptr [qword_7FF8571CC778]
    mov rdx, 55113A8CF74E615Bh
    add rcx, rdx
    mov rdx, rcx
    mov r9, -6C412A42118958C8h
    xor rdx, r9
    mov r9, rcx
    mov r10, -581E0F0117819B89h
    xor r9, r10
    add rdx, r9
    sub rcx, rdx
    mov rdx, -147FCA583EAD7FDCh
    add rcx, rdx
    xor rcx, r9
    and rax, qword ptr [rsp+50h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    jnz loc_7FF856822FCB
    mov eax, dword ptr [rsp+11Ch]
    mov dword ptr [rsp+1FCh], eax
    mov dword ptr [rsp+200h], r8d
    loc_7FF85681F5CC:
    mov eax, dword ptr [rsp+200h]
    mov ecx, dword ptr [rsp+1FCh]
    mov r9d, dword ptr [dword_7FF8571CC7A8]
    mov edx, 5B49AA5Ch
    xor r9d, edx
    lea r8d, [r9+219AB91Eh]
    mov edx, r8d
    not edx
    lea r10d, [rdx+rdx*2]
    mov r11d, edx
    and r11d, -75A175D3h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea esi, [r11+r11*2]
    mov r11d, edx
    and r11d, 75A175D2h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea edi, [r11+r11*2]
    mov ebx, r8d
    xor ebx, -75A175D3h
    lea r11d, [rbx*8]
    sub r11d, ebx
    mov ebx, r8d
    and ebx, 75A175D2h
    add ebx, ebx
    lea ebx, [rbx+rbx*2]
    mov ebp, r8d
    and ebp, 0A5E8A2Dh
    add ebp, ebp
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub ebp, ebx
    add r11d, edi
    add r11d, ebp
    sub r11d, esi
    sub r11d, r10d
    xor r11d, r9d
    xor r11d, -53222D78h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add r9d, 28C0A743h
    mov r10d, r9d
    or r10d, edx
    not r10d
    add r10d, r10d
    lea r10d, [r10+r10*4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    or r11d, r8d
    lea esi, [r11+r11*4]
    lea r11d, [r11+rsi*2]
    mov esi, r9d
    xor esi, r8d
    add esi, esi
    and edx, r9d
    shl edx, 3
    and r8d, r9d
    imul r8d, 0F5h
    sub r8d, edx
    sub r8d, esi
    add r8d, r11d
    sub r8d, r10d
    add r8d, dword ptr [rsp+120h]
    mov r9d, dword ptr [dword_7FF8571CC7AC]
    lea edx, [r9-45E1D0F7h]
    xor edx, -5EA204Eh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r11d, [rdx-6D28A3C7h]
    mov r10d, r11d
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov esi, r10d
    and esi, 7EECC57Ah
    lea edi, [rsi+rsi*4]
    lea esi, [rsi+rdi*2]
    mov edi, r11d
    or edi, 7EECC57Ah
    mov ebx, r11d
    and ebx, -7EECC57Bh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r11d, 7EECC57Ah
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
    nop
    nop
    nop
    nop
    add ebx, edi
    add ebx, r11d
    sub ebx, esi
    lea r11d, [rbx+r10]
    add r11d, 4DA358Dh
    lea esi, [rbx+r10]
    add esi, -2B6EAAB2h
    mov edi, ebx
    add edi, r10d
    lea r10d, [r9+rdx]
    add r10d, -45E1D0F7h
    mov ebx, 4BE52DCAh
    sub ebx, r10d
    xor ebx, r9d
    xor ebx, r11d
    add edx, ebx
    add edx, -6D28A3C7h
    sub edx, edi
    add edx, -742C7C3Fh
    xor edx, esi
    and edx, r8d
    mov r8, qword ptr [rsp+508h]
    add r8, qword ptr [rsp+50h]
    mov dword ptr [rsp+204h], ecx
    mov dword ptr [rsp+208h], eax
    mov qword ptr [rsp+610h], r8
    mov dword ptr [rsp+20Ch], edx
    loc_7FF85681FA60:
    mov rax, qword ptr [rsp+610h]
    mov edx, dword ptr [rsp+208h]
    mov r9d, eax
    xor r9d, edx
    mov r8d, dword ptr [dword_7FF8571CC7D0]
    lea r10d, [r8-5DAA91D5h]
    lea ecx, [r8-51E512C5h]
    xor ecx, -56D23384h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r11d, [r8+rcx]
    add r11d, -51E512C5h
    mov esi, 7A3A32BCh
    sub esi, r11d
    xor esi, r10d
    add ecx, r8d
    add ecx, esi
    mov r8d, r9d
    shr r8d, cl
    xor r8d, r9d
    mov ecx, dword ptr [dword_7FF8571CC7D4]
    mov r10d, ecx
    not r10d
    mov r9d, r10d
    and r9d, 1B605860h
    lea r11d, [r9+r9*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r10d, 649FA79Fh
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
    mov r9d, ecx
    and r9d, -1B605861h
    lea esi, [r9+r9*2]
    mov edi, r9d
    not edi
    add edi, edi
    mov r9d, ecx
    and r9d, 1B605860h
    mov ebx, r9d
    not ebx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    sub r9d, esi
    lea r9d, [r9+rbx*4]
    sub r9d, edi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r9d, r10d
    sub r9d, r11d
    lea r10d, [r9+27201DE0h]
    lea r11d, [r9-2E1CD2ABh]
    lea edi, [r9-39936927h]
    mov r15d, edi
    xor r15d, 34756537h
    mov r14d, edi
    xor r14d, 30A8008h
    mov ebx, edi
    xor ebx, 18B55BE3h
    mov esi, r15d
    add r9d, r15d
    add r9d, -4F81BF8Ah
    mov ebp, r15d
    and ebp, 133FC12Bh
    shl ebp, 3
    and esi, 2CC03ED4h
    add esi, esi
    sub ebp, esi
    lea esi, [rbx*8]
    sub ebx, esi
    mov esi, edi
    xor esi, 8801AC0h
    and esi, 0CC03ED4h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r14d, 133FC12Bh
    shl r14d, 2
    xor edi, 274AA41Ch
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add ebx, ebp
    lea edi, [rbx+rdi*4]
    sub edi, r14d
    lea esi, [rdi+rsi*8]
    xor r9d, r10d
    xor r9d, r11d
    xor r9d, esi
    add r9d, ecx
    imul r9d, r8d
    mov r8d, dword ptr [dword_7FF8571CC7D8]
    lea ecx, [r8-613E82C6h]
    lea r10d, [r8-436B1D0Eh]
    xor ecx, 30516A97h
    sub ecx, r8d
    sub ecx, r8d
    add ecx, -5F8DF14h
    mov r8d, r10d
    not r8d
    mov r11d, ecx
    or r11d, r8d
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
    mov esi, ecx
    or esi, r10d
    add esi, esi
    mov edi, ecx
    xor edi, r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r8d, ecx
    shl r8d, 2
    and ecx, r10d
    lea ecx, [r8+rcx*2]
    sub ecx, edi
    sub ecx, esi
    lea ecx, [rcx+r11*4]
    mov r8d, r9d
    shr r8d, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r8d, r9d
    mov ecx, dword ptr [dword_7FF8571CC7DC]
    lea r9d, [rcx+25273DC8h]
    lea r10d, [rcx+675A14E2h]
    xor r10d, 2C01E35Ah
    lea r11d, [r10+rcx]
    add r11d, 47D4C6A3h
    mov r10d, r9d
    not r10d
    mov ecx, r11d
    or ecx, r10d
    not ecx
    lea esi, [rcx+rcx*4]
    lea ecx, [rcx+rsi*4]
    mov esi, r11d
    or esi, r9d
    lea edi, [rsi+rsi*4]
    lea edi, [rsi+rdi*2]
    not esi
    lea ebx, [rsi+rsi*4]
    lea esi, [rsi+rbx*2]
    and r9d, r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ebx, [r9+r9*8]
    not r9d
    lea r14d, [r9+r9*4]
    lea r9d, [r9+r14*2]
    and r10d, r11d
    lea r11d, [r10+r10*4]
    lea r10d, [r10+r11*4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add ebx, r10d
    sub edi, ebx
    add edi, r9d
    sub edi, esi
    sub edi, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    imul edi, r8d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, edi
    shr r8d, 10h
    xor r8d, edi
    mov ecx, dword ptr [dword_7FF8571CC7E0]
    lea r10d, [rcx+4B88DF31h]
    mov r9d, r10d
    xor r9d, 7C519544h
    mov r11d, r9d
    mov r13d, r9d
    mov edi, -5BCDD42Bh
    sub edi, r9d
    or r9d, -233A97B0h
    lea esi, [r9+r9*4]
    lea esi, [r9+rsi*2]
    not r9d
    lea ebx, [r9*8]
    sub ebx, r9d
    mov r9d, r10d
    xor r9d, -7F7B97F0h
    and r9d, -233A97B0h
    mov ebp, r9d
    shl ebp, 4
    add ebp, r9d
    and r11d, -233A97B0h
    and r13d, 233A97AFh
    lea r9d, [r13+r13*8+0]
    lea r9d, [r13+r9*2+0]
    lea r14d, [r11+r11*2]
    lea r14d, [r9+r14*4]
    mov r9d, dword ptr [rsp+460h]
    sub r14d, esi
    mov r13d, r10d
    xor r13d, -14F531C8h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add r11d, r11d
    lea r11d, [r11+r11*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r14d, r11d
    add r14d, ebp
    lea r11d, [rbx+r14]
    add r11d, 59835E38h
    mov esi, r14d
    add esi, ebx
    mov ebx, r11d
    or ebx, -6729419Dh
    lea r14d, [rbx+rbx*4]
    lea ebx, [rbx+r14*2]
    mov ebp, r11d
    xor edi, r10d
    sub edi, ecx
    mov ecx, r11d
    xor edi, esi
    mov esi, r11d
    xor edi, r11d
    not r11d
    and r11d, 18D6BE63h
    add r11d, r11d
    lea r11d, [r11+r11*4]
    xor ebp, 18D6BE63h
    add ebp, ebp
    and ecx, 729419Ch
    shl ecx, 3
    and esi, -6729419Dh
    imul esi, 0F5h
    sub esi, ecx
    sub esi, ebp
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add esi, ebx
    sub esi, r11d
    xor edi, esi
    xor r10d, 14F531C7h
    mov r11d, edi
    or r11d, r10d
    not r11d
    shl r11d, 2
    lea esi, [r13*2]
    mov ecx, edi
    or ecx, r13d
    lea ecx, [rcx+rcx*4]
    and r10d, edi
    and edi, r13d
    lea edi, [rdi+rdi*2]
    lea r10d, [rdi+r10*4]
    sub ecx, r10d
    sub ecx, esi
    sub ecx, r11d
    mov r10, r9
    shl r10, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or r8, r10
    mov r11d, dword ptr [dword_7FF8571CC7E8]
    lea r10d, [r11+3034EF74h]
    xor r10d, -62C63971h
    lea ecx, [r10+1196DC4Fh]
    mov esi, ecx
    or esi, -3FD070CBh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edi, ecx
    xor edi, 3FD070CAh
    lea ebx, [rdi+rdi*2]
    mov ebp, ecx
    and ebp, -3FD070CBh
    mov edi, ecx
    and edi, 3FD070CAh
    sub edi, ebp
    add edi, ebx
    sub edi, esi
    not esi
    shl esi, 2
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ebx, ecx
    not ebx
    and ebx, -3FD070CBh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add edi, ebx
    sub edi, esi
    lea esi, [rdi-39C50660h]
    mov ebx, esi
    not ebx
    mov ebp, ebx
    and ebp, 0EFh
    and ebx, 10h
    lea r14d, 0FFFFFFFF8C75F340h[rdi*2]
    and esi, 17F6EFh
    add esi, esi
    sub r14d, esi
    add r14d, ebx
    sub ebp, r14d
    xor ecx, r11d
    xor ecx, 5Dh
    add ecx, r10d
    sub ecx, edi
    add ecx, edi
    add ecx, -39C50660h
    add ecx, ebp
    add cl, 10h
    shr r9, cl
    xor r9, r8
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, -0AE502812AA7333h
    imul r9, rcx
    mov r8d, dword ptr [dword_7FF8571CC7F0]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ecx, [r8+7C1E3E42h]
    mov r10d, ecx
    xor r10d, 6CDECE25h
    lea r11d, [r10-6B2C4C50h]
    mov esi, -3D982ED9h
    sub esi, r8d
    mov edi, r11d
    not edi
    mov ebx, esi
    or ebx, edi
    not ebx
    lea r14d, [rbx+rbx*4]
    lea ebx, [rbx+r14*2]
    mov r14d, esi
    or r14d, r11d
    lea r15d, [r14+r14*4]
    lea ebp, [r14+r15*2]
    mov r14d, esi
    xor r14d, r11d
    and edi, esi
    lea edi, [rdi+rdi*8]
    and esi, r11d
    imul r11d, esi, 0F5h
    sub r11d, edi
    sub r11d, r14d
    add r11d, ebp
    sub r11d, ebx
    sub r11d, r10d
    xor ecx, r8d
    xor ecx, r11d
    mov r10, r9
    shr r10, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r10, r9
    mov r11, qword ptr [qword_7FF8571CC7F8]
    mov r9, r11
    mov rcx, 3C47ED5902415568h
    xor r9, rcx
    mov rcx, -397D6902BAC7FAFEh
    add rcx, r9
    mov rsi, rcx
    mov r8, -4EC57F0D5D28EBA6h
    xor rsi, r8
    mov r8, 21CC86753EFDB795h
    add r8, rsi
    mov rdi, r8
    not rdi
    mov rbx, rdi
    mov r13, -6353FA2A3FBEA8A2h
    and rbx, r13
    lea r14, [rbx+rbx*4]
    lea rbx, [rbx+r14*2]
    mov r14, r8
    or r14, r13
    mov r15, r8
    mov rbp, 6353FA2A3FBEA8A1h
    and r15, rbp
    add r15, r14
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r8, r13
    imul r14, r8, 0F5h
    add r14, r15
    sub r14, rbx
    add r14, rdi
    mov r8, 67847167E941E8D8h
    sub r8, rsi
    xor r8, r11
    sub r8, r14
    add r8, rsi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov r9, 412CB8271B59B3CDh
    add r8, r9
    xor r8, rcx
    imul r8, r10
    mov ecx, dword ptr [dword_7FF8571CC800]
    mov r9d, ecx
    not r9d
    lea r10d, [r9*8]
    sub r10d, r9d
    mov r11d, r9d
    and r11d, 3303C966h
    lea r11d, [r11+r11*8]
    and r9d, 4CFC3699h
    add r9d, r9d
    lea r9d, [r9+r9*4]
    mov esi, ecx
    and esi, 3303C966h
    mov edi, esi
    not edi
    lea edi, [rdi+rdi*2]
    mov ebx, ecx
    and ebx, 4CFC3699h
    add ebx, ebx
    add esi, esi
    sub esi, ebx
    add esi, edi
    sub esi, r9d
    sub esi, r11d
    lea r9d, [rsi+r10]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea edi, [rsi+r10]
    add edi, 70BF4D34h
    mov r10d, edi
    xor r10d, 7E7A4B55h
    mov r11d, edi
    xor r11d, -7E7A4B56h
    mov esi, r11d
    and esi, -79B66BCEh
    lea esi, [rsi+rsi*2]
    mov ebx, r11d
    and ebx, 39B66BCDh
    shl ebx, 2
    or r11d, -79B66BCEh
    add r10d, r10d
    sub r11d, r10d
    sub r11d, ebx
    sub r11d, esi
    lea r10d, [r11-3]
    xor edi, ecx
    xor edi, -140C8ED8h
    mov ecx, r9d
    not ecx
    mov esi, edi
    or esi, ecx
    mov ebx, edi
    or ebx, r9d
    lea r14d, [rbx+rbx*4]
    lea ebx, [rbx+r14*2]
    mov ebp, edi
    and ecx, edi
    shl ecx, 3
    and edi, r9d
    imul edi, 0F5h
    sub edi, ecx
    mov ecx, r10d
    xor ecx, 5C131150h
    not esi
    add esi, esi
    lea esi, [rsi+rsi*4]
    xor ebp, r9d
    add ebp, ebp
    sub edi, ebp
    add edi, ebx
    sub edi, esi
    add edi, r11d
    add edi, -3
    xor r10d, -5C131151h
    mov r11d, edi
    or r11d, r10d
    not r11d
    mov esi, edi
    or esi, ecx
    not esi
    shl esi, 2
    mov ebx, edi
    xor ebx, ecx
    mov r14d, ebx
    not r14d
    and r10d, edi
    shl r10d, 3
    and edi, ecx
    add edi, edi
    sub r10d, edi
    lea edi, [rbx*8]
    sub ebx, edi
    add ebx, r10d
    lea r10d, [rbx+r14*4]
    sub r10d, esi
    lea r10d, [r10+r11*8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add ecx, r9d
    add ecx, r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add cl, 2Eh
    mov r9, r8
    shr r9, cl
    xor r9d, r8d
    mov rcx, qword ptr [rsp+388h]
    add rcx, qword ptr [rsp+380h]
    mov r8, -1
    cmovb rcx, r8
    loc_7FF85682106D:
    mov r8, qword ptr [qword_7FF8571CC808]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r10, -4400E0AB26B2538Dh
    add r10, r8
    sub r8, r10
    mov r11, 82BCF5675E540C8h
    xor r10, r11
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8, r10
    mov r10, -70474980A84C0EDDh
    add r8, r10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp rcx, r8
    mov r8d, 0
    cmovz rcx, r8
    loc_7FF8568211BE:
    mov r10, qword ptr [qword_7FF8571CC810]
    mov r11, r10
    not r11
    mov rsi, r11
    mov r14, 7AAB0DA63B329E28h
    and rsi, r14
    mov rbx, 554F259C4CD61D7h
    and r11, rbx
    add r11, r11
    mov r8, r10
    xor r8, rbx
    mov rdi, r10
    and rdi, rbx
    mov rbx, r10
    and rbx, r14
    lea rdi, [rbx+rdi*2]
    sub rdi, r10
    lea r8, [rdi+r8*2]
    sub r8, r11
    add r8, rsi
    mov r11, 60554AED25F9D089h
    lea rbx, [r8+r11]
    mov r11, 732EB7B53B282482h
    add r10, r11
    mov rdi, rbx
    not rdi
    mov r11, r10
    or r11, rdi
    mov rsi, r10
    or rsi, rbx
    mov r14, r10
    xor r14, rbx
    and rdi, r10
    and r10, rbx
    mov rbx, r14
    shl rdi, 3
    add r10, r10
    sub rdi, r10
    lea r10, [r14*8]
    sub r14, r10
    add r14, rdi
    mov r10, -3BB8389A600EC83Fh
    add r10, r8
    not r11
    not rsi
    shl rsi, 2
    not rbx
    lea rdi, [r14+rbx*4]
    sub rdi, rsi
    lea r11, [rdi+r11*8]
    sub r11, r8
    mov rsi, -4B18F23F49251481h
    add r11, rsi
    mov rsi, r10
    not rsi
    mov rdi, r11
    or rdi, rsi
    mov rbx, r11
    and rsi, r11
    and r11, r10
    lea r11, [r11+r11*2]
    lea r11, [r11+rsi*4]
    or rbx, r10
    lea rsi, [rbx+rbx*4]
    sub rsi, r11
    add r10, r10
    sub rsi, r10
    not rdi
    shl rdi, 2
    sub rsi, rdi
    mov r10, qword ptr [rsp+388h]
    mov r11, 7A3AFB8868D20AB1h
    add r8, r11
    add r8, rsi
    mov r11, qword ptr [rsp+50h]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp r10, r8
    jnz loc_7FF856821378
    mov dword ptr [rsp+0C8h], r9d
    lea r13, eidolon_sbox
    jmp loc_7FF856825DC0
    loc_7FF856821378:
    mov r8d, dword ptr [rsp+20Ch]
    mov esi, dword ptr [rsp+204h]
    add r11, qword ptr [rsp+0D8h]
    mov dword ptr [rsp+1D0h], esi
    mov dword ptr [rsp+1D4h], edx
    mov qword ptr [rsp+5E8h], rax
    mov dword ptr [rsp+1D8h], r8d
    mov dword ptr [rsp+1DCh], r9d
    mov qword ptr [rsp+5F0h], rcx
    mov qword ptr [rsp+5F8h], r11
    mov qword ptr [rsp+600h], r10
    lea r13, eidolon_sbox
    loc_7FF8568213D4:
    mov rax, qword ptr [rsp+600h]
    mov rcx, qword ptr [rsp+5F8h]
    mov rdx, qword ptr [rsp+5F0h]
    mov r8d, dword ptr [rsp+1DCh]
    mov r9d, dword ptr [rsp+1D8h]
    mov r10, qword ptr [rsp+5E8h]
    mov r11d, dword ptr [rsp+1D4h]
    mov qword ptr [rsp+388h], rax
    mov eax, dword ptr [rsp+1D0h]
    mov qword ptr [rsp+0D8h], rcx
    mov qword ptr [rsp+380h], rdx
    mov dword ptr [rsp+460h], r8d
    mov dword ptr [rsp+8Ch], r9d
    mov qword ptr [rsp+508h], r10
    mov dword ptr [rsp+110h], r11d
    mov dword ptr [rsp+88h], eax
    mov rax, qword ptr [qword_7FF8571CC758]
    mov rdx, rax
    not rdx
    mov r8, rax
    mov r11, 16FC090A080CB4C3h
    or r8, r11
    mov rcx, rax
    mov rsi, -16FC090A080CB4C4h
    xor rcx, rsi
    lea r9, [rcx+rcx*2]
    mov r10, rax
    and r10, r11
    mov rcx, rax
    and rcx, rsi
    sub rcx, r10
    add rcx, r9
    sub rcx, r8
    not r8
    shl r8, 2
    and rdx, r11
    add rcx, rdx
    sub rcx, r8
    mov rdx, 95FCE64218E1209h
    lea r8, [rcx+rdx]
    mov rdx, r8
    mov r9, r8
    mov rsi, -38D1D62BF726C730h
    or r9, rsi
    lea r10, [r9+r9*4]
    lea r9, [r9+r10*2]
    mov r10, r8
    mov r11, r8
    mov rdi, 18D1D62BF726C72Fh
    and r11, rdi
    shl r11, 3
    and r8, rsi
    imul r8, 0F5h
    sub r8, r11
    mov r11, 472E29D408D938D0h
    xor r10, r11
    add r10, r10
    sub r8, r10
    add r8, r9
    not rdx
    and rdx, r11
    add rdx, rdx
    lea rdx, [rdx+rdx*4]
    sub r8, rdx
    mov rdx, 141884EC17E8B3D7h
    add rdx, rcx
    mov r9, -1F2B8142EC4B53B6h
    xor rax, r9
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rax, r8
    sub rax, rcx
    mov rdx, -572D81FD32A3A3CBh
    add rax, rdx
    xor rax, rcx
    sub rax, rcx
    mov rcx, 3700094616C92654h
    add rax, rcx
    xor rax, qword ptr [rsp+380h]
    mov rcx, qword ptr [rsp+388h]
    cmp rcx, rax
    cmovb rax, rcx
    loc_7FF8568216F6:
    mov qword ptr [rsp+50h], rax
    mov eax, dword ptr [dword_7FF85723A9E8]
    lea ecx, [rax-66954453h]
    mov edx, ecx
    xor edx, -642744BAh
    xor eax, edx
    xor eax, 46032D36h
    sub eax, edx
    add eax, 4F95A9D0h
    loc_7FF85682171D:
    xor eax, ecx
    mov dword ptr [rsp+3Ch], eax
    jmp loc_7FF856813884
    loc_7FF856821728:
    mov rax, qword ptr [rsp+868h]
    movzx ecx, byte ptr [rsp+47h]
    xor cl, byte ptr [rax+r13]
    mov rax, qword ptr [rsp+358h]
    mov byte ptr [rax], cl
    mov rax, qword ptr [qword_7FF8571CC878]
    mov rcx, rax
    not rcx
    mov rdx, 0AF35F3EC3C04C7Dh
    and rcx, rdx
    lea rdx, [rax+rax]
    mov r8, -6A194182787F6706h
    or rdx, r8
    mov r8, rax
    mov r9, 350CA0C13C3FB382h
    and r8, r9
    shl r8, 2
    mov r9, rax
    mov r10, 4AF35F3EC3C04C7Dh
    and r9, r10
    lea r8, [r8+r9*2]
    mov r9, rax
    xor r9, r10
    sub r8, r9
    sub r8, rdx
    lea rcx, [r8+rcx*4]
    mov r8, rcx
    mov rdx, 11DE23DE94D6BFE3h
    xor r8, rdx
    mov rdx, r8
    mov r11, -518C0303AC82564Bh
    and r8, r11
    mov r9, r8
    not r9
    add r9, r9
    sub r9, r8
    mov r8, rcx
    mov r10, 2E21DC2043290014h
    xor r8, r10
    mov r10, 2E73FCFC537DA9B5h
    and r8, r10
    shl r8, 2
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
    mov qword ptr [rsp+870h], rcx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or rdx, r11
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, 5CE7F9F8A6FB536Bh
    add rdx, r8
    add rdx, r9
    mov r8, rdx
    mov r9, 2A4110D5D912AD2Eh
    xor r8, r9
    mov qword ptr [rsp+400h], r8
    mov r8, 627CE407EF7768C3h
    xor rcx, r8
    add rcx, rdx
    mov r8, -68131AF1E58203A8h
    xor rdx, r8
    xor rdx, rcx
    sub rdx, rax
    mov qword ptr [rsp+408h], rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov rcx, rax
    not rcx
    mov rdx, qword ptr [rsp+408h]
    or rcx, rdx
    not rcx
    mov qword ptr [rsp+878h], rcx
    or rdx, rax
    not rdx
    mov qword ptr [rsp+880h], rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, qword ptr [rsp+408h]
    xor rax, qword ptr [rsp+400h]
    not rax
    mov qword ptr [rsp+888h], rax
    mov eax, dword ptr [dword_7FF85723AB10]
    mov ecx, eax
    xor ecx, -4F14F26Ch
    sub ecx, eax
    xor eax, 132BAE25h
    add eax, -21C47EADh
    add ecx, 4B158951h
    jmp loc_7FF856825DF5
    loc_7FF856821A81:
    mov eax, dword ptr [dword_7FF85723AA10]
    mov ecx, eax
    xor ecx, 6D7CEh
    sub eax, ecx
    add eax, 5C85D9AFh
    jmp loc_7FF856813873
    loc_7FF856821A9B:
    movzx eax, byte ptr [rsp+45h]
    mov byte ptr [rsp+43h], al
    mov dword ptr [rsp+260h], 0
    loc_7FF856821AAF:
    movzx ecx, byte ptr [rsp+43h]
    xor ecx, dword ptr [rsp+260h]
    imul eax, ecx, -3361D2AFh
    mov edx, dword ptr [dword_7FF8571CC700]
    lea r10d, [rdx+5056F68Eh]
    lea r11d, [rdx+70308268h]
    mov r9d, r10d
    not r9d
    mov r8d, r11d
    or r8d, r9d
    not r8d
    mov esi, r11d
    or esi, r10d
    not esi
    shl esi, 2
    mov edi, r11d
    xor edi, r10d
    mov ebx, edi
    not ebx
    lea ebp, [rdi*8]
    and r9d, r11d
    shl r9d, 3
    and r11d, r10d
    add r11d, r11d
    sub r9d, r11d
    sub edi, ebp
    add edi, r9d
    lea r9d, [rdi+rbx*4]
    sub r9d, esi
    lea r8d, [r9+r8*8]
    add edx, r8d
    add edx, -1F3C8331h
    imul edx, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [dword_7FF8571CC704]
    mov r9d, ecx
    or r9d, -1D25BC1Ah
    mov r10d, ecx
    or r10d, 1D25BC19h
    mov r8d, ecx
    xor r8d, -1D25BC1Ah
    lea r11d, [rcx+rcx]
    mov esi, ecx
    and esi, -1D25BC1Ah
    lea esi, [rsi+rsi*2]
    mov edi, ecx
    and edi, 1D25BC19h
    lea edi, [rdi+rdi*2]
    add edi, esi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub edi, r11d
    add r8d, r10d
    add r8d, edi
    sub r8d, r9d
    lea r9d, [r8-6D69D7CCh]
    mov r10d, r9d
    not r10d
    and r10d, 640225ADh
    lea r10d, [r10+r10*4]
    mov r11d, r9d
    or r11d, 640225ADh
    lea r11d, [r11+r11*2]
    mov esi, r9d
    and esi, 1BFDDA52h
    and r9d, 640225ADh
    lea r9d, [r9+r9*8]
    lea r9d, [r9+rsi*4]
    sub r9d, r11d
    lea r11d, [r9+r10*2]
    add ecx, r8d
    add ecx, -6D69D7CCh
    lea r9d, [r9+r10*2]
    add r9d, 14745369h
    add ecx, r8d
    add ecx, r11d
    sub ecx, r9d
    add ecx, -6FA8E9B5h
    xor ecx, r9d
    shr eax, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or eax, edx
    mov ecx, dword ptr [dword_7FF8571CC708]
    lea edx, [rcx-767DDF22h]
    lea r8d, [rcx-0C35178Ah]
    xor r8d, -78F76E74h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8d, ecx
    add r8d, ecx
    add r8d, 2D256C77h
    mov r9d, r8d
    or r9d, edx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9d, r9d
    mov ecx, r8d
    and ecx, edx
    not ecx
    add ecx, ecx
    xor r8d, edx
    sub ecx, r8d
    sub ecx, r9d
    imul ecx, eax
    mov eax, dword ptr [rsp+138h]
    mov edx, eax
    not edx
    mov r8d, ecx
    or r8d, edx
    not r8d
    lea r8d, [r8+r8*4]
    lea r9d, [rax+rax]
    lea r9d, [r9+r9*2]
    mov r10d, ecx
    or r10d, eax
    lea r10d, [r10+r10*2]
    and edx, ecx
    and ecx, eax
    lea eax, [rcx+rcx*8]
    lea eax, [rax+rdx*4]
    sub eax, r10d
    sub eax, r9d
    lea eax, [rax+r8*2]
    mov dword ptr [rsp+264h], eax
    mov dword ptr [rsp+268h], eax
    mov dword ptr [rsp+26Ch], eax
    loc_7FF856821E21:
    mov eax, dword ptr [rsp+26Ch]
    mov ecx, dword ptr [rsp+268h]
    mov edx, dword ptr [rsp+264h]
    mov r8d, dword ptr [dword_7FF8571CC70C]
    mov r9d, r8d
    not r9d
    and r9d, 2346C54Bh
    shl r9d, 2
    mov r10d, r8d
    or r10d, -5CB93AB5h
    lea r10d, [r10+r10*4]
    mov r11d, r8d
    and r11d, 1CB93AB4h
    mov esi, r8d
    and esi, -5CB93AB5h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea esi, [rsi+rsi*2]
    lea r11d, [rsi+r11*4]
    sub r10d, r11d
    sub r10d, r9d
    lea r9d, [r10-468D8A96h]
    lea r11d, [r10+3ED3BC8Eh]
    mov esi, r11d
    not esi
    mov edi, r11d
    or edi, 0BA91091h
    and esi, 0BA91091h
    lea esi, [rsi+rsi*2]
    mov ebx, r11d
    and ebx, 0BA91091h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ebx, [rbx+rbx*2]
    and r11d, -0BA91092h
    sub ebx, r11d
    lea r11d, [rbx+r10]
    add r11d, 3ED3BC8Eh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r11d, esi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea esi, [rdi+r11]
    add esi, 77A6012Fh
    lea r11d, [rsi+rsi]
    mov edi, esi
    xor r9d, esi
    not esi
    mov ebx, esi
    and ebx, -257CB7D3h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and esi, 257CB7D2h
    and edi, 5A83482Dh
    add edi, edi
    sub r11d, edi
    add r11d, esi
    mov esi, 32DD205Dh
    sub esi, r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor esi, r8d
    sub ebx, r11d
    lea r8d, [rsi+rbx]
    add r8d, 257CB7D2h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r9d, r8d
    add r9d, dword ptr [rsp+13Ch]
    mov r8d, dword ptr [dword_7FF8571CC710]
    lea r10d, [r8+2147ECD3h]
    lea r11d, [r8+0D926AB6h]
    mov esi, r11d
    xor esi, -151F9D6Dh
    xor r11d, -25B83DA7h
    add r11d, esi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor r10d, r8d
    xor r10d, r11d
    and r10d, r9d
    mov r8, qword ptr [rsp+520h]
    add r8, qword ptr [rsp+78h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov dword ptr [rsp+270h], edx
    mov dword ptr [rsp+274h], ecx
    mov dword ptr [rsp+278h], eax
    mov qword ptr [rsp+678h], r8
    mov dword ptr [rsp+27Ch], r10d
    loc_7FF8568222DD:
    mov edx, dword ptr [rsp+27Ch]
    mov rcx, qword ptr [rsp+678h]
    mov eax, dword ptr [rsp+278h]
    mov r8d, dword ptr [rsp+274h]
    mov r9d, dword ptr [rsp+270h]
    mov dword ptr [rsp+14Ch], edx
    mov qword ptr [rsp+530h], rcx
    mov dword ptr [rsp+148h], r8d
    mov dword ptr [rsp+144h], r9d
    mov edx, eax
    or edx, ecx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and ecx, eax
    lea ecx, [rcx+r8*2]
    add ecx, r9d
    mov edx, -7
    sub edx, ecx
    mov ecx, edx
    shr ecx, 10h
    xor ecx, edx
    imul edx, ecx, -7A143595h
    mov r8d, dword ptr [dword_7FF8571CC730]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r11d, [r8+4581DA74h]
    lea r9d, [r8+5D29CBA0h]
    xor r9d, -29376144h
    lea r10d, [r9-13169B5Eh]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ecx, [r9+r8]
    add ecx, -13169B5Eh
    neg ecx
    lea esi, [r8+rcx]
    add esi, 5D29CBA0h
    add esi, 53FA1549h
    mov edi, esi
    mov ecx, esi
    or ecx, r11d
    lea ebx, [rsi+rsi]
    and esi, r11d
    not r11d
    or edi, r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add esi, esi
    sub ebx, esi
    add ecx, edi
    add ecx, ebx
    sub ecx, r11d
    inc ecx
    xor ecx, r9d
    sub ecx, r10d
    sub ecx, r8d
    add cl, 1Ah
    mov r8d, edx
    shr r8d, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    or ecx, edx
    lea r9d, [rcx+rcx*2]
    not ecx
    lea r10d, [rcx*8]
    sub r10d, ecx
    and r8d, edx
    lea edx, [r8+r9*2]
    add edx, r10d
    mov ecx, -7
    sub ecx, edx
    mov edx, dword ptr [dword_7FF8571CC734]
    lea r8d, [rdx-59ADF0BCh]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r9d, [rdx-0F617266h]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    or r11d, -4D50CDEDh
    and r10d, 32AF3213h
    lea r10d, [r10+r10*2]
    lea esi, [r9+r9*2]
    mov edi, r9d
    and edi, 32AF3213h
    shl edi, 2
    and r9d, 4D50CDECh
    lea r9d, [r9+r9*2]
    sub edi, r9d
    add edi, esi
    lea r9d, [rdi+r10*2]
    lea r10d, [r11+r9]
    add r10d, -301B2C71h
    lea esi, [r11+r9]
    add esi, -7DDBE821h
    add r9d, r11d
    xor esi, r8d
    xor esi, 4522A559h
    sub esi, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, r10d
    not r8d
    mov r11d, esi
    or r11d, r8d
    not r11d
    shl r11d, 2
    lea r9d, 0FFFFFFFF9FC9A71Eh[r9*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edx, esi
    or edx, r10d
    lea edx, [rdx+rdx*4]
    and r8d, esi
    and esi, r10d
    lea r10d, [rsi+rsi*2]
    lea r8d, [r10+r8*4]
    sub edx, r8d
    sub edx, r9d
    sub edx, r11d
    imul edx, ecx
    mov r9d, dword ptr [dword_7FF8571CC738]
    mov r8d, r9d
    xor r8d, -5D47F8BFh
    mov ecx, r9d
    xor ecx, 4C43D03Ah
    and ecx, -31942FC6h
    lea r10d, [rcx+rcx*4]
    lea r10d, [rcx+r10*4]
    mov r11d, r8d
    or r11d, -31942FC6h
    lea ecx, [r11+r11*4]
    lea ecx, [r11+rcx*2]
    not r11d
    lea esi, [r11+r11*4]
    lea r11d, [r11+rsi*2]
    mov esi, r8d
    and esi, -31942FC6h
    lea edi, [rsi+rsi*8]
    not esi
    lea ebx, [rsi+rsi*4]
    lea esi, [rsi+rbx*2]
    mov ebx, r8d
    and ebx, 31942FC5h
    lea r14d, [rbx+rbx*4]
    lea ebx, [rbx+r14*4]
    add edi, ebx
    sub ecx, edi
    add ecx, esi
    sub ecx, r11d
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
    xor r9d, ecx
    add ecx, 32C3AA09h
    xor ecx, r9d
    xor ecx, 58h
    sub ecx, r8d
    mov r9d, edx
    shr r9d, cl
    xor r9d, edx
    mov r8d, dword ptr [rsp+470h]
    mov rcx, r8
    shl rcx, 20h
    or r9, rcx
    shr r8d, 1
    xor r8, r9
    mov rcx, -0AE502812AA7333h
    imul r8, rcx
    mov edx, dword ptr [dword_7FF8571CC740]
    mov ecx, -214E7A32h
    sub ecx, edx
    mov r9d, edx
    not r9d
    mov r10d, ecx
    or r10d, r9d
    not r10d
    add r10d, r10d
    lea r10d, [r10+r10*4]
    mov r11d, ecx
    or r11d, edx
    lea esi, [r11+r11*4]
    lea r11d, [r11+rsi*2]
    mov esi, ecx
    xor esi, edx
    add esi, esi
    and r9d, ecx
    shl r9d, 3
    and ecx, edx
    imul ecx, 0F5h
    sub ecx, r9d
    sub ecx, esi
    add ecx, r11d
    sub ecx, r10d
    sub ecx, edx
    add cl, 3Eh
    mov rdx, r8
    shr rdx, cl
    xor rdx, r8
    mov rcx, -3B314601E57A13ADh
    imul rdx, rcx
    mov ecx, dword ptr [dword_7FF8571CC748]
    lea r8d, [rcx+6D1AC80Ch]
    mov r9d, r8d
    not r9d
    mov r10d, r9d
    or r10d, 7DDA76EAh
    mov r11d, r9d
    mov esi, r8d
    xor esi, 7DDA76EAh
    lea esi, [rsi+rsi*2]
    and r9d, 7DDA76EAh
    and r8d, 7DDA76EAh
    sub r8d, r9d
    add r8d, esi
    sub r8d, r10d
    not r10d
    shl r10d, 2
    and r11d, -7DDA76EBh
    add r8d, r11d
    sub r8d, r10d
    lea r9d, [rcx+r8]
    add r9d, 4053649Ch
    mov r8d, r9d
    or r8d, ecx
    not r8d
    lea r8d, [r8+r8*2]
    mov r10d, ecx
    not r10d
    mov r11d, r9d
    or r11d, r10d
    add r11d, r11d
    lea r11d, [r11+r11*2]
    mov esi, r9d
    xor esi, ecx
    and r10d, r9d
    lea r10d, [r10+r10*2]
    add r10d, r10d
    and r9d, ecx
    lea ecx, [r9+r9*2]
    lea ecx, [r10+rcx*2]
    add ecx, esi
    sub ecx, r11d
    lea ecx, [rcx+r8*2]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, edx
    not ecx
    mov r9d, r8d
    or r9d, ecx
    not r9d
    lea r10d, [r9+r9*4]
    lea r9d, [r9+r10*2]
    mov r10d, r8d
    or r10d, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r11d, [rdx+rdx*4]
    lea r11d, [rdx+r11*2]
    and ecx, r8d
    add ecx, r11d
    and edx, r8d
    imul edx, 0F5h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add ecx, r10d
    add ecx, edx
    sub ecx, r9d
    sub ecx, r8d
    mov dword ptr [rsp+150h], ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rsp+3B0h]
    add rcx, qword ptr [rsp+528h]
    mov rdx, -1
    cmovb rcx, rdx
    loc_7FF856822D1C:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp rcx, -1
    mov edx, 0
    cmovnz rdx, rcx
    loc_7FF856822D8B:
    mov qword ptr [rsp+538h], rdx
    mov rcx, qword ptr [rsp+3B0h]
    mov rdx, qword ptr [rsp+78h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    jz loc_7FF856822E99
    add rdx, qword ptr [rsp+0E0h]
    mov r8d, dword ptr [rsp+144h]
    mov r9d, dword ptr [rsp+148h]
    mov r10, qword ptr [rsp+530h]
    mov r11d, dword ptr [rsp+14Ch]
    mov esi, dword ptr [rsp+150h]
    mov rdi, qword ptr [rsp+538h]
    mov dword ptr [rsp+230h], r8d
    mov dword ptr [rsp+234h], r9d
    mov dword ptr [rsp+238h], eax
    mov qword ptr [rsp+650h], r10
    mov dword ptr [rsp+23Ch], r11d
    mov dword ptr [rsp+240h], esi
    mov qword ptr [rsp+658h], rdi
    mov qword ptr [rsp+660h], rdx
    mov qword ptr [rsp+668h], rcx
    jmp loc_7FF8568258EC
    loc_7FF856822E99:
    mov eax, dword ptr [dword_7FF85723AA54]
    mov ecx, eax
    xor ecx, 11E57F23h
    mov r8d, 44C8F4FCh
    sub r8d, ecx
    sub r8d, ecx
    xor r8d, eax
    lea eax, 38B2B19Eh[rcx*2]
    add ecx, 38B2B19Eh
    xor r8d, -246AD3F2h
    sub r8d, eax
    add r8d, -55391FA4h
    xor r8d, ecx
    mov dword ptr [rsp+3Ch], r8d
    jmp loc_7FF856813884
    loc_7FF856822EE1:
    mov eax, dword ptr [dword_7FF8571CC690]
    mov ecx, 310DC5C7h
    xor eax, ecx
    mov dword ptr [rsp+80h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+80h]
    mov ecx, -23E22625h
    add eax, ecx
    mov dword ptr [rsp+108h], eax
    mov ecx, eax
    not ecx
    mov edx, ecx
    and edx, 1FE1AE1Bh
    mov dword ptr [rsp+428h], edx
    and ecx, 201E51E4h
    shl ecx, 2
    mov dword ptr [rsp+42Ch], ecx
    and eax, -1FE1AE1Ch
    mov dword ptr [rsp+430h], eax
    mov eax, dword ptr [dword_7FF85723A9AC]
    lea ecx, [rax-5ED26F8Ch]
    mov edx, ecx
    xor edx, 3F5F34FDh
    lea r8d, [rdx-108E45D5h]
    mov r9d, r8d
    xor r9d, -2B6D66DDh
    sub r9d, ecx
    sub r9d, edx
    add r9d, 1B258330h
    xor r9d, r8d
    add r9d, eax
    xor r9d, edx
    mov dword ptr [rsp+3Ch], r9d
    jmp loc_7FF856813884
    loc_7FF856822FCB:
    mov rcx, qword ptr [rsp+50h]
    and rcx, -4
    add rcx, qword ptr [rsp+0D8h]
    mov qword ptr [rsp+390h], rcx
    mov ecx, dword ptr [rsp+120h]
    mov r8, rcx
    not r8
    mov rdx, rax
    or rdx, r8
    not rdx
    mov r9, rax
    or r9, rcx
    not r9
    shl r9, 2
    mov r10, rax
    xor r10, rcx
    mov r11, r10
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
    lea rsi, [r10*8]
    and r8, rax
    shl r8, 3
    mov edi, eax
    and edi, ecx
    add rdi, rdi
    sub r8, rdi
    sub r10, rsi
    add r10, r8
    lea r8, [r10+r11*4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    lea rdx, [r8+rdx*8]
    mov r8, qword ptr [rsp+390h]
    movzx r9d, byte ptr [r8]
    xor r9b, byte ptr [r13+rdx+0]
    mov byte ptr [rsp+44h], r9b
    mov byte ptr [r8], r9b
    mov r8, qword ptr [qword_7FF8571CC7B0]
    mov rdx, -3189050C3FF0A162h
    add rdx, r8
    mov r9, r8
    mov r10, 3D987376C5BA7176h
    xor r9, r10
    sub r9, rdx
    mov r10, 4EF4EDBA332EBA76h
    xor rdx, r10
    xor rdx, r9
    sub rdx, r8
    mov r8, qword ptr [qword_7FF8571CC7B8]
    mov r9, r8
    mov r10, r8
    mov r11, 20221C00009A01D0h
    xor r10, r11
    mov r11, 4F5DC0D6F405EE2Ah
    xor r8, r11
    mov r11, r8
    mov rdi, 2A321C54E49E43F8h
    or r11, rdi
    and r10, rdi
    lea r10, [r10+r10*2]
    mov rsi, r8
    and rsi, rdi
    shl rsi, 2
    mov rdi, r8
    mov rbx, -2A321C54E49E43F9h
    and rdi, rbx
    lea rdi, [rdi+rdi*2]
    sub rsi, rdi
    lea rdi, [r8+r8*2]
    add rsi, rdi
    lea r10, [rsi+r10*2]
    add r10, r11
    mov r11, 2D35602A44A6831h
    add r11, r10
    mov rsi, -17A65BAAF5687EA4h
    add r10, rsi
    mov rsi, r10
    mov rdi, 1A462AFB09DB5162h
    and rsi, rdi
    shl rsi, 2
    mov rdi, r10
    mov rbx, 25B9D504F624AE9Dh
    and rdi, rbx
    lea rdi, [rdi+rdi*2]
    sub rsi, rdi
    lea rdi, [r10+r10*2]
    add rsi, rdi
    mov rdi, r10
    not rdi
    mov rbx, 5A462AFB09DB5162h
    and rdi, rbx
    lea rdi, [rdi+rdi*2]
    lea rsi, [rsi+rdi*2]
    mov rdi, r10
    mov rbx, -25B9D504F624AE9Eh
    or rdi, rbx
    mov rbx, -1DA501E23B23E84Bh
    add rdi, rbx
    add rdi, rsi
    mov rsi, -3D65CD181784E49Bh
    xor r9, rsi
    add r10, r9
    mov r9, 7815CF0EAE012C74h
    add r10, r9
    add r10, rdi
    xor r10, r11
    sub r10, rdi
    xor r10, r8
    mov r8, -70EA8ECFF66B5901h
    add rdx, r8
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp rdx, r10
    jnz loc_7FF856827B63
    mov eax, dword ptr [dword_7FF85723AA08]
    lea ecx, [rax-18FB1C83h]
    xor ecx, 656B7233h
    add ecx, 34D226D6h
    xor ecx, eax
    add ecx, eax
    add eax, ecx
    add eax, 5415B7A2h
    jmp loc_7FF856813880
    loc_7FF8568233A0:
    mov eax, dword ptr [rsp+128h]
    mov ecx, dword ptr [rsp+12Ch]
    mov edx, dword ptr [rsp+0A0h]
    mov r8d, dword ptr [rsp+0A4h]
    mov dword ptr [rsp+24Ch], eax
    mov dword ptr [rsp+250h], ecx
    mov dword ptr [rsp+254h], edx
    mov dword ptr [rsp+258h], r8d
    loc_7FF8568233DA:
    mov eax, dword ptr [rsp+258h]
    mov ecx, dword ptr [rsp+254h]
    mov dword ptr [rsp+13Ch], eax
    mov dword ptr [rsp+138h], ecx
    mov rax, qword ptr [qword_7FF8571CC6C8]
    mov rcx, rax
    mov rdx, 22CD454966392927h
    xor rcx, rdx
    mov rdx, -7FCDCD90C43F1E11h
    lea r9, [rcx+rdx]
    mov rdx, 2F24F163967D5491h
    lea r8, [rcx+rdx]
    mov r10, r8
    mov rdx, 665E1A235B7D743Ah
    xor r10, rdx
    mov rdx, 7D36A069E5719084h
    xor r9, rdx
    mov rdx, -665E1A235B7D743Bh
    xor r8, rdx
    mov rdx, r9
    or rdx, r8
    mov r11, r9
    or r11, r10
    mov rsi, r9
    and rsi, r8
    xor r8, r9
    and r9, r10
    lea r10, [rsi+rsi*2]
    add r10, r10
    lea r9, [r10+r9*8]
    lea r10, [rdx+rdx*4]
    sub r9, r10
    not r11
    lea r8, [r8+r8*2]
    not rdx
    sub r9, r8
    lea r8, [r9+r11*8]
    mov r9, -20E03F7BD392528Eh
    add rdx, r9
    add rdx, r8
    mov r8, -22CD454966392928h
    xor rax, r8
    mov r8, rdx
    or r8, rax
    mov r9, rdx
    or r9, rcx
    mov r10, rdx
    and r10, rax
    xor rax, rdx
    and rdx, rcx
    lea rcx, [r10+r10*2]
    add rcx, rcx
    lea rcx, [rcx+rdx*8]
    lea rdx, [r8+r8*4]
    sub rcx, rdx
    lea rax, [rax+rax*2]
    sub rcx, rax
    not r9
    lea rdx, [rcx+r9*8]
    mov eax, dword ptr [rsp+250h]
    not r8
    add rdx, r8
    mov ecx, dword ptr [rsp+24Ch]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and rdx, qword ptr [rsp+78h]
    mov qword ptr [rsp+0E8h], rdx
    jz loc_7FF856825EB5
    mov rax, qword ptr [qword_7FF8571CC718]
    mov rcx, -1BCC50C897E97BA7h
    add rcx, rax
    mov rdx, 1F6B2B8413BC7B80h
    add rdx, rax
    mov r8, rdx
    mov r9, 36CA6E7399A83CBCh
    xor r8, r9
    mov r9, rdx
    mov r11, 16ED494AE06E8813h
    or r9, r11
    mov r10, rdx
    not r10
    and r10, r11
    and rdx, r11
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rdx, [rdx+r10*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rdx, r9
    sub rdx, r8
    mov r8, -2DDA9295C0DD1026h
    add rdx, r8
    mov r8, rcx
    not r8
    mov r9, rdx
    or r9, r8
    not r9
    lea r10, [r9+r9*4]
    lea r9, [r9+r10*2]
    mov r10, rdx
    or r10, rcx
    lea r11, [r10+r10*4]
    lea r10, [r10+r11*2]
    mov r11, rdx
    xor r11, rcx
    and r8, rdx
    lea r8, [r8+r8*8]
    and rdx, rcx
    imul rcx, rdx, 0F5h
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
    sub rcx, r11
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rcx, r9
    xor rcx, rax
    and rcx, qword ptr [rsp+78h]
    add rcx, qword ptr [rsp+0E0h]
    mov qword ptr [rsp+338h], rcx
    mov edx, dword ptr [rsp+13Ch]
    mov qword ptr [rsp+3B8h], rdx
    mov rcx, qword ptr [rsp+0E8h]
    mov rax, rcx
    or rcx, rdx
    not rdx
    or rax, rdx
    not rcx
    shl rcx, 2
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8, qword ptr [rsp+3B8h]
    not r8
    mov r9, qword ptr [rsp+0E8h]
    and r9, r8
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
    and r8, qword ptr [rsp+0E8h]
    add r9, r9
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r9, r8
    sub r9, rcx
    add r9, rax
    lea rax, [r9+rdx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rsp+338h]
    movzx edx, byte ptr [rcx]
    xor dl, byte ptr [rax+r13+1]
    mov byte ptr [rsp+45h], dl
    mov byte ptr [rcx], dl
    mov rax, qword ptr [rsp+0E8h]
    dec rax
    mov qword ptr [rsp+3C0h], rax
    jz loc_7FF856828DD8
    mov eax, dword ptr [dword_7FF85723A9EC]
    mov ecx, 2CAB9897h
    sub ecx, eax
    xor eax, 3C8630C1h
    xor ecx, eax
    add eax, ecx
    add eax, -8A6286Eh
    jmp loc_7FF856813880
    loc_7FF856823C0F:
    mov rax, qword ptr [rsp+8A0h]
    mov qword ptr [rsp+768h], rax
    mov eax, dword ptr [dword_7FF85723AB18]
    lea ecx, [rax-0F4119Fh]
    mov edx, ecx
    xor edx, -70FFEFD1h
    xor ecx, 2D2CDADEh
    sub edx, ecx
    add edx, 44DF7A81h
    xor ecx, eax
    xor ecx, edx
    xor ecx, -2219BBB7h
    mov dword ptr [rsp+3Ch], ecx
    jmp loc_7FF856813884
    loc_7FF856823C54:
    mov eax, dword ptr [rsp+430h]
    not eax
    add eax, eax
    mov ecx, dword ptr [rsp+108h]
    mov edx, -1FE1AE1Ch
    and ecx, edx
    sub eax, ecx
    sub eax, dword ptr [rsp+42Ch]
    sub eax, dword ptr [rsp+428h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add eax, -3FC35C38h
    mov ecx, eax
    xor ecx, -5BADF484h
    add eax, ecx
    add eax, -5D358F9Eh
    mov dword ptr [rsp+434h], eax
    mov ecx, dword ptr [rsp+80h]
    mov edx, eax
    mov r8d, eax
    or r8d, ecx
    and eax, ecx
    not ecx
    or edx, ecx
    not edx
    lea r9d, [rdx+rdx*4]
    lea edx, [rdx+r9*4]
    mov dword ptr [rsp+438h], edx
    lea edx, [r8+r8*4]
    lea edx, [r8+rdx*2]
    not r8d
    lea r9d, [r8+r8*4]
    lea r8d, [r8+r9*2]
    mov dword ptr [rsp+43Ch], r8d
    not eax
    lea r8d, [rax+rax*4]
    lea eax, [rax+r8*2]
    mov dword ptr [rsp+440h], eax
    mov dword ptr [rsp+444h], edx
    mov dword ptr [rsp+448h], ecx
    mov eax, dword ptr [dword_7FF85723A9C0]
    lea ecx, [rax-36EED1F0h]
    mov edx, ecx
    xor edx, -17837817h
    lea r8d, [rdx+6417770h]
    mov r9d, r8d
    xor r9d, -4416E3FBh
    mov r10d, -367A5416h
    sub r10d, r9d
    xor r10d, edx
    sub r10d, ecx
    add r10d, edx
    sub r10d, eax
    sub r10d, r8d
    lea eax, [r10+r9]
    add eax, -7A279E22h
    jmp loc_7FF856813880
    loc_7FF856823D94:
    mov ecx, dword ptr [dword_7FF8571CC9A0]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea eax, [rcx+66991310h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    xor edx, 605084C0h
    mov r10d, eax
    xor r10d, 1FAE6A37h
    mov r8d, r10d
    or r8d, 72D28EC1h
    and edx, 72D28EC1h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r11d, [r10+r10]
    mov r9d, r10d
    and r9d, 0D2D713Eh
    add r9d, r9d
    sub r11d, r9d
    add r11d, edx
    lea r9d, [r8+r11]
    add r9d, -72D28EC0h
    lea edx, [r8+r11]
    add edx, 3B1543EFh
    add r8d, r11d
    add r8d, -5E5EFF90h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r10d, 329077A8h
    xor r10d, edx
    mov r11d, r10d
    not r11d
    mov esi, r8d
    not esi
    mov edx, r10d
    or edx, esi
    not edx
    lea edx, [rdx+rdx*8]
    mov edi, r10d
    or edi, r8d
    not edi
    lea edi, [rdi+rdi*4]
    and esi, r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r10d, r8d
    lea ebx, [r10+r10*4]
    lea r10d, [r10+rbx*2]
    add r10d, esi
    not esi
    lea ebx, [rsi+rsi*4]
    lea esi, [rsi+rbx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r10d, esi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r10d, [r10+rdi*2]
    add edx, r11d
    add edx, r10d
    xor edx, r9d
    sub edx, ecx
    sub edx, r8d
    add edx, -77F64F37h
    mov ecx, eax
    not ecx
    mov r8d, edx
    or r8d, ecx
    not r8d
    lea r8d, [r8+r8*4]
    lea r9d, [rax+rax]
    lea r9d, [r9+r9*2]
    mov r10d, edx
    or r10d, eax
    lea r10d, [r10+r10*2]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and edx, eax
    lea eax, [rdx+rdx*8]
    lea eax, [rax+rcx*4]
    sub eax, r10d
    sub eax, r9d
    lea edx, [rax+r8*2]
    mov ecx, 31h
    mov r8d, 1Fh
    mov r9d, 43h
    call Eidolon_UpdateSharedStateIfSentinelMatches
    loc_7FF85682426A:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov byte ptr [r12+58h], 97h
    mov rcx, qword ptr [qword_7FF8571CC9A8]
    mov rax, 450A3EA612843630h
    lea r10, [rcx+rax]
    mov r8, r10
    mov rax, -4F3565D207830A33h
    xor r8, rax
    mov r9, r10
    mov rax, 4F3565D207830A32h
    xor r9, rax
    lea rax, [r9+r9*2]
    mov rdx, r9
    mov rsi, 56FBA32018B005A9h
    and rdx, rsi
    lea rdx, [rdx+rdx*2]
    mov r11, -56FBA32018B005AAh
    and r9, r11
    lea r11, [r9+r9*2]
    mov r9, -19CEC6F21F330F9Ch
    xor r10, r9
    lea r9, [r10*8]
    sub r9, r10
    add r9, r11
    mov r10, r8
    mov r11, -15663FE0129CAA4h
    xor rcx, r11
    xor rcx, r8
    mov r11, 29045CDFE74FFA56h
    and r8, r11
    add r8, r8
    lea r8, [r8+r8*2]
    and r10, rsi
    add r10, r10
    sub r10, r8
    add r10, r9
    sub r10, rdx
    sub r10, rax
    add rcx, r10
    xor rcx, qword ptr [r12+48h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r10, qword ptr [qword_7FF8571CC9B0]
    mov rax, 1F53CF212B84BF49h
    add r10, rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov rax, -17C4656102496181h
    xor r8, rax
    mov rax, -2F91F24AB03A6459h
    add rax, r8
    mov rdx, rax
    mov r9, 3B7FC5D7F6B87E79h
    xor rdx, r9
    mov r11, r10
    not r11
    mov r9, r10
    mov rdi, 487AE6D19102172Ah
    and r9, rdi
    lea r9, [r9+r9*8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rsi, r11
    and rsi, rdi
    lea rsi, [rsi+rsi*4]
    mov rdi, -487AE6D19102172Bh
    and r11, rdi
    and r10, rdi
    lea rdi, [r10+r10*4]
    lea r10, [r10+rdi*2]
    add r10, r11
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
    lea rdi, [r11+r11*4]
    lea r11, [r11+rdi*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r10, r11
    lea r10, [r10+rsi*2]
    add r10, r9
    sub r10, r8
    mov r8, -1C465163E98A02B3h
    add r10, r8
    mov r8, rax
    mov r9, -3B7FC5D7F6B87E7Ah
    xor r8, r9
    mov r9, r10
    or r9, r8
    not r9
    mov r11, r10
    or r11, rdx
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
    and rdx, r10
    and r8, r10
    add r8, r8
    lea r8, [r8+rdx*2]
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
    add rdx, r11
    add rdx, r8
    lea rdx, [rdx+r9*2]
    add rdx, 2
    xor rdx, rax
    mov eax, dword ptr [dword_7FF8571CC9B8]
    mov r8d, eax
    xor r8d, 8000C40h
    mov r10d, eax
    xor r10d, 26AAD1BEh
    mov r9d, r10d
    or r9d, -55777326h
    and r8d, 0A888CDAh
    mov r11d, eax
    xor r11d, -73DDA29Ch
    lea r11d, [r11+r11*2]
    lea esi, [r9+r9*4]
    not r9d
    mov edi, r10d
    and edi, 2A888CDAh
    lea edi, [rdi+rdi*2]
    add edi, edi
    mov ebx, r10d
    and ebx, 15777325h
    lea edi, [rdi+rbx*8]
    sub edi, esi
    sub edi, r11d
    lea r8d, [rdi+r8*8]
    add r8d, r9d
    xor r8d, 3967F52Eh
    lea r9d, [r8+5B477A25h]
    mov r11d, r9d
    mov esi, r9d
    mov edi, r9d
    mov ebx, r9d
    and ebx, 43B2C1C3h
    and r9d, -43B2C1C4h
    sub r9d, ebx
    add r10d, r8d
    add r10d, -194BE569h
    xor r10d, eax
    not r11d
    or esi, 43B2C1C3h
    xor edi, -43B2C1C4h
    lea edi, [rdi+rdi*2]
    add r9d, edi
    sub r9d, esi
    not esi
    shl esi, 2
    and r11d, 43B2C1C3h
    add r9d, r11d
    sub r9d, esi
    xor r10d, -287669A6h
    add r10d, r8d
    mov r11d, r9d
    not r11d
    mov esi, r10d
    or esi, r11d
    mov edi, r10d
    or edi, r9d
    and r9d, r10d
    and r11d, r10d
    not esi
    not edi
    add r11d, r11d
    lea r10d, [r11+r9*2]
    not r9d
    add r9d, edi
    add r9d, r10d
    lea r9d, [r9+rsi*2]
    sub r9d, r8d
    add r9d, -2AF60F47h
    mov r8d, eax
    not r8d
    mov r10d, r9d
    or r10d, r8d
    not r10d
    lea r11d, [r10+r10*4]
    lea r10d, [r10+r11*2]
    mov r11d, r9d
    or r11d, eax
    lea esi, [r11+r11*4]
    lea r11d, [r11+rsi*2]
    mov esi, r9d
    xor esi, eax
    and r8d, r9d
    and r9d, eax
    lea eax, [r8+r8*8]
    imul r8d, r9d, 0F5h
    sub r8d, eax
    sub r8d, esi
    add r8d, r11d
    sub r8d, r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r9, [rsp+60h]
    call qword ptr [VirtualProtect]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    jz loc_7FF856825EF9
    mov eax, dword ptr [dword_7FF85723AA90]
    mov ecx, eax
    xor ecx, -5D60F29Ah
    mov edx, eax
    xor edx, 63839F9Ch
    sub edx, ecx
    add eax, edx
    add eax, -1548E17Ah
    jmp loc_7FF856813880
    loc_7FF856824D14:
    mov eax, dword ptr [rsp+74h]
    mov qword ptr [rsp+5C8h], rax
    mov rcx, qword ptr [qword_7FF8571CC880]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, 2763454F1AA1255Fh
    add rax, rcx
    mov rdx, 250DDDD36F47BC1Dh
    lea r8, [rcx+rdx]
    mov rdx, r8
    mov r9, -75E7DD2F1ACDCC44h
    xor rdx, r9
    mov r9, r8
    not r9
    lea r10, [r9+r9*2]
    mov r11, r9
    mov rdi, 73BD336FF5460654h
    or r11, rdi
    mov rsi, r9
    mov rbx, -73BD336FF5460655h
    and rsi, rbx
    lea rsi, [rsi+rsi*2]
    add rsi, r11
    and r9, rdi
    lea r9, [r9+r9*2]
    and r8, rdi
    sub r9, r8
    add r9, rsi
    sub r9, r10
    mov r8, -4C4BFFB415D271C9h
    add r8, rdx
    add r9, r8
    xor rax, rcx
    xor rax, r9
    add rax, rdx
    add rax, qword ptr [rsp+5C8h]
    mov qword ptr [rsp+898h], rax
    mov rax, qword ptr [rsp+890h]
    mov qword ptr [rsp+768h], rax
    loc_7FF856824E40:
    mov rax, qword ptr [rsp+768h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rcx, qword ptr [rsp+48h]
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
    mov rdx, qword ptr [rsp+100h]
    mov r8, qword ptr [rsp+5C8h]
    add r8, rax
    movzx r8d, byte ptr [r13+r8+0]
    xor byte ptr [rdx+rcx], r8b
    mov rcx, qword ptr [rsp+48h]
    sub rcx, rax
    mov rdx, qword ptr [rsp+100h]
    mov r8, qword ptr [rsp+898h]
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
    movzx r8d, byte ptr [r13+r8+0]
    xor byte ptr [rcx+rdx+1], r8b
    add rax, -2
    mov qword ptr [rsp+8A0h], rax
    jz loc_7FF856824FF2
    mov eax, dword ptr [dword_7FF85723AA9C]
    mov ecx, 16095D5Fh
    xor eax, ecx
    lea ecx, [rax+199B1D5h]
    lea edx, [rax+2023268Ch]
    xor edx, 36749FBAh
    mov r8d, 2F543798h
    sub r8d, eax
    xor r8d, ecx
    add r8d, eax
    sub r8d, edx
    mov dword ptr [rsp+3Ch], r8d
    jmp loc_7FF856813884
    loc_7FF856824FF2:
    mov eax, dword ptr [rsp+1B4h]
    loc_7FF856824FF9:
    mov dword ptr [rsp+0D4h], eax
    mov eax, dword ptr [rsp+0D4h]
    mov ecx, dword ptr [rsp+74h]
    mov edx, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, dword ptr [rsp+74h]
    mov r9d, r8d
    and r9d, 7FFFFFFBh
    and r8d, 4
    lea r8d, [r8+r9*2]
    sub r8d, ecx
    mov r9d, ecx
    not r9d
    mov r10d, r9d
    and r10d, 4
    and r9d, 7FFFFFFBh
    add r9d, r9d
    xor edx, 7FFFFFFBh
    lea ecx, [r8+rdx*2]
    sub ecx, r9d
    add ecx, r10d
    mov edx, dword ptr [dword_7FF8571CC8A8]
    lea r8d, [rdx+17B7A379h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r9d, [rdx-43AF3869h]
    mov r10d, r9d
    xor r10d, 2F60D84Fh
    sub r10d, edx
    sub r10d, r9d
    xor r9d, 1B763ECCh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9d, 6E5EE94Fh
    add r10d, 25396899h
    xor r10d, r8d
    sub r10d, edx
    add r10d, -2A69F0B9h
    xor r10d, r9d
    add r10d, edx
    mov rdx, qword ptr [rsp+590h]
    add rdx, qword ptr [rsp+48h]
    and r10d, ecx
    mov dword ptr [rsp+30Ch], eax
    mov qword ptr [rsp+748h], rdx
    mov dword ptr [rsp+310h], r10d
    loc_7FF8568251B3:
    mov eax, dword ptr [rsp+310h]
    mov rdx, qword ptr [rsp+748h]
    mov ecx, dword ptr [rsp+30Ch]
    mov dword ptr [rsp+198h], eax
    mov qword ptr [rsp+5A8h], rdx
    mov dword ptr [rsp+0C4h], ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor edx, dword ptr [rsp+0C4h]
    mov eax, dword ptr [dword_7FF8571CC8AC]
    lea r8d, [rax+206297CBh]
    lea r9d, [rax+6C2D5C9Ch]
    mov ecx, r9d
    xor ecx, -1B60DD20h
    xor r9d, 19404405h
    and r9d, 19C966E5h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r9d, [r9+r9*4]
    mov r10d, ecx
    or r10d, 19C966E5h
    lea r10d, [r10+r10*2]
    mov r11d, ecx
    and r11d, 2636991Ah
    mov esi, ecx
    and esi, 19C966E5h
    lea esi, [rsi+rsi*8]
    lea r11d, [rsi+r11*4]
    sub r11d, r10d
    lea r9d, [r11+r9*2]
    add r9d, 654796A2h
    xor ecx, r8d
    xor ecx, r9d
    xor ecx, 0A2h
    sub ecx, eax
    mov eax, edx
    shr eax, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor eax, edx
    mov ecx, dword ptr [dword_7FF8571CC8B0]
    lea edx, [rcx+73EDE627h]
    mov r10d, edx
    or r10d, 320891CAh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r8d, [rdx+rdx]
    mov r9d, edx
    and r9d, 4DF76E35h
    mov r11d, edx
    and r11d, 320891CAh
    lea r11d, [r11+r11*2]
    lea r11d, [r11+r9*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r11d, r8d
    lea r9d, [r11+r10]
    add r9d, 267BD60Ah
    mov r8d, r11d
    add r8d, r10d
    mov r10d, r9d
    not r10d
    mov r11d, r9d
    or r11d, -300F4FEBh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r10d, 4FF0B015h
    lea r10d, [r10+r10*2]
    lea esi, [r9+r9*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edi, r9d
    and edi, 0FF0B015h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    shl edi, 2
    mov ebx, r9d
    and ebx, 300F4FEAh
    lea ebx, [rbx+rbx*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub edi, ebx
    add edi, esi
    lea r10d, [rdi+r10*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r10d, r11d
    add r10d, 6C9EF9AFh
    xor r10d, r9d
    sub r10d, edx
    lea edx, [r10+r8]
    add edx, -9C7946h
    xor edx, ecx
    imul edx, eax
    mov dword ptr [rsp+4D4h], edx
    mov edx, dword ptr [dword_7FF8571CC8B4]
    mov dword ptr [rsp+19Ch], edx
    not edx
    mov ecx, edx
    and ecx, -3C1BD52h
    lea eax, [rcx*8]
    sub eax, ecx
    and edx, 3C1BD51h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, edx
    shl ecx, 4
    add ecx, edx
    mov edx, dword ptr [rsp+19Ch]
    mov r8d, edx
    and r8d, 3C1BD51h
    lea r9d, [r8+r8*2]
    not r8d
    add r8d, r8d
    lea r8d, [r8+r8*2]
    mov r10d, edx
    or r10d, 3C1BD51h
    lea r11d, [r10+r10*4]
    lea r10d, [r10+r11*2]
    and edx, -3C1BD52h
    lea r11d, [rdx+rdx*8]
    lea edx, [rdx+r11*2]
    lea edx, [rdx+r9*4]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    sub edx, r8d
    add ecx, eax
    add ecx, edx
    mov dword ptr [rsp+1A0h], ecx
    mov eax, dword ptr [dword_7FF85723AAEC]
    mov ecx, eax
    xor ecx, -3512FBAAh
    lea edx, [rcx-39185667h]
    mov r8d, edx
    xor r8d, -5E8B172Ah
    lea r9d, [r8-28F39C1h]
    mov r10d, r9d
    xor r10d, -7D52A45Ah
    xor r9d, -7DB53DEEh
    sub r9d, r8d
    add r9d, -2F996B6Eh
    xor edx, eax
    xor edx, r9d
    sub edx, ecx
    sub edx, r10d
    sub edx, r8d
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF856825869:
    mov eax, dword ptr [rsp+90h]
    mov ecx, dword ptr [rsp+94h]
    mov rdx, qword ptr [rsp+398h]
    mov r8d, dword ptr [rsp+98h]
    mov r9d, dword ptr [rsp+9Ch]
    mov r10, qword ptr [rsp+3A0h]
    mov r11, qword ptr [rsp+3A8h]
    mov rsi, qword ptr [rsp+7C0h]
    mov dword ptr [rsp+230h], eax
    mov dword ptr [rsp+234h], ecx
    mov dword ptr [rsp+238h], ecx
    mov qword ptr [rsp+650h], rdx
    mov dword ptr [rsp+23Ch], r8d
    mov dword ptr [rsp+240h], r9d
    mov qword ptr [rsp+658h], r10
    mov qword ptr [rsp+660h], r11
    mov qword ptr [rsp+668h], rsi
    loc_7FF8568258EC:
    mov rax, qword ptr [rsp+668h]
    mov rcx, qword ptr [rsp+660h]
    mov rdx, qword ptr [rsp+658h]
    mov r8d, dword ptr [rsp+240h]
    mov r9d, dword ptr [rsp+23Ch]
    mov r10, qword ptr [rsp+650h]
    mov r11d, dword ptr [rsp+238h]
    mov esi, dword ptr [rsp+234h]
    mov edi, dword ptr [rsp+230h]
    mov qword ptr [rsp+3B0h], rax
    mov qword ptr [rsp+0E0h], rcx
    mov qword ptr [rsp+528h], rdx
    mov dword ptr [rsp+470h], r8d
    mov dword ptr [rsp+0A4h], r9d
    mov qword ptr [rsp+520h], r10
    mov dword ptr [rsp+0A0h], r11d
    mov dword ptr [rsp+12Ch], esi
    mov dword ptr [rsp+128h], edi
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
    mov rax, qword ptr [rsp+3B0h]
    cmp rax, rdx
    cmovb rdx, rax
    loc_7FF8568259FA:
    mov qword ptr [rsp+78h], rdx
    mov rax, qword ptr [qword_7FF8571CC6B0]
    mov rcx, -1B69517B6723D8FBh
    lea rdx, [rax+rcx]
    mov rcx, -3AA811B06355F87Bh
    lea r8, [rax+rcx]
    mov rcx, -71B4EE18981C8146h
    sub rcx, rax
    xor rcx, rdx
    mov rdx, rcx
    not rdx
    lea rdx, [rdx+rdx*2]
    mov r9, r8
    not r9
    mov r10, rcx
    or r10, r9
    not r10
    lea r10, [r10+r10*2]
    mov r11, rcx
    or r11, r8
    not r11
    lea r11, [r11+r11*2]
    mov rsi, rcx
    xor rsi, r8
    lea rdi, [rsi*8]
    sub rdi, rsi
    add rdi, r11
    and r9, rcx
    add r9, r9
    lea r9, [r9+r9*2]
    and rcx, r8
    add rcx, rcx
    sub rcx, r9
    add rcx, rdi
    sub rcx, r10
    sub rcx, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, -702C51C29C217FABh
    add rax, rdx
    add rax, rcx
    cmp qword ptr [rsp+528h], rax
    jnz loc_7FF856825B45
    mov eax, dword ptr [dword_7FF85723AA24]
    mov ecx, eax
    xor ecx, 4A786846h
    lea edx, [rcx-3D413957h]
    sub ecx, eax
    add ecx, -18317BE5h
    xor ecx, edx
    xor ecx, 3AF56DBh
    sub ecx, edx
    mov dword ptr [rsp+3Ch], ecx
    jmp loc_7FF856813884
    loc_7FF856825B45:
    mov eax, dword ptr [dword_7FF85723AA34]
    mov ecx, eax
    xor ecx, 48FF7030h
    lea edx, [rcx+5A211C41h]
    mov r8d, 0C11537Ah
    sub r8d, ecx
    xor r8d, edx
    xor r8d, edx
    xor edx, -5E6EDFFAh
    lea r9d, [rdx-7770C533h]
    xor r8d, r9d
    xor r8d, 0B50890Fh
    sub r8d, eax
    add r8d, ecx
    sub r8d, edx
    add r8d, -2111BC1Ch
    mov dword ptr [rsp+3Ch], r8d
    jmp loc_7FF856813884
    loc_7FF856825B99:
    mov eax, dword ptr [rsp+4F8h]
    mov qword ptr [rsp+410h], rax
    loc_7FF856825BA8:
    mov rax, qword ptr [rsp+410h]
    mov qword ptr [rsp+780h], rax
    cmp rax, qword ptr [rsp+370h]
    jnb loc_7FF856825C01
    mov eax, dword ptr [dword_7FF85723AA14]
    mov ecx, 4A24AC7Eh
    add eax, ecx
    mov ecx, eax
    xor ecx, -5642153Bh
    lea edx, [rcx-772ED5B7h]
    xor edx, eax
    xor eax, -1ADB03E6h
    lea r8d, [rcx+70EEBF50h]
    xor edx, 700AD4C2h
    sub edx, eax
    sub edx, ecx
    loc_7FF856825BF5:
    xor edx, r8d
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF856825C01:
    mov eax, dword ptr [rsp+64h]
    mov ecx, dword ptr [rsp+68h]
    mov rdx, qword ptr [rsp+378h]
    mov dword ptr [rsp+1C0h], eax
    mov dword ptr [rsp+1C4h], eax
    mov qword ptr [rsp+5D0h], 0
    mov dword ptr [rsp+1C8h], ecx
    mov dword ptr [rsp+1CCh], 0
    mov qword ptr [rsp+5D8h], 0
    mov qword ptr [rsp+5E0h], rdx
    loc_7FF856825C51:
    mov rax, qword ptr [rsp+5E0h]
    mov rcx, qword ptr [rsp+5D8h]
    mov edx, dword ptr [rsp+1CCh]
    mov r8d, dword ptr [rsp+1C8h]
    mov r9, qword ptr [rsp+5D0h]
    mov r10d, dword ptr [rsp+1C4h]
    mov r11d, dword ptr [rsp+1C0h]
    mov qword ptr [rsp+798h], rax
    mov qword ptr [rsp+790h], rcx
    mov dword ptr [rsp+10Ch], edx
    mov dword ptr [rsp+45Ch], r8d
    mov qword ptr [rsp+788h], r9
    mov dword ptr [rsp+458h], r10d
    mov dword ptr [rsp+454h], r11d
    mov rcx, qword ptr [rsp+330h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov qword ptr [rsp+7A0h], rcx
    jz loc_7FF856825DB2
    mov eax, dword ptr [dword_7FF85723A9E0]
    mov ecx, eax
    xor ecx, 6A664631h
    lea edx, [rcx-2BC3F3A8h]
    mov r8d, edx
    xor r8d, -7C92E8B8h
    xor edx, -6C3921E6h
    add r8d, ecx
    add r8d, -2BC3F3A8h
    sub r8d, edx
    add edx, -2FC34475h
    add ecx, r8d
    add ecx, -7310534Ch
    xor edx, eax
    xor edx, ecx
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF856825D6C:
    movzx eax, byte ptr [rsp+44h]
    mov byte ptr [rsp+42h], al
    mov dword ptr [rsp+1F8h], 0
    mov eax, dword ptr [dword_7FF85723A9F8]
    mov ecx, eax
    xor ecx, 66861C4Eh
    lea edx, [rcx+36C68FBAh]
    xor edx, 449F01F4h
    add eax, ecx
    add eax, 36C68FBAh
    sub edx, eax
    add edx, -6EC0535h
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF856825DB2:
    mov eax, dword ptr [rsp+10Ch]
    loc_7FF856825DB9:
    mov dword ptr [rsp+0C8h], eax
    loc_7FF856825DC0:
    mov eax, dword ptr [r12+40h]
    xor eax, dword ptr [rsp+0C8h]
    cmp eax, -18D9B3A8h
    jnz loc_7FF85682A6DB
    mov eax, dword ptr [dword_7FF85723AA00]
    mov ecx, eax
    xor ecx, 7E0DE38Bh
    mov edx, eax
    xor edx, 1B3070DFh
    sub ecx, edx
    add ecx, 4BBDC2F8h
    loc_7FF856825DF5:
    xor ecx, eax
    mov dword ptr [rsp+3Ch], ecx
    jmp loc_7FF856813884
    loc_7FF856825E00:
    mov eax, dword ptr [dword_7FF85723A9A8]
    mov ecx, eax
    xor ecx, 342AC278h
    lea edx, [rcx+53E710E9h]
    xor edx, 440188B5h
    add ecx, edx
    add ecx, 53E710E9h
    add ecx, eax
    mov dword ptr [rsp+3Ch], ecx
    jmp loc_7FF856813884
    loc_7FF856825E2D:
    mov dword ptr [rsp+0D0h], edx
    loc_7FF856825E34:
    mov eax, dword ptr [rsp+494h]
    xor eax, dword ptr [rsp+0D0h]
    cmp eax, -18D9B3A8h
    jnz loc_7FF856825E90
    mov eax, dword ptr [dword_7FF85723AA50]
    mov ecx, -3418B511h
    add eax, ecx
    mov ecx, eax
    xor ecx, -195145Eh
    mov edx, eax
    xor edx, 1CC6501Ah
    lea r8d, [rdx-4EEA86AFh]
    xor r8d, -0F4F2C85h
    add ecx, 6301277Ch
    xor ecx, edx
    sub ecx, eax
    sub ecx, r8d
    add ecx, edx
    lea eax, [rdx+rcx]
    add eax, -0B82B76Eh
    jmp loc_7FF856813880
    loc_7FF856825E90:
    mov eax, dword ptr [dword_7FF85723A9F4]
    mov ecx, 136FEC8Fh
    xor eax, ecx
    lea ecx, [rax-5F64D474h]
    xor ecx, -440A6D25h
    add eax, ecx
    add eax, 1632356Ch
    jmp loc_7FF856813880
    loc_7FF856825EB5:
    mov edx, dword ptr [rsp+138h]
    mov dword ptr [rsp+264h], ecx
    mov dword ptr [rsp+268h], eax
    mov dword ptr [rsp+26Ch], edx
    mov eax, dword ptr [dword_7FF85723AA4C]
    mov ecx, eax
    xor ecx, -52D1AD7Ah
    mov edx, 22F7B55Bh
    sub edx, ecx
    xor ecx, eax
    xor ecx, edx
    add ecx, -287847C2h
    mov dword ptr [rsp+3Ch], ecx
    jmp loc_7FF856813884
    loc_7FF856825EF9:
    mov eax, dword ptr [dword_7FF85723AA98]
    lea ecx, [rax-315190D5h]
    xor ecx, 19EA4221h
    lea edx, [rax+rcx]
    add edx, -315190D5h
    add ecx, eax
    add ecx, edx
    mov eax, -316E58E9h
    sub eax, ecx
    jmp loc_7FF856813880
    loc_7FF856825F24:
    mov eax, dword ptr [dword_7FF85723AB28]
    mov ecx, eax
    xor ecx, 84FA6CCh
    lea edx, [rcx-7DF2BD2Bh]
    lea r8d, [rcx+22231FE7h]
    xor edx, r8d
    xor edx, 43E3D7A1h
    sub edx, r8d
    add edx, eax
    lea eax, [rcx+rdx]
    add eax, -34BAA5CBh
    jmp loc_7FF856813880
    loc_7FF856825F5A:
    mov eax, dword ptr [dword_7FF85723AA70]
    mov ecx, eax
    xor ecx, 3AF1F350h
    mov edx, eax
    xor edx, 7B6CEBC7h
    lea r8d, [rdx+4122F4C1h]
    mov r9d, r8d
    xor r9d, 32739C63h
    mov r10d, r8d
    xor r10d, 61D8E567h
    xor r8d, -4DE32EA1h
    add r8d, r10d
    sub r8d, r9d
    add r8d, ecx
    sub r8d, eax
    xor r8d, edx
    mov dword ptr [rsp+3Ch], r8d
    jmp loc_7FF856813884
    loc_7FF856825FAB:
    mov eax, dword ptr [dword_7FF85723AADC]
    lea ecx, [rax-720778C9h]
    lea edx, [rax+4D627808h]
    xor edx, ecx
    add edx, eax
    add eax, edx
    add eax, 4821C163h
    jmp loc_7FF856813880
    loc_7FF856825FCD:
    mov rax, qword ptr [rsp+58h]
    shr rax, 2
    mov qword ptr [rsp+770h], rax
    mov dword ptr [rsp+2B4h], edx
    mov dword ptr [rsp+2B8h], ecx
    mov qword ptr [rsp+6C8h], 0
    nop dword ptr [rax+rax+00000000h]
    loc_7FF856826000:
    mov rdx, qword ptr [rsp+6C8h]
    mov r8d, dword ptr [rsp+2B8h]
    mov r9d, dword ptr [rsp+2B4h]
    mov r10d, dword ptr [dword_7FF8571CC910]
    lea ecx, [r10+342EB677h]
    mov r11d, ecx
    xor r11d, -674BB6CAh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea esi, [r11-0F56CFEBh]
    xor esi, -770D3FA3h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edi, r11d
    xor edi, esi
    add esi, -2F7443F3h
    xor esi, edi
    add r11d, esi
    add r11d, -0F56CFEBh
    clc
    xchg al, al
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r11d, r10d
    add r11d, -0B4D0F23h
    mov esi, ecx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edi, r11d
    or edi, esi
    not edi
    add edi, edi
    lea edi, [rdi+rdi*4]
    mov ebx, r11d
    or ebx, ecx
    lea r14d, [rbx+rbx*4]
    lea ebx, [rbx+r14*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ebp, r11d
    xor ebp, ecx
    add ebp, ebp
    and esi, r11d
    shl esi, 3
    and r11d, ecx
    imul r11d, 0F5h
    sub r11d, esi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r11d, ebp
    add r11d, ebx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r11d, edi
    mov ecx, r10d
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
    nop
    nop
    nop
    nop
    nop
    mov esi, r11d
    or esi, ecx
    not esi
    lea edi, [rsi+rsi*4]
    lea esi, [rsi+rdi*2]
    mov edi, r11d
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ebx, [r10+r10*4]
    lea ebx, [r10+rbx*2]
    and ecx, r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r10d, r11d
    imul r10d, 0F5h
    add ecx, ebx
    add ecx, edi
    add ecx, r10d
    sub ecx, esi
    sub ecx, r11d
    mov r10, rdx
    shl r10, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11, qword ptr [rsp+0F0h]
    mov ecx, dword ptr [r11+r10]
    mov esi, dword ptr [dword_7FF8571CC918]
    lea ebx, [rsi-5337111Ch]
    lea edi, [rsi-29980A81h]
    add esi, 4981B992h
    xor esi, -250D5C0Dh
    mov r14d, ebx
    not r14d
    mov r15d, esi
    or r15d, r14d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not r15d
    lea r15d, [r15+r15*4]
    lea r12d, [rbx+rbx]
    lea ebp, [r12]
    mov r12d, esi
    or r12d, ebx
    lea r12d, [r12]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r14d, esi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and esi, ebx
    lea esi, [rsi+rsi*8]
    lea esi, [rsi+r14*4]
    sub esi, r12d
    sub esi, ebp
    lea r13d, [rsi+r15*2]
    xor r13d, edi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov esi, dword ptr [dword_7FF8571CC91C]
    mov r14d, esi
    xor r14d, -2D500FB3h
    lea r12d, [r14-71DDA006h]
    xor esi, -428D60Ch
    add esi, r14d
    lea ebx, [r14+rsi]
    add ebx, 4D19E86Eh
    mov ebp, ebx
    mov esi, r12d
    not esi
    mov r15d, ebx
    or r15d, esi
    mov eax, ebx
    xor eax, r12d
    lea edi, [rax*8]
    sub edi, eax
    mov eax, ebx
    or eax, r12d
    and esi, ebx
    and ebx, r12d
    add esi, esi
    lea esi, [rsi+rsi*2]
    add ebx, ebx
    sub ebx, esi
    not eax
    lea eax, [rax+rax*2]
    add edi, eax
    imul r13d, ecx
    lea eax, [r14+5C30A39Ch]
    not ebp
    lea esi, [rbp+rbp*2+0]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    not r15d
    lea ebp, [r15+r15*2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add edi, ebx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub edi, ebp
    sub edi, esi
    sub edi, eax
    imul edi, ecx
    mov ecx, dword ptr [dword_7FF8571CC920]
    mov eax, ecx
    not eax
    mov esi, eax
    and esi, 6F874987h
    lea esi, [rsi+rsi*2]
    and eax, -6F874988h
    lea eax, [rax+rax*4]
    mov ebx, ecx
    xor ebx, 6F874987h
    add ebx, ebx
    mov r14d, ecx
    and r14d, 1078B678h
    shl r14d, 3
    sub r14d, ebx
    add r14d, eax
    lea eax, [r14+rsi]
    add eax, 2DA46FA8h
    xor eax, 3708BA4Ah
    lea esi, [rax-45AE9A62h]
    xor esi, eax
    xor esi, 3F2D8ECEh
    mov eax, esi
    or eax, ecx
    mov ebx, eax
    not ebx
    lea ebp, [rbx*8]
    sub ebp, ebx
    and esi, ecx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea eax, [rsi+rax*2]
    add eax, ebp
    mov cl, 0F9h
    sub cl, al
    shr r13d, cl
    mov eax, r13d
    xor eax, edi
    mov ecx, edi
    not ecx
    and ecx, r13d
    and edi, r13d
    lea ecx, [rdi+rcx*2]
    sub eax, ecx
    lea eax, [rax+r13*2]
    imul eax, 1B873593h
    xor eax, r9d
    rol eax, 0Dh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    mov ecx, dword ptr [dword_7FF8571CC924]
    mov r9d, ecx
    xor r9d, 100F2361h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov esi, ecx
    xor esi, 5DA2CFB7h
    lea edi, [rsi-2B29F88Ah]
    xor edi, -6EA762FAh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ebx, 0FFFFFFFF9876336Ah[rdi*2]
    add esi, ebx
    add esi, -2B29F88Ah
    sub ecx, esi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub ecx, r9d
    add ecx, edi
    add eax, ecx
    add eax, 47AE4E7h
    mov dword ptr [rsp+174h], eax
    lea r13, eidolon_sbox
    mov eax, dword ptr [r8+r13]
    xor dword ptr [r11+r10], eax
    mov eax, r8d
    mov ecx, r8d
    and ecx, 7FFFFFFBh
    mov r9d, r8d
    and r9d, 4
    lea ecx, [r9+rcx*2]
    sub ecx, r8d
    not r8d
    mov r9d, r8d
    and r9d, 4
    and r8d, 7FFFFFFBh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r8d, r8d
    xor eax, 7FFFFFFBh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ecx, [rcx+rax*2]
    sub ecx, r8d
    add ecx, r9d
    mov r8d, dword ptr [dword_7FF8571CC928]
    mov r11d, r8d
    not r11d
    mov eax, r11d
    and eax, 4DFF0846h
    add eax, eax
    add r11d, r11d
    or r11d, -6401EF74h
    mov r9d, r8d
    xor r9d, -4DFF0847h
    sub r11d, r9d
    sub r11d, eax
    mov r9d, r11d
    xor r9d, -4FC56444h
    add r9d, 4EA28623h
    mov r10d, r9d
    xor r10d, -75D4A62Ah
    mov eax, r9d
    xor eax, 2AA671Ch
    lea esi, [rax-53D825FCh]
    xor esi, 525AD74h
    add esi, eax
    add esi, -53D825FCh
    add esi, eax
    sub esi, r11d
    add esi, 3EB5AB37h
    mov eax, r9d
    xor eax, 75D4A629h
    mov r11d, esi
    or r11d, eax
    mov edi, esi
    or edi, r10d
    mov ebx, eax
    and eax, esi
    and r10d, esi
    lea eax, [r10+rax*2]
    xor ebx, esi
    sub eax, esi
    lea eax, [rax+rbx*2]
    not edi
    add edi, edi
    sub eax, edi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add eax, r11d
    sub eax, r9d
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
    and eax, ecx
    mov dword ptr [rsp+178h], eax
    mov r8, qword ptr [qword_7FF8571CC930]
    mov rax, 4C3DB1218AD604F1h
    lea rcx, [r8+rax]
    mov rax, -29954686C4181E13h
    add r8, rax
    mov rax, r8
    not rax
    mov r9, r8
    mov r11, 4C4F773A188F9EEDh
    xor r9, r11
    add r9, r9
    mov r10, r8
    mov rsi, 13B088C5E7706112h
    and r10, rsi
    shl r10, 3
    sub r10, r9
    mov r9, rax
    mov rsi, -4C4F773A188F9EEEh
    and rax, rsi
    lea rax, [rax+rax*4]
    add r10, rax
    and r9, r11
    lea rax, [r9+r9*2]
    mov r9, 7D8D54227ACE1AA6h
    add rax, r9
    add rax, r10
    mov r9, rax
    mov r10, 2BED0038A93E41EAh
    xor r9, r10
    mov r10, -11BFF7BEA9F01B17h
    xor rcx, r10
    add rcx, r9
    sub rcx, rax
    sub rcx, r8
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cmp rcx, qword ptr [rsp+770h]
    jz loc_7FF856827321
    mov edx, dword ptr [rsp+174h]
    mov r8d, dword ptr [rsp+178h]
    mov dword ptr [rsp+2B4h], edx
    mov dword ptr [rsp+2B8h], r8d
    mov qword ptr [rsp+6C8h], rcx
    jmp loc_7FF856826000
    loc_7FF856827321:
    mov eax, dword ptr [dword_7FF85723A9BC]
    lea ecx, [rax+2D8A3E30h]
    lea edx, 65CA4F49h[rax*2]
    add eax, -5B13CE93h
    xor edx, ecx
    xor edx, eax
    mov dword ptr [rsp+3Ch], edx
    mov r12, qword ptr [rsp+328h]
    jmp loc_7FF856813884
    loc_7FF85682734E:
    mov rax, qword ptr [rsp+78h]
    sub rax, rdx
    mov rcx, qword ptr [rsp+0E0h]
    add rdx, qword ptr [rsp+3B8h]
    movzx edx, byte ptr [r13+rdx+0]
    xor byte ptr [rcx+rax], dl
    mov rax, qword ptr [rsp+338h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    movzx eax, byte ptr [rax+2]
    mov edx, dword ptr [dword_7FF8571CC6F8]
    mov ecx, edx
    xor ecx, -2C792AACh
    mov r8d, edx
    xor r8d, 24702800h
    mov r9d, edx
    xor r9d, 80902ABh
    mov r10d, r9d
    and r10d, 590D56AFh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r8d, -590D56B0h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or r9d, -590D56B0h
    lea r9d, [r9+rcx*2]
    add r9d, r8d
    lea r8d, [r9+r10*2]
    lea r9d, [r9+r10*2]
    add r9d, -75EA3E2Fh
    add ecx, -569EDBB3h
    xor ecx, r9d
    add ecx, r8d
    sub ecx, edx
    add cl, 2
    shl eax, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov dword ptr [rsp+25Ch], eax
    loc_7FF8568276C0:
    mov eax, dword ptr [rsp+25Ch]
    mov dword ptr [rsp+474h], eax
    mov rax, qword ptr [rsp+338h]
    movzx eax, byte ptr [rax+1]
    mov dword ptr [rsp+478h], eax
    mov eax, dword ptr [dword_7FF8571CC6FC]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    xor ecx, 13DFE66Ah
    mov dword ptr [rsp+140h], ecx
    mov edx, eax
    xor edx, 24001010h
    and edx, 274C761Ah
    add edx, edx
    lea edx, [rdx+rdx*4]
    mov dword ptr [rsp+47Ch], edx
    or ecx, 274C761Ah
    lea edx, [rcx+rcx*4]
    lea ecx, [rcx+rdx*2]
    mov dword ptr [rsp+480h], ecx
    xor eax, 34939070h
    add eax, eax
    mov dword ptr [rsp+484h], eax
    mov eax, dword ptr [dword_7FF85723AA48]
    mov ecx, eax
    xor ecx, -27EFD46Dh
    lea edx, [rcx-4F7CEE3h]
    add eax, 1532E4C2h
    xor eax, edx
    mov edx, ecx
    add edx, -34E9DD92h
    add eax, ecx
    add eax, 77426E71h
    xor eax, edx
    add eax, ecx
    add eax, 4B307171h
    jmp loc_7FF856813880
    loc_7FF8568277A5:
    mov eax, dword ptr [dword_7FF85723AA6C]
    mov ecx, eax
    xor ecx, 5257C05Fh
    add eax, ecx
    add eax, -4B11E46Ah
    add eax, ecx
    add eax, -4B11E46Ah
    mov edx, -63B37463h
    sub edx, eax
    jmp loc_7FF85682900C
    loc_7FF8568277CD:
    mov eax, dword ptr [dword_7FF85723A99C]
    lea ecx, [rax+0B377D0Ah]
    mov edx, ecx
    xor edx, -1F08D8F7h
    xor ecx, 2CFC1939h
    neg edx
    add edx, ecx
    add edx, -5C46F5A7h
    xor edx, ecx
    add eax, edx
    add eax, 0B377D0Ah
    jmp loc_7FF856813880
    loc_7FF8568277FF:
    dec eax
    mov dword ptr [rsp+290h], eax
    mov dword ptr [rsp+294h], 0
    loc_7FF856827813:
    mov eax, dword ptr [rsp+294h]
    mov ecx, dword ptr [rsp+290h]
    mov dword ptr [rsp+49Ch], eax
    mov dword ptr [rsp+498h], ecx
    add eax, ecx
    mov edx, dword ptr [dword_7FF8571CC83C]
    lea ecx, [rdx-62298490h]
    lea r8d, [rdx+13C618F7h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor ecx, edx
    xor ecx, 5Fh
    sub ecx, edx
    add ecx, -68FA1C2Dh
    xor ecx, r8d
    shr eax, cl
    mov dword ptr [rsp+16Ch], eax
    mov rcx, qword ptr [rsp+3C8h]
    shl rax, 4
    mov rdx, qword ptr [rcx+rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add rdx, qword ptr [rcx+rax+8]
    cmp rdx, qword ptr [rsp+3D8h]
    setnbe byte ptr [rsp+46h]
    mov eax, dword ptr [rsp+16Ch]
    inc eax
    mov dword ptr [rsp+4A0h], eax
    mov eax, dword ptr [dword_7FF8571CC840]
    mov dword ptr [rsp+4A4h], eax
    mov ecx, eax
    xor ecx, -68C3686Fh
    mov dword ptr [rsp+170h], ecx
    xor eax, 4081484Ch
    and eax, 529D5FDCh
    mov dword ptr [rsp+4A8h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [dword_7FF85723AA84]
    lea ecx, [rax+313A54D3h]
    lea edx, [rax-75D0A1C5h]
    xor edx, ecx
    lea ecx, [rax-42E1AE3Ch]
    xor ecx, 3E875AFEh
    mov r8d, ecx
    sub r8d, eax
    lea eax, [r8+rcx]
    add eax, -0A00E833h
    xor eax, edx
    jmp loc_7FF856813880
    loc_7FF856827A7A:
    mov dword ptr [rsp+290h], ecx
    mov dword ptr [rsp+294h], eax
    mov eax, dword ptr [dword_7FF85723AA80]
    lea ecx, [rax-135A9587h]
    lea edx, [rax-1C5007FFh]
    xor edx, -33525FE5h
    add edx, eax
    add edx, -1A5E8902h
    xor edx, ecx
    add eax, edx
    add eax, 5BCF5566h
    jmp loc_7FF856813880
    loc_7FF856827AB6:
    mov eax, dword ptr [dword_7FF85723A9A4]
    lea ecx, [rax-0B733070h]
    lea edx, [rax-37B191B4h]
    xor edx, ecx
    lea ecx, [rax-4FC06AC8h]
    xor ecx, 368F26h
    xor edx, 6CD418CAh
    add edx, eax
    add edx, -4FC06AC8h
    xor edx, eax
    sub edx, eax
    lea eax, [rdx+rcx]
    add eax, 1AB07F8h
    jmp loc_7FF856813880
    loc_7FF856827AF5:
    mov eax, dword ptr [dword_7FF8571CC768]
    lea ecx, [rax+67631AB9h]
    lea edx, [rax-7632333h]
    xor edx, 78h
    add edx, eax
    add edx, -5C21063Bh
    xor ecx, eax
    xor ecx, edx
    mov rdx, qword ptr [rsp+50h]
    add cl, 53h
    mov rax, rdx
    shr rax, cl
    cmp rdx, 4
    jnb loc_7FF85682990C
    mov eax, dword ptr [dword_7FF85723AA0C]
    lea ecx, [rax+195F4DE6h]
    mov edx, ecx
    xor edx, -380F51E8h
    lea r8d, [rdx+1EE29BDEh]
    xor ecx, 712A8EDEh
    add ecx, edx
    xor ecx, r8d
    xor ecx, eax
    lea eax, [rdx+rcx]
    add eax, -21093DD4h
    jmp loc_7FF856813880
    loc_7FF856827B63:
    mov r8, rdx
    not r8
    mov r9, qword ptr [rsp+50h]
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
    nop
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
    shl r9, 2
    lea r10, [rdx+rdx]
    mov r11, qword ptr [rsp+50h]
    or r11, rdx
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
    mov rsi, qword ptr [rsp+50h]
    and r8, rsi
    and rsi, rdx
    lea rsi, [rsi+rsi*2]
    lea r8, [rsi+r8*4]
    sub r11, r8
    sub r11, r10
    sub r11, r9
    mov r8, qword ptr [rsp+0D8h]
    add rdx, rcx
    movzx r9d, byte ptr [r8+r11]
    xor r9b, byte ptr [r13+rdx+0]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov byte ptr [r8+r11], r9b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9, qword ptr [qword_7FF8571CC7C0]
    mov rdx, r9
    mov r11, -25294A579859B169h
    or rdx, r11
    lea r8, [rdx+rdx*2]
    not rdx
    lea r10, [rdx*8]
    sub r10, rdx
    mov rdx, r9
    and rdx, r11
    lea r8, [rdx+r8*2]
    add r8, r10
    mov rdx, -7
    sub rdx, r8
    mov r10, rdx
    mov rdi, 3D19B694EB69C0F4h
    or r10, rdi
    mov r8, rdx
    mov rbx, -3D19B694EB69C0F5h
    or r8, rbx
    mov r11, rdx
    xor r11, rdi
    add r11, r8
    lea rsi, [rdx+rdx]
    mov r8, rdx
    and r8, rdi
    lea rdi, [r8+r8*2]
    mov r8, rdx
    and r8, rbx
    lea r8, [r8+r8*2]
    add r8, rdi
    sub r8, rsi
    add r8, r11
    sub r8, r10
    mov r10, r8
    mov r11, -6839BB03C318BFDFh
    xor r10, r11
    mov r11, -126AC56A76B050EFh
    add r11, r10
    sub r10, r9
    add r10, r11
    mov r9, 787B367EF0167E18h
    add r11, r9
    add r11, r10
    mov r9, rdx
    not r9
    mov r10, r11
    or r10, r9
    mov rsi, r11
    or rsi, rdx
    mov rdi, r11
    xor rdi, rdx
    and r9, r11
    and r11, rdx
    shl r9, 2
    lea rdx, [r9+r11*2]
    sub rdx, rdi
    add rsi, rsi
    sub rdx, rsi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea rdx, [rdx+r10*4]
    add rdx, r8
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
    mov rdx, qword ptr [qword_7FF8571CC7C8]
    mov r8, 2FC6E2465B514C49h
    add r8, rdx
    mov r9, r8
    mov r10, 2C7D70E3E776E0FDh
    xor r9, r10
    sub r8, r9
    mov r9, -2EC7A9F3908F9EAEh
    add r8, r9
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    jnz loc_7FF85682A5D9
    mov eax, dword ptr [dword_7FF85723AA04]
    lea ecx, [rax+0A596158h]
    xor ecx, 6C2CE64Dh
    mov edx, eax
    xor edx, ecx
    xor edx, 4B44B108h
    add edx, ecx
    add edx, eax
    add edx, 0A596158h
    add edx, ecx
    add edx, 3A20A54Ch
    add ecx, 3A20A54Ch
    add eax, edx
    add eax, -60573386h
    xor eax, ecx
    xor eax, -55A3DD57h
    jmp loc_7FF856813880
    loc_7FF85682815D:
    mov dword ptr [rsp+1B8h], ecx
    mov dword ptr [rsp+1BCh], eax
    mov eax, dword ptr [dword_7FF85723A9B8]
    mov ecx, -7ABE4613h
    xor eax, ecx
    add eax, 1D851DC4h
    jmp loc_7FF856813880
    loc_7FF856828182:
    mov eax, dword ptr [rsp+0A0h]
    mov ecx, dword ptr [rsp+0A4h]
    mov dword ptr [rsp+244h], eax
    mov dword ptr [rsp+248h], ecx
    mov qword ptr [rsp+670h], 0
    loc_7FF8568281AA:
    mov rax, qword ptr [rsp+670h]
    mov r8d, dword ptr [rsp+248h]
    mov edx, dword ptr [rsp+244h]
    mov r9d, dword ptr [dword_7FF8571CC6D0]
    lea r10d, [r9-74CC6A7Ah]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r11d, [r9-6678D889h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, -4C42DA11h
    sub ecx, r9d
    xor ecx, r10d
    xor ecx, r11d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor ecx, 63h
    sub ecx, r11d
    mov r9, rax
    shl r9, cl
    mov r10, qword ptr [rsp+0E0h]
    mov ecx, dword ptr [r10+r9]
    xor ecx, dword ptr [r8+r13]
    mov dword ptr [r10+r9], ecx
    mov r10d, dword ptr [dword_7FF8571CC6D8]
    lea r9d, [r10-67D6B1FDh]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    not r11d
    mov esi, r11d
    and esi, -19FEAF5Ch
    lea edi, [rsi+rsi*4]
    lea esi, [rsi+rdi*2]
    mov edi, r9d
    or edi, -19FEAF5Ch
    mov ebx, r9d
    and ebx, 19FEAF5Bh
    add ebx, edi
    mov edi, r9d
    and edi, -19FEAF5Ch
    imul edi, 0F5h
    add edi, ebx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub edi, esi
    lea esi, [rdi+r11]
    add esi, -1DF188F3h
    add edi, r11d
    add r10d, 3A8DE3E6h
    xor r10d, esi
    add r10d, edi
    add r10d, 2E6F5C2Ah
    xor r10d, r9d
    add r10d, r8d
    and r10d, 3FFFh
    mov dword ptr [rsp+130h], r10d
    mov r8d, dword ptr [dword_7FF8571CC6DC]
    lea r9d, [r8-71C5D954h]
    lea r11d, [r8+0A44A147h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edi, r11d
    xor edi, 2E5D81Ah
    mov r10d, r11d
    xor r10d, 6384A143h
    lea ebx, [r10-64181E6Ch]
    mov esi, r11d
    xor esi, -2E5D81Bh
    mov r14d, edi
    and r14d, 7E3861C5h
    lea ebp, [r14+r14*8]
    mov r14d, esi
    and r14d, 7E3861C5h
    add r14d, r14d
    lea r14d, [r14+r14*4]
    and edi, -7E3861C6h
    mov r15d, edi
    not r15d
    lea r15d, [r15+r15*2]
    and esi, 1C79E3Ah
    add esi, esi
    add edi, edi
    sub edi, esi
    add edi, r15d
    sub edi, r14d
    sub edi, ebp
    add edi, 738AAC63h
    xor edi, ebx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor edi, 97E5ABFh
    lea esi, [rdi+r10]
    add esi, -64181E6Ch
    sub esi, r11d
    mov r11d, r8d
    not r11d
    mov edi, esi
    or edi, r11d
    not edi
    mov ebx, esi
    or ebx, r8d
    not ebx
    add ebx, ebx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r14d, esi
    and r14d, r11d
    xor r11d, esi
    and r8d, esi
    lea r8d, [r8+r14*2]
    sub r8d, esi
    lea r8d, [r8+r11*2]
    sub r8d, ebx
    add r8d, edi
    xor r8d, r9d
    sub r8d, r10d
    mov r10d, dword ptr [dword_7FF8571CC6E0]
    mov r9d, r10d
    xor r9d, -2296B950h
    lea edi, [r9+35866AF0h]
    mov r11d, edi
    xor r11d, -5BEB4CFFh
    mov ebp, edi
    xor ebp, -47E5F0B1h
    xor edi, 5BEB4CFEh
    mov esi, ebp
    or esi, edi
    not esi
    lea ebx, [rsi+rsi*4]
    lea ebx, [rsi+rbx*4]
    mov esi, ebp
    or esi, r11d
    lea r14d, [rsi+rsi*4]
    lea r14d, [rsi+r14*2]
    not esi
    lea r15d, [rsi+rsi*4]
    lea esi, [rsi+r15*2]
    and r11d, ebp
    mov r15d, r11d
    not r15d
    lea r12d, [r15+r15*4]
    lea r15d, [r12]
    and edi, ebp
    lea r12d, [rdi+rdi*4]
    lea edi, [rsp]
    lea r11d, [r11+r11*8]
    add r11d, edi
    sub r14d, r11d
    add r14d, r15d
    sub r14d, esi
    sub r14d, ebx
    add r8d, 59C2D4BAh
    imul r8d, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r14d, r10d
    add r14d, r9d
    imul r14d, ecx
    shr r8d, 11h
    or r8d, r14d
    imul ecx, r8d, 1B873593h
    xor ecx, edx
    rol ecx, 0Dh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov edx, dword ptr [dword_7FF8571CC6E4]
    lea r8d, [rdx-4F10C9F1h]
    mov r9d, r8d
    not r9d
    mov r10d, r9d
    and r10d, -1F4BD0Dh
    mov r11d, r9d
    and r11d, 1F4BD0Ch
    and r8d, 1F4BD0Ch
    lea r8d, [r8+r11*2]
    add r10d, edx
    add r10d, r8d
    add r9d, r9d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r9d, r10d
    lea r8d, [r9+rdx]
    add r8d, -4F10C9F1h
    add edx, r8d
    add edx, 1F4BD12h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    imul edx, ecx
    mov ecx, dword ptr [dword_7FF8571CC6E8]
    lea r8d, [rcx-1F8A0E56h]
    xor r8d, 0F1C9D35h
    add r8d, ecx
    add r8d, -1F8A0E56h
    sub ecx, r8d
    add ecx, edx
    add ecx, -492210D2h
    mov dword ptr [rsp+134h], ecx
    mov rcx, qword ptr [qword_7FF8571CC6F0]
    mov rdx, -48B3E29FB062AD2Ah
    lea r9, [rcx+rdx]
    mov r8, r9
    mov rdx, r9
    mov r10, -0D3CF4D191D227EAh
    xor rdx, r10
    mov r10, 530400081102149h
    xor r8, r10
    mov r10, r8
    mov rsi, -4570402ECD3DA94Eh
    or r8, rsi
    sub r8, rdx
    sub r8, rdx
    mov r11, 570402ECD3DA94Dh
    and r10, r11
    shl r10, 2
    sub r8, r10
    mov r10, 4F4966FEC997A77h
    add rcx, r10
    add rcx, r9
    mov r10, 80CB4D110C206A0h
    xor r9, r10
    and r9, rsi
    lea r9, [r9+r9*2]
    sub r8, r9
    add r8, -3
    mov r9, 30512C77D3DFBCFAh
    xor rcx, r9
    xor rcx, r8
    sub rcx, rdx
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
    cmp rcx, qword ptr [rsp+7C8h]
    jnz loc_7FF856828BAF
    mov eax, dword ptr [dword_7FF85723AA3C]
    mov ecx, eax
    xor ecx, -1C2BD099h
    lea edx, [rcx-34C1E1B3h]
    neg edx
    add edx, eax
    add edx, -503F584Dh
    xor eax, 6014892Dh
    lea r8d, [rcx-6D104147h]
    xor edx, ecx
    sub edx, eax
    xor edx, r8d
    add edx, ecx
    lea eax, [rcx+rdx]
    add eax, -640BC52Fh
    jmp loc_7FF85682A59C
    loc_7FF856828BAF:
    mov eax, dword ptr [rsp+130h]
    mov edx, dword ptr [rsp+134h]
    mov dword ptr [rsp+244h], edx
    mov dword ptr [rsp+248h], eax
    mov qword ptr [rsp+670h], rcx
    mov eax, dword ptr [dword_7FF85723AA38]
    mov ecx, eax
    xor ecx, -7CA71BFAh
    lea edx, [rcx+78A4BD9Fh]
    xor edx, -38082772h
    lea r8d, [rdx-4D5DE03Ah]
    lea r9d, [rdx+155F4315h]
    xor r8d, edx
    xor r8d, -6586DBBBh
    sub r8d, edx
    add r8d, -283C55B8h
    xor r8d, r9d
    add ecx, r8d
    add ecx, 78A4BD9Fh
    sub ecx, eax
    lea eax, [rdx+rcx]
    add eax, 5CFB9EA7h
    jmp loc_7FF85682A59C
    loc_7FF856828C2A:
    mov eax, dword ptr [rsp+0B0h]
    mov rcx, qword ptr [rsp+3E0h]
    mov edx, dword ptr [rsp+0B4h]
    mov r8d, dword ptr [rsp+0B8h]
    mov r9, qword ptr [rsp+3E8h]
    mov dword ptr [rsp+314h], eax
    mov qword ptr [rsp+750h], rcx
    mov dword ptr [rsp+318h], edx
    mov qword ptr [rsp+758h], r9
    mov dword ptr [rsp+31Ch], r8d
    loc_7FF856828C76:
    mov eax, dword ptr [rsp+31Ch]
    mov rcx, qword ptr [rsp+758h]
    mov edx, dword ptr [rsp+318h]
    mov r8, qword ptr [rsp+750h]
    mov r9d, dword ptr [rsp+314h]
    mov dword ptr [rsp+1B0h], eax
    mov qword ptr [rsp+5C0h], rcx
    mov dword ptr [rsp+1ACh], edx
    mov qword ptr [rsp+5B8h], r8
    mov dword ptr [rsp+1A8h], r9d
    mov rax, qword ptr [rsp+838h]
    inc rax
    cmp rax, qword ptr [rsp+3D0h]
    jnz loc_7FF856828CFE
    mov eax, dword ptr [dword_7FF85723AAFC]
    lea ecx, [rax+69204CC5h]
    mov edx, ecx
    xor edx, -32E15529h
    add edx, 0E2644EFh
    xor edx, ecx
    add edx, eax
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF856828CFE:
    mov rcx, qword ptr [rsp+580h]
    mov edx, dword ptr [rsp+1A8h]
    mov r8, qword ptr [rsp+5B8h]
    mov r9d, dword ptr [rsp+1ACh]
    mov r10, qword ptr [rsp+5C0h]
    mov r11d, dword ptr [rsp+1B0h]
    mov dword ptr [rsp+2D8h], edx
    mov qword ptr [rsp+6E8h], r8
    mov dword ptr [rsp+2DCh], r9d
    mov qword ptr [rsp+6F0h], rax
    mov dword ptr [rsp+2E0h], r11d
    mov qword ptr [rsp+6F8h], r10
    mov qword ptr [rsp+700h], rcx
    mov eax, dword ptr [dword_7FF85723A9C8]
    mov ecx, 10E4C4CAh
    xor eax, ecx
    lea ecx, [rax-5D1E34E9h]
    add eax, ecx
    add eax, -39D0003Bh
    xor ecx, 1FD1036Ch
    lea edx, [rcx+54DB7443h]
    xor eax, ecx
    xor eax, edx
    sub eax, ecx
    add eax, -16F2023Ah
    jmp loc_7FF856813880
    loc_7FF856828D9A:
    mov rax, qword ptr [rsp+570h]
    mov qword ptr [rsp+6E0h], rax
    mov eax, dword ptr [dword_7FF85723AAB0]
    lea ecx, [rax+4446D913h]
    lea edx, [rax+4CC0FF34h]
    xor edx, 4D2D06DBh
    xor ecx, 5AC626BCh
    add ecx, edx
    add ecx, eax
    add eax, ecx
    add eax, 67CE48FBh
    jmp loc_7FF856813880
    loc_7FF856828DD8:
    mov eax, dword ptr [dword_7FF85723AA60]
    mov ecx, eax
    xor ecx, 1BFC45C0h
    lea edx, [rcx+5C9146C6h]
    lea r8d, [rcx-67376319h]
    lea r9d, [rcx-5675DB38h]
    mov r10d, r9d
    xor r10d, -654FE328h
    add ecx, -7E75D99Ch
    xor ecx, r8d
    add ecx, r10d
    xor ecx, r9d
    sub ecx, eax
    xor ecx, edx
    sub ecx, r10d
    add ecx, 9889DB8h
    mov dword ptr [rsp+3Ch], ecx
    jmp loc_7FF856813884
    loc_7FF856828E29:
    mov eax, dword ptr [dword_7FF85723AB2C]
    lea ecx, [rax-7EC899Ah]
    mov edx, ecx
    xor edx, -15621BB6h
    mov r9d, 4C695F9h
    sub r9d, eax
    sub r9d, edx
    add eax, 4B36F54Bh
    add edx, 367A2577h
    xor edx, eax
    xor edx, r9d
    xor edx, ecx
    xor edx, 2270D25Ah
    add edx, -7EC899Ah
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF856828E70:
    mov eax, dword ptr [dword_7FF8571CC68C]
    mov ecx, 3A3058D8h
    xor eax, ecx
    mov dword ptr [rsp+164h], eax
    add eax, -15B19E74h
    mov dword ptr [rsp+70h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, dword ptr [rsp+70h]
    not eax
    and eax, 34F83459h
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
    mov ecx, dword ptr [rsp+70h]
    not ecx
    add ecx, ecx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or ecx, 69F068B2h
    mov edx, dword ptr [rsp+70h]
    mov r8d, 4B07CBA6h
    xor edx, r8d
    sub ecx, edx
    sub ecx, eax
    mov dword ptr [rsp+168h], ecx
    or ecx, -2B8581F6h
    mov dword ptr [rsp+490h], ecx
    mov eax, dword ptr [dword_7FF85723AA44]
    lea ecx, [rax+7CFD5D9Ch]
    mov edx, ecx
    xor edx, eax
    xor edx, ecx
    xor ecx, 154986E1h
    lea r8d, [rcx-69177156h]
    xor r8d, 5942D7C2h
    add r8d, -0D35B1B8h
    xor edx, r8d
    xor edx, 1E9D0FADh
    sub edx, eax
    add edx, -3C60004Fh
    loc_7FF85682900C:
    xor edx, ecx
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF856829017:
    mov eax, dword ptr [dword_7FF85723AAF0]
    lea ecx, [rax-5E8C9447h]
    xor ecx, 7D648055h
    lea edx, [rcx+33E8FFEBh]
    mov r8d, edx
    xor r8d, -5C47868Dh
    add ecx, -55564F9Eh
    xor ecx, edx
    xor edx, 72BBDC28h
    sub ecx, r8d
    sub ecx, eax
    add ecx, edx
    mov dword ptr [rsp+3Ch], ecx
    jmp loc_7FF856813884
    loc_7FF856829057:
    mov eax, dword ptr [dword_7FF85723AA68]
    mov ecx, 9E81672h
    xor eax, ecx
    lea ecx, [rax-30BC8914h]
    lea edx, [rax-41D5A5B1h]
    xor edx, ecx
    sub edx, eax
    add edx, -34D11A3Ch
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF856829083:
    mov dword ptr [rsp+2D4h], 0
    mov eax, dword ptr [dword_7FF85723AAA0]
    lea ecx, [rax+319B2C7Ah]
    mov edx, ecx
    xor edx, -7BE6285Ah
    add edx, -5932B137h
    xor ecx, -6A052167h
    sub ecx, eax
    xor ecx, edx
    add ecx, 370E7DCEh
    mov dword ptr [rsp+3Ch], ecx
    jmp loc_7FF856813884
    loc_7FF8568290C1:
    mov rax, qword ptr [rsp+348h]
    movzx eax, byte ptr [rax+2]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    shl eax, 10h
    mov dword ptr [rsp+2D4h], eax
    loc_7FF856829142:
    mov rax, qword ptr [rsp+348h]
    movzx eax, byte ptr [rax+1]
    shl eax, 8
    or eax, dword ptr [rsp+2D4h]
    mov dword ptr [rsp+2D0h], eax
    loc_7FF85682915F:
    mov rax, qword ptr [rsp+348h]
    movzx ecx, byte ptr [rax]
    xor ecx, dword ptr [rsp+2D0h]
    mov edx, dword ptr [dword_7FF8571CC8F8]
    mov r8d, edx
    mov r9d, edx
    mov r10d, edx
    mov eax, -59E720E7h
    sub eax, edx
    not edx
    and edx, 72C89FC3h
    lea edx, [rdx+rdx*4]
    or r8d, -0D37603Dh
    lea r8d, [r8+r8*2]
    and r9d, 0D37603Ch
    and r10d, -0D37603Dh
    lea r10d, [r10+r10*8]
    lea r9d, [r10+r9*4]
    sub r9d, r8d
    lea r8d, [r9+rdx*2]
    add r8d, 4F4C416Eh
    lea edx, [r9+rdx*2]
    add edx, -4230B854h
    mov r9d, edx
    xor eax, edx
    not edx
    lea r10d, [rdx+rdx]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r11d, edx
    and r11d, 2D63EC8Fh
    and edx, 529C1370h
    and r9d, -2D63EC90h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea edx, [r9+rdx*2]
    add edx, r11d
    sub r10d, edx
    xor eax, r8d
    add eax, r10d
    imul eax, ecx
    imul edx, ecx, 16A88000h
    mov ecx, dword ptr [dword_7FF8571CC8FC]
    mov r8d, ecx
    not r8d
    mov r9d, r8d
    and r9d, -26A6F124h
    lea r9d, [r9+r9*2]
    and r8d, 26A6F123h
    lea r8d, [r8+r8*4]
    mov r10d, ecx
    xor r10d, 59590EDCh
    add r10d, r10d
    mov r11d, ecx
    and r11d, 6A6F123h
    shl r11d, 3
    sub r11d, r10d
    add r11d, r8d
    lea r8d, [r11+r9]
    add r8d, 3EBD4A51h
    mov r9d, r8d
    xor r9d, -1AA4EA69h
    lea r10d, [r9-4CC39DA4h]
    mov r11d, r10d
    xor r11d, -5EE3B94Fh
    neg r11d
    add ecx, r11d
    add ecx, 1532A25Fh
    xor ecx, r8d
    sub ecx, r10d
    xor ecx, r9d
    shr eax, cl
    or eax, edx
    imul eax, 1B873593h
    xor eax, dword ptr [rsp+17Ch]
    mov dword ptr [rsp+184h], eax
    mov rcx, qword ptr [qword_7FF8571CC900]
    mov rdx, rcx
    mov rax, 1C09B726E31B1CF3h
    xor rdx, rax
    mov rax, -2C2D92C1322373B3h
    lea r8, [rdx+rax]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rax, -51F315A677147764h
    sub rax, rdx
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
    xor rax, r8
    sub rax, r8
    mov rdx, 33948E68361EBF7Fh
    add rax, rdx
    xor rax, rcx
    mov r8, qword ptr [qword_7FF8571CC908]
    mov rdx, r8
    mov rcx, -4E8B0C93DA85016h
    xor rdx, rcx
    mov rcx, 7154908F41FEF67Ch
    add rcx, rdx
    mov r9, rcx
    mov r10, -367C738B7CA2CB42h
    xor r9, r10
    mov r10, r9
    mov r11, 23187675878E0E18h
    and r10, r11
    mov r11, r9
    mov rsi, -23187675878E0E19h
    and r11, rsi
    lea r11, [r11+r11*8]
    lea r10, [r11+r10*4]
    mov r11, rcx
    mov rdi, 12E96089DCBACBD8h
    xor rcx, rdi
    add rcx, r8
    xor rcx, r9
    or r9, rsi
    lea r8, [r9+r9*2]
    sub r10, r8
    mov r8, 1464018A7820C141h
    xor r11, r8
    mov r8, 5CE7898A7871F1E7h
    and r11, r8
    lea r8, [r11+r11*4]
    lea r8, [r10+r8*2]
    add rcx, r8
    and rax, qword ptr [rsp+58h]
    sub rcx, rdx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov rdx, 1609682865F794DDh
    add rcx, rdx
    cmp rax, rcx
    jnz loc_7FF8568296FC
    mov eax, dword ptr [dword_7FF85723AAC4]
    lea ecx, [rax+3D1492FCh]
    xor ecx, -25EE91D8h
    lea edx, [rcx-2D97F642h]
    xor edx, 6346339Bh
    sub edx, ecx
    sub edx, eax
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF8568296FC:
    mov eax, dword ptr [dword_7FF85723AAA8]
    lea ecx, [rax+1839E132h]
    mov edx, -56412B6Dh
    sub edx, eax
    xor edx, ecx
    xor edx, eax
    xor edx, 1B2047A8h
    mov dword ptr [rsp+3Ch], edx
    jmp loc_7FF856813884
    loc_7FF856829722:
    mov dword ptr [rsp+2D0h], 0
    jmp loc_7FF85682915F
    def_7FF85681D630:
    mov eax, dword ptr [dword_7FF85723AAC8]
    mov ecx, 15545257h
    add eax, ecx
    xor eax, 0B048C6Ch
    jmp loc_7FF856813880
    loc_7FF856829749:
    mov eax, dword ptr [dword_7FF85723AA78]
    lea ecx, [rax-6CBBCE0Bh]
    lea edx, [rax-0D691769h]
    lea r8d, [rax-69BBE118h]
    xor r8d, ecx
    lea ecx, [rax+3C7EFC59h]
    lea r9d, [rax+17E05C76h]
    xor r9d, edx
    xor r9d, ecx
    sub r9d, eax
    add r9d, 11CD47E0h
    xor r9d, r8d
    sub r9d, eax
    add r9d, 79AD90D9h
    mov dword ptr [rsp+3Ch], r9d
    jmp loc_7FF856813884
    loc_7FF856829799:
    mov dword ptr [rsp+324h], 0
    mov eax, dword ptr [dword_7FF85723AB24]
    lea ecx, [rax-511180Ch]
    xor ecx, 40A06629h
    add ecx, eax
    neg ecx
    add eax, ecx
    add eax, 5915E008h
    jmp loc_7FF856813880
    loc_7FF8568297C6:
    mov rax, qword ptr [rsp+358h]
    movzx eax, byte ptr [rax+2]
    mov dword ptr [rsp+4D8h], eax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [dword_7FF8571CC868]
    mov eax, ecx
    not eax
    and eax, 6D57796Ch
    lea eax, [rax+rax*2]
    lea edx, [rcx+rcx]
    or edx, -25510D28h
    lea edx, [rdx+rdx*2]
    mov r8d, ecx
    xor r8d, -6D57796Dh
    mov r9d, ecx
    and r9d, 6D57796Ch
    lea r9d, [r9+r9*2]
    add r9d, r9d
    and ecx, 12A88693h
    lea ecx, [rcx+rcx*2]
    lea ecx, [r9+rcx*2]
    add ecx, r8d
    sub ecx, edx
    lea edx, [rcx+rax*2]
    mov dword ptr [rsp+4DCh], edx
    lea edx, [rcx+rax*2]
    add edx, 193A13A4h
    mov dword ptr [rsp+4E0h], edx
    lea eax, [rcx+rax*2+4B4468E6h]
    mov dword ptr [rsp+4E4h], eax
    mov ecx, eax
    not ecx
    mov edx, ecx
    and edx, 405E5EA6h
    mov dword ptr [rsp+4E8h], edx
    mov edx, ecx
    and edx, 3FA1A159h
    shl edx, 2
    mov dword ptr [rsp+4ECh], edx
    add ecx, ecx
    or ecx, -7F4342B4h
    mov dword ptr [rsp+4F0h], ecx
    and eax, -405E5EA7h
    neg eax
    mov dword ptr [rsp+4F4h], eax
    mov eax, dword ptr [dword_7FF85723AAF4]
    lea ecx, [rax+rax]
    add ecx, eax
    add ecx, 357CDD3h
    add eax, 53BFF1D5h
    jmp loc_7FF856825DF5
    loc_7FF85682990C:
    mov ecx, dword ptr [rsp+88h]
    mov edx, dword ptr [rsp+8Ch]
    mov dword ptr [rsp+1E0h], ecx
    mov dword ptr [rsp+1E4h], edx
    mov qword ptr [rsp+608h], 0
    nop word ptr [rax+rax+00000000h]
    loc_7FF856829940:
    mov rdx, qword ptr [rsp+608h]
    mov r9d, dword ptr [rsp+1E4h]
    mov r8d, dword ptr [rsp+1E0h]
    mov r10, qword ptr [rsp+0D8h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov ecx, dword ptr [r10+rdx*4]
    xor ecx, dword ptr [r9+r13]
    mov dword ptr [r10+rdx*4], ecx
    mov r10d, dword ptr [dword_7FF8571CC780]
    lea r11d, [r10+618CB3DCh]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov esi, r11d
    or esi, 4DC07B9Ah
    lea edi, [rsi+rsi*2]
    not esi
    lea ebx, [rsi*8]
    sub ebx, esi
    mov esi, r11d
    and esi, 4DC07B9Ah
    lea esi, [rsi+rdi*2]
    add esi, ebx
    mov edi, 50EB36FFh
    sub edi, esi
    mov ebx, edi
    xor ebx, 0B2A2D71h
    lea r14d, [rbx+1E294F46h]
    xor r14d, 26Ah
    mov r15d, edi
    xor r15d, -2D2523B7h
    add ebx, r15d
    add ebx, 1E294F46h
    sub ebx, r11d
    xor ebx, edi
    add r14d, r10d
    add r14d, ebx
    sub r14d, esi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r9d, r14d
    add r9d, -7
    and r9d, 3FFFh
    mov dword ptr [rsp+114h], r9d
    mov r10d, dword ptr [dword_7FF8571CC784]
    mov r11d, r10d
    xor r11d, 31051B40h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov esi, r10d
    xor esi, -41188F54h
    mov r9d, r10d
    xor r9d, -26B3A5FDh
    sub r9d, r11d
    sub r9d, esi
    sub r9d, r10d
    xor r10d, 5CF02B32h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r10d, 3601AC1Fh
    xor r9d, r10d
    imul r9d, ecx
    mov r10d, dword ptr [dword_7FF8571CC788]
    mov r11d, 4795A675h
    add r10d, r11d
    mov r11d, r10d
    not r11d
    mov esi, r10d
    or esi, -51431609h
    and r11d, -51431609h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea edi, [r10+r10]
    mov ebx, r10d
    and ebx, 51431608h
    add ebx, ebx
    sub edi, ebx
    add edi, r11d
    lea r11d, [rdi+rsi]
    lea ebx, [rsi+rdi]
    add ebx, 5143160Ah
    mov esi, ebx
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    and edi, 150E94FCh
    and esi, 2AF16B03h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    shl esi, 2
    mov r14d, ebx
    xor r14d, -6AF16B04h
    mov r15d, ebx
    xor r15d, 2AF16B03h
    mov ebp, ebx
    and ebp, 0AF16B03h
    shl ebp, 3
    and ebx, 150E94FCh
    add ebx, ebx
    sub ebp, ebx
    lea ebx, [r14*8]
    sub r14d, ebx
    add r14d, ebp
    lea ebx, [r14+r15*4]
    sub ebx, esi
    lea esi, [rbx+rdi*8]
    add esi, -71A48442h
    lea edi, [rbx+rdi*8-7EB46397h]
    mov ebx, edi
    not ebx
    mov r14d, edi
    or r14d, 542F25A9h
    and ebx, 542F25A9h
    lea r15d, [rdi+rdi]
    mov ebp, edi
    and ebp, 2BD0DA56h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    sub r15d, ebp
    add r15d, ebx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ebx, [r14+r15]
    add ebx, 0AC3A20Bh
    xor ebx, esi
    add r11d, ebx
    add r11d, 5143160Ah
    add r11d, edi
    add r10d, r11d
    add r10d, 6C11CC43h
    imul r10d, ecx
    mov ecx, dword ptr [dword_7FF8571CC78C]
    mov r11d, ecx
    not r11d
    and r11d, 225C3CE9h
    lea esi, [rcx+rcx]
    or esi, 44B879D2h
    mov edi, ecx
    xor edi, -5DA3C317h
    mov ebx, ecx
    and ebx, 1DA3C316h
    shl ebx, 2
    mov r14d, ecx
    and r14d, 225C3CE9h
    lea ebx, [rbx+r14*2]
    sub ebx, edi
    sub ebx, esi
    lea esi, [rbx+r11*4]
    lea r11d, [rbx+r11*4]
    add r11d, -6072D246h
    mov ebx, r11d
    xor ebx, -5E97AC6Eh
    add ebx, ecx
    sub ebx, esi
    add ebx, 2B609026h
    mov r14d, r11d
    not r14d
    mov ecx, ebx
    or ecx, r14d
    not ecx
    lea esi, [rcx+rcx*4]
    lea edi, [rcx+rsi*4]
    mov esi, ebx
    or esi, r11d
    lea ecx, [rsi+rsi*4]
    lea ecx, [rsi+rcx*2]
    not esi
    lea r15d, [rsi+rsi*4]
    lea esi, [rsi+r15*2]
    and r11d, ebx
    mov r15d, r11d
    not r15d
    lea r12d, [r15+r15*4]
    lea ebp, [r12]
    and r14d, ebx
    lea ebx, [r14+r14*4]
    lea ebx, [r14+rbx*4]
    lea r11d, [r11+r11*8]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add r11d, ebx
    sub ecx, r11d
    add ecx, ebp
    sub ecx, esi
    sub ecx, edi
    shr r9d, cl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or r9d, r10d
    imul ecx, r9d, 1B873593h
    xor ecx, r8d
    rol ecx, 0Dh
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r8d, dword ptr [dword_7FF8571CC790]
    lea r9d, [r8+47FF6282h]
    mov r10d, r9d
    xor r10d, 486E38FDh
    sub r10d, r9d
    add r8d, r10d
    add r8d, -4D5D932Bh
    imul r8d, ecx
    mov r9d, dword ptr [dword_7FF8571CC794]
    mov ecx, -229C47DEh
    add r9d, ecx
    mov ecx, r9d
    xor ecx, -64C55E5Ah
    mov r10d, r9d
    xor r10d, 60004649h
    mov r11d, r9d
    xor r11d, 4C51810h
    and r11d, 0CFFB934h
    and r10d, 730046CBh
    add r10d, r10d
    mov esi, r9d
    xor esi, 683AE76Dh
    mov edi, ecx
    and edi, 730046CBh
    mov ebx, ecx
    and ebx, 0CFFB934h
    lea edi, [rbx+rdi*2]
    sub edi, ecx
    lea esi, [rdi+rsi*2]
    sub esi, r10d
    lea edi, [rsi+r11]
    add edi, 17724A7Ch
    add esi, r11d
    mov r11d, esi
    xor r11d, -4B411D8Eh
    xor esi, 4B411D8Dh
    lea r10d, [rsi*8]
    sub r10d, esi
    mov r14d, r11d
    or r14d, edi
    mov ebx, r11d
    and ebx, edi
    xor ecx, edi
    not edi
    mov esi, r11d
    or esi, edi
    and edi, r11d
    mov r11d, ebx
    add edi, edi
    add ebx, ebx
    sub ebx, edi
    not r11d
    lea r11d, [r11+r11*2]
    add ebx, r11d
    not r14d
    add r14d, r14d
    lea r11d, [r14+r14*4]
    sub ebx, r11d
    not esi
    lea r11d, [rsi+rsi*8]
    sub ebx, r11d
    add ebx, r10d
    xor ecx, r9d
    xor ecx, ebx
    mov r9d, ecx
    xor r9d, 22581978h
    xor ecx, -22581979h
    mov r10d, r8d
    or r9d, r8d
    and r8d, ecx
    mov r11d, r8d
    not r11d
    add r11d, r11d
    sub r11d, r8d
    not r9d
    shl r9d, 2
    sub r11d, r9d
    or r10d, ecx
    add r11d, r10d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea ecx, [r11+rcx*2]
    inc ecx
    mov dword ptr [rsp+118h], ecx
    mov rcx, qword ptr [qword_7FF8571CC798]
    mov r8, rcx
    mov r9, -3233FC0F2CCD0DB4h
    xor r8, r9
    add r8, rcx
    mov r9, -5085DDA33A07FCF2h
    xor rcx, r9
    add rcx, rdx
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
    mov rdx, 3DF976CC9171A0FDh
    add rcx, rdx
    cmp rcx, rax
    jz loc_7FF85682A568
    mov edx, dword ptr [rsp+114h]
    mov r8d, dword ptr [rsp+118h]
    mov dword ptr [rsp+1E0h], r8d
    mov dword ptr [rsp+1E4h], edx
    mov qword ptr [rsp+608h], rcx
    jmp loc_7FF856829940
    loc_7FF85682A568:
    mov eax, dword ptr [dword_7FF85723A9F0]
    mov ecx, eax
    xor ecx, -0EE757EEh
    lea edx, [rcx-1E0AA7BEh]
    mov r8d, edx
    xor r8d, 351EDF14h
    xor eax, r8d
    xor eax, -15EB61ABh
    sub eax, r8d
    xor eax, ecx
    sub eax, ecx
    add eax, -27508673h
    xor eax, edx
    loc_7FF85682A59C:
    mov dword ptr [rsp+3Ch], eax
    mov r12, qword ptr [rsp+328h]
    jmp loc_7FF856813884
    loc_7FF85682A5AD:
    mov dword ptr [rsp+320h], 0
    mov eax, dword ptr [dword_7FF85723AB00]
    mov ecx, eax
    xor ecx, -4BF54527h
    add eax, ecx
    add eax, 5A1687FEh
    add eax, ecx
    add eax, -22BDDD79h
    jmp loc_7FF856813880
    loc_7FF85682A5D9:
    mov rdx, qword ptr [rsp+50h]
    sub rdx, rax
    mov r8, qword ptr [rsp+0D8h]
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
    movzx eax, byte ptr [r13+rcx+0]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor byte ptr [r8+rdx], al
    mov rax, qword ptr [rsp+390h]
    movzx eax, byte ptr [rax+2]
    shl eax, 10h
    mov dword ptr [rsp+1F4h], eax
    jmp loc_7FF85681B1CC
    loc_7FF85682A6DB:
    mov eax, 0AF6E099h
    xor eax, dword ptr [dword_7FF8571CC818]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r8d, [rax+11826431h]
    lea edx, [rax+527F19DAh]
    lea ecx, [rax-531531C7h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r10d, [rax+585DABDBh]
    xor r10d, edx
    lea edx, [rax-2D47960Eh]
    mov r9d, edx
    xor r9d, -36562DF3h
    xor r10d, 65349FDh
    mov r11d, r8d
    not r11d
    mov esi, r10d
    or esi, r11d
    not esi
    lea edi, [rsi+rsi*4]
    lea esi, [rsi+rdi*2]
    mov edi, r10d
    or edi, r8d
    lea ebx, [rdi+rdi*4]
    lea edi, [rdi+rbx*2]
    mov ebx, r10d
    xor ebx, r8d
    and r11d, r10d
    lea r11d, [r11+r11*8]
    and r10d, r8d
    imul r8d, r10d, 0F5h
    sub r8d, r11d
    sub r8d, ebx
    add r8d, edi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r8d, esi
    sub r8d, r9d
    add r8d, eax
    xor edx, ecx
    xor edx, r8d
    mov ecx, 3Ch
    mov r8d, 3Eh
    mov r9d, 6
    call Eidolon_UpdateSharedStateIfSentinelMatches
    loc_7FF85682A8AF:
    mov byte ptr [r12+58h], 96h
    jmp loc_7FF85682ABF6
    loc_7FF85682A8BA:
    mov edx, dword ptr [rsp+4CCh]
    sub edx, dword ptr [rsp+4C8h]
    sub edx, dword ptr [rsp+4C4h]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add edx, dword ptr [rsp+4C0h]
    add edx, dword ptr [rsp+4BCh]
    xor edx, dword ptr [rsp+4B8h]
    xor edx, dword ptr [rsp+4B4h]
    xor edx, dword ptr [rsp+4B0h]
    mov ecx, 0Fh
    mov r8d, 3Fh
    mov r9d, 26h
    call Eidolon_UpdateSharedStateIfSentinelMatches
    loc_7FF85682A950:
    cmp dword ptr [rsp+60h], 1
    jz loc_7FF85682ABB1
    mov eax, dword ptr [dword_7FF8571CC9C0]
    mov r8d, eax
    not r8d
    mov ecx, r8d
    and ecx, 2DBF2406h
    lea ecx, [rcx+rcx*2]
    mov edx, r8d
    and edx, 1240DBF9h
    shl edx, 2
    or r8d, 2DBF2406h
    sub r8d, eax
    sub r8d, eax
    sub r8d, edx
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub r8d, ecx
    lea ecx, [r8-3]
    mov edx, ecx
    not edx
    mov r9d, edx
    and r9d, 7753664Ch
    lea r9d, [r9+r9*2]
    mov r10d, edx
    and r10d, 8AC99B3h
    shl r10d, 2
    or edx, 7753664Ch
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lea r8d, 0FFFFFFFFFFFFFFFAh[r8*2]
    sub edx, r8d
    sub edx, r10d
    sub edx, r9d
    lea r8d, [rdx-3]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov r9d, r8d
    not r9d
    lea r10d, [r9+r9]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    and r11d, -26749B89h
    and r9d, 26749B88h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and r8d, 26749B88h
    lea r8d, [r8+r9*2]
    add r8d, r11d
    sub r8d, r10d
    add r8d, -2E32EE7Fh
    mov r9d, 54DFAFACh
    sub r9d, edx
    xor r9d, r8d
    sub r9d, eax
    sub r9d, ecx
    mov ecx, 2Dh
    mov edx, 2Ch
    mov r8d, 38h
    call Eidolon_ForwardDynamicKeyToProtectionEvent
    loc_7FF85682ABB1:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    loc_7FF85682ABF6:
    mov rcx, qword ptr [rsp+500h]
    call qword ptr [__imp_RtlReleaseSRWLockExclusive]
    nop
    add rsp, 8B8h
    pop rbx
    pop rbp
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    ret
    loc_7FF85682AC19:
    mov rcx, qword ptr [rsp+500h]
    add rsp, 8B8h
    pop rbx
    pop rbp
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    jmp qword ptr [__imp_RtlReleaseSRWLockExclusive]
    loc_7FF85682AC3B:
    int 3
_TEXT ENDS
END

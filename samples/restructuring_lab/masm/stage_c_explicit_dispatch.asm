; Stage C acceptance fixture: a small flattened state machine whose handlers
; all end in explicit native jumps.  The dispatcher uses direct conditional
; branches and large OLLVM-style state constants so IDA owns every target and
; D810's normal state-transition recovery can identify the routes.

OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_DATA SEGMENT ALIGN(16) 'DATA'
lab_stage_c_sink DWORD 0
_DATA ENDS

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC lab_stage_c_explicit_dispatch
lab_stage_c_explicit_dispatch:
    sub     rsp, 8
    mov     DWORD PTR [rsp], 0C6685257h
    xor     eax, eax
    jmp     stage_c_dispatch
    int     3
    ALIGN 4

stage_c_dispatch:
    mov     ecx, DWORD PTR [rsp]
    cmp     ecx, 0C6685257h
    je      stage_c_h0
    cmp     ecx, 0B92456DEh
    je      stage_c_h1
    cmp     ecx, 03C8960A9h
    je      stage_c_h2
    jmp     stage_c_done

stage_c_h0:
    add     eax, 011h
    mov     DWORD PTR [lab_stage_c_sink], eax
    mov     DWORD PTR [rsp], 0B92456DEh
    jmp     stage_c_dispatch

stage_c_h1:
    xor     eax, 022h
    mov     DWORD PTR [lab_stage_c_sink], eax
    mov     DWORD PTR [rsp], 03C8960A9h
    jmp     stage_c_dispatch

stage_c_h2:
    sub     eax, 033h
    mov     DWORD PTR [lab_stage_c_sink], eax
    mov     DWORD PTR [rsp], 01A2B3C4Dh
    jmp     stage_c_dispatch

stage_c_done:
    add     rsp, 8
    ret
_TEXT ENDS
END

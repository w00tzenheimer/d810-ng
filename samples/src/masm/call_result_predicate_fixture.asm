; Native call-result predicate regression fixture.
; Keep the call result and the later eax load physically distinct: the
; optimizer must treat the assigned call as a terminal value definition.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_TEXT SEGMENT ALIGN(16) 'CODE'
; D810_EXPORT call_result_predicate_helper
PUBLIC call_result_predicate_helper
call_result_predicate_helper:
    mov eax, 40h
    ret

PUBLIC call_result_predicate_fixture
call_result_predicate_fixture:
    ; 32-byte shadow space plus 8-byte alignment adjustment for the call.
    sub rsp, 28h
    call call_result_predicate_helper

    ; The ECX shift is a deliberate decoy.  The predicate uses the call
    ; result in EAX, while the later load is a separate physical EAX write.
    mov ecx, eax
    shr ecx, 0Ah
    shr eax, 6
    and eax, 1
    cmp eax, ecx
    jne short call_result_predicate_taken
    mov eax, DWORD PTR call_result_later_value
    ; Keep the decoy ECX definition live in the materializable path.
    add eax, ecx
    jmp short call_result_predicate_done

call_result_predicate_taken:
    xor eax, eax

call_result_predicate_done:
    add rsp, 28h
    ret
_TEXT ENDS

CONST SEGMENT ALIGN(4) 'DATA'
call_result_later_value DWORD 12345678h
CONST ENDS
END

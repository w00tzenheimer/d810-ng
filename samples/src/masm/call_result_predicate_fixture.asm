; Native call-result predicate regression fixture.
; Keep the call result and the later eax load physically distinct: the
; optimizer must treat the assigned call as a terminal value definition.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_TEXT SEGMENT ALIGN(16) 'CODE'
; D810_EXPORT call_result_predicate_helper
PUBLIC call_result_predicate_helper
call_result_predicate_helper:
    ; Deliberately opaque to the caller: production fact injection supplies
    ; the result bits, while the no-fact route must retain the branch.
    mov eax, ecx
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
    ; The branch predicate is the call-result bit itself.  ECX remains a
    ; deliberately live decoy in the later materializable path.
    cmp eax, 0
    ; Keep a materialized setnz candidate for the production Z3 rule.  SETNZ
    ; does not alter flags, so the following JNE remains the actual branch on
    ; the EAX predicate above.
    setnz dl
    movzx edx, dl
    jne short call_result_predicate_taken
    mov eax, DWORD PTR call_result_later_value
    ; Keep the decoy ECX definition live in the materializable path.
    add eax, ecx
    add eax, edx
    jmp short call_result_predicate_done

call_result_predicate_taken:
    mov eax, 0CAFEBABEh

call_result_predicate_done:
    add rsp, 28h
    ret
_TEXT ENDS

; This witness must remain writable so Hex-Rays cannot constant-fold the later
; load.  The call-result regression relies on observing the distinct EAX write.
_DATA SEGMENT
call_result_later_value DWORD 12345678h
_DATA ENDS
END

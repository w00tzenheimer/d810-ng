; Purpose-built x64 MASM fixtures for ticket d81-czrc: COMPUTED dispatcher
; state writes in a signed comparison-tree ("BST") flattening dispatcher.
;
; Both functions reproduce the writer shape measured on sub_7FFB0E398850, where
; 6 of its 75 writes to the state slot are not literals at all::
;
;     blk36:   mov #0xA84A23E8, ecx ; mov #0xBA1637C8, eax ; goto @136
;     blk135:  mov #0x5FDB1F09, ecx ; mov #0x1D431D66, eax
;     blk136:  xor ecx, eax -> %var_438 ; goto @5
;
; The next state is split across two registers that each predecessor sets to
; its own constant, and recombined in a shared block.  A literal scan of the
; state slot returns nothing for that block, so those states are ABSENT from
; the written-state set -- and "absent" is precisely what a range leaf's
; exactness proof reads as "no second state can occur in this interval".
; Resolving the write means partitioning by predecessor and folding once per
; incoming edge; joining the operand environments first would either collapse
; each register to unknown or manufacture the cross products K1^K4 / K3^K2,
; which no path produces.
;
; computed_state_writer_isolated   (POSITIVE)
;   Three states, three wide leaves, one state per leaf.  The transitions out
;   of leaf A and leaf B are BOTH computed in the shared block rlcw_compute,
;   whose two predecessors set ecx / r8d to constants:
;       0A84A23E8h xor 097801583h = 03FCA366Bh   (from leaf A)
;       05FDB1F09h xor 0296AB231h = 076B1AD38h   (from leaf B)
;   Every operand on every incoming edge is a provable constant, so the
;   computed writer resolves and the written-state set is COMPLETE.
;
; computed_state_writer_unresolved (NEGATIVE CONTROL)
;   Identical shape, except leaf B loads ecx from the caller's argument
;   instead of a literal.  One partition therefore binds a non-constant
;   operand, the resolver must ABSTAIN for the whole write (a partial value
;   set is an under-approximation, which is the unsound direction), the
;   written-state set stays INCOMPLETE and any closed-world range-leaf
;   reasoning must keep refusing.  If a future change starts reporting this
;   one as resolved, the all-or-nothing rule has been weakened into a guess.
;
; State slot: [rsp+8] (32-bit).  All three constants are >= 0x01000000 so they
; are recognised as selector values, and all positive as signed 32-bit so the
; signed comparison tree partitions them in sorted order:
;   0x1CAFDDE5 < 0x3FCA366B < 0x76B1AD38
; Pivots 0x2FFFFFFF and 0x5FFFFFFF put each state in its own wide leaf, so
; NO row of the recovered interval table is a width-1 singleton.

OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_TEXT SEGMENT ALIGN(16) 'CODE'

; Read-only probe.  Its only job is to make the caller's state slot
; address-taken so Hex-Rays cannot promote it to a register and constant-fold
; the whole dispatcher away.  It never writes through the pointer, so the
; recovered state machine stays sound.
PUBLIC d810_state_peek_czrc
d810_state_peek_czrc:
    mov     eax, dword ptr [rcx]
    ret


; D810_EXPORT computed_state_writer_isolated
PUBLIC computed_state_writer_isolated
computed_state_writer_isolated:
    sub     rsp, 40
    mov     dword ptr [rsp+8], 01CAFDDE5h      ; initial state
    mov     dword ptr [rsp+16], ecx            ; keep the argument
    lea     rcx, [rsp+8]
    call    d810_state_peek_czrc               ; escape the slot's address
    mov     eax, dword ptr [rsp+16]            ; accumulator seeded from arg

rlcw_dispatch:
    mov     edx, dword ptr [rsp+8]
    cmp     edx, 02FFFFFFFh
    jg      rlcw_right
    ; leaf A: (-inf, 0x30000000) -- contains only 0x1CAFDDE5
    add     eax, 11h
    xor     eax, 5A5A5A5Ah
    mov     ecx, 0A84A23E8h                    ; operand half 1 (edge A)
    mov     r8d, 097801583h                    ; operand half 2 (edge A)
    jmp     rlcw_compute

rlcw_right:
    cmp     edx, 05FFFFFFFh
    jg      rlcw_leaf_c
    ; leaf B: [0x30000000, 0x60000000) -- contains only 0x3FCA366B
    imul    eax, eax, 25h
    add     eax, 7h
    mov     ecx, 05FDB1F09h                    ; operand half 1 (edge B)
    mov     r8d, 0296AB231h                    ; operand half 2 (edge B)
    jmp     rlcw_compute

; The shared recombination block: two predecessors, one computed write.
; Nothing here names a state constant -- a literal scan of [rsp+8] sees a
; register, not a number.
rlcw_compute:
    xor     ecx, r8d
    mov     dword ptr [rsp+8], ecx
    jmp     rlcw_dispatch

rlcw_leaf_c:
    ; leaf C: [0x60000000, +inf) -- contains only 0x76B1AD38; terminal
    sub     eax, 3h
    add     rsp, 40
    ret


; D810_EXPORT computed_state_writer_unresolved
PUBLIC computed_state_writer_unresolved
computed_state_writer_unresolved:
    sub     rsp, 40
    mov     dword ptr [rsp+8], 01CAFDDE5h      ; initial state
    mov     dword ptr [rsp+16], ecx
    lea     rcx, [rsp+8]
    call    d810_state_peek_czrc
    mov     eax, dword ptr [rsp+16]

rucw_dispatch:
    mov     edx, dword ptr [rsp+8]
    cmp     edx, 02FFFFFFFh
    jg      rucw_right
    ; leaf A: same fully-constant edge as the positive fixture
    add     eax, 11h
    xor     eax, 5A5A5A5Ah
    mov     ecx, 0A84A23E8h
    mov     r8d, 097801583h
    jmp     rucw_compute

rucw_right:
    cmp     edx, 05FFFFFFFh
    jg      rucw_leaf_c
    ; leaf B: ecx comes from the ARGUMENT, not a literal.  This partition
    ; cannot be bound to a constant, so the whole computed write must abstain.
    imul    eax, eax, 25h
    add     eax, 7h
    mov     ecx, dword ptr [rsp+16]            ; NON-constant operand half 1
    mov     r8d, 0296AB231h
    jmp     rucw_compute

rucw_compute:
    xor     ecx, r8d
    mov     dword ptr [rsp+8], ecx
    jmp     rucw_dispatch

rucw_leaf_c:
    sub     eax, 3h
    add     rsp, 40
    ret

; The corpus build exports one symbol named after the source file; make that a
; real function rather than an unresolved forwarder.  It keeps both fixtures
; reachable from a single entry point and is itself unflattened (no dispatcher),
; so it adds no assertion surface of its own.
; D810_EXPORT computed_state_writers
PUBLIC computed_state_writers
computed_state_writers:
    sub     rsp, 40
    mov     dword ptr [rsp+32], ecx
    call    computed_state_writer_isolated
    mov     dword ptr [rsp+36], eax
    mov     ecx, dword ptr [rsp+32]
    call    computed_state_writer_unresolved
    add     eax, dword ptr [rsp+36]
    add     rsp, 40
    ret

_TEXT ENDS
END

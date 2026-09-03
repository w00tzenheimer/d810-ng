; Purpose-built x64 MASM fixtures for ticket d81-8xhg: range-leaf route
; exactness in a comparison-tree ("BST") flattening dispatcher.
;
; Both functions are flattened with the SAME dispatcher shape measured on
; sub_7FFB0E398850 (loader 12.1.0.69587): the dispatcher is a signed
; comparison tree, not an equality chain, so every recovered interval row is a
; WIDE [lo, hi) leaf and NOT a width-1 singleton.  Judging route exactness by
; interval width therefore refuses every leaf, the function-entry bridge for
; the initial state can never be built, and the emitter bails with
;   "BAILED (no entry bridge: initial_state=...)".
;
; range_leaf_isolated_state  (POSITIVE)
;   Three handler states, three leaves.  Each leaf's interval contains exactly
;   ONE of the constants the function ever writes to the state slot, so each
;   leaf is an unambiguous binding and the whole chain must unflatten.
;
; range_leaf_shared_corridor (NEGATIVE CONTROL)
;   Same shape, but TWO written constants (0x1CAFDDE5 and 0x1CAFDDE6) land in
;   the leaf that covers the initial state.  That leaf is a genuinely shared
;   corridor: it must stay refused, the entry bridge must stay unbuilt, and the
;   dispatcher must survive.  If a future change starts accepting this one, the
;   exactness rule has been widened into a guess.
;
; State slot: [rsp+8] (32-bit).  Constants are all >= 0x01000000 so they are
; recognised as selector values, and all positive as signed 32-bit so the
; signed comparison tree partitions them in sorted order:
;   0x1CAFDDE5 < 0x1CAFDDE6 < 0x3FCA366B < 0x76B1AD38
; Pivots 0x2FFFFFFF and 0x5FFFFFFF put each state in its own wide leaf.

OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_TEXT SEGMENT ALIGN(16) 'CODE'

; Read-only probe.  Its only job is to make the caller's state slot
; address-taken so Hex-Rays cannot promote it to a register and constant-fold
; the whole dispatcher away.  It never writes through the pointer, so the
; recovered state machine stays sound.
PUBLIC d810_state_peek
d810_state_peek:
    mov     eax, dword ptr [rcx]
    ret


; D810_EXPORT range_leaf_isolated_state
PUBLIC range_leaf_isolated_state
range_leaf_isolated_state:
    sub     rsp, 40
    mov     dword ptr [rsp+8], 01CAFDDE5h      ; initial state
    mov     dword ptr [rsp+16], ecx
    lea     rcx, [rsp+8]
    call    d810_state_peek                 ; escape the slot's address
    mov     eax, dword ptr [rsp+16]                            ; accumulator seeded from arg

rlis_dispatch:
    mov     edx, dword ptr [rsp+8]
    cmp     edx, 02FFFFFFFh
    jg      rlis_right
    ; leaf A: (-inf, 0x30000000) -- contains only 0x1CAFDDE5
    add     eax, 11h
    xor     eax, 5A5A5A5Ah
    mov     dword ptr [rsp+8], 03FCA366Bh
    jmp     rlis_dispatch

rlis_right:
    cmp     edx, 05FFFFFFFh
    jg      rlis_leaf_c
    ; leaf B: [0x30000000, 0x60000000) -- contains only 0x3FCA366B
    imul    eax, eax, 25h
    add     eax, 7h
    mov     dword ptr [rsp+8], 076B1AD38h
    jmp     rlis_dispatch

rlis_leaf_c:
    ; leaf C: [0x60000000, +inf) -- contains only 0x76B1AD38; terminal
    sub     eax, 3h
    add     rsp, 40
    ret

; D810_EXPORT range_leaf_shared_corridor
PUBLIC range_leaf_shared_corridor
range_leaf_shared_corridor:
    sub     rsp, 40
    mov     dword ptr [rsp+8], 01CAFDDE5h      ; initial state
    mov     dword ptr [rsp+16], ecx
    lea     rcx, [rsp+8]
    call    d810_state_peek                 ; escape the slot's address
    mov     eax, dword ptr [rsp+16]

rlsc_dispatch:
    mov     edx, dword ptr [rsp+8]
    cmp     edx, 02FFFFFFFh
    jg      rlsc_right
    ; leaf A: (-inf, 0x30000000) -- contains BOTH 0x1CAFDDE5 and 0x1CAFDDE6.
    ; Shared corridor: no exact binding for either state.
    add     eax, 11h
    xor     eax, 5A5A5A5Ah
    cmp     eax, 0h
    jle     rlsc_second_pass
    mov     dword ptr [rsp+8], 01CAFDDE6h
    jmp     rlsc_dispatch

rlsc_second_pass:
    mov     dword ptr [rsp+8], 03FCA366Bh
    jmp     rlsc_dispatch

rlsc_right:
    cmp     edx, 05FFFFFFFh
    jg      rlsc_leaf_c
    ; leaf B: [0x30000000, 0x60000000) -- contains only 0x3FCA366B
    imul    eax, eax, 25h
    add     eax, 7h
    mov     dword ptr [rsp+8], 076B1AD38h
    jmp     rlsc_dispatch

rlsc_leaf_c:
    sub     eax, 3h
    add     rsp, 40
    ret

_TEXT ENDS
END

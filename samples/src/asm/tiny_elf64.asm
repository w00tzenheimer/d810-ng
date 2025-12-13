; Taken from: ida-domain/blob/225410d33a4c3c636c15b985ce8ab86c9944cc3d/tests/resources/tiny.asm
; This is a test file for the IDA Pro assembler.
; It is used to test the assembler's ability to handle all types of operands.
; It is not used for any other purpose.
; nasm -f elf64 tiny.asm -o tiny.bin

BITS 64

section .text
    global _main

_main:
    ; Print "Hello, IDA!"
    mov     rax, 1              ; syscall: sys_write
    mov     rdi, 1              ; file descriptor (stdout)
    lea     rsi, [rel hello]    ; Load string address
    mov     rdx, hello_len      ; String length
    syscall

    ; =================================================================
    ; COMPREHENSIVE OPERAND TYPE TESTING SECTION
    ; =================================================================
    call    test_all_operand_types

    ; Perform addition: add_numbers(5, 10)
    mov     rdi, 5
    mov     rsi, 10
    call    add_numbers
    mov     r12, rax            ; Store sum result

    ; Print "Sum: "
    mov     rax, 1
    mov     rdi, 1
    lea     rsi, [rel sum_str]
    mov     rdx, sum_len
    syscall

    ; Print sum result
    mov     rdi, r12
    call    print_number

    ; Print newline
    mov     rax, 1
    mov     rdi, 1
    lea     rsi, [rel newline]
    mov     rdx, newline_len
    syscall

    ; Perform multiplication: multiply_numbers(5, 10)
    mov     rdi, 5
    mov     rsi, 10
    call    multiply_numbers
    mov     r12, rax            ; Store product result

    ; Print "Product: "
    mov     rax, 1
    mov     rdi, 1
    lea     rsi, [rel product_str]
    mov     rdx, product_len
    syscall

    ; Print product result
    mov     rdi, r12
    call    print_number

    ; Print newline
    mov     rax, 1
    mov     rdi, 1
    lea     rsi, [rel newline]
    mov     rdx, newline_len
    syscall

    ; Test call hierarchy
    call    level1_func

    ; Exit
    mov     rax, 60             ; syscall: exit
    xor     rdi, rdi
    syscall

; =================================================================
; COMPREHENSIVE OPERAND TESTING FUNCTION
; =================================================================
test_all_operand_types:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15

    ; === 1. REGISTER TO REGISTER OPERANDS ===
    mov     rax, rbx            ; reg64 to reg64
    mov     eax, ebx            ; reg32 to reg32
    mov     ax, bx              ; reg16 to reg16
    mov     al, bl              ; reg8 to reg8
    movzx   rax, ax             ; zero extend reg16 to reg64
    movsx   rax, eax            ; sign extend reg32 to reg64

    ; === 2. IMMEDIATE OPERANDS ===
    mov     rax, 0x1234567890ABCDEF    ; 64-bit immediate
    mov     eax, 0x12345678            ; 32-bit immediate
    mov     ax, 0x1234                 ; 16-bit immediate
    mov     al, 0x12                   ; 8-bit immediate
    add     rax, 42                    ; immediate arithmetic
    cmp     rax, -1                    ; signed immediate

    ; === 3. DIRECT MEMORY OPERANDS ===
    mov     rax, [rel test_data]           ; direct memory access
    mov     eax, [rel test_data]           ; 32-bit direct memory
    mov     ax, [rel test_data]            ; 16-bit direct memory
    mov     al, [rel test_data]            ; 8-bit direct memory

    ; === 4. REGISTER INDIRECT OPERANDS ===
    lea     rbx, [rel test_data]
    mov     rax, [rbx]                 ; simple register indirect
    mov     eax, [rbx]                 ; 32-bit register indirect
    mov     [rbx], rax                 ; write to register indirect

    ; === 5. DISPLACEMENT OPERANDS (register + offset) ===
    mov     rax, [rbp + 8]             ; positive displacement
    mov     rax, [rbp - 8]             ; negative displacement
    mov     rax, [rsp + 16]            ; stack with displacement
    mov     [rbp - 16], rax            ; write with displacement
    mov     eax, [rbx + 4]             ; 32-bit with displacement

    ; === 6. SIB OPERANDS (Scale-Index-Base) ===
    lea     rsi, [rel test_array]
    mov     rdi, 0                     ; index = 0

    ; Simple SIB: [base + index]
    mov     rax, [rsi + rdi]           ; [base + index], scale=1
    mov     rax, [rsi + rdi * 1]       ; explicit scale=1

    ; SIB with scale factors
    mov     rax, [rsi + rdi * 2]       ; [base + index*2]
    mov     rax, [rsi + rdi * 4]       ; [base + index*4]
    mov     rax, [rsi + rdi * 8]       ; [base + index*8]

    ; SIB with displacement
    mov     rax, [rsi + rdi * 2 + 8]   ; [base + index*scale + disp]
    mov     rax, [rsi + rdi * 4 - 4]   ; [base + index*scale - disp]

    ; SIB without base (index only)
    mov     rax, [rdi * 2]             ; [index*scale]
    mov     rax, [rdi * 4 + 16]        ; [index*scale + disp]

    ; Complex SIB addressing
    mov     rax, [rbp + rdi * 8 + 0x20] ; [base + index*8 + 32]
    mov     eax, [rbx + rcx * 2 - 8]    ; 32-bit with complex SIB

    ; === 7. DIFFERENT DATA SIZES ===
    ; 8-bit operations
    mov     byte [rel test_data], 0x42
    mov     bl, byte [rel test_data]
    add     byte [rsi + rdi], 1

    ; 16-bit operations
    mov     word [rel test_data], 0x1234
    mov     bx, word [rel test_data]
    add     word [rsi + rdi * 2], 100

    ; 32-bit operations
    mov     dword [rel test_data], 0x12345678
    mov     ebx, dword [rel test_data]
    add     dword [rsi + rdi * 4], 1000

    ; 64-bit operations
    mov     rax, 0x123456789ABCDEF0
    mov     qword [rel test_data], rax
    mov     rbx, qword [rel test_data]
    add     qword [rsi + rdi * 8], 10000

    ; === 8. FLOATING POINT OPERANDS ===
    ; SSE operations
    movss   xmm0, [rel float_val]        ; load 32-bit float
    movsd   xmm1, [rel double_val]       ; load 64-bit double
    movss   [rel temp_float], xmm0       ; store float
    movsd   [rel temp_double], xmm1      ; store double

    ; Packed operations
    movaps  xmm0, [rel vector_data]     ; aligned packed single
    movups  xmm1, [rel vector_data]     ; unaligned packed single

    ; === 9. STRING OPERATIONS ===
    lea     rsi, [rel src_string]
    lea     rdi, [rel dst_string]
    mov     rcx, 16
    rep     movsb                      ; string copy with rep prefix

    ; === 10. CONDITIONAL MOVES ===
    cmp     rax, rbx
    cmove   rcx, rdx                 ; conditional move if equal
    cmovg   rcx, rdx                 ; conditional move if greater

    ; === 11. BIT OPERATIONS ===
    bt      rax, 5                      ; bit test (immediate bit index)
    bt      rax, rcx                    ; bit test (register bit index)
    bts     qword [rel test_data], 3       ; bit test and set

    ; === 12. SEGMENT OVERRIDES (x64 mostly ignores, but valid) ===
    mov     rax, gs:[0x30]             ; segment override

    ; === 13. RIP-RELATIVE ADDRESSING (x64 specific) ===
    mov     rax, [rel test_data]       ; RIP-relative
    lea     rbx, [rel hello]           ; RIP-relative LEA

    ; === 14. JUMP/CALL OPERANDS ===
    ; Note: These won't execute in normal flow, but show operand types
    jmp     skip_jumps

    call    rax                       ; indirect call (register)
    call    [rbx]                     ; indirect call (memory)
    call    [rbx + rcx * 4]           ; indirect call (SIB)
    jmp     rax                        ; indirect jump (register)
    jmp     [rel test_data]                ; indirect jump (memory)

skip_jumps:

    ; === 15. STACK OPERATIONS ===
    push    rax                       ; push register
    push    qword [rel test_data]         ; push memory
    push    42                        ; push immediate
    pop     rbx                        ; pop to register
    pop     qword [rel test_data]          ; pop to memory

    ; === 16. ATOMIC OPERATIONS ===
    lock add qword [rel test_data], 1  ; locked memory operation
    xchg    rax, rbx                  ; exchange registers
    xchg    rax, [rel test_data]          ; exchange register and memory

    ; === 17. VECTOR INSTRUCTIONS (AVX examples) ===
    ; Note: These require CPU support
    ; vaddps ymm0, ymm1, ymm2      ; 256-bit vector add
    ; vmovdqa ymm0, [vector_data]  ; aligned vector move

    ; Restore registers and return
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; ------------------------------------------------------------------
; Function: add_numbers(int a, int b) -> int
; Adds two numbers and returns the result in RAX.
; ------------------------------------------------------------------
add_numbers:
    push    rbp
    mov     rbp, rsp
    mov     rax, rdi
    add     rax, rsi
    pop     rbp
    ret

; ------------------------------------------------------------------
; Function: multiply_numbers(int a, int b) -> int
; Multiplies two numbers and returns the result in RAX.
; ------------------------------------------------------------------
multiply_numbers:
    push    rbp
    mov     rbp, rsp
    mov     rax, rdi
    imul    rax, rsi
    pop     rbp
    ret

; ------------------------------------------------------------------
; Function: print_number(int num)
; Converts a number to ASCII and prints it to stdout.
; ------------------------------------------------------------------
print_number:
    mov     rbx, rsp
    sub     rsp, 20             ; Reserve stack space
    mov     rsi, rsp
    mov     rcx, 10             ; Base 10
    xor     rdx, rdx            ; Clear remainder

    .print_digit:
        div     rcx                 ; RAX /= 10, remainder in RDX
        add     dl, '0'             ; Convert remainder to ASCII
        dec     rsi                 ; Move buffer pointer
        mov     [rsi], dl           ; Store digit
        test    rax, rax
        jnz     .print_digit        ; Continue if RAX != 0

    mov     rax, 1              ; syscall: sys_write
    mov     rdi, 1
    mov     rdx, rbx
    sub     rdx, rsi            ; Calculate printed string length
    mov     rsi, rsi            ; rsi already points to buffer
    syscall

    add     rsp, 20             ; Restore stack
    ret

; =================================================================
; CALL HIERARCHY FOR TESTING CALLERS/CALLEES
; =================================================================

; Level 1: Called by _start, calls level2_func_a and level2_func_b
level1_func:
    push    rbp
    mov     rbp, rsp

    call    level2_func_a
    call    level2_func_b

    pop     rbp
    ret

; Level 2a: Called by level1_func, calls level3_func
level2_func_a:
    push    rbp
    mov     rbp, rsp

    call    level3_func

    pop     rbp
    ret

; Level 2b: Called by level1_func, calls level3_func
level2_func_b:
    push    rbp
    mov     rbp, rsp

    call    level3_func

    pop     rbp
    ret

; Level 3: Called by both level2_func_a and level2_func_b
level3_func:
    push    rbp
    mov     rbp, rsp

    ; Leaf function - no calls

    pop     rbp
    ret

section .data
    ; Test data for various operand types
    test_data       dq 0x1234567890ABCDEF
    test_array      dq 1, 2, 3, 4, 5, 6, 7, 8
    temp_float      dd 0.0
    temp_double     dq 0.0

    ; Vector data (128-bit aligned)
    align 16
    vector_data     dd 1.0, 2.0, 3.0, 4.0

    ; String data for testing
    src_string      db "Source string data", 0
    dst_string      times 32 db 0

section .rodata
    hello       db "Hello, IDA!", 10, 0
    hello_len   equ $ - hello

    sum_str     db "Sum: "
    sum_len     equ $ - sum_str

    product_str db "Product: "
    product_len equ $ - product_str

    newline     db 10
    newline_len equ 1

    float_val   dd 0x4048F5C3      ; 3.14 as 32-bit IEEE float
    double_val  dq 0x40191EB851EB851F ; 6.28 as 64-bit IEEE double
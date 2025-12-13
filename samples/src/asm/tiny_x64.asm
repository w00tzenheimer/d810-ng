; ----------------------------------------------------------------------------------------
;
; To assemble:
;
;     nasm -fmacho64 tiny_x64.asm; clang -arch x86_64 tiny_x64.o -o ../../bins/tiny_x64 && rm -f tiny_x64.o
;
; To run:
;
;     ../../bins/tiny_x64
;
; On macOS, this will emit a warning ld: warning: no platform load command ... which can be
; ignored since it is the correct output for the macOS platform.
; ----------------------------------------------------------------------------------------

          global    _main
          extern    _puts

          section   .text
_main:    push      rbx                     ; Call stack must be aligned
          lea       rdi, [rel message]      ; First argument is address of message
          call      _puts                   ; puts(message)
          pop       rbx                     ; Fix up stack before returning
          ret                          ; invoke operating system to exit

          section   .data
message:  db        "Hello, World", 10      ; note the newline at the end
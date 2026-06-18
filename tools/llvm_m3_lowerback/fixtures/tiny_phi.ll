; Hand-authored M3a lower-back contract fixture.
; This is not M1/M2 generated output. It pins the tiny PHI shape used by the
; IDA-free lower-back planner tests.

define i32 @tiny_phi(i1 %cond, i32 %a, i32 %b) {
entry:
  br i1 %cond, label %then, label %else

then:
  br label %merge

else:
  br label %merge

merge:
  %x = phi i32 [ %a, %then ], [ %b, %else ]
  ret i32 %x
}

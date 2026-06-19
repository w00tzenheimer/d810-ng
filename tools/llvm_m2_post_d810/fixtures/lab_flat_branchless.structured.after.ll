; Post-D810 structured oracle for lab_flat_branchless.
;
; This fixture models the source/spec semantics after d810 has recovered the
; branchless state dispatch into a structured if/else.  It is intentionally
; separate from the M0 mask/residue fixture.

@state_sink = external global i32
@value_sink = external global i32

define i32 @lab_flat_branchless_post_d810(i32 %token) {
entry:
  store volatile i32 -966241705, ptr @state_sink
  %base = add i32 %token, 17
  store volatile i32 %base, ptr @value_sink
  %low = and i32 %token, 1
  %is_even = icmp eq i32 %low, 0
  br i1 %is_even, label %even, label %odd

join:
  %value = phi i32 [ %odd_value, %odd ], [ %even_value, %even ]
  ret i32 %value

even:
  %even_value = add i32 %token, -34
  store volatile i32 %even_value, ptr @value_sink
  store volatile i32 439041101, ptr @state_sink
  br label %join

odd:
  %odd_value = xor i32 %base, 34
  store volatile i32 %odd_value, ptr @value_sink
  store volatile i32 439041101, ptr @state_sink
  br label %join
}

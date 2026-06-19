define i32 @mba_or(i32 %x, i32 %y) {
entry:
  %and = and i32 %x, %y
  %xor = xor i32 %x, %y
  %out = add i32 %and, %xor
  ret i32 %out
}

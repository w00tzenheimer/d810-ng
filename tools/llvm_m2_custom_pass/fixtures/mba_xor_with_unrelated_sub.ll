; M2c fixture: one d810 MBA/Z3 custom-pass candidate plus unrelated valid sub.
define i32 @m2c_mba_xor(i32 %x, i32 %y, i32 %z) {
entry:
  %or = or i32 %x, %y
  %and = and i32 %x, %y
  %out = sub i32 %or, %and
  %or2 = or i32 %out, %z
  %other = sub i32 %or2, %x
  ret i32 %other
}

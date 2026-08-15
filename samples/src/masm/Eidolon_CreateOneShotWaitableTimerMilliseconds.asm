; In-image target for the Worker13 fixture's direct timer call.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC Eidolon_CreateOneShotWaitableTimerMilliseconds
Eidolon_CreateOneShotWaitableTimerMilliseconds:
    xor eax, eax
    ret
_TEXT ENDS
END

; In-image target for the Worker13 fixture's direct timer call.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC Eid_CreateOneShotWaitableTimerMilliseconds
Eid_CreateOneShotWaitableTimerMilliseconds:
    xor eax, eax
    ret
_TEXT ENDS
END

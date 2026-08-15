; In-image target for the Worker13 fixture's direct queue call.
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC Eidolon_QueueHandleForCurrentFiber
Eidolon_QueueHandleForCurrentFiber:
    ret
_TEXT ENDS
END

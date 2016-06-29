"Common constants for heuristics"


# Function prologs and epilogs binary pattern, mainly ripped from archinfo
# (project Angr)

# arch name -> list of regexp expression
func_prologs = {
    'x86_32': [
        r"\x55\x8b\xec", # push ebp; mov ebp, esp
        r"\x55\x89\xe5",  # push ebp; mov ebp, esp
    ],
    'arml': [
        r"[\x00-\xff][\x00-\xff]\x2d\xe9",          # stmfd sp!, {xxxxx}
        r"\x04\xe0\x2d\xe5",                        # push {lr}
    ],
}
func_epilogs = {
    'x86_32': [
        r"\xc9\xc3", # leave; ret
        r"([^\x41][\x50-\x5f]{1}|\x41[\x50-\x5f])\xc3", # pop <reg>; ret
        r"[^\x48][\x83,\x81]\xc4([\x00-\xff]{1}|[\x00-\xff]{4})\xc3", #  add esp, <siz>; retq
    ],
    'arml': [
        r"[\x00-\xff]{2}\xbd\xe8\x1e\xff\x2f\xe1"   # pop {xxx}; bx lr
        r"\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1"         # pop {xxx}; bx lr
    ],
}

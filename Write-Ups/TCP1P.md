# TCP1P
This is a write-up about the flags I found for the TCP1P 2023 CTF

## debug me
This was a reverse engineering challenge, but as the title suggests, it is primarily done through debugging instead of running the binary through ghidra (or any other decompiler) as one would usually do for a reverse engineering challenge.
### final code
The final code that I ran to solve this challenge looked as follows (prettied-up for your viewing pleasure):  
#### debugme.py
```py
from pwn import *

# Possible characters for flag
characters = [b'#', b'$', b'!', b'_']
characters += [chr(i).encode() for i in range(48, 58)]
characters += [chr(i).encode() for i in range(63, 91)]
characters += [chr(i).encode() for i in range(97, 122)]

# The part of the flag we currently know
known_flag = b"TCP1P{"

# While the known flag is less than the size of the flag (as found through reading the disassembly)
while len(known_flag) < 0x48:
    flag_len = len(known_flag)
    # Test every character until we find one that the program loops an extra time for
    for c in characters:
        # start a new debugging process
        p = process("gdb main", shell=True)
        line = b""
        while not b"Breakpoint 2," in line:
            line = p.recvline()

        # The string we will be guessing in this loop
        guess = known_flag + c + (b'a' * (0x48 - len(known_flag) - 1))
        print(guess)
        print(len(guess))

        p.sendline(guess)
        print(p.recvline())
        print(p.recvline())

        p.sendline(b'c')

        line = b""
        # The number of times we have hit the breakpoint at the top of the coop
        i = -1
        # keep continuing until we don't hit the breakpoint/hit a "Wrong" response
        while not b"Wrong" in line:
            print(p.recvline())
            line = p.recvline()
            print("line", line)
            print(p.recvline())
            p.sendline(b'c')
            i += 1
        print(i)
        # If we hit the breakpoint more than the number of times we would expect
        # to with the known flag, we know we found another character of the flag
        if i > len(known_flag):
            known_flag += c
            print("-----------------------------------------")
            print(known_flag)
            print("-----------------------------------------")
            break
        p.close()
    if flag_len == len(known_flag):
        print("Failed to find character ", flag_len, " current known flag: ", known_flag)

print(known_flag)
```
#### .gdbinit
```sh
# the locations where the program crashes
break *init0+34
break *init1+206

break *main+265  

run
# when we hit the first crash, the program expects RAX to be zero
set $rax=0
continue

# when we hit the second crash, the program expects the stack variable
# to be 0
set *(uint64_t)($rbp-4)=0
continue
```
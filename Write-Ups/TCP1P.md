# TCP1P
This is a write-up about the flags I found for the TCP1P 2023 CTF

## debug me
This was a reverse engineering challenge, but as the title suggests, it is primarily done through debugging instead of running the binary through ghidra (or any other decompiler) as one would usually do for a reverse engineering challenge.
### final code
The final code that I ran to solve this challenge looked as follows:  
debugme.py:
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
    for c in characters:
        p = process("gdb main", shell=True)
        line = b""
        while not b"Breakpoint 2," in line:
            line = p.recvline()
        guess = known_flag + c + (b'a' * (0x48 - len(known_flag) - 1))
        print(guess)
        print(len(guess))
        p.sendline(guess)
        print(p.recvline())
        print(p.recvline())
        p.sendline(b'c')

        line = b""
        i = -1
        while not b"Wrong" in line:
            print(p.recvline())
            line = p.recvline()
            print("line", line)
            print(p.recvline())
            
            p.sendline(b'c')
            i += 1
        print(i)
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
.gdbinit:  
```sh

break *init0+34
break *init1+206
break *main+265  

run

set $rax=0
c
set *(uint64_t)($rbp-4)=0
c

```
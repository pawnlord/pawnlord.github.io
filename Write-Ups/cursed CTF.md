# cursed CTF
i exorcized these challenges.

## palindrome_number
### prompt
i took a while to write this and forgot it :)  
But, you need to solve the given leetcode problem (in this case, palindrome_number), while have less than some quantity compared to the last solve. In this case, you needed less 0 bits in the payload, and when i was doing it the record was 82 0 bits.
### server
The server is split into 2 files: lib.rs, which contains the server logic for all the code golf challenges, and palindrome.rs, which contains the palindrome challenge specific functionallity. The important things to note is how it runs the payload, how it generates test cases, and how it checks for the correct input.
### how the payload is run
```rust
for i in 0..P::test_case_len() {
    let Ok(mut emu) = Unicorn::new(Arch::X86, Mode::MODE_64) else {return "failed to instantiate emulator".to_string();};
    let _ = emu.mem_map(0x10000000, MAX_SIZE, Permission::ALL);
    let _ = emu.mem_map(0x20000000, MAX_SIZE, Permission::ALL);
    let _ = emu.mem_map(0x30000000, MAX_SIZE, Permission::ALL);
    let _ = emu.mem_write(0x10000000, &shellcode);
    let input = P::generate_input(i);
    let _ = emu.mem_write(0x20000000, &input);
    let res = emu.emu_start(0x10000000, (0x10000000 + shellcode.len()) as u64, 10 * SECOND_SCALE, 1000);
    let Ok(output_len) = emu.reg_read(RegisterX86::RAX) else {return ":(".to_string();};
    let Ok(output) = emu.mem_read_as_vec(0x30000000, output_len as usize) else {return format!("couldn't read output, probably invalid output len {output_len}").to_string();};
    let ret = P::check_output(&input, &output);
    info!("test case {} = {}, output len = {}", i, ret, output_len);
    accum &= ret;
}
if accum {
    redis::cmd("RPUSH").arg(&[&format!("golf:{}", P::name()),&format!("{}", P::score(&shellcode))]).query_async::<_, usize>(&mut con).await;
    env!("FLAG").to_string()
} else {
    "your answer was wrong smh".to_string()
}    
```
First, it makes an x64 emulator. It them gives permissions to `0x10000000`, `0x20000000`, and `0x30000000`, up to MAX_SIZE (4096 \* 64).

it writes the payload (`shellcode`) to `0x1`, the input generated from P (the current challenge, in this case palindrome) to `0x20000000`, and reads the output as a vector of u8s from `0x30000000`. The output_len is determined by the RAX register at the end of the program. The program can run for at most 1000 instructions before being halted, and for no longer than 10 seconds. It then checks the output through P (the current challenge, again).
### check_output
```rust
fn check_output(input: &[u8], output: &[u8]) -> bool {
    if input.len() < 4 || output.len() < 4  {
        return false;
    }
    pub fn is_palindrome(x: i32) -> i32 {
        let (mut rev, mut org) = (0,x);
        
        while org>0 {
            rev = (rev*10) + org%10;
            org/=10;
        }
        
        if rev == x { 1 } else { 0 }
    }
    is_palindrome(i32::from_le_bytes(input[0..4].try_into().unwrap())) == i32::from_le_bytes(output[0..4].try_into().unwrap())
}
```
Essentially, it takes the output and checks if it's 1 or 0, and then sees if that matches the boolean output of is_palindrome for the input. This is pretty simple
### generate_input
```rust
fn generate_input(idx: usize) -> Vec<u8> {
    [
        0i32,
        12,
        121,
        -121
    ][idx].to_le_bytes().to_vec()
}
```
...wait, so the only possible inputs are 0, 12, 121, and -121?  
This will be very useful to know for our later code golf
### sending the payload
There are probably better ways to do this, but i know how to use nasm and objcopy so i just built an object file and then copy the text to a separate file to send. The full script for sending the payload can be seen in build.py.
### code golfing
First, we need to setup the output and input registers. This is the largest place we can save on, because `0x20000000` has a large number of 0's in it, but `0x1FFFFFFF` has very few. So, we can set our register to `0x1FFFFFFF` and then increment it  
The next is the actual logic. We can move in the number we want to edit into a byte register (as 0, 12, 121, and -121 all fit in a byte). The bit layouts of each number is shown below:  
```
Isn't Palindrome
-121: 10000111
12:   00001100

Is Palindrome
121: 01111001
0:   00000000
```
The third bit is 0 in the palindromes and 1 in the non-palindromes, se we can check if this is 0 to check if a number is a "palindrome" (and thus pass all the tests). However, this is not the only optimization we can do in the check: the second and eighth bit are set in -121, but not set in either of the palindromes. So, if we also add these to the mask, the AND will still only be 0 for 121 and 0. This means that the optimal number for checking if something is a palindrome or not through AND is 134. The bit layout is as follows:
```
134: 10000110
```
We can then check the zero flag, and this will be our final answer.  
The final optimization we do is with the registers we use: using the [ModR/M](http://www.c-jump.com/CIS77/CPU/x86/X77_0060_mod_reg_r_m_byte.htm) table for x64, we can see the rbx and rdi registers will use the least 0 bits per instruction. So we use ebx for the input address, bh for the input number, and edi for the output address.  

### final payload
#### palindrome.s
```
    section .text
  
    mov ebx, 0x1FFFFFFF
    inc ebx
    mov bh, byte [ebx]
    and bh, 134
    setz bh
    mov edi, 0x2FFFFFFF
    inc edi
    mov byte[edi], bh
    mov al, 4
```

#### build.py
```py
import os
from pwn import *
import requests

# os.system("gcc -c palindrome.c -o palindrome.o && objcopy -O binary --only-section=.text palindrome.o program.text")
os.system("nasm -f elf64 palindrome.s -o palindrome.o  && objcopy -O binary --only-section=.text palindrome.o program.text")
binary_program = b""
with open("program.text", "rb") as f:
    binary_program = f.read()
shellcode = "".join([("0" * (2-len(hex(a)[2:]))) + hex(a)[2:] for a in binary_program]).replace("90","")

hex = unhex(shellcode)
total0 = 0
total1 = 0
for h in hex:
    c = 0
    for i in range(8):
        if (h >> i) & 1 == 1:
            c += 1
    total0 += (8 - c)
    total1 += (c)
print("Total 0s:", total0)
print("Total 1s:", total1)

print(disasm(unhex(shellcode), arch= 'amd64'))
target = "https://palindrome.chals.4.cursedc.tf"
print(shellcode)
os.system("curl " + target + "/score")
r = requests.post(target + "/submit", data='{"shellcode": "%s"}' % shellcode , headers={"Content-Type": "application/json"})
print()
print(r.text)
```
This gives a total 76 0 bits in the final payload, which is less than the previous record of 82 0 bits.

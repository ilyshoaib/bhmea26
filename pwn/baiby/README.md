# baiby — pwn

**Black Hat MEA 2026 CTF · PWN**

A tiny 64-bit Linux binary. You get a menu that lets you write numbers into an
array by index. The catch: it never checks if the index is in range, so you can
read and write memory far outside the array.

## The programme

- The binary is **No-PIE**, so its own addresses are fixed and known in advance.
- Menu option 1 does something like `arr[i] = v`, where **you** pick `i` and `v`.
- Because `i` is not bounds-checked, a negative or large `i` lets you write
  anywhere relative to the array — most importantly into the **GOT** (the table
  the programme uses to find library functions like `setbuf`, `memset`, `atol`).
- Values are limited to 7 decimal digits, so writes have to be done carefully in
  small pieces.

## The plan

The flag is on the remote server, so we need to run our own code there. Three
steps:

### 1. Leak libc (beat ASLR)

The binary's own addresses are fixed, but the **C library** is loaded at a random
address each run (ASLR). We need its real address to build a working exploit.

To leak it we point some GOT entries at small pieces of the programme's own code
(gadgets) and rebuild the `stdout` **FILE** structure by hand — a classic
**FSOP** (File-Structure-Oriented-Programming) trick. When `stdout` next flushes,
it prints out a pointer that lives in libc. From that one pointer we calculate
the **libc base address**.

### 2. Get control of execution

- Overwrite `atol`'s GOT entry with a `pop rbp; ret` gadget.
- Redirect execution into `gets()`.
- `gets()` reads a line from us with no size limit, so we **overflow the stack**
  and drop in a **ROP chain**.

### 3. Read the flag (ORW with a seccomp twist)

Normal plan is open → read → write (ORW). But the remote has **seccomp** that
blocks the classic `open` syscall. Workaround: use **`openat` (syscall 257)**
instead.

The chain does:
1. `openat(AT_FDCWD, "/", ...)` then `getdents64` to **list the root folder** and
   print it back to us — because the flag's filename is randomised.
2. Read the filename we see, then `openat` that file, `read` it, and `write` it
   back to us.

Because `gets()` stops at a newline, any chain containing a `0x0a` byte is
retried on a fresh connection (new ASLR) until we get a clean one.

## Run it

```bash
# local test
python3 solve.py

# against the remote instance
python3 solve.py --remote tcp.flagyard.com:PORT
```

> Note: the script expects the challenge's libc (`lib87/`) next to it for local
> runs. That file is the organisers' and isn't included here.

## Takeaways

- An unchecked array index is a full read/write primitive.
- No-PIE means the GOT is a reliable target.
- FSOP on `stdout` is a clean way to leak libc when you can forge a FILE struct.
- When `open` is blocked by seccomp, remember `openat`.

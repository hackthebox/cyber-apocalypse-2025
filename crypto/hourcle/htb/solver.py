import string, os
from pwn import *

if len(sys.argv) > 1:
    host, port = sys.argv[1].split(':')
    io = remote(host, port)
else:
    os.chdir('../challenge')
    io = process(['python3', 'server.py'], level='error')

def encrypt(user):
    io.sendlineafter(b'traveler :: ', b'1')
    if type(user) == str:
        user = user.encode()
    io.sendlineafter(b'archives :: ', user)
    io.recvuntil(b'scrolls: ')
    return bytes.fromhex(io.recvline().decode().strip())

def admin_login(pwd):
    io.sendlineafter(b'traveler :: ', b'2')
    io.sendlineafter(b'Sanctum :: ', pwd.encode())
    resp = io.recvline().decode().strip()
    return re.findall(r'HTB{.+}', resp)[0]

def _b(s):
    return [s[i:i+16] for i in range(0, len(s), 16)]

alph = string.ascii_letters + string.digits
password = ''
block_num = 1

while len(password) < 20:
    plaintext = 'x' * ((block_num+1) * 16 - 1 - len(password))
    target_ct = encrypt(plaintext)
    current_target_ct_block = _b(target_ct)[block_num]

    for c in alph:
        pt = (plaintext + password + c).encode()
        current_test_ct_blocks = _b(encrypt(pt))

        if current_test_ct_blocks[block_num] == current_target_ct_block:
            password += c
            if len(password) % 16 == 0:
                block_num += 1
            print(password)
            break
    else:
        print(f'oops || FAILED @ block = {block_num}')
        exit()

print(admin_login(password))
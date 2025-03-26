from pwn import remote, xor

io = remote('localhost', 1337)

io.sendlineafter(b' :: ', b'1')
io.sendlineafter(b' :: ', b'A'*16)

ct1 = bytes.fromhex(io.recvline().split(b': ')[1])
blocks_ct1 = [ct1[i:i+16] for i in range(0, len(ct1), 16)]

dkc1 = xor(blocks_ct1[1], b'A'*16)

io.sendlineafter(b' :: ', b'1')
io.sendlineafter(b' :: ', b'a')

ct2 = bytes.fromhex(io.recvline().split(b': ')[1])
blocks_ct2 = [ct2[i:i+16] for i in range(0, len(ct2), 16)]


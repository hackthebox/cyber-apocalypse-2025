from sage.all import factor, EllipticCurve, GF, pari, log, Integer
from pwn import remote, process, sys
from time import sleep

def is_generator(g):
    for f,e in p_1_factors:
        if pow(g, (p-1)//f, p) == 1 and f != p-1:
            return False
    return True

if len(sys.argv) > 1:
    host, port = sys.argv[1].split(':')
    if len(sys.argv) == 2:
        io = remote(host, port)
    else:
        io = remote(host, port, level=sys.argv[2])
else:
    io = process(['python3', 'challenge/server.py'])

io.recvuntil(b'knowledge.\n')

p = int(io.recvline().decode().split(' = ')[1])

io.sendlineafter(b'prime p? > ', str(p.bit_length()).encode())

F = GF(p)
pari.addprimes(p)

p_1_factors = list(factor(p-1))
factorization = '_'.join([f'{str(f)},{str(e)}' for f,e in p_1_factors])

io.sendlineafter(b' > ', factorization.encode())

io.recvuntil(b'otherwise 0.\n')
for _ in range(17):
    g = int(io.recvuntil(b'? > ')[:-4])
    io.sendline(str(int(is_generator(g))).encode())

io.recvuntil(b'proceed.\n')
a = int(io.recvline().strip().decode().split(' = ')[1])
b = int(io.recvline().strip().decode().split(' = ')[1])

E = EllipticCurve(F, [a,b])

io.sendlineafter(b'? > ', str(E.order()).encode())

Ep3 = EllipticCurve(GF(p**3, 'x'), [a,b])
Op3_factors = list(factor(Ep3.order()))
answer = '_'.join([f'{str(f)},{str(e)}' for f,e in Op3_factors])

io.sendlineafter(b' > ', answer.encode())

io.recvuntil(b'd * G.\n')

Gx = Integer(io.recvline().strip().decode().split(': ')[1])
Ax = Integer(io.recvline().strip().decode().split(': ')[1])

G = E.lift_x(Gx)
A = E.lift_x(Ax)

d = log(A, G)

io.sendlineafter(b'? > ', str(d).encode())

io.recvline()
print(io.recvline())
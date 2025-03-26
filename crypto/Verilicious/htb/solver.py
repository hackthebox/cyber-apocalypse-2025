from Crypto.PublicKey import RSA
from Crypto.Util.number import *
from sage.all import *
import re

key = RSA.import_key(open('pubkey.pem', 'rb').read())

n = key.n

l = n.bit_length()

exec(open('output.txt').read())

assert len(R) == 78

R += [1] # r = 1 is valid too

λ = len(R)

B = 1 << (l - 16)

print(f'{n = }')

M = identity_matrix(λ)*n

M = M.augment(zero_vector(λ))
M = M.augment(zero_vector(λ))

C = [2*B for _ in range(λ)]

n_ = next_prime(n)

M = M.stack(vector(QQ, R + [B/n_, 0]))
M = M.stack(vector(QQ, C + [0, B]))

L = M.LLL()

for row in L:
    if abs(row[-1]) == B:
        m = long_to_bytes(int(abs((row[-2]*n_) / B)))
        if b'HTB{' in m:
            print(re.findall(rb'HTB{.*}', m)[0])
            break
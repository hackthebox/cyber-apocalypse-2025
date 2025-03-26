from math import lcm
from hashlib import sha256
from ast import literal_eval
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def mul(a, b):
    return [b[a[i]] for i in range(n)]

def exp(a, e):
    b = list(range(n))
    while e:
        if e & 1:
            b = mul(b, a)
        a = mul(a, a)
        e >>= 1
    return b

with open('tales.txt') as f:
    c = literal_eval(f.readline().split('=')[1])
    enc_flag = bytes.fromhex(literal_eval(f.readline().split('=')[1]))


n = 0x1337
e = 0x10001

m = exp(c, pow(e, -1, lcm(*range(1, n+1))))

key = sha256(str(m).encode()).digest()
flag = AES.new(key, AES.MODE_ECB).decrypt(enc_flag)

print(unpad(flag, 16).decode())
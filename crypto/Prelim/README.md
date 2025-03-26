![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>Super Scrambled</font>

6<sup>th</sup> March 2025

Prepared By: `rasti`

Challenge Author(s): `blupper`

Difficulty: <font color='green'>Easy</font>


# Synopsis

This challenge presents the problem of taking the `e`th root in a group, much like the RSA cryptosystem, but instead of the integers modulo $pq$, it's the symmetric group $S_{4919}$. The order of this group can easily be calculated, allowing you to find the inverse of the public exponent.

## Description

Cedric has now found yet another secret message, but he dropped it on the floor and it got all scrambled! Do you think you can find a way to undo it?

## Skills Required

- Ability to recognize the binary exponentiation algorithm
- Ability to recognize the symmetric group from an implementation
- Basic understanding of group theory and/or the ideas behind RSA

## Skills Learned

- Generalizing the RSA cryptosystem to other groups

# Enumeration

## Analyzing the source code

In this challenge we are provided 2 files:
 - `chall.py`: The source code of the challenge, this is what generated `out.txt`
 - `out.txt`: The output of the challenge, this contains the encrypted flag

`chall.py` has two important functions. `scramble` takes in two lists of numbers which will be permuations of `list(range(4919))`, it then applies one of the permuations after the other. `super_scramble` implements the binary exponentiation algorithm with `scramble` as the group law.

The group law implements applying one permutation after the other, this is exactly the group law of the symmetric group $S_{4919}$, 
often defined as the group of all permutations of a set of 3000 elements.

A random permuation `message` (henceforth known as $m$) is generated and then `scrambled_message` (henceforth known as $c$) $c=m^e$ is calculated, with $e=$`0x10001`. The result is hashed and then XORed with the flag, which is then written to `output.txt` together with $c$.

Our goal is to recover $m$ from $c$ to then hash it and XOR it with the encrypted flag to undo the previous XOR, recovering the flag.

# Solution

## Finding the vulnerability

The difficulty of decrypting in the context of RSA, which is very similar, is that of computing the order of the group. But in this case we are working in the Symmetric group $S_{4919}$, and its order can easily be calculated as $\varphi = 4919!$ (factorial).

$4919!$ is very large, but not too large to compute. But if we want to speed up the script we can instead use $\varphi = \text{lcm}(1, 2, 3, ..., 4919)$, it's a divisor of $4919!$ but one which no element has an order greater than.

## Exploitation

Knowing the order of the group $\varphi$ we can compute the multiplicative inverse of the public exponent modulo the order of the group. This is the private exponent $d$ such that $e d \equiv 1 \pmod{\varphi}$, which allows us to compute $c^d = m^{e d} = m$, recovering $m$.

We can keep the original implementations of `scramble` and `super_scramble`, but rename them to `mul` and `exp` to be more clear

```python
from random import shuffle

def mul(a, b):
    return [b[a[i]] for i in range(n)]

def exp(a, e):
    b = one
    while e:
        if e & 1:
            b = mul(b, a)
        a = mul(a, a)
        e >>= 1
    return b
```

We then load the data from `out.txt`

```python
from ast import literal_eval
with open('tales.txt') as f:
    c = literal_eval(f.readline().split('=')[1])
    enc_flag = bytes.fromhex(literal_eval(f.readline().split('=')[1]))
```

Then we can use the above theory to calculate $m$

```python
n = 0x1337
e = 0x10001
one = list(range(n))
m = exp(c, pow(e, -1, lcm(*range(1, n+1))))
```

And lastly we decrypt the flag by hashing $m$ and XORing it with the encrypted flag

```python
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = sha256(str(m).encode()).digest()
flag = AES.new(key, AES.MODE_ECB).decrypt(enc_flag)
print(unpad(flag, 16).decode())
```
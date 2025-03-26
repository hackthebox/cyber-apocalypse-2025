![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='5'>Verilicious</font>

​	4<sup>th</sup> March 2025

​	Prepared By: `rasti`

​	Challenge Author(s): `rasti`

​	Difficulty: <font color=orange>Medium</font>

​	Classification: Official

# Synopsis

- `Verilicious` is a medium crypto challenge which teaches players about the PKCS#1 v1.5 padding scheme and what information it might leak for the decrypted message. They are provided enough samples to translate the problem into an instance of the HNP and eventually solve for the flag $m$.



## Description

- TBD



## Skills Required

- Basic knowledge of how RSA works.
- Familiar with the PKCS#1 v1.5 padding scheme.
- Familiar with translating linear equations into matrices and vectors.
- Basic knowledge of the Hidden Number Problem.
- Know how to research online papers for cryptographic attacks

## Skills Learned

- Learn more about the PKCS#1 v1.5 padding scheme and how it leaks information about the decrypted message.
- Learn how to convert linear equations to instances of the hidden number problem.
- Learn how to apply lattice reduction techniques with SageMath.

# Enumeration

In this challenge we are provided with three files:

- `source.py` : The main script of the challenge.
- `output.txt` : The output data generated from the script `source.py`.
- `pubkey.pem` : The RSA public key used in this challenge.

## Analyzing the source code

The source of the challenge is the following:

```python
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, long_to_bytes as l2b, bytes_to_long as b2l
from random import seed, randbytes
from data import R, s

seed(s)

class Verilicious:
    def __init__(self):
        self.key = RSA.import_key(open('privkey.pem', 'rb').read())
        self.cipher = PKCS1_v1_5.new(self.key, randbytes)

    def verify(self, c):
        c = b'\x00'*(self.key.n.bit_length()//8-len(c)) + c
        return int(self.cipher.decrypt(c, sen := get_random_bytes(self.key.n.bit_length()//8)) != sen)

    def encrypt(self, m):
        return self.cipher.encrypt(m)

ver = Verilicious()

enc_flag = ver.encrypt(open('flag.txt', 'rb').read()).hex()

assert all(ver.verify(l2b(pow(r, ver.key.e, ver.key.n) * int(enc_flag, 16) % ver.key.n)) for r in R)

import os ; os.system('openssl rsa -in privkey.pem -pubout -out pubkey.pem')

with open('output.txt', 'w') as f:
    f.write(f'{enc_flag = }\n')
    f.write(f'{R = }\n')
```

Looking at `output.txt`, we see the encrypted flag in hex format and a list $R$ with 78 integers, all of them being $< N$, the public modulus.

```
enc_flag = '723e808e262486bb05c39cef2a4ca2334e885ce90ebf318d6f0ab1d9e95fc9650cf95e7e4d5df2e3afef8aba4796240e958be4cc933cb944a0ec748619cdb9138b11ad0eb2e5f492c6280909e55def3db966cc96eb02f0212be4b33c04f5b4576d2d87a180649b6770dac45fd07d17d0a68bbbed87c0d18cd1610c1d52c25b52'
R = [134115821619995314496122564547916126947599980819405235082517192808507030501092656706168887309982033289987953471348763955476089416556147406160259955040757648917395767651179830169779066153799931136707924690852827516288300826437643041264226686893395744277118552895070277286649305077822610943759606681582403285622, ...,
130829797409030268973352996767957779365311690002579378946982172341323743450377476516069574855855224485237210467599418067612712824380628946412878127911436900313997947604882192929110839317179000399541063224855604445875473626055054487308281408204582792705082064340692302772564869303002107776645416860156072622955]
```

Let us go ahead and examine the source script in more detail.

It looks like the meat of the challenge is inside the Verilicious class and more specifically in the `verify` function. First, an RSA cipher is initialized using the PKCS#1 v1.5 padding scheme.

`verify` receives a ciphertext c, decrypts it with the private key and checks whether the message has valid PKCS#1 v1.5 padding. To produce deterministic results, a fixed seed is used for the `random` module. If the message is not properly padded, `sen` is returned instead which is basically a random byte string. For each value $r_i$ in the list $R$, it holds that:
$$
\text{verify}(c * r_i^e\pmod N) = \text{verify}((mr_i)^e \pmod N) = 1
$$
which implies that all of the messages $mr_0, mr_1,\ ...,\ mr_{77}$ produce valid padding.

# Solution

## Finding the vulnerability

This is one of these challenges that can be solved by finding the right paper or figuring out the attack manually, which would certainly take much more time. In fact, the attack for this challenge is showcased at page 32 of [this](https://eprint.iacr.org/2023/032.pdf) amazing paper (and resource).

The key point for understanding the attack is that valid PKCS#1 v1.5 padded messages, start with the bytes `\x00\x02`. As mentioned, let $B = 2^{l - 16}$, where $l$ is the bit length of $n$. It holds that:
$$
2B \leq r_im \pmod N < 3B
$$
One can verify this with local experiments for example with a 1024-bit modulus $N$:

```python
>>> p = getPrime(512)
>>> q = getPrime(512)
>>> n = p*q
>>> B = 2**(n.bit_length()-16)
>>> B.to_bytes(n.bit_length()//8).hex()
'0001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
>>> (2*B).to_bytes(n.bit_length()//8).hex()
'0002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
>>> (3*B).to_bytes(n.bit_length()//8).hex()
'0003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
```

Since a message with valid padding always starts with `0002`, it should lie between $2B$ and $3B$. With some rearrangement, we get that:
$$
k_i - r_im + 2B = 0 \pmod N
$$
where:

- $k_i$ are unknowns $< B$
- $0 \leq i < λ$​
- $λ = 78$, the cardinality of $R$.

This is precisely an instance of the Hidden Number Problem (HNP). Our target is to recover $m$​, the hidden number. We reference chapter 4.3 of the same paper for understanding the lattice setup for this kind of problems. Let the following matrix:
$$
M =
\begin{bmatrix}
N & 0 & 0 & \dots & 0 & 0 & 0\\
0 & N & 0 & \dots & 0 & 0 & 0\\
0 & 0 & N & \dots & 0 & 0 & 0\\
\vdots & \vdots & \vdots & \ddots & \vdots & \vdots & \vdots\\
0 & 0 & 0 & \dots & N & 0 & 0\\
r_0 & r_1 & r_2 & \dots & r_{λ-1} & B/N & 0\\
2B & 2B & 2B & \dots & 2B & 0 & B
\end{bmatrix}
,\quad
\textbf{x} =
\begin{pmatrix}
k_0\\
k_1\\
\vdots\\
k_{λ-1}\\
m\\
-1
\end{pmatrix}
$$
The rows of the matrix $M$ describe the bases of the lattice that we want to reduce with LLL.

This lattice (in other words, this set of bases) contains the vector $B$ too:
$$
B = \begin{pmatrix}k_0, k_1, \dots, k_{λ-1}, m\dfrac{B}{N}, -B\end{pmatrix}
$$

# Exploitation

First, let us read the data from `output.txt` and construct the matrix $M$ using SageMath.

```python
key = RSA.import_key(open('pubkey.pem', 'rb').read())

n = key.n
l = n.bit_length()
exec(open('output.txt').read())
assert len(R) == 78
λ = len(R)
B = 1 << (l - 16)

M = identity_matrix(λ)*n
M = M.augment(zero_vector(λ))
M = M.augment(zero_vector(λ))
C = [2*B for _ in range(λ)]
n_ = next_prime(n)
M = M.stack(vector(QQ, R + [B/n_, 0]))
M = M.stack(vector(QQ, C + [0, B]))
```

We used $\dfrac{B}{\bar{N}}$ instead of $\dfrac{B}{N}$ to keep the fraction irreducible, since $\bar{N}$​ is prime.

Then, we apply $LLL$​ on the matrix $M$​ and hopefully we obtain the target vector $B$​.

```python
L = M.LLL()
for row in L:
    if abs(row[-1]) == B:
        m = long_to_bytes(int(abs((row[-2]*n_) / B)))
        if b'HTB{' in m:
            print('[+] found!')
            break
```

We iterate over the rows of $L$ and we use the last element to check whether the reduced row is correct. The target value is $-B$ so we take the absolute value and compare it against $B$. If such row is found, then we know that the next to last element contains the message $m$ and can be solved by:
$$
m = \dfrac{\text{row[-2]}*\bar{N}}{B}
$$
When we run this code, `[+] found!` is not printed.

We can experiment locally to see why this is happening and we might notice that the number of $r_i$ is not enough to recover $m$. However, we notice that apart from these values, there is also the trivial $r = 1$ value which is not included in the list $R$. Let us manually append it and try again.

The output now is:

```python
[+] found!
```

We successfuly solved for $m$ and obtained the flag.

## Getting the flag

A final summary of all that was said above:

1. Figure out the equations that $r_i$ are satisfying.
2. Understand how the `verify` function leaks information about the flag $m$.
3. Implement the attack from the referenced paper (or figure it out manually) to solve for $m$.

![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>Twin oracles</font>

​	27<sup>th</sup> February 2025

​	Prepared By: `rasti`

​	Challenge Author(s): `Babafaba`

​	Difficulty: <font color=red>Hard</font>

​	Classification: Official

# Synopsis

- Break a BBS PRNG to get access to an RSA location oracle and use it to perform binary search for the flag.



## Description

- TBD



## Skills Required

- Basic Python source code analysis.
- Basic research skills.
- Advanced mathematical skills.
- Familiarity with the RSA cryptosystem.



## Skills Learned

- Better understanding of the Blum-Blum-Shub PRNG and its weaknesses.
- Better understanding of the RSA cryptosystem and corresponding attacks.



# Enumeration

## Analyzing the source code

If we look at the `source.py` script we can see that our goal is to decrypt the flag, given its encrypted counterpart with an RSA instance.

The basic workflow of the script is as follows:

1. A BBS(Blum-Blum-Shub PRNG) object is created.
2. A "Twin_oracles" object is created with input the BBS PRNG we created before. This is basically a combination of an RSA location oracle and an RSA parity oracle, more details below.
3. As part of the initialization process of the "Twin_oracles" object, an RSA private-public keypair is created, the player gets the RSA public modulus and the encrypted flag.
4. The player can make up to 1500 queries to the oracle in order to recover the flag.

Step 1 is performed by the following code:

```python
class ChaosRelic:
    def __init__(self):
        self.p = getPrime(8)
        self.q = getPrime(8)
        self.M = self.p * self.q
        self.x0 = getPrime(15)
        self.x = self.x0
        print(f"The Ancient Chaos Relic fuels the Seers' wisdom. Behold its power: M = {self.M}")
        
    def next_state(self):
        self.x = pow(self.x, 2, self.M)
        
    def get_bit(self):
        self.next_state()
        return self.extract_bit_from_state()
    
    def extract_bit_from_state(self):
        return self.x % 2
```

This PRNG outputs one bit at a time and its security is tied to how easy factoring `M = p*q` is. Here `M` is only 16 bits long so factoring it is trivial.


Steps 2 and 3 are done with the following python code for the "Twin_oracle" python class.
```python
class ObsidianSeers:
    def __init__(self, relic):
        self.relic = relic
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.n = self.p * self.q
        self.e = 65537 
        self.phi = (self.p - 1) * (self.q - 1)
        self.d = pow(self.e, -1, self.phi)

    def sacred_encryption(self, m):
        return pow(m, self.e, self.n)

    def sacred_decryption(self, c):
        return pow(c, self.d, self.n)

    def HighSeerVision(self, c):
        return int(self.sacred_decryption(c) > self.n//2)
    
    def FateSeerWhisper(self, c):
        return self.sacred_decryption(c) % 2
    
    def divine_prophecy(self, a_bit, c):
        return self.FateSeerWhisper(c) if a_bit == 0 else self.HighSeerVision(c)
        
    def consult_seers(self, c):
        next_bit = self.relic.get_bit()
        response = self.divine_prophecy(next_bit, c)
        return response
```
Important to note that in the `__init__` part of the class, an RSA-1024 instance in created and the player will get the public modulus and the ciphertext of the flag(the public exponent e is fixed to 65537)

Additionaly, notice that this Twin_oracles class contains two functions for two other oracles, a parity oracle(that given an RSA ciphertext responds with the parity of the corresponding plaintext) and a location oracle(that given an RSA ciphertext responds with the the half of [0, n - 1] on which the plaintext lies, i.e. 0 if the plaintext is in [0, (n - 1)/2] and 1 if its in [(n + 1)/2, n - 1])

The `twin_Oracles` function combines these two oracles together and given a bitvalue and a ciphertext queries the parity oracle if the bitvalue is 0 and the location oracle otherwise.

Finally, the `Ask_twins` function combines the `twin_Oracles` with a PRNG that outputs bits(here it'll be our BBS PRNG) that will provide the required bitvalues to determine which oracle will be asked on each query.

For the 4th step we simply have a counter in our `main` function that counts how many queries the player makes. If the counter exceeds 1500 queries then the program will exit.


# Solution

## Finding the vulnerability

There are the following vulnerabilites:
1. BBS security is based on how easily we can factor M and we can do that very easily here.
2. We know RSA can be broken when given access to a location oracle.

## Exploitation

### Connecting to the server

A pretty basic script for connecting to the server with `pwntools`:

```python
if __name__ == "__main__":
    r = remote("0.0.0.0", 1337)
    pwn()
```

### Breaking BBS

Let's break the PRNG first, it's not yet clear why but we'll explain it later.

Firstly, let's notice that we can build a distinguisher of whether the parity or location oracle was used when querying the twin oracle. This is done by querying the server with input `c == 1`, since `Enc(1) == 1` and `loc(1) == 0 and par(1) == 1`. With this distinguisher we can tell whether the BBS PRNG outputted 0 or 1.

Then, we factor M either with some online tool like [this](https://www.alpertron.com.ar/ECM.HTM) or with sympy's `factorint`

Now, without knowing the starting state of the PRNG we can't actually predict its output, however a BBS PRNG with such small modulus M will have a very small period after which its outputs will start repeating themselves. From a quick googling we can find either the [original BBS paper](https://shub.ccny.cuny.edu/articles/1986-A_simple_unpredictable_pseudo-random_number_generator.pdf) or [this stack exchange thread](https://cstheory.stackexchange.com/questions/10779/how-to-find-the-exact-period-of-blum-blum-shub-random-number-generator) that both say the period of BBS is equal to `λ(λ(M))` where `λ()` is the Carmichael lambda function(the calculation of which requires the factorization of M).

From this we can calculate the exact period length of the PRNG, query the server that many times for `c == 1` and then accurately predict every subsequent output.

For the calculation of the Carmichael lambda function we can either use [this](https://www.wolframalpha.com/input?i=carmichael+lambda%28carmichael+lambda%2823701%29%29) or the following python code:

```python
def carmichael_lambda(n, n_facs):
    if [fac[1] for fac in n_facs] == [1]*len(n_facs) and len(n_facs) > 1:
        return lcm(*[fac[0] - 1 for fac in n_facs])
    elif len(n_facs) == 1:
        if n_facs[0][0] == 2 and n_facs[0][1] >= 3:
            return n_facs[0][0]**(n_facs[0][1] - 2)
        else:
            return (n_facs[0][0] - 1) * n_facs[0][0]**(n_facs[0][1] - 1)
    else:
        total_lamda = lcm(*[carmichael_lambda(fac[0]**fac[1], [(fac[0], fac[1])]) for fac in n_facs])
        return total_lamda
```

### Breaking the Twin Oracles

If we could predict which oracle is used in each query then we can recover the flag. This is done in the following 2 steps:

**Step 1: Transforming the parity oracle to a location oracle.**

We'll denote the answer of the oracles for input `c` with `loc(c)` and `par(c)` respectively and with `m` the RSA "plaintext" corresponding to `c`

- Due to RSA's homomorphic properties we have `par(c*Enc(2)) == par(Enc(2*m)) == (2*m % n) % 2`
- We can "transform" the parity oracle to a location one simply by querying it for `c*Enc(2)` instead of `c` where `Enc` is the RSA encryption function.
- This works because for `loc(c) == 1` we have that `m > n//2`. This means `n < 2*m < 2*n` which in turn implies `(2*m % n) == 2*m - n`
- `2*m` is even and `n` is odd so `2*m - n` is odd, and therefore `par(2*m - n) == 1` so from the first point we have `par(c*Enc(2)) == 1`
- For the case `loc(c) == 0` we have that `m <= n//2`. This means `(2*m % n) == 2*m`
- Since `2*m` is even, `par(2*m) == 0` and from the first point `par(c*Enc(2)) == 0`

In both cases, it's shown that the above transformation can make a parity oracle respond equivalently to a location oracle.

**Step 2: Binary search from a location oracle**

Now that we have access to a location oracle we can perform binary search on an RSA ciphertext. This is done again by exploiting RSA's homomorphic properties. We first query the location oracle for `c`. The response is the half on which the plaintext `m` resides and thus our search space is halved from `[0, n - 1]`

We then multiply the ciphertext with `Enc(2)`, the decryption of this product is `2*m`. By querying the oracle for this value we'll once again half our search space. E.g. if `loc(c) == 0` then `0 <= m < n//2` and if `loc(c*Enc(2)) == 0` then `(0 <= m <= n//4) or (n//2 < m < 3*n//4)`, the union of these two sets is `0 <= m <= n//4` etc...

We continue this process of multiplying by `Enc(2)` and querying the server, and with every response we halve our search space, effectively performing a binary search for the plaintext value.

## Getting the flag

At this point, we can combine the two steps described above to finally get the flag. First we'll break the PRNG to predict all of its outputs and then we'll do the "loc attack" by performing the transformation parity -> location oracle only when we know the PRNG will output 0.

This is done with the following code:
```python
def twin_attack(c, e, n, my_conn, all_bits): # c is the encrypted flag, e, n are the RSA public parameters, my_conn is the pwntools remote connection and all_bits is the a list with the bits of the BBS PRNG that appear periodically
    bit_index = 0
    curr_ctxt = c
    mul = pow(2, e, n) # this is Enc(2) and due to RSA's homomorphic properties we can calculate Enc(2*m) for any m if we have Enc(m)
    m_space = [1, n - 1] # the range of possible values of the plaintext m
    
    while m_space[1] != m_space[0]:
        next_bit = all_bits[bit_index % len(all_bits)]
        if next_bit == 0:
            oracle_response = ask_twin_Oracle(my_conn, curr_ctxt*(pow(2, e, n)) % n)
        else:
            oracle_response = ask_twin_Oracle(my_conn, curr_ctxt)
        if oracle_response:
            m_space[0] = (m_space[1] + m_space[0] + 1)//2
        else:
            m_space[1] = (m_space[1] + m_space[0])//2
    
        curr_ctxt = mul * curr_ctxt % n # calculate Enc((2**i) * m)
        bit_index += 1

        
    # do small "bruteforce" close to the value we found to find the correct plaintext
    for i in range(-10, 10, 1):
        plaintext = m_space[0] + i
        if pow(plaintext, e, n) == c:
            print(f"Flag = {long_to_bytes(plaintext)}")
            #print(f"Number of tries = {bit_index + len(all_bits)}")
            return plaintext
```

A final summary of all that was said above:

1. We factored M.
2. We calculated the BBS period length.
3. We build an oracle distinguisher and used it to acquire the values of all the bits in the BBS period.
4. We build a transformation of the parity oracle to a location oracle.
5. We applied the transformation only when needed based on predicted BBS outputs.
6. We performed a binary search on the plaintext with the help of our location oracle.


This recap can be represented by code with the `pwn()` function:

```python
def pwn():
    n, e, enc_flag, M, factor_list = factor_M()
    period = calc_period_length(M, factor_list)
    period_bits = get_period_values(period)
    flag = twin_attack(enc_flag, e, n, conn, period_bits)
    print(long_to_bytes(flag))
```

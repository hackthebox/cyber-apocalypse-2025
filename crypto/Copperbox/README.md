![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>Copperbox</font>

6<sup>th</sup> March 2025

Prepared By: `rasti`

Challenge Author(s): `blupper`

Difficulty: <font color='orange'>Medium</font>


# Synopsis

This challenge asks players to recover the state of an LCG (linear congruential generator) given two pairs of quotients of two outputs each, but with the lower bits of each output truncated away.
This is done by constructing a polynomial equation with small solutions and then solving it using Coppersmith's method.


## Description

Cedric found a mysterious box made of pure copper in the old archive. He is convinced that it contains the secrets he is looking for, but he is unable to penetrate the metal case. Can you help?

## Skills Required

- Manipulation of algebraic equations
- Basic knowledge of the uses for Coppersmith's method

## Skills Learned

- Eliminating variables from complex equations
- Using Coppersmith's method on multivariate polynomials

# Enumeration

## Analyzing the source code

The source code is quite short. A prime $p$ is hard-coded and is used as a modulus. The parameters $a$ and $b$ for the LCG $s_{i+1} = a s_i + b$ are also given. $x$ is constructed from the flag appended with some random padding to make it large, this is then used as the seed for an LCG.

Four consecutive outputs of the LCG are generated, let's call them $s_1, s_2, s_3, s_4$. After that we compute $h_1 \equiv s_1 s_2^{-1} \pmod{p}$ and $h_2 \equiv s_3 s_4^{-1} \pmod{p}$, then `h1 >> 48` and `h2 >> 48` is written to `out.txt`, essentially removing the last 48 bits of each number.

# Solution

## Finding the vulnerability

Truncated LCG outputs is a relatively common  occurance in CTFs, and solving them usually involves some kind of lattice reduction techniques. The goal is to recover $x$, this amounts to seed-recovery of this LCG, we should expect to be able to do this with the given information if we just set up the right equations.

# Exploitation

Let $s_1, s_2, s_3, s_4$ be the LCG outputs as before. Then we have the equations

$$
h_1 \equiv s_1 s_2^{-1} \pmod{p} \implies s_1 - h_1 s_2 \equiv 0 \pmod{p} \\
h_2 \equiv s_3 s_4^{-1} \pmod{p} \implies s_3 - h_2 s_4 \equiv 0 \pmod{p}
$$

Since the given seed is $x$ we can write $s_i = a^{i} x + b \frac{a^{i}-1}{a-1}$. The exact coefficients in front of $x$ and the constant term in each $s_i$ is not really important and is easily calculated automatically, so let's for simplicity write $s_i = c_i x + d_i$.

We are only given an approximation $\widetilde{h}_i$ of $h_i, i \in \{1, 2\}$ such that $h_i = \widetilde{h}_i + e_i$ where $e_i$ is the bits which were truncated, so $0 \le e_i \lt 2^{48}$. With this information we can construct the following equations, from the ones above, where only $x, e_1$ and $e_2$ are unknown:

$$
c_1 x + d_1 - (\widetilde{h}_1 + e_1) (c_2 x + d_2) \equiv 0 \pmod{p} \\
c_3 x + d_3 - (\widetilde{h}_2 + e_2) (c_4 x + d_4) \equiv 0 \pmod{p}
$$

These are two equations in three unknown, but we know that both $e_1$ and $e_2$ are very small in comparison to the modulus. If we eliminate $x$ then we will be left with only small unknown variables, this is perfect for use in Coppersmith's method.

We can automatically eliminate $x$ by computing the resultant of the two equations above with respect to $x$, this leaves us with a single polynomial in $e_1$ and $e_2$ which we can give to our Coppersmith implementation of choice.

The recently released implementation of Keegan Ryan's paper on automated Coppersmith solving, [cuso](https://github.com/keeganryan/cuso), is able to do this variable elimination automatically, so if this is used then it simplifies the solving process slightly.

The algebraic manipulation of the expressions is easily done in SageMath. The final solving using Coppersmith's method can be done with many different implementations, but not the one in SageMath itself since it only supports univariate polynomials.

As mentioned the solver by Keegan Ryan simplifies the process a bit, but we demonstrate that it can also be solved using more primitive tools like the [classic one by defund](https://github.com/defund/coppersmith).

We can easily construct the equations like this, leveraging Pythons ducky-typing

```python
x, e1, e2 = polygens(F, 'x, e1, e2')
sym_gen = lcg(x, a, b)
p1 = next(sym_gen) - ((h1<<trunc) + e1)*next(sym_gen)
p2 = next(sym_gen) - ((h2<<trunc) + e2)*next(sym_gen)
```

`p1` and `p2` are two now polynomials which share the root $(x, e_1, e_2)$. Computing the resultant is a bit annoying because of limitations in Singular which SageMath uses, so `p1.resultant(p2, x)` doesnt quite work and we have to use the more explicit construction `p1.sylvester_matrix(p2, x).det()`.

Then we have a polynomial which we can solve for $e_1$ and $e_2$ with using Coppersmith's method. After that we can substitue them into `p1` above and we get a univariate equation in $x$, allowing us to solve for it and finally recover the flag.
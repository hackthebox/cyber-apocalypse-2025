![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font 
size='5'>Kewiri</font>

​	4<sup>th</sup> March 2025

​	Prepared By: `rasti`

​	Challenge Author: `rasti`

​	Difficulty: <font color=lightgreen>Very Easy</font>

​	Classification: Official

# Synopsis

- `Kewiri` is a very easy challenge that is in the form of a questionnaire. The first three questions are about finite fields of prime order and the last three about elliptic curves defined over finite fields of prime order.



## Description

- TBD



## Skills Required

- Basic knowledge of the SageMath library
- Basic knowledge of finite fields
- Basic knowledge of ECC

## Skills Learned

- Learn how to factor large integers in SageMath knowing one large factor
- Learn to distinguish whether an element of a group is a generator using Lagrange's theorem
- Learn how to solve the ECDLP in anomalous curves

# Enumeration

In this challenge, we are not provided any downloadable file - just a docker instance to connect to. By connecting to it, we see that this challenge is a questionnaire. Usually, in this type of challenges, we have to answer a few questions correct in order to get the flag.

# Solution

Let us start by examining all the questions one by one.

### Question 1

When we connect to the instance, we wait a few seconds so that the environment is initialized and then we are asked for the first question. It turns out that we have only two seconds to answer each question, otherwise we get `Too slow...`.

```
[!] The ancient texts are being prepared...
You have entered the Grand Archives of Eldoria! The scholars shall test your wisdom. Answer their questions to prove your worth and claim the hidden knowledge.
You are given the sacred prime: p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
[1] How many bits is the prime p? >
```

This question is straight forward. We can find the bit length of `p` by opening a python shell and typing:

```python
p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
print(p.bit_length())
```

### Question 2

The next question is:

> [2] Enter the full factorization of finite field F_p in ascending order of factors (format: p0,e0_p1,e1_ ..., where pi are the distinct factors and ei the multiplicities of each factor) > 

To answer that, we can use SageMath or any online factorization website, such as `factordb`. In this writeup, we will showcase SageMath for educational purposes. To define a finite field in Sage we can use the `GF` (Galois Field) constructor. The other important information required to answer this question is that the multiplicative order of a finite field defined over a prime $p$, is just $p-1$. Thus, the task is to factor $p-1$.

```python
F = GF(p)
print(factor(p-1))
```

Regarding the format of the answer, let us see how `factor` returns the factorization.

```python
sage: list(factor(9359))
[(7, 2), (191, 1)]
```

In this case, the proper format to answer, would be `7,2_191,1`.

### Question 3

The next question is:

> [3] For this question, you will have to send 1 if the element is a generator of the finite field F_p, otherwise 0.

Looks like a decisional problem. We will be provided with a few integers and we are called to determine whether they are generators in a limited amount of time.

From now on, we will refer only to the multiplicative group of the finite field $\mathbb{F}_p$. Therefore, the group operation will be multiplication and not addition.

Recall that a generator $g \in \mathbb{F}_p$ is an element with order $p-1$; that is, the smallest integer $k$ such that $g^k \equiv 1$ is $p-1$. In other words, by successive exponentiations, it generates the entire group. There are quite a few approaches for this, the naive approach would be to list all the powers $g^1, g^2, ..., g^k$ until we get $1$. However, for such large $p$ this is practically infeasible and we need an optimized solution. This is where Lagrange's theorem comes useful. The theorem tells us that:

> Let $G$ a group and $a \in G$. The order of $a$ divides the order of $G$.

Answers such as [[1]](https://math.stackexchange.com/a/3515578) and [[2]](https://crypto.stackexchange.com/a/40656) showcase how we can utilize this theorem to check if an element is a generator. The difficulty lies in the factorization of $p-1$ which we know already from question (2).

Therefore, we can write the following method to test if an element $g$ is a generator of $\mathbb{F}_p$.

```python
def is_generator(g):
		p_1_factors = list(factor(p-1))
    for f,_ in p_1_factors:
      	# ignore the multiplicity
        # we care only about the distinct factors
        if pow(g, (p-1)//f, p) == 1 and f != p-1:
            return False
		return True
```

It turns out that this should be repeated 17 times in total.

```python
for _ in range(17):
    g = int(io.recvuntil(b'? > ')[:-4])
    io.sendline(str(int(is_generator(g))).encode())
```

### Question 4

The first three questions were about finite fields of prime order, denoted as $\mathbb{F}_p$. The next three questions are about elliptic curves defined over prime finite fields, denoted as $E(\mathbb{F}_p)$.

> The scholars present a sacred mathematical construct, a curve used to protect the most guarded secrets of the realm. Only those who understand its nature may proceed.
> a = 408179155510362278173926919850986501979230710105776636663982077437889191180248733396157541580929479690947601351140
> b = 8133402404274856939573884604662224089841681915139687661374894548183248327840533912259514444213329514848143976390134
> [4] What is the order of the curve defined over F_p? > 

Again, using SageMath, we can construct elliptic curves using the `EllipticCurve` constructor.

```python
E = EllipticCurve(GF(p), [a,b])
```

The order can be computed as:

```python
print(E.order())
```

### Question 5

> [5] Enter the full factorization of the order of the elliptic curve defined over the finite field F_{p^3}. Follow the same format as in question 2 >

For this question, we have to work on the group $E(\mathbb{F}_{p^3})$. However, if we try declaring the elliptic curve as:

```python
E3 = EllipticCurve(GF(p^3), [a,b])
```

this might take indefinite amount of time to complete and that is because according to SageMath [docs](https://doc.sagemath.org/html/en/reference/finite_rings/sage/rings/finite_rings/finite_field_constructor.html#finite-fields), when no variable name is specified in the GF constructor, Sage attemps to to compute the pseudo-Conway polynomials which is usually an expensive task.

> If no variable name is specified for an extension field, Sage will fit the finite field into a compatible lattice of field extensions defined by pseudo-Conway polynomials.

and

> Note that the computation of pseudo-Conway polynomials is expensive when the degree is large and highly composite. If a variable name is specified then a random polynomial is used instead, which will be much faster to find.

Therefore, the solution is to pass a variable name into the GF constructor.

```python
E3 = EllipticCurve(GF(p^3, 'x'), [a,b])
```

This takes a few microseconds to finish.

The order of the curve $E3$ is:

```
9547468349770605965573984760817208987986240857800275642666264260062210623470017904319931275058250264223830562439645572562493214488086970563135688265933076141657703804791593446020774169988605421998202682898213433784381043211278976059744771523119218399190407965593665262490269084642700982261912090274007278407746985341700600062580644280196871035164
```

which is relatively large to factorise. However, this curve is defined over an extension field of $\mathbb{F}_p$ and as a result, $p$ itself is guaranteed to be a factor of $E3$'s order. When we explicitly know a prime factor of a large integer, we can go ahead and defining it in Sage as a user-defined prime:

```python
pari.addprimes(p)
```

The documentation of this method can be found [here](https://pari.math.u-bordeaux.fr/dochtml/html-stable/Arithmetic_functions.html#addprimes). Let us see this function in action:

```python
sage: from Crypto.Util.number import *
sage: p = getPrime(1024)
sage: q = getPrime(1024)
sage: n = p*q
sage: n
20757129878476196263766872240356958683650945798076285374429775626750970675513949330074446501516100612855517734182615205487375158770547675863132057845044511253612104340755258134472492863749974099238393211422482063848956290097603703403564775164108269935134123533832551877277983143057277347519638492514730585441221489703011952662960160030649683727711868449437792977325313522208091595856156628129900905301736295843987380979447190397144712286376614669181013408381064404716330492150142662639295566001441283955619169309869318853752127302884843929101272094587621444078042154214135497915486825032223429010111980881109120894619
sage: factor(n)
```

Normally, this would take forever to complete as $n$ is very large. However, we can add manually $p$ or $q$ in the pari dictionary and get an instant result when `factor` is called. That is because, when calling `factor`, SageMath first looks up at the table of user-defined primes and proceeds to factoring the integer at second phase.

```python
sage: pari.addprimes(p)
[135297421183906417726626566740392626259579894073148661948890956451534112118754812518541726232569467292282889478862196473691620312949705365444531155604964232384414519054467223902773473493544417851262252940216993215948007127456493797866112761691339199411393341226367641871932959447890003835446238132539812721059]
sage: factor(n)
135297421183906417726626566740392626259579894073148661948890956451534112118754812518541726232569467292282889478862196473691620312949705365444531155604964232384414519054467223902773473493544417851262252940216993215948007127456493797866112761691339199411393341226367641871932959447890003835446238132539812721059 * 153418518230746956832407389341510432321776318039049791930350617730834744222389125421305520696017649557031736476686177322840802928919743226100290944901830004530993711798893449524808895430620967209398867996295438442523055241368009393199337777457108938262414406752504285077712759094370202179724398445117658076841
```

Back to our challenge and armed with this knowledge, we can go ahead and manually add the prime $p$ in the table. This will result to instant factorization of the curve's order.

```python
sage: pari.addprimes(p)
[21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061]
sage: factor(E3.order())
2^2 * 7^2 * 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061 * <large_prime_factor>
```

Finally, we can submit the factorization as the answer following the same format as in question 2.

### Question 6

This is the last question.

> The final trial awaits. You must uncover the hidden multiplier "d" such that A = d * G.
> ⚔️ The chosen base point G has x-coordinate: 10754634945965100597587232538382698551598951191077578676469959354625325250805353921972302088503050119092675418338771
> 🔮 The resulting point A has x-coordinate: 776741307896310549358901148397047715054445374890300753826496778948879054114421829863318830784216542919559209003815

For this one, the player can just define the points over the curve $E$ and run `log(A, G)` to solve the discrete logarithm problem.

```python
sage: G = E.lift_x(10754634945965100597587232538382698551598951191077578676469959354625325250805353921972302088503050119092675418338771)
sage: A = E.lift_x(776741307896310549358901148397047715054445374890300753826496778948879054114421829863318830784216542919559209003815)
sage: %time log(A,G)
CPU times: user 257 ms, sys: 1.82 ms, total: 259 ms
Wall time: 258 ms
10467269628793371276566698866836952927307367226151628920389303503200368737798238832516990930420184955214737647295096
```

However, ECDLP is normally hard to solve whereas now the secret multiplier was recovered in a couple of milliseconds. The reason is that the curve $E$ is anomalous, which is caused due to the $E$'s order being equal to the prime $p$. This can be verified as:

```python
sage: E.order() == p
True
```

This makes ECDLP solveable via Smart's Attack.

After answering this last question, we finally get the flag.

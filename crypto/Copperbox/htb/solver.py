from sage.all import *
import re

p = 0x31337313373133731337313373133731337313373133731337313373133732ad
a = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
b = 0xdeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0de

def lcg(x, a, b):
    while True:
        yield (x := a*x + b)
        
trunc = 48
F = GF(p)

with open('output.txt') as o:
    h1 = int(o.readline().split(' = ')[1])
    h2 = int(o.readline().split(' = ')[1])

x, e1, e2 = polygens(F, 'x, e1, e2')
sym_gen = lcg(x, a, b)
p1 = next(sym_gen) - ((h1<<trunc) + e1)*next(sym_gen)
p2 = next(sym_gen) - ((h2<<trunc) + e2)*next(sym_gen)

R2 = F['e1, e2']
# resultant eliminating x, p1.resultant(p2, x) doesn't work
# because of singular
rel = R2(str(p1.sylvester_matrix(p2, x).det()))

# use this one or any other multivariate coppersmith solver
load('https://raw.githubusercontent.com/defund/coppersmith/refs/heads/master/coppersmith.sage')

e1, e2 = small_roots(rel, (1<<trunc, 1<<trunc))[0]
root = p1(e1=e1).univariate_polynomial().roots()[0][0]
flag = int(root).to_bytes(32, 'big')

print(re.search(rb'(HTB{.*})', flag).group(1).decode())
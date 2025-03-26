from Crypto.Util.number import *
import sympy
from math import lcm
from pwn import *

def factorint(p):
    return sympy.factorint(p)

def format_sympy_factorint(factor_dict):
    formatted_facs = []
    for key in factor_dict.keys():
        formatted_facs.append((key, factor_dict[key]))
    return formatted_facs

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
    
def ask_oracle(ctxt):
    io.sendlineafter(b'> ', b'2')
    io.recvuntil(b': ')
    io.sendline(hex(ctxt)[2:].encode())
    response = int(io.recvline().decode().split()[-1])
    return response


def twin_attack(c, e, n, all_bits): 
    bit_index = 0
    curr_ctxt = c
    mul = pow(2, e, n) # this is Enc(2) and due to RSA's homomorphic properties we can calculate Enc(2*m) for any m if we have Enc(m)
    m_space = [1, n - 1] # the range of possible values of the plaintext m
    
    while m_space[1] != m_space[0]:
        next_bit = all_bits[bit_index % len(all_bits)]
        if next_bit == 0:
            oracle_response = ask_oracle(curr_ctxt*(pow(2, e, n)) % n)
        else:
            oracle_response = ask_oracle(curr_ctxt)
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
            print(f"Number of tries = {bit_index + len(all_bits)}")
            return plaintext
    
    
def factor_M():
    io.recvuntil(b'power: ')
    M = int(io.recvline().decode().split()[-1])
    print(f'{M = }')
    io.sendlineafter(b'> ', b'1')
    n = int(io.recvline().decode().split()[-1])
    print(f'{n = }')
    enc_flag = int(io.recvline().decode().split()[-1])
    print(f'{enc_flag = }')
    e = 65537
    factor_list = format_sympy_factorint(factorint(M))
    return n, e, enc_flag, M, factor_list
    
def calc_period_length(M, factor_list):
    factors_lambda = carmichael_lambda(M, factor_list)
    lambda_factors_list = format_sympy_factorint(factorint(factors_lambda))
    print(f"λ(M) = {factors_lambda}")
    period = carmichael_lambda(factors_lambda, lambda_factors_list)
    print(f"λ(λ(M)) = period = {period}")
    return period
    
def get_period_values(period):
    period_bits = []
    for i in range(period):
        next_bit = ask_oracle(1)
        if next_bit == 1:
            period_bits.append(0)
        elif next_bit == 0:
            period_bits.append(1)
        else:
            print("hmm this shouldn't have happened")
            exit()
    return period_bits
    
def pwn():
    n, e, enc_flag, M, factor_list = factor_M()
    period = calc_period_length(M, factor_list)
    period_bits = get_period_values(period)
    flag = twin_attack(enc_flag, e, n, period_bits)
    print(long_to_bytes(flag))

if len(sys.argv) > 1:
    host, port = sys.argv[1].split(':')
    if len(sys.argv) == 2:
        io = remote(host, port)
    else:
        io = remote(host, port, level=sys.argv[2])
else:
    io = process(['python3', '../challenge/server.py'])
pwn()
        
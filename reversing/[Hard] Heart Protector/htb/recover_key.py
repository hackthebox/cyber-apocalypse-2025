from pwn import u8, u16, u32
import string, itertools

def ror(a, r):
    return 0xffffffff & ((a >> r) | (a << (32-r)))

def rol(a, r):
	return ror(a, 32-r)

def fnv1(data):
    val = 0x811c9dc5
    for c in data:
        val = ((0x1000193 * val) ^ c) & 0xffffffff
    return val

def add_ror13(data):
	val = 0
	for i in data:
		val += i
		val = ror(val, 0xd)
	return val

code = open('code.bin', 'rb').read()

enc_start = 0x22f
target_value_start = 0x42

enc_data = code[enc_start:enc_start+4*5]
target_value = u32(code[target_value_start:target_value_start+4])

enc_parts = [u32(enc_data[i:i+4]) for i in range(0, len(enc_data), 4)]
key = [-1 for _ in range(16)]

# indices order : [[10,12,14], [0,1,2,3], [5,6,7], [4], [11,13,15]]

key[4] = enc_parts[3] ^ 137
key[8] = 50
key[9] = 97

alph = '0123456789abcdef'#string.printable

for comb in itertools.product(alph, repeat=3):
    inp = ''.join(comb).encode()
    h1 = fnv1(inp)
    h2 = add_ror13(inp)
    if h1 == enc_parts[0]:
        key[10:15:2] = list(map(ord,comb))
        # print(inp)
    if h1 == enc_parts[2]:
        key[5:8] = list(map(ord,comb))
        # print(inp)
    if h2 == enc_parts[-1]:
        key[11:16:2] = list(map(ord,comb))
        # print(inp)

key0123_encoded = (enc_parts[1] ^ rol(621548, 4)) + 1869

key0123 = ''
P = 211

for i in range(4):
    key[i] = key0123_encoded % P
    key0123_encoded //= P

key = bytes(key)

assert fnv1(key) == target_value

key = key.decode()
print(f'{key = }')
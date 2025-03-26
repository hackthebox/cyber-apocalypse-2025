![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>Hourcle</font>

​	28<sup>th</sup> March 2025

​	Prepared By: `rasti`

​	Challenge Author: `rasti`

​	Difficulty: <font color=green>Easy</font>

​	Classification: Official

# Synopsis

- `Hourcle` is an easy crypto challenge in which the players have to apply a variant of the Chosen Plaintext ECB oracle attack to recover the admin's password. While this attack is usually applied for AES-ECB, in this challenge, the encryption scheme is AES-CBC decryption and due to its nature, identical plaintext blocks will lead to identical ciphertext blocks, a behaviour similar to AES-ECB. This behaviour makes it vulnerable to a Chosen Plaintext attack.



## Description

- TBD



## Skills Required

- Familiar with auditing Python source code
- Good knowledge of how AES-CBC and AES-ECB work
- Good research skills



## Skills Learned

- Familiarize with implementing custom attacks for AES-CBC
- Familiarize with the concept of the ECB oracle attack

# Enumeration

In this challenge we are provided with a single file and a docker instance to connect to.

- `server.py` : This is the main script that runs when we connect to the docker instance.

The source code is relatively small so let us go ahead and analyze it step by step.

## Analyzing the source code

The main script is provided below:

```python
def show_menu():
    return input('''
=========================================
||                                     ||
||   🏰 Eldoria's Shadow Keep 🏰       ||
||                                     ||
||  [1] Seal Your Name in the Archives ||
||  [2] Enter the Forbidden Sanctum    ||
||  [3] Depart from the Realm          ||
||                                     ||
=========================================

Choose your path, traveler :: ''')

def main():
    while True:
        ch = show_menu()
        print()
        if ch == '1':
            username = input('[+] Speak thy name, so it may be sealed in the archives :: ')
            pattern = re.compile(r"^[\w]{16,}$")
            if not pattern.match(username):
                print('[-] The ancient scribes only accept proper names-no forbidden symbols allowed.')
                continue
            encrypted_creds = encrypt_creds(username)
            print(f'[+] Thy credentials have been sealed in the encrypted scrolls: {encrypted_creds.hex()}')
        elif ch == '2':
            pwd = input('[+] Whisper the sacred incantation to enter the Forbidden Sanctum :: ')
            if admin_login(pwd):
                print(f"[+] The gates open before you, Keeper of Secrets! {open('flag.txt').read()}")
                exit()
            else:
                print('[-] You salt not pass!')
        elif ch == '3':
            print('[+] Thou turnest away from the shadows and fade into the mist...')
            exit()
        else:
            print('[-] The oracle does not understand thy words.')
```

We are given three options:

- We can provide our username, then the server encrypts our username along with the hardcoded application password and outputs them in hex format. Moreover, the username has to be at least 16 characters long.
- We can provide the application password and if it is correct, we get the flag.
- We can simply exit the application.

Our options are limited so let us focus on the first option and more specifically on the encryption scheme being used.

```python
import os, random, string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

KEY = os.urandom(32)

password = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(57)])

def encrypt_creds(user):
    padded = pad((user + password).encode(), 16)
    IV = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
    ciphertext = cipher.decrypt(padded)
    return ciphertext
```

To begin with, the key used by the cipher, is hardcoded and reused for each pair of credentials which is certainly an odd behaviour. Moreover, the cipher is not standard; AES in CBC decryption mode is chosen which is rather unusual for encryption.

# Solution

## Finding the vulnerability

Before diving into the vulnerability, let us recall how AES-CBC decryption works.

![](assets/aes-cbc.png)

Since it is used for encryption, `Ciphertext` and `Plaintext` are swapped.

One might notice that for identical plaintext blocks, the encryption produces the same blocks. This is an AES-ECB characteristic and it is the reason we avoid using it for cryptographic purposes. In this challenge though, AES is used in CBC decryption mode, which does not really change the exploitation process a lot.

# Exploitation

Knowing the initialisation vector, we can go ahead exploiting the AES-CBC oracle. After some minimal research online, one will stumble upon the so-called [AES-ECB oracle attack](https://www.ctfrecipes.com/cryptography/symmetric-cryptography/aes/mode-of-operation/ecb/ecb-oracle#exploitation) which is quite common in CTFs. The idea is briefly described below.

Suppose there is an oracle that encrypts messages of the form `user_input || secret`. The secret remains the same for each call to the oracle and suppose it is a 16-byte password. Then if we send input 15 bytes long, the blocks would be splitted as:

```
Block 0 : AAAAAAAAAAAAAAAx
Block 1 : xxxxxxxxxxxxxxxx
Block 2 : pppppppppppppppp
```

where $A$ our input bytes, `x` the unknown password bytes and `p` the padding bytes. Notice the following:

- Block 0 : We know everything **but** a single byte
- Block 1 : We know nothing
- Block 2 : We know the entire block

Even though the last byte of Block 0 is unknown, it is public knowledge that the password consists of alphanumeric characters so it is trivial to bruteforce it. Therefore, one can pre-fix 15 bytes and bruteforce the last byte of the first block as:

```
Block 0 : AAAAAAAAAAAAAAA?
```

The correct byte will match the original ciphertext of `AAAAAAAAAAAAAAAx`.

Having the first password byte, we can send 14-byte input bytes + the recovered password byte + bruteforce the second password byte:

```
Block 0 : AAAAAAAAAAAAAAx?
```

Back to our challenge, recall that we cannot send a username of less than 16 bytes therefore, we need to start from `Block 1` and not `Block 0`. This would mean that we start by sending 31 input bytes + 1 bruteforce byte and move on with the same approach.

The code below implements the AES-CBC decryption oracle attack.

```python
import string

alph = string.ascii_letters + string.digits
password = ''
block_num = 1

while len(password) < 57:
  	# prefix input bytes
    plaintext = 'x' * ((block_num+1) * 16 - 1 - len(password))
    # get the target ciphertext with which we can check the validity of the current bruteforce byte
    target_ct = encrypt(plaintext)
    current_target_ct_block = _b(target_ct)[block_num]
		
    # bruteforce each alphanumeric character
    for c in alph:
      	# send : input || password || ?
        pt = (plaintext + password + c).encode()
        current_test_ct_blocks = _b(encrypt(pt))

        if current_test_ct_blocks[block_num] == current_target_ct_block:
            password += c
            # if a full password block is filled, move to the next block
            if len(password) % 16 == 0:
                block_num += 1
            print(password)
            break
    else:
        print(f'oops || FAILED @ block = {block_num}')
        exit()
```

Having obtained the password, we can send the admin password and get the flag.

```python
def admin_login(pwd):
    io.sendlineafter(b'traveler :: ', b'2')
    io.sendlineafter(b'Sanctum :: ', pwd.encode())
    resp = io.recvline().decode().strip()
    return re.findall(r'HTB{.+}', resp)[0]

print(admin_login(password))
```

## Getting the flag

A final summary of all that was said above:

1. Notice that the encryption scheme being used is AES in CBC-decryption mode which is rather odd.
2. One might notice that this mode is very similar to AES-ECB. Thus, by nature, identical plaintext blocks lead to identical ciphertext blocks.
3. One can adjust the ECB-oracle attack for AES-CBC decryption and recover the password byte-by-byte.
4. Having the password, one can login and get the flag.

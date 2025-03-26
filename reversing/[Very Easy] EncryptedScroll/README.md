<img src="../../assets/banner.png" style="zoom: 80%;" align=center />

<img src="../../assets/htb.png" style="zoom: 80%;" align='left' /><font size="5">EncryptedScroll</font>

  6<sup>th</sup> 03 25

  Prepared By: clubby789

  Challenge Author: clubby789

  Difficulty: <font color=green>Very Easy</font>

  Classification: Official






# Synopsis

EncryptedScroll is a Very Easy reversing challenge. Players will analyze some basic arithmetic to extract the flag from the binary.

## Skills Required
- Familiarity with static and dynamic analysis tools
- Knowledge of simple obfuscation techniques
- Ability to bypass basic anti-debugging mechanisms

## Skills Learned
- How to analyze a compiled binary to extract hardcoded secrets
- Understanding string manipulation and character encoding in compiled programs

# Solution

Running the binary gives us the following output:

```
The ancient scroll hums with magical energy... Enter the mage’s spell:
```

If we enter a random string, it responds with:

```
The scroll remains unreadable... Try again.
```

We'll open the binary in a decompiler to analyze it.

## Analysis

Our input is passed to a `decrypt_message` function.

```c
  int64_t decrypt_message(char* arg1)

  char buf[0x28]
  __builtin_strcpy(dest: &buf, src: "IUC|t2nqm4`gm5h`5s2uin4u2d~")
  int32_t i = 0
  
  while (buf[i] != 0) {
      buf[i] -= 1
      i += 1
  }
  
  
  if (strcmp(arg1, &buf) != 0)
      puts(str: "The scroll remains unreadable... Try again.")
   else
      puts(str: "The Dragon's Heart is hidden beneath the Eternal Flame in El…")
```

A constant string is initialized, then 1 is subtracted from each byte. After this, it's compared to our input.

## Solving

One possible solution would be to patch out the `anti_debug` function, allowing us to use `ltrace` to see the arguments to `strcmp`. However, we can directly extract the compared string in Python.

```
string = b"IUC|t2nqm4`gm5h`5s2uin4u2d~"
print(''.join([chr(c - 1) for c in string]))
```

This will give us the flag.

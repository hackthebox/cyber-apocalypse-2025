![banner](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='6'>Singlestep</font>

17<sup>th</sup> March 2025

Prepared By: FizzBuzz101

Challenge Author: FizzBuzz101

Difficulty: <font color='orange'>Medium</font>




# Synopsis

Singlestep is a Medium reversing challenge. Players will analyse a metamorphic self-decrypting and re-encrypting 64 bit ELF. Each instruction is decrypted immediately before execution, and then re-encrypted immediately afterwards with the xor instruction.

### Skills Required
- Intermediate Reverse Engineering Abilities
- Binary Scripting Capabilities
- Rudimentary Linear Algebra Knowledge

### Skills Learned
- De-obfuscating a metamorphic self-decrypting binary

# Solution

## Preliminary Analysis

Starting from `main` in Binja, we see a function call to `sub_43e0`.
```
00008fe0  int32_t main(int32_t argc, char** argv, char** envp)

00008fe0  f30f1efa           endbr64 
00008fe4  55                 push    rbp {__saved_rbp}
00008fe5  4889e5             mov     rbp, rsp {__saved_rbp}
00008fe8  488b0529600100     mov     rax, qword [rel stdout]
00008fef  be00000000         mov     esi, 0x0
00008ff4  4889c7             mov     rdi, rax
00008ff7  e89481ffff         call    setbuf
00008ffc  b800000000         mov     eax, 0x0
00009001  e8dab3ffff         call    sub_43e0
00009006  b800000000         mov     eax, 0x0
0000900b  5d                 pop     rbp {__saved_rbp}
0000900c  c3                 retn     {__return_addr}
```

However, that function doesn't even make sense!

```
000043e0  int64_t sub_43e0(int16_t arg1 @ rax, int16_t arg2 @ rbx)

000043e0  9c                 pushfq   {var_8}
000043e1  813501000000e1e8…  xor     dword [rel data_43ec], 0xaeee8e1  {0xfa1e0ff3}
000043eb  9d                 popfq    {var_8}
000043ec  12e7               adc     ah, bh
000043ee  f0                 ??

000043ef                                               f0                 .       .
```

In IDA, these aren't even recognized as functions. What could be going on? Afterall, the program is printing out messages and also asking for our input.

Running the program under strace reveals a mprotect call that marked a section as RWX. Additionally, Binja recognizes an `_INIT_1` function, which comes from the .init_array section at `sub_13c0`. Looking more into strace, we can pretty much deduce what this function is doing.

```
openat(AT_FDCWD, "/proc/self/exe", O_RDONLY) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0`\22\0\0\0\0\0\0"..., 64) = 64
lseek(3, 123216, SEEK_SET)              = 123216
lseek(3, 125008, SEEK_SET)              = 125008
read(3, "\1\0\0\0\3\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0C\340\1\0\0\0\0\0"..., 64) = 64
getrandom("\x40\x11\xbb\x3c\x05\x5d\x45\x44", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x5f497b759000
brk(0x5f497b77a000)                     = 0x5f497b77a000
lseek(3, 122947, SEEK_SET)              = 122947
read(3, "\0.shstrtab\0.interp\0.note.gnu.pro"..., 266) = 266
lseek(3, 123216, SEEK_SET)              = 123216
read(3, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 64) = 64
lseek(3, 123280, SEEK_SET)              = 123280
read(3, "\v\0\0\0\1\0\0\0\2\0\0\0\0\0\0\0\30\3\0\0\0\0\0\0\30\3\0\0\0\0\0\0"..., 64) = 64
lseek(3, 123344, SEEK_SET)              = 123344
read(3, "\23\0\0\0\7\0\0\0\2\0\0\0\0\0\0\08\3\0\0\0\0\0\08\3\0\0\0\0\0\0"..., 64) = 64
lseek(3, 123408, SEEK_SET)              = 123408
read(3, "&\0\0\0\7\0\0\0\2\0\0\0\0\0\0\0h\3\0\0\0\0\0\0h\3\0\0\0\0\0\0"..., 64) = 64
lseek(3, 123472, SEEK_SET)              = 123472
read(3, "9\0\0\0\7\0\0\0\2\0\0\0\0\0\0\0\214\3\0\0\0\0\0\0\214\3\0\0\0\0\0\0"..., 64) = 64
lseek(3, 123536, SEEK_SET)              = 123536
read(3, "G\0\0\0\366\377\377o\2\0\0\0\0\0\0\0\260\3\0\0\0\0\0\0\260\3\0\0\0\0\0\0"..., 64) = 64
lseek(3, 123600, SEEK_SET)              = 123600
read(3, "Q\0\0\0\v\0\0\0\2\0\0\0\0\0\0\0\330\3\0\0\0\0\0\0\330\3\0\0\0\0\0\0"..., 64) = 64
lseek(3, 123664, SEEK_SET)              = 123664
read(3, "Y\0\0\0\3\0\0\0\2\0\0\0\0\0\0\0\30\6\0\0\0\0\0\0\30\6\0\0\0\0\0\0"..., 64) = 64
lseek(3, 123728, SEEK_SET)              = 123728
read(3, "a\0\0\0\377\377\377o\2\0\0\0\0\0\0\0,\7\0\0\0\0\0\0,\7\0\0\0\0\0\0"..., 64) = 64
lseek(3, 123792, SEEK_SET)              = 123792
read(3, "n\0\0\0\376\377\377o\2\0\0\0\0\0\0\0`\7\0\0\0\0\0\0`\7\0\0\0\0\0\0"..., 64) = 64
lseek(3, 123856, SEEK_SET)              = 123856
read(3, "}\0\0\0\4\0\0\0\2\0\0\0\0\0\0\0\260\7\0\0\0\0\0\0\260\7\0\0\0\0\0\0"..., 64) = 64
lseek(3, 123920, SEEK_SET)              = 123920
read(3, "\207\0\0\0\4\0\0\0B\0\0\0\0\0\0\0\270\10\0\0\0\0\0\0\270\10\0\0\0\0\0\0"..., 64) = 64
lseek(3, 123984, SEEK_SET)              = 123984
read(3, "\221\0\0\0\1\0\0\0\6\0\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0\20\0\0\0\0\0\0"..., 64) = 64
lseek(3, 124048, SEEK_SET)              = 124048
read(3, "\214\0\0\0\1\0\0\0\6\0\0\0\0\0\0\0 \20\0\0\0\0\0\0 \20\0\0\0\0\0\0"..., 64) = 64
lseek(3, 124112, SEEK_SET)              = 124112
read(3, "\227\0\0\0\1\0\0\0\6\0\0\0\0\0\0\0@\21\0\0\0\0\0\0@\21\0\0\0\0\0\0"..., 64) = 64
lseek(3, 124176, SEEK_SET)              = 124176
read(3, "\240\0\0\0\1\0\0\0\6\0\0\0\0\0\0\0P\21\0\0\0\0\0\0P\21\0\0\0\0\0\0"..., 64) = 64
lseek(3, 124240, SEEK_SET)              = 124240
read(3, "\251\0\0\0\1\0\0\0\6\0\0\0\0\0\0\0`\22\0\0\0\0\0\0`\22\0\0\0\0\0\0"..., 64) = 64
close(3)                                = 0
openat(AT_FDCWD, "/proc/self/maps", O_RDONLY) = 3
newfstatat(3, "", {st_mode=S_IFREG|0444, st_size=0, ...}, AT_EMPTY_PATH) = 0
read(3, "5f494f220000-5f494f221000 r--p 0"..., 1024) = 1024
close(3)                                = 0
mprotect(0x5f494f221000, 36864, PROT_READ|PROT_WRITE|PROT_EXEC) = 0
```

The initializer function opens the binary itself to parse for some ELF headers. The strings in decompilation reveal that it is looking for the `.text` section.

```
0000161a                                  if (strcmp(buf_2 + zx.q(buf), ".text") == 0)
00001623                                      int64_t var_188
00001623                                      var_1b0_1 = var_188
00001631                                      var_1a8_1 = var_178
00001638                                      break
```

It then opens the program map file and looks for the first entry, which corresponds to executable base. 
```
000016dc                              FILE* fp
000016dc                              fp, r8, r9, zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7 = fopen(filename: "/proc/self/maps", mode: &data_1c9cb)
000016dc                              
000016f0                              if (fp == 0)
0000176c                                  rax_5 = 0
000016f0                              else
000016f2                                  int64_t var_1e0 = 0
0000171b                                  void var_118
0000171b                                  
0000171b                                  if (fgets(buf: &var_118, n: 0x100, fp) != 0)
0000173d                                      __isoc99_sscanf(s: &var_118, format: &data_1c9dd, &var_1e0, &data_1c9dd)
```

Effectively, the initializer function parses the ELF header for the `.text` metadata, the program maps to deduce PIE base, and marks the whole region as RWX. This implies that their is some metamorphic code trickery.

## Metamorphic Code Analysis

Hopefully, this binary doesn't really implement anti-debug (strace doesn't show any `ptrace` calls). Let's run this in gef to analyze how this binary self-decrypts. Let's break at (0x0000555555554000 + 0x43e0), which is the first instance of the obfuscation mechanism from main. By the time we hit the last `popf` in that initial sequence, we see the code in the following state:
```
   0x5555555583e0:  pushf  
   0x5555555583e1:  xor    DWORD PTR [rip+0x1],0xaeee8e1        # 0x5555555583ec
=> 0x5555555583eb:  popf   
   0x5555555583ec:  endbr64 
   0x5555555583f0:  pushf  
   0x5555555583f1:  xor    DWORD PTR [rip+0xfffffffffffffff1],0xaeee8e1        # 0x5555555583ec
   0x5555555583fb:  popf   
```

An `endbr64` instruction appears, which is commonly the first instruction in function prologues since the introduction of Intel IBT technology. The assembly sequence afterwards then xor re-encrypts that instruction with the same xor key. This obfuscation mechanism is the essence of this challenge. Each real original instruction is nested between a prologue decryption and epilogue encryption mechanism. Let's look at the next instruction. 
```
   0x5555555583fc:  pushf  
   0x5555555583fd:  xor    BYTE PTR [rip+0x1],0x6e        # 0x555555558405
=> 0x555555558404:  popf   
   0x555555558405:  push   rbp
   0x555555558406:  pushf  
   0x555555558407:  xor    BYTE PTR [rip+0xfffffffffffffff7],0x6e        # 0x555555558405
   0x55555555840e:  popf 
```

While `endbr64` is a 4 byte instruction, `push rbp` is a single byte. The xor key this time is just 1 byte. The next instruction shows perhaps the final pattern we will encounter.
```
   0x55555555840f:  pushf  
   0x555555558410:  xor    WORD PTR [rip+0x8],0xbd49        # 0x555555558421
   0x555555558419:  xor    BYTE PTR [rip+0x3],0xf8        # 0x555555558423
=> 0x555555558420:  popf   
   0x555555558421:  mov    rbp,rsp
   0x555555558424:  pushf  
   0x555555558425:  xor    WORD PTR [rip+0xfffffffffffffff3],0xbd49        # 0x555555558421
   0x55555555842e:  xor    BYTE PTR [rip+0xffffffffffffffee],0xf8        # 0x555555558423
   0x555555558435:  popf   
```

Two xor instructions this time! This is because `mov rbp, rsp` is a 3 byte instruction. The rip relative xor instruction only operates in byte, word, and dword sizes, so a 3 byte instruction will require a combination of a word and byte sized xor. Note that qword is not possible with an intermediate. The `pushf` and `popf` are required to preserve the state of the EFLAGS register (the wonders of CISC architectures...), as xor affects its state.

## Deobfuscating

Obviously, figuring out what the program is doing via single-stepping in gdb is not fun. One can try it, but soon will realize that the program is quite long (from a single stepping perspective). Let's write a deobfuscator!

There are many ways to approach this. I used capstone for instruction disassembly and pwntools for ELF section parsing. Starting from the main function, I applied a depth first search traversal approach for automatic binary deobfuscation. For each xor decryption sequence (pushf, xor with positive rip offset, popf), I decrypted the associated instruction with the given constants and replaced the decryption sequence with nops. For each xor encryption sequence (pushf, xor with negative rip offset, popf), I replaced them with nops. Disassembly ends at `ret` instructions, and `call` instruction destinations are further explored as long as if they are in the `.text` section.

The following is my script:
```py
from pwn import *
import capstone
import sys
import ctypes

def xor(a, b):
    return bytes([a ^ b for a, b in zip(a, b)])

def disas_single(data):
    disas = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    inst = next(disas.disasm(data, 0))
    return inst, inst.size, inst.mnemonic

def deobufscate(elf, code, text_off, text_end, addr, modified):
    stop = False
    while not stop:
        inst, sz, mneumonic = disas_single(code[addr:])
        if mneumonic == 'ret':
            stop = True
        elif mneumonic == 'call':
            call_dst = addr + ctypes.c_int64(int(inst.op_str, 16)).value
            if call_dst >= text_off and call_dst <= text_end:
                deobufscate(elf, code, text_off, text_end, call_dst, modified)
        elif mneumonic == 'xor':
            if '[rip + ' in inst.op_str:
                rip_rel = int(inst.op_str.split('[rip + ')[1].split(']')[0], 16)
                key = int(inst.op_str.split(',')[1], 16)
                decrypt = b''
                if inst.op_str.startswith('qword ptr '):
                    decrypt = xor(p64(key), code[addr + sz + rip_rel: addr + sz + rip_rel + 8])
                elif inst.op_str.startswith('dword ptr '):
                    decrypt = xor(p32(key), code[addr + sz + rip_rel: addr + sz + rip_rel + 4])
                elif inst.op_str.startswith('word ptr '):
                    decrypt = xor(p16(key), code[addr + sz + rip_rel: addr + sz + rip_rel + 2])
                elif inst.op_str.startswith('byte ptr '):
                    decrypt = xor(p8(key), code[addr + sz + rip_rel: addr + sz + rip_rel + 1])
                assert(len(decrypt) in [1, 2, 4, 8])
                for i, b in enumerate(decrypt):
                    modified[addr + sz + rip_rel + i] = b
                for i in range(addr, addr + sz):
                    modified[i] = 0x90
                if code[addr - 0x1] == 0x9c:
                    modified[addr - 0x1] = 0x90
                if code[addr + sz] == 0x9d:
                    modified[addr + sz] = 0x90
            elif '[rip -' in inst.op_str:
                for i in range(addr, addr + sz):
                    modified[i] = 0x90
                if code[addr - 0x1] == 0x9c:
                    modified[addr - 0x1] = 0x90
                if code[addr + sz] == 0x9d:
                    modified[addr + sz] = 0x90
            code = bytes(modified)
        addr += sz


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'{sys.argv[0]} obfuscated main_offset')
        exit(1)
    elf = ELF(sys.argv[1])
    main = int(sys.argv[2], 16)
    text_off = elf.get_section_by_name('.text').header.sh_offset
    text_end = elf.get_section_by_name('.text').header.sh_offset + elf.get_section_by_name('.text').header.sh_size
    sz = text_off + text_end
    with open(elf.path, 'rb') as f:
        full = f.read()
    data = full[:sz]
    modified = bytearray(data)
    deobufscate(elf, data, text_off, text_end, main, modified)
    with open(f'{elf.path}_deobfuscate', 'wb') as f:
        f.write(bytes(modified) + full[sz:])

```

Running this should return a behaviorally equivalent binary but with the obfuscation removed. Let's open this in a decompiler now.

## Reversing the de-obfuscated version

Here is `sub_4500` again:

```
000043e0  int64_t sub_43e0()

00004492      void* fsbase
00004492      int64_t rax = *(fsbase + 0x28)
00004512      int64_t var_218
00004512      __builtin_memset(s: &var_218, c: 0, n: 0x200)
00005991      void var_278
00005991      sub_1820(&var_278, 4, 4)
00005a78      void var_258
00005a78      sub_1820(&var_258, 4, 4)
00005b5f      void var_238
00005b5f      sub_1820(&var_238, 4, 4)
00005c71      sub_2180(&var_278, 0, 0, 0x58)
00005d97      sub_2180(&var_278, 0, 1, -0x11)
00005ea9      sub_2180(&var_278, 0, 2, 0x13)
00005fcf      sub_2180(&var_278, 0, 3, -0x39)
000060e1      sub_2180(&var_278, 1, 0, 0x2d)
00006207      sub_2180(&var_278, 1, 1, -9)
00006319      sub_2180(&var_278, 1, 2, 0xa)
0000643f      sub_2180(&var_278, 1, 3, -0x1d)
00006565      sub_2180(&var_278, 2, 0, -0x38)
00006677      sub_2180(&var_278, 2, 1, 0xb)
0000679d      sub_2180(&var_278, 2, 2, -0xc)
000068af      sub_2180(&var_278, 2, 3, 0x24)
000069d5      sub_2180(&var_278, 3, 0, -0x28)
00006ae7      sub_2180(&var_278, 3, 1, 8)
00006c0d      sub_2180(&var_278, 3, 2, -9)
00006d1f      sub_2180(&var_278, 3, 3, 0x1a)
00006db0      puts(str: &data_1c8c8)
00006e41      puts(str: &data_1c918)
00006ed2      puts(str: data_1f010)
00006f8e      printf(format: &data_1c968)
00007075      int32_t rax_3 = read(fd: 0, buf: &var_218, nbytes: 0x100)
00007075      
000071fc      if (rax_3 s>= 0 && *(&var_218 + sx.q(rax_3 - 1)) == 0xa)
0000729c          *(&var_218 + sx.q(rax_3 - 1)) = 0
0000729c      
0000737c      if (sub_3690(&var_218) == 0x13)
00007437          int32_t var_29c_1 = 0
0000747c          char var_29e_1 = 1
00007da8          int64_t var_118
00007da8          
00007da8          for (int32_t i = 0; i s<= 0x12; i += 1)
000076f6              if (i s% 5 != 4)
000078f9                  int32_t rax_25 = var_29c_1
00007950                  var_29c_1 = rax_25 + 1
00007a2a                  *(&var_118 + sx.q(rax_25)) = *(&var_218 + sx.q(i))
00007bf9                  int32_t rax_33
00007bf9                  
00007bf9                  if (*(&var_218 + sx.q(i)) s<= 0x40 || *(&var_218 + sx.q(i)) s> 0x5a)
00007c76                      rax_33 = 0
00007bf9                  else
00007c23                      rax_33 = 1
00007c23                  
00007cd0                  int32_t rax_34
00007cd0                  rax_34.b = (rax_33 & zx.d(var_29e_1)) != 0
00007cfa                  var_29e_1 = rax_34.b
000076f6              else
00007874                  uint32_t rax_24
00007874                  rax_24.b = (zx.d(*(&var_218 + sx.q(i)) == 0x2d) & zx.d(var_29e_1)) != 0
0000789e                  var_29e_1 = rax_24.b
0000789e          
00007e56          if (var_29e_1 == 1)
00008487              for (int32_t i_1 = 0; i_1 s<= 3; i_1 += 1)
000083d9                  for (int32_t j = 0; j s<= 3; j += 1)
0000832e                      sub_2180(&var_258, sx.q(i_1), sx.q(j), sx.q(sx.d(*(&var_118 + sx.q(j + (i_1 << 2)))) - 0x41 - i_1 * j))
0000832e              
000084be              char var_29d_1 = 1
000085ff              sub_2630(&var_278, &var_258, &var_238)
000085ff              
00008d60              for (int32_t i_2 = 0; i_2 s<= 3; i_2 += 1)
00008cb2                  for (int32_t j_1 = 0; j_1 s<= 3; j_1 += 1)
00008863                      int64_t var_280
00008863                      sub_1ca0(&var_238, sx.q(i_2), sx.q(j_1), &var_280)
00008863                      
000088f0                      if (i_2 != j_1)
00008b5c                          int64_t rax_56
00008b5c                          rax_56.b = var_280 == 0
00008bda                          uint32_t rax_58
00008bda                          rax_58.b = (zx.d(rax_56.b) & zx.d(var_29d_1)) != 0
00008c04                          var_29d_1 = rax_58.b
000088f0                      else
000089b7                          int64_t rax_53
000089b7                          rax_53.b = var_280 == 1
00008a35                          uint32_t rax_55
00008a35                          rax_55.b = (zx.d(rax_53.b) & zx.d(var_29d_1)) != 0
00008a5f                          var_29d_1 = rax_55.b
00008a5f              
00008dcf              if (var_29d_1 == 0)
00008ee1                  sub_3ea0()
00008dcf              else
00008e63                  sub_3fc0(&var_218)
00007e56          else
00007eaf              sub_3ea0()
0000737c      else
000073d5          sub_3ea0()
000073d5      
00008f6d      if (rax == *(fsbase + 0x28))
00008fc2          return rax - *(fsbase + 0x28)
00008fc2      
00008f97      __stack_chk_fail()
00008f97      noreturn
```

`sub_1820` is this:
```
00001820  int64_t* sub_1820(int64_t* arg1, int64_t arg2, int64_t arg3)

00001930      *arg1 = arg2
00001989      arg1[1] = arg3
00001aac      arg1[2] = calloc(n: arg2 * arg3, elem_size: 8)
00001ae2      return arg1
```

`sub_2180` is this:
```
00002180  int64_t sub_2180(int64_t* arg1, int64_t arg2, int64_t arg3, int64_t arg4)

000022d6      if (arg2 u>= *arg1)
00002300          return 0
00002300      
000023ac      if (arg3 u>= arg1[1])
000023d6          return 0
000023d6      
000025c7      *(arg1[2] + ((arg3 + arg1[1] * arg2) << 3)) = arg4
000025ef      return 1
```

`sub_1ca0` is this:
```
00001ca0  int64_t sub_1ca0(int64_t* arg1, int64_t arg2, int64_t arg3, int64_t* arg4)

00001df6      if (arg2 u>= *arg1)
00001e20          return 0
00001e20      
00001ecc      if (arg3 u>= arg1[1])
00001ef6          return 0
00001ef6      
0000210e      *arg4 = *(((arg3 + arg1[1] * arg2) << 3) + arg1[2])
00002136      return 1
```

These are initializer, setters, and getters for a 2d array of `int64_t`, like matrices. The struct is this:
```c
struct matrix_t
{
    size_t rows;
    size_t cols;
    int64_t *vals;
};
```

`sub_3690` is just `strlen`:
```
00003690  int64_t sub_3690(char* arg1)

0000370e      char* var_20 = arg1
00003734      int64_t result = 0
00003734      
00003840      while (*var_20 != 0)
0000378d          result += 1
000037b8          var_20 = &var_20[1]
000037b8      
0000388a      return result
```

`sub_3ea0` is a lose function, while `sub_3fc0` is a win function based on the strings. 

`sub_2630` is harder to discern, however it is taking in 3 matrices based on how those variables are used in the matrix initialization function. Upon retyping and looking at the algorithm, we see that it is just matrix multiplication.
```
00002630  int64_t mat_mult_2630(struct matrix_t* arg1, struct matrix_t* arg2, struct matrix_t* arg3)

00002713      void* fsbase
00002713      int64_t rax = *(fsbase + 0x28)
00002824      int64_t result
00002824      
00002824      if (arg1->cols != arg2->rows)
0000284e          result = 0
00002824      else if (arg3->rows != arg1->rows || arg3->cols != arg2->cols)
00002a44          result = 0
00002a1a      else
00002aa3          int32_t var_34_1 = 0
00002aa3          
0000356c          while (sx.q(var_34_1) u< arg1->rows)
00002b0d              int32_t var_30_1 = 0
00002b0d              
00003468              while (sx.q(var_30_1) u< arg2->cols)
00002b71                  int64_t var_18_1 = 0
00002bab                  int32_t var_2c_1 = 0
00002bab                  
00003188                  while (true)
00003188                      if (sx.q(var_2c_1) u>= arg2->rows)
0000331d                          if (set_mat_val_2180(arg3, sx.q(var_34_1), sx.q(var_30_1), var_18_1) != 1)
00003347                              result = 0
00003372                              goto label_35eb
00003372                          
00003396                          var_30_1 += 1
000033a5                          break
000033a5                      
00002c0f                      int64_t var_28 = 0
00002c43                      int64_t var_20 = 0
00002c43                      
00002ddb                      if (get_mat_val_1ca0(arg1, sx.q(var_34_1), sx.q(var_2c_1), &var_28) != 1)
00002e05                          result = 0
00002e30                          goto label_35eb
00002e30                      
00002fc2                      if (get_mat_val_1ca0(arg2, sx.q(var_2c_1), sx.q(var_30_1), &var_20) != 1)
00002fec                          result = 0
00003017                          goto label_35eb
00003017                      
0000308f                      var_18_1 += var_20 * var_28
000030ab                      var_2c_1 += 1
000030ab              
0000348f              var_34_1 += 1
0000359a          result = 1
0000359a      
000035eb      label_35eb:
000035eb      *(fsbase + 0x28)
000035eb      
00003626      if (rax == *(fsbase + 0x28))
0000367b          return result
0000367b      
00003650      __stack_chk_fail()
00003650      noreturn

```

Now looking back at `sub_43c0`:
```
000043e0  int64_t sub_43e0()

00004492      void* fsbase
00004492      int64_t rax = *(fsbase + 0x28)
00004512      char var_218[0x100]
00004512      __builtin_memset(s: &var_218, c: 0, n: 0x100)
00004ff2      char s[0x100]
00004ff2      __builtin_memset(&s, c: 0, n: 0x100)
00005991      struct matrix_t var_278
00005991      init_mat_1820(&var_278, 4, 4)
00005a78      struct matrix_t var_258
00005a78      init_mat_1820(&var_258, 4, 4)
00005b5f      struct matrix_t var_238
00005b5f      init_mat_1820(&var_238, 4, 4)
00005c71      set_mat_val_2180(&var_278, 0, 0, 0x58)
00005d97      set_mat_val_2180(&var_278, 0, 1, -0x11)
00005ea9      set_mat_val_2180(&var_278, 0, 2, 0x13)
00005fcf      set_mat_val_2180(&var_278, 0, 3, -0x39)
000060e1      set_mat_val_2180(&var_278, 1, 0, 0x2d)
00006207      set_mat_val_2180(&var_278, 1, 1, -9)
00006319      set_mat_val_2180(&var_278, 1, 2, 0xa)
0000643f      set_mat_val_2180(&var_278, 1, 3, -0x1d)
00006565      set_mat_val_2180(&var_278, 2, 0, -0x38)
00006677      set_mat_val_2180(&var_278, 2, 1, 0xb)
0000679d      set_mat_val_2180(&var_278, 2, 2, -0xc)
000068af      set_mat_val_2180(&var_278, 2, 3, 0x24)
000069d5      set_mat_val_2180(&var_278, 3, 0, -0x28)
00006ae7      set_mat_val_2180(&var_278, 3, 1, 8)
00006c0d      set_mat_val_2180(&var_278, 3, 2, -9)
00006d1f      set_mat_val_2180(&var_278, 3, 3, 0x1a)
00006db0      puts(str: &data_1c8c8)
00006e41      puts(str: &data_1c918)
00006ed2      puts(str: data_1f010)
00006f8e      printf(format: &data_1c968)
00007075      int32_t rax_3 = read(fd: 0, buf: &var_218, nbytes: 0x100)
00007075      
000071fc      if (rax_3 s>= 0 && var_218[sx.q(rax_3 - 1)] == 0xa)
0000729c          var_218[sx.q(rax_3 - 1)] = 0
0000729c      
0000737c      if (strlen_3690(&var_218) == 0x13)
00007437          int32_t var_29c_1 = 0
0000747c          char var_29e_1 = 1
0000747c          
00007da8          for (int32_t i = 0; i s<= 0x12; i += 1)
000076f6              if (i s% 5 != 4)
000078f9                  int32_t rax_25 = var_29c_1
00007950                  var_29c_1 = rax_25 + 1
00007a2a                  s[sx.q(rax_25)] = var_218[sx.q(i)]
00007bf9                  int32_t rax_33
00007bf9                  
00007bf9                  if (var_218[sx.q(i)] s<= 0x40 || var_218[sx.q(i)] s> 0x5a)
00007c76                      rax_33 = 0
00007bf9                  else
00007c23                      rax_33 = 1
00007c23                  
00007cd0                  int32_t rax_34
00007cd0                  rax_34.b = (rax_33 & zx.d(var_29e_1)) != 0
00007cfa                  var_29e_1 = rax_34.b
000076f6              else
00007874                  uint32_t rax_24
00007874                  rax_24.b = (zx.d(var_218[sx.q(i)] == 0x2d) & zx.d(var_29e_1)) != 0
0000789e                  var_29e_1 = rax_24.b
0000789e          
00007e56          if (var_29e_1 == 1)
00008487              for (int32_t i_1 = 0; i_1 s<= 3; i_1 += 1)
000083d9                  for (int32_t j = 0; j s<= 3; j += 1)
0000832e                      set_mat_val_2180(&var_258, sx.q(i_1), sx.q(j), sx.q(sx.d(s[sx.q(j + (i_1 << 2))]) - 0x41 - i_1 * j))
0000832e              
000084be              char var_29d_1 = 1
000085ff              mat_mult_2630(&var_278, &var_258, &var_238)
000085ff              
00008d60              for (int32_t i_2 = 0; i_2 s<= 3; i_2 += 1)
00008cb2                  for (int32_t j_1 = 0; j_1 s<= 3; j_1 += 1)
00008863                      int64_t var_280
00008863                      get_mat_val_1ca0(&var_238, sx.q(i_2), sx.q(j_1), &var_280)
00008863                      
000088f0                      if (i_2 != j_1)
00008b5c                          int64_t rax_56
00008b5c                          rax_56.b = var_280 == 0
00008bda                          uint32_t rax_58
00008bda                          rax_58.b = (zx.d(rax_56.b) & zx.d(var_29d_1)) != 0
00008c04                          var_29d_1 = rax_58.b
000088f0                      else
000089b7                          int64_t rax_53
000089b7                          rax_53.b = var_280 == 1
00008a35                          uint32_t rax_55
00008a35                          rax_55.b = (zx.d(rax_53.b) & zx.d(var_29d_1)) != 0
00008a5f                          var_29d_1 = rax_55.b
00008a5f              
00008dcf              if (var_29d_1 == 0)
00008ee1                  fail_3ea0()
00008dcf              else
00008e63                  win_3fc0(&var_218)
00007e56          else
00007eaf              fail_3ea0()
0000737c      else
000073d5          fail_3ea0()
000073d5      
00008f6d      if (rax == *(fsbase + 0x28))
00008fc2          return rax - *(fsbase + 0x28)
00008fc2      
00008f97      __stack_chk_fail()
00008f97      noreturn

```

It checks that the input is of length 0x13, that all characters are between 'A' and 'Z', except for characters at index positions where idx % 5 == 4. It only saves the characters between 'A' and 'Z', and then fills a matrix up with it here:
```
00007e56          if (var_29e_1 == 1)
00008487              for (int32_t i_1 = 0; i_1 s<= 3; i_1 += 1)
000083d9                  for (int32_t j = 0; j s<= 3; j += 1)
0000832e                      set_mat_val_2180(&var_258, sx.q(i_1), sx.q(j), sx.q(sx.d(s[sx.q(j + (i_1 << 2))]) - 0x41 - i_1 * j))
```

Then, it multiples a pre-initialized matrix with the input matrix, and then ensures that the resulting matrix is a 4 by 4 identity matrix. This means that the input matrix has to be the inverse of the other matrix based on rudimentary linear algebra knowledge.

```
000085ff              mat_mult_2630(&var_278, &var_258, &var_238)
000085ff              
00008d60              for (int32_t i_2 = 0; i_2 s<= 3; i_2 += 1)
00008cb2                  for (int32_t j_1 = 0; j_1 s<= 3; j_1 += 1)
00008863                      int64_t var_280
00008863                      get_mat_val_1ca0(&var_238, sx.q(i_2), sx.q(j_1), &var_280)
00008863                      
000088f0                      if (i_2 != j_1)
00008b5c                          int64_t rax_56
00008b5c                          rax_56.b = var_280 == 0
00008bda                          uint32_t rax_58
00008bda                          rax_58.b = (zx.d(rax_56.b) & zx.d(var_29d_1)) != 0
00008c04                          var_29d_1 = rax_58.b
000088f0                      else
000089b7                          int64_t rax_53
000089b7                          rax_53.b = var_280 == 1
00008a35                          uint32_t rax_55
00008a35                          rax_55.b = (zx.d(rax_53.b) & zx.d(var_29d_1)) != 0
00008a5f                          var_29d_1 = rax_55.b
```

## Finding the correct input

Retrieving the correct input from this crackme is quite simple. We first find the inverse of the program's matrix:
```py
import numpy as np

matrix = np.array([[88, -17, 19, -57], [45, -9, 10, -29], [-56, 11, -12, 36], [-40, 8, -9, 26]])

ans = np.linalg.inv(matrix)
```

Then we apply the simple transformations on the input:
```py
flag = ''
for i in range(4):
    for j in range(4):
        flag += chr(round(ans[i][j]) + i * j + 0x41)
    flag += '-'
flag = flag[:-1]
```

We get `BFCF-EJJL-CKKL-BLJQ`. Typing this into the program should result in the proper flag (which is XOR stream encrypted by the correct serial).


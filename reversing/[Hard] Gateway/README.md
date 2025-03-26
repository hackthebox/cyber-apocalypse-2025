![banner](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='6'>Gateway</font>

17<sup>th</sup> March 2025

Prepared By: FizzBuzz101

Challenge Author: FizzBuzz101

Difficulty: <font color='red'>Hard</font>




# Synopsis

Gateway is a Hard reversing challenge. Players will reverse a 64-bit polyglot binary presented as an i386 statically linked ELF. Much of the flag checking logic is hidden away as 64-bit code, and execution is switched between compatiblity and 64-bit mode through the [Heavensgate](https://0xk4n3ki.github.io/posts/Heavens-Gate-Technique/) malware technique. Traditionally, Heavensgate is a Windows technique due to WoW64, but it can be applied in a [limited way](https://redcanary.com/blog/threat-detection/heavens-gate-technique-on-linux/) on Linux.

### Skills Required
- Intermediate Reverse Engineering Abilities
- x86 Architectural Knowledge on Segmentation Registers

### Skills Learned
- De-obfuscating an x86/amd64 polyglot utilizing the Heavensgate technique
- Bypassing anti-decompilation/anti-disassembly measures

# Solution

## Preliminary Analysis

The binary is statically linked and stripped. In this day and era, this really shouldn't be a problem thanks to IDA FLARE signatures or Binary Ninja sigkit. Additionally, library functions aren't heavily used in this challenge. One can find main as the last call in `_start` is effectively `__libc_start_main(main, ...`. This makes main at `sub_8049b7c`.

Unfortunately, the decompilation looks really broken halfway through the function in Binary Ninja (and IDA as well).
```
08049b7c  int32_t sub_8049b7c()

08049b83      void* const __return_addr_1 = __return_addr
08049b86      int32_t ebp
08049b86      int32_t var_8 = ebp
08049b8c      void* var_18 = &arg_4
08049b9e      void* gsbase
08049b9e      int32_t eax = *(gsbase + 0x14)
08049ba4      int32_t var_24 = eax
08049ba7      bool p = unimplemented  {xor eax, eax}
08049ba7      bool a = undefined
08049ba9      int32_t var_a4 = 0
08049bc5      void s_2
08049bc5      __builtin_memset(s: &s_2, c: 0, n: 0x7c)
08049bd9      void s_1
08049bd9      __builtin_memset(s: &s_1, c: 0, n: 0x80)
08049bf0      void var_124
08049bf0      int32_t ecx
08049bf0      int32_t esi
08049bf0      int32_t edi
08049bf0      edi, esi, ecx = __builtin_memcpy(dest: &var_124, src: &data_80de860, n: 0x80)
08049bf2      int32_t s
08049bf2      __builtin_memset(&s, c: 0, n: 0x18)
08049c34      int32_t* var_1e4 = &s
08049c34      int32_t var_1e8 = ecx
08049c34      void* const var_1ec = &data_80de860
08049c34      int32_t* var_1f0 = &data_8114000
08049c34      int32_t** var_1f4 = &var_1f0
08049c34      int32_t* var_1f8 = &var_8
08049c34      int32_t var_1fc = esi
08049c34      int32_t var_200 = edi
08049c35      bool d
08049c35      int32_t var_204 = (0 ? 1 : 0) << 0xb | (d ? 1 : 0) << 0xa | (0 s< 0 ? 1 : 0) << 7 | (eax == eax ? 1 : 0) << 6 | (a ? 1 : 0) << 4 | (p ? 1 : 0) << 2 | (0 ? 1 : 0)
08049c38      int32_t var_208 = 0x23
08049c40      int32_t (* var_20c)(int32_t arg1, int32_t arg2, void* arg3, int32_t* arg4, int32_t arg5, int32_t arg6) = sub_8049c4b
08049c41      int32_t var_210 = 0x33
08049c49      int32_t (* var_214)() = sub_80499b9
08049c4a      undefined
```

## Obfuscation Analysis

It's time to go to the disassembly.
```
08049bf2  c78544feffff0000…  mov     dword [ebp-0x1bc {s}], 0x0
08049bfc  c78548feffff0000…  mov     dword [ebp-0x1b8 {var_1c0}], 0x0
08049c06  c7854cfeffff0000…  mov     dword [ebp-0x1b4 {var_1bc}], 0x0
08049c10  c78550feffff0000…  mov     dword [ebp-0x1b0 {var_1b8}], 0x0
08049c1a  c78554feffff0000…  mov     dword [ebp-0x1ac {var_1b4}], 0x0
08049c24  c78558feffff0000…  mov     dword [ebp-0x1a8 {var_1b0}], 0x0
08049c2e  8d8544feffff       lea     eax, [ebp-0x1bc {s}]
08049c34  60                 pushad   {var_1e4} {s} {var_1e8} {var_1ec} {var_1f0} {var_1f4} {var_1f0} {var_1f8} {var_8} {var_1fc} {var_200}  {data_80de860}  {data_8114000}
08049c35  9c                 pushfd   {var_204}
08049c36  89c3               mov     ebx, eax {s}
08049c38  6a23               push    0x23 {var_208}
08049c3a  8d054b9c0408       lea     eax, [sub_8049c4b]
08049c40  50                 push    eax {var_20c}  {sub_8049c4b}
08049c41  6a33               push    0x33 {var_210}
08049c43  8d05b9990408       lea     eax, [sub_80499b9]
08049c49  50                 push    eax {var_214}  {sub_80499b9}
08049c4a  cb                 ret far 


08049c4b  int32_t sub_8049c4b(int32_t arg1, int32_t arg2, void* arg3, int32_t* arg4, int32_t arg5, int32_t arg6)

08049c4b  9d                 popfd    {__return_addr}
08049c4c  61                 popad    {arg1} {arg2} {arg3} {arg4} {arg5} {arg6} {arg_20}
```

Here, some values are moved into a context structure that is saved into ebx. Then, the program pushes all the general purpose registers and eflags register onto the stack. It also pushes 0x23, `sub_8049c4b`, 0x33, `sub_80499b9` onto the stack. Note that `sub_8049c4b` expects the stack to return back to where eflags is on top, before restoring the eflags and general purpose registers. Then, a ret far instruction is used.

According to x86 documentation, [ret far](https://www.felixcloutier.com/x86/ret) pops two items off the stack - the return address and a code segment address. On Linux, the [CS register](https://elixir.bootlin.com/linux/v6.13.6/source/arch/x86/include/asm/segment.h) determines whether a program is executing in compatibility mode or 64-bit mode. A value of 0x23 causes the program to execute in 32 bit mode, while a value of 0x33 causes the program to execute in 64 bit mode. Hence, the ret far transfers control flow to `sub_80499b9` in 64 bit mode.

The decompilation for that function looks pretty reasonable:
```
080499b9  int32_t sub_80499b9()

080499fd      sub_80497b5()
08049a02      return &data_8114000

```

```
080497b5  int32_t sub_80497b5()

080497c2      data_811531c = 0x1337
080497ce      return &data_8114000
```

But why is the function so large for such simple operations in `sub_80499b9`? Let's observe the assembly:
```
080499b9  int32_t sub_80499b9()

080499b9  e8a9050000         call    sub_8049f67
080499be  0542a60c00         add     eax, 0xca642  {data_8114000}
080499c3  31c0               xor     eax, eax
080499c5  40                 inc     eax  {0x0}
080499c6  7535               jne     0x80499fd  {0x1}

080499c8  89631c             mov     dword [ebx+0x1c], esp {__return_addr}  {data_811401c}
080499cb  48                 dec     eax
080499cc  83ec10             sub     esp, 0x10
080499cf  48                 dec     eax  {0xffffffff}
080499d0  c7c00f000000       mov     eax, 0xf
080499d6  48                 dec     eax
080499d7  f7d0               not     eax
080499d9  48                 dec     eax  {0xfffffff0}
080499da  21c4               and     esp, eax
080499dc  8b3b               mov     edi, dword [ebx]  {data_8114000}
080499de  8b7304             mov     esi, dword [ebx+0x4]  {data_8114004}
080499e1  8b5308             mov     edx, dword [ebx+0x8]  {data_8114008}
080499e4  8b4b0c             mov     ecx, dword [ebx+0xc]  {data_811400c}
080499e7  44                 inc     esp
080499e8  8b4310             mov     eax, dword [ebx+0x10]  {data_8114010}
080499eb  44                 inc     esp
080499ec  8b4b14             mov     ecx, dword [ebx+0x14]  {data_8114014}
080499ef  53                 push    ebx {var_12}  {data_8114000}
080499f0  e848060000         call    sub_804a03d
080499f5  5b                 pop     ebx {var_12}  {data_8114000}
080499f6  894318             mov     dword [ebx+0x18], eax  {data_8114018}
080499f9  8b631c             mov     esp, dword [ebx+0x1c]  {data_811401c}
080499fc  cb                 ret far 

080499fd  e8b3fdffff         call    sub_80497b5
08049a02  c3                 retn     {__return_addr}
```

This disassembly is somewhat non-sensical. The following sequence will always cause the `jne` branch to be taken:
```
080499c3  31c0               xor     eax, eax
080499c5  40                 inc     eax  {0x0}
080499c6  7535               jne     0x80499fd  {0x1}
```

Why does the disassembly look so weird? This is due to the polyglot code confusing the disassembler and decompiler. In fact, this polyglot sequence is a [famous example of 32-bit/64-bit polyglot code](https://stackoverflow.com/questions/38063529/x86-32-x86-64-polyglot-machine-code-fragment-that-detects-64bit-mode-at-run-ti) that causes code to behave differently but still disassemble in a valid manner across both architectures. Disassembling this function as 64-bit would make better sense as we are now in 64-bit mode:

```
080499b9  uint64_t sub_80499b9(int32_t* arg1 @ rbx)

080499b9  e8a9050000         call    sub_8049f67
080499be  0542a60c00         add     eax, 0xca642
080499c3  31c0               xor     eax, eax  {0x0}
080499c5  407535             jne     0x80499fd  {0x0}

080499c8  89631c             mov     dword [rbx+0x1c], esp {__return_addr}
080499cb  4883ec10           sub     rsp, 0x10
080499cf  48c7c00f000000     mov     rax, 0xf
080499d6  48f7d0             not     rax  {0xfffffffffffffff0}
080499d9  4821c4             and     rsp, rax
080499dc  8b3b               mov     edi, dword [rbx]
080499de  8b7304             mov     esi, dword [rbx+0x4]
080499e1  8b5308             mov     edx, dword [rbx+0x8]
080499e4  8b4b0c             mov     ecx, dword [rbx+0xc]
080499e7  448b4310           mov     r8d, dword [rbx+0x10]
080499eb  448b4b14           mov     r9d, dword [rbx+0x14]
080499ef  53                 push    rbx {var_18}
080499f0  e848060000         call    sub_804a03d
080499f5  5b                 pop     rbx {var_18}
080499f6  894318             mov     dword [rbx+0x18], eax  {0xfeedfacecafebabe}
080499f9  8b631c             mov     esp, dword [rbx+0x1c]
080499fc  cb                 ret far 

080499fd  e8b3fdffff         call    sub_80497b5
08049a02  c3                 retn     {__return_addr}
```

The encoding for `inc eax` is 0x40, which acts as a REX prefix for `jcc` on x86_64, which has no effect on the jump. The repeated calls to `sub_8049f67` is just the following:
```
08049f67  void* const sub_8049f67() __pure

08049f67  8b0424             mov     eax, dword [esp {__return_addr}]
08049f6a  c3                 retn     {__return_addr}
```

This is a common pattern 32 bit binaries use for position independent code - this is an artifact from the way this crackme was compiled and linked, but still works just fine in 64-bit mode.

`sub_804a03d` looks like the following (the disassembly/decompilation will once again look off if not treated as 64-bits):
```
0804a03d  void sub_804a03d()

0804a04f      data_8115320 = -0x3501454121524111
0804a060      data_8115328 = -0x112053135014542
0804a067      data_8115330 = 1
```

Anyways, the sequence of valid disassembly above re-aligns the stack, stores the old stack value into the context structure, sets register values from the context structure the rbx register pointed to beforehand, calls a function, saves the return value (rax register) into the context structure again, restores the stack register, and calls `ret far` again. Recall that the stack now is `sub_8049c4b` and 0x23, allowing the program to return back into 32 bit mode execution. The register values correspond to the [SYSVABI](https://wiki.osdev.org/System_V_ABI#x86-64) calling convention on amd64, so the context structure is really a way for the ret far transition to pass arguments and return values back and forth.

These transition assembly sequences are repeated throughout the program for entering 64-bit code. Generally, each sequence has a fake and real function as in above (the fake one here is `sub_80497b5` while the real one is `sub_804a03d`), tricking careless reversers with this anti-disassembly/anti-decompilation trap. 

## Cleaning up the Analysis

Now that we understand this Heavensgate sequence, let's perform some patching to help clean up this Heavensgate sequence. Scrolling through main, we know that this sequence is mostly inlined, but it only happens a few times. Recall that first the ret far happens to a 64-bit function stub, from which the real function gets called. We can just patch the binary such that the call happens in the stub leading up to the ret far, and nop other sequences out. I patched the above sequence to just a call to the real function likewise:
```
08049bf2  e846040000         call    seed_804a03d
08049bf7  90                 nop     
08049bf8  90                 nop     
08049bf9  90                 nop     
08049bfa  90                 nop     
08049bfb  90                 nop     
08049bfc  90                 nop     
08049bfd  90                 nop     
```

Sometimes, the program sets the eax value with the context structure's return value, so that may need to be patched out as well for the decompiler. 

The next sequence of transitions happens at 08049ccd, where the real function is at `sub_8049fd3` and the fake function is at `sub_80769d0`. The real function makes a read syscall in 64-bit mode (the fake one just performs a `read` library call). I patched it to the following sequence to emulate the calling convention difference:

```
mov edi, 0
lea esi, [ebp - 0x9c]
mov edx, 0x80
call    sub_8049fd3
```

Note that Binary Ninja seems a bit finnicky with cross-architectural calls - I had to check the decompiled version in 64-bit, before changing it back to 32-bit and manually changing the calling convention for the caller's decompilation to look correct. Otherwise, the functions in the caller will always take no arguments.

Another Heavensgate transition happens at 08049d6e. The fake function is at `sub_80497fc`, while the real function is at `sub_804a118`:

```
080497fc  uint32_t sub_80497fc(char arg1)

08049815      uint8_t var_8_2 = not.b(arg1) ^ 0x5a
08049829      uint8_t eax_4 = var_8_2 << 4 | var_8_2 u>> 4
0804983e      uint8_t eax_8 = eax_4 u>> 5 | eax_4 << 3
08049861      return zx.d(((eax_8 * 2) & 0xaa) | ((zx.d(eax_8) s>> 1).b & 0x55))
```

```
0804a118  uint64_t sub_804a118(char arg1) __pure

0804a125      int64_t var_10 = 0
0804a150      return zx.q((zx.d(arg1) * 2) & 0xaa) | zx.q(zx.d(arg1) u>> 1 & 0x55)
```

These are both just simple byte transformation functions.

It takes one argument, so I patched this sequence into:
```
mov edi, eax
call sub_804a118
```

Another sequence happens at 08049e29. The fake function is at `sub_8049862` and the real function is at `sub_804a151`:

```
08049862  int32_t sub_8049862(int32_t arg1, int32_t arg2)

08049872      uint32_t var_10 = 0xffffffff
08049872      
080498cc      for (void* i = nullptr; i u< arg2; i += 1)
08049890          var_10 ^= zx.d(*(i + arg1))
08049890          
080498c0          for (int32_t j = 0; j u<= 7; j += 1)
080498a4              if ((var_10 & 1) == 0)
080498b5                  var_10 u>>= 1
080498a4              else
080498b0                  var_10 = var_10 u>> 1 ^ 0xedb88320
080498b0      
080498d4      return not.d(var_10)
```

```
0804a151  int64_t sub_804a151(int64_t arg1, int64_t arg2)

0804a161      uint64_t var_20 = -1
0804a161      
0804a1d8      for (void* i = nullptr; i u< arg2; i += 1)
0804a184          var_20 ^= zx.q(*(i + arg1))
0804a184          
0804a1c9          for (int64_t j = 0; j u<= 7; j += 1)
0804a19c              if (zx.q(var_20.d & 1) == 0)
0804a1bb                  var_20 u>>= 1
0804a19c              else
0804a1b5                  var_20 = 0xc96c5795d7870f42 ^ var_20 u>> 1
0804a1b5      
0804a1e2      return not.q(var_20)
```

These are both variations of CRC - the fake one is CRC32 and the latter one is a variant of CRC64 based on the constants. Rather than a lookup table, these are the generative and slower versions of the CRC functions.

The patch was this:
```
08049e29  89c7               mov     edi, eax
08049e2b  be01000000         mov     esi, 0x1
08049e30  e81c030000         call    sub_804a151
```

The last Heavensgate transition in the binary comes from the `sub_8049a9d` call in main, specifically at `08049aca`. The fake function is at `sub_80497cf` while the real function is at `sub_804a071`:
```
080497cf  int32_t sub_80497cf()

080497ee      data_811531c = data_811531c * 0x343fd + 0x269ec3
080497fb      return data_811531c
```

```
0804a071  int64_t sub_804a071()

0804a089      int32_t s
0804a089      __builtin_memset(&s, c: 0, n: 0x14)
0804a106      int64_t result
0804a106      int64_t var_18_1
0804a106      
0804a106      for (; s s<= zx.d(data_8115330); s += 1)
0804a092          int64_t rax_1 = data_8115320
0804a09d          int64_t rax_2 = data_8115328
0804a0ac          data_8115320 = rax_2
0804a0bb          int64_t var_18_3 = rax_1 ^ rax_1 << 0x17
0804a0d7          var_18_1 = var_18_3 ^ var_18_3 u>> 0x11 ^ rax_2 u>> 0x1a ^ rax_2
0804a0df          data_8115328 = var_18_1
0804a0f1          result = rax_2 + var_18_1
0804a0f1      
0804a10c      data_8115330 = var_18_1.b
0804a117      return result
```

Recall the first function we analyzed and how they reference similar data positions. Those first functions were seed functions, and these are pseudo-RNG functions. I patched this final transition to just a call to the real function.

`sub_8049ad` ends up looking like this, which is just a simple shuffle function:
```
08049a9d  int32_t sub_8049a9d(char* arg1, int32_t arg2)

08049ab3      void* gsbase
08049ab3      int32_t eax_1 = *(gsbase + 0x14)
08049ab3      
08049b62      for (void* i = nullptr; i u< arg2; i += 1)
08049b18          uint32_t temp1_1 = modu.dp.d(0:(prng_804a071(i)), arg2)
08049b20          int32_t var_38_1 = 0
08049b2f          char eax_7 = arg1[temp1_1]
08049b43          arg1[temp1_1] = *(i + arg1)
08049b56          *(arg1 + i) = eax_7
08049b56      
08049b73      if (eax_1 == *(gsbase + 0x14))
08049b7b          return eax_1 - *(gsbase + 0x14)
08049b7b      
08049b75      sub_8079620()
08049b75      noreturn
```

## Analyzing the De-obfuscated Binary

Here is main with some variables cleaned up. Some of it is still a bit broken due to register calling convention and the polyglot nature of the binary, but the overall flow is there.

```
08049b7c  int80_t main_8049b7c()

08049b83      void* const __return_addr_1 = __return_addr
08049b8c      void* var_18 = &arg_4
08049b9e      void* gsbase
08049b9e      int32_t eax = *(gsbase + 0x14)
08049ba9      char buffer[0x80]
08049ba9      buffer[0].d = 0
08049bc5      __builtin_memset(s: &buffer[4], c: 0, n: 0x7c)
08049bd9      uint32_t computed[0x20]
08049bd9      __builtin_memset(s: &computed, c: 0, n: 0x80)
08049bf0      uint32_t var_124[0x20]
08049bf0      __builtin_memcpy(dest: &var_124, src: &data_80de860, n: 0x80)
08049bf2      seed_804a03d()
08049c5b      print_805abe0(data_8114450, 0)
08049c6d      print_8058b00(data_8114068)
08049c7f      print_8058b00(&data_80de6a4)
08049c91      print_8058b00(&data_80de6f0)
08049ca3      print_8058b00("And fall down into the mortal re…")
08049cb5      int80_t result = sub_8052700(&data_80de768)
08049cdd      int32_t eax_3 = read_8049fd3(fd: 0, &buffer, n: 0x80)
08049d2d      char var_1d5_1
08049d2d      
08049d2d      if (eax_3 == 0x21)
08049d3c          buffer[eax_3 - 1] = 0
08049d44          int32_t var_1c8_1 = eax_3 - 1
08049d44          
08049df0          for (int32_t i = 0; i s< var_1c8_1; i += 1)
08049dd9              buffer[i] = byte_transform_804a118(&buffer[i.b])
08049dd9          
08049e07          shuffle_8049a9d(&buffer, var_1c8_1)
08049e07          
08049ea6          for (int32_t i_1 = 0; i_1 s< var_1c8_1; i_1 += 1)
08049e30              int32_t eax_15
08049e30              int32_t edx_2
08049e30              eax_15, edx_2 = crc64_804a151(&buffer[i_1], count: 1)
08049e8c              computed[eax_15] = edx_2
08049eac          var_1d5_1 = 1
08049eac          
08049f03          for (int32_t i_2 = 0; i_2 s<= 0x1f; i_2 += 1)
08049ee2              int32_t eax_19
08049ee2              eax_19.b = computed[i_2] == var_124[i_2]
08049eec              uint32_t eax_21
08049eec              eax_21.b = (zx.d(eax_19.b) & zx.d(var_1d5_1)) != 0
08049eef              var_1d5_1 = eax_21.b
08049eef      
08049f0c      if (eax_3 != 0x21 || var_1d5_1 == 0)
08049f42          print_8058b00("\x1b[1;31mOof... you used the wr…")
08049f0c      else
08049f18          print_8058b00("\x1b[1;32mENCHANTMENT CORRECT! Y…")
08049f2a          print_8058b00(data_811406c)
08049f2a      
08049f4d      *(gsbase + 0x14)
08049f4d      
08049f54      if (eax == *(gsbase + 0x14))
08049f66          return result
08049f66      
08049f56      sub_8079620()
08049f56      noreturn

```

The input is read, ensured to be 33 bytes long (with the last byte nulled out). The byte transformation function is applied, which swaps the position of the even and the odd bits, the input is shuffled with the prng, and then crc64 is computed on each byte before being compared to an answer.

## Deriving the flag

First, we write some helper functions to reverse these operations:
```c
static uint64_t xstate1;
static uint64_t xstate2;
static uint8_t rounds;

void seed() {
    xstate1 = 0xcafebabedeadbeefULL;
    xstate2 = 0xfeedfacecafebabeULL;
    rounds = 1;
}

uint64_t xorshift128p() {
    uint64_t answer = 0;
    uint64_t t = 0;
    
    for (int i = 0; i <= rounds; i++) {
        t = xstate1;
        uint64_t s = xstate2;
        xstate1 = s;
        
        t ^= (t << 23);
        t ^= (t >> 17);
        t ^= s ^ (s >> 26);
        
        xstate2 = t;
        answer = t + s;
    }
    
    rounds = t & 0xFF;
    return answer;
}

uint8_t char_bit_twiddle(uint8_t c) {
    uint64_t temp = 0;
    temp = ((uint64_t)c & 0b01010101) << 1;
    temp |= ((uint64_t)c & 0b10101010) >> 1;
    return (uint8_t)temp;
}

uint64_t crc64(uint8_t *s, size_t n) {
    uint64_t crc=0xFFFFFFFFFFFFFFFFULL;
    
    for(size_t i=0;i<n;i++) {
        crc ^= s[i];
        for(size_t j=0;j<8;j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xC96C5795D7870F42;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

int *gen_shuffle(char *inp, size_t len) {
    int *idx = malloc(sizeof(int)*len);
    for (int i = 0; i < len; i++) {
        idx[i] = i; 
    }
    for (size_t i = 0; i < len; i++) {
        uint64_t replace = xorshift128p() % len;
        int temp = idx[replace];
        idx[replace] = idx[i];
        idx[i] = temp; 
    }
    return idx;
}
```

The purpose of `gen_shuffle` is for us to find the shuffle order and reverse it. I chained these helpers together to find the flag:
```c
void main() {
    uint32_t ans[0x20] = {0xb62a1500, 0x1d5c0861, 0x4c6f6e28, 0x4312c5af, 0x3cd56ab6, 0x1e6ab55b, 0x3cd56ab6, 0xc06c89bf, 0xed3f1f80, 0xbaf0e1e8, 0xbfab26a6, 0x3cd56ab6, 0xb3e0301b, 0xbaf0e1e8, 0xe1e5eb68, 0xb0476f74, 0xb3e0301b, 0x3cd56ab6, 0xbfab26a6, 0xe864d8ce, 0x4c6f6e28, 0x4312c5af, 0xb3e0301b, 0x9d14f94b, 0xee9840ef, 0x3cd56ab6, 0xbfab26a6, 0xbfab26a6, 0x9d14f94b, 0xbaf0e1e8, 0x14dd3bc7, 0x97329582};
    uint8_t inp[0x21] = {0};
    seed();
    int *shuffle_idx = gen_shuffle(inp, 0x20);
    for (int i = 0; i < 0x20; i++) {
        uint8_t b = 0;
        for (uint16_t c = 0; c <= 255; c++) {
            b = (uint8_t)c;
            uint32_t val = crc64(&b, 1);
            if (val == ans[i])
                break;
        }
        inp[shuffle_idx[i]] = char_bit_twiddle(b);
    }
    free(shuffle_idx);
    for (int i = 0; i < 0x20; i++) {
        printf("%c", inp[i]);
    }

    puts("");
}
```

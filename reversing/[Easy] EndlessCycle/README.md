![banner](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='5'>EndlessCycle</font>

14<sup>th</sup> February 2025

Prepared By: clubby789

Challenge Author: clubby789

Difficulty: <font color='green'>Easy</font>




# Synopsis

EndlessCycle is a Easy reversing challenge. Players will extract code obfuscated using libc `rand()`, before decoding the XOR'd flag.

## Skills Required

- Using a decompiler
- Dumping self-modifying code with a debugger

## Skills Learned

- Obfuscating code using `rand()`

# Solution

When we run the program, we're asked for the flag. Entering a random response yields a failure message.

## Decompilation

The binary is stripped, but small.

```c
int32_t main(int32_t argc, char** argv, char** envp)
  uint8_t* code = mmap(addr: nullptr, len: 0x9e, prot: 7, flags: 0x21, fd: 0xffffffff, offset: 0)
  srand(x: number)
  
  for (uint64_t i = 0; i u<= 0x9d; i += 1)
      for (uint64_t j = 0; j u< sx.q(numbers[i]); j += 1)
          rand()
      
      code[i] = rand() & 0xff
  
  if (code() != 1)
      puts(str: "The mysteries of the universe remain closed to you...")
  else
      puts(str: "You catch a brief glimpse of the Dragon's Heart - the truth has …")
  
  return 0
```

We begin by allocating some memory with `PROT_READ|PROT_WRITE|PROT_EXEC` permissions. We then seed `rand` with some global variable.

We then iterate over a series of numbers. For each, we call `rand()` that many times, advancing the internal state of the RNG. We then finally call `rand()` once more and store the least significant byte in the `code` array.

This seems to be constructing some machine code function by advancing `rand` by specific amounts and taking the result.

We can use a debugger to dump the constructed function.

## Debugging

First, we'll place a breakpoint at mmap and then call `finish` so we know where the code is allocated. We'll use `hbreak *$rax` to brake at the entry point of the allocated code.

Note that we use a hardware breakpoint - normal breakpoints work by writing a trap instruction (`0xcc`) into the code, which would be later overwritten by the generated code.

Once we hit the breakpoint, we'll use `dump memory /tmp/out $rip $rip+0x1000` to dump it out, then open up the produced code in a decompiler.

We begin by printing a prompt and reading the response into a buffer.
```c
int64_t _start()
  int64_t var_10 = 0x101213e
  int64_t prompt
  __builtin_strncpy(dest: &prompt, src: "What is the flag? ", n: 0x14)
  syscall(sys_write {1}, fd: 1, buf: &prompt, count: 0x12)
  void buffer
  int64_t result = syscall(sys_read {0}, fd: 0, buf: &buffer, count: 0x100)
  
  if (result s<= 0)
      return result
```

We then loop over the buffer 4 bytes at a time, XORing it with `0xbeefcafe`
```c
  int32_t* i = &buffer
  bool is_ok
  
  do
      *i ^= 0xbeefcafe
      i = &i[1]
  while (i u< 0x1a + &buffer)
```

Finally, we perform a memcmp of the XORed data against some embedded data.
```c
  char* bufptr = &buffer
  uint8_t* dataptr = &data_84
  int64_t i_1 = 0x1a
  
  while (i_1 != 0)
      uint8_t dataval = *dataptr
      char bufval = *bufptr
      is_ok = dataval == bufval
      dataptr = &dataptr[1]
      bufptr = &bufptr[1]
      i_1 -= 1
      
      if (dataval != bufval)
          break
  
  return zx.q(is_ok)
```

If they match, we return 1.

To solve, we can simply extract the bytes at `data_84` and XOR them with `0xbeefcafe` - but reversing the bytes as due to the endianess. This will give us the flag.


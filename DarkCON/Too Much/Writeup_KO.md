# [DarkCON CTF] ezpz

## Info

+ 51 solves / 467 points

How about reversing 200 functions at once?? Try yourself!!!

## Summary

+ angr

## Exploit

**Angr**

바이너리를 열면 main에서 일정 바이트만큼 입력받은 후, 입력이 조건을 만족하는지 200개 함수를 통해 확인한다.

```python
import angr

def main():
    p = angr.Project("rev")
    simgr = p.factory.simulation_manager(p.factory.full_init_state())
    simgr.explore(find=0x4046dd, avoid=0x4046eb)

    return simgr.found[0].posix.dumps(0)

if __name__ == '__main__':
    print(main())
```

angr를 이용해 조건을 만족하는 입력을 찾는 코드를 작성한 뒤 실행해주면 금방 답을 구할 수 있다.

```
l0tus@DESKTOP-6V5O4LP:/mnt/c/Users/SKYPC364/documents/github/2021_ctf/darkcon/Too Much$ python3 exploit.py
WARNING | 2021-02-24 22:59:58,265 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
b'darkCON{4r3_y0u_r34lly_th1nk1n9_th4t_y0u_c4n_try_th15_m4nu4lly???_Ok_I_th1nk_y0u_b3tt3r_us3_s0m3_aut0m4t3d_t00ls_l1k3_4n9r_0r_Z3_t0_m4k3_y0ur_l1f3_much_e4s13r.C0ngr4ts_f0r_s0lv1in9_th3_e4sy_ch4ll3ng3}'
```

## Flag

+ darkCON{4r3_y0u_r34lly_th1nk1n9_th4t_y0u_c4n_try_th15_m4nu4lly???_Ok_I_th1nk_y0u_b3tt3r_us3_s0m3_aut0m4t3d_t00ls_l1k3_4n9r_0r_Z3_t0_m4k3_y0ur_l1f3_much_e4s13r.C0ngr4ts_f0r_s0lv1in9_th3_e4sy_ch4ll3ng3}
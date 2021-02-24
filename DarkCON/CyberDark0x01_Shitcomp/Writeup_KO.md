# [DarkCON CTF] CyberDark_0x01: ShitComp

## Info

+ 9 solves / 495 points

```
Goldhand: Hey I want to play the new game "CyberDark", it's so cool. But I have a problem... I want you to hack the game installer.
V: Here to staisfy ur needs
Goldhand: Ok I am giving you the Installer after changing it with my own compressor "ShitComp"... Crack the Installer after Decompressing it. I want to verify ur skills ;)
V: CyberDarkIsACoolGameAndIWannaPlayIt
```

## Summary

+ decrypt

## Exploit

**Decompilation**

주어진 바이너리를 `ShitComp -c -p key filename` 으로 실행하게 되면 암호화 과정을 거쳐 `filename.shitty`가 만들어진다.

```c++
void compress(char* filename, char* src, int size, char* key)
{
...
    for(int i=0; i<=size;){
        num = 1;
        while(src[i] != src[i+num]) num++;

        buf[len] = cur;
        buf[len+1] = num >> 8;
        buf[len+2] = num;

        i += num;
        len += 3;
    }
    puts("[+] Encryption goes brrr...");
    encrypt(buf, len, key);

    fp = fopen(filename, "wb");
    fwrite(buf, len, 1, fp);

    printf("[+] Compressed to %s\n", filename);
    fclose(fp);
    free(buf);
}
```

compress() 함수는 연속된 같은 문자를 하나로 압축한 뒤 길이를 저장한다.

```c++
void encrypt(char* buf, int size, char *password)
{
    len = strlen(password);
    for(int i=0; i<size; i++){
        buf[i] ^= password[i%len];
    }
}
```

encrypt() 함수는 압축한 내용과 password를 xor한다.

**Decompress**

password를 알고 있다면 사용된 복호화된 파일을 구하는 것은 어렵지 않다.

```python
def decompress(key, filename):
	src = list(open(filename+".shitty","rb").read())
	sz = len(key)
	dest = b""
	for i in range(0,len(src),3):
		hi = src[i+1]^ord(key[(i+1)%sz])
		lo = src[i+2]^ord(key[(i+2)%sz])
		c = (src[i]^ord(key[i%sz]))
		dest += bytes([c for _ in range(hi*256+lo)])
	open(filename,"wb").write(dest)
```

Installer를 압축하는데 사용된 password를 구하기 위해 Installer.shitty 파일을 쪼개서 분석해 보자.

```python
def divide_file(filename, num):
	src = list(open(filename,"rb").read())
	file = ["" for i in range(num)]
	for i in range(len(src)):
		file[i%num] += chr(src[i])
	return file

file = divide_file("Installer.shitty",3)
```

Installer는 실행 가능한 파일이라고 생각되므로 같은 바이트가 256번 넘게 연속되는 일은 흔치 않을 것이다. 따라서 decompress 과정에서 hi에 해당하는 부분은 대부분 0이라고 가정할 수 있다.

`src[3k+1]==ord(key[(3k+1)%sz])`

실제로 file[1]을 출력해보면 아래와 같은 문자열이 반복되는 것을 확인할 수 있다.

`yrrsoGedaaatbDkAoaAInPyCeaIClmnWnlI`

하지만 위 문자열은 password의 1/3에 불과하다. 나머지 1/3을 알아내기 위해 file[2]를 활용해 보자. 위의 가정을 조금 확장해보면, 실행 가능한 바이너리에서 같은 바이트가 연속되는 일 자체가 그리 많지 않을 것이다. 따라서 우리는 lo의 값이 대부분 1일 것이라고 생각해볼 수 있다.

```python
def recover(src, cycle):
	res = ""
	for i in range(cycle):
		num = [0 for j in range(0x100)]
		for j in range(i,len(src),cycle):
			num[ord(src[j])] += 1
		x = 0
		for j in range(0x100):
			if num[j]>num[x]:
				x = j
		res += chr(x^0x1)
	print("[+] result: " + res)
	return res
                    
passwd = ["" for i in range(3)]
passwd[1] = "yrrsoGedaaatbDkAoaAInPyCeaIClmnWnlI"
passwd[2] = recover(file[2], len(passwd[1]))
                    
key = ""
for i in range(len(passwd[1])):
	key += "?"
	key += list(passwd[1])[i]
	key += list(passwd[2])[i]

print("[+] key: " + key)
```

recover() 함수는 가장 많이 등장하는 바이트가 실제 password에 1을 xor한 값이라고 가정함으로써 password를 복원해낸다.

password의 2/3을 구했으므로 알지 못하는 부분을 ?로 처리해서 출력하면 다음과 같이 나온다.

```
l0tus@DESKTOP-6V5O4LP:/mnt/c/Users/SKYPC364/documents/GitHub/2021_CTF/darkcon/CyberDark0x01_Shitcomp$ python3 exploit.py
[+] result: bDkAoaAInPyCeaIClmnWnlIyrrsoGedaaat
[+] key: ?yb?rD?rk?sA?oo?Ga?eA?dI?an?aP?ay?tC?be?Da?kI?AC?ol?am?An?IW?nn?Pl?yI?Cy?er?ar?Is?Co?lG?me?nd?Wa?na?la?It
```

문제 설명의 V의 대사를 생각해보면 password는  `CyberDarkIsACoolGameAndIWannaPlayIt`를 세 번 반복한 것이라고 생각된다.

```python
passwd = "CyberDarkIsACoolGameAndIWannaPlayIt"*3
decompress(passwd, "Installer")
```

추측한 password를 바탕으로 주어진 파일을 복원하면 아래와 같이 실행 가능한 바이너리를 얻을 수 있다. 바이너리를 실행하면 flag가 화면에 출력된다.

 ```
l0tus@DESKTOP-6V5O4LP:/mnt/c/Users/SKYPC364/documents/GitHub/2021_CTF/darkcon/CyberDark0x01_Shitcomp$ file Installer
Installer: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, missing section headers
 ```

## Flag

+ darkCON{c0MpR3553d_g4M3_1N5T4Ll3R_w1th_5h1mTTY_p455W0RD}
# [DarkCON CTF] CyberDark_0x02: ShitComp

## Info

+ 6 solves / 497 points

```
Goldhand: So you have proven you worth.
V: Told Ya
GoldHand: Now send me the keys...
```

## Summary

+ decrypt

## Exploit

**Decompilation**

Installer는 ABCD-EFGH-IJKL 꼴의 key를 입력받아 그것이 올바른지 출력해준다. key를 확인하는 과정에 사용되는 함수는 총 3가지이다.

```c++
void load(char *buf)
{
    uint8_t uVar1;
    uint32_t uVar2;
    uint64_t uVar3;
    uint8_t uVar4;
    
    uVar2 = 1;
    uVar3 = 1;
    do {
        uVar4 = (uint8_t)uVar3;
        uVar1 = uVar4 * 2 ^ uVar4;
        if ((char)uVar4 < '\0') {
            uVar1 = uVar1 ^ 0x1b;
        }
        uVar3 = (uint64_t)uVar1;
        uVar2 = uVar2 * 2 ^ uVar2;
        uVar2 = uVar2 ^ uVar2 * 4;
        uVar2 = uVar2 << 4 ^ uVar2;
        if ((char)uVar2 < '\0') {
            uVar2 = uVar2 ^ 9;
        }
        uVar4 = (uint8_t)uVar2;
        buf[uVar3] =
             (uVar4 << 1 | (char)uVar4 < '\0') ^ (uVar4 << 4 | uVar4 >> 4) ^ uVar4 ^ (uVar4 << 2 | uVar4 >> 6) ^
             (uVar4 << 3 | uVar4 >> 5) ^ 0x63;
    } while (uVar1 != 1);
    buf[0] = 0x63;
    return;
}
```

load() 함수는 주어진 버퍼에 정해진 숫자들을 채워넣는다.

```python
void validate(int *key)
{
	memcpy(table, 0x3560, 0x2008);
    int x = table[(uint8_t)key[0]];
    for(int i=1; i<12; i++){
        if(key[i] != table[x]) return 0;
        x = table[x+1];
    }
    return 1;
}

```

validate() 함수는 key[0]와 정해진 table을 기준으로 나머지 key가 올바른지 검증한다. table의 내용이 변하지 않으므로 하나의 key[0]에 대해 최대 한 개의 올바른 key만 대응된다는 것을 알 수 있다.

```c++
void check(void)
{
    ...
    
    load(buf);
    for(int i=0; i<12; i++){
        key[i] = buf[key[i]];
    }
    uVar4 = validate(key);
    
    ...
}
```

check() 함수는 사용자가 입력한 key를 buf에 따라 변형해서 validate()에 전달한다.

**Decrypt**

```c++
int main()
{
    FILE *fp = fopen("Installer","rb");
    fseek(fp, 0x3560, 0);
    fread(table, 1, 0x2008, fp);

    load();
    for(int i='A'; i<='Z'; i++)
        num[(uint8_t)buf[i]] = i;

    for(int i='A'; i<='Z'; i++){
        key[0] = buf[i];
        validate();
    }

    fclose(fp);
}
```

위에서 보인 모든 과정은 역산 가능하므로 key[0]에 'A'부터 'Z'까지 대입해가며 올바른 key를 찾아주면 된다.

```c++
void validate()
{

    int x = table[(uint8_t)key[0]];
    for(int i=1; i<12; i++){
        if(x>=(0x2008>>2)||x<0) return;
        key[i] = table[x];
        x = table[x+1];
    }
    for(int i=0; i<12; i++){
        if(num[(uint8_t)key[i]]==0) return;
    }
    for(int i=0; i<12; i++){
        if(i==4||i==8) printf("-");
        printf("%c",num[(uint8_t)key[i]]);
    }
    printf("\n");
}
```

10개의 key를 한 번에 알아내기 위해 validate() 함수가 key를 출력하도록 구현하였다.

 ```
l0tus@DESKTOP-6V5O4LP:/mnt/c/Users/SKYPC364/documents/GitHub/2021_CTF/darkcon/CyberDark0x02_Installer$ ./exploit
ADGR-THFS-SZPF
BNQO-PSBL-SDHD
CROG-IURB-TNDE
IOXT-KDQL-VZFE
JIRX-YPMF-IZLO
QWMA-LSRT-PZKX
SXFH-MICO-PEWZ
WECN-UQWO-PQWX
XBUZ-CHUC-IKLY
YJFS-ZLMU-RVJT
 ```

구한 key를 서버에서 구동되는 checker에 차례대로 전송하면 flag를 획득할 수 있다.

```
Here's your key after so much trouble
+-----------------------------------------+
| darkCON{DRM_FR33_g4m35_4r3_EZ-T0_cR4ck} |
+-----------------------------------------+
```

## Flag

+ darkCON{DRM_FR33_g4m35_4r3_EZ-T0_cR4ck}
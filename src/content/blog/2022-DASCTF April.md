---
author: s0rry
pubDatetime: 2022-06-05T15:22:00Z
modDatetime: 2022-06-05T20:13:00Z
title: 2022-DASCTF April
slug: 2022-DASCTF-April
featured: false
draft: false
tags:
  - CTF
description: 迟到的dasctf 4月复现
---

# 2022-DASCTF April

## 前言

都6月了才复现完4月的比赛，我是懒狗。

## \***\*Crackme\*\***

[微软官方的加密库特征值](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030044.png)

0x8003对应MD5

0x8004对应SHA

我也不知道有反调试，遇到这种要creck本能用x64来解，无意间就把反调试过了

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030045.png)

先检验key，key经过sha与char1E0比较，动调获得char1E0，经过发现只有4个字母

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030046.png)

这个比较的前面还有一个比较加密的前半段key用的md5

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030047.png)

得到完整key为NocTuRne

最后后半部分解flag

把完整的key经过md5得出的结果用于加密flag

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030048.png)

下面框中的部分调用的是微软的官方库，可以直接用官方提供的解密函数解出

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030049.png)

直接复制这段代码，把加密改为解密，稍微修改一下参数就可以运行，下面直接给出脚本参考：

```cpp
#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>

bool __stdcall re(BYTE* pbData, DWORD dwDataLen, BYTE* a3, DWORD* pdwDataLen)
{
    {
        BOOL v6; // [esp+4h] [ebp-18h]
        HCRYPTKEY phKey; // [esp+Ch] [ebp-10h] BYREF
        HCRYPTPROV phProv; // [esp+10h] [ebp-Ch] BYREF
        HCRYPTHASH phHash; // [esp+14h] [ebp-8h] BYREF

        phProv = 0;
        phHash = 0;
        phKey = 0;
        v6 = CryptAcquireContextA(&phProv, 0, 0, 0x18u, 0xF0000000);
        if (v6)
        {
            v6 = CryptCreateHash(phProv, 0x8003u, 0, 0, &phHash);
            if (v6)
            {
                v6 = CryptHashData(phHash, pbData, dwDataLen, 0);
                if (v6)
                {
                    v6 = CryptDeriveKey(phProv, 0x660Eu, phHash, 1u, &phKey);
                    if (v6)
                        v6 = CryptDecrypt(phKey, 0, 1, 0, a3, pdwDataLen);
                }
            }
        }
        if (phKey)
            CryptDestroyKey(phKey);
        if (phHash)
            CryptDestroyHash(phHash);
        if (phProv)
            CryptReleaseContext(phProv, 0);
        return v6;
    }
}
int main() {

    BYTE input[] = { 0x5C,0x53,0xA4,0xA4,0x1D,0x52,0x43,0x7A,0x9F,0xA1,0xE9,0xC2,0x6C,0xA5,0x90,0x90 };
    DWORD len_input = 0x10;
// 这个是与之前一样动态调试出来的
    BYTE encode[] = { 0x5B,0x9C,0xEE,0xB2,0x3B,0xB7,0xD7,0x34,0xF3,0x1B,0x75,0x14,0xC6,0xB2,0x1F,0xE8,0xDE,0x33,0x44,0x74,0x75,0x1B,0x47,0x6A,0xD4,0x37,0x51,0x88,0xFC,0x67,0xE6,0x60,0xDA,0x0D,0x58,0x07,0x81,0x43,0x53,0xEA,0x7B,0x52,0x85,0x6C,0x86,0x65,0xAF,0xB4 };
    DWORD len_encode = 0x30;
    re(input, len_input, encode, &len_encode);

    return 0;

}
```

由于上面的脚本懒得写输出脚本，所以自接调试拿输出结果

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030050.png)

我只能说vscode是世界上最好用的ide(哈哈哈哈，我的vscode真好看

得出flag:DASCTF{H@sh_a^d_Aes_6y_W1nCrypt}

## fakePica

这个jadx打开一看，居然连mainactivity居然都没有应该是有壳，查一下壳

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030051.png)

脱壳工具：[https://github.com/CodingGay/BlackDex](https://github.com/CodingGay/BlackDex)

安装到虚拟机，再把要脱壳程序安装到虚拟机，就可以开始脱壳了

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030052.png)

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030053.png)

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030054.png)

adb连到指定目录拉到电脑上就行，pull可以百度一下

```cpp
adb pull /storage/emulated/0/Android/data/top.niunaijun.blackdexa32/dump/com.ppsuc.ppsucctf/
```

这里的到四个dex文件，一般都是最大的那个，拖入jadx审计代码

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030055.png)

把下面的两个数组变成无符号的16进行

```cpp
#include <stdio.h>

int main(){

    char a[] = {-114, 95, -37, 127, -110, 113, 41, 74, 40, 73, 19, 124, -57, -88, 39, -116, -16, -75, -3, -45, -73, -6, -104, -6, -78, 121, 110, 74, -90, -47, -28, -28};
    char b[] = {-40, 26, 95, -49, -40, -123, 72, -90, -100, -41, 122, -4, 25, -101, -58, 116};
    for(int i =0 ;i < 32;i++){
        printf("%2x",(unsigned char)a[i]);
    }
    printf("\n");
    for(int i =0 ;i < 16;i++){
        printf("%2x",(unsigned char)b[i]);
    }

    return 0;
}
//8e5fdb7f9271294a2849137cc7a8278cf0b5fdd3b7fa98fab2796e4aa6d1e4e4
//d81a5fcfd88548a69cd77afc199bc674
```

AES解密网站：[http://www.hiencode.com/caes.html](http://www.hiencode.com/caes.html)

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030056.png)

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030057.png)

解出账号密码

```cpp
账号：picacomic@gmail.com
密码：picacomic
```

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030058.png)

flag: picacomic@gmail.compicacomic

## 奇怪的交易

查壳

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030059.png)

upx壳可惜是linux平台的不然就手脱了，这里用工具脱

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030060.png)

拖入ida一看，python打包的elf文件

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030061.png)

只做过python打包的exe文件，打包的elf解法看：[https://github.com/extremecoders-re/pyinstxtractor/wiki/Extracting-Linux-ELF-binaries](https://github.com/extremecoders-re/pyinstxtractor/wiki/Extracting-Linux-ELF-binaries)

```cpp
objcopy --dump-section pydata=pydata.dump testfile.elf
#使用将命名为文件objcopy的部分转储

python pyinstxtractor.py pydata.dump
#现在在转储文件上运行 pyinstxtractor
```

改完之后，合成pyc文件，但是不能uncompyle6，要看字节码咯

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030062.png)

看字节码的脚本之前VNctf的那篇博客写过，这里再写一遍

```cpp
import marshal, dis
fp = open(r"trade.pyc", 'rb')
fp.seek(16)
co = marshal.load(fp)
dis.dis(co)
```

运行结果：

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030063.png)

人肉翻译一下，用[在线网站弄](https://tool.lu/pyc/)的有点小问题：

这里懒得自己翻译了，抄一抄[大哥们的博客](https://blog.t0hka.top/index.php/archives/36/)，主要主要那几个导库的字节码也要写下来，才能看得懂

```cpp
from cup import *
from libnum import *

if __name__ == '__main__':
    flag = input('请输入flag')
    pub_key = [
        0x649EE967E7916A825CC9FD3320BEABF263BEAC68C080F52824A0F521EDB6B78577EC52BF1C9E78F4BB71192F9A23F1A17AA76E5979E4D953329D3CA65FB4A71DA57412B59DFD6AEDF0191C5555D3E5F582B81B5E6B23163E9889204A81AFFDF119FE25C92F4ED59BD3285BCD7AAE14824240D2E33C5A97848F4EB7AAC203DE6330D2B4D8FF61691544FBECD120F99A157B3D2F58FA51B2887A9D06CA383C44D071314A12B17928B96F03A06E959A5AFEFA0183664F52CD32B9FC72A04B45913FCB2D5D2D3A415A14F611CF1EAC2D6C785142A8E9CC41B67A6CD85001B06EDB8CA767D367E56E0AE651491BF8A8C17A38A1835DB9E4A9292B1D86D5776C98CC25,
        0x647327833ACFEF1F9C83E74E171FC300FA347D4A6769476C33DA82C95120ACB38B62B33D429206FE6E9BB0BB7AB748A1036971BEA36EC47130B749C1C9FF6FE03D0F7D9FC5346EB0E575BDFA6C530AA57CD676894FC080D2DD049AB59625F4B9C78BCFD95CDCD2793E440E26E189D251121CB6EB177FEDB596409034E8B0C5BBD9BD9342235DBB226C9170EFE347FF0FD2CFF9A1F7B647CC83E4D8F005FD7125A89251C768AFE70BDD54B88116814D5030F499BCAC4673CCCC342FB4B6AC58EA5A64546DC25912B6C430529F6A7F449FD96536DE269D1A1B015A4AC6B6E46EE19DCE8143726A6503E290E4BAE6BD78319B5878981F6CFFDB3B818209341FD68B]
    m = libnum.s2n(flag)
    c = str(pow(m, pub_key[1], pub_key[0]))
    store = []
    cipher = [3532577106, 1472742623, 3642468664, 4193500461, 2398676029, 617653972, 1474514999, 1471783658, 1012864704,
              3615627536, 993855884, 438456717, 3358938551, 3906991208, 198959101, 3317190635, 3656923078, 613157871,
              2398768861, 97286225, 2336972940, 1471645170, 3233163154, 583597118, 2863776301, 3183067750, 1384330715,
              2929694742, 3522431804, 2181488067, 3303062236, 3825712422, 145643141, 2148976293, 2940910035, 506798154,
              994590281, 2231904779, 3389770074, 2814269052, 1105937096, 1789727804, 3757028753, 2469686072, 1162286478,
              680814033, 2934024098, 2162521262, 4048876895, 2121620700, 4240287315, 2391811140, 3396611602, 3091349617,
              3031523010, 2486958601, 3164065171, 1285603712, 798920280, 2337813135, 4186055520, 3523024366, 1077514121,
              1436444106, 2731983230, 1507202797, 500756149, 198754565, 2382448647, 880454148, 1970517398, 3217485349,
              1161840191, 560498076, 1782600856, 2643721918, 1285196205, 788797746, 1195724574, 4061612551, 103427523,
              2502688387, 4147162188, 617564657, 978211984, 1781482121, 2205798970, 3939973102, 3826603515, 659557668,
              2582884932, 1561884856, 2217488804, 1189296962, 169145316, 2781742156, 1323893433, 824667876, 408202876,
              3759637634, 4094868412, 1508996065, 162419237, 3732146944, 3083560189, 3955940127, 2393776934, 2470191468,
              3620861513, 481927014, 2756226070, 3154651143, 1261069441, 2063238535, 2222237213, 101459755, 3159774417,
              1721190841, 1078395785, 176506553, 3552913423, 1566142515, 1938949000, 1499289517, 3315102456, 829714860,
              3843359394, 952932374, 1283577465, 2045007203, 3957761944, 3767891405, 2917089623, 3296133521, 482297421,
              1734231412, 3670478932, 2575334979, 2827842737, 3413631016, 1533519803, 4008428470, 3890643173, 272960248,
              317508587, 3299937500, 2440520601, 27470488, 1666674386, 1737927609, 750987808, 2385923471, 2694339191,
              562925334, 2206035395]

    i = 0
    # rsa 生成的密文遍历加密
    while i < len(c):  # i<155
        index = 0
        for ii in c[i:i + 4]:
            index = (index << 8) + ord(ii)
        store.append(index)

        i += 4
        if not i < len(c):
            key = [54, 54, 54, 54]
            store_len = len(store)
            res = encrypt(store_len, store, key)
            if store == cipher:
                print('You are right!')
                input('')
                quit()
            else:
                print('Why not drink a cup of tea and have a rest?')

        continue
```

这里先经过了RSA加密然后，调用encrypt加密，而encrypt是cup库里面的，cup库被加密了，在调用的时候进行解密，解密函数在下面这个pyc文件中，第一个是解密用的密钥，第二个里面的Cipher函数，而且都能被compyle6.exe解开（这里解不开，因为是python3.10，可以用在线解密弄个大概）

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030064.png)

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030066.png)

被加密的库在extacted文件夹下

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030067.png)

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206061030068.png)

解密脚本：

```cpp
#!/usr/bin/env python3
import tinyaes
import zlib

CRYPT_BLOCK_SIZE = 16

# 从crypt_key.pyc获取key，也可自行反编译获取
key = bytes('0000000000000tea', 'utf-8')

inf = open('cup.pyc.encrypted', 'rb')  # 打开加密文件
outf = open('cup.pyc', 'wb')  # 输出文件

# 按加密块大小进行读取
iv = inf.read(CRYPT_BLOCK_SIZE)

cipher = tinyaes.AES(key, iv)

# 解密
plaintext = zlib.decompress(cipher.CTR_xcrypt_buffer(inf.read()))

# 补pyc头(最后自己补也行)
outf.write(b'\x6f\x0d\x0d\x0a\0\0\0\0\0\0\0\0\0\0\0\0')

# 写入解密数据
outf.write(plaintext)

inf.close()
outf.close()
```

在线解密后的cup库：

```cpp
#!/usr/bin/env python
# visit https://tool.lu/pyc/ for more information
# Version: Python 3.10

import libnum
from ctypes import *

def MX(z, y, total, key, p, e):
    temp1 = (z.value >> 5 ^ y.value << 2) + (y.value >> 3 ^ z.value << 4)
    temp2 = (total.value ^ y.value) + (key[p & 3 ^ e.value] ^ z.value)
    return c_uint32(temp1 ^ temp2)

def encrypt(ᘗ, ᘖ, ᘘ):
    ᘜ = 0x9E3779B9L
    ᘛ = 6 + 52 // ᘗ
    total = c_uint32(0)
    ᘔ = c_uint32(ᘖ[ᘗ - 1])
    ᘕ = c_uint32(0)
    if ᘛ > 0:
        total.value += ᘜ
        ᘕ.value = total.value >> 2 & 3
        ᘚ = c_uint32(ᘖ[0])
        ᘖ[ᘗ - 1] = c_uint32(ᘖ[ᘗ - 1] + MX(ᘔ, ᘚ, total, ᘘ, ᘗ - 1, ᘕ).value).value
        ᘔ.value = ᘖ[ᘗ - 1]
        ᘛ -= 1
        if not ᘛ > 0:
            return ᘖ
```

可以看出大概就是xxtea加密的，直接写解题脚本了，但是这里的RSA的n太长了不能分解，必须使用维纳攻击，维纳攻击在github上有现成的python脚本，维纳攻击适用于RSA的e**过大或过小**的情况下，可使用算法从e中快速推断出d的值：

xxtea解密脚本：

```cpp
//xxtea
#include <stdio.h>
#include <stdint.h>

#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

void xxtea(uint32_t* v, int n, uint32_t* key)
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;

    if (n > 1)             // encrypt
    {
        rounds = 6 + 52/n;
        sum = 0;
        z = v[n-1];
        do
        {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p=0; p<n-1; p++)
            {
                y = v[p+1];
                z = v[p] += MX;
            }
            y = v[0];
            z = v[n-1] += MX;
        }
        while (--rounds);
    }
    else if (n < -1)      // decrypt
    {
        n = -n;
        rounds = 6 + 52/n;
        sum = rounds * DELTA;
        y = v[0];
        do
        {
            e = (sum >> 2) & 3;
            for (p=n-1; p>0; p--)
            {
                z = v[p-1];
                y = v[p] -= MX;
            }
            z = v[n-1];
            y = v[0] -= MX;
            sum -= DELTA;
        }
        while (--rounds);
    }
}

// test
int main()
{
    // 两个32位无符号整数，即待加密的64bit明文数据,数量可以添加
    uint32_t v[155] = { 3532577106, 1472742623, 3642468664, 4193500461, 2398676029, 617653972, 1474514999, 1471783658, 1012864704,
              3615627536, 993855884, 438456717, 3358938551, 3906991208, 198959101, 3317190635, 3656923078, 613157871,
              2398768861, 97286225, 2336972940, 1471645170, 3233163154, 583597118, 2863776301, 3183067750, 1384330715,
              2929694742, 3522431804, 2181488067, 3303062236, 3825712422, 145643141, 2148976293, 2940910035, 506798154,
              994590281, 2231904779, 3389770074, 2814269052, 1105937096, 1789727804, 3757028753, 2469686072, 1162286478,
              680814033, 2934024098, 2162521262, 4048876895, 2121620700, 4240287315, 2391811140, 3396611602, 3091349617,
              3031523010, 2486958601, 3164065171, 1285603712, 798920280, 2337813135, 4186055520, 3523024366, 1077514121,
              1436444106, 2731983230, 1507202797, 500756149, 198754565, 2382448647, 880454148, 1970517398, 3217485349,
              1161840191, 560498076, 1782600856, 2643721918, 1285196205, 788797746, 1195724574, 4061612551, 103427523,
              2502688387, 4147162188, 617564657, 978211984, 1781482121, 2205798970, 3939973102, 3826603515, 659557668,
              2582884932, 1561884856, 2217488804, 1189296962, 169145316, 2781742156, 1323893433, 824667876, 408202876,
              3759637634, 4094868412, 1508996065, 162419237, 3732146944, 3083560189, 3955940127, 2393776934, 2470191468,
              3620861513, 481927014, 2756226070, 3154651143, 1261069441, 2063238535, 2222237213, 101459755, 3159774417,
              1721190841, 1078395785, 176506553, 3552913423, 1566142515, 1938949000, 1499289517, 3315102456, 829714860,
              3843359394, 952932374, 1283577465, 2045007203, 3957761944, 3767891405, 2917089623, 3296133521, 482297421,
              1734231412, 3670478932, 2575334979, 2827842737, 3413631016, 1533519803, 4008428470, 3890643173, 272960248,
              317508587, 3299937500, 2440520601, 27470488, 1666674386, 1737927609, 750987808, 2385923471, 2694339191,
              562925334, 2206035395};
    // 四个32位无符号整数，即128bit的key
    uint32_t k[4]= {54,54,54,54};
    //n的绝对值表示v的长度，取正表示加密，取负表示解密，随着加密数据变化
    int n = 155;

    xxtea(v, -n, k);
    for(int i = 0; i < 155; i++){
        printf("%c", (((v[i]) & 0xff000000) >> 24));
        printf("%c", ((v[i]) & 0x00ff0000) >> 16);
        printf("%c", ((v[i]) & 0x0000ff00)>>8);
        printf("%c", ((v[i]) & 0xff));
    }

    return 0;
}
//输出:
//10610336534759505889607399322387179316771488492347274741918862678692508953185876570981227584004676580623553664818853686933004290078153620168054665086468417541382824708104480882577200529822968531743002301934310349005341104696887943182074473298650903541494918266823037984054778903666406545980557074219162536057146090758158128189406073809226361445046225524917089434897957301396534515964547462425719205819342172669899546965221084098690893672595962129879041507903210851706793788311452973769358455761907303633956322972510500253009083922781934406731633755418753858930476576720874219359466503538931371444470303193503733920039
```

维纳攻击github项目地址：[https://github.com/pablocelayes/rsa-wiener-attack](https://github.com/pablocelayes/rsa-wiener-attack)

```cpp
import gmpy2
from Crypto.PublicKey import RSA
import ContinuedFractions, Arithmetic
from Crypto.Util.number import long_to_bytes

def wiener_hack(e, n):
    # firstly git clone https://github.com/pablocelayes/rsa-wiener-attack.git !
    frac = ContinuedFractions.rational_to_contfrac(e, n)
    convergents = ContinuedFractions.convergents_from_contfrac(frac)
    for (k, d) in convergents:
        if k != 0 and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = n - phi + 1
            discr = s * s - 4 * n
            if (discr >= 0):
                t = Arithmetic.is_perfect_square(discr)
                if t != -1 and (s + t) % 2 == 0:
                    return d
    return False

def main():
    pub_key = [
    0x649EE967E7916A825CC9FD3320BEABF263BEAC68C080F52824A0F521EDB6B78577EC52BF1C9E78F4BB71192F9A23F1A17AA76E5979E4D953329D3CA65FB4A71DA57412B59DFD6AEDF0191C5555D3E5F582B81B5E6B23163E9889204A81AFFDF119FE25C92F4ED59BD3285BCD7AAE14824240D2E33C5A97848F4EB7AAC203DE6330D2B4D8FF61691544FBECD120F99A157B3D2F58FA51B2887A9D06CA383C44D071314A12B17928B96F03A06E959A5AFEFA0183664F52CD32B9FC72A04B45913FCB2D5D2D3A415A14F611CF1EAC2D6C785142A8E9CC41B67A6CD85001B06EDB8CA767D367E56E0AE651491BF8A8C17A38A1835DB9E4A9292B1D86D5776C98CC25,
    0x647327833ACFEF1F9C83E74E171FC300FA347D4A6769476C33DA82C95120ACB38B62B33D429206FE6E9BB0BB7AB748A1036971BEA36EC47130B749C1C9FF6FE03D0F7D9FC5346EB0E575BDFA6C530AA57CD676894FC080D2DD049AB59625F4B9C78BCFD95CDCD2793E440E26E189D251121CB6EB177FEDB596409034E8B0C5BBD9BD9342235DBB226C9170EFE347FF0FD2CFF9A1F7B647CC83E4D8F005FD7125A89251C768AFE70BDD54B88116814D5030F499BCAC4673CCCC342FB4B6AC58EA5A64546DC25912B6C430529F6A7F449FD96536DE269D1A1B015A4AC6B6E46EE19DCE8143726A6503E290E4BAE6BD78319B5878981F6CFFDB3B818209341FD68B]
    # 0->n,1->e

    n = pub_key[0]
    e = pub_key[1]
    c = 10610336534759505889607399322387179316771488492347274741918862678692508953185876570981227584004676580623553664818853686933004290078153620168054665086468417541382824708104480882577200529822968531743002301934310349005341104696887943182074473298650903541494918266823037984054778903666406545980557074219162536057146090758158128189406073809226361445046225524917089434897957301396534515964547462425719205819342172669899546965221084098690893672595962129879041507903210851706793788311452973769358455761907303633956322972510500253009083922781934406731633755418753858930476576720874219359466503538931371444470303193503733920039
    d = wiener_hack(e, n)
    m = pow(c, d, n)
    print(long_to_bytes(m)) #  flag{You_Need_Some_Tea}

if __name__ == "__main__":
    main()
```

## 总结

这次的题目还好，有新颖的地方，又学到了很多知识，最后一道go逆向等等再弄(烂了。

参考博客：
https://gift1a.github.io/2022/04/23/DASCTF-FATE-Reverse/
https://blog.t0hka.top/index.php/archives/36/
https://bbs.pediy.com/thread-271253.htm

---
author: s0rry
pubDatetime: 2022-04-29T09:45:18Z
modDatetime: 2022-04-29T12:45:18Z
title: 2022-StarCTF
slug: 2022-StarCTF
featured: false
draft: false
tags:
  - CTF
description: 通过StarCTF学一些知识
---

# 通过NaCl题目，了解对模拟栈帧的简单修复

### 前言

这个程序通过r15来维护栈比较有趣，感觉很像低配vm，但是代码量比较大，目前来说对于这种纯汇编的人肉反编译还是比较缺少经验，得多练习练习，在反编译的时候要注意把代码逻辑写下来，方便分析。

这道题目前看到两种解法：

**方法1：** 对于这个程序进行纯汇编层面的分析，结合动态调试来分析出大概逻辑。我试着分析了一下，在进行xtez加密之前的还有一种加密，得分析出它的加密逻辑，这就是这道题的难点，水平有限加上时间成本太高了，初略分析了一下就放弃了，当然这种方法是在比赛的时候不知道下面那种解法的唯一的解法了，所以还是得学，Lu1u师傅说的对一遍调试不行就再来n遍。

**方法2：**由于rsp寄存器被替换成r15，所以在调用其他函数的时候就要进行自己**模拟传参的处理**，以及在退出函数的时候要进行**对返回位置的确定**，通过对于平常rsp的作用的分析，用r15替代后必须要实现相同的作用就会出现特征，通过这个特征就可将函数简单还原。

由于方法1主要看个人实力，所以这里就不进行复现描述了。下面主要对方法2这个看技巧的方法进行复现。

### ipython常用指令

```python
print_insn_mnem(adr) #得到adr地址的操作码

next_head(adr) #取下一条指令的地址

get_operand_value(adr，long n) #获取操作数 第一个操作数 n是0 第二个n是1 ...

get_bytes(adr,end-adr) #获取一片空间的字节
tmp=get_bytes(adr,end-adr)
tmp=tmp.replace(b'\x74\x03\x75\x01\xE8',b'\x90'*5) #批量patch

patch_byte(adr,hex_numb)#parch adr 处的指令
```

### r15模拟rsp的功能分析

**r15模拟堆栈**

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204291641328.png)

这是刚进函数的时候的原始栈顶的位置，这个位置一直没变化。

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204291641330.png)

经过分析了解到模拟的栈底，从模拟栈底慢慢往上压栈

**模拟函数调用 call**

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204291641331.png)

这里的nop就好像特征码一样，每一处模拟的call都有这个nop而且还没什么用，同样没什么用的就是传给r12的这个函数地址，在整个流程都没调用到，这都是用来混淆分析人员和ida的。如何知道这里是模拟的call呢？ 感觉找到这些点都是要通过**反复调试跟踪而且要结合rsp在正常程序中的功能**才可以发现。

**模拟函数返回 ret**

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204291641332.png)

如果能发现上面的模拟call，和模拟堆栈的话，这个ret还是比较好发现的，这里不过多解释。

### 通过ipython去除模拟过程中的无用部分

ipython脚本(从师傅们那儿抄的脚本

```python
start = 0x807FEC0
end = 0x8080AD1

address = [0 for i in range(5)]
callTarget = ["lea", "lea", "mov", "jmp"]
retnTarget = ["lea", "mov", "and", "lea", "jmp"]

def nop(s, e):
	while (s < e):
		patch_byte(s, 0x90)
		s += 1

def turnCall(s, e, h):
	# nop掉call之前的值
	nop(s, e)
	patch_byte(e, 0xE8)
	# 把后面的花指令去掉 重新计算去花长度
	huaStart = next_head(e)
	huaEnd = h
	nop(huaStart, huaEnd)

def turnRetn(s, e):
	nop(s, e)
	# 注意原来是jmp xxx
	# 所以前面nop掉一个 后面改成retn
	patch_byte(e, 0x90)
	patch_byte(e + 1, 0xC3)

p = start
while p < end:
	address[0] = p
	address[1] = next_head(p)
	address[2] = next_head(address[1])
	address[3] = next_head(address[2])
	address[4] = next_head(address[3])

	for i in range(0, 4):
		if print_insn_mnem(address[i]) != callTarget[i]:
			break
	else:
		turnCall(address[0], address[3], get_operand_value(address[1], 1))
		p = next_head(next_head(address[3]))
		continue

	for i in range(0, 5):
		if print_insn_mnem(address[i]) != retnTarget[i]:
			break
	else:
		turnRetn(address[0], address[4])
		p = next_head(next_head(address[4]))
		continue

	p = next_head(p)
```

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204291641333.png)

脚本执行后保存一下，重新放入ida让它分析

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204291641334.png)

这些函数里面可能还是有点问题但是不影响大致分析了。

其中一个xtea加密加上一个Feistel的密码结构

xtea就不过多解释了，说一下Feistel密码结构在，Feistel密码结构是用于分组密码中的一种对称结构。逆向它就只需要把步骤逆回去就行，这里的大致结构就是(这里是写的伪代码，只看逻辑)

```python
加密部分--------
h(高4位的变量) d（低4位的变量）
for 44
	tmp = d
	v7 = rol(d,1)&rol(d,8)
	d = h^( rol(d,1)&rol(d,8) )^rol(d,2)^key
	h = tmp
return d<<32|h
解密部分---------
h d
h <->d 交换h和d
for 43->0
	tmp = d
	d = h
	v7 = rol(h,1)&rol(h,8)
	h = tmp^( rol(h,1)&rol(h,8) )^rol(h,2)^key[i]
```

写出解密脚本

```python
#include<iostream>
#define ut32 unsigned int
#define delta 0x10325476
unsigned int key[44] = {
    0x04050607, 0x00010203, 0x0C0D0E0F, 0x08090A0B, 0xCD3FE81B, 0xD7C45477, 0x9F3E9236, 0x0107F187,
    0xF993CB81, 0xBF74166C, 0xDA198427, 0x1A05ABFF, 0x9307E5E4, 0xCB8B0E45, 0x306DF7F5, 0xAD300197,
    0xAA86B056, 0x449263BA, 0x3FA4401B, 0x1E41F917, 0xC6CB1E7D, 0x18EB0D7A, 0xD4EC4800, 0xB486F92B,
    0x8737F9F3, 0x765E3D25, 0xDB3D3537, 0xEE44552B, 0x11D0C94C, 0x9B605BCB, 0x903B98B3, 0x24C2EEA3,
    0x896E10A2, 0x2247F0C0, 0xB84E5CAA, 0x8D2C04F0, 0x3BC7842C, 0x1A50D606, 0x49A1917C, 0x7E1CB50C,
    0xFC27B826, 0x5FDDDFBC, 0xDE0FC404, 0xB2B30907
};
void XTea_Decrypt(ut32* enc, ut32* k,ut32 r) {
	ut32 sum = delta * r;
	ut32 v0 = enc[0];
	ut32 v1 = enc[1];
	for (int i = 0; i < r; i++) {
		v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
		sum -= delta;
		v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
	}
	enc[0] = v0;
	enc[1] = v1;
}

int rol(unsigned int n,unsigned int m){
    return (n << m)|(n>>(32-m));
}
int ror(unsigned int n,unsigned int m){
    return (n>>m)|(n<<(32-m));
}

void encode(unsigned int* m){
    unsigned a = m[0];
    unsigned b = m[1];
    unsigned int tmp = 0;
    for(int i = 0;i< 44;i++){
        tmp = a;
        a = (rol(a,1)&rol(a,8))^rol(a,2)^b^key[i];
        b = tmp;
    }
    tmp = a;
    a = b;
    b =tmp;
    m[0] = a;
    m[1] = b;
}
void decode(unsigned int* m){
    unsigned a = m[0];
    unsigned b = m[1];
    unsigned int tmp = a;
    a = b;
    b =tmp;
    for(int i = 43;i > -1;i--){
        tmp = a;
        a = b;
        b = tmp^(rol(b,1)&rol(b,8))^rol(b,2)^key[i];
    }
    m[0] = a;
    m[1] = b;
}

int main() {
	ut32 m[8] = { 0xFDF5C266, 0x7A328286, 0xCE944004, 0x5DE08ADC, 0xA6E4BD0A, 0x16CAADDC, 0x13CD6F0C, 0x1A75D936 };
	ut32 k[4] = { 0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C };
	for (int i = 0; i < 4; ++i) {
		XTea_Decrypt(m + 2*i, k,1<<(i+1));
	}
    for (int i = 0; i < 4; ++i) {
		decode(m + 2*i);
	}
    printf("*ctf{");
	for (int i = 0; i < 8; i++) {
		printf("%c%c%c%c",m[i]>>(6*4),(m[i]>>(4*4))&0xff,(m[i]>>(2*4))&0xff,m[i]&0xff);
	}
    printf("}\n");
	return 0;
}
//0xe71f5179 ,0xb55f9204 ,0x722d4a3a ,0x238e8b65 ,0x4385e0f2 ,0x6703757a ,0xaabe9be3 ,0x4de4253b ,

//输出*ctf{mM7pJIobsCTQPO6R0g-L8kFExhYuivBN}
```

# \***\*Simple File System\*\***

进入大概搜索，猜测了一下这里就是与flag相关的操作

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204291641335.png)

刚开始调试半天，调试不出来，原来是我的flag的文件是空的，原来这个程序是从flag的文件来读入的输入。直接开始动态调试

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204291641336.png)

这个函数会从一个地方读出密钥key用来异或读出的flag来加密。

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204291641337.png)

原来的flag文件中含有CTF{XXXXXXXXXXXXXXXXXXXX}，有固定的前缀，同时我们也在ida中无法直接找到它要参与比较的数据，在加密完前几个数据后直接在给的另一个文件中用010找到

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204291641338.png)

这里就是加密后的结果，通过动态调试得出key，然后就可直接逆向。

```python
#include <stdio.h>

int main(){
    unsigned int key[4] = {0xef,0xbe,0xed,0xde};
    unsigned char encode[] = {0xd2,0xfc,0xd8, 0xa2,0xda,0xba,0x9e, 0x9c,0x26,0xf8,0xf6, 0xb4,0xce,0x3c,0xcc, 0x96,0x88,0x98,0x34, 0x82,0xde,0x80,0x36, 0x8a,0xd8,0xc0,0xf0, 0x38,0xae,0x40};
    for(int i= 0;i< 30;i++){
        encode[i] = encode[i]<<5 | encode[i]>>3;
        encode[i] ^= key[3];
        encode[i] = encode[i]<<4 | encode[i]>>4;
        encode[i] ^= key[2];
        encode[i] = encode[i]<<3 | encode[i]>>5;
        encode[i] ^= key[1];
        encode[i] = encode[i]<<2 | encode[i]>>6;
        encode[i] ^= key[0];
        encode[i] = encode[i]<<1 | encode[i]>>7;
        printf("%c",encode[i]);
    }


    return 0;
}
```

# 总结

大概就复现这两个，能力有限，第二个复现用了好多时间了，先是自己逆汇编逆了一天大概是能逆出来的，但是没有继续深入下去了，然后就去看师傅们的博客了解捷径去了（bushi。师傅们的博客写的好啊。

参考博客：
lu1u师傅：https://lu1u.xyz/2022/04/19/StarCTF-2022/
Pz师傅：https://www.bilibili.com/video/BV1D541127ug?spm_id_from=333.337.search-card.all.click

---
author: s0rry
pubDatetime: 2022-04-03T19:08:00Z
modDatetime: 2022-04-03T19:08:00Z
title: SUSCTF Login复现
slug: SUSCTF-Login-Reproduction
featured: false
draft: false
tags:
  - CTF
description: SUSCTF Login复现，理解socket通信
---

# 2022-SUSCTF Login复现

# 前言

这道题，要注意调试技巧，打开看见有两个文件就有点慌。

理解了socket了之后就了解，这道题得调试服务端的check程序。

本文很多都网上查找资料中的原话，我把它重新整理精炼了一下，方便自己理解，加深记忆。

# socket技术

### 两种通信方式：

SOCK_STREAM：向连接的数据传输方式。

数据可以准确无误，如果损坏或丢失，可以重新发送，效率相对较慢，http 协议就使用 SOCK_STREAM 传输数据

SOCK_DGRAM：无连接的数据传输方式。

只管传输数据，不作数据校验。如果数据在传输中损坏，或者没有到达另一台计算机，无法重传。校验少，效率高。QQ视频用的这种方式

### TCP数据包结构：

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204092217187.png)

阴影部分比较重要，下面有用到

**标志位（6bit）：**

```python
（1）URG：紧急指针（urgent pointer）有效。
（2）ACK：确认序号有效。
（3）PSH：接收方应该尽快将这个报文交给应用层。
（4）RST：重置连接。
（5）SYN：建立一个新连接。
（6）FIN：断开一个连接。
```

### 建立连接（3次握手）：

**客户端**调用 **socket()** 函数创建套接字后，因为没有建立连接，所以套接字处于CLOSED状态；**服务器端**调用 **listen()** 函数后，套接字进入LISTEN状态，开始监听客户端请求

**客户端发起请求：**

1.**客户端**调用 **connect()** 函数，TCP协议会组建一个数据包，并设置 **SYN** 标志位，用来建立连接的包，生成一个随机数字 1000，填充“**序号（Seq）**”字段，表示该数据包的序号。向服务器端发送数据包，客户端就进入了SYN-SEND状态。

2.**服务器端**收到数据包，检测到SYN 标志位。服务器端也会组建一个数据包，并设置 **SYN** 和 **ACK** 标志位。生成一个随机数 2000，填充“**序号（Seq）**”字段，将客户端数据包序号（1000）加1，得到1001，填充“**确认号（Ack）**”字段，进入SYN-RECV状态

3.**客户端**收到数据包，检测到已经设置了 SYN 和 ACK 标志位，检测“确认号（Ack）”字段，看它的值是否为 1000+1。再发一个包，并设置 **ACK** 标志位，将刚才服务器发来的数据包序号（2000）加1，填充“**确认号（Ack）**”字段，客户端进入ESTABLISED状态。

4.**服务器端**收到数据包，检测到已经设置了 **ACK 标志位**，检测“**确认号（Ack）**”字段，服务器进入ESTABLISED状态

连接成功

---

注意这里就用了**connect()** ，这一个函数，详细的内容都是自动帮我们完成的。

### 断开连接：

**客户端发起断开连接的请求：**

1.**客户端**调用 **close()** 函数，向服务器发送 **FIN** 数据包，进入FIN_WAIT_1状态

2.**服务器**收到数据包，检测到设置了 FIN 标志位，向客户端发送“确认包”，进入CLOSE_WAIT状态。

3.**客户端**收到“确认包”后进入FIN_WAIT_2状态，**等待**服务器准备完毕后再次发送数据包。

4.**服务器**准备完毕，主动向客户端发送 **FIN** 包，然后进入LAST_ACK状态

5.**客户端**收到服务器的 FIN 包后，再向服务器发送 **ACK** 包，进入TIME_WAIT状态

6. **服务器**收到客户端的 ACK 包后，就断开连接，关闭套接字，进入CLOSED状态。

同样这里只调用了close（）函数

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204092217189.png)

# 开始分析

将check程序放入ida，直接开始动态调试。

调试的时候注意用linux_server监听1234端口，因为在check程序里面给bind函数传入的是1234端口，说明这程序接受1234端口的数据

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204092217190.png)

linux_server监听1234端口的方法

```python
./linux_server64 -p 1234
```

调试的时候还有一个要注意的就是上面下断点的地方

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204092217191.png)

这是一个明显的linux程序反调试，先创建子进程利用子父进程sys_clone()的返回值不同，让子父进程运行不同的代码，并且将子进程用ptrace()附加，进程只能被一个调试器附加，这样就算且换进程调试子进程也会被产生异常。解决办法就是直接不执行这段代码，直接跳转到具有实际逻辑的代码部分，汇编状态下ctrl+n可以强制设置rip到鼠标所指的位置，直接跳转到信息交换的函数部分。

启动客户端，调试开始。

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204092217192.png)

# 发现关键点

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204092217193.png)

很明显的判断点

# 三大加密算法

发现关键点后自习分析这两个判断条件分别对应两个加密算法

### 第一个为RSA加密

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204092217194.png)

RSA加密用到的e的值

很长的那一连串数据就是n了，分解这个大数，以前用都是yafu来分解，看了大佬们的博客才知道，yafu是什么\*\*，太慢啦，还是在线网站来的快（[http://www.factordb.com/index.php](http://www.factordb.com/index.php) ）好网站！！

下面直接写脚本完成RSA解密

```python
import gmpy2

q = 98197216341757567488149177586991336976901080454854408243068885480633972200382596026756300968618883148721598031574296054706280190113587145906781375704611841087782526897314537785060868780928063942914187241017272444601926795083433477673935377466676026146695321415853502288291409333200661670651818749836420808033
p = 133639826298015917901017908376475546339925646165363264658181838203059432536492968144231040597990919971381628901127402671873954769629458944972912180415794436700950304720548263026421362847590283353425105178540468631051824814390421486132775876582962969734956410033443729557703719598998956317920674659744121941513
e = 0x10001
encode = 0x2e7469206873696c6f70206577206e6f697461737265766e6f63207962202c646e696d2065687420686369726e6520657720676e6964616572207942
# encode 数据可以直接动态调出来
d = gmpy2.invert(e,(p-1)*(q-1))
c = gmpy2.powmod(encode,d,q*p)
print(c)
#解出11963777321199993924175387978397443935563034091716786597947508874393819454915798980986262132792605021295930274531653741552766395859285325677395421549163602968276475448835066393456449574469736327622969755801884982386140722904578598391534204834007447860153096480268812700725451958035204357033892179559153729604237187552716580637492579876006993181920209114166153317182827927606249871955662032809256743464460825303610341043145126848787575238499023185150429072724679210155061579052743238859739734301162335989939278904459012917375108407803445722785027315562371588439877746983153339473213449448259686486917983129418859935686
```

### 第二个hill加密（希尔加密）

在这里有个函数一直很疑惑

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204092217195.png)

pz师傅直接就看出来它是rand（）函数，去问了一下为啥，师傅说是之前看过rand的代码，分析到这儿直接就看出来了（可恶）

大致分析一下逻辑将上面赋值的一连串数值作为hill加密的矩阵，将输入的密码加密，然后与rand（）的返回值比较，rand（）在没有种子的情况下是一个固定的数组，直接在linux上跑出来进行。

写脚本的时候我用numpy弄出来的逆转矩阵好怪，这里还是直接用师傅们的网站（[https://www.sfu.ca/~jtmulhol/math302/sagemath.html](https://www.sfu.ca/~jtmulhol/math302/sagemath.html)），把下面的脚本往上一放就出来答案省事啊

```python
x = Matrix(GF(257), [[113, 219, 37, 46, 122, 15], [76, 163, 106, 34, 170, 41], [110, 27, 169, 122, 138, 39], [47, 128, 240, 14, 170, 86], [247, 89, 88, 0, 169, 242], [246, 154, 78, 28, 72, 201]])

enc =  Matrix(GF(257), [[163, 151, 162, 85, 83, 190], [241, 252, 249, 121, 107, 82], [20, 19, 233, 226, 45, 81], [142, 31, 86, 8, 87, 39], [167, 5, 212, 208, 82, 130], [119, 117, 27, 153, 74, 237]])

flag = x.inverse()*enc
print(flag)
#解出5132d202c32d95b9f978d514e3294220513b15623482b4c02e9afde8bad5ec07486a5488
```

带入再调试，结果后面又要输入加密后，输出flag

### 第三个AES加密

调试跟踪到这个位置

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204092217196.png)

看看这个是什么数据

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204092217197.png)

百度前几个数据，发现是AES的逆s盒

下面是对于这个AES加密的分析，这个AES加密被魔改了，先将输入的账号和密码用rand（）函数”随机“提取出来，融合在一起作为AES加密的密钥

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204092217198.png)

然后就是把这个密钥拓展

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204092217199.png)

进入加密函数，下面是分析结果

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204092217200.png)

由于是魔改后的，所以得自己写代码，这里直接用PZ师傅的脚本啦，白嫖

```python
#include <stdio.h>

static const int S[256] =
{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const unsigned char Rcon[11] =
{
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static const int deColM[4][4] =
{
	0xE, 0xB, 0xD, 0x9,
	0x9, 0xE, 0xB, 0xD,
	0xD, 0x9, 0xE, 0xB,
	0xB, 0xD, 0x9, 0xE
};

static unsigned char W[44];

void ExtendKey(unsigned char * key);
void AddRoundKey(unsigned char (*stateMatrix)[4], unsigned char * key);
void DeShiftRows(unsigned char (*stateMatrix)[4]);
void DeSubBytes(unsigned char (*stateMatrix)[4]);
void DeMixColumns(unsigned char (*stateMatrix)[4]);
void XorIv(unsigned char * plainText, unsigned char * iv);
void AESDecode(unsigned char * enc, unsigned char * plainText, unsigned char * key);

int main(void)
{
	unsigned char key[] = {50, 48, 7, 54, 106, 55, 120, 49, 72, 57, 66, 57, 20, 49, 213, 50};
	unsigned char iv[] = {98, 54, 249, 56, 66, 48, 195, 49, 106, 53, 72, 56, 52, 53, 84, 52, 41, 52, 81, 54, 21, 57, 210, 56, 210, 57, 32, 49, 185, 50, 46, 48};
    unsigned char enc[] = {254, 249, 231, 62, 246, 161, 35, 204, 87, 97, 193, 21, 119, 251, 156, 187, 202, 47, 177, 232, 79, 217, 7, 216, 12, 107, 234, 207, 232, 66, 162, 250};
    unsigned char plainText[32] = { 0 };
    int i;

    for ( i = 0; i < 32; i += 16)
    {
    	AESDecode(enc + i, plainText + i, key);
    	XorIv(plainText + i, iv + i);
	}
    for ( i = 0; i < 32; i++ )
    	printf("%c", plainText[i]);

	return 0;
}

void XorIv(unsigned char * plainText, unsigned char * iv)
{
	int i;

	for ( i = 0; i < 16 ; i++ )
		plainText[i] ^= iv[i];
}

void GetStateMatrix(unsigned char (*stateMatrix)[4], unsigned char * enc)
{
	int i, j;

	for ( i = 0; i < 4; i++ )
		for ( j = 0; j < 4; j++ )
			stateMatrix[j][i] = enc[i * 4 + j];
}

void PutStateMatrix(unsigned char * plainText, unsigned char (*stateMatrix)[4])
{
	int i, j;

	for ( i = 0; i < 4; i++ )
		for ( j = 0; j < 4; j++ )
			plainText[i * 4 + j] = stateMatrix[j][i];
}

void AESDecode(unsigned char * enc, unsigned char * plainText, unsigned char * key)
{
	int i, j;
	ExtendKey(key);

	unsigned char stateMatrix[4][4] = { 0 };
	GetStateMatrix(stateMatrix, enc);

	i = 10;
	AddRoundKey(stateMatrix, W + i * 16);
	for ( i--; ; i-- )
	{
		DeShiftRows(stateMatrix);
		DeSubBytes(stateMatrix);
		AddRoundKey(stateMatrix, W + i * 16);
		if ( i == 0 )
			break;
		DeMixColumns(stateMatrix);
	}

	PutStateMatrix(plainText, stateMatrix);
}

static int GFMul2(int s)
{
	int result = s << 1;
	int a7 = result & 0x00000100;			//判断位移后的那位是否为 1

	if ( a7 != 0 )
	{
		result = result & 0x000000FF;
		result = result ^ 0x1B;				//矩阵乘法的特殊性
	}

	return result;
}

static int GFMul3(int s)
{
	return GFMul2(s) ^ s;
}

static int GFMul4(int s)
{
	return GFMul2(GFMul2(s));
}

static int GFMul8(int s)
{
	return GFMul2(GFMul4(s));
}

static int GFMul9(int s)
{
	return GFMul8(s) ^ s;
}

static int GFMul11(int s)
{
	return GFMul9(s) ^ GFMul2(s);
}

static int GFMul12(int s)
{
	return GFMul8(s) ^ GFMul4(s);
}

static int GFMul13(int s)
{
	return GFMul12(s) ^ s;
}

static int GFMul14(int s)
{
	return GFMul12(s) ^ GFMul2(s);
}

/**
 *	GF上的二元运算
 */
static int GFMul(int n, int s)
{
	int result;

	if ( n == 1 )
		result = s;
	else if ( n == 2 )
		result = GFMul2(s);
	else if ( n == 3 )
		result = GFMul3(s);
	else if ( n == 9 )
		result = GFMul9(s);
	else if ( n == 0xB )
		result = GFMul11(s);
	else if ( n == 0xD )
		result = GFMul13(s);
	else if ( n == 0xE )
		result = GFMul14(s);

	return result;
}

void DeMixColumns(unsigned char (*stateMatrix)[4])
{
	unsigned char tmpArray[4][4];
	int i, j;

	for ( i = 0; i < 4; i++ )
		for ( j = 0; j < 4; j++ )
			tmpArray[i][j] = stateMatrix[i][j];

	for ( i = 0; i < 4; i++ )
		for ( j = 0; j < 4; j++ )
			stateMatrix[i][j] = GFMul(deColM[i][0], (int)tmpArray[0][j]) ^
								GFMul(deColM[i][1], (int)tmpArray[1][j]) ^
								GFMul(deColM[i][2], (int)tmpArray[2][j]) ^
								GFMul(deColM[i][3], (int)tmpArray[3][j]);
}

void DeSubBytes(unsigned char (*stateMatrix)[4])
{
	int i, j;

	for ( i = 0; i < 4; i++ )
		for ( j = 0; j < 4; j++ )
			stateMatrix[i][j] = S[stateMatrix[i][j]];
}

void DeShiftRows(unsigned char (*stateMatrix)[4])
{
	int i, j, count, t;

	for ( i = 1; i <= 3; i++ )
	{
		count = 0;
		while ( count++ < i )
		{
			t = stateMatrix[i][3];
			for ( j = 3; j >= 1; j-- )
				stateMatrix[i][j] = stateMatrix[i][j - 1];
			stateMatrix[i][0] = t;
		}
	}
}

void AddRoundKey(unsigned char (*stateMatrix)[4], unsigned char * key)
{
	int i, j;

	for ( i = 0; i <= 3; i++ )
		for ( j = 0; j <= 3; j++ )
			stateMatrix[i][j] ^= key[4 * j + i];
}

void ExtendKey(unsigned char * key)
{
	unsigned char tmp[16];
	int i, j;

	for ( i = 0; i <= 3; i++ )
	{
		W[4 * i] = key[4 * i];
		W[4 * i + 1] = key[4 * i + 1];
		W[4 * i + 2] = key[4 * i + 2];
		W[4 * i + 3] = key[4 * i + 3];
	}

	for ( j = 4; j < 44; j++ )
	{
		unsigned char v9 = W[4 * (j - 1)];
		unsigned char v10 = W[4 * (j - 1) + 1];
		unsigned char v11 = W[4 * (j - 1) + 2];
		unsigned char v12 = W[4 * (j - 1) + 3];
		if ( (j & 3) == 0 )
		{
			v10 = S[v11];
			v11 = S[v12];
			v12 = S[W[4 * (j - 1)]];
			v9 = S[W[4 * (j - 1) + 1]] ^ Rcon[j >> 2];
		}
		W[(4 * j)] = v9 ^ W[4 * (j - 4)];
		W[(4 * j) + 1] = v10 ^ W[4 * (j - 4) + 1];
		W[(4 * j) + 2] = v11 ^ W[4 * (j - 4) + 2];
		W[(4 * j) + 3] = v12 ^ W[4 * (j - 4) + 3];
	}
}
#输出7026271d7bb5d404d63a72b88e6b4d63
```

# 小结

写了这边wp，又弄懂几个了之前复现的时候的异或，逆向这种事情弄透彻了，感觉是很爽的，这道题让我认识到了网络编程，对于注册机这种东西有了一定的认识，希望下次看到类似的还能想起这篇wp哈哈。

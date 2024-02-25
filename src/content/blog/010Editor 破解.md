---
author: s0rry
pubDatetime: 2022-05-07T20:06:55Z
modDatetime: 2022-05-08T00:06:55Z
title: 010Editor 破解
slug: 010Editor-Learn
featured: false
draft: false
tags:
  - windows
description: 010Editor 破解，学习注册机编写
---

# 010Editor 破解

## 准备阶段

分析版本：010editor 版本：12.0.1

使用工具：x64dbg & ida

## 前言

实践点东西。这次对010这个程序进行了逆向分析，这是本人第一次系统的对程序进行分析，比较菜，但是学到了弄这种注册的整个大概思路。本来想着用纯汇编去逆向的，后来在逆部分算法的时候还是借用了ida f5的威力。

由于想锻炼自己的汇编能力，所以没有上来直接就上ida，感觉这种程序看汇编比看ida的伪代码要舒服一些。

## 摸索爆破

由于刚从官网上下的还在试用期，打开就直接启动了，自己乱点半天什么都没看出来，用x64也没有任何的输入点。然后我把它放到我的win7虚拟机中去，调虚拟机时间往后调了2年，准备将它的试用时间结束，结果还是没有到期（这个是一个疑惑点，之后可以细细了解一下），之后又反复调了几次才到期。

成功进入登录界面可以开始分析

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202205081103671.png)

由于登录失败有弹窗，所以在windows的系统弹窗函数CreateWindowExW下断点，查看调用堆栈向上跟踪（在看调用堆栈的时候注意分清是哪个线程，通常就是第一线程，通过jmp转的是不会在调用堆栈里面的）

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202205081103673.png)

这种地址比较的大的都是系统函数调用，选择正常地址且比较靠下的地址比较好跟，因为靠上的函数一跟进去就进系统函数了什么都看不到。这里从红色那位置跟一下试试

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202205081103674.png)

单步跟踪很快就到了，一系列的跳转与输入的账号和验证码有关

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202205081103675.png)

这里看到字符串都是明文才反应过来可以直接搜字符串定位的，我菜死了。

爆破的话直接在这里把全部判断nop掉就行。

## 深入算法部分

我是以学习汇编和研究破解为目的，所以深入挖掘它检验密码正确的算法是什么样的，达到可以自己写密码的目的。

通过上面有个跳转判断edx的值后就显示我的密码是错误的，向上追述改动ebx的位置，按H x64可以显示高亮

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202205081103676.png)

下面的是跳转到刚刚的判断的指令，所以就很明显了，在上面的函数就是密码的验证函数，也就是可能包含了对输入的密码的解读就在函数里，单步跟进去就开始逆算法了，其实也不算逆，只需要通过汇编弄出c代码，找到一条满足所有if判断的路径就可以。

算法部分就没什么好说的了，这里列出一下**大概逻辑**：

---

**密码转换成16进制数字（每两个一组）**→**判断第4组转换后的密码的值**（**不同的值**对应**不同的密码格式**，这里我就用的8位密码，这样第四组数据位0x9c）→**两个加密函数分别对不同的位置进行加密**，返回一个用于下面判断的值 → **对返回值进行判断**（第一个函数得返回不等于0，第二个返回的值要小于0x3e7）→**对输入的账号进行类似hash的加密**→**将加密后的值与与密码分组比较**→结束

---

解密源码:

```c
#include <stdio.h>
#include <windows.h>
#include <time.h>
int password[] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88 };
int sig = 100;// 看雪上的大佬说这个是密码的次数
char input_name[] = "s0rry";// 这里是用户名可以更改
unsigned int hash = 0;
void name_hash() {
	unsigned int num[] = {
	0x39CB44B8, 0x23754F67, 0x5F017211, 0x3EBB24DA, 0x351707C6, 0x63F9774B, 0x17827288, 0x0FE74821,
	0x5B5F670F, 0x48315AE8, 0x785B7769, 0x2B7A1547, 0x38D11292, 0x42A11B32, 0x35332244, 0x77437B60,
	0x1EAB3B10, 0x53810000, 0x1D0212AE, 0x6F0377A8, 0x43C03092, 0x2D3C0A8E, 0x62950CBF, 0x30F06FFA,
	0x34F710E0, 0x28F417FB, 0x350D2F95, 0x5A361D5A, 0x15CC060B, 0x0AFD13CC, 0x28603BCF, 0x3371066B,
	0x30CD14E4, 0x175D3A67, 0x6DD66A13, 0x2D3409F9, 0x581E7B82, 0x76526B99, 0x5C8D5188, 0x2C857971,
	0x15F51FC0, 0x68CC0D11, 0x49F55E5C, 0x275E4364, 0x2D1E0DBC, 0x4CEE7CE3, 0x32555840, 0x112E2E08,
	0x6978065A, 0x72921406, 0x314578E7, 0x175621B7, 0x40771DBF, 0x3FC238D6, 0x4A31128A, 0x2DAD036E,
	0x41A069D6, 0x25400192, 0x00DD4667, 0x6AFC1F4F, 0x571040CE, 0x62FE66DF, 0x41DB4B3E, 0x3582231F,
	0x55F6079A, 0x1CA70644, 0x1B1643D2, 0x3F7228C9, 0x5F141070, 0x3E1474AB, 0x444B256E, 0x537050D9,
	0x0F42094B, 0x2FD820E6, 0x778B2E5E, 0x71176D02, 0x7FEA7A69, 0x5BB54628, 0x19BA6C71, 0x39763A99,
	0x178D54CD, 0x01246E88, 0x3313537E, 0x2B8E2D17, 0x2A3D10BE, 0x59D10582, 0x37A163DB, 0x30D6489A,
	0x6A215C46, 0x0E1C7A76, 0x1FC760E7, 0x79B80C65, 0x27F459B4, 0x799A7326, 0x50BA1782, 0x2A116D5C,
	0x63866E1B, 0x3F920E3C, 0x55023490, 0x55B56089, 0x2C391FD1, 0x2F8035C2, 0x64FD2B7A, 0x4CE8759A,
	0x518504F0, 0x799501A8, 0x3F5B2CAD, 0x38E60160, 0x637641D8, 0x33352A42, 0x51A22C19, 0x085C5851,
	0x032917AB, 0x2B770AC7, 0x30AC77B3, 0x2BEC1907, 0x035202D0, 0x0FA933D3, 0x61255DF3, 0x22AD06BF,
	0x58B86971, 0x5FCA0DE5, 0x700D6456, 0x56A973DB, 0x5AB759FD, 0x330E0BE2, 0x5B3C0DDD, 0x495D3C60,
	0x53BD59A6, 0x4C5E6D91, 0x49D9318D, 0x103D5079, 0x61CE42E3, 0x7ED5121D, 0x14E160ED, 0x212D4EF2,
	0x270133F0, 0x62435A96, 0x1FA75E8B, 0x6F092FBE, 0x4A000D49, 0x57AE1C70, 0x004E2477, 0x561E7E72,
	0x468C0033, 0x5DCC2402, 0x78507AC6, 0x58AF24C7, 0x0DF62D34, 0x358A4708, 0x3CFB1E11, 0x2B71451C,
	0x77A75295, 0x56890721, 0x0FEF75F3, 0x120F24F1, 0x01990AE7, 0x339C4452, 0x27A15B8E, 0x0BA7276D,
	0x60DC1B7B, 0x4F4B7F82, 0x67DB7007, 0x4F4A57D9, 0x621252E8, 0x20532CFC, 0x6A390306, 0x18800423,
	0x19F3778A, 0x462316F0, 0x56AE0937, 0x43C2675C, 0x65CA45FD, 0x0D604FF2, 0x0BFD22CB, 0x3AFE643B,
	0x3BF67FA6, 0x44623579, 0x184031F8, 0x32174F97, 0x4C6A092A, 0x5FB50261, 0x01650174, 0x33634AF1,
	0x712D18F4, 0x6E997169, 0x5DAB7AFE, 0x7C2B2EE8, 0x6EDB75B4, 0x5F836FB6, 0x3C2A6DD6, 0x292D05C2,
	0x052244DB, 0x149A5F4F, 0x5D486540, 0x331D15EA, 0x4F456920, 0x483A699F, 0x3B450F05, 0x3B207C6C,
	0x749D70FE, 0x417461F6, 0x62B031F1, 0x2750577B, 0x29131533, 0x588C3808, 0x1AEF3456, 0x0F3C00EC,
	0x7DA74742, 0x4B797A6C, 0x5EBB3287, 0x786558B8, 0x00ED4FF2, 0x6269691E, 0x24A2255F, 0x62C11F7E,
	0x2F8A7DCD, 0x643B17FE, 0x778318B8, 0x253B60FE, 0x34BB63A3, 0x5B03214F, 0x5F1571F4, 0x1A316E9F,
	0x7ACF2704, 0x28896838, 0x18614677, 0x1BF569EB, 0x0BA85EC9, 0x6ACA6B46, 0x1E43422A, 0x514D5F0E,
	0x413E018C, 0x307626E9, 0x01ED1DFA, 0x49F46F5A, 0x461B642B, 0x7D7007F2, 0x13652657, 0x6B160BC5,
	0x65E04849, 0x1F526E1C, 0x5A0251B6, 0x2BD73F69, 0x2DBF7ACD, 0x51E63E80, 0x5CF2670F, 0x21CD0A03,
	0x5CFF0261, 0x33AE061E, 0x3BB6345F, 0x5D814A75, 0x257B5DF4, 0x0A5C2C5B, 0x16A45527, 0x16F23945
	};
	int about_retn_func = sig * 15;
	int retn_func = about_retn_func & 0xff;
	//printf("\n%x %x\n", retn_func, num[retn_func]);
	int zero = 0 * 17;

	unsigned int tmp = 0;
	unsigned int v9 = 0;
	unsigned int v19 = 0;

	for (int i = 0; i < strlen(input_name); i++) {
		if (input_name[i] <= 'z' && input_name[i] >= 'a') {
			input_name[i] = input_name[i] - 'a' + 'A';
		}
		unsigned int* pZero = &num[zero];
		retn_func = about_retn_func & 0xff;
		unsigned int* pretn_func = &num[retn_func];
		tmp = hash + num[input_name[i]];
		unsigned int in_13 = num[input_name[i] + 13];
		unsigned int index_in_47 = input_name[i] + 47;
		v19 = v9;
		zero += 9;
		about_retn_func += 13;

		v9 += 19;
		hash = *pretn_func + *pZero + num[v19] + num[index_in_47] * (tmp ^ in_13);
	}
}
int main(){
    srand(time(NULL));
    name_hash();// 根据用户名确定部分密码的值，再爆破其他值
    password[3] = 0x9c;
		password[4] = (hash & 0xff);
		password[5] = ((hash >> 8) & 0xff);
		password[6] = ((hash >> 16) & 0xff);
		password[7] = ((hash >> 24) & 0xff);
    while (1) {
				password[0] = rand() % 0xff;
				if ((((password[0] ^ password[6] ^ 0x18) + 0x3d) ^ 0xa7) != 0) {
					break;
				}
		}
    while(1){
        password[2] = rand() % 0xff;
				password[1] = rand() % 0xff;
				DWORD tmp = (0x100 * (password[1] ^ password[7] & 0xFF) + password[2] ^ password[5] & 0xff) & 0xFFFF;
				DWORD times = (((tmp ^ 0x7892) + 0x4d30) ^ 0x3421) & 0xFFFF;
				if (times % 0xB == 0 && (times / 0xB) == 100)//密码可用次数
				{
					break;
				}
    }
    printf("\n");
    for(int i =0;i<8;i++){
        printf("%x",password[i]);
    }
    return 0;
}
```

## 总结

虽然这个软件已经被逆向人员扒干净了，但是作为新手还是有学习的必要的，没有壳，这个程序日常也在使用，逆出来还是有一定的成就感。通过对它的分析，我了解到注册获取激活码的基本流程。

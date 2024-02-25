---
author: s0rry
pubDatetime: 2022-06-18T10:33:00Z
modDatetime: 2022-06-18T18:23:00Z
title: 浅谈Electron框架逆向
slug: Electron-Reverse
featured: true
draft: true
tags:
  - reverse
description: 浅谈Electron框架逆向
---

# 浅谈electron框架逆向

## 前期准备

分析版本：010editor 版本：1.0.3

环境：

Node.js 版本：v16.13.1

python 版本：3.7

HOOK框架：frida 版本： 15.1.17

asar文件解包工具： asar

## 前言

浅谈electron框架逆向，electron作为一个跨平台的的开发框架，被广泛应用于众多桌面程序，就拿windows平台来说就有 vscode， 阿里云盘， utools, Typore等等，这里就拿Typore来探究electron框架下的js代码处理。

typora作为一个出色的markdown编写工具，界面十分简洁。更新1.0的后typora开始收费了，虽然基本功能不收费，但是对于逆向人员来说，这个收费界面本身就充满了趣味。

## Electron

项目基本结构

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206190128028.png)

Chromium : 为Electron提供了强大的UI能力，可以不考虑兼容性的情况下，利用强大的Web生态来开发界面。本质上就是chrome开源版本的浏览器

native apis：N-API为开发者提供了一套C/C++ API用于开发Node.js的Native扩展模块。从Node.js 8.0.0开始，N-API以实验性特性作为Node.js本身的一部分被引入，并且从Node.js 10.0.0开始正式全面支持N-API。

## win平台下Electron程序的特征

有以.asar的文件后缀，其中app.asar里面一般就是程序的源码，被封装起来了

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206190128029.png)

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206190128030.png)

## 分析步骤

### 1.对app.asar文件进行解包

- 安装node.js
- 用node.js的包管理器npm下载解包工具asar

```cpp
npm install -g asar
```

- 使用asar解包

```cpp
asar extract app.asar {输出的文件夹}
```

这里对app.asar这个文件解包

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206190128031.png)

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206190128032.png)

### 2.代码解密

Js代码要运行就必须得变成明文或者字节码，这里代码看到是乱码应该是被加密了。一定在某个地方进行了解密的，只需要找到这个地方吗，编写一个一模一样的解密代码就可以了。

这里就注意到main.node这个文件，js代码能运行在nodejs的环境下就是靠的这个文件，在其中一定存在解密函数。

### hook法

由于文件一定会被解密后才可以运行，可以直接找到哪个地方是解密完成的点，直接hook这个点获取到解密后的明文即可。

hook的方法这里就很多了，由于最近在看frida hook框架，刚好又在看雪上看到一篇用frida hook到的文章，这里直接用frida来hook了。

[看雪师傅](https://bbs.pediy.com/thread-272604.htm)的frida的hook代码

```cpp
let napi_create_string_utf8 = Module.getExportByName(null, 'napi_create_string_utf8');
var index = 0;
if (napi_create_string_utf8) {
    console.log('yes');
    Interceptor.attach(napi_create_string_utf8, {
        onEnter: function (args) {
            console.log('napi_create_string_utf8', '调用', args[0], args[1].readCString().substring(0, 100), args[2], args[3]);

            if (args[2].toInt32() > 100) {
                index += 1;
                var f = new File('export_' + String(index) + '.js', 'wb');
                f.write(args[1].readByteArray(args[2].toInt32()));
                f.flush();
                f.close();

            }
        }
    });
} else {
    console.log('no');
}
```

这里选择hook的是napi_create_string_utf8这个api，就是一个创建字符串的api。

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206190128033.png)

frida有两种hook模式，一种是结合python把js代码嵌入python中去运行，还有一种是直接调用js代码通过命令行hook，命令行的比较简单，这里直接用命令行的就好。

```cpp
frida -f Typora.exe -l typorahook.js --no-pause
```

详细的命令含义直接百度一下，这里不过多解释，给出hook结果

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206190128034.png)

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206190128035.png)

---

### 直接解密法

上面的hook法，虽然比较快，但是没办法得到函数名，如果要修改代码逻辑的话还得是用直接解密的方法才比较好用。

利用ida的插件发现，main.node、调用了AES的s盒的数据

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206190128036.png)

**交叉引用逆s盒，找到解密代码，去除main,node的地址随机加载ALSR功能，用x64调试typro,在AES解密处下断点，找到AES密钥及其扩散后的结果**

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206190128037.png)

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206190128038.png)

解密代码,写的比较粗糙，再解md5之前得先把文件base64解码，base64我用的是python弄的，这里AES我又是用c语言写的，拼装在一起用哈哈哈哈

```cpp
#include <stdio.h>
#include <cstdio>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <string.h>
#include <windows.h>
// 逆s盒
int Nk = 8, Nr = 14;
int Nb = 4;

uint8_t inv_s_box[267] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};
uint8_t key[] = {
	0x4e,0xe1,0xb3,0x82,0x94,0x9a,0x02,0x4b,0x80,0x2f,0x52,0xb4,0xb4,0xfe,0x57,0xf1,
    0xbe,0xf4,0x08,0x53,0x10,0x92,0x56,0xe2,0xc2,0x0d,0xec,0xa3,0xdd,0x8d,0xd5,0x6d,
    0x12,0xe2,0x8f,0x43,0x86,0x78,0x8d,0x08,0x06,0x57,0xdf,0xbc,0xb2,0xa9,0x88,0x4d,
    0x89,0x27,0xcc,0xb0,0x99,0xb5,0x9a,0x52,0x5b,0xb8,0x76,0xf1,0x86,0x35,0xa3,0x9c,
    0x86,0xe8,0x51,0x07,0x00,0x90,0xdc,0x0f,0x06,0xc7,0x03,0xb3,0xb4,0x6e,0x8b,0xfe,
    0x04,0xb8,0xf1,0x0b,0x9d,0x0d,0x6b,0x59,0xc6,0xb5,0x1d,0xa8,0x40,0x80,0xbe,0x34,
    0x4f,0x46,0x49,0x0e,0x4f,0xd6,0x95,0x01,0x49,0x11,0x96,0xb2,0xfd,0x7f,0x1d,0x4c,
    0x50,0x6a,0x55,0x22,0xcd,0x67,0x3e,0x7b,0x0b,0xd2,0x23,0xd3,0x4b,0x52,0x9d,0xe7,
    0x47,0x18,0xdd,0xbd,0x08,0xce,0x48,0xbc,0x41,0xdf,0xde,0x0e,0xbc,0xa0,0xc3,0x42,
    0x35,0x8a,0x7b,0x0e,0xf8,0xed,0x45,0x75,0xf3,0x3f,0x66,0xa6,0xb8,0x6d,0xfb,0x41,
    0x6b,0x17,0x5e,0xd1,0x63,0xd9,0x16,0x6d,0x22,0x06,0xc8,0x63,0x9e,0xa6,0x0b,0x21,
    0x3e,0xae,0x50,0xf3,0xc6,0x43,0x15,0x86,0x35,0x7c,0x73,0x20,0x8d,0x11,0x88,0x61,
    0xc9,0xd3,0xb1,0x8c,0xaa,0x0a,0xa7,0xe1,0x88,0x0c,0x6f,0x82,0x16,0xaa,0x64,0xa3,
    0x79,0x02,0x13,0xf9,0xbf,0x41,0x06,0x7f,0x8a,0x3d,0x75,0x5f,0x07,0x2c,0xfd,0x3e,
    0xf8,0x87,0x03,0x49,0x52,0x8d,0xa4,0xa8,0xda,0x81,0xcb,0x2a,0xcc,0x2b,0xaf,0x89
};

uint8_t gmult(uint8_t a, uint8_t b) {

	uint8_t p = 0, i = 0, hbs = 0;

	for (i = 0; i < 8; i++) {
		if (b & 1) {
			p ^= a;
		}

		hbs = a & 0x80;
		a <<= 1;
		if (hbs) a ^= 0x1b; // 0000 0001 0001 1011
		b >>= 1;
	}

	return (uint8_t)p;
}

void coef_mult(uint8_t *a, uint8_t *b, uint8_t *d) {

	d[0] = gmult(a[0],b[0])^gmult(a[3],b[1])^gmult(a[2],b[2])^gmult(a[1],b[3]);
	d[1] = gmult(a[1],b[0])^gmult(a[0],b[1])^gmult(a[3],b[2])^gmult(a[2],b[3]);
	d[2] = gmult(a[2],b[0])^gmult(a[1],b[1])^gmult(a[0],b[2])^gmult(a[3],b[3]);
	d[3] = gmult(a[3],b[0])^gmult(a[2],b[1])^gmult(a[1],b[2])^gmult(a[0],b[3]);
}

void add_round_key(uint8_t *state, uint8_t *w, uint8_t r) {

	uint8_t c;

	for (c = 0; c < Nb; c++) {
		// 按列循环，计算第c列的值
		// state[row,col] = state[row,col]^w[col,row]（r=0）
		state[Nb*0+c] = state[Nb*0+c]^w[4*Nb*r+4*c+0];   //debug, so it works for Nb !=4
		state[Nb*1+c] = state[Nb*1+c]^w[4*Nb*r+4*c+1];
		state[Nb*2+c] = state[Nb*2+c]^w[4*Nb*r+4*c+2];
		state[Nb*3+c] = state[Nb*3+c]^w[4*Nb*r+4*c+3];
	}
}
void inv_shift_rows(uint8_t *state) {

	uint8_t i, k, s, tmp;

	for (i = 1; i < 4; i++) {
		s = 0;
		while (s < i) {
			tmp = state[Nb*i+Nb-1];

			for (k = Nb-1; k > 0; k--) {
				state[Nb*i+k] = state[Nb*i+k-1];
			}

			state[Nb*i+0] = tmp;
			s++;
		}
	}
}

void inv_sub_bytes(uint8_t *state) {

	uint8_t i, j;
	uint8_t row, col;

	for (i = 0; i < 4; i++) {
		for (j = 0; j < Nb; j++) {
			row = (state[Nb*i+j] & 0xf0) >> 4;
			col = state[Nb*i+j] & 0x0f;
			state[Nb*i+j] = inv_s_box[16*row+col];
		}
	}
}
void inv_mix_columns(uint8_t *state) {

	uint8_t a[] = {0x0e, 0x09, 0x0d, 0x0b}; // a(x) = {0e} + {09}x + {0d}x2 + {0b}x3
	uint8_t i, j, col[4], res[4];

	for (j = 0; j < Nb; j++) {
		for (i = 0; i < 4; i++) {
			col[i] = state[Nb*i+j];
		}

		coef_mult(a, col, res);

		for (i = 0; i < 4; i++) {
			state[Nb*i+j] = res[i];
		}
	}
}

void inv_cipher(uint8_t *in, uint8_t *out, uint8_t *w) {

	uint8_t state[4*Nb];
	uint8_t r, i, j;

	for (i = 0; i < 4; i++) {
		for (j = 0; j < Nb; j++) {
			state[Nb*i+j] = in[i+4*j];
		}
	}


	add_round_key(state, w, Nr);

	for (r = Nr-1; r >= 1; r--) {
		inv_shift_rows(state);
		inv_sub_bytes(state);
		add_round_key(state, w, r);
		inv_mix_columns(state);
	}

	inv_shift_rows(state);
	inv_sub_bytes(state);
	add_round_key(state, w, 0);

	for (i = 0; i < 4; i++) {
		for (j = 0; j < Nb; j++) {
			out[i+4*j] = state[Nb*i+j];
		}
	}
}

int main(){
	char path[] = {"E:\\Typora\\resources\\workstation\\app.asar\\License.jsDecodeBase64"};
	char path_decrypt[] = {"E:\\Typora\\resources\\workstation\\app.asar\\LicenceDecodeMD5.js"};
	FILE  *file_decrpt = fopen(path_decrypt,"wb+");
	FILE  *file = fopen(path,"rb");
	fseek(file,0,SEEK_END);//定位到文件的最后面
	long length  = ftell(file);//ftell获得该文件指示符此时的偏移量,此时已经是在文件末尾,故能获得文件的大小
	fseek(file,0,SEEK_SET);//定位到文件的最后面
	BYTE* file_start;
	file_start = (BYTE*)malloc(length);
	char* file_decrpt_code;
	file_decrpt_code = (char*)malloc(length);
	memset(file_decrpt_code,0,length);
	fread(file_start, 1, length, file);
	fclose(file);
	printf("\n%d\n",length);
	uint8_t mod[16];
	uint8_t encode[16];
	for(int i = 0; i<length/16-1;i++){
		for(int j = 0;j<16;j++){
			mod[j] = file_start[j+i*16];
			encode[j] = file_start[j+(i+1)*16];
			//printf("%x ",encode[j]);
		}
		// if(i == (length/16)-1){
		// 	for(int j = 0;j<16;j++){
		// 		printf("%x ",encode[j]);
		// 	}
		// 	break;
		// }
		uint8_t out[16] = { 0,};
		inv_cipher(encode,out,key);
		for(int j = 0;j<16;j++){
			out[j] ^= mod[j];
			file_decrpt_code[i*16+j] = out[j];
			//printf("%c",file_decrpt_code[i*16+j]);
		}
	}
	int num = 0;
	for(int j = 15;j>0;j--){
		if(file_decrpt_code[(length/16-1-1)*16+j]==0xb){
			num++;
		}
	}
	fwrite(file_decrpt_code,1,length-16-num,file_decrpt);
	fclose(file_decrpt);
    return 0;
}
```

运行结果

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202206190128039.png)

## 小结

就electron框架而言，官方是没有提供相关代码层面的保护的，electron的这种代码的保护方法是github上一个大佬的提出的源代码保护方案，但是这种保护方案还是比较的好破，同时在当源码被获取到的时候typora并没有后续的检测操作，希望增加检测方式来得知，程序的源码是否被篡改。

新版的electron在asar的解包上做了一定的操作，当我再对新版的app.asar解包的时候并未得到先关的加密后的js代码，只能获得一个main.node文件，详细的信息我还不得而知，等之后探索了再得出结论。

## 参考博客

[https://bbs.pediy.com/thread-272604.htm](https://bbs.pediy.com/thread-272604.htm)

[https://www.52pojie.cn/forum.php?mod=viewthread&tid=1553967&highlight=Typora](https://www.52pojie.cn/forum.php?mod=viewthread&tid=1553967&highlight=Typora)

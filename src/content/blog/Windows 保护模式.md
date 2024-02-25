---
author: s0rry
pubDatetime: 2023-06-08T03:39:00Z
modDatetime: 2023-06-08T03:39:00Z
title: Windows 保护模式
slug: Windows-Protection
featured: false
draft: false
tags:
  - windows
description: Windows 保护模式，深入了解一个操作系统还是得往内核学
---

# window 保护模式

**实模式**：在实模式下，内存是以**段:段内偏移**的方式寻址的，所操作的地址都是物理地址，并且所有的段都是可以读、写、执行的，就相当于直接运行在机器之上的程序，没有任何保护措施，可以认为当一个程序修改了 0x1000的内存地址，另一个程序读取0x1000的地址会是被修改后的数据。

**保护模式**：段保护 页保护

为了将程序之间的（内存）空间隔离开

## 段

### 段寄存器

16+80位 （这80位是缓存在硬件里的，修改GDT表后不会立即变化）

CPU共有八个段寄存器 ： ES CS SS DS FS GS LDTR TR ，OD可见前6个，但GS段寄存器windows并未使用（32位下）。

如果运行在实模式下，则只有前四个有用。

如果是64位，则使用GS而不是FS。

![Untitled.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled.png)

读段寄存器指令：mov ax,es 只能读16位（可见部分）

写段寄存器指令：mov ds,ax 写了96位的。

![Untitled 1.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%201.png)

### \***\*段描述符\*\***

### \***\*GDT 全局描述符表\*\***

GDT是一块内存，是CPU设计中要求操作系统提供的一款内存。这块内存是操作系统在启动时填充的。

```cpp
r gdtr  r查看gdtr寄存器(内存)的前32位也就是位置
r gdtl  r查看gdtr寄存器(内存)的后16位也就是大小
```

### \***\*LDT 局部描述符表\*\***

与GDT作用一样，但是在windows中很少

### 段描述符结构

![Untitled 2.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%202.png)

### 段选择子

段选择子决定去GDT/LDT表中查哪一个段描述符

段选择子的RPL一定要<=对应段描述符的DPL ，否则试图使用该选择子加载对应段描述符的行为将由于权限不足而失败

![Untitled 3.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%203.png)

### \***\*段描述符属性\*\***

先看p位 → s位 → Typeu域

**P位**

有效位 1：描述符有效 0：描述符无效

**G位**

在上文填充段寄存器隐藏部分时，Limit在描述符中只有5个16进制位表示，剩下的3个16进制位就需要看G位。

当G为0时，整个段将以字节对齐，Limit大小单位为字节，所以精确到1。Limit直接就是段长。段寄存器中的Limit高位补0。

当G为1时，整个段将以4KB对齐，Limit大小单位为4KB，所以段的末尾处一定是以FFF结尾。段寄存器中的Limit低位补FFF。

\***\*S位\*\***

描述符类型位。 为0时，是系统段描述符。 为1时，是代码或数据段描述符。具体类型需要搭配type属性来判断。

\***\*Type域\*\***

决定了具体是代码段还是数据段描述符

s==1

```cpp
数据段：
A位：数据段是否被访问过位，访问过为1，未访问过为0  段描述符是否被加载过
W位：数据段是否可写位，可写为1，不可写为0
E位：向下扩展位，0向上扩展：段寄存器.base+limit区域可访问（fs[1]等）。1向下扩展(4gb)：除了base+limit以外的部分可访问。
代码段：
A位：代码段是否被访问过位，访问过为1，未访问过为0  段描述符是否被加载过
R位：代码段是否可读位，可读为1，不可读为0
C位：一致位。1：一致代码段。   0：非一致代码段  具体后文解释
```

![Untitled 4.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%204.png)

![Untitled 5.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%205.png)

s==0

![Untitled 6.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%206.png)

**D/B位**

大段或者小段，分为三种情况：

对CS段来说：

为1时，默认为32位寻址。 为0时，默认为16位寻址。

对SS段来说：

为1时，隐式堆栈访问指令（PUS H POP CALL RETN等）修改的是32位寄存器ESP

为0时，隐式堆栈访问指令（PUSH POP CALL RETN等）修改的是16位寄存器SP

对于向下扩展的数据段：

为1时，段上限大小为4GB。 为0时 段上限大小为64KB

### \***\*段权限检查\*\***

**CPU分级（与操作系统无关）**

0环 1环 2环 3环 特权指令只能运行在0环

**CPL-当前特权级别**

当前特权级：CS和SS段选择子的后两位。之所以称为3环程序就是CPL为3

CS和SS段选择子的后两位永远相同！（X86规定的）

所以所谓的你程序是几环的就是看CS SS，而所谓的提权就是改CS SS，只要有一种方法能改掉CS

SS，那就是提权。

**DPL-描述符特权级别**

描述符特权级别：访问该段所需要的特权级别。

**RPL-请求特权级别**

请求特权级别：段选择子中的后两位，可以随意指定。

当使用选择子来加载段描述符时，会检查CPL DPL RPL三者。

RPL 段选择子的最后两位，可以自己指定

DPL 在段描述符中，由段决定

CPL cs和ss的最后两位，由当前代码在哪一环运行决定

CPL<=DPL且RPL<=DPL代码才会执行

### \***\*代码跨段跳转\*\***

必须保证CS与EIP同时修改，因此没有lcs这种只修改cs的指令

```cpp
JMP FAR、CALL FAR、RETF、INT、IRETED
```

1.0x20为段选择子，拆分后RPL=0 TI=0 INDEX=4，因此查GDT表，索引为4，请求特权级为0

2.查GDT找对应段描述符。由于是修改CS段，所以不是所有段描述符都可以，四种情况可以跳转：代码段、调用门、TSS任务段、任务门    此处为了练习我们只规定其必须使用代码段描述符。

3.权限检查 如果是非一致代码段  CPL== DPL 且 RPL<=DPL   严格检查权限则使用非一致代码段

如果是一致代码段  CPL>=DPL  不会破坏内核数据的可以使用一致代码段

4.将段描述符加载到CS段寄存器中。

5.将SC.base+Offset写入EIP，然后执行CS:EIP处的代码

一致代码段：

也就是共享的段，特权级高的程序不允许访问特权级低的数据：内核态不允许访问用户态数据

特权级低的程序可以访问特权级高的数据：用户态可以访问内核态数据，但特权级依然是用户级别。

非一致代码段：

普通代码段，只允许同级访问。禁止不同级别的访问。

**测试数据**

```cpp
// 修改004b为48 cs还是会被修改为4b
jmp far 004b:0040155b

// 非一致代码段 DPL==3 成功
eq 8003f048 00cffb00`0000ffff

// 非一致代码段 DPL==0 失败
eq 8003f048 00cf9b00`0000ffff

// 一致代码段 DPL==0 成功
eq 8003f048 00cf9f00`0000ffff
```

### \***\*长调用与短调用\*\***

CALL FAR指令 不只修改CS 和 EIP 同时修改堆栈

**短调用**

![Untitled 7.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%207.png)

**长调用**

CALL FAR 不提权

3环跳转到另一个3环代码段，不会切换堆栈。

比段调用多push 段寄存器CS

![Untitled 8.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%208.png)

CALL FAR 提权

从3环跳转到0环，此过程发生堆栈替换。

![Untitled 9.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%209.png)

CALL CS:EIP(EIP是废弃的)

EIP是废弃的，所有信息都根据CS获取，这个CS是段选择子，指向GDT表中的一个特殊的“段”，这个特殊的“段”叫调用门。在提权长调用中，0环堆栈除了返回地址，调用者CS以外，还压入了调用者的SS和ESP，这部分数据是从TSS段中获取的

### 无参调用门构造方式

调用门描述符中的段选择子字段要设置成指向某个系统代码段，比如8003f008，则段选择子设置为00001000b = 0x08

TYPE固定设置成0xC表示这是一个调用门

XXXX XXXX表示要执行的函数地址

```cpp
XXXXEC00 00008XXXX
```

### 带参数的调用门

设置 Param Count 字段,代表传入的参数

```cpp
XXXXEC03 0008XXXX
```

堆栈情况如下

![Untitled 10.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2010.png)

```cpp
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>

int x,y,z;

// 该函数通过 CALL FAR 调用，使用调用门提权，拥有0环权限
void __declspec(naked) FunctionHas0CPL()
{
	__asm
	{
		pushad
		pushfd

		// pushad 和 pushfd 使ESP减小了 0x24 个字节
		// 原ESP+8就是参数1，+C就是参数2，+10就是参数3，详见堆栈图
		// 如果这里还有疑问，可以在windbg的内存窗口中观察
		mov eax,[esp+0x24+0x8+0x8] // 参数3
		mov dword ptr ds:[x],eax
		mov eax,[esp+0x24+0x8+0x4] // 参数2
		mov dword ptr ds:[y],eax
		mov eax,[esp+0x24+0x8+0x0] // 参数1
		mov dword ptr ds:[z],eax

		popfd
		popad

		retf 0xC
	}
}

int main(int argc, char* argv[])
{
	char buff[6] = {0,0,0,0,0x48,0};
	__asm
	{
		push 0x3
		push 0x2
		push 0x1
		call fword ptr [buff] // 长调用，使用调用门提权
	}
	printf("%x %x %x\n",x,y,z);
	getchar();
	return 0;
}
```

### 中断门

指令 int N

N表示中断门描述符在IDT表中的下标

**中断门描述符**

![Untitled 11.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2011.png)

N表示中断门描述符在IDT表中的下标

不提权时，INT N 会压栈CS，EFLAG EIP；提权时，会依次压栈 SS ESP EFLAG CS EIP。需要用堆栈保存EFLAG是因为中断门会将EFLAG的IF位置0.

堆栈情况

![Untitled 12.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2012.png)

查看代码

```jsx
r idtr
r idtl
```

提权中断门

**CPL=DPL才能成功触发中断**

```jsx
0041 13A0 地址

0041EE00`000813A0
eq 8003f500 0041EE00`000813A0

00418E00`000813A0
eq 8003f500 00418E00`000813A0
```

### 陷阱门

陷阱门和中断门的结构是一样的

32位下，中断门是0xE，陷阱门是0xF

中断门会将IF位置0，而陷阱门不会。IF置0表示不响应可屏蔽中断，IF置1表示响应可屏蔽中断。IF对不可屏蔽中断无影响。键盘输入就是可屏蔽中断，按电源键就是不可屏蔽中断。

```jsx
IF=0 时：程序不再接收可屏蔽中断
可屏蔽中断：比如程序正在运行时，我们通过键盘敲击了锁屏的快捷键，若IF位为1，CPU就能够接收到我们敲击键盘的指令并锁屏
不可屏蔽中断：断电时，电源会向CPU发出一个请求，这个请求叫作不可屏蔽中断，此时不管IF位是否为0，CPU都要去处理这个请求
```

windows不使用陷阱门。

也是用int N触发

### \***\*TSS，TR寄存器，TSS门描述符的关系\*\***

![Untitled 13.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2013.png)

TSS（Task-state segment）是一块104字节的内存，用于存储大部分寄存器的值；

TSS设计出来的目的是任务切换，或者说是一次性替换一大堆寄存器。

![Untitled 14.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2014.png)

CPU如何找到TSS呢？TR段寄存器

TR寄存器存储了TSS的地址，大小，和TSS门描述符选择子；

![Untitled 15.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2015.png)

**TSS描述符是GDT表中的一项，操作系统启动时，从门描述符取值初始化TR寄存器。**

![Untitled 16.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2016.png)

### \***\*LTR STR 指令\*\***

0环指令

```jsx
mov ax,SelectorTSS
ltr ax
```

从GDT表取TSS描述符填充TR寄存器，但并不会修改其他寄存器。

执行指令后，TSS描述符TYPE域低2位会置1.

TYPE = 9，说明该段描述符没有加载到TR寄存器中/TYPE = B，说明该段描述符已经加载到TR寄存器中

STR 指令只会读取 TR 的16位选择子部分，该指令没有特权要求。指令格式如下：

```jsx
str ax
```

### \***\*TSS\*\***

Windows只使用了TSS的SS0和ESP0，用于权限切换。

TSS这个东西是Intel设计出来做任务切换的，windows和linux都没有使用任务，而是自己实现了线程。

构造tss段（注意要构造一个新的栈，运行时才能分配的内存，所以每次运行后才能确定），写入gdt表(eq 8003f048 XX00e9XX` XXXX0068)，call段选择子

### 任务门

IDT表有三个门 任务门，中断门，陷阱门

![Untitled 17.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2017.png)

![Untitled 18.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2018.png)

除了TSS描述符选择子以外， 其他位都是固定的

在 8003f048 处设置TSS描述符

```jsx
放入IDT表中
0000e500` 00480000
放入GDT表中
XX00e9XX` XXXX0068
```

## 页

### windwos分页模式

\***\*WinXP\*\***

默认为2-9-9-12分页，可指定为10-10-12分页方式(将noexecute中的no删除)

\***\*Win7~11\*\***

默认为2-9-9-12分页模式（PAE模式）,可指定为10-10-12分页方式(使用工具EasyBCD快捷修改启动引导属)

区别：

10-10-12的**PTE是32位**，其中低1**2位属性**当做0补到高20位，总共是32位寻址，即4GB物理内存范围

2-9-9-12的**PTE是64位**，其中有36位可用作物理地址寻址，即64GB。

### \***\*CR3寄存器\*\***

CR3是一个寄存器，每个核只有一个。他是唯一一个存储着物理地址的寄存器。这个物理地址指向第一级目录（PDE，共4096字节）

通过拆分虚拟地址后的第一个10, ×4后，可以找到PDE中存储的一个地址（PTE）

通过拆分虚拟地址后的第二个10, ×4后， 可以找到PTE中存储的一个地址（物理页）

通过拆分虚拟地址后的第三个12（偏移）加上物理页首地址，得到真正的物理地址。

注：拆分得到的10为索引，32位下地址宽度4字节，所以需要×4，得到的12为偏移，无需×4

### 10-10-12分页方式

![Untitled 19.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2019.png)

### \***\*2-9-9-12分页（PAE模式-物理地址扩展）\*\***

增大了上一种分页的寻址大小，原理基本上一致

只不过刚开始的时候没想通的是

为什么从10变成的9反而寻址空间还变大了呢？

原来是10变成了9与寻址空间的大小其实与寻址空间大小其实无关，寻址空间的大小其实只与页表的单位数据类型有关，如果是32位能寻到4g的空间如果是33位就能寻到8g空间，只不过随着寻找空间的增加，一个页表内的数量会越来越少，数会越来越小，但是整体数量会增加

![Untitled 20.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2020.png)

![Untitled 21.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2021.png)

![Untitled 22.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2022.png)

![Untitled 23.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2023.png)

![Untitled 24.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2024.png)

### **XD/NX位（DEP数据执行保护）：**

在PAE分页模式下，PDE/PTE的最高位称为XD/NX位。不可执行位，为1时，该段内存不可执行。

就是我们常见的DEP数据执行保护

### 读内存

1.内核中遍历进程,或者ring3传入进程到内核.

2.内核中通过进程Pid找出对应的EPROCES结构 (PsLookupProcessByProcessId)

3.通过EPROCESS结构找到其DirBase的偏移.获取其偏移位置的DirBase的物理地址

4.通过10-10-12分页的模式,拆分传入的你想查看的这个进程的任一虚拟地址.

5.通过上述实际操作的原理,进行自己读取内存.

### \***\*TLB(快表机制)\*\***

读取一个线性地址的数值时，CPU会先读这个线性地址对应的PDE再读PTE再读物理内存。太慢了，CPU内部做了一张表用来存储已读取过得线性地址和物理地址间的映射关系。

![Untitled 25.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2025.png)

LA,PA是线性地址到物理地址的映射，LRU是最近最久未使用的意思，用来控制替换的优先级，当TLB表填满了，就会根据LRU删除优先级低的项，以腾出空间给其他项。ATTR是属性，如果是10-10-12分页，那么就是PDE和PTE的属性逻辑与，如果是2-9-9-12分页，那么就是PDPE,PDE,PTE的属性逻辑与。

进程切换时，CR3改变，TLB就会随之刷新，这是因为相同的线性地址通过不同的CR3会映射到不同的物理地址。

操作系统的高2G映射基本不变，如果Cr3改了，TLB刷新，重建高2G以上很浪费。
所以PDE和PTE中有个G标志位，如果G位为1刷新TLB时将不会刷新 PDE/PTE的
G位为1的页，当TLB满了，根据统计信息将不常用的地址废弃，最近最常用的保留.

### **TLB种类：**

物理页分为普通页（4KB）、大页（2MB/4MB），物理页又分为指令和数据。因此分为4种TLB

### **INVLPG**

INVLPG特权指令可以强制将某个地址从TLB中刷新掉。而不看G位。

1. 为0地址挂PTE，写入数据A，更改0地址的PTE，读0地址，发现还是数据A，证实了TLB存在。
2. 为0地址挂PTE，写入数据A，更改0地址的PTE，切换CR3（mov eax,cr3 mov cr3,eax），读0地址，发现变成了数据B，证实了TLB的刷新。
3. 为0地址挂一个G位为1的PTE，写入数据A，更改0地址的PTE，切换CR3（mov eax,cr3 mov cr3,eax），读0地址，发现还是数据A，证实了全局页存在。
4. 为0地址挂一个G位为1的PTE，写入数据A，更改0地址的PTE，切换CR3（mov eax,cr3 mov cr3,eax），INVLPG强制刷新TLB中的数据（INVLPG dword ptr ds:[0]），读0地址，发现变成了数据B，证实了INVLPG指令的作用。

### 利用TLB机制实现内存隐藏的方式

在进行crc校验代码完整性的时候，由于存在两种TLB机制分别为TLB的数据页表缓存和TLB的指令页表缓存，在执行的时候用的是指令页的缓存，在校验的时候用的是数据页缓存，但是又是同一段物理地址，所以我们可以替换其中一个来绕过校验。

这种方式在3环是不稳定的，原因是TLB经常刷新。

### \***\*中断与异常\*\***

\***\*中断概念\*\***

中断分为可屏蔽中断（INTR）和不可屏蔽中断（NMI），中断本质就是改变了CPU执行路线

X86 CPU有两条中断线，分别是： 可屏蔽中断线（NMI） 不可屏蔽中断线（INTR）， 中断描述符表（IDT） 中索引为2的门为不可屏蔽中断处理程序。

当可屏蔽中断请求发生时，CPU会观察EFLAG寄存器中的IF位来决定要不要处理这条中断请求。为1处理，0不处理。

**X86架构下常见的异常处理程序编号**

页错误走E号门， 段错误走D号门 ，除0错误走0号门， 双重错误走8号门

**中断流程**

![Untitled 26.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2026.png)

### \***\*控制寄存器\*\***

CR**0寄存器**

![Untitled 27.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2027.png)

PE：置0表示实地址模式；置1表示保护模式。

PG：置0表示不开启分页机制；置1表示开启分页机制。

WP：置0表示R0代码可以读写任意用户级物理页；置1表示R0可以读取任意用户级物理页，但对于只读的物理页则不能写。

\***\*CR1寄存器\*\***

保留，不使用

\***\*CR2寄存器\*\***

![Untitled 28.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2028.png)

当CPU访问某个无效页面时，会产生缺页异常，此时，CPU会将引起异常

的线性地址存放在CR2中。

\***\*CR3寄存器（PDBR）\*\***

存储进程页目录。

\***\*CR4寄存器\*\***

![Untitled 29.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%2029.png)

PAE：置0表示10-10-12分页；置1表示2-9-9-12分页。

PSE：PS位的总开关，置1时启用PS位，置0时不启用PS位（所有页都是4KB小页）

## 小结

算是简单的完成了对windowsXP保护模式的学习，参考了很多前辈们的博客。本来是打算看海哥的视频来学习的，但是前辈们的博客写的太详细了，直接看博客就可以搞懂啦

下面是参考博客：

[https://bbs.kanxue.com/thread-267944.htm#0.cpu指令预读取](https://bbs.kanxue.com/thread-267944.htm#0.cpu%E6%8C%87%E4%BB%A4%E9%A2%84%E8%AF%BB%E5%8F%96)

[https://blog.csdn.net/kwansy/category_10411796_2.html](https://blog.csdn.net/kwansy/category_10411796_2.html)

[https://jev0n.com/2021/03/26/106.html](https://jev0n.com/2021/03/26/106.html)

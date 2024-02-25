---
author: s0rry
pubDatetime: 2022-10-01T09:15:00Z
modDatetime: 2022-10-01T19:23:00Z
title: PLT表和GOT表
slug: PLT-GOT
featured: false
draft: false
tags:
  - Linux
description: PLT表和GOT表
---

# PLT表和GOT表

## GOT表

**概念：**每一个**外部定义的符号**在全局偏移表（_Global offset Table_）中有相应的条目，GOT位于ELF的**数据段**中，叫做GOT段。

**作用：**把位置无关的地址计算重定位到一个绝对地址。程序首次调用某个库函数时，运行时连接编辑器（rtld）找到相应的符号，并将它重定位到GOT之后每次调用这个函数都会将控制权直接转向那个位置，而不再调用rtld

## PLT表

**过程连接表**(_Procedure Linkage Table_)，**一个PLT条目对应一个GOT条目**

用于调用GOT中的数据

**PLT不是数据，是一段可执行的代码，处于代码段**

## 详细过程

下面通过这个简单的测试程序就能了解

![Untitled.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled.png)

这是这个程序的整段汇编，在每个调用函数下断，单步进入

![Untitled 1.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%201.png)

来到plt内部，这是理解整个过程的关键部分，第一个jmp是jmp got表中存的printf在内存中的地址

如果还没执行过printf，则此时改位置存的是当前这个plt表的下一条指令的位置，也就是push 0的位置

翻译一下下面的汇编就是：

```python
jmp [got:printf] // got表中存的printf在内存中的地址，但是是第一次执行时got表中该位置存的为push 0的位置
push 0 // 我觉得就是got表项中printf的函数的位次（请原谅我这么叫它）
jmp plt:[0] // plt这个段代码的头部
```

![Untitled 2.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%202.png)

这是第一次执行printf，所以继续向下执行，进入这个函数，从名字可以看出这个函数名为\_dl_runtime_resolve_xsave，而这个函数根据前一条指令，push的值来找到对应的共享库特征值（按windows的来说就是dll，与windows相似这些共享链接库是以链表的形式储存在内存中的）

翻译一下就是：

```python
plt:[0]:
			push got:[1] // 共享库的特征值
			jmp got:[2] // _dl_runtime_resolve_xsave函数的位置
```

![Untitled 3.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%203.png)

### \_dl_runtime_resolve_xsave函数的作用：

这里就拿printf来举例子，用于在内存中寻找printf的位置并把它填会got表的那个位置上，当下一次再调用时，就会在进入glt表的第一个jmp代码的位置，直接跳到printf的实际代码位置

## 问题总结

### **同一个\_dl_runtime_resolve_xsave函数为什么能确定是printf函数呢？**

很明显，一个传了两个参数给\_dl_runtime_resolve_xsave，第二个push got:[0]用于确定链接库，那第一个push 0就是用于确定是调用的printf函数的

**那么这个参数0是怎么来的呢？**

我觉得是在程序编译时确定的，更加详细的部分，我还不太了解，我只能根据下面这个图片来推测

![Untitled 4.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%204.png)

当\_dl_runtime_resolve_xsave收到0的参数的时候，会从got表上找到储存printf的位置的表项，从而根据相关信息得出需要找的是printf函数，然后把printf的地址填到这个地方。

## **为什么会有plt和got表呢？**

应为程序运行的时候，操作系统是不能改变代码段的数据的，要实现运行时重定位就要运行时才确定相关函数的位置，这个变换的数据只能由代码段转换到数据段，从而有了plt表和got表。

## 整个过程可以总结成下面的图

第一次调用

![Untitled 5.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%205.png)

第二次调用

![Untitled 6.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/Untitled%206.png)

参考博客

[深入理解GOT表和PLT表 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/130271689)

[(3条消息) 一篇文章，搞懂 GOT表 & PLT表\_Code Segment的博客-CSDN博客\_got表](https://blog.csdn.net/qq_43547885/article/details/108703430)

[[原创] ELF文件结构详解-Android安全-看雪论坛-安全社区|安全招聘|bbs.pediy.com](https://bbs.pediy.com/thread-255670.htm)

[[分享]Pwn 基础：PLT&GOT 表以及延迟绑定机制（笔记）-Pwn-看雪论坛-安全社区|安全招聘|bbs.pediy.com](https://bbs.pediy.com/thread-257545.htm)

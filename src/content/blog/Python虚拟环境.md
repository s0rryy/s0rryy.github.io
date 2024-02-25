---
author: s0rry
pubDatetime: 2022-03-30T18:06:20Z
modDatetime: 2022-04-01T12:24:00Z
title: Python虚拟环境
slug: Python-viev
featured: false
draft: false
tags:
  - Python
description: Python虚拟环境，解决依赖冲突问题
---

## 背景

Python库十分丰富，但很多时候不同的 Python 库所依赖的版本是冲突的，所以得找到一个能适应所有 Python 应用的软件环境，解决这一问题的方法是 python虚拟环境。

虚拟环境是一个包含了特定 Python 解析器以及一些软件包的自包含目录，不同的应用程序可以使用不同的虚拟环境，从而解决了依赖冲突问题。

## 构建虚拟环境

### 原理

利用了操作系统中环境变量以及进程间环境隔离的特性，也就是说进程可以单独创建该进程需要的环境，不影响操作系统的环境变量。

### 创建

#### python3.3之前

只能通过virtualenv 创建虚拟环境

```
pip install virtualenv #安装virtualenv
virtualenv --no-site-packages myvenv #创建一个名字为myvenv的虚拟环境
```

其中--no-site-packages意思是创建一个没有第三方包的虚拟环境

相关其他指令

-p: 用于指定 Python 解析器，就是安装好的 Python 应用程序，默认为当前环境中的 Python

--no-pip：不需要安装 pip，默认为安装

--clear：如果创建虚拟环境的目录已经有了其他虚拟环境，清楚重建

---

#### python3.3之后

python自带创建虚拟环境的功能 venv

```
python -m venv myvenv #创建一个名字为myvenv的虚拟环境
```

其他指令

--without-pip: 不需要安装 pip，默认为安装

--clear：如果创建虚拟环境的目录已经有了其他虚拟环境，清楚重建

### 激活

激活可以看作把当前命令行的PATH替换掉

上述的两种创建方法的激活方式是相同的（其实就是运行创建的环境中的一个文件夹下的一个脚本）

```
myvenv/Scripts/Activate.ps1 #windows powershell
myvenv/Scripts/activate.bat	#windows cmd  注意第一个路径名是创建的环境名
source myvenv/bin/activate  #linux 默认脚本没有执行权限，可以设置脚本为可执行，或者用 source 命令执行
```

使用这个指令成功后如图

![image-20220324141813731](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202203301819378.png)

### 查看虚拟环境

```
echo $PATH    #linux
echo %PATH%    #windows
```

![image-20220324142016350](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202203301819759.png)

### 退出

退出虚拟环境很简单，只需要执行 `deactivate` 命令就行，这个命令也在虚拟环境的脚本目录下，因为激活时，将脚本目录设置到 PATH 中了，所以可以直接使用

### 平时使用

在使用的时候每次只需要重复上面激活的步骤即可，而且只需要把它当做正常的python来用即可

### 与vscode结合

vscode作为我平时写脚本的利器，当然要与虚拟环境结合起来才能更加的方便

![image-20220324144553390](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202203301819695.png)

点击这个就可以快捷的切换python环境，当列表中没有我们想要的python环境时，我们只需要添加一个即可（选择即已经创建好的虚拟Scripts文件夹中的 Python 程序，就可以创建一个新的解析器）

![image-20220324143433163](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202203301819715.png)

### 总结

有了这个虚拟环境终于可以让自己的强迫症得到满足，避免了乱糟糟的python包，舒服多了。

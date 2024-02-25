---
author: s0rry
pubDatetime: 2023-01-10T04:35:00Z
modDatetime: 2023-01-11T12:44:00Z
title: Pixel2 AOSP10编译并安装以及各个镜像的相关作用
slug: Pixel2-AOSP10
featured: false
draft: false
tags:
  - Android
description: Pixel2 AOSP10编译并安装以及各个镜像的相关作用
---

老早之前就打算尝试编译这源码了来着，前前后后尝试了几次都没成功。之前尝试都是在学校，没办法一直守在电脑前面，导致编译的时候断断续续的，报了几次错之后编译出来的产品刷上开不了机，就找不到错误的原因是什么了。重新再编译太浪费时间了，就没太敢尝试了。

现在在家，时间挺多的。准备把之前挖的坑填完，所以准备再尝试一下。

原则上按照我下面的步骤进行编译是一定会成功的。

然后再介绍一下编译好的各个镜像的作用，便于了解我们修改的源码到底属于哪一个镜像。

## 环境

**ubuntu 20.4**

内存12G，交换空间16G， 磁盘300G， CPU数量越多越好

### 为啥用ubuntu20呢

之前我用ubuntu22编译另一个手机的内核的时候，由于gcc版本太高了，就一直报错。

所以尽量保持gcc在9左右的版本比较好，这个有点玄（。

### 内存12G，交换空间16G

交换空间4G以上基本上就ok，内存12G以上。这个很关键好吧，之前编译一半停下来，多半都是这个问题，因为这个报错停下来可以减少线程数量，继续make的，但是如果想流程的一次跑完的话，就可以这么配置完就去睡觉啦。

交换空间的设置方法如下

```jsx
dd if=/dev/zero of=/SWAPfile bs=1M count=16384
chmod 0600 /SWAPfile
mkswap /SWAPfile
```

这个SWAPfile的名字可以顺便取

dd 复制

1M \* 16384 = 16G的空间

给启动文件配置一下

```jsx
vim / etc / fstab;
```

添加一行

```jsx
/SWAPfile          swap       swap     defaults       0       0
```

挂载

```jsx
swapon / SWAPfile;
```

查看

```jsx
free - h;
```

### 安装依赖

```jsx
sudo apt-get update
sudo apt install -y openjdk-8-jdk
```

```jsx
sudo apt-get install git-core gnupg flex bison build-essential zip curl zlib1g-dev gcc-multilib g++-multilib libc6-dev-i386 libncurses5 lib32ncurses5-dev x11proto-core-dev libx11-dev lib32z1-dev libgl1-mesa-dev libxml2-utils xsltproc unzip fontconfig
```

## 源码下载

### repo 工具下载

repo是什么呢，其实就是git，由于安卓源码太大了git仓库比较多，所以谷歌用repo来统一管理。

但是谷歌的服务在国外，就得换源

国内有两家源库选择第一个是中科大的源，还有一个是清华的源。两个我都用过，第一次用的清华源，最后一次用的中科大的源。相比较而言中科大的源更快，而且清华源的证书还过期了，有点麻烦。

中科大源

[https://lug.ustc.edu.cn/wiki/mirrors/help/aosp/](https://lug.ustc.edu.cn/wiki/mirrors/help/aosp/)

### 下载repo命令

```jsx
mkdir ~/bin
PATH=~/bin:$PATH
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo
```

如果之后要用repo这个命令的话，可以把PATH="${HOME}/bin:${PATH}”添加到环境变量~/.bashrc

这里只用一次下载就不添加了，直接PATH=~/bin:$PATH

### 下载源码

先创建一个文件夹

```jsx
mkdir aosp && cd aosp
```

选择一个版本

[https://source.android.com/setup/start/build-numbers#source-code-tags-and-builds](https://source.android.com/setup/start/build-numbers#source-code-tags-and-builds)

```jsx
export REPO_URL='https://mirrors.ustc.edu.cn/aosp/git-repo.git/'
repo init -u git://mirrors.ustc.edu.cn/aosp/platform/manifest -b android-10.0.0_r2
repo sync -j4
```

线程不要超过4就行

### 下载相关驱动包

注意：

这一步很关键，关系到编译后的镜像能否刷入后运行

下载链接：[https://developers.google.com/android/drivers](https://developers.google.com/android/drivers)

下载解压后会有两个脚本文件，运行后输入I ACCEPT就会得到一个ventor文件夹的文件夹

然后直接将它拷贝到aosp目录下，也就是下载的源码的目录下

## AOSP 源码编译

首先加载配置文件，然后选择机型

```jsx
source build/envsetup.sh
lunch aosp_walleye-userdebug
```

这里直接输入lunch就能看到可以编译的全部机型，然后选择对应的机型就行

然后就直接

```jsx
make - j6;
```

如果期间有什么报错可以百度，修复后，直接make -j6继续运行就行。

可以去睡觉啦，起来就会看到已经编译好镜像了。

## 刷入镜像

没错，刷入镜像的时候还有坑。

这里推荐刷入镜像的时候，去官网下载一个相同版本的线刷包，先用官方的线刷包先重新刷一下系统再刷自己编译好的系统

线刷包下载地址：[https://developers.google.com/android/images](https://developers.google.com/android/images)

为什么要刷一遍线刷包呢，因为线刷包里有我们编译好的镜像里没有的东西，之前往源码里面添加的驱动文件跟这个有关

### 刷入的命令

就在之前编译的那个窗口就能运行

不过linux运行adb要添加设备信息，没有就会报错，如果报错了就自行百度吧

```jsx
adb reboot bootloader
fastboot flashall -w
```

### 至此

完全编译安卓源码的过程就结束了，如何后面要对安卓源码的部分进行修改，然后重新编译刷入就不再需要怎么麻烦的操作了。

## 安卓刷入部分镜像

### 编译后各个镜像的功能介绍

**ramdisk.img**

ramdisk 为内存文件系统，是一个最小型文件系统， 在内核启动的时候会将其作为根文件系统进行挂，文件实际为 gzip 文件，可以直接解压

**boot.img**

boot.img 包含内 Linux 内核镜像 zImage 和根文件系统 ramdisk 文件,

镜像基本构成为：头部，内核，ramdisk 镜像

**dtbo.img**

dtb overlay, 叠加 DT。由原始设计制造商 (ODM)/原始设备制造商 (OEM) 提供的设备专用配置

**system.img**

system 镜像会提供 android 所需要的命令，内置 app，运行动态库，以及系统配置文件， 在system-as-root特性中， system 镜像会被直接挂载成根目录下。

**vendor.img/odm.img/oem.img/product.img**

包含有厂商私有的可执行程序、库、系统服务和 app 等。可以将此分区看做是 system 分区的补充，厂商定制 ROM 的一些功能都可以放在此分区，odm 是贴牌厂商定制镜像， oem 是代工厂商定制镜像，

**super.img**

自 Android Q(10.0)以后，系统支持动态分区（dynamic partition），它将多个系统只读分区（包括 system、product、vendor、odm 或者其他厂商自定义分区）合并为一个 super 分区。物理分区只有 super 分区的概念，而没有 system等分区

**userdata.img**

用户存储空间。一般新买来的手机此分区几乎是空的，用户安装的 app 以及用户数据都是存放在此分区中。用户通过系统文件管理器访问到的手机存储（sdcard）即此分区的一部分，是通过 fuse 或 sdcardfs 这类用户态文件系统实现的一块特殊存储空间。

**vbmeta.img**

验证启动（Verified Boot）是 Android 4.4 开始引入的一个新的安全功能，作用是在系统启动时校验分区是否被篡改或者发生过改动，比如用户使用 root 软件强行植入 su 文件，但最后删除了 su， 这种情况也能检测出来。一旦检验不过，系统就不能正常启动，并且有相关的图文提示， 简单描述做法就是在启动过程中增加一条校验链，即 ROM code 校验 BootLoader，确保 BootLoader 的合法性和完整性，BootLoader 则需要校验 bootimage，确保 Kernel 启动所需 image 的合法性和完整性，而 Kernel 则负责校验 System 分区和 vendor 分区。

**recovery.img**

recovery 分区的镜像，一般用作系统恢复和升级，在 A/B 设备中，升级就不放在 recovery 中了。包含 recovery系统的 kernel 和 ramdisk。如果 bootloader 选择启动 recovery 模式，则会引导启动此分区的 kernel 并加载 ramdisk，并启动其中的 init 继而启动 recovery 程序，至此可以操作 recovery 模式功能（主要包括 OTA 升级、双清等）。boot.img 中 ramdisk 里 的 init.rc 位 于system/core/init/init.rc, 而 recovery.img 中 ramdisk 里 的 init.rc 位 于bootable/recovery/etc/init.rc

**cache.img**

主要用于缓存系统升级 OTA 包等。双清就是指对 userdata 分区和 cache 分区的清理。在 A/B 设备中，OTA 包就不需要存储在此。

### 刷入部分镜像

由于常常修改的都是System镜像部分内容，但是编译出来的System有两个部分system.img和system_other.img使用这里就讲一讲System一个如何单独刷入进去。

于Android8之后采用A/B更新, 所以有2套分区, 刷分区方式和以往不同:

```jsx
tboot flash system system.img
fastboot flash system_a system_other.img
fastboot set_active b
fastboot reboot
```

## 总结

编译这系统可以说是处处碰壁了，这一套了解下来，谷歌已经在编译的时候让编译变得十分的简单了，所以整个部分比较麻烦的就是相关环境的准备了。看网上的各个文章都是只介绍其中的一部分，一知半解的，现在终于透彻了。

### 相关链接

[https://blog.shi1011.cn/rev/android/2284](https://blog.shi1011.cn/rev/android/2284)

[https://blog.csdn.net/weixin_39904116/article/details/110663839](https://blog.csdn.net/weixin_39904116/article/details/110663839)

[https://wertherzhang.com/android8-partiton-table/](https://wertherzhang.com/android8-partiton-table/)

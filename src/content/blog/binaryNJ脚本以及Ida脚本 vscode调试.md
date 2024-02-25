---
author: s0rry
pubDatetime: 2023-06-29T22:11:00Z
modDatetime: 2023-06-29T22:11:00Z
title: binaryNJ脚本以及Ida脚本 vscode调试
slug: binaryNJ-Sctrpt-Debug
featured: false
draft: false
tags:
  - reverse
description: binaryNJ脚本以及Ida脚本 vscode调试
---

## 安装环境

ctrl + p
打开设置 安装python模块 debugpy
![image.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/20240226032251.png)

直接用文件夹中给的python安装好之后，nj是无法检测到这个包的

## vscode安装代码补全环境

进入scripts文件夹
运行python install_api.py
将会安装代码环境到自带的python中
![image.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/20240226032329.png)
![image.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/20240226032343.png)

## vscode配置环境

打开调试按钮
![image.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/20240226032350.png)

添加一个Python的远程调试选项，这里我已经添加好了
在配置文件中进行如下配置
![image.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/20240226032401.png)

## 对NJ的调试脚本进行的修改

在调试的时候可能重复调试一个脚本多次，但是在它源码中写的方式的话，每次调试都得重启NJ，比较麻烦
下面来解释一下，这是原本的源码，红框部分是我新加的
当在调试的时候，安装原来的方式 尝试创建一个监听端口，但是如果这个监听端口在之前就已创建过了，那么再次创建程序就会终止，所以就不得不重启NJ，关闭创建的监听端口
要解决这个办法只需要加段代码如图，判断是否已经创建这端口，如果已经创建那么就直接跳过这一步
![image.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/20240226032408.png)

```python
# add start
import socket
def is_debugpy_listening(port):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind(('localhost', port))
		sock.close()
		return False
	except socket.error:
		return True
# add end

def connect_vscode_debugger(port=5678):
	"""
	Connect to Visual Studio Code for debugging. This function blocks until the debugger
	is connected! Not recommended for use in startup.py

	.. note:: See https://docs.binary.ninja/dev/plugins.html#remote-debugging-with-vscode for step-by-step instructions on how to set up Python debugging.

	:param port: Port number for connecting to the debugger.
	"""
	# pip install --user debugpy
	import debugpy  # type: ignore
	import sys
	if sys.platform == "win32":
		debugpy.configure(python=f"{sys.base_exec_prefix}/python", qt="pyside2")
	else:
		debugpy.configure(python=f"{sys.base_exec_prefix}/bin/python3", qt="pyside2")
	if not is_debugpy_listening(port):
		debugpy.listen(("127.0.0.1", port))
	debugpy.wait_for_client()
	execute_on_main_thread(lambda: debugpy.debug_this_thread())
	return debugpy
```

## 食用方法

在需要调试的脚本中加入一行代码
connect_vscode_debugger(port=5678)
在需要下断的地方添加
debugpy.breakpoint()
如下

```python
from binaryninja import *
debugpy = connect_vscode_debugger(port=5678)

print("hello")

debugpy.breakpoint()
print("success")
```

在NJ中运行该脚本文件，程序会被卡住
![image.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/20240226032420.png)

直接点击左侧的启动按钮
![image.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/20240226032424.png)

下断成功
![image.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/20240226032428.png)

## 拓展食用 - 调试Ida脚本

用到的函数与上面类似

```python
import debugpy
import socket
import sys
def is_debugpy_listening(port):

	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind(('localhost', port))
		sock.close()
		return False
	except socket.error:
		return True

def connect_vscode_debugger(port=5678):

	# pip install --user debugpy

	if sys.platform == "win32":
		debugpy.configure(python=f"{sys.base_exec_prefix}/python", qt="pyside2")
	else:
		debugpy.configure(python=f"{sys.base_exec_prefix}/bin/python3", qt="pyside2")

	if not is_debugpy_listening(port):
		debugpy.listen(("127.0.0.1", port))
	debugpy.wait_for_client()
```

使用方式也类似

```python
connect_vscode_debugger() # 程序代码首行添加
debugpy.breakpoint() # 在需要下断的地方添加
```

如下 需要调试的是print("success")开始的代码就在print("success")之前添加断点

```
import debugpy
import socket
import sys
def is_debugpy_listening(port):

	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind(('localhost', port))
		sock.close()
		return False
	except socket.error:
		return True

def connect_vscode_debugger(port=5678):

	# pip install --user debugpy

	if sys.platform == "win32":
		debugpy.configure(python=f"{sys.base_exec_prefix}/python", qt="pyside2")
	else:
		debugpy.configure(python=f"{sys.base_exec_prefix}/bin/python3", qt="pyside2")

	if not is_debugpy_listening(port):
		debugpy.listen(("127.0.0.1", port))
	debugpy.wait_for_client()


connect_vscode_debugger()

print("12312312312")

debugpy.breakpoint()

print("success")


```

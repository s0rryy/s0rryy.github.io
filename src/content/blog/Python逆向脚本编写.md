---
author: s0rry
pubDatetime: 2022-09-26T04:48:00Z
modDatetime: 2022-09-26T14:32:00Z
title: Python逆向脚本编写
slug: Python-Reverse-Script
featured: false
draft: false
tags:
  - Python
description: Python逆向脚本编写
---

# python逆向脚本编写

最近经常遇见混淆，需要写脚本来去，写的过程中发现总是忘这忘那的，要现搜才能抠出脚本来，比较低效，所以对这些常常的短路的点做了简单集中的记录，便于用到的时候查找，可能有有些地方写的比较简单，如果有看不懂的地方，可以去最后给的链接中查看详细的介绍。另外这篇文章会一直更新一些比较完整的python脚本。

# python的数据处理

在逆向中，由于python的弱数据类型，在调库时带来了许多不便，这里我规定自己一直用byte类型来作为使用时主要的类型，其他类型则通过byte类型来转换，下面介绍相关的转换方法

string是Unicode，由str类型表示，二进制数据则由bytes类型表示。

- byte→string

```jsx
b = b"asdfg\n"
str = str(b,encoding = "utf-8")
```

- string→byte

```jsx
str = "s0rry";
b = bytes(str, (encoding = "utf-8"));
```

- byte→hex的str类型

```jsx
b = b"s0rry"
h = b.hex()
# h: <class 'str'> '73616461736471'
```

- hex的str类型→byte

```jsx
h = "73616461736471"
bb = bytes.fromhex(h)
# bb: <class 'bytes'> b'sadasdq'
```

- 长整型→byte

```python
#方法一
i = 6788912312
str = "%020x" % i
he = hex(i)
b = bytes.fromhex(str)
print(b)

# 方法二
i = 6788912312
b = i.to_bytes(len(str(i))//2+1,byteorder="big")
print(b)
```

- byte→长整型

```jsx
ii = int.from_bytes(b, (byteorder = "big"));
print(ii);
```

- list→byte

```python
l = [1,2,3,4,5,5,6]
b = bytes(l)
```

- list（list中有str）→byte

```python
l = ['1', 'C', 'E', 'B', 'E', '0', '8', '9', '7', '4', 'A', '9', '6', '1', 'C', '5']
# 先转str再转byte
b = bytes("".join(cArr2[0:24]),encoding="utf-8")
```

- byte→list

```python
b =  b'\x01\x03-\x06'
ll = list(b)
```

# idc脚本编写

## 读取数据api

`idc.get_wide_byte(addr)`，从addr处读取一个字节值

`idc.get_wide_word(addr)`，从addr处读取一个字（2字节）值

`idc.get_wide_dword(addr)`，从addr处读取一个双字（4字节）值

`idc.get_qword(addr)`，从addr处读取一个四字（8字节）值

`ida_bytes.patch_byte(addr,byte)`，设置addr处的一个字节值

`ida_bytes.patch_word(addr,word)`，设置addr处的一个字值

`ida_bytes.patch_dword(addr,dword)`，设置addr处的一个双字值

`ida_bytes.patch_qword(addr,qword)`，设置addr处的一个四字值

`ida_bytes.is_loaded(addr)`，如果addr包含有效数据，则返回1，否则返回0

## 与当前光标交互

`idc.here() 或 idc.get_screen_ea()`，取当前地址

`ida_ida.inf_get_min_ea()`，获取最小地址（可以使用的）（基址）

`ida_ida.inf_get_max_ea()`，获取最大地址（可以使用的）

`idc.read_selection_start()`，获取所选范围的起始地址

`idc.read_selection_end()`，获取光标所选范围的结束地址

## \***\*反汇编行组件\*\***

`idc.GetDisasm(addr) 或 idc.generate_disasm_line(addr,flags)`，返回地址处的汇编，flag填个0就

行

`idc.print_insn_mnem(ea)`，获取汇编操作指令（如mov、add）

`idc.print_operand(ea,index)`，返回反汇编窗口中目标地址的操作数的`文本形式`（汇编指令的形

式），index为操作数编号从0开始。

`idc.get_operand_type(ea,index)`，返回一个整数，指出给定地址的给定操作数的类型

`idc.get_operand_value(ea,index)`，获取指定索引操作数中的值: 如 calll 0x00402004 对应汇编为: FF

15 04 20 40 00 其中FF15=Call 而操作数的值则为04 20 40 00 (小端) 使用函数之后获取则为地址00402004

`idc.next_head(addr)`，获取下一行汇编地址

`idc.prev_head(addr)`，获取上一行汇编地址

```jsx
import idc

basic_addr = ida_ida.inf_get_min_ea()
print("函数基址："+hex(basic_addr))
addr = 0x0403F0D
cur_asm = idc.GetDisasm(addr)
print(type(cur_asm)," ",cur_asm)
next_asm = idc.GetDisasm(idc.next_head(addr))
print(type(next_asm)," ",next_asm)
prev_asm = idc.GetDisasm(idc.prev_head(addr))
print(type(prev_asm)," ",prev_asm)
cur_hex_asm = idc.get_operand_value(addr,1)
print(type(cur_hex_asm)," ",hex(cur_hex_asm))
```

![image-1664192736552](/upload/2022/09/image-1664192736552.png)

## \***\*段操作\*\***

`idc.get_segm_name(addr)`，获取段的名字（参数为当前的地址）

`idc.get_segm_start(addr)`，获取段的开始地址

`idc.get_segm_end(addr)`，获取段的结束地址

`idc.get_first_seg(addr)`，获取第一个段

`idc.get_next_seg(addr)`，获取下一个段

`idautils.Segments()`，返回一个列表记录所有段的地址

```jsx
import idc
import idaapi
import idautils

basic_addr = ida_ida.inf_get_min_ea()
print("函数基址："+hex(basic_addr),"-----------------------------------------------")
for seg_addr in idautils.Segments():
    segname = idc.get_segm_name(seg_addr)
    segstart = idc.get_segm_start(seg_addr)
    segend   = idc.get_segm_end(seg_addr)
    print("段名：" + segname + "  起始地址：" + hex(segstart) + "  结束地址：" + hex(segend))
```

![image-1664192753066](/upload/2022/09/image-1664192753066.png)

## \***\*函数操作\*\***

`idautils.Functions(startaddr,endaddr)`，获取指定地址之间的所有函数，如果不给参数就是返回所有的函数地址

`idc.get_func_name(addr)`，获取指定地址的函数名

`get_func_cmt(addr, repeatable)` ，repeatable:0/1 0是获取常规注释 1是获取重复注释，获取函数的注释

`idc.set_func_cmt(ea, cmt, repeatable)`，设置函数注释

`idc.choose_func(title)`，弹出框框要求用户进行选择 参数则是信息

`idc.get_func_off_str(addr)`，返回: addr 距离函数的偏移形式

`idc.find_func_end(addr)`，寻找函数结尾,如果函数存在则返回结尾地址,否则返回BADADDR

`ida_funcs.set_func_end(ea, newend)`，newend:新的结束地址，设置函数结尾

`ida_funcs.set_func_start(addr, newstart)`，设置函数开头

`idc.set_name(ea, name, SN_CHECK)`，Ex函数也使用set_name,设置地址处的名字

`idc.get_prev_func(ea)`，获取首个函数

`idc.get_next_func(ea)`，获取下一个函数

`idc.get_name_ea_simple(fun_name)`，返回函数的线性地址（不明白这个是干啥的）

```jsx
import idc
import idaapi
import idautils

basic_addr = ida_ida.inf_get_min_ea()
print("函数基址："+hex(basic_addr),"-----------------------------------------------")
for func_addr in idautils.Functions():
    print("函数首地址："+hex(func_addr)+" 函数名字："+idc.get_func_name(func_addr) )
```

![image-1664192768954](/upload/2022/09/image-1664192768954.png)

## \***\*数据查询\*\***

`idc.find_binary(ea, flag, searchstr, radix=16, from_bc695=False)`，查找二进制找到返回地址没找到返回-1(BADADDR) 用来去花指令比较好用

```jsx
idc.find_binary(ea, SEARCH_DOWN, "C4 00 C4");
```

`ida_search.find_data(ea, sflag)`，从ea开始寻找下一个数据地址

`ida_search.find_code(ea, sflag)`，从ea开始寻找下一个代码地址

`ida_kernwin.jumpto(ea)`，跳转到ea位置

flags取值：

```
SEARCH_DOWN 向下搜索
SEARCH_UP 向上搜索
SEARCH_NEXT 获取下一个找到的对象。
SEARCH_CASE 指定大小写敏感度
SEARCH_UNICODE 搜索 Unicode 字符串。
```

参考链接

[IDA Python 常用API（持续更新） | HotSpurzzZ](https://hotspurzzz.github.io/2021/11/17/IDA%20Python%20%E5%B8%B8%E7%94%A8API%EF%BC%88%E6%8C%81%E7%BB%AD%E6%9B%B4%E6%96%B0%EF%BC%89/)

[Porting from IDAPython 6.x-7.3, to 7.4 (hex-rays.com)](https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml)

# python正则表达式

原始字符串表示法:

`r"\n"`表示包含 `'\'`和 `'n'`两个字符的字符串，而 `"\n"`则表示只包含一个换行符的字符串。

## re模块有12个函数

### flag参数

re模块中的函数可能含有flag参数，flag参数的作用是通用的

`re.I` 使匹配对大小写不敏感
`re.L` 做本地化识别（locale-aware）匹配
`re.M` 多行匹配，影响 ^ 和 $
`re.S` 使 . 匹配包括换行在内的所有字符
`re.U` 根据Unicode字符集解析字符。这个标志影响 \w, \W, \b, \B.
`re.X` 该标志通过给予你更灵活的格式以便你将正则表达式写得更易于理解。

### 1.查找一个匹配项

- **`search`：** 查找任意位置的匹配项

`re.match(pattern, string, flags=0)`

- **`match`：** 必须从字符串开头匹配
- **`fullmatch`：** 整个字符串与正则完全匹配

**查找 一个匹配项 返回的都是一个匹配对象（Match）**

### 2.查找多个匹配项

- **`findall`：** 从字符串任意位置查找，**返回一个列表**
- **`finditer`**：从字符串任意位置查找，**返回一个迭代器**

列表是一次性生成在内存中，而迭代器是需要使用时一点一点生成出来的，内存使用更优。

如果可能存在大量的匹配项的话，建议使用**finditer函数**

### 3.分割

- **`re.split(pattern, string, maxsplit=0, flags=0)`**函数：

用 **pattern**分开 string ， **maxsplit**表示最多进行分割次数， **flags**表示模式，就是上面我们讲解的常量！

`str.split`函数功能简单，不支持正则分割，而`re.split`支持正则

### 4.替换

替换主要有**sub函数**与 **subn函数:**

- **`re.sub(pattern, repl, string, count=0, flags=0)`**函数参数讲解：

repl替换掉string中被pattern匹配的字符， count表示最大替换次数，flags表示正则表达式的常量。

- **`re.subn(pattern, repl, string, count=0, flags=0)`**函数与**`re.sub`函数**功能一致，只不过返回一个元组 (字符串, 替换次数)。

### 5.编译正则对象

- **`compile`函数**与 **`template`函数**将正则表达式的样式编译为一个 正则表达式对象 （正则对象Pattern），这个对象与re模块有同样的正则函数

### 6.其他

- **`re.escape(pattern)`**
  可以转义正则表达式中具有特殊含义的字符，比如：`.`或者 `*`
- **`re.purge()`**函数作用就是清除 **正则表达式缓存**

## 正则符号

\***\*正则表达式一般趋向于最大长度匹配，就是贪婪模式。\*\***

\***\*匹配到结果就好，就少的匹配字符，就是非贪婪模式。\*\***

`^` 匹配字符串的开头
`$` 匹配字符串的末尾。
`.` 匹配任意字符，除了换行符，当re.DOTALL标记被指定时，则可以匹配包括换行符的任意字符。
`[...]` 用来表示一组字符,单独列出：[amk] 匹配 'a'，'m'或'k'
`[^...]` 不在[]中的字符：[^abc] 匹配除了a,b,c之外的字符。
`re*` 匹配0个或多个的表达式。
`re+` 匹配1个或多个的表达式。
`re?` 匹配0个或1个由前面的正则表达式定义的片段，**非贪婪方式**
`re{ n}` 精确匹配 n 个前面表达式。例如， o{2} 不能匹配 "Bob" 中的 "o"，但是能匹配 "food" 中的两个 o。
`re{ n,}` 匹配 n 个前面表达式。例如， o{2,} 不能匹配"Bob"中的"o"，但能匹配 "foooood"中的所有 o。"o{1,}" 等价于 "o+"。"o{0,}" 则等价于 "o\*"。
`re{ n, m}` 匹配 n 到 m 次由前面的正则表达式定义的片段，**贪婪方式**
a| b 匹配a或b
`(re)` 对正则表达式分组并记住匹配的文本
`(?imx)` 正则表达式包含三种可选标志：i, m, 或 x 。只影响括号中的区域。
`(?-imx)` 正则表达式关闭 i, m, 或 x 可选标志。只影响括号中的区域。
`(?: re)` 类似 (...), 但是不表示一个组
`(?imx: re)` 在括号中使用i, m, 或 x 可选标志
`(?-imx: re)` 在括号中不使用i, m, 或 x 可选标志
`(?#...)` 注释.
`(?= re)` 前向肯定界定符。如果所含正则表达式，以 ... 表示，在当前位置成功匹配时成功，否则失败。但一旦所含表达式已经尝试，匹配引擎根本没有提高；模式的剩余部分还要尝试界定符的右边。
`(?! re)` 前向否定界定符。与肯定界定符相反；当所含表达式不能在字符串当前位置匹配时成功
`(?> re)` 匹配的独立模式，省去回溯。
`\w` 匹配字母数字及下划线
`\W` 匹配非字母数字及下划线
`\s` 匹配任意空白字符，等价于 [ \t\n\r\f]。
`\S` 匹配任意非空字符
`\d` 匹配任意数字，等价于 [0-9].
`\D` 匹配任意非数字
`\A` 匹配字符串开始
`\Z` 匹配字符串结束，如果是存在换行，只匹配到换行前的结束字符串。
`\z` 匹配字符串结束
`\G` 匹配最后匹配完成的位置。
`\b` 匹配一个单词边界，也就是指单词和空格间的位置。例如， 'er\b' 可以匹配"never" 中的 'er'，但不能匹配 "verb" 中的 'er'。
`\B` 匹配非单词边界。'er\B' 能匹配 "verb" 中的 'er'，但不能匹配 "never" 中的 'er'。
`\n, \t`, 等. 匹配一个换行符。匹配一个制表符。等
`\1...\9` 匹配第n个分组的内容。
`\10` 匹配第n个分组的内容，如果它经匹配。否则指的是八进制字符码的表达式。

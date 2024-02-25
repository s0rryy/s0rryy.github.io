---
author: s0rry
pubDatetime: 2022-04-09T14:08:50Z
modDatetime: 2022-04-09T14:08:50Z
title: C++ 面向对象学习笔记
slug: CPP-Object-Oriented-Learning-Notes
featured: false
draft: false
tags:
  - notes
description: C++ 面向对象与STL库容器学习笔记
---

# C++ 面向对象与STL库容器学习笔记

# 代码格式

## 头文件的写法

防卫式声明 gurad

```python
ifndef __COMPLEX__  #这个名次是自己取的
#define __COMPLEX__
.   #前置声明
.   #类-声明
.   #类-定义
#endif
```

# 标准库中基于对象的两个典型案例

## 类中不带指针（复数complex）

```python
#include <iostream>
using namespace std;

// 同一个class的各个object（对象）互为友元  可以直接用另一个对象的pricvate的数据
class complex
{
public: //公开
    complex(double r = 0, double i = 0)
        : re(r), im(i)
    {  }
    complex& operator += (const complex&);
// const 指这个函数不能改变对象里面的数据 传入的参数加const 指不能改变参数的数值
// const 放在类的前面是常对象 只能调用类的 const 成员（包括 const 成员变量和 const 成员函数）
    double real () const { return re; }
    double imag () const { return im; }

private:
    double re,im;
// 声明一个全局函数的友元
    friend complex& __doapl ( complex*, const complex& );
};

inline complex&
__doapl (complex* ths, const complex& r)
{
    ths->re += r.re;
    ths->im += r.im;
    return *ths;
}

inline complex&
complex::operator += (const complex& r)
{
    return __doapl (this, r);
}

// cout 重载只能是作为友元函数，或者是全局函数，因为成员函数的调用是需要由这个对象引发的，而重载的符号只能作用在它前一个类型上，
// 也就是说当作为成员函数的时候必须要是 obj<<cout ，这样才能告诉编译器去成员函数里面去找重载类型，显然这样写是十分反人类的
ostream&
operator << (ostream& os, const complex& x)
{
    return os << '(' << x.real() << ',' << x.imag() << ')';
}

int main()
{
    complex c(1,2);
    cout << c;

    return 0;
}
```

## 类中带有指针的（字符串string）

```python
#include <iostream>
#include <string.h>
using namespace std;
#ifndef __MYSTRING__
#define __MASTRING__

class String
{
public:
    String(const char* cstr = 0);
    String(const String &str);
    ~String( );
    String& operator = (const String& str);
    char * get_c_str() const { return m_date; }
private:
    char * m_date;
};

#endif

inline
String::String(const char* cstr = 0)
{
    if (cstr) {
        m_date = new char [ strlen(cstr)+1];
        strcpy(m_date, cstr);
    }
    else {
        m_date = new char [1];
        * m_date = '\0';
    }
}

inline
String::~String()
{
    delete[] m_date;
}

inline
String::String(const String &str)// string a(b)    c++新创建的东西会自动调用构造函数    string a = b 一样
{
    m_date = new char [strlen(str.m_date)+ 1];
    strcpy(m_date, str.m_date);
}

inline
String & String::operator= (const String & str)
{
    if (this == &str)  // 检验自我赋值
        return *this;
    delete[] m_date;
    m_date = new char [strlen(str.m_date)+ 1];
    strcpy(m_date, str.m_date);
    return *this;
}

inline
ostream & operator << (ostream & os, const String & str)
{
    os << str.get_c_str();
    return os;

int main(){
    return 0;
}
```

# 类与类之间的关系

## 复合（Composition）

例子： 表示has-a

一个类复合另一个功能更强大的类只开放这个类的部分功能(开放的这个类与调用的类同时加载)

Untitled

构造由内向外构造

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204041747993.png)

在掉用内部的构造函数时编译器只会调用默认构造函数，如果想要调用其他构造函数想要在外层的构造函数里面调用

析构由外向内析构

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204041747995.png)

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204041747996.png)

代码实现

```python
tempale <class T>
class quene{
...
protected:
	deque<T> c;
public:
	bool empty() const { return c.empty(); }
	size_type size() const { return c.size(); }
	reference front() { return c.front(); }
	referrece back() { return c.back(); }

	void push (const value_type& x) { c.push_back(x); }
	void pop() { c.pop_front(); }
}
```

## 委托（Delegation）

composition by reference

例子:

编译防火墙，客户端与实现类分离（reference counting）

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204041747998.png)

用指针调用其他类（**只有在调用的时候才会构造这个类,用指针相连寿命不一致**）

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204041747999.png)

代码实现

```python
class StringREp;
class String {
public:
	String();
	String(const char *s);
	String(const String& s);
	String &operator=(const String& S);
	~String ();
pricvate:
	StringRep *rep;
}
```

## 继承（Inheritance）

继承语法：(is a关系)

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204041747000.png)

父类的数据是可以完美继承下来的

子类的对象会有父类的**成分**

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204041747001.png)

调用构造函数与析构函数的情况与复合关系时相似，调用的是默认构造函数

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204041747002.png)

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204041747003.png)

代码实现

```python
struct _List_ndoe_base
{
	_List_node_base* _M_next;
	_List_node_base* _M_prev;
};

tmplate<typename _Tp>
stuct _List_node
	:public _list_ndoe_base // 三种继承方式public是一种
{
	_Tp _M_date;
}
```

## 类中三种访问权限

public 类内可以用，类外可以访问

protected 类内可以访问 类外不可以访问

private 类内可以访问 类外不可以访问

两者主要在继承的时候有区别

在派生类中protected的数据可以访问，而private不能访问，通过类创建出来的对象也无法访问

## struct 与 class 区别

最本质的一个区别就是默认的访问控制：默认的**继承访问权限**

struct是public的，class是private的。

```python
struct A
{
  char a;
}；
struct B : A
{
  char b;
}
```

这个时候B是public继承A的。

如果都将上面的struct改成class，那么B是private继承A的。这就是默认的继承访问权限

**public继承还是private继承，取决于子类而不是基类。**

struct可以继承class，同样class也可以继承struct，默认的继承访问权限是**看子类**到底是用的struct还是class

```python
struct A{}；
class B : A{}; //private继承
struct C : B{}； //public继承
```

要做的更像是一种数据结构的话，那么用struct。要做的更像是一种对象的话，那么用class

struct可以像c一样用大括号直接赋值，如A a={'p', 7, 3.1415926}; 但是在struct内部加入一个函数又不能赋值了，class把访问属性改为public也能赋值

# 虚函数

例子：

一个形状类（类似于框架，部分属性待定，与递归相似）

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204041747004.png)

纯虚函数：父类不定义（大部分），留给子类定义（子类必须定义）

虚函数：父类有定义，子类可以重新定义

非虚汗：子类不能定义

继承一般要配合虚函数使用

template mathod

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204041747005.png)

# 面向对象进阶

## 转换函数（conversion function）

当必要时，c++可以把创建的类自动转换为一个值

```python
class Fraction
{
public:
	Fraction(int num, int den=1)
		: m_numerator(num), m_denominator(den) {  }
	operator double() const {  // 这里的意思是当需要分数化为double型的时候，编译器可以直接转
		return (double)(m_numerator / m_denomination);
	}
private:
	int m_numerator; //分子
	int m_denominator;  // 分母
	}
}
```

调用时

Fraction f(3,5);

Fraction d2 = f+4;// f被自动转换

转换函数要注意不要与构造函数冲突，当冲突的时候可以加在构造函数前加上 explict ，表示只有构造的时候，构造函数才能使用，不要自动转换。

## pointer-like classes 智能指针

实例：迭代器

```python
template<class T>
class shared_ptr
{
public:
	T& operator*() cosnt    // 注意c++对于这两种操作符的重载
	{ return *px; }
	T& operator->() cosnt
	{ return px; }

	shared_ptr(T* p) : px(p){  }
private:
	T* px;
}
```

## function-like classes 仿函数

重载小括号

```python
struct identity
{
	const T&
	operator() (const T& x) const { return x; } // 括号里的就是参数
};
```

## 模板

类模板

调用的时候要用<>指名类型

函数模板

直接调用

成员模板

在模板类里面，又有模板

用于实现下面这种关系

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204041747006.png)

模板全特化

```python
//泛华代码
template<class Key>
struct hash {  };
//------------------------------------
//特化
template<>
struct hash<int>{
	sise_t operator()(int x) const { return x; }
	};
```

类模板偏特化

类型偏特化：

当我们需要指定部分的模板变量的时候，需要偏特化

```python
#include <iostream>
#include <cstring>
using namespace std;

template<typename T, typename T1>
class A {
  public:
    A() = default;
    A(const T1& n) {
        cout << n << endl;
    }
    bool cmp(const T &t1, const T &t2) {
        return t1 == t2;
    }
};

template<typename T1>  // 篇特化
class A<char*, T1> {
  public:
    A() = default;
    A(T1& n) {
        cout << n << endl;
    }
    bool cmp(const char* t1, const char* t2) {
        while(*t1 != '\0' && *t2 != '\0') {
            if(*t1 != *t2) {
                return false;
            }
            ++t1;
            ++t2;
        }
        return true;
    }
};

int main() {
    char* p1 = "hello";
    char* p2 = "hello";
    A<int, char*>c(p1);
    cout << c.cmp(1, 2) << endl;
    A<char*, char*>c1(p2);  // 即使是偏特化，也要全部声明模板
    cout << c1.cmp(p1, p2) << endl;
    return 0;
}
```

范围偏特化:

```python
template <typename T>
class C {...}; //此泛化版本的T可以是任何类型

template <typename T>
class C<T*> {...}; //特化版本，T为指针类型 将范围缩小
```

函数在全特化的时候只需要在函数前面加上template<>就行。并且函数又函数重载的概念所以没有偏特化。

模板的模板参数：

当需要一个变化的容器，没有确定传入这个容器的变量类型时用模板的模板

```python
template<typename T,
					template <typename T>
						class SmartPtr
						>
class XCLs
{
private:
	SmartPtr<T> sp;
public:
	XCLs():sp(new T){  }
};

// 调用方式
XCLS<strin, shared_ptr> p1;
```

注意：这里待定的容器不能有默认参数，当有默认参数再使用模板，会报错，可以用c++2.0来解决

### 模板参数可变化

将传入的参数分为一个和一包

```python
void print(){
}

template<typename T,typename... Types>
void print(cosnt T& firstArg,cosnt Type&... args)
{
	cout << first << endl;
	print(args...);
}

// sizeof...(args)
```

## auto 语法糖

auto会自己推出类型，必须要在定义的时候就赋值

## for循环

for( decl : coll ){ //coll是容器

statement;

}

```python
for (auto i : {1,2,3,4,5,6,7}){ // i为后面的容器的值pass by value
	cout << i << endl;            // 如果要改后面的值 则需要auto&传引用
}
```

## 对象模型 虚指针 续表

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204041747007.png)

带着虚函数的对象会多一个指针（虚指针），指向虚表。

后面继承的对象可以重写虚函数，改掉虚表的地址位置不变。

动态绑定条件：

1.通过指针调用

2.有**向上转型**的动作

3.调用虚函数

向上转型：

向上转型就是将子类转换为父类

1、子类除继承父类数据成员，并且还会有自己的数据成员，但是在向上转型后子类的数据成员会被舍弃

2、赋值的本质是将现有的数据写入已分配好的内存中，对象的内存只包含了成员变量，所以对象之间的赋值是成员变量的赋值，成员函数不存在赋值问题。

## this

每个成员函数都有的一个this的指针（指向这对象的地址）

执行动态绑定

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204041747008.png)

## 静态绑定与动态绑定

在vs中实际的测试带码和结果如下

```python
#include <iostream>
using namespace std;
class father
{
public:
	virtual void fun1(){
		cout << "father" << endl;
	}
};

class child:
	public father
{
public:
	virtual void fun1() {
		cout << "child" << endl;
	}
};

int main() {
	child c;
	father f;
//	静态绑定
	father f_n = (father)c;
	f_n.fun1();
// 动态绑定
	father* p_f_n = (father *)&c;
	p_f_n->fun1();
//  动态绑定
	father* p_f_n_n = new father;
	p_f_n_n->fun1();
//  动态绑定
	child* p_c_n_n = new child;
	p_c_n_n->fun1();
//  动态绑定
	father& d_c = c;
	d_c.fun1();

	return 0;
}
```

# c++STL库之容器

# 1.STL体系介绍

c++泛型编程（模板）的产物STL库

**目标：**

- 使用c++标准库
- 认识c++标准库（胸中自由丘壑）
- 良好使用c++标准库
- 扩充c++标准库

---

**STL分为六大部件**

- 容器（containers）
- 分配器（allocatiors）支持容器，分配内存
- 算法（algorithms）
- 迭代器（iterators）
- 适配器（adapters） 转换器，变压器
- 仿函数（functors）

---

**容器采用前闭后开区间**

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204262241734.png)

遍历vector容器 这里大概描述了一下容器的使用

```python
Conrainer<T> c;
...
Container<T>::iterator ite = c.begin();
for (;ite != c.end(); ++ite)
	...
//
//c++ 11后可用代码 ------------------------------------
//
std::vertor<double> vec;
...
for (auto elem : vec){
	std::cout << elem << std::endl;
}
for (auto& elem: vec ){
	elem *= 3;
}
```

# 2.容器的分类

**所有的容器都维护了两个迭代器，头和尾**

---

## 序列式容器（Sequence Containers）

数组（Arra y）

向量（Vector）：末端会自动扩充 ， 双倍扩充

双向队列（Deque）：两端可进可出 buf大小扩充

双向链表（List）：双向环状列表

单向链表（Forward-List）：

## 关联式容器（ Associative Containers） —用于查找

Set(集合)/Multiset（）:Set（元素不能重复），Multiset（元素可以重复）

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204262241736.png)

Map/Multimap:

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204262241737.png)

multiset(红黑树作为底层结构)

## 不定序（Unordered Containers） （底层hash 表）

Unordered Set/Multiset:

Unordered Map/Multimap:

---

## 分配器

每个容器都有一个默认的分配器，也可强行选用其他分配器

作用类似于c语言的malloc，只不过的对于大量的数据的时候单一的malloc显然不是最优解，因为不肯能存在这么大的内存，所以选用比较好的分配器能够有效的节省空间，或者提高效率。

自己写代码的时候可以用分配器，但是没有必要，分配器搭配容器更佳。

## 迭代器

**设计原理**：**5种必须接口**（下面list的迭代器有详细的介绍）

迭代器为算法提供访问容器的方式

**萃取器**：模板的偏特化 ，可能容器的**iterator**只有指针，不是复杂的类，为了区别开这些迭代器，所以采用了萃取器的技术，保证了为算法提供的接口还是拥有5种规范的接口

---

# 3.容器的底层结构

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204262241738.png)

## List

模板接口

template<class T, class Alloc = alloc>

**list_iterator 源码**(由于这是第一个迭代器会写的比较详细一点)

```cpp
template<class T, class Ref, class Ptr>//可以只传一个值
struct _list_iterator{
	typedef _list_iterator<T,Ref> self;
	typedef bidirectional_iterator_tag iterator_category;//（1）这个是表示这是一个双向的列表
	typedef T value_type;// （2）所有容器必须含有的5个信息
	typedef Ptr pointer;// （3）
	typedef Ref reference;// （4）
	typedef _list_node<T>* link_type;
	typedef ptrdiff_t differemce_type;// （5）头与尾的最大距离

	link_type node;

	reference operator*() const { return (*node).data; }
	pointer operator->() const { return &(operator*()); }// 调用上面的重载
	self& operator++() //前加加相当于没有操作数，并且返回引用，可以连续的前加加
		{ node = (link_type)((*node).next); return *this; }
	self operator++(int)//后加加相当于有操作数，不返回引用，不能连续后加加
		{ self tmp = *this; ++*this; return tmp; }// （有点不明白，为什么传值就可以不连续加加）
	...
};
```

### forward_list 单向链表

## vector

自动成倍扩充，就是数组，连续空间

空间不够时，将原来的拷贝到一个新的地址，这个拷贝函数还把要拷贝后面的数据也要拷贝过来，因为**insert函数（插入函数）**也要调用这个拷贝函数，所以为了方便insert函数才这样设计的

**iterator:**

就是指针，所以在这里**萃取器**就起作用了

## array

就是数组，为了使用c++的算法才被包装成类，没有ctor，dtor（构造函数析构函数）

array<int,10> maarray //指定大小10

## deque（40byte）

分段连续的空间，对外好称连续

靠指针数组来实现双向扩充，指针数组不够的时候也是成倍增加然后复制过去，数组中每个指针指向一个数组（buffer/node）

i**terator**

deque的iterator迭代器含有 cur first last node

cur指向当前的数组的当前位置，first指向当前数组第一个位置，last指向当前数组**最后一位的下一个位置**，node指向这个数组在指针数组中的位置。

![Untitled](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/202204262241739.png)

**insert函数 插入一个数据**

- 首先判断是否为头尾
- 然后判断距离头近还是尾近，然后插入，节省时间

**deque的iterator如何实现模拟连续空间**

- 重载-号运算符，算距离
- 对边界调节进行判断

### stack与queue

stack先进后出 queue先进先出

是**deque封锁住部分功能实现的**

不允许遍历， 不提供iterator

它们可以选择list和deque来作为底层实现， stack可以选用vector来作为底层实现（只要有需要实现的功能就能用作底部实现）

采用list作为底层实现的方式：stack<string,list<string>> c;

## rb_tree

底层：红黑树（平衡二元搜寻数 ）

### 红黑树

高度平衡，没有一个分支太长导致搜寻过慢，利于遍历

树中元素理论上不能改变值，但是当是key|data时，是允许改变data的值

insert_unique() ： key是独一无二

insert_equal()： key是可以重复的

```cpp
template< class Key,
					class Value, // key|data key与data合成value pair（key，data）
					class KeyOfValue,// key拿出来的方式
					class Compare, // 比较大小的方式
					class Alloc = alloc>
class rb_tree{
	...
};
```

### set和multiset

value与key合二为一

set的key不可重复，用的是rb_tree的insert_unique() container adaptr

multiset元素的key可重复，用的是rb_tree的insert_equal()

### map和multimap

value与key分开

迭代器可以改data不能改key ， 在进入红黑树的时候把key直接变为了const

## hashtable（散列表）

采用Separate Chaining ，元素个数大于篮子的个数时会把篮子的个数（可能是素数）增加

hashFcn是算出的编号的算法

迭代器神似deque的迭代器

```cpp
template< class Value,
					class Key,
					class HashFcn, // 取出编号的方式
					class Extractkey, // 取key的方式
					class EqualKey, // 相等的判断方式
					class Alloc=alloc>
class hashtable{
	...
}
```

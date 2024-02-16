# 环境搭建

ubuntu 直接sudo apt install llvm-14
这里的版本可以自由选择
文件和库文件在 /usr/include/llvm-14 和 /usr/lib/llvm-14 下
再下载一个对应版本的clang即可

# 第一个pass

## 项目结构

![image.png](https://cdn.nlark.com/yuque/0/2024/png/23002651/1705841493077-238c5370-6bb5-4090-bbb3-b8f01468bb02.png#averageHue=%23242323&clientId=u39fc12b2-a20c-4&from=paste&height=354&id=u21edea83&originHeight=354&originWidth=277&originalType=binary&ratio=1&rotation=0&showTitle=false&size=16790&status=done&style=none&taskId=uba7fd656-7b39-446b-aeaa-c6fa93b2d6b&title=&width=277)

## 编译

这里采用cmake编译

```cmake
cmake_minimum_required(VERSION 3.10)
// 项目名
project(MyPass)
// 采用的C++标准
set(CMAKE_CXX_STANDARD 14)
// 定义一个变量表示LLVM的路径
set(LLVM_PATH /usr/lib/llvm-14)
// 头文件
include_directories(${LLVM_PATH}/include)
// MODULE代表编译的文件的类型
add_library(mypass MODULE src/MyPass.cpp)
// 设置编译的属性
set_target_properties(mypass PROPERTIES
        COMPILE_FLAGS "-fno-rtti"
        )

target_link_libraries(mypass ${LLVM_PATH}/lib/libLLVM-14.so)
```

编译命令
`cmake -B build`
`cmake --build build`
使用编译生成的so

1. 生成IR中间代码

`clang -S -emit-llvm -O0 -Xclang -disable-O0-optnone tmp/foo.c -o tmp/foo.ll`

2. 使用编译生成的pass进行优化

`opt -S -load-pass-plugin**=**build/libmypass.so -passes**=**"mypass" tmp/foo.ll -o tmp/foo_mypass.ll`

# Pass结构

这里直接学习上一个测试demo的头文件就能对pass有一个基本的认识

```cpp
#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

namespace llvm {

    class MyPass : public PassInfoMixin<MyPass> {
    public:
        PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
    };

}  // namespace llvm

// Register the pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "MyPass", "v0.1",
        [](llvm::PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](llvm::StringRef Name, llvm::FunctionPassManager &FPM,
                llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
                    if(Name == "mypass"){
                        FPM.addPass(llvm::MyPass());
                        return true;
                    }
                    return false;
                }
                );
        }
    };
}
```

## pass注册

`::llvm::PassPluginLibraryInfo`这个表示在全局作用域的llvm命名空间下的PassPluginLibraryInfo函数，同时也是`llvmGetPassPluginInfo`这个函数的返回值

```cpp
struct PassPluginLibraryInfo {
  /// The API version understood by this plugin, usually \c
  /// LLVM_PLUGIN_API_VERSION
  uint32_t APIVersion;
  /// A meaningful name of the plugin.
  const char *PluginName;
  /// The version of the plugin.
  const char *PluginVersion;

  /// The callback for registering plugin passes with a \c PassBuilder
  /// instance
  void (*RegisterPassBuilderCallbacks)(PassBuilder &);
};
```

RegisterPassBuilderCallbacks参数以及内容介绍
参数llvm::PassBuilder:
一个工具类，用于添加、移除、查询和管理 Pass

- **llvm::PassBuilder::addGlobalOptimizationPipeline**()：向 Pass 优化流水线中添加全局优化 Pass，这些 Pass 通常对整个程序进行优化。
- **llvm::PassBuilder::addFunctionOptimizationPipeline**()：向 Pass 优化流水线中添加函数级别的优化 Pass，这些 Pass 仅对每个函数进行优化。
- **llvm::PassBuilder::registerPipelineParsingCallback**()：注册一个回调函数，用于解析和配置 Pass 优化流水线。该回调函数通常接受 llvm::StringRef 类型的参数，用于指定 Pass 名称，以及llvm::FunctionPassManager 类型的参数，用于管理函数级别的 Pass。

```cpp
[](llvm::PassBuilder &PB) {
  PB.registerPipelineParsingCallback(
    [](llvm::StringRef Name, llvm::FunctionPassManager &FPM,
       llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        // 用于与命令行交互
      if(Name == "mypass"){
        FPM.addPass(llvm::MyPass());
        return true;
      }
      return false;
    }
  );
}
```

## pass编写

```cpp
namespace llvm {

  class MyPass : public PassInfoMixin<MyPass> {
  public:
    PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
  };

}  // namespace llvm
```

实现功能只需要写run方法即可

# 指令类型

获取方法

```cpp
void GetIns(Function &F){
    for(inst_iterator It = inst_begin(F), E = inst_end(F); It != E; ++It){
        Instruction *I = &*It;
        // 通过dyn_cast函数来向下转型成对应的操作数
        // if (auto *II = dyn_cast<IntrinsicInst>(I)) {
        //     if (II->getIntrinsicID() == Intrinsic::eh_typeid_for) {
        //         continue;
        //     }
        // }
    }
}
```

## PHI指令 - PHINode

在静态单赋值（SSA）形式的程序中，用于从其输入中根据控制流选择一个值。

```cpp
entry:
  %cond = icmp eq i32 %a, 0
  br i1 %cond, label %ifblock, label %elseblock

ifblock:
  %x = add i32 %a, 1
  br label %mergeblock

elseblock:
  %y = sub i32 %a, 1
  br label %mergeblock

mergeblock:
  %result = phi i32 [ %x, %ifblock ], [ %y, %elseblock ]
  ret i32 %result
```

## Landingpad指令 - LandingPadInst

在LLVM中异常处理指令和异常处理代码块是很特殊的指令，很多优化都要跳过。

```cpp
void bar();
void foo() throw (const char *) {
    try {
        bar();
    } catch (int) {
    }
}
```

```cpp
@_ZTIPKc = external dso_local constant i8*
@_ZTIi = external dso_local constant i8*

; Function Attrs: noinline uwtable mustprogress
define dso_local void @_Z3foov() #0 personality i8* bitcast (i32 (...)* @__gxx_personality_v0 to i8*) {
  %1 = alloca i8*, align 8
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
    // 先当与try {bar();}
    // invoke指令用于调用一个函数，并指定在正常执行和异常发生时的控制流转移。
  invoke void @_Z3barv()
          to label %4 unwind label %5
// 正常返回位置
4:                                                ; preds = %0
  br label %23
// 出现异常返回的位置
5:                                                ; preds = %0
    // landingpad 用于标识异常处理块的"着陆块"
  %6 = landingpad { i8*, i32 }
          catch i8* bitcast (i8** @_ZTIi to i8*)
          filter [1 x i8*] [i8* bitcast (i8** @_ZTIPKc to i8*)]
  %7 = extractvalue { i8*, i32 } %6, 0
  store i8* %7, i8** %1, align 8
  %8 = extractvalue { i8*, i32 } %6, 1
  store i32 %8, i32* %2, align 4
  br label %9

9:                                                ; preds = %5
  %10 = load i32, i32* %2, align 4
  %11 = call i32 @llvm.eh.typeid.for(i8* bitcast (i8** @_ZTIi to i8*)) #3
  %12 = icmp eq i32 %10, %11
  br i1 %12, label %18, label %13

13:                                               ; preds = %9
  %14 = load i32, i32* %2, align 4
  %15 = icmp slt i32 %14, 0
  br i1 %15, label %16, label %24

16:                                               ; preds = %13
  %17 = load i8*, i8** %1, align 8
  call void @__cxa_call_unexpected(i8* %17) #4
  unreachable

18:                                               ; preds = %9
  %19 = load i8*, i8** %1, align 8
  %20 = call i8* @__cxa_begin_catch(i8* %19) #3
  %21 = bitcast i8* %20 to i32*
  %22 = load i32, i32* %21, align 4
  store i32 %22, i32* %3, align 4
  call void @__cxa_end_catch() #3
  br label %23

23:                                               ; preds = %18, %4
  ret void

24:                                               ; preds = %13
  %25 = load i8*, i8** %1, align 8
  %26 = load i32, i32* %2, align 4
  %27 = insertvalue { i8*, i32 } undef, i8* %25, 0
  %28 = insertvalue { i8*, i32 } %27, i32 %26, 1
  resume { i8*, i32 } %28
}

declare dso_local void @_Z3barv() #1

declare dso_local i32 @__gxx_personality_v0(...)

; Function Attrs: nounwind readnone
// 在异常处理中被用来获取一个特定类型的类型标识符， 这个类型标识符可以用来匹配异常处理程序
declare i32 @llvm.eh.typeid.for(i8*) #2

declare dso_local i8* @__cxa_begin_catch(i8*)

declare dso_local void @__cxa_end_catch()

declare dso_local void @__cxa_call_unexpected(i8*)
```

## Intrinsic 指令 - IntrinsicInst

LLVM自带的一些函数调用，提供了对于常规LLVM IR（中间表示）无法或难以表达的操作的访问。例如，一些特定的硬件指令或者优化的数学运算等。
比如这里的llvm.eh.typeid.for

# 操作数类型

获取方法

```cpp
void GetOperands(Instruction &I){
    for (unsigned int i = 0; i < I->getNumOperands(); ++i) {
        auto Operand = I->getOperand(i);
        // 如果需要对操作数的类型进行判断
        // if (isa<ConstantExpr>(I->getOperand(i)))
        //     WorkList.insert(I);
    }
}
```

123

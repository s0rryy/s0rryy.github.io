---
author: s0rry
pubDatetime: 2023-02-25T15:01:00Z
modDatetime: 2023-02-25T18:01:00Z
title: unicorn的相关函数学习
slug: Unicorn-Notes
featured: false
draft: false
tags:
  - notes
description: unicorn的相关函数学习
---

# unicorn

主要代码都是dump的，这里主要是记录一下设计思路。

unicorn用来去花指令，简直是神，免去了些idapython的苦恼，我一直认为去写idapython是一件费力不讨好的事情，因为idapython调试起来比较的麻烦。

## 快速入门

python包中的hook_add函数原型

`def hook_add(self, htype, callback, user_data=None, begin=1, end=0, arg1=0)`

- htype 就是Hook的类型，callback是hook回调用；
- callback 是Hook的处理handler指针。请注意！不同类型的hook，handler的参数定义也是不同的。
- user_data 附加参数，所有的handler都有一个user_data参数，由这里传值。
- begin hook 作用范围起始地址
- end hook 作用范围结束地址，默认则作用于所有代码。

### 简单例子

```jsx
from unicorn import *
from unicorn.arm_const import *
ARM_CODE   = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0"
# mov r0, #0x37;
# sub r1, r2, r3
# Test ARM

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))

def test_arm():
    print("Emulate ARM code")
    try:
				#第一步设置执行汇编的指令集，对应的位数或模式
			  #x64
				#emu = Uc(UC_ARCH_X86, UC_MODE_64)
        # Initialize emulator in ARM mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

				#映射内存
        # map 2MB memory for this emulation
        ADDRESS = 0x10000
        mu.mem_map(ADDRESS, 2 * 0x10000)
        mu.mem_write(ADDRESS, ARM_CODE)#写入硬编码的指令，只支持python的byte数组

        mu.reg_write(UC_ARM_REG_R0, 0x1234)
        mu.reg_write(UC_ARM_REG_R2, 0x6789)
        mu.reg_write(UC_ARM_REG_R3, 0x3333)

				#在begin...end范围内的每一条指令被执行前都会调用callback
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS)
        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(ARM_CODE))
        r0 = mu.reg_read(UC_ARM_REG_R0)
        r1 = mu.reg_read(UC_ARM_REG_R1)
        print(">>> R0 = 0x%x" % r0)
        print(">>> R1 = 0x%x" % r1)
    except UcError as e:
        print("ERROR: %s" % e)
```

## 基于unicorn的调试器

大致原理是对每一个指令进行hook，再判断是否是我们下的断点的位置，如果是的话就会停下来解释命令，不是就会直接运行

代码出处: [https://bbs.kanxue.com/thread-253868.htm](https://bbs.kanxue.com/thread-253868.htm)

```jsx
# -*- coding: utf-8 -*-
# @Time : 2023-02-24 13:16
# @Author : s0rry

from unicorn import *
from unicorn import arm_const
import sys
import hexdump
import capstone as cp

BPT_EXECUTE = 1
BPT_MEMREAD = 2
UDBG_MODE_ALL = 1
UDBG_MODE_FAST = 2

REG_ARM = {arm_const.UC_ARM_REG_R0: "R0",
           arm_const.UC_ARM_REG_R1: "R1",
           arm_const.UC_ARM_REG_R2: "R2",
           arm_const.UC_ARM_REG_R3: "R3",
           arm_const.UC_ARM_REG_R4: "R4",
           arm_const.UC_ARM_REG_R5: "R5",
           arm_const.UC_ARM_REG_R6: "R6",
           arm_const.UC_ARM_REG_R7: "R7",
           arm_const.UC_ARM_REG_R8: "R8",
           arm_const.UC_ARM_REG_R9: "R9",
           arm_const.UC_ARM_REG_R10: "R10",
           arm_const.UC_ARM_REG_R11: "R11",
           arm_const.UC_ARM_REG_R12: "R12",
           arm_const.UC_ARM_REG_R13: "R13",
           arm_const.UC_ARM_REG_R14: "R14",
           arm_const.UC_ARM_REG_R15: "R15",
           arm_const.UC_ARM_REG_PC: "PC",
           arm_const.UC_ARM_REG_SP: "SP",
           arm_const.UC_ARM_REG_LR: "LR"
           }

REG_TABLE = {UC_ARCH_ARM: REG_ARM}

def str2int(s):
    if s.startswith('0x') or s.startswith("0X"):
        return int(s[2:], 16)
    return int(s)

def advance_dump(data, base):
    PY3K = sys.version_info >= (3, 0)
    generator = hexdump.genchunks(data, 16)
    retstr = ''
    for addr, d in enumerate(generator):
        # 00000000:
        line = '%08X: ' % (base + addr * 16)
        # 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
        dumpstr = hexdump.dump(d)
        line += dumpstr[:8 * 3]
        if len(d) > 8:  # insert separator if needed
            line += ' ' + dumpstr[8 * 3:]
        # ................
        # calculate indentation, which may be different for the last line
        pad = 2
        if len(d) < 16:
            pad += 3 * (16 - len(d))
        if len(d) <= 8:
            pad += 1
        line += ' ' * pad

        for byte in d:
            # printable ASCII range 0x20 to 0x7E
            if not PY3K:
                byte = ord(byte)
            if 0x20 <= byte <= 0x7E:
                line += chr(byte)
            else:
                line += '.'
        retstr += line + '\n'
    return retstr

def _dbg_trace(mu, address, size, self):
    self._tracks.append(address)
    if not self._is_step and self._tmp_bpt == 0:
        if address not in self._list_bpt:
            return

    if self._tmp_bpt != address and self._tmp_bpt != 0:
        return

    return _dbg_trace_internal(mu, address, size, self)

def _dbg_memory(mu, access, address, length, value, self):
    pc = mu.reg_read(arm_const.UC_ARM_REG_PC)
    print("memory error: pc: %x access: %x address: %x length: %x value: %x" %
          (pc, access, address, length, value))
    _dbg_trace_internal(mu, pc, 4, self)
    mu.emu_stop()
    return True

def _dbg_trace_internal(mu, address, size, self):
    self._is_step = False
    print("======================= Registers =======================")
    self.dump_reg()
    print("======================= Disassembly =====================")
    self.dump_asm(address, size * self.dis_count)

    while True:
        raw_command = input(">")
        if raw_command == '':
            raw_command = self._last_command
        self._last_command = raw_command
        command = []
        for c in raw_command.split(" "):
            if c != "":
                command.append(c)
        try:
            if command[0] == 'set':
                if command[1] == 'reg':  # set reg regname value
                    self.write_reg(command[2], str2int(command[3]))
                elif command[1] == 'bpt':
                    self.add_bpt(str2int(command[2]))
                else:
                    print("[Debugger Error]command error see help.")

            elif command[0] == 's' or command[0] == 'step':
                # self._tmp_bpt = address + size
                self._tmp_bpt = 0
                self._is_step = True
                break
            elif command[0] == 'n' or command[0] == 'next':
                self._tmp_bpt = address + size
                self._is_step = False
                break

            elif command[0] == 'r' or command[0] == 'run':
                self._tmp_bpt = 0
                self._is_step = False
                break
            elif command[0] == 'dump':
                if len(command) >= 3:
                    nsize = str2int(command[2])
                else:
                    nsize = 4 * 16
                self.dump_mem(str2int(command[1]), nsize)
            elif command[0] == 'list':
                if command[1] == 'bpt':
                    self.list_bpt()
            elif command[0] == 'del':
                if command[1] == 'bpt':
                    self.del_bpt(str2int(command[2]))
            elif command[0] == 'stop':
                exit(0)
            elif command[0] == 't':
                self._castone = self._capstone_thumb
                print("======================= Disassembly =====================")
                self.dump_asm(address, size * self.dis_count)
            elif command[0] == 'a':
                self._castone = self._capstone_arm
                print("======================= Disassembly =====================")
                self.dump_asm(address, size * self.dis_count)
            elif command[0] == 'f':
                print(" == recent ==")
                for i in self._tracks[-10:-1]:
                    print(self.sym_handler(i))
            else:
                print("Command Not Found!")

        except:
            print("[Debugger Error]command error see help.")

class UnicornDebugger:
    def __init__(self, mu, mode=UDBG_MODE_ALL):
        self._tracks = []
        self._mu = mu
        self._arch = mu._arch
        self._mode = mu._mode
        self._list_bpt = []
        self._tmp_bpt = 0
        self._error = ''
        self._last_command = ''
        self.dis_count = 5
        self._is_step = False
        self.sym_handler = self._default_sym_handler
        self._capstone_arm = None
        self._capstone_thumb = None

        if self._arch != UC_ARCH_ARM:
            mu.emu_stop()
            raise RuntimeError("arch:%d is not supported! " % self._arch)

        if self._arch == UC_ARCH_ARM:
            capstone_arch = cp.CS_ARCH_ARM
        elif self._arch == UC_ARCH_ARM64:
            capstone_arch = cp.CS_ARCH_ARM64
        elif self._arch == UC_ARCH_X86:
            capstone_arch = cp.CS_ARCH_X86
        else:
            mu.emu_stop()
            raise RuntimeError("arch:%d is not supported! " % self._arch)

        if self._mode == UC_MODE_THUMB:
            capstone_mode = cp.CS_MODE_THUMB
        elif self._mode == UC_MODE_ARM:
            capstone_mode = cp.CS_MODE_ARM
        elif self._mode == UC_MODE_32:
            capstone_mode = cp.CS_MODE_32
        elif self._mode == UC_MODE_64:
            capstone_mode = cp.CS_MODE_64
        else:
            mu.emu_stop()
            raise RuntimeError("mode:%d is not supported! " % self._mode)

        self._capstone_thumb = cp.Cs(cp.CS_ARCH_ARM, cp.CS_MODE_THUMB)
        self._capstone_arm = cp.Cs(cp.CS_ARCH_ARM, cp.CS_MODE_ARM)

        self._capstone = self._capstone_thumb

        if mode == UDBG_MODE_ALL:
            mu.hook_add(UC_HOOK_CODE, _dbg_trace, self)

        mu.hook_add(UC_HOOK_MEM_UNMAPPED, _dbg_memory, self)
        mu.hook_add(UC_HOOK_MEM_FETCH_PROT, _dbg_memory, self)

        self._regs = REG_TABLE[self._arch]

    def dump_mem(self, addr, size):
        data = self._mu.mem_read(addr, size)
        print(advance_dump(data, addr))

    def dump_asm(self, addr, size):
        md = self._capstone
        code = self._mu.mem_read(addr, size)
        count = 0
        for ins in md.disasm(code, addr):
            if count >= self.dis_count:
                break
            print("%s:\t%s\t%s" % (self.sym_handler(ins.address), ins.mnemonic, ins.op_str))

    def dump_reg(self):
        result_format = ''
        count = 0
        for rid in self._regs:
            rname = self._regs[rid]
            value = self._mu.reg_read(rid)
            if count < 4:
                result_format = result_format + '  ' + rname + '=' + hex(value)
                count += 1
            else:
                count = 0
                result_format += '\n' + rname + '=' + hex(value)
        print(result_format)

    def write_reg(self, reg_name, value):
        for rid in self._regs:
            rname = self._regs[rid]
            if rname == reg_name:
                self._mu.reg_write(rid, value)
                return
        print("[Debugger Error] Reg not found:%s " % reg_name)

    def show_help(self):
        help_info = """
        # commands
        # set reg <regname> <value>
        # set bpt <addr>
        # n[ext]
        # s[etp]
        # r[un]
        # dump <addr> <size>
        # list bpt
        # del bpt <addr>
        # stop
        # a/t change arm/thumb
        # f show ins flow
        """
        print(help_info)

    def list_bpt(self):
        for idx in range(len(self._list_bpt)):
            print("[%d] %s" % (idx, self.sym_handler(self._list_bpt[idx])))

    def add_bpt(self, addr):
        self._list_bpt.append(addr)

    def del_bpt(self, addr):
        self._list_bpt.remove(addr)

    def get_tracks(self):
        for i in self._tracks[-100:-1]:
            # print (self.sym_handler(i))
            pass
        return self._tracks

    def _default_sym_handler(self, address):
        return hex(address)

    def set_symbol_name_handler(self, handler):
        self.sym_handler = handler
```

## 模拟执行逻辑

如何实现自动化模拟执行，还原ollvm的呢？

先通过代码的CFG图，分析出代码块之间的关系，然后模拟执行每个代码块、

用unicorn模拟执行的主要难点是，如何处理分支的情况

这里对每个块进行单独的模拟执行，先采用normal_hook，如果当前块存在分支再对分支进行模拟执行此时采用branch_hook

这里由于采用的单独对每个块进行模拟，那么实际上就与angr的思路是基本一致的，没有完全发挥unicorn的威力，后续我会对这段代码进行优化，为每个代码块添加上下文，实现模拟执行的准确性。

代码出处: [https://github.com/mFallW1nd/deflat](https://github.com/mFallW1nd/deflat)

```jsx
from emu_utils import *
from emu_analysis import *
from unicorn import *
from unicorn.x86_const import *

def log_hook(emu, addr, size, user_data):
    # init
    disasm = get_disasm(emu, addr, size)

    # log
    if DEBUG and VERBOSE:
        print(hex(addr) + '\t' + disasm['op'] + '\t' + disasm['opstr'])

def step_over_hook(emu, addr, size, relevant):
    # init
    disasm = get_disasm(emu, addr, size)

    # step over
    if (disasm['op'] == 'call'):
        emu.reg_write(UC_X86_REG_RIP, addr+size)

    if (disasm['op'] == 'ret' or
        disasm['op'] == 'retn'
    ):
        print('\t\tretn node')
        emu.emu_stop()

def normal_hook(emu, addr, size, relevant):
    # init
    disasm = get_disasm(emu, addr, size)
    relevant.node_inst.append(disasm)

    # judge if have branch
    if ('cmov' in disasm['op']):
        # get information
        relevant.have_branch = True
        relevant.branch_type = disasm['op'][4:]
        relevant.cmov_inst = disasm

        # normal reg
        print("\t\tbranch 0 executing!")
        relevant.node_inst.clear()
        relevant.cmov_inst['branch'] = 0
        emulate_execution(
            filename,
            relevant.sg_node.addr,
            0xFFFFFFFF,
            branch_hook,
            relevant
        )

        # condition_reg
        print("\t\tbranch 1 executing!")
        relevant.node_inst.clear()
        relevant.cmov_inst['branch'] = 1
        emulate_execution(
            filename,
            relevant.sg_node.addr,
            0xFFFFFFFF,
            branch_hook,
            relevant
        )

        # stop
        emu.emu_stop()

    # add coedge
    if (hex(addr) in tar_func.relevant_nodes and
            addr != relevant.sg_node.addr
        ):
        print('\t\tbranch', 'is:' + hex(addr))
        relevant.branch_addr[0] = addr
        emu.emu_stop()

def branch_hook(emu, addr, size, relevant):
    # init
    disasm = get_disasm(emu, addr, size)
    relevant.node_inst.append(disasm)

    # change state value
    if ('cmov' in disasm['op']):
        reg0 = get_reg_in_str(relevant.cmov_inst['opstr'].split(', ')[0])
        reg1 = get_reg_in_str(relevant.cmov_inst['opstr'].split(', ')[1])

        if (relevant.cmov_inst['branch'] == 1):
            reg1_value = emu.reg_read(reg1[1])
            emu.reg_write(reg0[1], reg1_value)

        emu.reg_write(UC_X86_REG_RIP, addr+size)

    # add coedge
    if (hex(addr) in tar_func.relevant_nodes and
            len(relevant.node_inst) > 1
        ):
        print('\t\t\tbranch', relevant.cmov_inst['branch'], 'is:' + hex(addr))

        if relevant.cmov_inst['branch'] == 0:
            relevant.branch_addr[0] = addr
        elif relevant.cmov_inst['branch'] == 1:
            relevant.branch_addr[1] = addr

        emu.emu_stop()

def emulate_execution(filename, start_addr, end_addr, hook_func, user_data):
    emu = Uc(UC_ARCH_X86, UC_MODE_64)

    textSec = get_section(filename, '.text')

    textSec_entry = textSec.header['sh_addr']
    textSec_size = textSec.header['sh_size']
    textSec_raw = textSec.header['sh_offset']

    TEXT_BASE  = textSec_entry >> 12 << 12
    TEXT_SIZE  = (textSec_size + 0x1000) >> 12 << 12
    TEXT_RBASE = textSec_raw >> 12 << 12

    VOID_BASE  = 0x00000000
    VOID_SIZE  = TEXT_BASE

    STACK_BASE = TEXT_BASE + TEXT_SIZE
    STACK_SIZE = 0xFFFFFFFF - STACK_BASE >> 12 << 12

    emu.mem_map(TEXT_BASE, TEXT_SIZE)
    emu.mem_map(VOID_BASE, VOID_SIZE)
    emu.mem_map(STACK_BASE, STACK_SIZE)

    emu.mem_write(TEXT_BASE, read(filename)[TEXT_RBASE:TEXT_RBASE+TEXT_SIZE])
    emu.reg_write(UC_X86_REG_RBP, STACK_BASE + 0x1000)
    emu.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SIZE // 2)

    emu.hook_add(UC_HOOK_CODE, log_hook)
    emu.hook_add(UC_HOOK_CODE, step_over_hook, user_data)
    emu.hook_add(UC_HOOK_CODE, hook_func, user_data)

    emu.emu_start(start_addr, end_addr)

if __name__ == '__main__':
    DEBUG   = True
    VERBOSE = False
    if DEBUG:
        filename   = './ezam'
        start_addr = 0x4008F0
        end_addr   = 0x401B49
    else:
        filename, start_addr, end_addr = get_args()

    # get function's information
    print('\n[+] < Preparing for emulate execution >')
    tar_func = TarFunc(filename, start_addr, end_addr)

    print('\n[*] < Function\'s information >')
    print('\nprologue_node >\n', tar_func.prologue_node)
    print('\nmain_dispatcher_node >\n', tar_func.main_dispatcher_node)
    print('\npre_dispatcher_node >\n', tar_func.pre_dispatcher_node)
    print('\nrelevant nodes >\n')
    for relevant in tar_func.relevant_nodes:
        print(tar_func.relevant_nodes[relevant].sg_node)
    print('\nretn node >\n', tar_func.retn_node)

    # reconstruct control flow
    print('\n[+] < Reconstructing control flow >')
    for relevant in tar_func.relevant_nodes:
        print('['+relevant+'] ', end='')
        print("relevant executing!")
        emulate_execution(
            filename,
            int(relevant, 16),
            0xFFFFFFFF,
            normal_hook,
            tar_func.relevant_nodes[relevant]
        )

    # patch binary
    print('\n[+] < Patching binary file >')
    new_filename = tar_func.filename + '_recovered_' + hex(start_addr)

    for relevant in tar_func.relevant_nodes.values():
        relevant.get_node_inst(tar_func)
        if relevant.sg_node.addr != tar_func.retn_node.addr:
            relevant.patch(tar_func)
    tar_func.fill_nop()

    with open(new_filename, 'wb') as f:
        f.write(tar_func.file_buf)

    # success
    print('\n[*] Recovered successfully! The output file is:', new_filename)
```

## 小结

用unicorn来执行程序，跟写loader是一个道理，分配内存，映射段，开始执行，需要比较扎实的基本。

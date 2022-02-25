# Lab1
*鸭鸭(1)班 HoTay*
***
## 练习1
> 理解通过make生成执行文件的过程
### 1. 操作系统镜像文件ucore.img是如何一步一步生成的?(需要比较详细地解释Makefile中每一条相关命令和命令参数的含义,以及说明命令导致的结果)  
在Makefile中可以看到,生成ucore.img需要kernel和bootblock,其中生成ucore.img的代码如下:  
````makefile
$(UCOREIMG): $(kernel) $(bootblock)
	$(V)dd if=/dev/zero of=$@ count=10000
	$(V)dd if=$(bootblock) of=$@ conv=notrunc
	$(V)dd if=$(kernel) of=$@ seek=1 conv=notrunc

$(call create_target,ucore.img)
````
首先创建一个大小为10000个block的文件,然后将bootblock和kernel拷贝进去.其中默认block大小为512字节.其中第四行`seek=1`的含义为跳过bookblock已占据的一个块.

生成bootblock的代码如下:
````makefile
$(bootblock): $(call toobj,$(bootfiles)) | $(call totarget,sign)
    @echo + ld $@
    $(V)$(LD) $(LDFLAGS) -N -e start -Ttext 0x7C00 $^ -o $(call toobj,bootblock)
    @$(OBJDUMP) -S $(call objfile,bootblock) > $(call asmfile,bootblock)
    @$(OBJCOPY) -S -O binary $(call objfile,bootblock) $(call outfile,bootblock)
    @$(call totarget,sign) $(call outfile,bootblock) $(bootblock)
    
$(call create_target,bootblock)
````
其中,生成bootblock需要先生成bootasm.o和bootmain.o以及sign.
通过命令`make V=`我们可以看到,gcc编译bootasm.S和bootmain.生成bootasm.o以及bootmain.o.并通过ld命令将二者链接生成bootblock.o,其中`-Ttext 0x7C00`将初始地址重定向至`0x7C00`.并且采用`i386-elf-objcopy -S -O binary obj/bootblock.o obj/bootblock.out`命令去除bootblock.o中的标志和重定位信息并输出到bootblock.out. 
而后gcc编译生成sign工具.sign工具读入bootblock.out并生成一个只有512字节的引导文件bootblock,并将其中最后两个字节设定为`0x55AA`.

而生成kernel的代码如下:
````makefile
$(kernel): tools/kernel.ld

$(kernel): $(KOBJS)
	@echo + ld $@
	$(V)$(LD) $(LDFLAGS) -T tools/kernel.ld -o $@ $(KOBJS)
	@$(OBJDUMP) -S $@ > $(call asmfile,kernel)
	@$(OBJDUMP) -t $@ | $(SED) '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $(call symfile,kernel)

$(call create_target,kernel)
````
可以看到,要链接生成kernel需要kern目录下的.c文件全部编译生成对应的.o文件.然后根据链接脚本kernel.ld来链接生成.
### 2. 一个被系统认为是符合规范的硬盘主引导扇区的特征是什么?
- 磁盘主引导扇区只有512字节
- 磁盘最后两个字节为`0x55AA`
- ~~由不超过466字节的启动代码和不超过64字节的硬盘分区表加上两个字节的结束符组成~~(ucore未实现)
***
## 练习2
> 使用qemu执行并调试lab1中的软件

我们可以通过`make debug`命令对ucore进行调试,其对应在makefile中的代码为:
````makefile
debug: $(UCOREIMG)
	$(V)$(QEMU) -S -s -parallel stdio -hda $< -serial null &
	$(V)sleep 2
	$(V)$(TERMINAL) gdb -q -tui -x tools/gdbinit
````
可以看到我们首先启动了一个qemu虚拟机,并加载ucore硬盘映像,同时使用`-S -s`参数使其停在启始位置并等待gdb的连接.

等待2秒后运行gdb,并使用`-x tools/gdbinit`运行相应gdb脚本,脚本代码如下:
````
file bin/kernel
target remote :1234
break kern_init
continue
````
其中脚本所做的工作为:
1. 加载二进制kernel文件
2. 连接到端口1234
3. 在`kern_init()`函数设置断点
4. 继续虚拟机的运行
***
## 练习3
> 分析bootloader进入保护模式的过程
### 1. 为何开启A20,以及如何开启A20
当A20关闭时,cpu为了兼容8086,在寻址1MB以上空间时会发生回绕.所以在进入保护模式时,要将A20置1,使得全部32条地址线可用.以下是开启A20的代码:
````x86asm
    # Enable A20:
    #  For backwards compatibility with the earliest PCs, physical
    #  address line 20 is tied low, so that addresses higher than
    #  1MB wrap around to zero by default. This code undoes this.
seta20.1:
    inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
    testb $0x2, %al
    jnz seta20.1

    movb $0xd1, %al                                 # 0xd1 -> port 0x64
    outb %al, $0x64                                 # 0xd1 means: write data to 8042's P2 port

seta20.2:
    inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
    testb $0x2, %al
    jnz seta20.2

    movb $0xdf, %al                                 # 0xdf -> port 0x60
    outb %al, $0x60                                 # 0xdf = 11011111, means set P2's A20 bit(the 1 bit) to 1
````
### 2. 如何初始化GDT表
* 加载GDT表
````x86asm
lgdt gdtdesc
````
### 3. 如何使能和进入保护模式
* 将CR0的第0位置1(开启段机制)
````x86asm
movl %cr0, %eax
orl $CR0_PE_ON, %eax
movl %eax, %cr0
````
* 长跳转到32位代码段,重装CS和EIP 
````x86asm
ljmp $PROT_MODE_CSEG, $protcseg
````
* 重装DS,ES等寄存器
````x86asm
# Set up the protected-mode data segment registers
movw $PROT_MODE_DSEG, %ax                       # Our data segment selector
movw %ax, %ds                                   # -> DS: Data Segment
movw %ax, %es                                   # -> ES: Extra Segment
movw %ax, %fs                                   # -> FS
movw %ax, %gs                                   # -> GS
movw %ax, %ss                                   # -> SS: Stack Segment
````
* 设置ebp和esp栈寄存器,准备调用c函数
````x86asm
# Set up the stack pointer and call into C. The stack region is from 0--start(0x7c00)
movl $0x0, %ebp
movl $start, %esp
call bootmain
````
***
## 练习4:
> 分析bootloader加载ELF格式的OS的过程

以下是`bootmain()`的代码:
````cpp
/* bootmain - the entry of bootloader */
void
bootmain(void) {
    // read the 1st page off disk
    readseg((uintptr_t)ELFHDR, SECTSIZE * 8, 0);

    // is this a valid ELF?
    if (ELFHDR->e_magic != ELF_MAGIC) {
        goto bad;
    }

    struct proghdr *ph, *eph;

    // load each program segment (ignores ph flags)
    ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
    eph = ph + ELFHDR->e_phnum;
    for (; ph < eph; ph ++) {
        readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
    }

    // call the entry point from the ELF header
    // note: does not return
    ((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();

bad:
    outw(0x8A00, 0x8A00);
    outw(0x8A00, 0x8E00);

    /* do nothing */
    while (1);
}
````
### 1. bootloader如何读取硬盘扇区的?
从`bootmain()`函数中可以看出,首先是调用了`readseg()`函数来读取硬盘扇区,而`readseg()`函数则循环调用了真正读取硬盘扇区的函数`readsect()`,`readsect()`的代码如下:
````cpp
/* readsect - read a single sector at @secno into @dst */
static void
readsect(void *dst, uint32_t secno) {
    // wait for disk to be ready
    waitdisk();

    outb(0x1F2, 1);                         // count = 1
    outb(0x1F3, secno & 0xFF);
    outb(0x1F4, (secno >> 8) & 0xFF);
    outb(0x1F5, (secno >> 16) & 0xFF);
    outb(0x1F6, ((secno >> 24) & 0xF) | 0xE0);
    outb(0x1F7, 0x20);                      // cmd 0x20 - read sectors

    // wait for disk to be ready
    waitdisk();

    // read a sector
    insl(0x1F0, dst, SECTSIZE / 4);
}
````
### 2. bootloader是如何加载ELF格式的OS?
* 判断是否是ELF格式
````cpp
// is this a valid ELF?
if (ELFHDR->e_magic != ELF_MAGIC) {
    goto bad;
}
````
* 读取ELF文件头,并根据文件头的描述从硬盘读入每个程序段
````cpp
// load each program segment (ignores ph flags)
ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
eph = ph + ELFHDR->e_phnum;
for (; ph < eph; ph ++) {
    readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
}
````
* 根据ELF文件头提供的入口信息,找到内核的入口并开始运行
````cpp
// call the entry point from the ELF header
// note: does not return
((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();
````
***
## 练习5
> 实现函数调用堆栈跟踪函数

> 一个函数调用动作可分解为零到多个 PUSH指令(用于参数入栈)和一个 CALL 指令.CALL 指令内部其实还暗含了一个将返回地址压栈的动作,这是由硬件完成的.几乎所有本地编译器都会在每个函数体之前插入类似如下的汇编指令：
>>  ````x86asm
    pushl %ebp
    movl %esp,%ebp
    ````

> 原ebp值已经被压栈(位于栈顶),而新的ebp又恰恰指向栈顶.此时ebp寄存器就已经处于一个
非常重要的地位,该寄存器中存储着栈中的一个地址(原 ebp入栈后的栈顶),从该地址为基准,
向上(栈底方向)能获取返回地址、参数值,向下(栈顶方向)能获取函数局部变量值,而该地址
处又存储着上一层函数调用时的ebp值.
而由此我们可以直接根据ebp就能读取到各个栈帧的地址和值,一般而言,ss:[ebp+4]处为返回地址,ss:[ebp+8]处为第一个参数值(最后一个入栈的参数值,此处假设其占用 4 字节内存,对应32位系统),ss:[ebp-4]处为第一个局部变量,ss:[ebp]处为上一层 ebp 值.
> 堆栈示意图如下:
>> | 栈底方向 | 高位地址 |
| :---- | :----: |
| ... |
| ... |
| 参数3 |
| 参数2 |
| 参数1 |
| 返回地址 |
| 上一层[ebp] | <---[ebp] |
| 居部变量 | 低位地址 |

由此我们可以在kdebug.c的`print_stackframe()`中添加相应代码来跟踪函数调用栈:
````cpp
void
print_stackframe(void) {
    uint32_t ebp = read_ebp(); //获取本层的ebp
    uint32_t eip = read_eip(); //通过read_eip()内的ebp+4来或取上一层的eip
    int i = 0;
    while (i<STACKFRAME_DEPTH && ebp!=0) {

        uint32_t *args = (uint32_t*)ebp + 2;
        cprintf("ebp:0x%08x eip:0x%08x args:0x%08x 0x%08x 0x%08x 0x%08x\n",ebp,eip,
                args[0],args[1],args[2],args[3]);
        print_debuginfo(eip-1);

        eip = *((uint32_t*)ebp+1); //通过本层的ebp+4来获取上一层的eip
        ebp = *(uint32_t*)ebp;

        ++i;
    }
}
````
***
## 练习6
> 完善中断初始化和处理
### 1. 中断描述符表(也可简称为保护模式下的中断向量表)中一个表项占多少字节?其中哪几位代表中断处理代码的入口?
一个表项占8个字节.其中0\~15位和48\~63位分别为offset的低16位和高16位.16\~31位为段选择子.通过段选择子获得段基址,加上段内偏移量即可得到中断处理代码的入口.
### 2. 请编程完善kern/trap/trap.c中对中断向量表进行初始化的函数`idt_init()`
* 声明存放中断服务程序入口地址的数组`__vectors[]`
````cpp
extern uintptr_t __vectors[];
````
* 填充中断描述符表IDT
````cpp
for (int i=0;i<256;++i)
    SETGATE(idt[i],0,GD_KTEXT,__vectors[i],DPL_KERNEL);
// set for switch from user to kernel
SETGATE(idt[T_SWITCH_TOK], 0, GD_KTEXT, __vectors[T_SWITCH_TOK], DPL_USER);
````
* 加载中断描述符表
````cpp
// load the IDT
lidt(&idt_pd);
````

mmu.h中对`SETGATE`的定义为:
````cpp
#define SETGATE(gate, istrap, sel, off, dpl)
````

其参数为:

| 参数 | 解释 |
| :----: | ---- |
| gate | 为相应的idt[]数组内容,处理函数的入口地址 |
| istrap | 系统段设置为1,中断门设置为0 |
| sel | 段选择子 |
| off | 为__vectors[]数组内容 |
| dpl | 设置特权级.这里中断都设置为内核级,即第0级 |

### 3. 请编程完善trap.c中的中断处理函数`trap()`
在`trap_dispatch()`的相应中断处理`case IRQ_OFFSET + IRQ_TIMER`中调用`print_ticks()`:
````cpp
case IRQ_OFFSET + IRQ_TIMER:
    if (ticks++%TICK_NUM == 0) print_ticks();
    break;
````
***
## 扩展练习 Challenge 1
> 扩展proj4,增加syscall功能,即增加一用户态函数(可执行一特定系统调用:获得时钟计数值),当内核初始完闭后,可从内核态返回到用户态的函数,而用户态的函数又通过系统调用得到内核态的服务

调用函数`lab1_switch_to_user()`从内核态转到用户态:
````cpp
static void
lab1_switch_to_user(void) {
    //LAB1 CHALLENGE 1 : TODO
    asm volatile (
        "sub $0x8, %%esp \n"
        "int %0 \n"
        "movl %%ebp, %%esp"
        :
        : "i"(T_SWITCH_TOU)
    );
}
````
其中内联汇编的含意为:
* 空出8个字节以模拟跨特权级时trapframe中特有的部分
````x86asm
sub $0x8, %%esp
````
其中特有的部分为:
````cpp
uintptr_t tf_esp;
uint16_t tf_ss;
uint16_t tf_padding5;
````
* 调用相应的陷入指令
````x86asm
int %0
````
* 恢复调用前的栈帧
````x86asm
movl %%ebp, %%esp
````

之后在trap.c中处理相关的中断服务:
* 用一块空间来当做临时的trapframe
````cpp
switchk2u = *tf;
````
* 将相关的寄存器设置为用户态对应的值
````cpp
switchk2u.tf_cs = USER_CS;
switchk2u.tf_ds = switchk2u.tf_es = switchk2u.tf_ss = USER_DS;
````
* 将真正调用前的esp赋给tf_esp
````cpp
switchk2u.tf_esp = (uint32_t)tf + sizeof(struct trapframe) -8;
````
* 降低IO指令特权级
````cpp
switchk2u.tf_eflags |= FL_IOPL_MASK;
````
* 将临时空间的地址赋给堆栈作之后返回用 
````cpp
  *((uint32_t *)tf - 1) = (uint32_t)&switchk2u;
````

调用函数`lab1_switch_to_kernel()`从用户态转到内核态:
````cpp
static void
lab1_switch_to_kernel(void) {
    asm volatile (
        "int %0 \n"
        "movl %%ebp, %%esp \n"
        :
        : "i"(T_SWITCH_TOK)
    );
}
````
其中内联汇编的含意为:
* 调用相应的陷入指令
````x86asm
int %0
````
* 恢复调用前的栈帧
````x86asm
movl %%ebp, %%esp
````

之后在trap.c中处理相关的中断服务:
* 将相关寄存器设置为内核态对应的值
````cpp
tf->tf_cs = KERNEL_CS;
tf->tf_ds = tf->tf_es = KERNEL_DS;
````
* 提升IO指令特权级
````cpp
tf->tf_eflags &= ~FL_IOPL_MASK;
````
* 伪造出同特权级调用的trapframe以返回内核态
````cpp
switchu2k = (struct trapframe *)(tf->tf_esp - (sizeof(struct trapframe) - 8));
memmove(switchu2k, tf, sizeof(struct trapframe) - 8);
````
* 修改存在堆栈的地址
````cpp
  *((uint32_t *)tf - 1) = (uint32_t)switchu2k;
````

特别注意:
* 在vectors.S中,除了中断8\~14和17,其余中断硬件均不会压入error code;需要指令`pushl $0`压入一个0来占位
* 在trapentry.S中,存在指令`addl $0x8, %esp`来跳过trap number和error code
***
## 扩展练习 Challenge 2
> 用键盘实现用户模式内核模式的切换

在`kern_init()`函数最后的死循换中加入相关代码来读取键盘输入并调用`lab1_switch_to_user()`和`lab1_switch_to_kernel()`函数来切换特权级:
````cpp
while (1) {
    char c = getchar();
    cprintf("serial [%03d] %c\n", c, c);
    switch (c) {
        case '0':
            cprintf("+++ switch to  user  mode +++\n");
            lab1_switch_to_user();
            lab1_print_cur_status();
            break;
        case '3':
            cprintf("+++ switch to kernel mode +++\n");
            lab1_switch_to_kernel();
            lab1_print_cur_status();
            break;
        default:
            break;
    }
}
````

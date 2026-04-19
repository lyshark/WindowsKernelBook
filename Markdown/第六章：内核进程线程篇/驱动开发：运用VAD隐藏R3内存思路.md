---
title: 驱动开发：运用VAD隐藏R3内存思路
copyright: true
date: '2023-5-3 10:40'
description: >-
  在进程的`_EPROCESS`中有一个`_RTL_AVL_TREE`类型的`VadRoot`成员，它是一个存放进程内存块的二叉树结构，如果我们找到了这个二叉树中我们想要隐藏的内存，直接将这个内存在二叉树中`抹去`，其实是让上一个节点的`EndingVpn`指向下个节点的`EndingVpn`，类似于摘链隐藏进程，就可以达到隐藏的效果。VadRoot成员是一个指向二叉树结构的指针，用于存储一个进程的虚拟地址描述符（VAD）对象。每个VAD对象描述了进程的一段虚拟地址空间。VAD对象的起始地址和结束地址都是按照一定顺序组成的二叉树结构来管理的，以便于快速地查找和操作。
tags:
  - '《Windows 内核安全编程技术实践》'
  - '第六章：内核进程线程篇'
categories: '《Windows 内核安全编程技术实践》'
abbrlink: 'c0c86505'
---

在进程的`_EPROCESS`中有一个`_RTL_AVL_TREE`类型的`VadRoot`成员，它是一个存放进程内存块的二叉树结构，如果我们找到了这个二叉树中我们想要隐藏的内存，直接将这个内存在二叉树中`抹去`，其实是让上一个节点的`EndingVpn`指向下个节点的`EndingVpn`，类似于摘链隐藏进程，就可以达到隐藏的效果。

在Windows内核中，VadRoot成员是一个指向二叉树结构的指针，用于存储一个进程的虚拟地址描述符（VAD）对象。每个VAD对象描述了进程的一段虚拟地址空间。VAD对象的起始地址和结束地址都是按照一定顺序组成的二叉树结构来管理的，以便于快速地查找和操作。

如果想要隐藏某个内存区域，可以通过修改相应的VAD对象来实现。具体来说，可以在VAD树中搜索到包含该内存区域的VAD对象，然后将其从树中移除。这个过程可以通过将该VAD对象的父节点的`LeftChild`或`RightChild`指向该VAD对象的子节点来实现。这样一来，该VAD对象就不再在VAD树中了，而该内存区域也就被隐藏了。

通过`dt _EPROCESS`得到EProcess结构`VadRoot`如下:

![](./image/1379525-20221013155034526-1855943313.png)

例如当调用`VirtualAlloc`分配内存空间。
```c
#include <iostream>
#include <Windows.h>

int main(int argc, char *argv[])
{
	LPVOID p1 = VirtualAlloc(NULL, 0x10000, MEM_COMMIT, PAGE_READWRITE);
	LPVOID p2 = VirtualAlloc(NULL, 0x10000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	std::cout << "address = " << p1 << std::endl;
	std::cout << "address2 = " << p2 << std::endl;

	getchar();
	return 0;
}
```

运行程序得到两个内存地址`0xf00000`和`0xfe0000`

![](./image/1379525-20221013155411897-523414677.png)

通过`!process 0 0`枚举所有进程，并得到我们所需进程的EProcess地址。

![](./image/1379525-20221013155734246-1751543775.png)

检查进程`!process ffffe28fbb451080`得到`VAD`地址`ffffe28fbe0b7e40`

![](./image/1379525-20221013155926230-1592829217.png)

此处以`0xf00000`为例，这里我们看到`windbg`中的值和进程中分配的内存地址并不完全一样，这是因为`x86 cpu`默认内存页大小`4k`也就是`0x1000`，所以这里还要再乘以`0x1000`才是真正的内存地址。

![](./image/1379525-20221013160549607-684432063.png)

所以计算结果刚好等于`0xf00000`

![](./image/1379525-20221013160712153-911821650.png)

而隐藏进程内特定内存段核心代码在于`p1->EndingVpn = p2->EndingVpn;`将VAD前后节点连接。
```c
PMMVAD p1 = vad_enum((PMMVAD)VadRoot, 0x3a0); // 遍历第一个结点
PMMVAD p2 = vad_enum((PMMVAD)VadRoot, 0x3b0); // 遍历找到第二个结点
if (p1 && p2)
{
p1->EndingVpn = p2->EndingVpn; // 将第二个结点完全隐藏起来
}
```

需要注意，这种方法只是将VAD对象从树中移除，并没有真正释放内存区域，如果想要真正释放该内存区域，还需要调用相应的内核函数来释放该内存。此外，这种方法可能会破坏系统稳定性，因为隐藏进程的行为可能会影响系统的正常运行。因此，建议谨慎使用这种方法。
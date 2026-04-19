---
title: 驱动开发：内核枚举SSDT表基址
copyright: true
date: '2023-4-25 14:01'
description: >-
  在SSDT枚举篇的第一部分，我们将介绍如何枚举SSDT表。我们将详细介绍如何在内核中定位SSDT表、如何遍历SSDT表中的每个系统API函数、以及如何获取这些函数的地址和相关信息。我们还将提供实例演示，帮助读者更好地理解这些技术的实现方法和步骤。通过本文，读者将了解如何在内核驱动程序中实现对SSDT表和SSSDT表的枚举，以及如何利用这些表来实现驱动保护和系统监控。我们将提供详细的示例代码和实例演示，帮助读者更好地理解这些技术的实现方法和步骤。
tags:
	- '《Windows 内核安全编程技术实践》'
	- '第五章：内核SSDT枚举篇'
categories: '《Windows 内核安全编程技术实践》'
abbrlink: '9e8b6c5d'
---

本文将重点介绍内核如何枚举SSDT表和SSSDT表，这两个表是操作系统内核中非常重要的一部分，它们记录了系统API函数和系统服务函数的地址和相关信息。因此，枚举这些表是实现许多驱动保护和系统监控的关键步骤。

在本文中，我们将逐步介绍如何使用内核驱动程序来枚举SSDT表和SSSDT表。我们将详细介绍如何获取内核的地址空间、如何定位这些表、如何遍历这些表、以及如何获取这些表中函数的地址和相关信息。我们还将介绍如何使用这些信息来实现一些常见的驱动保护和系统监控功能，例如API钩子、系统调用监控和根套接字过滤等。

在SSDT枚举篇的第一部分，我们将介绍如何枚举SSDT表。我们将详细介绍如何在内核中定位SSDT表、如何遍历SSDT表中的每个系统API函数、以及如何获取这些函数的地址和相关信息。我们还将提供实例演示，帮助读者更好地理解这些技术的实现方法和步骤。

在SSDT枚举篇的第二部分，我们将介绍如何枚举SSSDT表。我们将详细介绍如何在内核中定位SSSDT表、如何遍历SSSDT表中的每个系统服务函数、以及如何获取这些函数的地址和相关信息。我们还将提供实例演示，帮助读者更好地理解这些技术的实现方法和步骤。

通过本文，读者将了解如何在内核驱动程序中实现对SSDT表和SSSDT表的枚举，以及如何利用这些表来实现驱动保护和系统监控。我们将提供详细的示例代码和实例演示，帮助读者更好地理解这些技术的实现方法和步骤。

微软的`Windows 10`系统已经覆盖了大多数个人PC终端，以前的方法也该进行迭代更新了，或许在网上你能够找到类似的文章，但我可以百分百肯定都不能用，今天`LyShark`将带大家一起分析`Win10 x64`最新系统`SSDT`表的枚举实现。

看一款闭源ARK工具的枚举效果:

![](./image/1379525-20221018213523969-1153296140.png)

直接步入正题，首先`SSDT`表中文为系统服务描述符表，SSDT表的`作用`是把`应用`层与`内核`层`联系起来`起到`桥梁`的作用，枚举`SSDT表`也是`反内核`工具最基本的功能，通常在`64位`系统中要想找到`SSDT`表，需要先找到`KeServiceDescriptorTable`这个函数，由于该函数没有被导出，所以只能动态的查找它的地址，庆幸的是我们可以通过查找`msr(c0000082)`这个特殊的寄存器来替代查找`KeServiceDescriptorTable`这一步，在新版系统中查找SSDT可以归纳为如下这几个步骤。

- rdmsr c0000082 -> KiSystemCall64Shadow -> KiSystemServiceUser -> SSDT

首先第一步通过`rdmsr C0000082` MSR寄存器得到`KiSystemCall64Shadow`的函数地址，计算`KiSystemCall64Shadow`与`KiSystemServiceUser`偏移量，如下图所示。

 - 得到相对偏移`6ed53180(KiSystemCall64Shadow) - 6ebd2a82(KiSystemServiceUser) = 1806FE`
 - 也就是说 `6ed53180(rdmsr) - 1806FE = KiSystemServiceUser`

![](./image/1379525-20221019095901194-2089380036.png)

如上当我们找到了`KiSystemServiceUser`的地址以后，在`KiSystemServiceUser`向下搜索可找到`KiSystemServiceRepeat`里面就是我们要找的`SSDT`表基址。

其中`fffff8036ef8c880`则是`SSDT表`的基地址，紧随其后的`fffff8036ef74a80`则是`SSSDT表`的基地址。

![](./image/1379525-20221019100441631-1244464583.png)

那么如果将这个过程通过代码的方式来实现，我们还需要使用`《内核枚举IoTimer定时器》`中所使用的特征码定位技术，如下我们查找这段特征。
```c
#include <ntifs.h>
#pragma intrinsic(__readmsr)

ULONGLONG ssdt_address = 0;

// 获取 KeServiceDescriptorTable 首地址
ULONGLONG GetLySharkCOMKeServiceDescriptorTable()
{
	// 设置起始位置
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082) - 0x1806FE;

	// 设置结束位置
	PUCHAR EndSearchAddress = StartSearchAddress + 0x100000;
	DbgPrint("[LyShark Search] 扫描起始地址: %p --> 扫描结束地址: %p \n", StartSearchAddress, EndSearchAddress);

	PUCHAR ByteCode = NULL;

	UCHAR OpCodeA = 0, OpCodeB = 0, OpCodeC = 0;
	ULONGLONG addr = 0;
	ULONG templong = 0;

	for (ByteCode = StartSearchAddress; ByteCode < EndSearchAddress; ByteCode++)
	{
		// 使用MmIsAddressValid()函数检查地址是否有页面错误
		if (MmIsAddressValid(ByteCode) && MmIsAddressValid(ByteCode + 1) && MmIsAddressValid(ByteCode + 2))
		{
			OpCodeA = *ByteCode;
			OpCodeB = *(ByteCode + 1);
			OpCodeC = *(ByteCode + 2);

			// 对比特征值 寻找 nt!KeServiceDescriptorTable 函数地址
			/*
			nt!KiSystemServiceRepeat:
			fffff803`6ebd2b94 4c8d15e59c3b00  lea     r10,[nt!KeServiceDescriptorTable (fffff803`6ef8c880)]
			fffff803`6ebd2b9b 4c8d1dde1e3a00  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff803`6ef74a80)]
			fffff803`6ebd2ba2 f7437880000000  test    dword ptr [rbx+78h],80h
			fffff803`6ebd2ba9 7413            je      nt!KiSystemServiceRepeat+0x2a (fffff803`6ebd2bbe)  Branch
			*/
			if (OpCodeA == 0x4c && OpCodeB == 0x8d && OpCodeC == 0x15)
			{
				// 获取高位地址fffff802
				memcpy(&templong, ByteCode + 3, 4);

				// 与低位64da4880地址相加得到完整地址
				addr = (ULONGLONG)templong + (ULONGLONG)ByteCode + 7;
				return addr;
			}
		}
	}
	return  0;
}

VOID UnDriver(PDRIVER_OBJECT driver)
{
	DbgPrint(("驱动程序卸载成功! \n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DbgPrint("hello lyshark.com");

	ssdt_address = GetLySharkCOMKeServiceDescriptorTable();
	DbgPrint("[LyShark] SSDT = %p \n", ssdt_address);

	DriverObject->DriverUnload = UnDriver;
	return STATUS_SUCCESS;
}
```

如上代码中所提及的步骤我想不需要再做解释了，这段代码运行后即可输出SSDT表的基址。

![](./image/1379525-20221019101526281-783656916.png)

如上通过调用`GetLySharkCOMKeServiceDescriptorTable()`得到`SSDT`地址以后我们就需要对该地址进行解密操作。

得到`ServiceTableBase`的地址后，就能得到每个服务函数的地址。但这个表存放的并不是`SSDT`函数的完整地址，而是其相对于`ServiceTableBase[Index]>>4`的数据，每个数据占四个字节，所以计算指定`Index`函数完整地址的公式是；

 - 在x86平台上: FuncAddress = KeServiceDescriptorTable + 4 * Index
 - 在x64平台上：FuncAddress = [KeServiceDescriptorTable+4*Index]>>4 + KeServiceDescriptorTable

如下汇编代码就是一段解密代码，代码中`rcx`寄存器传入SSDT的下标，而`rdx`寄存器则是传入SSDT表基址。
```c
  48:8BC1                  | mov rax,rcx                             |  rcx=index
  4C:8D12                  | lea r10,qword ptr ds:[rdx]              |  rdx=ssdt
  8BF8                     | mov edi,eax                             |
  C1EF 07                  | shr edi,7                               |
  83E7 20                  | and edi,20                              |
  4E:8B1417                | mov r10,qword ptr ds:[rdi+r10]          |
  4D:631C82                | movsxd r11,dword ptr ds:[r10+rax*4]     |
  49:8BC3                  | mov rax,r11                             |
  49:C1FB 04               | sar r11,4                               |
  4D:03D3                  | add r10,r11                             |
  49:8BC2                  | mov rax,r10                             |
  C3                       | ret                                     |
```
有了解密公式以后代码的编写就变得很容易，如下是读取SSDT的完整代码。
```c
#include <ntifs.h>
#pragma intrinsic(__readmsr)

typedef struct _SYSTEM_SERVICE_TABLE
{
	PVOID     ServiceTableBase;
	PVOID     ServiceCounterTableBase;
	ULONGLONG   NumberOfServices;
	PVOID     ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

ULONGLONG ssdt_base_aadress;
PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

typedef UINT64(__fastcall *SCFN)(UINT64, UINT64);
SCFN scfn;

// 解密算法
VOID DecodeSSDT()
{
	UCHAR strShellCode[36] = "\x48\x8B\xC1\x4C\x8D\x12\x8B\xF8\xC1\xEF\x07\x83\xE7\x20\x4E\x8B\x14\x17\x4D\x63\x1C\x82\x49\x8B\xC3\x49\xC1\xFB\x04\x4D\x03\xD3\x49\x8B\xC2\xC3";
	/*
	48:8BC1                  | mov rax,rcx                             |  rcx=index
	4C:8D12                  | lea r10,qword ptr ds:[rdx]              |  rdx=ssdt
	8BF8                     | mov edi,eax                             |
	C1EF 07                  | shr edi,7                               |
	83E7 20                  | and edi,20                              |
	4E:8B1417                | mov r10,qword ptr ds:[rdi+r10]          |
	4D:631C82                | movsxd r11,dword ptr ds:[r10+rax*4]     |
	49:8BC3                  | mov rax,r11                             |
	49:C1FB 04               | sar r11,4                               |
	4D:03D3                  | add r10,r11                             |
	49:8BC2                  | mov rax,r10                             |
	C3                       | ret                                     |
	*/
	scfn = ExAllocatePool(NonPagedPool, 36);
	memcpy(scfn, strShellCode, 36);
}

// 获取 KeServiceDescriptorTable 首地址
ULONGLONG GetKeServiceDescriptorTable()
{
	// 设置起始位置
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082) - 0x1806FE;

	// 设置结束位置
	PUCHAR EndSearchAddress = StartSearchAddress + 0x8192;
	DbgPrint("扫描起始地址: %p --> 扫描结束地址: %p \n", StartSearchAddress, EndSearchAddress);

	PUCHAR ByteCode = NULL;

	UCHAR OpCodeA = 0, OpCodeB = 0, OpCodeC = 0;
	ULONGLONG addr = 0;
	ULONG templong = 0;

	for (ByteCode = StartSearchAddress; ByteCode < EndSearchAddress; ByteCode++)
	{
		// 使用MmIsAddressValid()函数检查地址是否有页面错误
		if (MmIsAddressValid(ByteCode) && MmIsAddressValid(ByteCode + 1) && MmIsAddressValid(ByteCode + 2))
		{
			OpCodeA = *ByteCode;
			OpCodeB = *(ByteCode + 1);
			OpCodeC = *(ByteCode + 2);

			// 对比特征值 寻找 nt!KeServiceDescriptorTable 函数地址
			// LyShark.com
			// 4c 8d 15 e5 9e 3b 00  lea r10,[nt!KeServiceDescriptorTable (fffff802`64da4880)]
			// 4c 8d 1d de 20 3a 00  lea r11,[nt!KeServiceDescriptorTableShadow (fffff802`64d8ca80)]
			if (OpCodeA == 0x4c && OpCodeB == 0x8d && OpCodeC == 0x15)
			{
				// 获取高位地址fffff802
				memcpy(&templong, ByteCode + 3, 4);

				// 与低位64da4880地址相加得到完整地址
				addr = (ULONGLONG)templong + (ULONGLONG)ByteCode + 7;
				return addr;
			}
		}
	}
	return  0;
}

// 得到函数相对偏移地址
ULONG GetOffsetAddress(ULONGLONG FuncAddr)
{
	ULONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;
	if (KeServiceDescriptorTable == NULL)
	{
		KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTable();
	}
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = (ULONG)(FuncAddr - (ULONGLONG)ServiceTableBase);
	return dwtmp << 4;
}

// 根据序号得到函数地址
ULONGLONG GetSSDTFunctionAddress(ULONGLONG NtApiIndex)
{
	ULONGLONG ret = 0;
	if (ssdt_base_aadress == 0)
	{
		// 得到ssdt基地址
		ssdt_base_aadress = GetKeServiceDescriptorTable();
	}
	if (scfn == NULL)
	{
		DecodeSSDT();
	}
	ret = scfn(NtApiIndex, ssdt_base_aadress);
	return ret;
}

VOID UnDriver(PDRIVER_OBJECT driver)
{
	DbgPrint(("驱动程序卸载成功! \n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DbgPrint("hello lyshark.com \n");

	ULONGLONG ssdt_address = GetKeServiceDescriptorTable();
	DbgPrint("SSDT基地址 = %p \n", ssdt_address);

	// 根据序号得到函数地址
	ULONGLONG address = GetSSDTFunctionAddress(51);
	DbgPrint("[LyShark] NtOpenFile地址 = %p \n", address);
	 
	// 得到相对SSDT的偏移量
	DbgPrint("函数相对偏移地址 = %p \n", GetOffsetAddress(address));

	DriverObject->DriverUnload = UnDriver;
	return STATUS_SUCCESS;
}
```

运行后即可得到`SSDT`下标为`51`的函数也就是得到`NtOpenFile`的绝对地址和相对地址。

![](./image/1379525-20221019103344768-563715669.png)

你也可以打开ARK工具，对比一下是否一致，如下图所示，`LyShark`的代码是没有任何问题的。

![](./image/1379525-20221019103445885-197467968.png)

根据上述方法的内容进行扩展，枚举完整SSDT表我们可以这样来实现，通过循环一个列表依次输出所有的SSDT字符串并得到其地址，代码如下所示；
```c
#include <ntifs.h>

#pragma intrinsic(__readmsr)

typedef struct _SYSTEM_SERVICE_TABLE
{
	PVOID     ServiceTableBase;
	PVOID     ServiceCounterTableBase;
	ULONGLONG   NumberOfServices;
	PVOID     ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

ULONGLONG ssdt_base_aadress;
PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

typedef UINT64(__fastcall *SCFN)(UINT64, UINT64);
SCFN scfn;

// 解密算法
VOID DecodeSSDT()
{
	UCHAR strShellCode[36] = "\x48\x8B\xC1\x4C\x8D\x12\x8B\xF8\xC1\xEF\x07\x83\xE7\x20\x4E\x8B\x14\x17\x4D\x63\x1C\x82\x49\x8B\xC3\x49\xC1\xFB\x04\x4D\x03\xD3\x49\x8B\xC2\xC3";
	/*
	48:8BC1                  | mov rax,rcx                             |  rcx=index
	4C:8D12                  | lea r10,qword ptr ds:[rdx]              |  rdx=ssdt
	8BF8                     | mov edi,eax                             |
	C1EF 07                  | shr edi,7                               |
	83E7 20                  | and edi,20                              |
	4E:8B1417                | mov r10,qword ptr ds:[rdi+r10]          |
	4D:631C82                | movsxd r11,dword ptr ds:[r10+rax*4]     |
	49:8BC3                  | mov rax,r11                             |
	49:C1FB 04               | sar r11,4                               |
	4D:03D3                  | add r10,r11                             |
	49:8BC2                  | mov rax,r10                             |
	C3                       | ret                                     |
	*/
	scfn = ExAllocatePool(NonPagedPool, 36);
	memcpy(scfn, strShellCode, 36);
}

// 获取 KeServiceDescriptorTable 首地址
ULONGLONG GetKeServiceDescriptorTable()
{
	// 设置起始位置
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082) - 0x1806FE;

	// 设置结束位置
	PUCHAR EndSearchAddress = StartSearchAddress + 0x8192;
	// DbgPrint("扫描起始地址: %p --> 扫描结束地址: %p \n", StartSearchAddress, EndSearchAddress);

	PUCHAR ByteCode = NULL;

	UCHAR OpCodeA = 0, OpCodeB = 0, OpCodeC = 0;
	ULONGLONG addr = 0;
	ULONG templong = 0;

	for (ByteCode = StartSearchAddress; ByteCode < EndSearchAddress; ByteCode++)
	{
		// 使用MmIsAddressValid()函数检查地址是否有页面错误
		if (MmIsAddressValid(ByteCode) && MmIsAddressValid(ByteCode + 1) && MmIsAddressValid(ByteCode + 2))
		{
			OpCodeA = *ByteCode;
			OpCodeB = *(ByteCode + 1);
			OpCodeC = *(ByteCode + 2);

			// 对比特征值 寻找 nt!KeServiceDescriptorTable 函数地址
			// LyShark.com
			// 4c 8d 15 e5 9e 3b 00  lea r10,[nt!KeServiceDescriptorTable (fffff802`64da4880)]
			// 4c 8d 1d de 20 3a 00  lea r11,[nt!KeServiceDescriptorTableShadow (fffff802`64d8ca80)]
			if (OpCodeA == 0x4c && OpCodeB == 0x8d && OpCodeC == 0x15)
			{
				// 获取高位地址fffff802
				memcpy(&templong, ByteCode + 3, 4);

				// 与低位64da4880地址相加得到完整地址
				addr = (ULONGLONG)templong + (ULONGLONG)ByteCode + 7;
				return addr;
			}
		}
	}
	return  0;
}

// 得到函数相对偏移地址
ULONG GetOffsetAddress(ULONGLONG FuncAddr)
{
	ULONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;
	if (KeServiceDescriptorTable == NULL)
	{
		KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTable();
	}
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = (ULONG)(FuncAddr - (ULONGLONG)ServiceTableBase);
	return dwtmp << 4;
}

// 根据序号得到函数地址
ULONGLONG GetSSDTFunctionAddress(ULONGLONG NtApiIndex)
{
	ULONGLONG ret = 0;
	if (ssdt_base_aadress == 0)
	{
		// 得到ssdt基地址
		ssdt_base_aadress = GetKeServiceDescriptorTable();
	}
	if (scfn == NULL)
	{
		DecodeSSDT();
	}
	ret = scfn(NtApiIndex, ssdt_base_aadress);
	return ret;
}

// 查询函数系统地址
ULONG_PTR QueryFunctionSystemAddress(PWCHAR name)
{
	UNICODE_STRING na;
	ULONG_PTR address;
	RtlInitUnicodeString(&na, name);
	address = (ULONG_PTR)MmGetSystemRoutineAddress(&na);
	return address;
}

VOID UnDriver(PDRIVER_OBJECT driver)
{
	DbgPrint(("驱动程序卸载成功! \n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DbgPrint("hello lyshark.com \n");

	char *SSDT[464] = { "NtAccessCheck", "NtWorkerFactoryWorkerReady", "NtAcceptConnectPort", "NtMapUserPhysicalPagesScatter", "NtWaitForSingleObject", "NtCallbackReturn", "NtReadFile", "NtDeviceIoControlFile", "NtWriteFile", "NtRemoveIoCompletion", "NtReleaseSemaphore", "NtReplyWaitReceivePort", "NtReplyPort", "NtSetInformationThread", "NtSetEvent", "NtClose", "NtQueryObject", "NtQueryInformationFile", "NtOpenKey", "NtEnumerateValueKey", "NtFindAtom", "NtQueryDefaultLocale", "NtQueryKey", "NtQueryValueKey", "NtAllocateVirtualMemory", "NtQueryInformationProcess", "NtWaitForMultipleObjects32", "NtWriteFileGather", "NtSetInformationProcess", "NtCreateKey", "NtFreeVirtualMemory", "NtImpersonateClientOfPort", "NtReleaseMutant", "NtQueryInformationToken", "NtRequestWaitReplyPort", "NtQueryVirtualMemory", "NtOpenThreadToken", "NtQueryInformationThread", "NtOpenProcess", "NtSetInformationFile", "NtMapViewOfSection", "NtAccessCheckAndAuditAlarm", "NtUnmapViewOfSection", "NtReplyWaitReceivePortEx", "NtTerminateProcess", "NtSetEventBoostPriority", "NtReadFileScatter", "NtOpenThreadTokenEx", "NtOpenProcessTokenEx", "NtQueryPerformanceCounter", "NtEnumerateKey", "NtOpenFile", "NtDelayExecution", "NtQueryDirectoryFile", "NtQuerySystemInformation", "NtOpenSection", "NtQueryTimer", "NtFsControlFile", "NtWriteVirtualMemory", "NtCloseObjectAuditAlarm", "NtDuplicateObject", "NtQueryAttributesFile", "NtClearEvent", "NtReadVirtualMemory", "NtOpenEvent", "NtAdjustPrivilegesToken", "NtDuplicateToken", "NtContinue", "NtQueryDefaultUILanguage", "NtQueueApcThread", "NtYieldExecution", "NtAddAtom", "NtCreateEvent", "NtQueryVolumeInformationFile", "NtCreateSection", "NtFlushBuffersFile", "NtApphelpCacheControl", "NtCreateProcessEx", "NtCreateThread", "NtIsProcessInJob", "NtProtectVirtualMemory", "NtQuerySection", "NtResumeThread", "NtTerminateThread", "NtReadRequestData", "NtCreateFile", "NtQueryEvent", "NtWriteRequestData", "NtOpenDirectoryObject", "NtAccessCheckByTypeAndAuditAlarm", "NtQuerySystemTime", "NtWaitForMultipleObjects", "NtSetInformationObject", "NtCancelIoFile", "NtTraceEvent", "NtPowerInformation", "NtSetValueKey", "NtCancelTimer", "NtSetTimer", "NtAccessCheckByType", "NtAccessCheckByTypeResultList", "NtAccessCheckByTypeResultListAndAuditAlarm", "NtAccessCheckByTypeResultListAndAuditAlarmByHandle", "NtAcquireProcessActivityReference", "NtAddAtomEx", "NtAddBootEntry", "NtAddDriverEntry", "NtAdjustGroupsToken", "NtAdjustTokenClaimsAndDeviceGroups", "NtAlertResumeThread", "NtAlertThread", "NtAlertThreadByThreadId", "NtAllocateLocallyUniqueId", "NtAllocateReserveObject", "NtAllocateUserPhysicalPages", "NtAllocateUuids", "NtAllocateVirtualMemoryEx", "NtAlpcAcceptConnectPort", "NtAlpcCancelMessage", "NtAlpcConnectPort", "NtAlpcConnectPortEx", "NtAlpcCreatePort", "NtAlpcCreatePortSection", "NtAlpcCreateResourceReserve", "NtAlpcCreateSectionView", "NtAlpcCreateSecurityContext", "NtAlpcDeletePortSection", "NtAlpcDeleteResourceReserve", "NtAlpcDeleteSectionView", "NtAlpcDeleteSecurityContext", "NtAlpcDisconnectPort", "NtAlpcImpersonateClientContainerOfPort", "NtAlpcImpersonateClientOfPort", "NtAlpcOpenSenderProcess", "NtAlpcOpenSenderThread", "NtAlpcQueryInformation", "NtAlpcQueryInformationMessage", "NtAlpcRevokeSecurityContext", "NtAlpcSendWaitReceivePort", "NtAlpcSetInformation", "NtAreMappedFilesTheSame", "NtAssignProcessToJobObject", "NtAssociateWaitCompletionPacket", "NtCallEnclave", "NtCancelIoFileEx", "NtCancelSynchronousIoFile", "NtCancelTimer2", "NtCancelWaitCompletionPacket", "NtCommitComplete", "NtCommitEnlistment", "NtCommitRegistryTransaction", "NtCommitTransaction", "NtCompactKeys", "NtCompareObjects", "NtCompareSigningLevels", "NtCompareTokens", "ArbPreprocessEntry", "NtCompressKey", "NtConnectPort", "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter", "ArbAddReserved", "NtCreateDebugObject", "NtCreateDirectoryObject", "NtCreateDirectoryObjectEx", "NtCreateEnclave", "NtCreateEnlistment", "NtCreateEventPair", "NtCreateIRTimer", "NtCreateIoCompletion", "NtCreateJobObject", "ArbAddReserved", "NtCreateKeyTransacted", "NtCreateKeyedEvent", "NtCreateLowBoxToken", "NtCreateMailslotFile", "NtCreateMutant", "NtCreateNamedPipeFile", "NtCreatePagingFile", "NtCreatePartition", "NtCreatePort", "NtCreatePrivateNamespace", "NtCreateProcess", "NtCreateProfile", "NtCreateProfileEx", "NtCreateRegistryTransaction", "NtCreateResourceManager", "NtCreateSectionEx", "NtCreateSemaphore", "NtCreateSymbolicLinkObject", "NtCreateThreadEx", "NtCreateTimer", "NtCreateTimer2", "NtCreateToken", "NtCreateTokenEx", "NtCreateTransaction", "NtCreateTransactionManager", "NtCreateUserProcess", "NtCreateWaitCompletionPacket", "NtCreateWaitablePort", "NtCreateWnfStateName", "NtCreateWorkerFactory", "NtDebugActiveProcess", "NtDebugContinue", "NtDeleteAtom", "NtDeleteBootEntry", "NtDeleteDriverEntry", "NtDeleteFile", "NtDeleteKey", "NtDeleteObjectAuditAlarm", "NtDeletePrivateNamespace", "NtDeleteValueKey", "NtDeleteWnfStateData", "NtDeleteWnfStateName", "NtDisableLastKnownGood", "NtDisplayString", "NtDrawText", "NtEnableLastKnownGood", "NtEnumerateBootEntries", "NtEnumerateDriverEntries", "NtEnumerateSystemEnvironmentValuesEx", "NtEnumerateTransactionObject", "NtExtendSection", "NtFilterBootOption", "NtFilterToken", "NtFilterTokenEx", "NtFlushBuffersFileEx", "NtFlushInstallUILanguage", "ArbPreprocessEntry", "NtFlushKey", "NtFlushProcessWriteBuffers", "NtFlushVirtualMemory", "NtFlushWriteBuffer", "NtFreeUserPhysicalPages", "NtFreezeRegistry", "NtFreezeTransactions", "NtGetCachedSigningLevel", "NtGetCompleteWnfStateSubscription", "NtGetContextThread", "NtGetCurrentProcessorNumber", "NtGetCurrentProcessorNumberEx", "NtGetDevicePowerState", "NtGetMUIRegistryInfo", "NtGetNextProcess", "NtGetNextThread", "NtGetNlsSectionPtr", "NtGetNotificationResourceManager", "NtGetWriteWatch", "NtImpersonateAnonymousToken", "NtImpersonateThread", "NtInitializeEnclave", "NtInitializeNlsFiles", "NtInitializeRegistry", "NtInitiatePowerAction", "NtIsSystemResumeAutomatic", "NtIsUILanguageComitted", "NtListenPort", "NtLoadDriver", "NtLoadEnclaveData", "NtLoadKey", "NtLoadKey2", "NtLoadKeyEx", "NtLockFile", "NtLockProductActivationKeys", "NtLockRegistryKey", "NtLockVirtualMemory", "NtMakePermanentObject", "NtMakeTemporaryObject", "NtManageHotPatch", "NtManagePartition", "NtMapCMFModule", "NtMapUserPhysicalPages", "NtMapViewOfSectionEx", "NtModifyBootEntry", "NtModifyDriverEntry", "NtNotifyChangeDirectoryFile", "NtNotifyChangeDirectoryFileEx", "NtNotifyChangeKey", "NtNotifyChangeMultipleKeys", "NtNotifyChangeSession", "NtOpenEnlistment", "NtOpenEventPair", "NtOpenIoCompletion", "NtOpenJobObject", "NtOpenKeyEx", "NtOpenKeyTransacted", "NtOpenKeyTransactedEx", "NtOpenKeyedEvent", "NtOpenMutant", "NtOpenObjectAuditAlarm", "NtOpenPartition", "NtOpenPrivateNamespace", "NtOpenProcessToken", "NtOpenRegistryTransaction", "NtOpenResourceManager", "NtOpenSemaphore", "NtOpenSession", "NtOpenSymbolicLinkObject", "NtOpenThread", "NtOpenTimer", "NtOpenTransaction", "NtOpenTransactionManager", "NtPlugPlayControl", "NtPrePrepareComplete", "NtPrePrepareEnlistment", "NtPrepareComplete", "NtPrepareEnlistment", "NtPrivilegeCheck", "NtPrivilegeObjectAuditAlarm", "NtPrivilegedServiceAuditAlarm", "NtPropagationComplete", "NtPropagationFailed", "NtPulseEvent", "NtQueryAuxiliaryCounterFrequency", "NtQueryBootEntryOrder", "NtQueryBootOptions", "NtQueryDebugFilterState", "NtQueryDirectoryFileEx", "NtQueryDirectoryObject", "NtQueryDriverEntryOrder", "NtQueryEaFile", "NtQueryFullAttributesFile", "NtQueryInformationAtom", "NtQueryInformationByName", "NtQueryInformationEnlistment", "NtQueryInformationJobObject", "NtQueryInformationPort", "NtQueryInformationResourceManager", "NtQueryInformationTransaction", "NtQueryInformationTransactionManager", "NtQueryInformationWorkerFactory", "NtQueryInstallUILanguage", "NtQueryIntervalProfile", "NtQueryIoCompletion", "NtQueryLicenseValue", "NtQueryMultipleValueKey", "NtQueryMutant", "NtQueryOpenSubKeys", "NtQueryOpenSubKeysEx", "CmpCleanUpHigherLayerKcbCachesPreCallback", "NtQueryQuotaInformationFile", "NtQuerySecurityAttributesToken", "NtQuerySecurityObject", "NtQuerySecurityPolicy", "NtQuerySemaphore", "NtQuerySymbolicLinkObject", "NtQuerySystemEnvironmentValue", "NtQuerySystemEnvironmentValueEx", "NtQuerySystemInformationEx", "NtQueryTimerResolution", "NtQueryWnfStateData", "NtQueryWnfStateNameInformation", "NtQueueApcThreadEx", "NtRaiseException", "NtRaiseHardError", "NtReadOnlyEnlistment", "NtRecoverEnlistment", "NtRecoverResourceManager", "NtRecoverTransactionManager", "NtRegisterProtocolAddressInformation", "NtRegisterThreadTerminatePort", "NtReleaseKeyedEvent", "NtReleaseWorkerFactoryWorker", "NtRemoveIoCompletionEx", "NtRemoveProcessDebug", "NtRenameKey", "NtRenameTransactionManager", "NtReplaceKey", "NtReplacePartitionUnit", "NtReplyWaitReplyPort", "NtRequestPort", "NtResetEvent", "NtResetWriteWatch", "NtRestoreKey", "NtResumeProcess", "NtRevertContainerImpersonation", "NtRollbackComplete", "NtRollbackEnlistment", "NtRollbackRegistryTransaction", "NtRollbackTransaction", "NtRollforwardTransactionManager", "NtSaveKey", "NtSaveKeyEx", "NtSaveMergedKeys", "NtSecureConnectPort", "NtSerializeBoot", "NtSetBootEntryOrder", "NtSetBootOptions", "NtSetCachedSigningLevel", "NtSetCachedSigningLevel2", "NtSetContextThread", "NtSetDebugFilterState", "NtSetDefaultHardErrorPort", "NtSetDefaultLocale", "NtSetDefaultUILanguage", "NtSetDriverEntryOrder", "NtSetEaFile", "NtSetHighEventPair", "NtSetHighWaitLowEventPair", "NtSetIRTimer", "NtSetInformationDebugObject", "NtSetInformationEnlistment", "NtSetInformationJobObject", "NtSetInformationKey", "NtSetInformationResourceManager", "NtSetInformationSymbolicLink", "NtSetInformationToken", "NtSetInformationTransaction", "NtSetInformationTransactionManager", "NtSetInformationVirtualMemory", "NtSetInformationWorkerFactory", "NtSetIntervalProfile", "NtSetIoCompletion", "NtSetIoCompletionEx", "BvgaSetVirtualFrameBuffer", "NtSetLowEventPair", "NtSetLowWaitHighEventPair", "NtSetQuotaInformationFile", "NtSetSecurityObject", "NtSetSystemEnvironmentValue", "NtSetSystemEnvironmentValueEx", "NtSetSystemInformation", "NtSetSystemPowerState", "NtSetSystemTime", "NtSetThreadExecutionState", "NtSetTimer2", "NtSetTimerEx", "NtSetTimerResolution", "NtSetUuidSeed", "NtSetVolumeInformationFile", "NtSetWnfProcessNotificationEvent", "NtShutdownSystem", "NtShutdownWorkerFactory", "NtSignalAndWaitForSingleObject", "NtSinglePhaseReject", "NtStartProfile", "NtStopProfile", "NtSubscribeWnfStateChange", "NtSuspendProcess", "NtSuspendThread", "NtSystemDebugControl", "NtTerminateEnclave", "NtTerminateJobObject", "NtTestAlert", "NtThawRegistry", "NtThawTransactions", "NtTraceControl", "NtTranslateFilePath", "NtUmsThreadYield", "NtUnloadDriver", "NtUnloadKey", "NtUnloadKey2", "NtUnloadKeyEx", "NtUnlockFile", "NtUnlockVirtualMemory", "NtUnmapViewOfSectionEx", "NtUnsubscribeWnfStateChange", "NtUpdateWnfStateData", "NtVdmControl", "NtWaitForAlertByThreadId", "NtWaitForDebugEvent", "NtWaitForKeyedEvent", "NtWaitForWorkViaWorkerFactory", "NtWaitHighEventPair", "NtWaitLowEventPair" };

	for (size_t lyshark = 0; lyshark < 464; lyshark++)
	{
		// 获取起源地址
		ANSI_STRING ansi = { 0 };
		UNICODE_STRING uncode = { 0 };

		ULONGLONG ssdt_address = GetKeServiceDescriptorTable();
		// DbgPrint("SSDT基地址 = %p \n", ssdt_address);

		// 根据序号得到函数地址
		ULONGLONG address = GetSSDTFunctionAddress(lyshark);
		ULONG offset = GetOffsetAddress(address);

		RtlInitAnsiString(&ansi, SSDT[lyshark]);
		RtlAnsiStringToUnicodeString(&uncode, &ansi, TRUE);
		PULONGLONG source_address = MmGetSystemRoutineAddress(&uncode);
		DbgPrint("[LyShark] 序号 => [%d] | 当前地址 => %p | 起源地址 => %p | 相对地址 => %p | SSDT => %s \n", lyshark, address, source_address, offset, SSDT[lyshark]);
	}

	DriverObject->DriverUnload = UnDriver;
	return STATUS_SUCCESS;
}
```

我们运行这段程序，即可得到整个系统中所有的SSDT表地址信息；

![](/image/1379525-20221019135751165-36856509.png)

在WinDBG中可看到完整的输出内容，当然有些函数没有被导出，起源地址是拿不到的。

![](/image/1379525-20221019135920083-233649646.png)

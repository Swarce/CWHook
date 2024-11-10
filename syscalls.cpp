#define PHNT_VERSION PHNT_WIN10_22H2
#include <phnt_windows.h>
#include <phnt.h>
#include <ntexapi.h>
#include <ntpsapi.h>
#include <minidumpapiset.h>
#include <cstdint>
#include <iostream>

#include "syscalls.h"

uint64_t SetInformationSysCall = 0x0;
uint64_t CreateThreadSysCall = 0x0;
uint64_t QueryInformationSysCall = 0x0;
uint64_t CreateThreadExSysCall = 0x0;
uint64_t QueryInformationProcessSysCall = 0x0;
uint64_t QuerySystemInformationSysCall = 0x0;
uint64_t CreateFileSysCall = 0x0;
uint64_t AllocateVirtualMemorySysCall = 0x0;
uint64_t ProtectVirtualMemorySysCall = 0x0;
uint64_t NtQueryObjectSysCall = 0x0;
uint64_t NtCreateDebugObjectSysCall = 0x0;
uint64_t NtCloseSysCall = 0x0;

void SetSyscallsFromNtdll()
{
	HMODULE ntdllModule = GetModuleHandle("ntdll.dll");

	if (ntdllModule != NULL)
	{
		void* NtSetInformationThreadAddr		= (void*)GetProcAddress(ntdllModule, "NtSetInformationThread");
		void* NtCreateThreadAddr				= (void*)GetProcAddress(ntdllModule, "NtCreateThread");
		void* NtQueryInformationThreadAddr		= (void*)GetProcAddress(ntdllModule, "NtQueryInformationThread");
		void* NtCreateThreadExAddr				= (void*)GetProcAddress(ntdllModule, "NtCreateThreadEx");
		void* NtQueryInformationProcessAddr		= (void*)GetProcAddress(ntdllModule, "NtQueryInformationProcess");
		void* NtQuerySystemInformationAddr		= (void*)GetProcAddress(ntdllModule, "NtQuerySystemInformation");
		void* NtCreateFileAddr					= (void*)GetProcAddress(ntdllModule, "NtCreateFile");
		void* NtAllocateVirtualMemoryAddr		= (void*)GetProcAddress(ntdllModule, "NtAllocateVirtualMemory");
		void* ProtectVirtualMemorySysCallAddr	= (void*)GetProcAddress(ntdllModule, "NtProtectVirtualMemory");
		void* NtQueryObjectAddr					= (void*)GetProcAddress(ntdllModule, "NtQueryObject");
		void* NtCreateDebugObjectAddr			= (void*)GetProcAddress(ntdllModule, "NtCreateDebugObject");
		void* NtCloseAddr						= (void*)GetProcAddress(ntdllModule, "NtClose");

		SetInformationSysCall			= *(uint32_t*)((char*)NtSetInformationThreadAddr + 0x4);
		CreateThreadSysCall				= *(uint32_t*)((char*)NtCreateThreadAddr + 0x4);
		QueryInformationSysCall			= *(uint32_t*)((char*)NtQueryInformationThreadAddr + 0x4);
		CreateThreadExSysCall			= *(uint32_t*)((char*)NtCreateThreadExAddr + 0x4);
		QueryInformationProcessSysCall	= *(uint32_t*)((char*)NtQueryInformationProcessAddr + 0x4);
		QuerySystemInformationSysCall	= *(uint32_t*)((char*)NtQuerySystemInformationAddr + 0x4);
		CreateFileSysCall				= *(uint32_t*)((char*)NtCreateFileAddr + 0x4);
		AllocateVirtualMemorySysCall	= *(uint32_t*)((char*)NtAllocateVirtualMemoryAddr + 0x4);
		ProtectVirtualMemorySysCall		= *(uint32_t*)((char*)ProtectVirtualMemorySysCallAddr + 0x4);
		NtQueryObjectSysCall			= *(uint32_t*)((char*)NtQueryObjectAddr + 0x4);
		NtCreateDebugObjectSysCall		= *(uint32_t*)((char*)NtCreateDebugObjectAddr + 0x4);
		NtCloseSysCall					= *(uint32_t*)((char*)NtCloseAddr + 0x4);
	}
}
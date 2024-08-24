#include <asmjit/core/operand.h>
#include <asmjit/x86/x86operand.h>
#include <cstring>
#define PHNT_VERSION PHNT_WIN10_22H2
#include <phnt_windows.h>
#include <phnt.h>
#include <ntexapi.h>
#include <ntpsapi.h>
#include <minidumpapiset.h>

#include <TlHelp32.h>
#include <mmeapi.h>

#include <filesystem>
#include <string.h>
#include <stdio.h>
#include <vector>
#include <intrin.h>
#include <string>
#include <string_view>
#include <iostream>
#include <filesystem>

#include <asmjit/core/jitruntime.h>
#include <asmjit/x86/x86assembler.h>

#include "libs/patterns/Hooking.Patterns.h"
#include "libs/minhook/include/MinHook.h"
#include "restorentdll.h"
#include "utils.h"
#include "systemhooks.h"
#include "arxan.h"
#include "paths.h"
#include "syscalls.h"

std::vector<intactChecksumHook> intactchecksumHooks;
std::vector<intactBigChecksumHook> intactBigchecksumHooks;
std::vector<splitChecksumHook> splitchecksumHooks;

LPVOID ntdllAsmStubLocation;

inlineAsmStub* inlineStubs = nullptr;
size_t stubCounter = 0;

int fixChecksum(uint64_t rbpOffset, uint64_t ptrOffset, uint64_t* ptrStack, uint32_t jmpInstructionDistance, uint32_t calculatedChecksumFromArg)
{
	// get size of image from codcw
	uint64_t baseAddressStart = (uint64_t)GetModuleHandle(nullptr);
	IMAGE_DOS_HEADER* pDOSHeader = (IMAGE_DOS_HEADER*)GetModuleHandle(nullptr);
	IMAGE_NT_HEADERS* pNTHeaders =(IMAGE_NT_HEADERS*)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
	auto sizeOfImage = pNTHeaders->OptionalHeader.SizeOfImage;
	uint64_t baseAddressEnd = baseAddressStart + sizeOfImage;

	// check if our checksum hooks got overwritten
	// we could probably ifdef this now but it's a good indicator to know if our checksum hooks still exist
	{
		for (int i=0; i < intactchecksumHooks.size(); i++)
		{
			DWORD old_protect{};

			if (memcmp(intactchecksumHooks[i].functionAddress, intactchecksumHooks[i].buffer, sizeof(uint8_t) * 7))
			{
				uint64_t idaAddress = (uint64_t)intactchecksumHooks[i].functionAddress - baseAddressStart + StartOfBinary;

				printf("%llx %llx got changed\n", idaAddress, (uint64_t)intactchecksumHooks[i].functionAddress);
				fprintf(logFile, "%llx got changed\n", idaAddress);
				fflush(logFile);
			}

			VirtualProtect(intactchecksumHooks[i].functionAddress, sizeof(uint8_t) * 7, PAGE_EXECUTE_READWRITE, &old_protect);
			memcpy(intactchecksumHooks[i].functionAddress, intactchecksumHooks[i].buffer, sizeof(uint8_t) * 7);
			VirtualProtect(intactchecksumHooks[i].functionAddress, sizeof(uint8_t) * 7, old_protect, &old_protect);
			FlushInstructionCache(GetCurrentProcess(), intactchecksumHooks[i].functionAddress, sizeof(uint8_t) * 7);
		}

		for (int i=0; i < intactBigchecksumHooks.size(); i++)
		{
			DWORD old_protect{};

			if (memcmp(intactBigchecksumHooks[i].functionAddress, intactBigchecksumHooks[i].buffer, sizeof(uint8_t) * 7))
			{
				uint64_t idaAddress = (uint64_t)intactBigchecksumHooks[i].functionAddress - baseAddressStart + StartOfBinary;

				printf("%llx %llx got changed\n", idaAddress, (uint64_t)intactBigchecksumHooks[i].functionAddress);
				fprintf(logFile, "%llx got changed\n", idaAddress);
				fflush(logFile);
			}
			
			VirtualProtect(intactBigchecksumHooks[i].functionAddress, sizeof(uint8_t) * 10, PAGE_EXECUTE_READWRITE, &old_protect);
			memcpy(intactBigchecksumHooks[i].functionAddress, intactBigchecksumHooks[i].buffer, sizeof(uint8_t) * 10);
			VirtualProtect(intactBigchecksumHooks[i].functionAddress, sizeof(uint8_t) * 10, old_protect, &old_protect);
			FlushInstructionCache(GetCurrentProcess(), intactBigchecksumHooks[i].functionAddress, sizeof(uint8_t) * 10);
		}

		for (int i=0; i < splitchecksumHooks.size(); i++)
		{
			DWORD old_protect{};

			if (memcmp(splitchecksumHooks[i].functionAddress, splitchecksumHooks[i].buffer, sizeof(uint8_t) * 7))
			{
				uint64_t idaAddress = (uint64_t)splitchecksumHooks[i].functionAddress - baseAddressStart + StartOfBinary;

				printf("%llx %llx got changed\n", idaAddress, (uint64_t)splitchecksumHooks[i].functionAddress);
				fprintf(logFile, "%llx got changed\n", idaAddress);
				fflush(logFile);
			}
			
			VirtualProtect(splitchecksumHooks[i].functionAddress, sizeof(uint8_t) * 8, PAGE_EXECUTE_READWRITE, &old_protect);
			memcpy(splitchecksumHooks[i].functionAddress, splitchecksumHooks[i].buffer, sizeof(uint8_t) * 8);
			VirtualProtect(splitchecksumHooks[i].functionAddress, sizeof(uint8_t) * 8, old_protect, &old_protect);
			FlushInstructionCache(GetCurrentProcess(), splitchecksumHooks[i].functionAddress, sizeof(uint8_t) * 8);
		}
	}

	static int fixChecksumCalls = 0;
	fixChecksumCalls++;

	uint32_t calculatedChecksum = calculatedChecksumFromArg;
	uint32_t reversedChecksum = reverse_bytes(calculatedChecksumFromArg);
	uint32_t* calculatedChecksumPtr = (uint32_t*)((char*)ptrStack+0x120); // 0x120 is a good starting point to decrement downwards to find the calculated checksum on the stack
	uint32_t* calculatedReversedChecksumPtr = (uint32_t*)((char*)ptrStack+0x120); // 0x120 is a good starting point to decrement downwards to find the calculated checksum on the stack

	bool doubleTextChecksum = false;
	uint64_t* previousResultPtr = nullptr;
	if (ptrOffset == 0 && rbpOffset < 0x90)
	{
		uint64_t* textPtr = (uint64_t*)((char*)ptrStack+rbpOffset + (rbpOffset % 0x8)); // make sure rbpOffset is aligned by 8 bytes
		int pointerCounter = 0;

		for (int i=0; i < 20; i++)
		{
			uint64_t derefPtr = *(uint64_t*)textPtr;

			if (derefPtr >= baseAddressStart && derefPtr <= baseAddressEnd)
			{
				uint64_t derefResult = **(uint64_t**)textPtr;
				pointerCounter++;

				// store the ptr above 0xffffffffffffffff and then use it in our originalchecksum check
				if (derefResult == 0xffffffffffffffff)
				{
					if (pointerCounter > 2)
					{
						doubleTextChecksum = true;

						// because textptr will be pointing at 0xffffffffffffffff, increment it once 
						// so we are pointing to the correct checksum location

						// TODO: remove this, doesnt do anything, confirm with checksum 0x79d397c8
						// since we use previousResultPtr which doesnt rely on this
						textPtr++;
					}

					break;
				}

				previousResultPtr = textPtr;
			}

			textPtr--;
		}
	}
	else
	{	// for debugging stack traces on bigger rbp offset checksums
		uint64_t* textPtr = (uint64_t*)((char*)ptrStack+rbpOffset + (rbpOffset % 0x8)); // make sure rbpOffset is aligned by 8 bytes

		for (int i=0; i < 30; i++)
		{
			uint64_t derefPtr = *(uint64_t*)textPtr;

			if (derefPtr >= baseAddressStart && derefPtr <= baseAddressEnd)
				uint64_t derefResult = **(uint64_t**)textPtr;

			textPtr--;
		}
	}

	// find calculatedChecksumPtr, we will overwrite this later with the original checksum
	for (int i=0; i < 80; i++)
	{
		uint32_t derefPtr = *(uint32_t*)calculatedChecksumPtr;

		if (derefPtr == calculatedChecksum)
			break;

		calculatedChecksumPtr--;
	}

	// find calculatedReversedChecksumPtr, we will overwrite this later with the original checksum
	for (int i=0; i < 80; i++)
	{
		uint32_t derefPtr = *(uint32_t*)calculatedReversedChecksumPtr;

		if (derefPtr == reversedChecksum)
			break;

		calculatedReversedChecksumPtr--;
	}

	uint64_t* textPtr = (uint64_t*)((char*)ptrStack+rbpOffset + (rbpOffset % 0x8)); // add remainder to align ptr
	uint32_t originalChecksum = NULL;
	uint32_t* originalChecksumPtr = nullptr;

	// searching for a .text pointer that points to the original checksum, upwards from the rbp	
	for (int i=0; i < 10; i++)
	{
		uint64_t derefPtr = *(uint64_t*)textPtr;

		if (derefPtr >= baseAddressStart && derefPtr <= baseAddressEnd)
		{
			if (ptrOffset == 0 && rbpOffset < 0x90)
			{
				if (doubleTextChecksum)
					originalChecksum = **(uint32_t**)previousResultPtr; 
				else
					originalChecksum = *(uint32_t*)derefPtr; 
			}
			else
			{
				originalChecksum = *(uint32_t*)((char*)derefPtr+ptrOffset*4); // if ptrOffset is used the original checksum is in a different spot
				originalChecksumPtr = (uint32_t*)((char*)derefPtr+ptrOffset*4);
			}
			
			break;
		}

		textPtr--;
	}

	*calculatedChecksumPtr = (uint32_t)originalChecksum;
	*calculatedReversedChecksumPtr = reverse_bytes((uint32_t)originalChecksum);

	// for big intact we need to keep overwriting 4 more times
	// seems to still run even if we comment this out wtf?
	uint32_t* tmpOriginalChecksumPtr = originalChecksumPtr;
	uint32_t* tmpCalculatedChecksumPtr = calculatedChecksumPtr;
	uint32_t* tmpReversedChecksumPtr = calculatedReversedChecksumPtr;
	if (originalChecksumPtr != nullptr)
	{
		for (int i=0; i <= ptrOffset; i++)
		{
			*tmpCalculatedChecksumPtr = *(uint32_t*)tmpOriginalChecksumPtr;
			*tmpReversedChecksumPtr = reverse_bytes(*(uint32_t*)tmpOriginalChecksumPtr);

			tmpOriginalChecksumPtr--;
			tmpCalculatedChecksumPtr--;
			tmpReversedChecksumPtr--;
		}
	}
	
	return originalChecksum;
}


NTSTATUS ntdllSyscallSetInformation(HANDLE handle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
{
	DWORD flags;
	if (ThreadInformation == 0 && ThreadInformationLength == 0 && (GetHandleInformation(handle, &flags) != 0))
	{
		return 0;
	}
	else
		return 0xc0000008;
}

NTSTATUS ntdllSyscallQueryInformation(HANDLE handle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
{
	if (weAreDebugging)
		return 0x1337;

	DWORD flags;
	if (ThreadInformationLength == sizeof(BOOLEAN) && (GetHandleInformation(handle, &flags) != 0))
	{
		char* info = (char*)ThreadInformation;
		*info = 1;
		return 0;
	}
	else
		return 0x80000002;
}

NTSTATUS ntdllSyscallCreateThreadEx(PHANDLE ThreadHandle, NTSTATUS syscallResult)
{
	NTSTATUS setThreadResult = SetThreadContextOrig(*(PHANDLE*)ThreadHandle, &context);

	return syscallResult;
}

void ntdllSyscallCreateThread()
{
	// TODO: if this gets called we would need to do setthreadcontext
	printf("thread created inside\n");
}

void ntdllQueryInformationProcess(PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation)
{
	switch(ProcessInformationClass)
	{
		// TODO: we aren't setting ntstatus to 0xC0000353 if debugobjecthandle is true
		case ProcessDebugObjectHandle:
		case ProcessDebugPort:
			memset(ProcessInformation, 0x0, sizeof(uint8_t) * 8);
			break;
		case ProcessImageFileName:
		case ProcessImageFileNameWin32:
			if (ProcessInformation != nullptr)
				remove_evil_keywords_from_string(*static_cast<UNICODE_STRING*>(ProcessInformation));
			break;
		case ProcessDebugFlags:
			memset(ProcessInformation, 1, sizeof(uint64_t));
			break;
		default:
			break;
	}
}

void ntdllQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation)
{
	switch(SystemInformationClass)
	{
		// TODO: we aren't setting ntstatus to 0xC0000353 if debugobjecthandle is true
		case SystemProcessInformation:
		case SystemSessionProcessInformation:
		case SystemExtendedProcessInformation:
		case SystemFullProcessInformation:
			uint8_t* addr;
			addr = (uint8_t*)(SystemInformation);

			SYSTEM_PROCESS_INFORMATION* previousInfo;

			while (true)
			{
				SYSTEM_PROCESS_INFORMATION* info;
				info = (SYSTEM_PROCESS_INFORMATION*)addr;

				if (info->ImageName.Buffer != nullptr)
					if (remove_evil_keywords_from_string(info->ImageName))
						previousInfo->NextEntryOffset += info->NextEntryOffset;

				previousInfo = (SYSTEM_PROCESS_INFORMATION*)addr;

				if (!info->NextEntryOffset)
					return;

				addr = addr + info->NextEntryOffset;
			}
			break;
		case SystemHandleInformation:
		case SystemExtendedHandleInformation:
			printf("\nchecked for handle information\n");
			break;
		default:
			break;
	}
}

void checkIfWIN32UGetsCalled()
{
	printf("got called!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	SuspendAllThreads();
	__debugbreak();
}

// TODO: check if arxan cares if we even handle this case
//#pragma optimize( "", off )
/*
NTSTATUS ntdllCreateFile(PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength)
{
	OBJECT_ATTRIBUTES objAttributes = { 0 };
	UNICODE_STRING unicodeString = { 0 };

	wchar_t* fileName = ObjectAttributes->ObjectName->Buffer;

	if (wcscmp(fileName, L"\\??\\C:\\Windows\\System32\\GDI32.dll") == 0)
	{
		RtlInitUnicodeString(&unicodeString, win32u_dir);
		InitializeObjectAttributes(&objAttributes, &unicodeString, OBJ_CASE_INSENSITIVE, 0, NULL);
		ObjectAttributes = &objAttributes;
		return 0x1337;
	}

	if (wcscmp(fileName, L"\\??\\C:\\Windows\\System32\\USER32.dll") == 0)
	{
		RtlInitUnicodeString(&unicodeString, win32u_dir);
		InitializeObjectAttributes(&objAttributes, &unicodeString, OBJ_CASE_INSENSITIVE, 0, NULL);
		ObjectAttributes = &objAttributes;
		return 0x1337;
	}

	if (wcscmp(fileName, L"\\??\\C:\\Windows\\System32\\win32u.dll") == 0)
	{
		RtlInitUnicodeString(&unicodeString, win32u_dir);
		InitializeObjectAttributes(&objAttributes, &unicodeString, OBJ_CASE_INSENSITIVE, 0, NULL);
		ObjectAttributes = &objAttributes;
		return 0x1337;
	}

	return 0x0;
}
*/
//#pragma optimize( "", on )

void ntdllAsmStub()
{
	hook::pattern syscallLocations = hook::module_pattern(GetModuleHandle("ntdll.dll"), "4C 8B D1 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? 0F 05");
	size_t syscallCount = syscallLocations.size();

	printf("ntdll syscallCount %d\n", syscallCount);

	// allocate asm stub rwx page
	const size_t allocationSize = sizeof(uint8_t) * 128;
	ntdllAsmStubLocation = allocate_somewhere_near(GetModuleHandle("ntdll.dll"), allocationSize);
	memset(ntdllAsmStubLocation, 0x90, allocationSize);
	printf("ntdll stub location %llx\n", ntdllAsmStubLocation);

	// assembly stub
	static asmjit::JitRuntime runtime;
	asmjit::CodeHolder code;
	code.init(runtime.environment());

	using namespace asmjit::x86;
	Assembler a(&code);

	asmjit::Label L1 = a.newLabel();
	asmjit::Label SetInformation = a.newLabel();
	asmjit::Label QueryInformation = a.newLabel();
	asmjit::Label CreateThreadEx = a.newLabel();
	asmjit::Label CreateThread = a.newLabel();
	asmjit::Label RegularSyscall = a.newLabel();
	asmjit::Label QueryInformationProcess = a.newLabel();
	asmjit::Label QueryInformationProcess_L1 = a.newLabel();
	asmjit::Label QuerySystemInformation = a.newLabel();
	asmjit::Label QuerySystemInformation_L1 = a.newLabel();
	asmjit::Label QuerySystemInformation_L2 = a.newLabel();
	asmjit::Label DEBUG = a.newLabel();

	a.test(byte_ptr(0x7FFE0308), 1);
	a.jnz(L1);

	a.cmp(rax, SetInformationSysCall);
	a.je(SetInformation);
	a.cmp(rax, QueryInformationSysCall);
	a.je(QueryInformation);
	a.cmp(rax, CreateThreadSysCall);
	a.je(CreateThread);
	a.cmp(rax, CreateThreadExSysCall);
	a.je(CreateThreadEx);

	a.cmp(rax, QueryInformationProcessSysCall);	// NtQueryInformationProcessAddr
	a.je(QueryInformationProcess);
	a.cmp(rax, QuerySystemInformationSysCall);	// NtQuerySystemInformationAddr
	a.je(QuerySystemInformation);

	//a.cmp(rax, CreateFileSysCall);
	//a.je(CreateFile);

	a.bind(RegularSyscall);
		a.syscall();
		a.ret();

	a.bind(L1);
		a.int_(0x2E);
		a.ret();

#if 1
	a.bind(DEBUG);
	a.int3();
	a.jmp(DEBUG);
#endif

	// rdi has the address location?
	a.bind(QueryInformationProcess);
		a.cmp(rdx, ProcessImageFileNameWin32);
		a.je(QueryInformationProcess_L1);
		a.cmp(rdx, ProcessImageFileName);
		a.je(QueryInformationProcess_L1);
		a.cmp(rdx, ProcessDebugPort);
		a.je(QueryInformationProcess_L1);
		a.cmp(rdx, ProcessDebugFlags);
		a.je(QueryInformationProcess_L1);
		a.cmp(rdx, ProcessDebugObjectHandle);
		a.je(QueryInformationProcess_L1);

		// else do regular syscall
		a.jmp(RegularSyscall);

	a.bind(QueryInformationProcess_L1);
		a.movq(xmm14, rdx);  // ProcessInformationClass
		a.movq(xmm15, r8); // ProcessInformation

		a.syscall();

		#if 0
		a.bind(DEBUG);
		a.int3();
		a.jmp(DEBUG);
		#endif

		pushad64();

		a.movq(rcx, xmm14);
		a.movq(rdx, xmm15);

		a.sub(rsp, 0x20);
		a.call(ntdllQueryInformationProcess);
		a.add(rsp, 0x20);

		popad64();

		a.push(rax);
		a.mov(rax, 0);
		a.movq(xmm14, rax);
		a.movq(xmm15, rax);
		a.pop(rax);
		
		a.ret();

	a.bind(QuerySystemInformation);
		a.cmp(rcx, SystemProcessInformation);
		a.je(QuerySystemInformation_L1);
		a.cmp(rcx, SystemSessionProcessInformation);
		a.je(QuerySystemInformation_L1);
		a.cmp(rcx, SystemExtendedProcessInformation);
		a.je(QuerySystemInformation_L1);
		a.cmp(rcx, SystemFullProcessInformation);
		a.je(QuerySystemInformation_L1);
		a.cmp(rcx, SystemHandleInformation);
		a.je(QuerySystemInformation_L1);
		a.cmp(rcx, SystemExtendedHandleInformation);
		a.je(QuerySystemInformation_L1);
		// else do regular syscall
		a.jmp(RegularSyscall);

	a.bind(QuerySystemInformation_L1);
		a.movq(xmm14, rcx);  // ProcessInformationClass
		a.movq(xmm15, rdx); // ProcessInformation

		a.syscall();
		// check if ntstatus is success
		a.cmp(rax, 0x0);
		a.je(QuerySystemInformation_L2);
		a.ret();

	a.bind(QuerySystemInformation_L2);
		pushad64();

		a.movq(rcx, xmm14);
		a.movq(rdx, xmm15);

		#if 0
		a.bind(DEBUG);
		a.int3();
		a.jmp(DEBUG);
		#endif

		a.sub(rsp, 0x20);
		a.call(ntdllQuerySystemInformation);
		a.add(rsp, 0x20);

		popad64();

		a.push(rax);
		a.mov(rax, 0);
		a.movq(xmm14, rax);
		a.movq(xmm15, rax);
		a.pop(rax);
		
		a.ret();

	a.bind(SetInformation);
		// do regular syscall if hidefromdebugger is not set
		a.cmp(rdx, ThreadHideFromDebugger);
		a.jne(RegularSyscall);

		a.sub(rsp, 0x20);
		a.call(ntdllSyscallSetInformation);
		a.add(rsp, 0x20);
		a.ret();

	a.bind(QueryInformation);
		// do regular syscall if hidefromdebugger is not set
		a.cmp(rdx, ThreadHideFromDebugger);
		a.jne(RegularSyscall);

		a.sub(rsp, 0x20);
		a.call(ntdllSyscallQueryInformation);
		a.add(rsp, 0x20);
		// if we call the function ourselves
		a.cmp(rax, 0x1337);
		a.je(RegularSyscall);
		a.ret();

	a.bind(CreateThreadEx);
		// remove hide from debugger flag
		a.movzx(eax, dword_ptr(rsp, 0x38));
		a.mov(r15, rax);
		a.mov(rax, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER);
		a.not_(rax);
		a.and_(r15, rax);
		a.mov(rax, r15);
		a.mov(dword_ptr(rsp, 0x38), eax);

		// create thread with syscall
		a.mov(rax, CreateThreadExSysCall);
		a.mov(r15, rcx);
		a.syscall();
		a.mov(rdx, rax);
		a.mov(rcx, r15);

		// set hwbp's on newly created thread
		a.sub(rsp, 0x20);
		a.call(ntdllSyscallCreateThreadEx);
		a.add(rsp, 0x20);
		a.ret();

	a.bind(CreateThread);
		a.sub(rsp, 0x20);
		a.call(ntdllSyscallCreateThread);
		a.add(rsp, 0x20);
		a.syscall();
		a.ret();

	void* asmjitResult = nullptr;
	runtime.add(&asmjitResult, &code);

	// copy over the content to the stub
	uint8_t* tempBuffer = (uint8_t*)malloc(sizeof(uint8_t) * code.codeSize());
	memcpy(tempBuffer, asmjitResult, code.codeSize());
	memcpy(ntdllAsmStubLocation, tempBuffer, sizeof(uint8_t) * code.codeSize());

	DWORD old_protect{};
	VirtualProtect(ntdllAsmStubLocation, allocationSize, PAGE_EXECUTE, &old_protect);

	//char* functionAddress = (char*)syscallLocations.get(0).get<void*>(0) + 18;
	//const int callInstructionBytes = 0x100000;
	//const int callInstructionLength = sizeof(uint8_t) * callInstructionBytes;

	//DWORD old_protect{};
	//BOOL result = VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);

	// inline hook every function using syscall
	//for (int i=0; i < syscallCount; i++)
	for (int i=0; i < syscallCount-5; i++)
	{
		// 18 since the signature puts us at the start of the function
		char* functionAddress = (char*)syscallLocations.get(i).get<void*>(0) + 18;
		uint64_t jmpDistance = (uint64_t)ntdllAsmStubLocation - (uint64_t)functionAddress - 5;

		const int callInstructionBytes = 6;
		const int callInstructionLength = sizeof(uint8_t) * callInstructionBytes;

		// E8 cd CALL rel32  Call near, relative, displacement relative to next instruction
		uint8_t* jmpInstructionBuffer = (uint8_t*)malloc(sizeof(uint8_t) * callInstructionBytes);

		if (jmpInstructionBuffer != nullptr)
		{
			jmpInstructionBuffer[0] = 0xE9;
			jmpInstructionBuffer[1] = (jmpDistance >> (0 * 8));
			jmpInstructionBuffer[2] = (jmpDistance >> (1 * 8));
			jmpInstructionBuffer[3] = (jmpDistance >> (2 * 8));
			jmpInstructionBuffer[4] = (jmpDistance >> (3 * 8));
			jmpInstructionBuffer[5] = 0x90;
		}

		DWORD old_protect{};
		int c = VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);

		if (c != 0)
			memcpy(functionAddress, jmpInstructionBuffer, callInstructionLength);
		else
			printf("couldnt change page protection at %llx\n", functionAddress);
		
		//int d = VirtualProtect(functionAddress, callInstructionLength, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), functionAddress, callInstructionLength);
	}

	//printf("done\n");
}

void createInlineAsmStub()
{
	hook::pattern locationsIntact = hook::module_pattern(GetModuleHandle(nullptr), "89 04 8A 83 45 ? FF");
	hook::pattern locationsIntactBig = hook::module_pattern(GetModuleHandle(nullptr), "89 04 8A 83 85");
	hook::pattern locationsSplit = hook::module_pattern(GetModuleHandle(nullptr), "89 04 8A E9");

	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));

	size_t intactCount = locationsIntact.size();
	size_t intactBigCount = locationsIntactBig.size();
	size_t splitCount = locationsSplit.size();
	size_t totalCount = intactCount + intactBigCount + splitCount;

	const size_t allocationSize = sizeof(uint8_t) * 128;
	inlineStubs = (inlineAsmStub*)malloc(sizeof(inlineAsmStub) * totalCount);

	for (int i=0; i < intactCount; i++)
	{
		inlineStubs[stubCounter].functionAddress = locationsIntact.get(i).get<void*>(0);
		inlineStubs[stubCounter].type = intactSmall;
		inlineStubs[stubCounter].bufferSize = 7;
		stubCounter++;
	}

	for (int i=0; i < intactBigCount; i++)
	{
		inlineStubs[stubCounter].functionAddress = locationsIntactBig.get(i).get<void*>(0);
		inlineStubs[stubCounter].type = intactBig;
		inlineStubs[stubCounter].bufferSize = 10;
		stubCounter++;
	}

	for (int i=0; i < splitCount; i++)
	{
		inlineStubs[stubCounter].functionAddress = locationsSplit.get(i).get<void*>(0);
		inlineStubs[stubCounter].type = split;
		inlineStubs[stubCounter].bufferSize = 8;
		stubCounter++;
	}

	LPVOID asmBigStubLocation = allocate_somewhere_near(GetModuleHandle(nullptr), allocationSize * 0x80);
	memset(asmBigStubLocation, 0x90, allocationSize * 0x80);

	// avoid stub generation collision
	char* previousStubOffset = nullptr;
	// for jmp distance calculation
	char* currentStubOffset = nullptr;

	// TODO: once we are done with that merge all the checksum fix stub generators into one function
	// make that also use one big allocated memory page

	// TODO: fix the asm stub that requires a movzx, registers maybe are getting owned?

	for (int i=0; i < stubCounter; i++)
	{
		// we don't know the previous offset yet
		if (currentStubOffset == nullptr)
			currentStubOffset = (char*)asmBigStubLocation;

		if (previousStubOffset != nullptr)
			currentStubOffset = previousStubOffset;

		void* functionAddress = inlineStubs[i].functionAddress;
		uint64_t jmpDistance = (uint64_t)currentStubOffset - (uint64_t)functionAddress - 5; // 5 bytes from relative call instruction

		// backup instructions that will get destroyed
		const int length = sizeof(uint8_t) * 8;
		uint8_t instructionBuffer[8] = {};
		memcpy(instructionBuffer, functionAddress, length);

		uint32_t instructionBufferJmpDistance = 0;
		if (instructionBuffer[3] == 0xE9)
			memcpy(&instructionBufferJmpDistance, (char*)functionAddress+0x4, 4); // 0x4 so we skip 0xE9

		uint64_t rbpOffset = 0x0;
		bool jumpDistanceNegative = instructionBufferJmpDistance >> 31; // get sign bit from jump distance
		int32_t jumpDistance = instructionBufferJmpDistance;
		
		if (inlineStubs[i].type == split)
		{
			// TODO: receive the rbpOffset by going through the jmp instruction
			// on big rbp offsets we could do the same hack we did on big intact where we do rbpOffset+0x100 if its below 0x60
			char* rbpOffsetPtr = nullptr;

			// TODO: just use jumpDistance once we got a working test case
			if (jumpDistanceNegative)
				rbpOffsetPtr = (char*)((uint64_t)functionAddress+jumpDistance+0x8);
			else
				rbpOffsetPtr = (char*)((uint64_t)functionAddress+instructionBufferJmpDistance+0x8);

			rbpOffsetPtr++;

			// depending on the rbp offset from add dword ptr we need one more byte for the rbpOffset
			if (*(unsigned char*)rbpOffsetPtr == 0x45) 		// add dword ptr [rbp+68],-01
			{
				rbpOffsetPtr++;
				rbpOffset = *(char*)rbpOffsetPtr;
			}
			else if (*(unsigned char*)rbpOffsetPtr == 0x85)	// add dword ptr [rbp+1CC],-01
			{
				rbpOffsetPtr++;
				rbpOffset = *(short*)rbpOffsetPtr;
			}
		}

		// create assembly stub content
		// TODO: we could create three different asmjit build sections for each type
		// so we don't have if statements inbetween instructions for the cost of LOC but it would be more readible
		static asmjit::JitRuntime runtime;
		asmjit::CodeHolder code;
		code.init(runtime.environment());
		asmjit::x86::Assembler a(&code);

		if (inlineStubs[i].type != split)
			rbpOffset = instructionBuffer[5];

		a.sub(asmjit::x86::rsp, 0x32);
		pushad64();

		a.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x20), asmjit::x86::rax);
		a.mov(asmjit::x86::rdx, asmjit::x86::rcx);	// offset within text section pointer (ecx*4)
		
		// we dont use rbpoffset since we only get 1 byte from the 2 byte offset (rbpOffset)
		// 0x130 is a good starting ptr to decrement downwards so we can find the original checksum
		if (inlineStubs[i].type == intactBig)
			a.mov(asmjit::x86::rcx, 0x120); 	
		else
			a.mov(asmjit::x86::rcx, rbpOffset);

		a.mov(asmjit::x86::r8, asmjit::x86::rbp);

		if (inlineStubs[i].type == split)
		{
			if (jumpDistanceNegative)
				a.mov(asmjit::x86::r9, jumpDistance);
			else
				a.mov(asmjit::x86::r9, instructionBufferJmpDistance);
		}
		else
			a.mov(asmjit::x86::r9, instructionBufferJmpDistance);	// incase we mess up a split checksum

		a.mov(asmjit::x86::rax, (uint64_t)(void*)fixChecksum);
		a.call(asmjit::x86::rax);
		a.add(asmjit::x86::rsp, 0x8*4); // so that r12-r15 registers dont get corrupt

		popad64WithoutRAX();
		a.add(asmjit::x86::rsp, 0x32);

		a.mov(ptr(asmjit::x86::rdx, asmjit::x86::rcx, 2), asmjit::x86::eax); // mov [rdx+rcx*4], eax

		if (instructionBufferJmpDistance == 0)
		{
			if (inlineStubs[i].type == intactBig)
				rbpOffset += 0x100;

			a.add(dword_ptr(asmjit::x86::rbp, rbpOffset), -1); // add dword ptr [rbp+rbpOffset], 0FFFFFFFFh
		}
		else
		{
			// jmp loc_7FF641C707A5
			// push the desired address on to the stack and then perform a 64 bit RET
			a.add(asmjit::x86::rsp, 0x8); // pop return address off the stack cause we will jump
			uint64_t addressToJump = (uint64_t)functionAddress + instructionBufferJmpDistance;
			
			if (inlineStubs[i].type == split)
			{
				// TODO: just use jumpDistance once we got a working test case
				if (jumpDistanceNegative)
					addressToJump = (uint64_t)functionAddress + jumpDistance + 0x8; // 0x8 call instruction + offset + 2 nops
				else
					addressToJump = (uint64_t)functionAddress + instructionBufferJmpDistance + 0x8; // 0x8 call instruction + offset + 2 nops
			}

			a.mov(asmjit::x86::r11, addressToJump);	// r11 is being used but should be fine based on documentation
			
			if (inlineStubs[i].type == split)
				a.add(asmjit::x86::rsp, 0x8); // since we dont pop off rax we need to sub 0x8 the rsp

			a.push(asmjit::x86::r11);
		}

		if (inlineStubs[i].type != split)
			a.add(asmjit::x86::rsp, 0x8); // since we dont pop off rax we need to sub 0x8 the rsp

		a.ret();

		void* asmjitResult = nullptr;
		runtime.add(&asmjitResult, &code);

		// copy over the content to the stub
		uint8_t* tempBuffer = (uint8_t*)malloc(sizeof(uint8_t) * code.codeSize());
		memcpy(tempBuffer, asmjitResult, code.codeSize());
		memcpy(currentStubOffset, tempBuffer, sizeof(uint8_t) * code.codeSize());

		size_t callInstructionBytes = inlineStubs[i].bufferSize;
		size_t callInstructionLength = sizeof(uint8_t) * callInstructionBytes;

		DWORD old_protect{};
		VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);
		memset(functionAddress, 0, callInstructionLength);
		VirtualProtect(functionAddress, callInstructionLength, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), functionAddress, callInstructionLength);

		// E8 cd CALL rel32  Call near, relative, displacement relative to next instruction
		uint8_t* jmpInstructionBuffer = (uint8_t*)malloc(sizeof(uint8_t) * callInstructionBytes);
		jmpInstructionBuffer[0] = 0xE8;
		jmpInstructionBuffer[1] = (jmpDistance >> (0 * 8));
		jmpInstructionBuffer[2] = (jmpDistance >> (1 * 8));
		jmpInstructionBuffer[3] = (jmpDistance >> (2 * 8));
		jmpInstructionBuffer[4] = (jmpDistance >> (3 * 8));
		jmpInstructionBuffer[5] = 0x90;
		jmpInstructionBuffer[6] = 0x90;

		if (inlineStubs[i].type == intactBig)
		{
			jmpInstructionBuffer[7] = 0x90;
			jmpInstructionBuffer[8] = 0x90;
			jmpInstructionBuffer[9] = 0x90;
		}

		if (inlineStubs[i].type == split)
			jmpInstructionBuffer[7] = 0x90;

		VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);
		memcpy(functionAddress, jmpInstructionBuffer, callInstructionLength);
		VirtualProtect(functionAddress, callInstructionLength, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), functionAddress, callInstructionLength);

		// store location & bytes to check if arxan is removing our hooks
		if (inlineStubs[i].type == intactSmall)
		{
			intactChecksumHook intactChecksum = {};
			intactChecksum.functionAddress = (uint64_t*)functionAddress;
			memcpy(intactChecksum.buffer, jmpInstructionBuffer, sizeof(uint8_t) * inlineStubs[i].bufferSize);
			inlineStubs[i].buffer = intactChecksum.buffer;
			intactchecksumHooks.push_back(intactChecksum);
		}

		if (inlineStubs[i].type == intactBig)
		{
			intactBigChecksumHook intactBigChecksum = {};
			intactBigChecksum.functionAddress = (uint64_t*)functionAddress;
			memcpy(intactBigChecksum.buffer, jmpInstructionBuffer, sizeof(uint8_t) * inlineStubs[i].bufferSize);
			inlineStubs[i].buffer = intactBigChecksum.buffer;
			intactBigchecksumHooks.push_back(intactBigChecksum);
		}

		if (inlineStubs[i].type == split)
		{
			splitChecksumHook splitChecksum = {};
			splitChecksum.functionAddress = (uint64_t*)functionAddress;
			memcpy(splitChecksum.buffer, jmpInstructionBuffer, sizeof(uint8_t) * inlineStubs[i].bufferSize);
			inlineStubs[i].buffer = splitChecksum.buffer;
			splitchecksumHooks.push_back(splitChecksum);
		}

		previousStubOffset = currentStubOffset + sizeof(uint8_t) * code.codeSize() + 0x8;
	}

	printf("p %d\n", intactCount);
	printf("p %d\n", intactBigCount);
	printf("p %d\n", splitCount);
}

bool arxanHealingChecksum(uint64_t rbp)
{
	// check if rbpAddressLocationPtr is within the range of 8 bytes up & down from every checksum that we placed.
	uint64_t rbpAddressLocationPtr = *(uint64_t*)(rbp+0x10);

	for (int i=0; i < stubCounter; i++)
	{
		// 0x8
		// TODO: if 0x7 is too big then "mov [rdx], al" will make the game crash probably because its trying to overwrite areas next to our hooks that have to get modified.
		// we could do two seperate functions since "mov [rdx], eax" would be a 32 byte offset (?) and "mov [rdx], al" would be 4 byte offset (?)

		if (rbpAddressLocationPtr+0x7 >= (uint64_t)inlineStubs[i].functionAddress && 
			rbpAddressLocationPtr-0x7 <= (uint64_t)inlineStubs[i].functionAddress)
		{
			return true;
		}
	}

	return false;
}

struct checksumHealingLocation
{
	hook::pattern checksumPattern;
	size_t length;
};

void createChecksumHealingStub()
{
	void* baseModule = GetModuleHandle(nullptr);

	checksumHealingLocation healingLocations[] {
		{hook::module_pattern(baseModule, "89 02 8B 45 20"), 5},
		{hook::module_pattern(baseModule, "88 02 83 45 20 FF"), 6},
		{hook::module_pattern(baseModule, "89 02 E9"), 7},
		{hook::module_pattern(baseModule, "88 02 E9"), 7},
	};

	const size_t allocationSize = sizeof(uint8_t) * 0x100 * 1000;
	LPVOID healingStubLocation = allocate_somewhere_near(GetModuleHandle(nullptr), allocationSize);
	memset(healingStubLocation, 0x90, allocationSize);

	// avoid stub generation collision
	char* previousStubOffset = nullptr;
	// for jmp distance calculation
	char* currentStubOffset = nullptr;

	size_t amountOfPatterns = sizeof(healingLocations) / sizeof(checksumHealingLocation);
	for (int type=0; type < amountOfPatterns; type++)
	{
		size_t locations = healingLocations[type].checksumPattern.size();
		for (int i=0; i < locations; i++)
		{
			uint8_t instructionBuffer[4] = {}; // 88 02 E9: 4          
			int32_t jumpDistance = 0;
			size_t callInstructionOffset = 5; // 0xE8 ? ? ? ?
			uint64_t jumpInstruction;
			uint64_t locationToJump;

			// we don't know the previous offset yet
			if (currentStubOffset == nullptr)
				currentStubOffset = (char*)healingStubLocation;

			if (previousStubOffset != nullptr)
				currentStubOffset = previousStubOffset;

			void* functionAddress = healingLocations[type].checksumPattern.get(i).get<void*>(0);

			if (*(uint8_t*)((uint8_t*)functionAddress + 2) == 0xe9)
			{
				memcpy(&jumpDistance, (char*)functionAddress+3, 4); // ptr after 0xE9
				jumpInstruction = (uint64_t)functionAddress+2; 		// at the jmp instruction
				locationToJump = jumpInstruction + jumpDistance + callInstructionOffset;
				
				// get size of image from codcw
				uint64_t baseAddressStart = (uint64_t)GetModuleHandle(nullptr);
				IMAGE_DOS_HEADER* pDOSHeader = (IMAGE_DOS_HEADER*)GetModuleHandle(nullptr);
				IMAGE_NT_HEADERS* pNTHeaders = (IMAGE_NT_HEADERS*)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
				auto sizeOfImage = pNTHeaders->OptionalHeader.SizeOfImage;
				uint64_t baseAddressEnd = baseAddressStart + sizeOfImage;

				if ((locationToJump > baseAddressStart && locationToJump < baseAddressEnd) != true)
					continue;

				memcpy(instructionBuffer, (char*)locationToJump, sizeof(uint8_t) * 4);

				if (type == 2)
				{
					uint8_t instruction[3] = { 0x8B, 0x45, 0x20 };
					if (memcmp(instructionBuffer, instruction, sizeof(uint8_t) * 3) != 0)
						continue;
				}

				if (type == 3)
				{
					uint8_t instruction[4] = { 0x83, 0x45, 0x20, 0xFF };
					if (memcmp(instructionBuffer, instruction, sizeof(uint8_t) * 4) != 0)
						continue;
				}
			}

			static asmjit::JitRuntime runtime;
			asmjit::CodeHolder code;
			code.init(runtime.environment());

			using namespace asmjit::x86;
			Assembler a(&code);
			asmjit::Label L1 = a.newLabel();
			asmjit::Label DEBUG = a.newLabel();

			a.sub(rsp, 0x32);
			pushad64_Min();

			a.mov(rcx, rbp);
			a.mov(r15, (uint64_t)(void*)arxanHealingChecksum);
			a.call(r15);
			a.movzx(r15, al);	// if arxan tries to replace our checksum set r15 to 1

			popad64_Min();
			a.add(rsp, 0x32);

			switch(type)
			{
				case 0:
				/*
					mov     [rdx], eax
					mov     eax, [rbp+20h]
				*/
					// dont replace our checksum if r15 is 1
					a.cmp(r15, 1);
					a.je(L1);
					a.mov(qword_ptr(rdx), eax);

					a.bind(L1);
					a.mov(eax, qword_ptr(rbp, 0x20));
					a.ret();
					break;
				case 1:
				/*
					mov     [rdx], al
					add     dword ptr [rbp+20h], -1
				*/
					// dont replace our checksum if r15 is 1
					a.cmp(r15, 1);
					a.je(L1);
					a.mov(qword_ptr(rdx), al);

					a.bind(L1);
					a.add(dword_ptr(rbp, 0x20), -1);
					a.ret();
					break;
				case 2:
				/*
					mov     [rdx], eax
					jmp     loc_7FF7366C7B94
				*/
					// dont replace our checksum if r15 is 1
					a.cmp(r15, 1);
					a.je(L1);
					a.mov(qword_ptr(rdx), eax);

					a.bind(L1);
					a.add(rsp, 0x8);
					a.mov(r15, locationToJump);
					a.push(r15);
					a.ret();
					break;
				case 3:
				/*
					mov     [rdx], al
					jmp     loc_7FF738FB7A45
				*/
					// dont replace our checksum if r15 is 1
					a.cmp(r15, 1);
					a.je(L1);
					a.mov(qword_ptr(rdx), al);

					a.bind(L1);
					a.add(rsp, 0x8);
					a.mov(r15, locationToJump);
					a.push(r15);
					a.ret();
					break;
				default:
					printf("Error: We shouldn't be here");
					getchar();
					abort();
			}

			void* asmjitResult = nullptr;
			runtime.add(&asmjitResult, &code);

			// copy over the content to the stub
			uint8_t* tempBuffer = (uint8_t*)malloc(sizeof(uint8_t) * code.codeSize());
			memcpy(tempBuffer, asmjitResult, code.codeSize());
			memcpy(currentStubOffset, tempBuffer, sizeof(uint8_t) * code.codeSize());

			size_t callInstructionBytes = healingLocations[type].length;
			size_t callInstructionLength = sizeof(uint8_t) * callInstructionBytes;

			DWORD old_protect{};
			VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);
			memset(functionAddress, 0, callInstructionLength);
			VirtualProtect(functionAddress, callInstructionLength, old_protect, &old_protect);
			FlushInstructionCache(GetCurrentProcess(), functionAddress, callInstructionLength);

			uint64_t jmpDistance = (uint64_t)currentStubOffset - (uint64_t)functionAddress - 5;
			uint8_t* jmpInstructionBuffer = (uint8_t*)malloc(sizeof(uint8_t) * callInstructionBytes);
			
			// E8 cd CALL rel32  Call near, relative, displacement relative to next instruction
			jmpInstructionBuffer[0] = 0xE8;
			jmpInstructionBuffer[1] = (jmpDistance >> (0 * 8));
			jmpInstructionBuffer[2] = (jmpDistance >> (1 * 8));
			jmpInstructionBuffer[3] = (jmpDistance >> (2 * 8));
			jmpInstructionBuffer[4] = (jmpDistance >> (3 * 8));

			for (int v = 0; v < callInstructionBytes-5; v++)
				jmpInstructionBuffer[5+v] = 0x90;

			VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);
			memcpy(functionAddress, jmpInstructionBuffer, callInstructionLength);
			VirtualProtect(functionAddress, callInstructionLength, old_protect, &old_protect);
			FlushInstructionCache(GetCurrentProcess(), functionAddress, callInstructionLength);

			previousStubOffset = currentStubOffset + sizeof(uint8_t) * code.codeSize() + 0x8;
			
			// debugging printf
			if (i == 0)
				printf("type: %d %llx\n", type, functionAddress);
		}
	}
}

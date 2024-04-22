#include <asmjit/core/operand.h>
#include <asmjit/x86/x86operand.h>
#define PHNT_VERSION PHNT_WIN10_22H2
#include <phnt_windows.h>
#include <phnt.h>
#include <ntexapi.h>
#include <ntpsapi.h>
#include <minidumpapiset.h>

#include <TlHelp32.h>
#include <mmeapi.h>

#include <stdio.h>
#include <intrin.h>

#include <asmjit/core/jitruntime.h>
#include <asmjit/x86/x86assembler.h>

#include "winstructs.h"
#include "utils.h"
#include "systemhooks.h"
#include "arxan.h"
#include "exceptions.h"
#include "gamehooks.h"

LONG WINAPI exceptionHandler(const LPEXCEPTION_POINTERS info)
{
	if (info->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (info->ExceptionRecord->ExceptionCode == STATUS_INVALID_HANDLE)
	{
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	// Veh hooking
	// PageGuardMemory(breakpointAddress, 1);
	if (info->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
	{
		uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
		uint64_t idaExceptionAddr = (uint64_t)info->ExceptionRecord->ExceptionAddress - baseAddr + StartOfTextSection - 0x1000;
		uint64_t idaAddrAccessed = (uint64_t)info->ExceptionRecord->ExceptionInformation[1] - baseAddr + StartOfTextSection - 0x1000;

		uint64_t addrInProcess = (uint64_t)info->ExceptionRecord->ExceptionAddress;
		uint64_t addrAccessed = (uint64_t)info->ExceptionRecord->ExceptionInformation[1];

		if (info->ExceptionRecord->ExceptionInformation[1] == reinterpret_cast<ULONG_PTR>(breakpointAddress))
			printf("guard page hit %llx %llx %llx\n", idaExceptionAddr, addrInProcess, addrAccessed);

		info->ContextRecord->EFlags |= 0x100;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
		uint64_t exceptionAddr = (uint64_t)info->ExceptionRecord->ExceptionAddress;
		uint64_t idaExceptionAddr = exceptionAddr - baseAddr + StartOfTextSection - 0x1000;

		uint64_t returnAddr = *(uint64_t*)info->ContextRecord->Rsp;
		returnAddr = returnAddr - baseAddr + StartOfTextSection - 0x1000;

		if (info->ContextRecord->Dr6 & 0x1)
		{
			info->ContextRecord->EFlags |= ResumeFlag;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (info->ContextRecord->Dr6 & 0x2)
		{
			// get size of image from codcw
			uint64_t baseAddressStart = (uint64_t)GetModuleHandle(nullptr);
			IMAGE_DOS_HEADER* pDOSHeader = (IMAGE_DOS_HEADER*)GetModuleHandle(nullptr);
			IMAGE_NT_HEADERS* pNTHeaders =(IMAGE_NT_HEADERS*)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
			auto sizeOfImage = pNTHeaders->OptionalHeader.SizeOfImage;
			uint64_t baseAddressEnd = baseAddressStart + sizeOfImage;

			if (exceptionAddr >= baseAddressStart && exceptionAddr <= baseAddressEnd)
			{
				static int counter = 0;
				counter++;

				printf("bp2: %llx %llx %d\n", exceptionAddr, idaExceptionAddr, counter);
				fprintf(logFile, "bp2: %llx %llx %d\n", exceptionAddr, idaExceptionAddr, counter);
				fflush(logFile);
			}

			info->ContextRecord->EFlags |= ResumeFlag;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (info->ContextRecord->Dr6 & 0x4)
		{
			static int counter = 0;
			counter++;

			if (counter == 5)
			{
				createInlineAsmStub();
				disableTlsCallbacks();
				nopChecksumFixingMemcpy();
				InitializeGameHooks();
			}

			info->ContextRecord->EFlags |= ResumeFlag;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (info->ContextRecord->Dr6 & 0x8)
		{
			// get size of image from codcw
			uint64_t baseAddressStart = (uint64_t)GetModuleHandle(nullptr);
			IMAGE_DOS_HEADER* pDOSHeader = (IMAGE_DOS_HEADER*)GetModuleHandle(nullptr);
			IMAGE_NT_HEADERS* pNTHeaders =(IMAGE_NT_HEADERS*)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
			auto sizeOfImage = pNTHeaders->OptionalHeader.SizeOfImage;
			uint64_t baseAddressEnd = baseAddressStart + sizeOfImage;

			if (exceptionAddr >= baseAddressStart && exceptionAddr <= baseAddressEnd)
			{
				static int counter = 0;
				counter++;

				printf("bp4: %llx %llx %d\n", exceptionAddr, idaExceptionAddr, counter);
				fprintf(logFile, "bp4: %llx %llx %d\n", exceptionAddr, idaExceptionAddr, counter);
				fflush(logFile);
			}

			info->ContextRecord->EFlags |= ResumeFlag;
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (info->ExceptionRecord->ExceptionCode == 0xc0000005)
	{
		static int access_violation_counter = 0;
		access_violation_counter++;

		if (access_violation_counter == 2)
		{
			printf("something exploded: %llx\n", info->ExceptionRecord->ExceptionCode);
			fprintf(logFile, "something exploded: %llx\n", info->ExceptionRecord->ExceptionCode);
			fflush(logFile);

			HANDLE hFile = CreateFile("dump.dmp", GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

			MINIDUMP_EXCEPTION_INFORMATION minidump_exception_info = {GetCurrentThreadId(), info, FALSE};

			constexpr auto type = MiniDumpIgnoreInaccessibleMemory //
				| MiniDumpWithHandleData //
				| MiniDumpScanMemory //
				| MiniDumpWithProcessThreadData //
				| MiniDumpWithFullMemoryInfo //
				| MiniDumpWithThreadInfo //
				| MiniDumpWithUnloadedModules;

			MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, (MINIDUMP_TYPE)type, &minidump_exception_info, nullptr, nullptr);
			CloseHandle(hFile);

			SuspendAllThreads();
			__debugbreak();
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}
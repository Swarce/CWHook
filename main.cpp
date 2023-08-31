#include <Windows.h>
#include <winternl.h>
#include <filesystem>
#include <string.h>
#include <stdio.h>
#include <vector>
#include <intrin.h>
#include <TlHelp32.h>
#include <string>
#include <string_view>
#include <iostream>

#include "libs/minhook/include/MinHook.h"
#include "gamestructs.h"
#include "winstructs.h"

enum Condition { Execute = 0, Write = 1, ReadWrite = 3 };
const uint64_t EndOfTextSection = 0x2305000;
const uint64_t StartOfTextSection = 0x7FF644DC1000;

HANDLE debugThreadHandle = nullptr;
bool multiplayerEnabled = false;
int multiplayerCounter = 0;
bool hookedfunction = false;
bool suspendNewThreads = false;
char* endofTextSectionAddr = nullptr;
char* baseFuncAddr = nullptr;
HANDLE gameHandle = nullptr;
HANDLE inputHandle = nullptr;
const char* disconnectCvar = "disconnect\n";
const char* devmapCvar = "sv_cheats 1\ndevmap mp_tank 1 0\n";
CONTEXT context = {};

extern HMODULE module;

void initalizeHooks();
void disableTlsCallbacks();
void SuspendAllThreads();

inline void SetBits(unsigned long& dw, int lowBit, int bits, int newValue)
{
	int mask = (1 << bits) - 1; // e.g. 1 becomes 0001, 2 becomes 0011, 3 becomes 0111

	dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
}

typedef int(__stdcall* GetThreadContext_t)(HANDLE hThread, CONTEXT* lpContext);
GetThreadContext_t GetThreadContextOrig;

typedef int(__stdcall* SetThreadContext_t)(HANDLE hThread, CONTEXT* lpContext);
SetThreadContext_t SetThreadContextOrig;

typedef HANDLE(__stdcall* CreateThread_t)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
CreateThread_t CreateThreadOrig;

typedef ULONGLONG(__stdcall* GetTickCount64_t)();
GetTickCount64_t GetTickCount64Orig;

typedef NTSTATUS(__stdcall* NtQueryInformationProcess_t)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
NtQueryInformationProcess_t NtQueryInformationProcessOrig;

typedef NTSTATUS(__stdcall* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NtQuerySystemInformation_t NtQuerySystemInformationOrig;

typedef NTSTATUS(__stdcall* NtTerminateProcess_t)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
NtTerminateProcess_t NtTerminateProcessOrig;

typedef int(__stdcall* GetWindowText_t)(HWND hWnd, LPSTR lpString, int nMaxCount);
GetWindowText_t GetWindowTextOrig;

typedef BOOL(__stdcall* EnumWindowsOrig_t)(WNDENUMPROC lpEnumFunc, LPARAM lParam);
EnumWindowsOrig_t EnumWindowsOrig;

typedef BOOL(__stdcall* CheckRemoteDebuggerPresent_t)(HANDLE hProcess, PBOOL pbDebuggerPresent);
CheckRemoteDebuggerPresent_t CheckRemoteDebuggerPresentOrig;

typedef HANDLE(__stdcall* CreateMutexEx_t)(const LPSECURITY_ATTRIBUTES attributes, const LPCSTR name, const DWORD flags, const DWORD access);
CreateMutexEx_t CreateMutexExOrig;

// TODO: doesn't get called i think? check again with hwbp execute
typedef __int64(__fastcall* LoadBuffer_t)(__int64* luaState, const char* buff, __int64 size, char* a4);
LoadBuffer_t LoadBuffer;

typedef __int64(__fastcall* CbufAddText_t)(__int64 playerNum, const char* buff);
CbufAddText_t CbufAddText;

typedef __int64(__fastcall* SetScreen_t)(__int64 screenNum);
SetScreen_t SetScreen;

typedef __int64(__fastcall* LiveStorage_ParseKeysTxt_t)(const char* key);
LiveStorage_ParseKeysTxt_t LiveStorage_ParseKeysTxt;

typedef __int64(__fastcall* LiveStorage_ParseKeysTxt2_t)(const char* key);
LiveStorage_ParseKeysTxt2_t LiveStorage_ParseKeysTxt2;

typedef NTSTATUS(__fastcall* NtSetInformationThread_t)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
NtSetInformationThread_t NtSetInformationThreadOrig;

typedef NTSTATUS(__fastcall* NtQueryInformationThread_t)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
NtQueryInformationThread_t NtQueryInformationThreadOrig;

bool remove_evil_keywords_from_string(const UNICODE_STRING& string)
{
	static const std::wstring evil_keywords[] =
	{
		L"IDA",
		L"ida",
		L"HxD",
		L"cheatengine",
		L"Cheat Engine",
		L"x96dbg",
		L"x32dbg",
		L"x64dbg",
		L"Wireshark",
		L"Debug",
		L"DEBUG",
		L"msvsmon",
	};

	if (!string.Buffer || !string.Length)
	{
		return false;
	}

	const std::wstring_view path(string.Buffer, string.Length / sizeof(string.Buffer[0]));

	bool modified = false;
	for (const auto& keyword : evil_keywords)
	{
		while (true)
		{
			const auto pos = path.find(keyword);
			if (pos == std::wstring::npos)
			{
				break;
			}

			modified = true;

			for (size_t i = 0; i < keyword.size(); ++i)
			{
				string.Buffer[pos + i] = L'a';
			}
		}
	}

	return modified;
}

NTSTATUS NtQueryInformationProcessFunc(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
	auto* source = _ReturnAddress();
	HMODULE module;
	GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, static_cast<LPCSTR>(source), &module);

	NTSTATUS status = { 0 };
	status = NtQueryInformationProcessOrig(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	if (ProcessInformationClass == ProcessDebugObjectHandle)
	{
		*static_cast<HANDLE*>(ProcessInformation) = nullptr;
		return static_cast<LONG>(0xC0000353);
	}
	else if (ProcessInformationClass == ProcessImageFileName || static_cast<int>(ProcessInformationClass) == ProcessImageFileNameWin32)
	{
		remove_evil_keywords_from_string(*static_cast<UNICODE_STRING*>(ProcessInformation));
	}
	else if (ProcessInformationClass == ProcessDebugPort)
	{
		*static_cast<HANDLE*>(ProcessInformation) = nullptr;
	}
	else if (ProcessInformationClass == ProcessDebugFlags)
	{
		*static_cast<ULONG*>(ProcessInformation) = 1;
	}

	return status;
}

NTSTATUS NtQuerySystemInformationFunc(SYSTEM_INFORMATION_CLASS system_information_class, PVOID system_information, ULONG system_information_length, PULONG return_length)
{
	NTSTATUS status = { 0 };
	status = NtQuerySystemInformationOrig(system_information_class, system_information, system_information_length, return_length);

	if (NT_SUCCESS(status))
	{
		if (system_information_class == SystemProcessInformation)
		{
			auto addr = static_cast<uint8_t*>(system_information);
			while (true)
			{
				const auto info = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(addr);

				if (info->ImageName.Buffer != nullptr)
					remove_evil_keywords_from_string(info->ImageName);

				if (!info->NextEntryOffset)
				{
					break;
				}

				addr = addr + info->NextEntryOffset;
			}
		}

		if (system_information_class == SystemHandleInformation)
		{
			PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)system_information;
			for (int i = 0; i < handleInfo->HandleCount; i++)
			{
				SYSTEM_HANDLE handle = handleInfo->Handles[i];
				printf("%d ", handle.ProcessId);
			}

			printf("\nchecked for handle information\n");
		}

		if (system_information_class == SystemHandleInformationEx)
		{
			printf("\nchecked for handle information ex\n");
		}
	}

	return status;
}

NTSTATUS NtTerminateProcessFunc(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
	printf("im dead\n");
	return STATUS_INVALID_HANDLE;
}

NTSTATUS NtSetInformationThreadFunc(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
{
	if (ThreadInformationClass == NTDLL::ThreadHideFromDebugger)
	{
		if (ThreadHandle != GetCurrentThread())
		{
			debugThreadHandle = ThreadHandle;
			ThreadInformationClass = (THREADINFOCLASS)NTDLL::ThreadBasePriority;
			printf("thread %llx threadhidefromdebugger\n", GetThreadId(ThreadHandle));
		}
	}

	return NtSetInformationThreadOrig(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

NTSTATUS NtQueryInformationThreadFunc(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength)
{
	if (ThreadInformationClass == NTDLL::ThreadHideFromDebugger)
		printf("checked if thread is hidden from debugger\n");

	NTSTATUS result = NtQueryInformationThreadOrig(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
	return result;
}

int GetWindowTextFunc(HWND hWnd, LPSTR lpString, int nMaxCount)
{
	/*
	if (nMaxCount > 18)
	{
		strcpy(lpString, "Cheat Engine 7.5");
		printf("windowtext: %s\n", lpString);
	}
	*/

	//wprintf(L"windowtext: %s\n", pszMem);
	//printf("get window got called %llx\n", _ReturnAddress());

	return 0;
}

BOOL EnumWindowsFunc(WNDENUMPROC lpEnumFunc, LPARAM lParam)
{
	printf("enum called\n");
	return EnumWindowsOrig(lpEnumFunc, lParam);
}

void SleepAllThreadsBesidesMainThread()
{
	HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (snapshotHandle == INVALID_HANDLE_VALUE)
		printf("couldn't get snapshot\n");

	THREADENTRY32 entry = {};
	entry.dwSize = sizeof(THREADENTRY32);

	int counter = 0;

	auto z = Thread32First(snapshotHandle, &entry);
	do {
		if (entry.th32OwnerProcessID == GetCurrentProcessId())
		{
			HANDLE currentThread = OpenThread(THREAD_ALL_ACCESS, false, entry.th32ThreadID);

			if (counter == 0)
			{
				gameHandle = currentThread;
				counter++;
				continue;
			}

			SuspendThread(currentThread);
		}

	} while (Thread32Next(snapshotHandle, &entry));
}

HANDLE WINAPI CreateThreadFunc(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	// Loop each thread and attach breakpoints
	HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (snapshotHandle == INVALID_HANDLE_VALUE)
		printf("couldn't get snapshot\n");

	THREADENTRY32 entry = {};
	entry.dwSize = sizeof(THREADENTRY32);

	auto z = Thread32First(snapshotHandle, &entry);
	do {
		if (entry.th32OwnerProcessID == GetCurrentProcessId())
		{
			HANDLE currentThread = OpenThread(THREAD_ALL_ACCESS, false, entry.th32ThreadID);
			bool setThreadResult = 1;

			if (!suspendNewThreads)
				setThreadResult = SetThreadContextOrig(currentThread, &context);

			if (setThreadResult == 0)
				printf("didn't work to overwrite thread context\n");
		}

	} while (Thread32Next(snapshotHandle, &entry));

	HANDLE thread = CreateThreadOrig(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

	if (suspendNewThreads)
		SuspendThread(thread);

	return thread;
}

HANDLE CreateMutexExFunc(const LPSECURITY_ATTRIBUTES attributes, const LPCSTR name, const DWORD flags, const DWORD access)
{
	int compare1 = strcmp(name, "$ IDA trusted_idbs");
	int compare2 = strcmp(name, "$ IDA registry mutex $");

	if ((compare1 == 0))
	{
		return CreateMutexExOrig(attributes, "blablabla", flags, access);
	}

	if ((compare2 == 0))
	{
		return CreateMutexExOrig(attributes, "blablablabla", flags, access);
	}

	return CreateMutexExOrig(attributes, name, flags, access);
}

DWORD WINAPI ConsoleInput(LPVOID lpReserved)
{
	while (true)
	{
		std::string input;
		getline(std::cin, input);

		if (strcmp(input.c_str(), "b") == 0)
		{
			if (gameHandle != nullptr)
				ResumeThread(gameHandle);
		}
		else if (strcmp(input.c_str(), "a") == 0)
		{
			uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
			for (int i = 0; i < 4096; i++)
			{
				std::string cvarCmd = "cmd iwr " + std::to_string(i) + " 1\n";
				CbufAddText(0, cvarCmd.c_str());
			}

			CbufAddText(0, "disconnect\n");
		}
		else
		{
			CbufAddText(0, input.c_str());
			printf("cmd: %s\n", input.c_str());
		}
	}
	return 0;
}

BOOL CheckRemoteDebuggerPresentFunc(HANDLE hProcess, PBOOL pbDebuggerPresent)
{
	//printf("checked for debugger %llx\n", _ReturnAddress());

	*(BOOL*)pbDebuggerPresent = false;
	return true;
}

ULONGLONG GetTickCount64Func()
{
	//printf("checked for debugger\n");
	auto* const peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
	// TODO: check why this is crashing the game
	// Maybe it temporarly enables beingdebugged and then later disables it
	// So if we clear it when it tries to enable and checks that its gone the game probably crashes
	/*
	peb->BeingDebugged = false;
	*reinterpret_cast<PDWORD>(LPSTR(peb) + 0xBC) &= ~0x70;
	*/

	return GetTickCount64Orig();
}

bool GetThreadContextFunc(HANDLE thread, CONTEXT context)
{
	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
	auto* source = _ReturnAddress();
	HMODULE module;
	GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, static_cast<LPCSTR>(source), &module);

	if (baseAddr == (uint64_t)module)
		return 0;
	else
		return GetThreadContextOrig(thread, &context);
}

bool SetThreadContextFunc(HANDLE thread, CONTEXT* context)
{
	HMODULE module;
	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
	auto* source = _ReturnAddress();
	GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, static_cast<LPCSTR>(source), &module);

	if (baseAddr == (uint64_t)module)
		return 0;
	else
		return SetThreadContextOrig(thread, context);
}

void generalTlsCallbackFunction()
{
	return;
}

void* breakpointAddress;
auto PageGuardMemory(void* address, const SIZE_T length) -> void
{
	DWORD oldProtect;
	MEMORY_BASIC_INFORMATION mbi;

	bool vqResult = VirtualQuery(static_cast<const void*>(address), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	bool vpResult = VirtualProtect(address, length, mbi.Protect | PAGE_GUARD, &oldProtect);

	if (!vqResult || !vpResult)
		printf("didn't work to place page guard\n");
	//else
	//	printf("applied page guard\n");
}

auto UnPageGuardMemory(void* address, const SIZE_T length) -> void
{
	DWORD oldProtect;
	MEMORY_BASIC_INFORMATION mbi;

	VirtualQuery(static_cast<const void*>(address), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(address, length, mbi.Protect & ~PAGE_GUARD, &oldProtect);
}

auto initializeBreakpoint(void* address) -> void
{
	//create our "breakpoint" by doing an initial PAGE_GUARD on target memory
	breakpointAddress = address;
	PageGuardMemory(breakpointAddress, 1ui64);
}

auto disableBreakpoint(void* address) -> void
{
	breakpointAddress = nullptr;
	UnPageGuardMemory(address, 1ui64);
}

void SuspendAllThreads()
{
	printf("suspended: %llx %d\n", GetCurrentThreadId(), GetCurrentThreadId());
	disableTlsCallbacks();
	suspendNewThreads = true;
	SleepAllThreadsBesidesMainThread();

	if (inputHandle != nullptr)
		ResumeThread(inputHandle);
	
	SuspendThread(GetCurrentThread());
}

LONG WINAPI exceptionHandler(const LPEXCEPTION_POINTERS info)
{
	if (info->ExceptionRecord->ExceptionCode == STATUS_INVALID_HANDLE)
	{
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (info->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
	{
		uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
		uint64_t idaExceptionAddr = (uint64_t)info->ExceptionRecord->ExceptionAddress - baseAddr + StartOfTextSection - 0x1000;
		uint64_t idaAddrAccessed = (uint64_t)info->ExceptionRecord->ExceptionInformation[1] - baseAddr + StartOfTextSection - 0x1000;

		uint64_t addrInProcess = (uint64_t)info->ExceptionRecord->ExceptionAddress;
		uint64_t addrAccessed = (uint64_t)info->ExceptionRecord->ExceptionInformation[1];

		if (info->ExceptionRecord->ExceptionInformation[1] == reinterpret_cast<ULONG_PTR>(breakpointAddress))
			printf("guard page hit %llx %llx %llx\n", idaExceptionAddr, addrInProcess, addrAccessed);

		info->ContextRecord->EFlags |= 0x100ui32;

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
		uint64_t exceptionAddr = (uint64_t)info->ExceptionRecord->ExceptionAddress;
		uint64_t idaExceptionAddr = exceptionAddr - baseAddr + StartOfTextSection - 0x1000;

		// only valid if bp is at start of func
		uint64_t returnAddr = *(uint64_t*)info->ContextRecord->Rsp;
		returnAddr = returnAddr - baseAddr + StartOfTextSection - 0x1000;

		if (info->ContextRecord->Dr6 & 0x1)
		{
			/* Turns off kernel32 debugging function stubbing
			byte patching detected by integrity checks
			
			uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
			char* byteToPatch = reinterpret_cast<char*>(baseAddr + 0x1778342 + 0x1000);
			*byteToPatch = 0x85;
			*/
			info->ContextRecord->Rax = 0;
			printf("bp1: %llx %llx %llx\n", exceptionAddr, idaExceptionAddr, returnAddr);
			
			//SuspendAllThreads();
			info->ContextRecord->EFlags |= ResumeFlag;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (info->ContextRecord->Dr6 & 0x2)
		{
			// map mp_cartel 1 1
			// sv_ae_init
			// cmd mrp 48 20 146 0

			printf("bp2: %llx %llx %llx\n", exceptionAddr, idaExceptionAddr, returnAddr);
			printf("%s strlen: %d\n", (char*)info->ContextRecord->Rdx, strlen((char*)info->ContextRecord->Rdx));

			if (strcmp((char*)info->ContextRecord->Rdx, "cmd iwr 2 1\n") == 0)
				multiplayerCounter += 1;

			if (multiplayerCounter == 2 && !multiplayerEnabled)
			{
				*(DWORD64*)(baseAddr + 0xa85f9c8 + 0x1000) = 1;
				*(DWORD64*)(baseAddr + 0x2ec4fc8 + 0x1000) = 10;
				LiveStorage_ParseKeysTxt("mp_common,1,LKBcjAtLFtrhGQqXZP3GQN2MXbGe4yBA4CJ8KK+Tmyw=");
				LiveStorage_ParseKeysTxt2("mp_common,1,LKBcjAtLFtrhGQqXZP3GQN2MXbGe4yBA4CJ8KK+Tmyw=");

				// if we call cbufaddtext in here we crash since we are basically creating an infintely loop
				info->ContextRecord->Rdx = (DWORD64)disconnectCvar;
				
				multiplayerEnabled = true;
			}

			if (strcmp((char*)info->ContextRecord->Rdx, "map mp_tank 1 0\n") == 0)
				info->ContextRecord->Rdx = (DWORD64)devmapCvar;
				

			//SuspendAllThreads();
			info->ContextRecord->EFlags |= ResumeFlag;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (info->ContextRecord->Dr6 & 0x4)
		{
			printf("bp3: %llx %llx %llx\n", exceptionAddr, idaExceptionAddr, returnAddr);
			//SuspendAllThreads();
			//printf("cvar addr: %llx\n", info->ContextRecord->Rdx);

			//SuspendAllThreads();
			info->ContextRecord->EFlags |= ResumeFlag;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (info->ContextRecord->Dr6 & 0x8)
		{
			static int bpCounter = 0;
			bpCounter++;
			printf("bp4: %llx %llx %llx\n", exceptionAddr, idaExceptionAddr, returnAddr);
			info->ContextRecord->Rax = 0;
			/*
			if (bpCounter == 2)
				SuspendAllThreads();
			*/

			info->ContextRecord->EFlags |= ResumeFlag;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		// Veh hooking
		// PageGuardMemory(breakpointAddress, 1);
		
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

DWORD WINAPI hide_being_debugged(LPVOID lpReserved)
{
	while (true) {
		auto* const peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
		peb->BeingDebugged = false;
		*reinterpret_cast<PDWORD>(LPSTR(peb) + 0xBC) &= ~0x70;
	}
}

void disableTlsCallbacks()
{
	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
	char* tlscallback_1 = reinterpret_cast<char*>(baseAddr + 0xf9b6a02 + 0x1000);
	char* tlscallback_2 = reinterpret_cast<char*>(baseAddr + 0x6d4b17 + 0x1000);
	char* tlscallback_3 = reinterpret_cast<char*>(baseAddr + 0xbe2912 + 0x1000);

	if (MH_CreateHook(tlscallback_1, &generalTlsCallbackFunction, NULL) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(tlscallback_1) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(tlscallback_2, &generalTlsCallbackFunction, NULL) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(tlscallback_2) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(tlscallback_3, &generalTlsCallbackFunction, NULL) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(tlscallback_3) != MH_OK) { printf("hook didn't work\n"); }

	printf("disabled tls callbacks\n");
}

// TOOD: function to remove BP's
// SetBits(cxt.Dr7, m_index*2, 1, 0);

void placeHardwareBP(void* addr, int count, Condition condition)
{
	context.ContextFlags = (CONTEXT_DEBUG_REGISTERS & ~CONTEXT_AMD64);

	switch (count)
	{
	case 0:
		context.Dr0 = (DWORD64)addr;
		SetBits((unsigned long&)context.Dr7, 0, 1, 1);
		SetBits((unsigned long&)context.Dr7, 16, 2, condition);
		SetBits((unsigned long&)context.Dr7, 18, 2, 8);
		break;
	case 1:
		context.Dr1 = (DWORD64)addr;
		SetBits((unsigned long&)context.Dr7, 2, 1, 1);
		SetBits((unsigned long&)context.Dr7, 20, 2, condition);
		SetBits((unsigned long&)context.Dr7, 22, 2, 8);
		break;
	case 2:
		context.Dr2 = (DWORD64)addr;
		SetBits((unsigned long&)context.Dr7, 4, 1, 1);
		SetBits((unsigned long&)context.Dr7, 24, 2, condition);
		SetBits((unsigned long&)context.Dr7, 26, 2, 8);
		break;
	case 3:
		context.Dr3 = (DWORD64)addr;
		SetBits((unsigned long&)context.Dr7, 6, 1, 1);
		SetBits((unsigned long&)context.Dr7, 28, 2, condition);
		SetBits((unsigned long&)context.Dr7, 30, 2, 8);
		break;
	default:
		printf("Error: bp count is out of scope!\n");
	}

	bool result = SetThreadContextOrig(GetCurrentThread(), &context);
	if (result == 0)
		printf("didn't work to overwrite thread context\n");

	// Loop each thread and attach breakpoints
	HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (snapshotHandle == INVALID_HANDLE_VALUE)
		printf("couldn't get snapshot\n");

	THREADENTRY32 entry = {};
	entry.dwSize = sizeof(THREADENTRY32);

	auto z = Thread32First(snapshotHandle, &entry);
	do {
		if (entry.th32OwnerProcessID == GetCurrentProcessId())
		{
			HANDLE currentThread = OpenThread(THREAD_ALL_ACCESS, false, entry.th32ThreadID);
			bool setThreadResult = SetThreadContextOrig(currentThread, &context);

			if (setThreadResult == 0)
				printf("didn't work to overwrite thread context\n");
		}

	} while (Thread32Next(snapshotHandle, &entry));
}

void initalizeHooks()
{
	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
	char* byteToPatch = reinterpret_cast<char*>(baseAddr + 0x1778342 + 0x1000);
	*byteToPatch = 0x85;
	disableTlsCallbacks();
}

DWORD WINAPI main(LPVOID lpReserved)
{
	AddVectoredExceptionHandler(true, exceptionHandler);

	auto* const peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
	peb->BeingDebugged = false;
	*reinterpret_cast<PDWORD>(LPSTR(peb) + 0xBC) &= ~0x70;

	/*
	// CreateThread is detected, maybe check to see how we can avoid detection of threads
	// Else we could just hook GetTickCount64 and use that to call something frequently
	// Return INVALID_HANDLE_VALUE somehow when it wants to access the thread?
	CreateThread(nullptr, 0, hide_being_debugged, module, 0, nullptr);
	*/

	/*
		NtSetInformationThread / NtQueryInformationThread with ThreadHideFromDebugger
		OutputDebugStringA
		EnumWindows
	*/

	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));

	void* GetWindowTextAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "GetWindowTextA");
	void* EnumWindowsAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "EnumWindows");

	void* GetThreadContextAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "GetThreadContext");
	void* OpenProcessAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "OpenProcess");
	void* SetThreadContextAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "SetThreadContext");
	void* GetTickCount64Addr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "GetTickCount64");
	void* CheckRemoteDebuggerPresentAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "CheckRemoteDebuggerPresent");
	void* OutputDebugStringAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "OutputDebugStringA");

	void* CreateThreadAddr = (void*)GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateThread");
	void* CreateMutexExAddr = (void*)GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateMutexExA");

	void* NtSetInformationThreadAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtSetInformationThread");
	void* NtQueryInformationThreadAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");
	void* NtQueryInformationProcessAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");
	void* NtQuerySystemInformationAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
	void* NtTerminateProcessAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtTerminateProcess");

	// TODO: finish this hook
	void* RtlCreateQueryDebugBufferAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCreateQueryDebugBuffer");
	void* CreateDXGIFactory1Addr = (void*)GetProcAddress(GetModuleHandle("dxgi.dll"), "CreateDXGIFactory1");

	AllocConsole();
	freopen("CONIN$", "r", stdin);
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);
	inputHandle = CreateThread(nullptr, 0, ConsoleInput, module, 0, nullptr);

	auto mhinit = MH_Initialize();

	if (MH_CreateHook(GetWindowTextAddr, &GetWindowTextFunc, reinterpret_cast<LPVOID*>(&GetWindowTextOrig)) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(GetWindowTextAddr) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(EnumWindowsAddr, &EnumWindowsFunc, reinterpret_cast<LPVOID*>(&EnumWindowsOrig)) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(EnumWindowsAddr) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(GetThreadContextAddr, &GetThreadContextFunc, reinterpret_cast<LPVOID*>(&GetThreadContextOrig)) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(GetThreadContextAddr) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(SetThreadContextAddr, &SetThreadContextFunc, reinterpret_cast<LPVOID*>(&SetThreadContextOrig)) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(SetThreadContextAddr) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(CreateThreadAddr, &CreateThreadFunc, reinterpret_cast<LPVOID*>(&CreateThreadOrig)) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(CreateThreadAddr) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(GetTickCount64Addr, &GetTickCount64Func, reinterpret_cast<LPVOID*>(&GetTickCount64Orig)) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(GetTickCount64Addr) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(CreateMutexExAddr, &CreateMutexExFunc, reinterpret_cast<LPVOID*>(&CreateMutexExOrig)) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(CreateMutexExAddr) != MH_OK) { printf("hook didn't work\n"); }
	
	if (MH_CreateHook(NtQueryInformationProcessAddr, &NtQueryInformationProcessFunc, reinterpret_cast<LPVOID*>(&NtQueryInformationProcessOrig)) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(NtQueryInformationProcessAddr) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(NtQuerySystemInformationAddr, &NtQuerySystemInformationFunc, reinterpret_cast<LPVOID*>(&NtQuerySystemInformationOrig)) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(NtQuerySystemInformationAddr) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(NtSetInformationThreadAddr, &NtSetInformationThreadFunc, reinterpret_cast<LPVOID*>(&NtSetInformationThreadOrig)) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(NtSetInformationThreadAddr) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(NtQueryInformationThreadAddr, &NtQueryInformationThreadFunc, reinterpret_cast<LPVOID*>(&NtQueryInformationThreadOrig)) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(NtQueryInformationThreadAddr) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(CheckRemoteDebuggerPresentAddr, &CheckRemoteDebuggerPresentFunc, reinterpret_cast<LPVOID*>(&CheckRemoteDebuggerPresentOrig)) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(CheckRemoteDebuggerPresentAddr) != MH_OK) { printf("hook didn't work\n"); }

	baseFuncAddr = reinterpret_cast<char*>(baseAddr + 0x177833f + 0x1000);
	placeHardwareBP(baseFuncAddr, 0, Condition::Execute);

	char* addr2 = reinterpret_cast<char*>(baseAddr + 0x16f2a10 + 0x1000);
	placeHardwareBP(addr2, 1, Condition::Execute);

	char* addr3 = reinterpret_cast<char*>(baseAddr + 0x1011340 + 0x1000);
	placeHardwareBP(addr3, 2, Condition::Execute);

	// TODO: reverse the dvar pool creation more
	//char* addr4 = reinterpret_cast<char*>(baseAddr + 0x4eb07f0 + 0x1000);
	//placeHardwareBP(addr4, 3, Condition::Write);
	char* addr4 = reinterpret_cast<char*>(baseAddr + 0x10113a6 + 0x1000);
	placeHardwareBP(addr4, 3, Condition::Execute);

	// VEH hooking
	//initializeBreakpoint(CreateDXGIFactory1Addr);

	CbufAddText = reinterpret_cast<CbufAddText_t>(baseAddr + 0x16f2a10 + 0x1000);
	LiveStorage_ParseKeysTxt = reinterpret_cast<LiveStorage_ParseKeysTxt_t>(baseAddr + 0x1011720);
	LiveStorage_ParseKeysTxt2 = reinterpret_cast<LiveStorage_ParseKeysTxt2_t>(baseAddr + 0x1012900);
	SetScreen = reinterpret_cast<SetScreen_t>(baseAddr + 0x105D9C0);

	printf("hooked %llx\n", baseFuncAddr);
	return 0;
}
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
#include "gamestructs.h"
#include "winstructs.h"
#include "restorentdll.h"
#include "utils.h"
#include "systemhooks.h"
#include "exceptions.h"

bool weAreDebugging = false;
HANDLE inputHandle = nullptr;
HANDLE ntdllFileHandle = nullptr;
HANDLE ntdllOriginalFileHandle = nullptr;
HANDLE win32uFileHandle = nullptr;
HANDLE win32uOriginalFileHandle = nullptr;
HANDLE gameHandle = nullptr;
HANDLE debugThreadHandle = nullptr;
bool hookedfunction = false;
bool suspendNewThreads = false;
char* endofTextSectionAddr = nullptr;
void* RtlRestoreContextAddr;
uint64_t OffsetOfSetInfoFunc = 0;

std::vector<PVOID> VectoredExceptions;
CONTEXT context = {};

typedef HWND(__stdcall* CreateWindowEx_t)(DWORD     dwExStyle,
	LPCSTR    lpClassName,
	LPCSTR    lpWindowName,
	DWORD     dwStyle,
	int       X,
	int       Y,
	int       nWidth,
	int       nHeight,
	HWND      hWndParent,
	HMENU     hMenu,
	HINSTANCE hInstance,
	LPVOID    lpParam);
CreateWindowEx_t CreateWindowExOrig;

typedef int(__stdcall* GetWindowText_t)(HWND hWnd, LPSTR lpString, int nMaxCount);
GetWindowText_t GetWindowTextOrig;

typedef BOOL(__stdcall* EnumWindowsOrig_t)(WNDENUMPROC lpEnumFunc, LPARAM lParam);
EnumWindowsOrig_t EnumWindowsOrig;

typedef int(__stdcall* GetThreadContext_t)(HANDLE hThread, CONTEXT* lpContext);
GetThreadContext_t GetThreadContextOrig;

typedef int(__stdcall* SetThreadContext_t)(HANDLE hThread, CONTEXT* lpContext);
SetThreadContext_t SetThreadContextOrig;

typedef HANDLE(__stdcall* CreateThread_t)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
CreateThread_t CreateThreadOrig;

typedef ULONGLONG(__stdcall* GetTickCount64_t)();
GetTickCount64_t GetTickCount64Orig;

typedef PVOID(__stdcall* AddVectoredExceptionHandler_t)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
AddVectoredExceptionHandler_t AddVectoredExceptionHandlerOrig;

typedef LPTOP_LEVEL_EXCEPTION_FILTER(__stdcall* SetUnhandledExceptionFilter_t)(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
SetUnhandledExceptionFilter_t SetUnhandledExceptionFilterOrig;

typedef HANDLE(__stdcall* NtUserQueryWindow_t)(HWND hwnd, WINDOWINFOCLASS WindowInfo);
NtUserQueryWindow_t NtUserQueryWindowOrig;

typedef HWND(__stdcall* NtUserGetForegroundWindow_t)();
NtUserGetForegroundWindow_t NtUserGetForegroundWindowOrig;

typedef NTSTATUS(__stdcall* NtUserBuildHwndList_t)(HDESK hDesk, HWND hWndNext, BOOL EnumChildren, BOOL RemoveImmersive, DWORD ThreadID, UINT Max, HWND* List, PULONG Cnt);
NtUserBuildHwndList_t NtUserBuildHwndListOrig;

typedef NTSTATUS(__stdcall* NtCreateFile_t)(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength);
NtCreateFile_t NtCreateFileOrig;

typedef NTSTATUS(__stdcall* NtQueryInformationProcess_t)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
NtQueryInformationProcess_t NtQueryInformationProcessOrig;

typedef NTSTATUS(__stdcall* NtSetInformationProcess_t)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
NtSetInformationProcess_t NtSetInformationProcessOrig;

typedef NTSTATUS(__stdcall* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NtQuerySystemInformation_t NtQuerySystemInformationOrig;

typedef BOOL(__stdcall* CheckRemoteDebuggerPresent_t)(HANDLE hProcess, PBOOL pbDebuggerPresent);
CheckRemoteDebuggerPresent_t CheckRemoteDebuggerPresentOrig;

typedef HANDLE(__stdcall* CreateMutexEx_t)(const LPSECURITY_ATTRIBUTES attributes, const LPCSTR name, const DWORD flags, const DWORD access);
CreateMutexEx_t CreateMutexExOrig;

typedef NTSTATUS(__stdcall* NtCreateThreadEx_t)(PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PUSER_THREAD_START_ROUTINE StartRoutine,
	PVOID Argument,
	ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PPS_ATTRIBUTE_LIST AttributeList);
NtCreateThreadEx_t NtCreateThreadExOrig;

typedef HHOOK(__stdcall* SetWindowsHookEx_t)(
	int       idHook,
	HOOKPROC  lpfn,
	HINSTANCE hmod,
	DWORD     dwThreadId);
SetWindowsHookEx_t SetWindowsHookExOrig;

ULONGLONG GetTickCount64Func()
{
	return GetTickCount64Orig();
}

bool GetThreadContextFunc(HANDLE thread, CONTEXT context)
{
	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
	auto* source = _ReturnAddress();
	HMODULE module;
	GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, static_cast<LPCSTR>(source), &module);

	if ((baseAddr == (uint64_t)module) && !weAreDebugging)
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

	if ((baseAddr == (uint64_t)module) && !weAreDebugging)
		return 0;
	else
		return SetThreadContextOrig(thread, context);
}

typedef NTSTATUS(__fastcall* NtSetInformationThread_t)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
NtSetInformationThread_t NtSetInformationThreadOrig;

typedef NTSTATUS(__fastcall* NtQueryInformationThread_t)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
NtQueryInformationThread_t NtQueryInformationThreadOrig;

typedef NTSTATUS(__fastcall* NtQueryInformationFile_t)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
	ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
NtQueryInformationFile_t NtQueryInformationFileOrig;

typedef void(__fastcall* RtlRestoreContext_t)(PCONTEXT ContextRecord, _EXCEPTION_RECORD* ExceptionRecord);
RtlRestoreContext_t RtlRestoreContextOrig;

typedef NTSTATUS(__fastcall* NtAllocateVirtualMemory_t)(HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect);
NtAllocateVirtualMemory_t NtAllocateVirtualMemoryOrig;

typedef NTSTATUS(__fastcall* NtMapViewOfSection_t)(HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);
NtMapViewOfSection_t NtMapViewOfSectionOrig;

typedef NTSTATUS(__fastcall* NtSetInformationJobObject_t)(HANDLE* JobHandle,
	ACCESS_MASK        DesiredAccess,
	OBJECT_ATTRIBUTES* ObjectAttributes);
NtSetInformationJobObject_t NtSetInformationJobObjectOrig;

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

NTSTATUS NtCreateThreadExFunc(PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PUSER_THREAD_START_ROUTINE StartRoutine,
	PVOID Argument,
	ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PPS_ATTRIBUTE_LIST AttributeList)
{
	if (CreateFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER)
	{
		//printf("thread tried to hide from debugger\n");

		CreateFlags = THREAD_CREATE_FLAGS_NONE;
		NTSTATUS result = NtCreateThreadExOrig(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, THREAD_CREATE_FLAGS_NONE, ZeroBits, StackSize, MaximumStackSize, AttributeList);
		return result;
	}

	NTSTATUS result = NtCreateThreadExOrig(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
	return result;
}

HHOOK SetWindowsHookExFunc(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId)
{
	//printf("SetHookEx called with hook id %llx from thread id %llx\n", idHook, dwThreadId);
	return 0;
}


NTSTATUS NtQuerySystemInformationFunc(SYSTEM_INFORMATION_CLASS system_information_class, PVOID system_information, ULONG system_information_length, PULONG return_length)
{
	NTSTATUS status = { 0 };
	status = NtQuerySystemInformationOrig(system_information_class, system_information, system_information_length, return_length);

	if (NT_SUCCESS(status))
	{
		if (system_information_class == SystemProcessInformation || system_information_class == SystemSessionProcessInformation || system_information_class == SystemExtendedProcessInformation)
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
			for (int i = 0; i < handleInfo->NumberOfHandles; i++)
			{
				SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = handleInfo->Handles[i];
				printf("%d ", handle.UniqueProcessId);
			}

			printf("\nchecked for handle information\n");
		}

		if (system_information_class == SystemExtendedHandleInformation)
		{
			printf("\nchecked for handle information ex\n");
		}
	}

	return status;
}

NTSTATUS NtSetInformationThreadFunc(HANDLE handle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
{
	if (ThreadInformationClass == ThreadHideFromDebugger)
	{
		//printf("thread %llx %llx %llx threadhidefromdebugger\n", handle, ThreadInformation, ThreadInformationLength);

		DWORD flags;
		if (ThreadInformation == 0 && ThreadInformationLength == 0 && (GetHandleInformation(handle, &flags) != 0))
		{
			return 0;
		}
		else
			return 0xc0000008;

		printf("thread thats hidden from debugger got made\n");
	}

	return NtSetInformationThreadOrig(handle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

NTSTATUS NtQueryInformationFileFunc(HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass)
{
	if (FileHandle == ntdllFileHandle)
	{
		//printf("checked for our own ntdll file handle, info class %d\n", FileInformationClass);

		if (FileInformationClass == FileNameInformation)
		{
			FILE_NAME_INFORMATION* nameInfo = (FILE_NAME_INFORMATION*)FileInformation;

			char ntdll_iosb[256];
			NTSTATUS origCall = NtQueryInformationFileOrig(ntdllOriginalFileHandle, (PIO_STATUS_BLOCK)ntdll_iosb, FileInformation, Length, FileInformationClass);

			char ntdllHooked_buffer[MAX_PATH * 2] = {};
			NTSTATUS hookedCall = NtQueryInformationFileOrig(FileHandle, IoStatusBlock, ntdllHooked_buffer, MAX_PATH * 2, FileInformationClass);

			return hookedCall;
		}

		NTSTATUS result = NtQueryInformationFileOrig(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
		return result;
	}

	if (FileHandle == win32uFileHandle)
	{
		//printf("checked for our own win32u file handle, info class %d\n", FileInformationClass);

		if (FileInformationClass == FileNameInformation)
		{
			FILE_NAME_INFORMATION* nameInfo = (FILE_NAME_INFORMATION*)FileInformation;

			char win32u_iosb[256];
			NTSTATUS origCall = NtQueryInformationFileOrig(win32uOriginalFileHandle, (PIO_STATUS_BLOCK)win32u_iosb, FileInformation, Length, FileInformationClass);

			char win32uHooked_buffer[MAX_PATH * 2] = {};
			NTSTATUS hookedCall = NtQueryInformationFileOrig(FileHandle, IoStatusBlock, win32uHooked_buffer, MAX_PATH * 2, FileInformationClass);

			return hookedCall;
		}

		NTSTATUS result = NtQueryInformationFileOrig(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
		return result;
	}

	NTSTATUS result = NtQueryInformationFileOrig(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	return result;
}

void RtlRestoreContextFunc(PCONTEXT ContextRecord, _EXCEPTION_RECORD* ExceptionRecord)
{
	// After recovering from an exception, the main thread's hw Dr0-3 registers get set.
	// Clears hw breakpoints
	ContextRecord->Dr0 = 0;
	ContextRecord->Dr1 = 0;
	ContextRecord->Dr2 = 0;
	ContextRecord->Dr3 = 0;
	RtlRestoreContextOrig(ContextRecord, ExceptionRecord);

	MH_RemoveHook(RtlRestoreContextAddr);
}

NTSTATUS NtQueryInformationThreadFunc(HANDLE handle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength)
{
	if (ThreadInformationClass == ThreadHideFromDebugger)
	{
		DWORD flags;
		if (ThreadInformationLength == sizeof(BOOLEAN) && (GetHandleInformation(handle, &flags) != 0))
		{
			char* info = (char*)ThreadInformation;
			*info = 1;
			//RestoreNtdllDbgFunctions();
			return 0;
		}
		else
			return 0x80000002;

		//printf("thread hide from debugger query slipped through\n");
	}

	return NtQueryInformationThreadOrig(handle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}

std::vector<uint64_t> previousHandles = { 0x0 };

NTSTATUS NtAllocateVirtualMemoryFunc(HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect)
{
	NTSTATUS result = NtAllocateVirtualMemoryOrig(ProcessHandle,
		BaseAddress,
		ZeroBits,
		RegionSize,
		AllocationType,
		Protect);

	if (Protect & PAGE_EXECUTE_READWRITE && *(SIZE_T*)RegionSize == 0x1EF000)
	{
		//printf("ntdll.dll allocated %llx %llx %llx %llx\n", *BaseAddress, *(SIZE_T*)RegionSize, Protect, AllocationType);

		uint64_t baseAddr = *(uint64_t*)BaseAddress;
		uint64_t setInfoOffset = baseAddr + 0x9C300;
		//printf("setinfo offset: %llx\n", setInfoOffset);
	}

	return result;
}

HWND DialogButton = 0;
DWORD WINAPI testThread()
{
	while (true)
	{
		SendMessage(DialogButton, BM_CLICK, 0, 0);

		if (!IsWindowVisible(DialogButton))
			return 0;
	}
}

HWND CreateWindowExFunc(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle,
	int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
	HWND result = CreateWindowExOrig(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);

	// style for buttons, hardcoded since I didn't bother reading the flags for when a button is made
	if (dwStyle == 0x50000000)
	{
		static int counter = 0;
		counter++;

		// sliders get included too as "buttons", 3rd counter is the recommended options
		if (counter == 5)
		{
			DialogButton = result;
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)testThread, NULL, 0, NULL);
		}
	}

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
	//printf("enum called\n");
	return EnumWindowsOrig(lpEnumFunc, lParam);
}

void SleepAllThreadsBesidesMainThread()
{
	HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

	//if (snapshotHandle == INVALID_HANDLE_VALUE)
		//printf("couldn't get snapshot\n");

	THREADENTRY32 entry = {};
	entry.dwSize = sizeof(THREADENTRY32);
	Thread32First(snapshotHandle, &entry);
	int counter = 0;

	//printf("suspending...\n");

	do {
		if (entry.th32OwnerProcessID == GetCurrentProcessId())
		{
			HANDLE currentThread = OpenThread(THREAD_ALL_ACCESS, true, entry.th32ThreadID);

			//if (currentThread == NULL)
				//printf("couldn't openthread\n");

			if (counter == 0)
			{
				gameHandle = currentThread;
				counter++;
				continue;
			}

			char threadHiddenFromDebugger = 0;
			NtQueryInformationThreadOrig(currentThread, ThreadHideFromDebugger, &threadHiddenFromDebugger, sizeof(char), NULL);
			//printf("thread %d suspend: %llx\n", GetThreadId(currentThread), threadHiddenFromDebugger);

			SuspendThread(currentThread);
		}

	} while (Thread32Next(snapshotHandle, &entry));
}

HANDLE WINAPI CreateThreadFunc(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	if (weAreDebugging)
	{
		HANDLE thread = CreateThreadOrig(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
		return thread;
	}

	// Loop each thread and attach breakpoints
	HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	//if (snapshotHandle == INVALID_HANDLE_VALUE)
		//printf("couldn't get snapshot\n");

	THREADENTRY32 entry = {};
	entry.dwSize = sizeof(THREADENTRY32);
	Thread32First(snapshotHandle, &entry);

	do {
		if (entry.th32OwnerProcessID == GetCurrentProcessId())
		{
			HANDLE currentThread = OpenThread(THREAD_ALL_ACCESS, false, entry.th32ThreadID);
			bool setThreadResult = 1;

			if (!suspendNewThreads)
				setThreadResult = SetThreadContextOrig(currentThread, &context);

			//	if (setThreadResult == 0)
			//		printf("didn't work to overwrite thread context\n");
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

HANDLE NtUserQueryWindowFunc(HWND hwnd, WINDOWINFOCLASS WindowInfo)
{
	if ((WindowInfo == WindowProcess || WindowInfo == WindowThread) && IsWindowBad(hwnd))
	{
		if (WindowInfo == WindowProcess)
			return NtCurrentTeb()->ClientId.UniqueProcess;
		if (WindowInfo == WindowThread)
			return NtCurrentTeb()->ClientId.UniqueThread;
	}

	HANDLE result = NtUserQueryWindowOrig(hwnd, WindowInfo);
	return result;
}

HWND NtUserGetForegroundWindowFunc()
{
	HWND result = NtUserGetForegroundWindowOrig();

	if (result != nullptr && IsWindowBad(result))
		result = NULL;

	return result;
}

NTSTATUS NtUserBuildHwndListFunc(HDESK hDesk, HWND hWndNext, BOOL EnumChildren, BOOL RemoveImmersive, DWORD ThreadID, UINT Max, HWND* List, PULONG Cnt)
{
	NTSTATUS result = NtUserBuildHwndListOrig(hDesk, hWndNext, EnumChildren, RemoveImmersive, ThreadID, Max, List, Cnt);

	if (NT_SUCCESS(result) && List != nullptr && Cnt != nullptr)
		FilterHwndList(List, Cnt);

	return result;
}

BOOL CheckRemoteDebuggerPresentFunc(HANDLE hProcess, PBOOL pbDebuggerPresent)
{
	//printf("checked for debugger %llx\n", _ReturnAddress());

	*(BOOL*)pbDebuggerPresent = false;
	return true;
}

PVOID AddVectoredExceptionHandlerFunc(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
{
	//printf("exception handler added %llx\n", Handler);
	PVOID handler = AddVectoredExceptionHandlerOrig(First, Handler);

	VectoredExceptions.push_back(handler);
	return handler;
}

LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilterFunc(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
{
	//printf("seh filter called\n");

	//return SetUnhandledExceptionFilterOrig(lpTopLevelExceptionFilter);
	return 0;
}

NTSTATUS NtCreateFileFunc(
	PHANDLE FileHandle,
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
	NTSTATUS result = NtCreateFileOrig(FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength);

	auto fileName = ObjectAttributes->ObjectName->Buffer;
	//printf("%ls %d\n", fileName, wcscmp((const wchar_t*)fileName, L"GDI32.dll"));

	// dont use wcsstr, use wcscmp instead
	//if (wcsstr((const wchar_t*)fileName, L"GDI32.dll") != nullptr)
	//	printf("gdi32 mapped manually\n");

	// dont use wcsstr, use wcscmp instead
	//if (wcsstr((const wchar_t*)fileName, L"USER32.dll") != nullptr)
	//	printf("user32 mapped manually\n");

	if (wcscmp((const wchar_t*)fileName, L"\\??\\C:\\Windows\\System32\\win32u.dll") == 0)
	{
		//printf("win32u mapped manually\n");

		NtCreateFileOrig(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
		win32uOriginalFileHandle = *(HANDLE*)FileHandle;

		int fd = _open_osfhandle((uint64_t)win32uOriginalFileHandle, _O_RDONLY);
		FILE* win32uFile = _fdopen(fd, "rb");

		// create buffer from ntdll that we will later feed to the pipe
		fseek(win32uFile, 0L, SEEK_END);
		uint64_t size = ftell(win32uFile);
		fseek(win32uFile, 0L, SEEK_SET);

		char* win32uBuffer = (char*)malloc(sizeof(char) * size);
		fread(win32uBuffer, sizeof(char), size, win32uFile);
		fseek(win32uFile, 0L, SEEK_SET);

		// memcpy ntdll into virtualalloced chunk
		LPVOID allocatedChunk = VirtualAlloc(NULL, sizeof(char) * size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		//printf("allocatedChunk %llx\n", allocatedChunk);
		memcpy(allocatedChunk, win32uBuffer, sizeof(char) * size);

		uint64_t ntUserQueryWindowOffset = (uint64_t)allocatedChunk + 0x0630;
		uint64_t ntUserBuildHwndListOffset = (uint64_t)allocatedChunk + 0x07B0;
		uint64_t ntUserGetForegroundWindowOffset = (uint64_t)allocatedChunk + 0x0BB0;

		//void* NtUserQueryWindowAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserQueryWindow");
		//memcpy((void*)ntUserQueryWindowOffset, NtUserQueryWindowAddr, sizeof(char) * 14);

		ManualHookFunction((uint64_t)NtUserQueryWindowFunc, ntUserQueryWindowOffset);
		ManualHookFunction((uint64_t)NtUserBuildHwndListFunc, ntUserBuildHwndListOffset);
		ManualHookFunction((uint64_t)NtUserGetForegroundWindowFunc, ntUserGetForegroundWindowOffset);

		// memcpy hooked virtual alloc chunk into buffer
		memcpy(win32uBuffer, allocatedChunk, sizeof(char) * size);
		VirtualFree(allocatedChunk, 0, MEM_RELEASE);

		// write buffer back to a file
		FILE* fakeNtdll = fopen("E:/SteamLibrary/steamapps/common/BOCW/win32u.dll", "wb+");
		fwrite(win32uBuffer, sizeof(char), size, fakeNtdll);
		fclose(fakeNtdll);
		free(win32uBuffer);

		OBJECT_ATTRIBUTES objAttributes = {};
		UNICODE_STRING unicodeString;

		RtlInitUnicodeString(
			&unicodeString,
			L"\\??\\E:\\SteamLibrary\\steamapps\\common\\BOCW\\win32u.dll"
		);

		InitializeObjectAttributes(&objAttributes, &unicodeString, OBJ_CASE_INSENSITIVE, 0, NULL);

		NTSTATUS result = NtCreateFileOrig(FileHandle, DesiredAccess, &objAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

		ntdllFileHandle = *(HANDLE*)FileHandle;

		//printf("CreateFile win32u.dll called %llx\n", ntdllFileHandle);
		return result;
	}

	//if (wcsstr((const wchar_t*)fileName, L"ntdll.dll") != nullptr)
	if (wcscmp((const wchar_t*)fileName, L"\\??\\C:\\Windows\\SYSTEM32\\ntdll.dll") == 0)
	{
		NtCreateFileOrig(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
		ntdllOriginalFileHandle = *(HANDLE*)FileHandle;

		int fd = _open_osfhandle((uint64_t)ntdllOriginalFileHandle, _O_RDONLY);
		FILE* ntdllFile = _fdopen(fd, "rb");

		// create buffer from ntdll that we will later feed to the pipe
		fseek(ntdllFile, 0L, SEEK_END);
		uint64_t size = ftell(ntdllFile);
		fseek(ntdllFile, 0L, SEEK_SET);

		char* ntdllBuffer = (char*)malloc(sizeof(char) * size);
		fread(ntdllBuffer, sizeof(char), size, ntdllFile);
		fseek(ntdllFile, 0L, SEEK_SET);

		// memcpy ntdll into virtualalloced chunk
		LPVOID allocatedChunk = VirtualAlloc(NULL, sizeof(char) * size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		//printf("allocatedChunk %llx\n", allocatedChunk);
		memcpy(allocatedChunk, ntdllBuffer, sizeof(char) * size);

		uint64_t ntSetInformationThreadOffset = (uint64_t)allocatedChunk + 0x9C300;
		uint64_t ntQueryInformationThreadOffset = (uint64_t)allocatedChunk + 0x9C600;
		uint64_t ntCreateThreadExOffset = (uint64_t)allocatedChunk + 0x9D970;
		uint64_t ntCreateFileOffset = (uint64_t)allocatedChunk + 0x9CC70;
		uint64_t ntQueryInformationProcessOffset = (uint64_t)allocatedChunk + 0x9C480;
		uint64_t ntQuerySystemInformationOffset = (uint64_t)allocatedChunk + 0x9C820;

		ManualHookFunction((uint64_t)NtSetInformationThreadFunc, ntSetInformationThreadOffset);
		ManualHookFunction((uint64_t)NtQueryInformationThreadFunc, ntQueryInformationThreadOffset);
		ManualHookFunction((uint64_t)NtCreateThreadExFunc, ntCreateThreadExOffset);
		ManualHookFunction((uint64_t)NtCreateFileFunc, ntCreateFileOffset);
		ManualHookFunction((uint64_t)NtQueryInformationProcessFunc, ntQueryInformationProcessOffset);
		ManualHookFunction((uint64_t)NtQuerySystemInformationFunc, ntQuerySystemInformationOffset);

		// memcpy hooked virtual alloc chunk into buffer
		memcpy(ntdllBuffer, allocatedChunk, sizeof(char) * size);
		VirtualFree(allocatedChunk, 0, MEM_RELEASE);

		// write buffer back to a file
		FILE* fakeNtdll = fopen("E:/SteamLibrary/steamapps/common/BOCW/ntdll.dll", "wb+");
		fwrite(ntdllBuffer, sizeof(char), size, fakeNtdll);
		fclose(fakeNtdll);
		free(ntdllBuffer);

		OBJECT_ATTRIBUTES objAttributes = {};
		UNICODE_STRING unicodeString;

		RtlInitUnicodeString(
			&unicodeString,
			L"\\??\\E:\\SteamLibrary\\steamapps\\common\\BOCW\\ntdll.dll"
		);

		InitializeObjectAttributes(&objAttributes, &unicodeString, OBJ_CASE_INSENSITIVE, 0, NULL);

		NTSTATUS result = NtCreateFileOrig(FileHandle, DesiredAccess, &objAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

		ntdllFileHandle = *(HANDLE*)FileHandle;

		//printf("CreateFile NTDLL.dll called %llx\n", ntdllFileHandle);
		return result;
	}

	return result;
}

// TODO: Sets BeingDebugged to a funny number so we cant just hook it and return 0
// Crashes the game after a while
DWORD WINAPI hide_being_debugged(LPVOID lpReserved)
{
	while (true) {
		auto* const peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
		peb->BeingDebugged = false;
		*reinterpret_cast<PDWORD>(LPSTR(peb) + 0xBC) &= ~0x70;
	}
}

void ManualHookFunction(uint64_t functionAddress, uint64_t setInfoOffset)
{
	unsigned char instructionBuffer[8] = {};
	unsigned char jmpBuffer[14] = {};

	memset(instructionBuffer, 0, sizeof(char) * 8);
	memset(jmpBuffer, 0, sizeof(char) * 14);

	// reverse function address bytes
	for (int i = 0; i < 8; i++)
		instructionBuffer[i] = (functionAddress >> i * 8) & 0xFF;

	// absolute (far) jump instruction
	jmpBuffer[0] = 0xFF;
	jmpBuffer[1] = 0x25;

	// insert function address bytes
	for (int i = 0; i <= 8; i++)
		jmpBuffer[14 - i] = instructionBuffer[8 - i];

	memcpy((char*)setInfoOffset, jmpBuffer, sizeof(unsigned char) * 14);
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

void disableTlsCallbacks()
{
	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
	char* tlscallback_1 = reinterpret_cast<char*>(baseAddr + 0x5f6390 + 0x1000);
	char* tlscallback_2 = reinterpret_cast<char*>(baseAddr + 0x615530 + 0x1000);
	char* tlscallback_3 = reinterpret_cast<char*>(baseAddr + 0x622a10 + 0x1000);

	printf("tls1: %llx\n", tlscallback_1);
	printf("tls2: %llx\n", tlscallback_2);
	printf("tls3: %llx\n", tlscallback_3);

	if (MH_CreateHook(tlscallback_1, &generalTlsCallbackFunction, NULL) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(tlscallback_1) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(tlscallback_2, &generalTlsCallbackFunction, NULL) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(tlscallback_2) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(tlscallback_3, &generalTlsCallbackFunction, NULL) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(tlscallback_3) != MH_OK) { printf("hook didn't work\n"); }

	printf("disabled tls callbacks\n");
}

void SuspendAllThreads()
{
	//printf("suspended: %llx %d\n", GetCurrentThreadId(), GetCurrentThreadId());
	RestoreNtdllDbgFunctions();

	for (int i = 0; i < VectoredExceptions.size(); i++)
	{
		auto result = RemoveVectoredExceptionHandler(VectoredExceptions[i]);
		//if (result != NULL)
		//	printf("removed exception handle at %llx\n", VectoredExceptions[i]);
	}

	/*
	auto result = RemoveVectoredExceptionHandler(exceptionHandle);
	if (result != NULL)
		printf("removed our own exception handle\n");
	*/

	weAreDebugging = true;
	removeAllHardwareBP();

	suspendNewThreads = false;
	SleepAllThreadsBesidesMainThread();

	if (inputHandle != nullptr)
		ResumeThread(inputHandle);

	void* RtlRestoreContextAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlRestoreContext");

	if (MH_CreateHook(RtlRestoreContextAddr, &RtlRestoreContextFunc, (LPVOID*)(&RtlRestoreContextOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_EnableHook(RtlRestoreContextAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_DisableHook(MH_ALL_HOOKS) != MH_OK)
		printf("couldnt remove all hooks\n");

	disableTlsCallbacks();

	// cold war removes the function ptr from ntdll Kernel32ThreadInitThunkFunction to its own, redirecting createremotethread
	// does rdtsc checks which in turn makes it so that if the process is completely suspended, will crash on created threads
	void* BaseInitThread = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlUserThreadStart");
	void* BaseThreadInitThunk = (void*)GetProcAddress(GetModuleHandle("kernel32.dll"), "BaseThreadInitThunk");

	PVOID RtlUserThreadStart = (PVOID)((DWORD64)BaseInitThread + 0x7);
	DWORD64 RtlUserThreadStartFuncOffset = (UINT64)((PUCHAR)RtlUserThreadStart + *(PULONG)((PUCHAR)RtlUserThreadStart + 0x3) + 0x7);
	uint64_t* basethreadinitptr = (uint64_t*)RtlUserThreadStartFuncOffset;
	memcpy(basethreadinitptr, &BaseThreadInitThunk, sizeof(uint64_t));

	char threadHiddenFromDebugger = 0;
	NtQueryInformationThreadOrig(GetCurrentThread(), ThreadHideFromDebugger, &threadHiddenFromDebugger, sizeof(char), NULL);
	//printf("thread %d suspend: %llx\n", GetThreadId(GetCurrentThread()), threadHiddenFromDebugger);

	auto* const peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
	peb->BeingDebugged = false;
	*reinterpret_cast<PDWORD>(LPSTR(peb) + 0xBC) &= ~0x70;

	printf("attach debugger\n");
	
	//while (true) {Sleep(100);}

	// TODO: remove this back to how it normally was after we are done debugging
	while (!IsDebuggerPresent()) {Sleep(100);}
	//Sleep(1000);
	//assert(0);

	//SuspendThread(GetCurrentThread());
	//printf("running...\n");
}

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

	//if (result == 0)
	//	printf("didn't work to overwrite thread context\n");

	// Loop each thread and attach breakpoints
	HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	//if (snapshotHandle == INVALID_HANDLE_VALUE)
	//	printf("couldn't get snapshot\n");

	THREADENTRY32 entry = {};
	entry.dwSize = sizeof(THREADENTRY32);
	Thread32First(snapshotHandle, &entry);

	do {
		if (entry.th32OwnerProcessID == GetCurrentProcessId())
		{
			HANDLE currentThread = OpenThread(THREAD_ALL_ACCESS, false, entry.th32ThreadID);
			bool setThreadResult = SetThreadContextOrig(currentThread, &context);

			//if (setThreadResult == 0)
			//	printf("didn't work to overwrite thread context\n");
		}

	} while (Thread32Next(snapshotHandle, &entry));

	printf("bp %d placed at %llx\n", count + 1, addr);
}

void removeAllHardwareBP()
{
	context.ContextFlags = (CONTEXT_DEBUG_REGISTERS & ~CONTEXT_AMD64);

	context.Dr0 = 0;
	SetBits((unsigned long&)context.Dr7, 0, 1, 0);
	SetBits((unsigned long&)context.Dr7, 16, 2, 0);
	SetBits((unsigned long&)context.Dr7, 18, 2, 0);

	context.Dr1 = 0;
	SetBits((unsigned long&)context.Dr7, 2, 1, 0);
	SetBits((unsigned long&)context.Dr7, 20, 2, 0);
	SetBits((unsigned long&)context.Dr7, 22, 2, 0);

	context.Dr2 = 0;
	SetBits((unsigned long&)context.Dr7, 4, 1, 0);
	SetBits((unsigned long&)context.Dr7, 24, 2, 0);
	SetBits((unsigned long&)context.Dr7, 26, 2, 0);

	context.Dr3 = 0;
	SetBits((unsigned long&)context.Dr7, 6, 1, 0);
	SetBits((unsigned long&)context.Dr7, 28, 2, 0);
	SetBits((unsigned long&)context.Dr7, 30, 2, 0);

	HANDLE mainThread = OpenThread(THREAD_ALL_ACCESS, false, GetCurrentThreadId());
	//bool result = SetThreadContextOrig(GetCurrentThread(), &context);
	bool result1 = SetThreadContextOrig(mainThread, &context);
	if (result1 == 0)
		printf("didn't work to overwrite thread context!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

	bool result2 = SetThreadContextOrig(GetCurrentThread(), &context);
	if (result2 == 0)
		printf("didn't work to overwrite thread context!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

	// Loop each thread and attach breakpoints
	HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (snapshotHandle == INVALID_HANDLE_VALUE)
		printf("couldn't get snapshot\n");

	THREADENTRY32 entry = {};
	entry.dwSize = sizeof(THREADENTRY32);
	Thread32First(snapshotHandle, &entry);

	do {
		if (entry.th32OwnerProcessID == GetCurrentProcessId())
		{
			HANDLE currentThread = OpenThread(THREAD_ALL_ACCESS, false, entry.th32ThreadID);
			bool setThreadResult = SetThreadContextOrig(currentThread, &context);

			//if (setThreadResult == 0)
			//	printf("didn't work to overwrite thread context\n");
		}

	} while (Thread32Next(snapshotHandle, &entry));

	printf("removed all hardware bp's\n");
}

void InitializeSystemHooks()
{
	void* GetThreadContextAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "GetThreadContext");
	void* OpenProcessAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "OpenProcess");
	void* SetThreadContextAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "SetThreadContext");
	void* GetTickCount64Addr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "GetTickCount64");
	void* CheckRemoteDebuggerPresentAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "CheckRemoteDebuggerPresent");
	void* OutputDebugStringAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "OutputDebugStringA");
	void* SetUnhandledExceptionFilterAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "SetUnhandledExceptionFilter");

	void* AddVectoredExceptionHandlerAddr = (void*)GetProcAddress(GetModuleHandle("kernel32.dll"), "AddVectoredExceptionHandler");
	void* CreateThreadAddr = (void*)GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateThread");
	void* CreateMutexExAddr = (void*)GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateMutexExA");

	void* SetWindowsHookExAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "SetWindowsHookExW");
	void* GetWindowTextAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "GetWindowTextA");
	void* CreateWindowExAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "CreateWindowExW");
	void* EnumWindowsAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "EnumWindows");

	void* NtSetInformationThreadAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtSetInformationThread");
	void* NtQueryInformationThreadAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");
	void* NtQueryInformationFileAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationFile");
	void* NtCreateThreadExAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
	void* NtQueryInformationProcessAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");
	void* NtQuerySystemInformationAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
	void* NtAllocateVirtualMemoryAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtAllocateVirtualMemory");
	void* NtCreateFileAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateFile");

	// win32u.dll
	void* NtUserQueryWindowAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserQueryWindow");
	void* NtUserGetForegroundWindowAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserGetForegroundWindow");
	void* NtUserBuildHwndListAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserBuildHwndList");
	void* NtUserFindWindowExAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserFindWindowEx");

	if (MH_CreateHook(CreateWindowExAddr, &CreateWindowExFunc, (LPVOID*)(&CreateWindowExOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(CreateWindowExAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(GetWindowTextAddr, &GetWindowTextFunc, (LPVOID*)(&GetWindowTextOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(GetWindowTextAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(EnumWindowsAddr, &EnumWindowsFunc, (LPVOID*)(&EnumWindowsOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(EnumWindowsAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(GetThreadContextAddr, &GetThreadContextFunc, (LPVOID*)(&GetThreadContextOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(GetThreadContextAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(SetThreadContextAddr, &SetThreadContextFunc, (LPVOID*)(&SetThreadContextOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(SetThreadContextAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(CreateThreadAddr, &CreateThreadFunc, (LPVOID*)(&CreateThreadOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(CreateThreadAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(GetTickCount64Addr, &GetTickCount64Func, (LPVOID*)(&GetTickCount64Orig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(GetTickCount64Addr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(SetWindowsHookExAddr, &SetWindowsHookExFunc, (LPVOID*)(&SetWindowsHookExOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(SetWindowsHookExAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(CreateMutexExAddr, &CreateMutexExFunc, (LPVOID*)(&CreateMutexExOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(CreateMutexExAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(NtCreateThreadExAddr, &NtCreateThreadExFunc, (LPVOID*)(&NtCreateThreadExOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(NtCreateThreadExAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(NtQueryInformationProcessAddr, &NtQueryInformationProcessFunc, (LPVOID*)(&NtQueryInformationProcessOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(NtQueryInformationProcessAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(NtQuerySystemInformationAddr, &NtQuerySystemInformationFunc, (LPVOID*)(&NtQuerySystemInformationOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(NtQuerySystemInformationAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(NtSetInformationThreadAddr, &NtSetInformationThreadFunc, (LPVOID*)(&NtSetInformationThreadOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(NtSetInformationThreadAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(NtQueryInformationThreadAddr, &NtQueryInformationThreadFunc, (LPVOID*)(&NtQueryInformationThreadOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(NtQueryInformationThreadAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(NtQueryInformationFileAddr, &NtQueryInformationFileFunc, (LPVOID*)(&NtQueryInformationFileOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(NtQueryInformationFileAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(NtCreateFileAddr, &NtCreateFileFunc, (LPVOID*)(&NtCreateFileOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(NtCreateFileAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(NtAllocateVirtualMemoryAddr, &NtAllocateVirtualMemoryFunc, (LPVOID*)(&NtAllocateVirtualMemoryOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(NtAllocateVirtualMemoryAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(CheckRemoteDebuggerPresentAddr, &CheckRemoteDebuggerPresentFunc, (LPVOID*)(&CheckRemoteDebuggerPresentOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(CheckRemoteDebuggerPresentAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(AddVectoredExceptionHandlerAddr, &AddVectoredExceptionHandlerFunc, (LPVOID*)(&AddVectoredExceptionHandlerOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(AddVectoredExceptionHandlerAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(SetUnhandledExceptionFilterAddr, &SetUnhandledExceptionFilterFunc, (LPVOID*)(&SetUnhandledExceptionFilterOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(SetUnhandledExceptionFilterAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(NtUserQueryWindowAddr, &NtUserQueryWindowFunc, (LPVOID*)(&NtUserQueryWindowOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(NtUserQueryWindowAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(NtUserGetForegroundWindowAddr, &NtUserGetForegroundWindowFunc, (LPVOID*)(&NtUserGetForegroundWindowOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(NtUserGetForegroundWindowAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(NtUserBuildHwndListAddr, &NtUserBuildHwndListFunc, (LPVOID*)(&NtUserBuildHwndListOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(NtUserBuildHwndListAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}
}
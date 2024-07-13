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
#include "arxan.h"
#include "paths.h"

bool weAreDebugging = false;
DWORD inputThreadId = -1;
HANDLE inputHandle = nullptr;
HANDLE ntdllFileHandle = nullptr;
HANDLE ntdllOriginalFileHandle = nullptr;
HANDLE win32uFileHandle = nullptr;
HANDLE win32uOriginalFileHandle = nullptr;
HANDLE gameHandle = nullptr;
HANDLE debugThreadHandle = nullptr;
bool hookedfunction = false;
char* endofTextSectionAddr = nullptr;
void* RtlRestoreContextAddr;
uint64_t OffsetOfSetInfoFunc = 0;
bool firstTimeNTDLLCreatedFalsePath = true;

GetWindowText_t GetWindowTextOrig;
EnumWindowsOrig_t EnumWindowsOrig;
GetThreadContext_t GetThreadContextOrig;
CreateThread_t CreateThreadOrig;
AddVectoredExceptionHandler_t AddVectoredExceptionHandlerOrig;
SetUnhandledExceptionFilter_t SetUnhandledExceptionFilterOrig;
NtUserQueryWindow_t NtUserQueryWindowOrig;
NtUserGetForegroundWindow_t NtUserGetForegroundWindowOrig;
NtUserBuildHwndList_t NtUserBuildHwndListOrig;
NtSetInformationProcess_t NtSetInformationProcessOrig;
CheckRemoteDebuggerPresent_t CheckRemoteDebuggerPresentOrig;
CreateMutexEx_t CreateMutexExOrig;
SetWindowsHookEx_t SetWindowsHookExOrig;
SetThreadContext_t SetThreadContextOrig;
NtUserFindWindowEx_t NtUserFindWindowExOrig;
NtUserWindowFromPoint_t NtUserWindowFromPointOrig;
CreateWindowEx_t CreateWindowExOrig;
RtlRestoreContext_t RtlRestoreContextOrig;
NtAllocateVirtualMemory_t NtAllocateVirtualMemoryOrig;
NtMapViewOfSection_t NtMapViewOfSectionOrig;
NtSetInformationJobObject_t NtSetInformationJobObjectOrig;
NtUserGetClassName_t NtUserGetClassNameOrig;
NtUserInternalGetWindowText_t NtUserInternalGetWindowTextOrig;

GetWindowThreadProcessId_t GetWindowThreadProcessIdOrig;
GetClassName_t GetClassNameOrig;
EnumChildWindows_t EnumChildWindowsOrig;
GetMenu_t GetMenuOrig;
GetMenuString_t GetMenuStringOrig;
GetSubMenu_t GetSubMenuOrig;

std::vector<PVOID> VectoredExceptions;
CONTEXT context = {};

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

HHOOK SetWindowsHookExFunc(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId)
{
	return 0;
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

NTSTATUS NtAllocateVirtualMemoryFunc(HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect)
{
	NTSTATUS result = NtAllocateVirtualMemoryOrig(ProcessHandle,BaseAddress,ZeroBits,RegionSize,AllocationType,Protect);

	if (Protect & PAGE_EXECUTE_READWRITE && *(SIZE_T*)RegionSize == ntdllSize)
	{
		static int counter = 0;
		counter++;

		/*
			p 57
			p 41
			p 30
		*/

		static bool firstTime = true;
		if (firstTime) // if (firstTime && counter == 4)
		{
			clock_t start_time = clock();
			// TODO: enable this later
			createInlineAsmStub();
			createChecksumHealingStub();
			
			double elapsed_time = (double)(clock() - start_time) / CLOCKS_PER_SEC;
			printf("creating inline hooks for checksums took: %f seconds\n", elapsed_time);
			printf("done hooking\n");
			
			firstTime = false;
		}

		if (counter == 6)
		{
			uint64_t baseAddr = (uint64_t)GetModuleHandle(nullptr);

/*
			if (MH_CreateHook((char*)(baseAddr + 0xb5a10d0), &Demo_OpenFileWrite, (LPVOID*)(&Demo_OpenFileWriteOrig)) != MH_OK) 
				{ printf("hook didn't work\n"); }
			if (MH_EnableHook((char*)(baseAddr + 0xb5a10d0)) != MH_OK) 
				{ printf("hook didn't work\n"); }
*/

			disableTlsCallbacks();
			// pmove offset 0x76041f0

			// TODO: for our little module we will load later, modify some stuff from our player entity

			// 7FF71B6A1DF3                 call    qword ptr [rsp+1AE0h]
			// player entity state
			//placeHardwareBP((char*)(baseAddr + 0x7FF72601DEB0 - StartOfBinary), 0, Condition::Execute);

/*
			placeHardwareBP((char*)(baseAddr + 0x7ff738c428a1 - StartOfBinary), 0, Condition::Write);
			placeHardwareBP((char*)(baseAddr + 0x7ff736672212 - StartOfBinary), 1, Condition::Write);
			placeHardwareBP((char*)(baseAddr + 0x7ff738e429da - StartOfBinary), 2, Condition::Write);
*/
		}
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

HWND NtUserFindWindowExFunc(HWND hwndParent, HWND hwndChildAfter, PUNICODE_STRING ucClassName, PUNICODE_STRING ucWindowName)
{
	printf("ntuserfindwindowexfunc got called\n");

	return 0;
}

HWND NtUserWindowFromPointFunc(LONG X,LONG Y)
{
	printf("window from point got called\n");

	return 0x0;
}

int GetWindowTextFunc(HWND hWnd, LPSTR lpString, int nMaxCount)
{
	return 0;
}

// game closes itself if we return false
BOOL EnumWindowsFunc(WNDENUMPROC lpEnumFunc, LPARAM lParam)
{
	return EnumWindowsOrig(lpEnumFunc, lParam);
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

	if (compare1 == 0)
		return CreateMutexExOrig(attributes, "blablabla", flags, access);

	if (compare2 == 0)
		return CreateMutexExOrig(attributes, "blablablabla", flags, access);

	return CreateMutexExOrig(attributes, name, flags, access);
}

// TODO: maybe causes a startup crash now? tries to read memory from 0x0 inside crashdump
HANDLE NtUserQueryWindowFunc(HWND hwnd, WINDOWINFOCLASS WindowInfo)
{
	//if ((WindowInfo == WindowProcess || WindowInfo == WindowThread) && IsWindowBad(hwnd))
	if (WindowInfo == WindowProcess || WindowInfo == WindowThread)
	{
		if (WindowInfo == WindowProcess)
			return NtCurrentTeb()->ClientId.UniqueProcess;
		if (WindowInfo == WindowThread)
			return NtCurrentTeb()->ClientId.UniqueThread;
	}

	return NtUserQueryWindowOrig(hwnd, WindowInfo);
}

HWND NtUserGetForegroundWindowFunc()
{
	/*
	HWND result = NtUserGetForegroundWindowOrig();

	if (result != nullptr && IsWindowBad(result))
		result = NULL;

	return result;
	*/

	HWND result = NtUserGetForegroundWindowOrig();
	DWORD processId = 0;
	GetWindowThreadProcessIdOrig(result, &processId);

	if (processId == GetCurrentProcessId())
		return result;
	else
		return 0x0;
}

NTSTATUS NtUserBuildHwndListFunc(HDESK hDesk, HWND hWndNext, BOOL EnumChildren, BOOL RemoveImmersive, DWORD ThreadID, UINT Max, HWND* List, PULONG Cnt)
{
	NTSTATUS result = NtUserBuildHwndListOrig(hDesk, hWndNext, 0, RemoveImmersive, ThreadID, Max, List, Cnt);

	if (NT_SUCCESS(result) && List != nullptr && Cnt != nullptr)
		FilterHwndList(List, Cnt);

	return result;
}

DWORD GetWindowThreadProcessIdFunc(HWND hWnd, LPDWORD lpdwProcessId)
{
	//return GetWindowThreadProcessIdOrig(hWnd, lpdwProcessId);
	return 0x0;
}

int GetClassNameFunc(HWND hWnd, LPSTR lpClassName, int nMaxCount)
{
	//return GetClassNameOrig(hWnd, lpClassName, nMaxCount);
	return 0x0;
}


BOOL EnumChildWindowsFunc(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam)
{
	//return EnumChildWindowsOrig(hWndParent, lpEnumFunc, lParam);
	return false;
}


HMENU GetMenuFunc(HWND hWnd)
{
	//return GetMenuOrig(hWnd);
	return 0x0;
}


int GetMenuStringFunc(HMENU hMenu,UINT uIDItem,LPSTR lpString, int cchMax,UINT flags)
{
	//return GetMenuStringOrig(hMenu, uIDItem, lpString, cchMax, flags);
	return 0x0;
}


HMENU GetSubMenuFunc(HMENU hMenu, int nPos)
{
	//return GetSubMenuOrig(hMenu, nPos);
	return 0x0;
}

BOOL CheckRemoteDebuggerPresentFunc(HANDLE hProcess, PBOOL pbDebuggerPresent)
{
	*(BOOL*)pbDebuggerPresent = false;
	return true;
}

PVOID AddVectoredExceptionHandlerFunc(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
{
	PVOID handler = AddVectoredExceptionHandlerOrig(First, Handler);

	VectoredExceptions.push_back(handler);
	return handler;
}

LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilterFunc(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
{
	return 0;
}

void generalTlsCallbackFunction()
{
	return;
}

void disableTlsCallbacks()
{
	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
	char* tlscallback_1 = reinterpret_cast<char*>(baseAddr + 0x6b9220);
	char* tlscallback_2 = reinterpret_cast<char*>(baseAddr + 0x6d7110);
	char* tlscallback_3 = reinterpret_cast<char*>(baseAddr + 0x6e8480);
	char* tlscallback_4 = reinterpret_cast<char*>(baseAddr + 0x6e9a90);

	printf("tls1: %llx\n", tlscallback_1);
	printf("tls2: %llx\n", tlscallback_2);
	printf("tls3: %llx\n", tlscallback_3);
	printf("tls4: %llx\n", tlscallback_4);

	if (MH_CreateHook(tlscallback_1, &generalTlsCallbackFunction, NULL) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(tlscallback_1) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(tlscallback_2, &generalTlsCallbackFunction, NULL) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(tlscallback_2) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(tlscallback_3, &generalTlsCallbackFunction, NULL) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(tlscallback_3) != MH_OK) { printf("hook didn't work\n"); }

	if (MH_CreateHook(tlscallback_4, &generalTlsCallbackFunction, NULL) != MH_OK) { printf("hook didn't work\n"); }
	if (MH_EnableHook(tlscallback_4) != MH_OK) { printf("hook didn't work\n"); }

	printf("disabled tls callbacks\n");
}

void InitializeSystemHooks()
{
	void* GetThreadContextAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "GetThreadContext");
	void* SetThreadContextAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "SetThreadContext");
	void* CheckRemoteDebuggerPresentAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "CheckRemoteDebuggerPresent");
	void* OutputDebugStringAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "OutputDebugStringA");
	void* SetUnhandledExceptionFilterAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "SetUnhandledExceptionFilter");

	void* AddVectoredExceptionHandlerAddr = (void*)GetProcAddress(GetModuleHandle("kernel32.dll"), "AddVectoredExceptionHandler");
	void* CreateThreadAddr = (void*)GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateThread");
	void* CreateMutexExAddr = (void*)GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateMutexExA");

	void* NtAllocateVirtualMemoryAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtAllocateVirtualMemory");

	void* EnumWindowsAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "EnumWindows");
	void* GetWindowThreadProcessIdAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "GetWindowThreadProcessId");
	void* GetClassNameAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "GetClassNameA");
	void* GetWindowTextAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "GetWindowTextA");
	void* EnumChildWindowsAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "EnumChildWindows");
	void* GetMenuAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "GetMenu");
	void* GetMenuStringAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "GetMenuStringA");
	void* GetSubMenuAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "GetSubMenu");
	void* SetWindowsHookExAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "SetWindowsHookExW");
	void* CreateWindowExAddr = (void*)GetProcAddress(GetModuleHandle("user32.dll"), "CreateWindowExW");

	void* NtUserQueryWindowAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserQueryWindow");
	void* NtUserGetForegroundWindowAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserGetForegroundWindow");
	void* NtUserBuildHwndListAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserBuildHwndList");
	void* NtUserFindWindowExAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserFindWindowEx");
	void* NtUserWindowFromPointAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserWindowFromPoint");
	void* NtUserInternalGetWindowTextAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserInternalGetWindowText");
	void* NtUserGetWindowProcessHandleAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserGetWindowProcessHandle");
	void* NtUserGetTopLevelWindowAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserGetTopLevelWindow");
	void* NtUserChildWindowFromPointExAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserChildWindowFromPointEx");
	void* NtUserInternalGetWindowIconAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserInternalGetWindowIcon");
	void* NtUserRealChildWindowFromPointAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserRealChildWindowFromPoint");
	void* NtUserWindowFromDCAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserWindowFromDC");
	void* NtUserGetClassNameAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserGetClassName");


	struct hook_t
	{
		void* addr;
		void* ourFunction;
		void** originalFunction;
	};

	hook_t hooks[] {
		{NtUserFindWindowExAddr, &NtUserFindWindowExFunc, (LPVOID*)(&NtUserFindWindowExOrig)},
		{NtUserWindowFromPointAddr, &NtUserWindowFromPointFunc, (LPVOID*)(&NtUserWindowFromPointOrig)},
		{CreateWindowExAddr, &CreateWindowExFunc, (LPVOID*)(&CreateWindowExOrig)},
		{GetWindowTextAddr, &GetWindowTextFunc, (LPVOID*)(&GetWindowTextOrig)},
		{EnumWindowsAddr, &EnumWindowsFunc, (LPVOID*)(&EnumWindowsOrig)},
		{GetThreadContextAddr, &GetThreadContextFunc, (LPVOID*)(&GetThreadContextOrig)},
		{SetThreadContextAddr, &SetThreadContextFunc, (LPVOID*)(&SetThreadContextOrig)},
		{CreateThreadAddr, &CreateThreadFunc, (LPVOID*)(&CreateThreadOrig)},
		{SetWindowsHookExAddr, &SetWindowsHookExFunc, (LPVOID*)(&SetWindowsHookExOrig)},
		{CreateMutexExAddr, &CreateMutexExFunc, (LPVOID*)(&CreateMutexExOrig)},
		{NtAllocateVirtualMemoryAddr, &NtAllocateVirtualMemoryFunc, (LPVOID*)(&NtAllocateVirtualMemoryOrig)},
		{CheckRemoteDebuggerPresentAddr, &CheckRemoteDebuggerPresentFunc, (LPVOID*)(&CheckRemoteDebuggerPresentOrig)},
		{AddVectoredExceptionHandlerAddr, &AddVectoredExceptionHandlerFunc, (LPVOID*)(&AddVectoredExceptionHandlerOrig)},
		{SetUnhandledExceptionFilterAddr, &SetUnhandledExceptionFilterFunc, (LPVOID*)(&SetUnhandledExceptionFilterOrig)},
		{NtUserGetForegroundWindowAddr, &NtUserGetForegroundWindowFunc, (LPVOID*)(&NtUserGetForegroundWindowOrig)},
		{NtUserBuildHwndListAddr, &NtUserBuildHwndListFunc, (LPVOID*)(&NtUserBuildHwndListOrig)},
		
		// might crash more frequent?
		{NtUserQueryWindowAddr, &NtUserQueryWindowFunc, (LPVOID*)(&NtUserQueryWindowOrig)},

		{GetWindowThreadProcessIdAddr, &GetWindowThreadProcessIdFunc, (LPVOID*)(&GetWindowThreadProcessIdOrig)},
		{GetClassNameAddr, &GetClassNameFunc, (LPVOID*)(&GetClassNameOrig)},
		{EnumChildWindowsAddr, &EnumChildWindowsFunc, (LPVOID*)(&EnumChildWindowsOrig)},
		{GetMenuAddr, &GetMenuFunc, (LPVOID*)(&GetMenuOrig)},
		{GetMenuStringAddr, &GetMenuStringFunc, (LPVOID*)(&GetMenuStringOrig)},
		{GetSubMenuAddr, &GetSubMenuFunc, (LPVOID*)(&GetSubMenuOrig)},
		
		{NtUserInternalGetWindowTextAddr, &GetMenuFunc, (LPVOID*)(&NtUserInternalGetWindowTextOrig)},
		{NtUserGetWindowProcessHandleAddr, &GetMenuFunc, NULL},
		{NtUserGetTopLevelWindowAddr, &GetMenuFunc, NULL},
		{NtUserChildWindowFromPointExAddr, &GetMenuFunc, NULL},
		{NtUserInternalGetWindowIconAddr, &GetMenuFunc, NULL},
		{NtUserRealChildWindowFromPointAddr, &GetMenuFunc, NULL},
		{NtUserWindowFromDCAddr, &GetMenuFunc, NULL},
		{NtUserGetClassNameAddr, &GetMenuFunc, (LPVOID*)(&NtUserGetClassNameOrig)},
	};

	size_t amountHooks = sizeof(hooks) / sizeof(hook_t);
	for (int i=0; i < amountHooks; i++)
	{
		if (MH_CreateHook(hooks[i].addr, hooks[i].ourFunction, hooks[i].originalFunction) != MH_OK)
			printf("hook didn't work\n");

		if (MH_EnableHook(hooks[i].addr) != MH_OK)
			printf("hook didn't work\n");
	}
}
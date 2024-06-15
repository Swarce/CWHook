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
bool suspendNewThreads = false;
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
	//printf("SetHookEx called with hook id %llx from thread id %llx\n", idHook, dwThreadId);
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

std::vector<uint64_t> previousHandles = { 0x0 };

typedef __int64(__fastcall* tryhookingmaybe_t)(__int64 a1, char* a2, unsigned __int64 a3, __int64 a4, __int64 a5, __int64 a6);
tryhookingmaybe_t tryhookingmaybeOrig;

__int64 tryHooking(__int64 a1, char* a2, unsigned __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
	//if (a2 != nullptr)
	if (a2 != nullptr)
		printf("a2: %s\n", a2);

	//	printf("a4: %s\n\n", a4);

	return tryhookingmaybeOrig(a1, a2, a3, a4, a5, a6);
}

NTSTATUS NtAllocateVirtualMemoryFunc(HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect)
{
	NTSTATUS result = NtAllocateVirtualMemoryOrig(ProcessHandle,BaseAddress,ZeroBits,RegionSize,AllocationType,Protect);

	if (Protect & PAGE_EXECUTE_READWRITE && *(SIZE_T*)RegionSize == 0x1EF000)
	{
		static int counter = 0;
		counter++;
		//printf("ntdll counter %d\n", counter);

		//if (counter == 1)
		//	placeHardwareBP((char*)((uint64_t)GetModuleHandle(nullptr) + 0x1b5654f8), 0, Condition::Execute);

		/*
			p 57
			p 41
			p 30
		*/

		static bool firstTime = true;
		//if (firstTime && counter == 4)
		if (firstTime)
		{

			// try moving our hook after bp1: 7ff637c3b429 7ff738f1b429 1 ??????
			// bp1: 7ff637c3b429 7ff738f1b429 1
			// bp1: 7ff637c3b429 7ff738f1b429 1

			//SuspendAllThreads();
			//__debugbreak();

			// TODO: allocating close to the module/process takes a ton of time, we could make this faster by allocating one huge page and then fix all the stubs in there, same goes with the checksum fixer stubs
			// later on we can even create an array with the address locations where we have to do inline hooks at
			
			// TODO: replace our pattern function with the one from the boiii / cold war dll since we are getting owned by MEM_RESERVE pages

			clock_t start_time = clock();
			createInlineAsmStub();
			nopChecksumFixingMemcpy();
			nopChecksumFixingMemcpy2();
			nopChecksumFixingMemcpy3();
			nopChecksumFixingMemcpy4();
			nopChecksumFixingMemcpy5();

			// crashes the game with movzx change, but are necessary to work and reduce the chances of crashes happening from checksum checks
			//nopChecksumFixingMemcpy6(); 

			nopChecksumFixingMemcpy7();
			nopChecksumFixingMemcpy8();
			nopChecksumFixingMemcpy9();
			double elapsed_time = (double)(clock() - start_time) / CLOCKS_PER_SEC;
			printf("creating inline hooks for checksums took: %f seconds\n", elapsed_time);

			// TODO: checksum late hooking
			printf("done hooking\n");
			
			firstTime = false;
		}

		if (counter == 6)
		{
			char* draw2dPtr = (char*)((uint64_t)GetModuleHandle(nullptr) + 0xb5e4320);
			*(char*)draw2dPtr++ = 0xC3;
			*(char*)draw2dPtr++ = 0x90;
			*(char*)draw2dPtr++ = 0x90;
			*(char*)draw2dPtr++ = 0x90;
			*(char*)draw2dPtr++ = 0x90;
			printf("draw2dPtr %llx\n", draw2dPtr);

			/*
			char* printfFunctionSmth = (char*)((uint64_t)GetModuleHandle(nullptr) + 0xd55aa74);
			printf("loc %llx\n", printfFunctionSmth);

			if (MH_CreateHook(printfFunctionSmth, &tryHooking, (LPVOID*)(&tryhookingmaybeOrig)) != MH_OK)
					{ printf("hook didn't work\n"); }
			
			if (MH_EnableHook(printfFunctionSmth) != MH_OK)
				{ printf("hook didn't work\n"); }
			*/
			
			disableTlsCallbacks();
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

//	SuspendAllThreads();
//	__debugbreak();

	return 0;
}

HWND NtUserWindowFromPointFunc(LONG X,LONG Y)
{
	printf("window from point got called\n");

	SuspendAllThreads();
	__debugbreak();

	return 0x0;
}

int GetWindowTextFunc(HWND hWnd, LPSTR lpString, int nMaxCount)
{
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

	THREADENTRY32 entry = {};
	entry.dwSize = sizeof(THREADENTRY32);
	Thread32First(snapshotHandle, &entry);
	int counter = 0;

	do {
		if (entry.th32OwnerProcessID == GetCurrentProcessId())
		{
			HANDLE currentThread = OpenThread(THREAD_ALL_ACCESS, true, entry.th32ThreadID);
			if (currentThread == NULL)
				printf("openthread: %s\n", GetLastErrorAsString().c_str());
			
			char threadHiddenFromDebugger = 0;
			NtQueryInformationThread(currentThread, ThreadHideFromDebugger, &threadHiddenFromDebugger, sizeof(char), NULL);

			if (threadHiddenFromDebugger)
				printf("thread %d debugger on: %llx\n", GetThreadId(currentThread), threadHiddenFromDebugger);

#if 0
			if (counter == 0)
			{
				gameHandle = currentThread;
				counter++;
				continue;
			}
#else
			// doing suspendallthreads early or too late
				if (GetCurrentThreadId() == entry.th32ThreadID)
					continue;
#endif


			DWORD suspendResult = SuspendThread(currentThread);
			if (suspendResult == -1)
				printf("suspend: %s\n", GetLastErrorAsString().c_str());
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

HANDLE NtUserQueryWindowFunc(HWND hwnd, WINDOWINFOCLASS WindowInfo)
{
	/*
	if ((WindowInfo == WindowProcess || WindowInfo == WindowThread) && IsWindowBad(hwnd))
	{
		if (WindowInfo == WindowProcess)
			return NtCurrentTeb()->ClientId.UniqueProcess;
		if (WindowInfo == WindowThread)
			return NtCurrentTeb()->ClientId.UniqueThread;
	}

	HANDLE result = NtUserQueryWindowOrig(hwnd, WindowInfo);
	return result;
	*/

	// TODO: maybe causes a startup crash now? tries to read memory from 0x0 inside crashdump
	return 0x0;
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

	//auto result = RemoveVectoredExceptionHandler(exceptionHandle);
	//if (result != NULL)
	//	printf("removed our own exception handle\n");

	weAreDebugging = true;
#if REMOVE_HWBP_ON_SUSPEND
	removeAllHardwareBP();
#endif

	printf("start\n");

	suspendNewThreads = false;
	SleepAllThreadsBesidesMainThread();

	printf("suspended\n");

	if (inputHandle != nullptr)
		ResumeThread(inputHandle);

#if REMOVE_HWBP_ON_SUSPEND
	void* RtlRestoreContextAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlRestoreContext");

	if (MH_CreateHook(RtlRestoreContextAddr, &RtlRestoreContextFunc, (LPVOID*)(&RtlRestoreContextOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_EnableHook(RtlRestoreContextAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}
#endif

	if (MH_DisableHook(MH_ALL_HOOKS) != MH_OK)
		printf("couldnt remove all hooks\n");

	disableTlsCallbacks();

	printf("tls callback removed\n");

	// cold war removes the function ptr from ntdll Kernel32ThreadInitThunkFunction to its own, redirecting createremotethread
	// does rdtsc checks which in turn makes it so that if the process is completely suspended, will crash on created threads
	void* BaseInitThread = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlUserThreadStart");
	void* BaseThreadInitThunk = (void*)GetProcAddress(GetModuleHandle("kernel32.dll"), "BaseThreadInitThunk");

	PVOID RtlUserThreadStart = (PVOID)((DWORD64)BaseInitThread + 0x7);
	DWORD64 RtlUserThreadStartFuncOffset = (UINT64)((PUCHAR)RtlUserThreadStart + *(PULONG)((PUCHAR)RtlUserThreadStart + 0x3) + 0x7);
	uint64_t* basethreadinitptr = (uint64_t*)RtlUserThreadStartFuncOffset;
	memcpy(basethreadinitptr, &BaseThreadInitThunk, sizeof(uint64_t));
	
	printf("Kernel32ThreadInitThunkFunction\n");

	char threadHiddenFromDebugger = 0;
	NtQueryInformationThread(GetCurrentThread(), ThreadHideFromDebugger, &threadHiddenFromDebugger, sizeof(char), NULL);

	if (threadHiddenFromDebugger)
		printf("thread %d suspend: %llx\n", GetThreadId(GetCurrentThread()), threadHiddenFromDebugger);

	auto* const peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
	peb->BeingDebugged = false;
	*reinterpret_cast<PDWORD>(LPSTR(peb) + 0xBC) &= ~0x70;

	printf("attach debugger\n");
	
	//while (true) {Sleep(100); __debugbreak();}

	// TODO: remove this back to how it normally was after we are done debugging
	while (!IsDebuggerPresent()) {
		Sleep(100);
	}
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

	if (result == 0)
		printf("didn't work to overwrite thread context\n");

	// Loop each thread and attach breakpoints
	HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

	THREADENTRY32 entry = {};
	entry.dwSize = sizeof(THREADENTRY32);
	Thread32First(snapshotHandle, &entry);

	do {
		if (entry.th32OwnerProcessID == GetCurrentProcessId())
		{
			HANDLE currentThread = OpenThread(THREAD_ALL_ACCESS, false, entry.th32ThreadID);
			bool setThreadResult = SetThreadContextOrig(currentThread, &context);

			if (setThreadResult == 0)
				printf("didn't work to overwrite thread context\n");
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
	void* SetThreadContextAddr = (void*)GetProcAddress(GetModuleHandle("kernelbase.dll"), "SetThreadContext");
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

	void* NtAllocateVirtualMemoryAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtAllocateVirtualMemory");

	// win32u.dll
	void* NtUserQueryWindowAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserQueryWindow");
	void* NtUserGetForegroundWindowAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserGetForegroundWindow");
	void* NtUserBuildHwndListAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserBuildHwndList");
	void* NtUserFindWindowExAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserFindWindowEx");
	void* NtUserWindowFromPointAddr = (void*)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserWindowFromPoint");

	if (MH_CreateHook(NtUserFindWindowExAddr, &NtUserFindWindowExFunc, (LPVOID*)(&NtUserFindWindowExOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_EnableHook(NtUserFindWindowExAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_CreateHook(NtUserWindowFromPointAddr, &NtUserWindowFromPointFunc, (LPVOID*)(&NtUserWindowFromPointOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}

	if (MH_EnableHook(NtUserWindowFromPointAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}

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
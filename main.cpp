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

enum Condition { Execute = 0, Write = 1, ReadWrite = 3 };
const uint64_t EndOfTextSection = 0xbb3a000;
const uint64_t StartOfTextSection = 0x7FF626C71000;
const uint64_t StartOfBinary = 0x7FF626C70000;

FILE* logFile;

std::vector<intactChecksumHook> intactchecksumHooks;
std::vector<intactBigChecksumHook> intactBigchecksumHooks;
std::vector<splitChecksumHook> splitchecksumHooks;

std::vector<PVOID> VectoredExceptions;

HANDLE ntdllFileHandle = nullptr;
HANDLE ntdllOriginalFileHandle = nullptr;
HANDLE win32uFileHandle = nullptr;
HANDLE win32uOriginalFileHandle = nullptr;

HANDLE exceptionHandle = nullptr;
HANDLE gameHandle = nullptr;
HANDLE inputHandle = nullptr;
HANDLE debugThreadHandle = nullptr;
bool weAreDebugging = false;
bool multiplayerEnabled = false;
int multiplayerCounter = 0;
int mainThreadId = 0;
bool hookedfunction = false;
bool suspendNewThreads = false;
char* endofTextSectionAddr = nullptr;
char* baseFuncAddr = nullptr;
void* RtlRestoreContextAddr;
uint64_t OffsetOfSetInfoFunc = 0;

char* discordSet1;
char* discordSet2;

const char* disconnectCvar = "disconnect\n";
const char* devmapCvar = "sv_cheats 1\ndevmap mp_tank 1 0\n";
CONTEXT context = {};

extern HMODULE module;

void disableTlsCallbacks();
void SuspendAllThreads();
void removeAllHardwareBP();
void placeHardwareBP(void* addr, int count, Condition condition);

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

typedef int(__stdcall* GetWindowText_t)(HWND hWnd, LPSTR lpString, int nMaxCount);
GetWindowText_t GetWindowTextOrig;

typedef BOOL(__stdcall* EnumWindowsOrig_t)(WNDENUMPROC lpEnumFunc, LPARAM lParam);
EnumWindowsOrig_t EnumWindowsOrig;

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

// TODO: doesn't get called i think? check again with hwbp execute
typedef __int64(__fastcall* LoadBuffer_t)(__int64* luaState, const char* buff, __int64 size, char* a4);
LoadBuffer_t LoadBuffer;

typedef __int64(__fastcall* CbufAddText_t)(__int64 playerNum, const char* buff);
CbufAddText_t CbufAddText;

typedef __int64(__fastcall* SetScreen_t)(__int64 screenNum);
SetScreen_t SetScreen;

typedef __int64(__fastcall* SessionState_t)(__int64 state);
SessionState_t SessionState;

typedef __int64(__fastcall* LobbyBaseSetNetworkmode_t)(unsigned int networkMode);
LobbyBaseSetNetworkmode_t LobbyBaseSetNetworkmode;

typedef __int64(__fastcall* LiveStorage_ParseKeysTxt_t)(const char* key);
LiveStorage_ParseKeysTxt_t LiveStorage_ParseKeysTxt;

typedef __int64(__fastcall* LiveStorage_ParseKeysTxt2_t)(const char* key);
LiveStorage_ParseKeysTxt2_t LiveStorage_ParseKeysTxt2;

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
			//for (int i = 0; i < handleInfo->HandleCount; i++)
			for (int i = 0; i < handleInfo->NumberOfHandles; i++)
			{
				//SYSTEM_HANDLE handle = handleInfo->Handles[i];
				SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = handleInfo->Handles[i];
				//printf("%d ", handle.ProcessId);
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

			SetScreen(10);
			LobbyBaseSetNetworkmode(1);
			SessionState(1);

			*discordSet1 = 1;
			*discordSet2 = 1;

			SetScreen(11);
		}
		else
		{
			CbufAddText(0, input.c_str());
			printf("cmd: %s\n", input.c_str());
		}
	}
	return 0;
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
	Sleep(1000);
	//assert(0);

	//SuspendThread(GetCurrentThread());
	//printf("running...\n");
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

uint32_t reverse_bytes(uint32_t bytes)
{
    uint32_t aux = 0;
    uint8_t byte;
    int i;

    for(i = 0; i < 32; i+=8)
    {
        byte = (bytes >> i) & 0xff;
        aux |= byte << (32 - 8 - i);
    }
    return aux;
}

// TODO: create an inline stub cause just noping the instruction out doesnt work
void nopChecksumFixingMemcpy()
{
	return;

	hook::pattern checksumFixers = hook::module_pattern(GetModuleHandle(nullptr), "89 02 8B 45 20 83 C0 FC E9");
	size_t checksumFixersCount = checksumFixers.size();
	
	for (int i=0; i < checksumFixersCount; i++)
	{
		void* functionAddress = checksumFixers.get(i).get<void*>(0);
	}
}

int fixChecksum(uint64_t rbpOffset, uint64_t ptrOffset, uint64_t* ptrStack, uint32_t jmpInstructionDistance, uint32_t calculatedChecksumFromArg)
{
	// get size of image from codcw
	uint64_t baseAddressStart = (uint64_t)GetModuleHandle(nullptr);
	IMAGE_DOS_HEADER* pDOSHeader = (IMAGE_DOS_HEADER*)GetModuleHandle(nullptr);
	IMAGE_NT_HEADERS* pNTHeaders =(IMAGE_NT_HEADERS*)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
	auto sizeOfImage = pNTHeaders->OptionalHeader.SizeOfImage;
	uint64_t baseAddressEnd = baseAddressStart + sizeOfImage;

	// fix checksums here, else thread true memcpy attempt
	// seems like its working but eventually dies because arxan at some fixes the checksums and checksums in general dont get called so much
	// it does make the game run almost every time now
	{
		for (int i=0; i < intactchecksumHooks.size(); i++)
		{
			DWORD old_protect{};

			if (memcmp(intactchecksumHooks[i].functionAddress, intactchecksumHooks[i].buffer, sizeof(uint8_t) * 7))
			{
				uint64_t idaAddress = (uint64_t)intactchecksumHooks[i].functionAddress - baseAddressStart + StartOfBinary;

				printf("%llx got changed\n", idaAddress);
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

				printf("%llx got changed\n", idaAddress);
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

				printf("%llx got changed\n", idaAddress);
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

	//printf("rbp %llx, ptr %llx, stack %llx, distance %x, calculatedChecksum %x\n", rbpOffset, ptrOffset, ptrStack, jmpInstructionDistance, calculatedChecksumFromArg);
	//printf("rbp %llx, ptr %llx, stack %llx, distance %x, calculatedChecksum %x, fixChecksumCalls %d\n", rbpOffset, ptrOffset, ptrStack, jmpInstructionDistance, calculatedChecksumFromArg, fixChecksumCalls);
	//fprintf(logFile, "rbp %llx, ptr %llx, stack %llx, distance %x, calculatedChecksum %x, fixChecksumCalls %d\n", rbpOffset, ptrOffset, ptrStack, jmpInstructionDistance, calculatedChecksumFromArg, fixChecksumCalls);
	//fflush(logFile);

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

				//printf("result: %llx\n", derefResult);
				//fprintf(logFile, "result: %llx\n", derefResult);
				//fflush(logFile);

				// store the ptr above 0xffffffffffffffff and then use it in our originalchecksum check
				if (derefResult == 0xffffffffffffffff)
				{
					if (pointerCounter > 2)
					{
						//SuspendAllThreads();
						//__debugbreak();

						doubleTextChecksum = true;

						//printf("found double pointer text section\n", derefResult);
						//fprintf(logFile, "found double pointer text section\n", derefResult);
						//fflush(logFile);

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
			{
				uint64_t derefResult = **(uint64_t**)textPtr;

				//printf("result: %llx\n", derefResult);
				//fprintf(logFile, "result: %llx\n", derefResult);
				//fflush(logFile);
			}

			textPtr--;
		}
	}

	// find calculatedChecksumPtr, we will overwrite this later with the original checksum
	for (int i=0; i < 80; i++)
	{
		uint32_t derefPtr = *(uint32_t*)calculatedChecksumPtr;

		if (derefPtr == calculatedChecksum)
		{
			//printf("found calculatedChecksum on stack %llx\n", calculatedChecksumPtr);
			//fprintf(logFile, "found calculatedChecksum on stack %llx\n", calculatedChecksumPtr);
			//fflush(logFile);
			break;
		}

		calculatedChecksumPtr--;
	}

	// find calculatedReversedChecksumPtr, we will overwrite this later with the original checksum
	for (int i=0; i < 80; i++)
	{
		uint32_t derefPtr = *(uint32_t*)calculatedReversedChecksumPtr;

		if (derefPtr == reversedChecksum)
		{
			//printf("found reversedChecksum on stack %llx\n", calculatedChecksumPtr);
			//fprintf(logFile, "found reversedChecksum on stack %llx\n", calculatedReversedChecksumPtr);
			//fflush(logFile);
			break;
		}

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
			//printf("found potential checksum location: %llx\n", derefPtr);
			//fprintf(logFile, "found potential checksum location: %llx\n", derefPtr);
			//fflush(logFile);

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

	// TODO: if we still die, find some 0x120 rbp big and if statement the checksum, save the stack as a reference with and without hwbp
	// remove our push pop changes back to what it was before, make sure that intact big small and jump all work

	// TODO: if it still looks messed up try calling the function like how the boiii project does it

	// TODO: if that still doesnt work we would need to allocate our own stack and based on the current thread id give access to that specific stack
	// we 100% should refactor our assembly stub generation tho because its getting really annoying to do changes

	//fprintf(logFile, "originalChecksum: %llx\n\n", originalChecksum);
	//fflush(logFile);
	return originalChecksum;
}

void createInlineAsmStub()
{
	// get size of image from codcw
	uint64_t baseAddressStart = (uint64_t)GetModuleHandle(nullptr);
	IMAGE_DOS_HEADER* pDOSHeader = (IMAGE_DOS_HEADER*)GetModuleHandle(nullptr);
	IMAGE_NT_HEADERS* pNTHeaders =(IMAGE_NT_HEADERS*)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
	auto sizeOfImage = pNTHeaders->OptionalHeader.SizeOfImage;
	uint64_t baseAddressEnd = baseAddressStart + sizeOfImage;

	hook::pattern locationsIntact = hook::module_pattern(GetModuleHandle(nullptr), "89 04 8A 83 45 ? FF");
	hook::pattern locationsIntactBig = hook::module_pattern(GetModuleHandle(nullptr), "89 04 8A 83 85");
	hook::pattern locationsSplit = hook::module_pattern(GetModuleHandle(nullptr), "89 04 8A E9");
	size_t intactCount = locationsIntact.size();
	size_t intactBigCount = locationsIntactBig.size();
	size_t splitCount = locationsSplit.size();
	const size_t allocationSize = sizeof(uint8_t) * 128;

	printf("p %d\n", intactCount);
	printf("p %d\n", intactBigCount);
	printf("p %d\n", splitCount);

	// TODO: refactor this later so we for loop through all the address locations
	// and only do things based on the differences between every checksum type

	// intact
	for (int i=0; i < intactCount; i++)
	{

		LPVOID asmStubLocation = allocate_somewhere_near(GetModuleHandle(nullptr), allocationSize);
		memset(asmStubLocation, 0x90, allocationSize);
		void* functionAddress = locationsIntact.get(i).get<void*>(0); // locationsIntact.get(i)
		uint64_t jmpDistance = (uint64_t)asmStubLocation - (uint64_t)functionAddress - 5; // 5 bytes from relative call instruction

		// backup instructions that will get destroyed
		const int length = sizeof(uint8_t) * 8;
		uint8_t instructionBuffer[8] = {};
		memcpy(instructionBuffer, functionAddress, length);

		uint32_t instructionBufferJmpDistance = 0;
		if (instructionBuffer[3] == 0xE9)
			memcpy(&instructionBufferJmpDistance, (char*)functionAddress+0x4, 4); // 0x4 so we skip 0xE9

		// create assembly stub content
		static asmjit::JitRuntime runtime;
		asmjit::CodeHolder code;
		code.init(runtime.environment());
		asmjit::x86::Assembler a(&code);

		uint64_t rbpOffset = instructionBuffer[5];
		
		/*
		asmjit::Label L1 = a.newLabel();
		a.bind(L1);
		a.jmp(L1);
		*/

		a.sub(asmjit::x86::rsp, 0x400); // 0x40? 0x32 before
		pushad64();

		//a.mov(asmjit::x86::rax, (uint64_t)(void*)SuspendAllThreads);
		//a.call(asmjit::x86::rax);

		// TODO: Find out a way to create our own allocated stack and modify rsp and rbp to use it
		// once we come out of the function we restore rsp and rbp back to normal

		a.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x20), asmjit::x86::rax);
		a.mov(asmjit::x86::rdx, asmjit::x86::rcx);	// offset within text section pointer (ecx*4)
		a.mov(asmjit::x86::rcx, rbpOffset);

		a.mov(asmjit::x86::r8, asmjit::x86::rbp);
		a.mov(asmjit::x86::r9, instructionBufferJmpDistance);	// incase we mess up a split checksum
		a.mov(asmjit::x86::rax, (uint64_t)(void*)fixChecksum);
		a.call(asmjit::x86::rax);
		a.add(asmjit::x86::rsp, 0x8*4); // so that r12-r15 registers dont get corrupt
										// TODO: remove these changes including the utils.h whenever we figure out why we are crashing from checksum failures

		//popad64();
		popad64WithoutRAX();
		a.add(asmjit::x86::rsp, 0x400);

		a.mov(ptr(asmjit::x86::rdx, asmjit::x86::rcx, 2), asmjit::x86::eax); // mov [rdx+rcx*4], eax

		if (instructionBufferJmpDistance == 0)
		{
			a.add(dword_ptr(asmjit::x86::rbp, rbpOffset), -1); // add dword ptr [rbp+rbpOffset], 0FFFFFFFFh
		}
		else
		{
			// printf("instructionBufferJmpDistance: %x\n", instructionBufferJmpDistance);
			// https://forum.osdev.org/viewtopic.php?p=168467#p168467
			// push the desired address on to the stack and then perform a 64 bit RET

			// jmp loc_7FF641C707A5
			a.add(asmjit::x86::rsp, 0x8); // pop return address off the stack cause we will jump
			uint64_t addressToJump = (uint64_t)functionAddress + instructionBufferJmpDistance;
			a.mov(asmjit::x86::r11, addressToJump);	// r11 is being used but should be fine based on documentation
			a.push(asmjit::x86::r11);
		}

		a.add(asmjit::x86::rsp, 0x8); // since we dont pop off rax we need to sub 0x8 the rsp
		a.ret();

		void* asmjitResult = nullptr;
		runtime.add(&asmjitResult, &code);
		
		// copy over the content to the stub
		uint8_t* tempBuffer = (uint8_t*)malloc(sizeof(uint8_t) * code.codeSize());
		memcpy(tempBuffer, asmjitResult, code.codeSize());
		memcpy(asmStubLocation, tempBuffer, sizeof(uint8_t) * code.codeSize());

		const int callInstructionBytes = 7;
		const int callInstructionLength = sizeof(uint8_t) * callInstructionBytes;

		DWORD old_protect{};
		VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);
		memset(functionAddress, 0, callInstructionLength);
		VirtualProtect(functionAddress, callInstructionLength, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), functionAddress, callInstructionLength);

		// E8 cd CALL rel32  Call near, relative, displacement relative to next instruction
		uint8_t jmpInstructionBuffer[callInstructionBytes] = {};
		jmpInstructionBuffer[0] = 0xE8;
		jmpInstructionBuffer[1] = (jmpDistance >> (0 * 8));
		jmpInstructionBuffer[2] = (jmpDistance >> (1 * 8));
		jmpInstructionBuffer[3] = (jmpDistance >> (2 * 8));
		jmpInstructionBuffer[4] = (jmpDistance >> (3 * 8));
		jmpInstructionBuffer[5] = 0x90;
		jmpInstructionBuffer[6] = 0x90;

		VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);
		memcpy(functionAddress, jmpInstructionBuffer, callInstructionLength);
		VirtualProtect(functionAddress, callInstructionLength, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), functionAddress, callInstructionLength);

		// temporary way to test if this would get us into the game all the time
		// we basically overwrite at a set small time the instructions from a different thread cause
		// arxan is currently undoing our checksum fixes
		intactChecksumHook intactChecksum;
		intactChecksum.functionAddress = (uint64_t*)functionAddress;
		memcpy(intactChecksum.buffer, jmpInstructionBuffer, sizeof(uint8_t) * 7);
		intactchecksumHooks.push_back(intactChecksum);
	}

	// big intact
	for (int i=0; i < intactBigCount; i++)
	{

		LPVOID asmStubLocation = allocate_somewhere_near(GetModuleHandle(nullptr), allocationSize);
		memset(asmStubLocation, 0x90, allocationSize);
		void* functionAddress = locationsIntactBig.get(i).get<void*>(0); // locationsIntact.get(i)
		//void* functionAddress = locationsSplit.get(i).get<void*>(0); // locationsIntact.get(i)
		uint64_t jmpDistance = (uint64_t)asmStubLocation - (uint64_t)functionAddress - 5; // 5 bytes from relative call instruction

		// backup instructions that will get destroyed
		const int length = sizeof(uint8_t) * 8;
		uint8_t instructionBuffer[8] = {};
		memcpy(instructionBuffer, functionAddress, length);

		uint32_t instructionBufferJmpDistance = 0;
		if (instructionBuffer[3] == 0xE9)
			memcpy(&instructionBufferJmpDistance, (char*)functionAddress+0x4, 4); // 0x4 so we skip 0xE9

		// create assembly stub content
		static asmjit::JitRuntime runtime;
		asmjit::CodeHolder code;
		code.init(runtime.environment());
		asmjit::x86::Assembler a(&code);

		uint64_t rbpOffset = instructionBuffer[5];

		//pushad64();
		//a.sub(asmjit::x86::rsp, 0x40); // 0x40? 0x32 before

		a.sub(asmjit::x86::rsp, 0x400); // 0x40? 0x32 before
		pushad64();

		//a.mov(asmjit::x86::rax, (uint64_t)(void*)SuspendAllThreads);
		//a.call(asmjit::x86::rax);

		a.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x20), asmjit::x86::rax);
		a.mov(asmjit::x86::rdx, asmjit::x86::rcx);		// offset within text section pointer (ecx*4)
		a.mov(asmjit::x86::rcx, 0x120); 				// we dont use rbpoffset since we only get 1 byte from the 2 byte offset (rbpOffset)
														// 0x130 is a good starting ptr to decrement downwards so we can find the original checksum
		
		a.mov(asmjit::x86::r8, asmjit::x86::rbp);				// we need this so we know what stack the stub was at
		a.mov(asmjit::x86::r9, instructionBufferJmpDistance);	// incase we mess up a split checksum
		a.mov(asmjit::x86::rax, (uint64_t)(void*)fixChecksum);
		a.call(asmjit::x86::rax);
		a.add(asmjit::x86::rsp, 0x8*4); // so that r12-r15 registers dont get corrupt

		//a.add(asmjit::x86::rsp, 0x40);
		//popad64();
		popad64WithoutRAX();
		a.add(asmjit::x86::rsp, 0x400);

		a.mov(ptr(asmjit::x86::rdx, asmjit::x86::rcx, 2), asmjit::x86::eax); // mov [rdx+rcx*4], eax

		if (instructionBufferJmpDistance == 0)
		{
			// TODO: big intact functions the way we are getting rbpOffset needs another byte for it to work
			// do this for now kinda scuffed
			rbpOffset += 0x100;
			a.add(dword_ptr(asmjit::x86::rbp, rbpOffset), -1); // add dword ptr [rbp+rbpOffset], 0FFFFFFFFh
		}
		else
		{
			//printf("instructionBufferJmpDistance: %x\n", instructionBufferJmpDistance);
			// https://forum.osdev.org/viewtopic.php?p=168467#p168467
			// push the desired address on to the stack and then perform a 64 bit RET

			// jmp loc_7FF641C707A5
			a.add(asmjit::x86::rsp, 0x8); // pop return address off the stack cause we will jump
			uint64_t addressToJump = (uint64_t)functionAddress + instructionBufferJmpDistance;
			a.mov(asmjit::x86::r11, addressToJump);	// r11 is being used but should be fine based on documentation
			a.push(asmjit::x86::r11);
		}

		a.add(asmjit::x86::rsp, 0x8); // since we dont pop off rax we need to sub 0x8 the rsp
		a.ret();

		void* asmjitResult = nullptr;
		runtime.add(&asmjitResult, &code);
		
		// copy over the content to the stub
		uint8_t* tempBuffer = (uint8_t*)malloc(sizeof(uint8_t) * code.codeSize());
		memcpy(tempBuffer, asmjitResult, code.codeSize());
		memcpy(asmStubLocation, tempBuffer, sizeof(uint8_t) * code.codeSize());

		const int callInstructionBytes = 7 + 3; // three more nops on big intact
		const int callInstructionLength = sizeof(uint8_t) * callInstructionBytes;

		DWORD old_protect{};
		VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);
		memset(functionAddress, 0, callInstructionLength);
		VirtualProtect(functionAddress, callInstructionLength, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), functionAddress, callInstructionLength);

		// E8 cd CALL rel32  Call near, relative, displacement relative to next instruction
		uint8_t jmpInstructionBuffer[callInstructionBytes] = {};
		jmpInstructionBuffer[0] = 0xE8;
		jmpInstructionBuffer[1] = (jmpDistance >> (0 * 8));
		jmpInstructionBuffer[2] = (jmpDistance >> (1 * 8));
		jmpInstructionBuffer[3] = (jmpDistance >> (2 * 8));
		jmpInstructionBuffer[4] = (jmpDistance >> (3 * 8));
		jmpInstructionBuffer[5] = 0x90;
		jmpInstructionBuffer[6] = 0x90;
		// TODO: on big intact checksums we fuck up the instructions with the call
		// check if the same thing happens on regular intact checksums
		jmpInstructionBuffer[7] = 0x90;
		jmpInstructionBuffer[8] = 0x90;
		jmpInstructionBuffer[9] = 0x90;

		VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);
		memcpy(functionAddress, jmpInstructionBuffer, callInstructionLength);
		VirtualProtect(functionAddress, callInstructionLength, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), functionAddress, callInstructionLength);

		intactBigChecksumHook intactBigChecksum;
		intactBigChecksum.functionAddress = (uint64_t*)functionAddress;
		memcpy(intactBigChecksum.buffer, jmpInstructionBuffer, sizeof(uint8_t) * (7+3));
		intactBigchecksumHooks.push_back(intactBigChecksum);
	}

	// splitCount
	for (int i=0; i < splitCount; i++)
	{
		LPVOID asmStubLocation = allocate_somewhere_near(GetModuleHandle(nullptr), allocationSize);
		memset(asmStubLocation, 0x90, allocationSize);
		void* functionAddress = locationsSplit.get(i).get<void*>(0); // locationsIntact.get(i)
		//void* functionAddress = locationsSplit.get(i).get<void*>(0); // locationsIntact.get(i)
		uint64_t jmpDistance = (uint64_t)asmStubLocation - (uint64_t)functionAddress - 5; // 5 bytes from relative call instruction

		// backup instructions that will get destroyed
		const int length = sizeof(uint8_t) * 8;
		uint8_t instructionBuffer[8] = {};
		memcpy(instructionBuffer, functionAddress, length);

		uint32_t instructionBufferJmpDistance = 0;
		if (instructionBuffer[3] == 0xE9)
			memcpy(&instructionBufferJmpDistance, (char*)functionAddress+0x4, 4); // 0x4 so we skip 0xE9

		// TODO: fix negative instructionBufferJmpDistance when we are trying to get the rbpOffset
		/*
		static int huhCounter = 0;
		huhCounter++;
		if (huhCounter == 7)
		{
			SuspendAllThreads();
			__debugbreak();
		}
		*/

		bool jumpDistanceNegative = instructionBufferJmpDistance >> 31; // get sign bit from jump distance
		//int32_t jumpDistance = 0;
		int32_t jumpDistance = instructionBufferJmpDistance;

		// convert the hex number to a negative int
		//if (jumpDistanceNegative)
		//	jumpDistance = instructionBufferJmpDistance | 0xff << 24;

		// TODO: receive the rbpOffset by going through the jmp instruction
		// on big rbp offsets we could do the same hack we did on big intact where we do rbpOffset+0x100 if its below 0x60
		uint64_t rbpOffset = 0x0;
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


		// create assembly stub content
		static asmjit::JitRuntime runtime;
		asmjit::CodeHolder code;
		code.init(runtime.environment());
		asmjit::x86::Assembler a(&code);

		// pushad64();
		// a.sub(asmjit::x86::rsp, 0x40); // 0x40? 0x32 before

		a.sub(asmjit::x86::rsp, 0x400); // 0x40? 0x32 before
		pushad64();

		/*
		asmjit::Label L1 = a.newLabel();
		a.bind(L1);
		a.int3();
		a.jmp(L1);
		*/

		a.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x20), asmjit::x86::rax);
		a.mov(asmjit::x86::rdx, asmjit::x86::rcx);	// offset within text section pointer (ecx*4)
		a.mov(asmjit::x86::rcx, rbpOffset);

		a.mov(asmjit::x86::r8, asmjit::x86::rbp);	// we need this so we know what stack the stub was at
		
		// TODO: check if this is still fucked, the value is actually 0xfedef2b2 not 0xffdef2b2
		// since we swap out the last byte we mess up the jump distance
		/*
		if (jumpDistance == 0xffdef2b2)
		{
			SuspendAllThreads();
			__debugbreak();
		}
		*/

		if (jumpDistanceNegative)
			a.mov(asmjit::x86::r9, jumpDistance);
		else
			a.mov(asmjit::x86::r9, instructionBufferJmpDistance);

		a.mov(asmjit::x86::rax, (uint64_t)(void*)fixChecksum);
		a.call(asmjit::x86::rax);
		a.add(asmjit::x86::rsp, 0x8*4); // so that r12-r15 registers dont get corrupt

		//a.add(asmjit::x86::rsp, 0x40);
		//popad64();

		popad64WithoutRAX();
		a.add(asmjit::x86::rsp, 0x400);

		a.mov(ptr(asmjit::x86::rdx, asmjit::x86::rcx, 2), asmjit::x86::eax); // mov [rdx+rcx*4], eax

		if (instructionBufferJmpDistance == 0)
		{
			a.add(dword_ptr(asmjit::x86::rbp, rbpOffset), -1); // add dword ptr [rbp+rbpOffset], 0FFFFFFFFh
		}
		else
		{
			//printf("instructionBufferJmpDistance: %x\n", instructionBufferJmpDistance);
			// https://forum.osdev.org/viewtopic.php?p=168467#p168467
			// push the desired address on to the stack and then perform a 64 bit RET

			a.add(asmjit::x86::rsp, 0x8); // pop return address off the stack cause we will jump
			uint64_t addressToJump = 0;
			
			// TODO: just use jumpDistance once we got a working test case
			if (jumpDistanceNegative)
				addressToJump = (uint64_t)functionAddress + jumpDistance + 0x8; // 0x8 call instruction + offset + 2 nops
			else
				addressToJump = (uint64_t)functionAddress + instructionBufferJmpDistance + 0x8; // 0x8 call instruction + offset + 2 nops

			a.mov(asmjit::x86::r11, addressToJump);	// r11 is being used but should be fine based on documentation
			
			// on jmp checksums we do the rsp add earlier
			a.add(asmjit::x86::rsp, 0x8); // since we dont pop off rax we need to sub 0x8 the rsp
			a.push(asmjit::x86::r11);
		}

		a.ret();

		void* asmjitResult = nullptr;
		runtime.add(&asmjitResult, &code);
		
		// copy over the content to the stub
		uint8_t* tempBuffer = (uint8_t*)malloc(sizeof(uint8_t) * code.codeSize());
		memcpy(tempBuffer, asmjitResult, code.codeSize());
		memcpy(asmStubLocation, tempBuffer, sizeof(uint8_t) * code.codeSize());

		const int callInstructionBytes = 8;
		const int callInstructionLength = sizeof(uint8_t) * callInstructionBytes;

		DWORD old_protect{};
		VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);
		memset(functionAddress, 0, callInstructionLength);
		VirtualProtect(functionAddress, callInstructionLength, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), functionAddress, callInstructionLength);

		// E8 cd CALL rel32  Call near, relative, displacement relative to next instruction
		uint8_t jmpInstructionBuffer[callInstructionBytes] = {};
		jmpInstructionBuffer[0] = 0xE8;
		jmpInstructionBuffer[1] = (jmpDistance >> (0 * 8));
		jmpInstructionBuffer[2] = (jmpDistance >> (1 * 8));
		jmpInstructionBuffer[3] = (jmpDistance >> (2 * 8));
		jmpInstructionBuffer[4] = (jmpDistance >> (3 * 8));
		jmpInstructionBuffer[5] = 0x90;
		jmpInstructionBuffer[6] = 0x90;
		jmpInstructionBuffer[7] = 0x90;

		VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);
		memcpy(functionAddress, jmpInstructionBuffer, callInstructionLength);
		VirtualProtect(functionAddress, callInstructionLength, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), functionAddress, callInstructionLength);

		splitChecksumHook splitChecksum;
		splitChecksum.functionAddress = (uint64_t*)functionAddress;
		memcpy(splitChecksum.buffer, jmpInstructionBuffer, sizeof(uint8_t) * 8);
		splitchecksumHooks.push_back(splitChecksum);
	}
}

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

		// only valid if bp is at start of func
		uint64_t returnAddr = *(uint64_t*)info->ContextRecord->Rsp;
		returnAddr = returnAddr - baseAddr + StartOfTextSection - 0x1000;

		if (info->ContextRecord->Dr6 & 0x1)
		{
			// printf("bp1: %llx %llx %llx\n", exceptionAddr, idaExceptionAddr, returnAddr);
			// printf("cmd: %s\n", (char*)info->ContextRecord->Rdx);

			if ((strcmp((char*)info->ContextRecord->Rdx, "exec gamedata/configs/common/default_720p.cfg\n") == 0) && !multiplayerEnabled)
			{
				// function is wrong or something...
				printf("executing...\n");
				
				nopChecksumFixingMemcpy();

				SetScreen(11);
				LobbyBaseSetNetworkmode(1);
				SessionState(1);

				*discordSet1 = 1;
				*discordSet2 = 1;

				LiveStorage_ParseKeysTxt("mp_common,1,LKBcjAtLFtrhGQqXZP3GQN2MXbGe4yBA4CJ8KK+Tmyw=\n"
					"zm_common,1,uVkxOTxN2vKCJHt2piY5tGqy33LKZ0dKlKizutZifuI=\n"
					"wz_common,1,qYOw3RHpf/4LoNqha7D8w0l1uJs1a8f1GXvz9RSlcpc=\n"
					"cp_common,1,1Xms8bivDnvtle9GlNy3IHsDBYi5q6kSJTqMJUZbUBo=");
				LiveStorage_ParseKeysTxt2("mp_common,1,LKBcjAtLFtrhGQqXZP3GQN2MXbGe4yBA4CJ8KK+Tmyw=\n"
					"zm_common,1,uVkxOTxN2vKCJHt2piY5tGqy33LKZ0dKlKizutZifuI=\n"
					"wz_common,1,qYOw3RHpf/4LoNqha7D8w0l1uJs1a8f1GXvz9RSlcpc=\n"
					"cp_common,1,1Xms8bivDnvtle9GlNy3IHsDBYi5q6kSJTqMJUZbUBo=");

				// we cant disable the tls callbacks because the game checks for inlined hooks
				// allows for veh and regular dll injections to work
				disableTlsCallbacks();
			}

			if (strcmp((char*)info->ContextRecord->Rdx, "cmd iwr 2 1\n") == 0)
				multiplayerCounter += 1;

			if (multiplayerCounter == 2 && !multiplayerEnabled)
			{
				SetScreen(11);
				LobbyBaseSetNetworkmode(1);
				SessionState(1);

				*discordSet1 = 1;
				*discordSet2 = 1;

				LiveStorage_ParseKeysTxt("mp_common,1,LKBcjAtLFtrhGQqXZP3GQN2MXbGe4yBA4CJ8KK+Tmyw=\n"
					"zm_common,1,uVkxOTxN2vKCJHt2piY5tGqy33LKZ0dKlKizutZifuI=\n"
					"wz_common,1,qYOw3RHpf/4LoNqha7D8w0l1uJs1a8f1GXvz9RSlcpc=\n"
					"cp_common,1,1Xms8bivDnvtle9GlNy3IHsDBYi5q6kSJTqMJUZbUBo=");
				LiveStorage_ParseKeysTxt2("mp_common,1,LKBcjAtLFtrhGQqXZP3GQN2MXbGe4yBA4CJ8KK+Tmyw=\n"
					"zm_common,1,uVkxOTxN2vKCJHt2piY5tGqy33LKZ0dKlKizutZifuI=\n"
					"wz_common,1,qYOw3RHpf/4LoNqha7D8w0l1uJs1a8f1GXvz9RSlcpc=\n"
					"cp_common,1,1Xms8bivDnvtle9GlNy3IHsDBYi5q6kSJTqMJUZbUBo=");

				// if we call cbufaddtext in here we crash since we are basically creating an infintely loop
				info->ContextRecord->Rdx = (DWORD64)disconnectCvar;

				multiplayerEnabled = true;
			}

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
				createInlineAsmStub();

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

				//if (counter == 168207)
				//	SuspendAllThreads();

				printf("bp4: %llx %llx %d\n", exceptionAddr, idaExceptionAddr, counter);
				fprintf(logFile, "bp4: %llx %llx %d\n", exceptionAddr, idaExceptionAddr, counter);
				fflush(logFile);
			}

			info->ContextRecord->EFlags |= ResumeFlag;
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		// Veh hooking
		// PageGuardMemory(breakpointAddress, 1);

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

int main()
{
// TODO: refactor this later
#if 1
	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
	exceptionHandle = AddVectoredExceptionHandler(true, exceptionHandler);

	auto* const peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
	peb->BeingDebugged = false;
	*reinterpret_cast<PDWORD>(LPSTR(peb) + 0xBC) &= ~0x70;

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

	AllocConsole();
	freopen("CONIN$", "r", stdin);
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);
	//inputHandle = CreateThread(nullptr, 0, ConsoleInput, module, 0, nullptr);

	char* tlscallbackArrayAddr = reinterpret_cast<char*>(baseAddr + 0xbb443a8 + 0x1000);
	//printf("tls location: %llx\n", tlscallbackArrayAddr);

	RestoreNtdllDbgFunctions();
	auto mhinit = MH_Initialize();

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
#endif
	logFile = fopen("log.txt", "w+");

	static asmjit::JitRuntime runtime;

	asmjit::CodeHolder code;
	code.init(runtime.environment());

	asmjit::x86::Assembler a(&code);

	baseFuncAddr = reinterpret_cast<char*>(baseAddr + 0x821b8e0 + 0x1000);
	placeHardwareBP(baseFuncAddr, 0, Condition::Execute);

	// checksum comparison finding bp
	uint64_t tlsJmpAddr = 0x7FF627267390;
	uint64_t tlsFuncAddr = 0x7FF6402333F9;
	//char* bpAddr1 = reinterpret_cast<char*>(baseAddr + tlsJmpAddr - StartOfBinary);
	//placeHardwareBP(bpAddr1, 1, Condition::ReadWrite);

	// checksum fixing bp
	//char* bpAddr2 = reinterpret_cast<char*>(baseAddr + 0x7FF64254467C - StartOfBinary);
	//placeHardwareBP(bpAddr2, 2, Condition::ReadWrite);
	char* bpAddr2 = reinterpret_cast<char*>(baseAddr + 0x7FF641E3CD6E - StartOfBinary);
	placeHardwareBP(bpAddr2, 2, Condition::Execute);

	// arxan self healing changes back this hook
	//char* bpAddr1 = reinterpret_cast<char*>(baseAddr + 0x7FF6413597B5 - StartOfBinary);
	char* bpAddr1 = reinterpret_cast<char*>(baseAddr + 0x7ff6418ca8f5 - StartOfBinary);
	placeHardwareBP(bpAddr1, 3, Condition::Write);

	//char* bpAddr4 = reinterpret_cast<char*>(baseAddr + 0x7FF641E3CD6E - StartOfBinary);
	//placeHardwareBP(bpAddr4, 1, Condition::Execute);

	CbufAddText = reinterpret_cast<CbufAddText_t>(baseAddr + 0x821b8e0 + 0x1000);
	LobbyBaseSetNetworkmode = reinterpret_cast<LobbyBaseSetNetworkmode_t>(baseAddr + 0x9508b10 + 0x1000);
	SetScreen = reinterpret_cast<SetScreen_t>(baseAddr + 0x977e220 + 0x1000);
	SessionState = reinterpret_cast<SessionState_t>(baseAddr + 0xa6c1d90 + 0x1000);
	LiveStorage_ParseKeysTxt = reinterpret_cast<LiveStorage_ParseKeysTxt_t>(baseAddr + 0x8908280 + 0x1000);
	LiveStorage_ParseKeysTxt2 = reinterpret_cast<LiveStorage_ParseKeysTxt2_t>(baseAddr + 0x8909c30 + 0x1000);

	discordSet1 = reinterpret_cast<char*>(baseAddr + 0x18cff450 + 0x1000);
	discordSet2 = reinterpret_cast<char*>(baseAddr + 0x18d093e8 + 0x1000);

	// disable audio being turned on
	DWORD dwVolume;
	if (waveOutGetVolume(NULL, &dwVolume) == MMSYSERR_NOERROR)
		waveOutSetVolume(NULL, 0);

	// remove cached files for isTrial to work
	const char configPath[] = "C://Users//user//Documents//Call Of Duty Black Ops Cold War//player";

	for (const auto& entry : std::filesystem::directory_iterator(configPath))
	{
		auto fileName = entry.path().filename();
		auto filePath = entry.path();

		if (wcscmp(fileName.c_str(), L"config.ini") != 0)
			std::filesystem::remove(filePath);
	}

	// remove crashdumps
	const char crashPath[] = "C://Users//user//AppData//Local//CrashDumps";

	for (const auto& entry : std::filesystem::directory_iterator(crashPath))
	{
		auto filePath = entry.path();
		std::filesystem::remove(filePath);
	}

	mainThreadId = GetCurrentThreadId();
	return 0;
}
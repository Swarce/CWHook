#pragma once

#define PHNT_VERSION PHNT_WIN10_22H2
#include <phnt_windows.h>
#include <phnt.h>
#include <ntexapi.h>
#include <ntpsapi.h>
#include <minidumpapiset.h>
#include <TlHelp32.h>
#include <mmeapi.h>

#include "utils.h"

extern void* breakpointAddress;
extern HANDLE inputHandle;
extern DWORD inputThreadId;
extern CONTEXT context;
extern bool weAreDebugging;
extern std::vector<PVOID> VectoredExceptions;
extern uint64_t ntdllSize;

typedef enum _WINDOWINFOCLASS {
	WindowProcess,
	WindowThread,
	WindowActiveWindow,
	WindowFocusWindow,
	WindowIsHung,
	WindowClientBase,
	WindowIsForegroundThread,
#ifdef FE_IME
	WindowDefaultImeWindow,
	WindowDefaultInputContext,
#endif
} WINDOWINFOCLASS;

#define REMOVE_HWBP_ON_SUSPEND 0

typedef int(__stdcall* SetThreadContext_t)(HANDLE hThread, CONTEXT* lpContext);
extern SetThreadContext_t SetThreadContextOrig;

typedef HANDLE(__stdcall* NtUserQueryWindow_t)(HWND hwnd, WINDOWINFOCLASS WindowInfo);
extern NtUserQueryWindow_t NtUserQueryWindowOrig;

typedef __int64(__stdcall* NtUserInternalGetWindowText_t)(HWND hWnd, LPWSTR lpString, INT nMaxCount);
extern NtUserInternalGetWindowText_t NtUserInternalGetWindowTextOrig;

typedef int(__stdcall* NtUserGetClassName_t)(HWND hwnd, BOOL real, UNICODE_STRING* name);
extern NtUserGetClassName_t NtUserGetClassNameOrig;

void InitializeSystemHooks();
void DisableTlsCallbacks();
void DisableKiUserApcDispatcherHook();
void RestoreKernel32ThreadInitThunkFunction();

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

typedef int(__stdcall* GetWindowText_t)(HWND hWnd, LPSTR lpString, int nMaxCount);
typedef bool(__stdcall* FreeLibrary_t)(HMODULE hLibModule);
typedef void(__stdcall* FreeLibraryAndExitThread_t)(HMODULE hLibModule, DWORD dwExitCode);
typedef HWND(__stdcall* NtUserFindWindowEx_t)(HWND hwndParent,HWND hwndChildAfter, PUNICODE_STRING ucClassName, PUNICODE_STRING  ucWindowName);
typedef HWND(__stdcall* NtUserWindowFromPoint_t)(LONG X, LONG Y);
typedef BOOL(__stdcall* EnumWindowsOrig_t)(WNDENUMPROC lpEnumFunc, LPARAM lParam);
typedef int(__stdcall* GetThreadContext_t)(HANDLE hThread, CONTEXT* lpContext);

typedef HANDLE(__stdcall* CreateThread_t)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef PVOID(__stdcall* AddVectoredExceptionHandler_t)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
typedef LPTOP_LEVEL_EXCEPTION_FILTER(__stdcall* SetUnhandledExceptionFilter_t)(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
typedef HWND(__stdcall* NtUserGetForegroundWindow_t)();
typedef NTSTATUS(__stdcall* NtUserBuildHwndList_t)(HDESK hDesk, HWND hWndNext, BOOL EnumChildren, BOOL RemoveImmersive, DWORD ThreadID, UINT Max, HWND* List, PULONG Cnt);
typedef NTSTATUS(__stdcall* NtSetInformationProcess_t)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
typedef NTSTATUS(__stdcall* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef BOOL(__stdcall* CheckRemoteDebuggerPresent_t)(HANDLE hProcess, PBOOL pbDebuggerPresent);

typedef DWORD(__stdcall* GetWindowThreadProcessId_t)(HWND hWnd, LPDWORD lpdwProcessId);
typedef int(__stdcall* GetClassName_t)(HWND hWnd, LPSTR lpClassName, int nMaxCount);
typedef BOOL(__stdcall* EnumChildWindows_t)(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam);
typedef HMENU(__stdcall* GetMenu_t)(HWND hWnd);
typedef int(__stdcall* GetMenuString_t)(HMENU hMenu,UINT uIDItem,LPSTR lpString, int cchMax,UINT flags);
typedef HMENU(__stdcall* GetSubMenu_t)(HMENU hMenu, int nPos);

typedef HANDLE(__stdcall* CreateMutexEx_t)(const LPSECURITY_ATTRIBUTES attributes, const LPCSTR name, const DWORD flags, const DWORD access);

typedef HHOOK(__stdcall* SetWindowsHookEx_t)(
	int       idHook,
	HOOKPROC  lpfn,
	HINSTANCE hmod,
	DWORD     dwThreadId);

typedef void(__fastcall* RtlRestoreContext_t)(PCONTEXT ContextRecord, _EXCEPTION_RECORD* ExceptionRecord);

typedef NTSTATUS(__fastcall* NtAllocateVirtualMemory_t)(HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect);

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

typedef NTSTATUS(__fastcall* NtSetInformationJobObject_t)(HANDLE* JobHandle,
	ACCESS_MASK        DesiredAccess,
	OBJECT_ATTRIBUTES* ObjectAttributes);

#define PHNT_VERSION PHNT_WIN10_22H2
#include <phnt_windows.h>
#include <phnt.h>
#include <ntexapi.h>
#include <ntpsapi.h>
#include <minidumpapiset.h>

#include <TlHelp32.h>
#include <mmeapi.h>
#include <string>

#include "libs/patterns/Hooking.Patterns.h"
#include "libs/minhook/include/MinHook.h"
#include "utils.h"
#include "systemhooks.h"
#include "restorentdll.h"

const WCHAR* BadProcessnameList[] =
{
	L"ollydbg.exe",
	L"ida.exe",
	L"ida64.exe",
	L"idag.exe",
	L"idag64.exe",
	L"idaw.exe",
	L"idaw64.exe",
	L"idaq.exe",
	L"idaq64.exe",
	L"idau.exe",
	L"idau64.exe",
	L"scylla.exe",
	L"scylla_x64.exe",
	L"scylla_x86.exe",
	L"protection_id.exe",
	L"x64dbg.exe",
	L"x32dbg.exe",
	L"windbg.exe",
	L"reshacker.exe",
	L"ImportREC.exe",
	L"IMMUNITYDEBUGGER.EXE",
	L"devenv.exe",
	L"cheatengine-x86_64-SSE4-AVX2.exe",
	L"cheatengine.exe",
	L"ReClass.NET.exe",
	L"ReClassEx64.exe",
};

const WCHAR* BadWindowTextList[] =
{
	L"OLLYDBG",
	L"ida",
	L"disassembly",
	L"scylla",
	L"Debug",
	L"[CPU",
	L"Immunity",
	L"WinDbg",
	L"x32dbg",
	L"x64dbg",
	L"Import reconstructor"
	L"Cheat Engine",
	L"Cheat Engine 7.3",
	L"Cheat Engine 7.5",
	L"ReClass",
	L"ReClass.NET",
	L"ReClass.NET - Info",
	L"ReClass.NET - Class Selection",
	L"ReClass.NET - Enums",
	L"ReClass.NET - Code Generator",
	L"ReClass.NET - Process Informations",
	L"ReClass.NET - Scanner",
	L"ReClass.NET - Named Addresses",
	L"ReClass.NET - Attach to Process",
	L"ReClass.NET - Settings",
	L"ReClass.NET - Plugins",
	L"Process Informations",
	L".NET-BroadcastEventWindow",
	L"BroadcastEventWindow",
};

const WCHAR* BadWindowClassList[] =
{
	L"OLLYDBG",
	L"Zeta Debugger",
	L"Rock Debugger",
	L"ObsidianGUI",
	L"ID", //Immunity Debugger
	L"WinDbgFrameClass", //WinDBG
	L"idawindow",
	L"tnavbox",
	L"idaview",
	L"tgrzoom",
	L"ReClass",
	L"SysTreeView32",
	L".NET-BroadcastEventWindow",
	L"tooltips_class32",
};

FILE* logFile = nullptr;
bool suspendNewThreads = false;

void FilterHwndList(HWND* phwndFirst, PULONG pcHwndNeeded)
{
	for (UINT i = 0; i < *pcHwndNeeded; i++)
	{
		if (phwndFirst[i] != nullptr && IsWindowBad(phwndFirst[i]))
		{
			// TODO: do enumwindows ourselves or whatever its called and check if we are filtering properly

			if (i == 0)
			{
				// Find the first HWND that belongs to a different process (i + 1, i + 2... may still be ours)
				for (UINT j = i + 1; j < *pcHwndNeeded; j++)
				{
					if (phwndFirst[j] != nullptr && !IsWindowBad(phwndFirst[j]))
					{
						phwndFirst[i] = phwndFirst[j];
						break;
					}
				}
			}
			else
			{
				phwndFirst[i] = phwndFirst[i - 1]; //just override with previous
			}
		}
	}
}

std::string GetLastErrorAsString()
{
    //Get the error message ID, if any.
    DWORD errorMessageID = ::GetLastError();
    if(errorMessageID == 0) {
        return std::string(); //No error message has been recorded
    }
    
    LPSTR messageBuffer = nullptr;

    //Ask Win32 to give us the string version of that message ID.
    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
    
    //Copy the error message into a std::string.
    std::string message(messageBuffer, size);
    
    //Free the Win32's string's buffer.
    LocalFree(messageBuffer);
            
    return message;
}

bool IsWindowBad(HWND hWnd)
{
	DECLARE_UNICODE_STRING_SIZE(ClassName, 256);
	DECLARE_UNICODE_STRING_SIZE(WindowText, 512);
	
	//typedef int(__stdcall* NtUserGetClassName_t)(HWND hwnd, BOOL real, UNICODE_STRING* name);
	//NtUserGetClassName_t NtUserGetClassName = (NtUserGetClassName_t)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserGetClassName");

	//typedef int(__stdcall* NtUserInternalGetWindowText_t)(HWND hwnd, WCHAR* text, INT count);
	//NtUserInternalGetWindowText_t NtUserInternalGetWindowText = (NtUserInternalGetWindowText_t)GetProcAddress(GetModuleHandle("win32u.dll"), "NtUserInternalGetWindowText");

	ClassName.Length = (USHORT)NtUserGetClassNameOrig(hWnd, FALSE, &ClassName) * sizeof(WCHAR);
	ClassName.Buffer[ClassName.Length / sizeof(WCHAR)] = UNICODE_NULL;
	if (IsWindowClassNameBad(&ClassName))
		return true;

	WindowText.Length = (USHORT)NtUserInternalGetWindowTextOrig(hWnd, WindowText.Buffer, (INT)(WindowText.MaximumLength / sizeof(WCHAR))) * sizeof(WCHAR);
	WindowText.Buffer[WindowText.Length / sizeof(WCHAR)] = UNICODE_NULL;
	return IsWindowNameBad(&WindowText);
}

bool RtlUnicodeStringContains(PUNICODE_STRING Str, PUNICODE_STRING SubStr, BOOLEAN CaseInsensitive)
{
	if (Str == nullptr || SubStr == nullptr || Str->Length < SubStr->Length)
		return false;

	const USHORT numCharsDiff = (Str->Length - SubStr->Length) / sizeof(WCHAR);
	UNICODE_STRING slice = *Str;
	slice.Length = SubStr->Length;

	for (USHORT i = 0; i <= numCharsDiff; ++i, ++slice.Buffer, slice.MaximumLength -= sizeof(WCHAR))
	{
		if (RtlEqualUnicodeString(&slice, SubStr, CaseInsensitive))
			return true;
	}
	return false;
}


bool IsWindowClassNameBad(PUNICODE_STRING className)
{
	if (className == nullptr || className->Length == 0 || className->Buffer == nullptr)
		return false;

	UNICODE_STRING badWindowClassName;
	for (int i = 0; i < _countof(BadWindowClassList); i++)
	{
		RtlInitUnicodeString(&badWindowClassName, const_cast<PWSTR>(BadWindowClassList[i]));
		if (RtlUnicodeStringContains(className, &badWindowClassName, TRUE))
			return true;
	}
	return false;
}

bool IsWindowNameBad(PUNICODE_STRING windowName)
{
	if (windowName == nullptr || windowName->Length == 0 || windowName->Buffer == nullptr)
		return false;

	UNICODE_STRING badWindowName;
	for (int i = 0; i < _countof(BadWindowTextList); i++)
	{
		RtlInitUnicodeString(&badWindowName, const_cast<PWSTR>(BadWindowTextList[i]));
		if (RtlUnicodeStringContains(windowName, &badWindowName, TRUE))
			return true;
	}
	return false;
}

bool remove_evil_keywords_from_string(const UNICODE_STRING& string)
{
	static const std::wstring evil_keywords[] =
	{
		L"IDA",
		L"ida",
		L"HxD",
		L"cheatengine",
		L"Cheat Engine",
		L"ReClass",
		L"reclass",
		L"ReClass.NET",
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

bool is_relatively_far(const void* pointer, const void* data)
{
    const int64_t diff = size_t(data) - (size_t(pointer) + 5);
    const auto small_diff = int32_t(diff);
    return diff != int64_t(small_diff);
}

uint8_t* allocate_somewhere_near(const void* base_address, const size_t size)
{
    size_t offset = 0;
    while (true)
    {
        offset += size;
        auto* target_address = static_cast<const uint8_t*>(base_address) - offset;
        if (is_relatively_far(base_address, target_address))
        {
            return nullptr;
        }

        const auto res = VirtualAlloc(const_cast<uint8_t*>(target_address), size, MEM_RESERVE | MEM_COMMIT,
                                      PAGE_EXECUTE_READWRITE);
        if (res)
        {
            if (is_relatively_far(base_address, target_address))
            {
                VirtualFree(res, 0, MEM_RELEASE);
                return nullptr;
            }

            return static_cast<uint8_t*>(res);
        }
    }
}

FILE* fmemopen(void* buf, size_t len, const char* type)
{
	int fd;
	FILE* fp;
	char tp[MAX_PATH - 13];
	char fn[MAX_PATH + 1];
	int* pfd = &fd;
	int retner = -1;
	char tfname[] = "MemTF_";
	if (!GetTempPathA(sizeof(tp), tp))
		return NULL;
	if (!GetTempFileNameA(tp, tfname, 0, fn))
		return NULL;
	retner = _sopen_s(pfd, fn, _O_CREAT | _O_SHORT_LIVED | _O_TEMPORARY | _O_RDWR | _O_BINARY | _O_NOINHERIT, _SH_DENYRW, _S_IREAD | _S_IWRITE);
	if (retner != 0)
		return NULL;
	if (fd == -1)
		return NULL;
	fp = _fdopen(fd, "wb+");
	if (!fp) {
		_close(fd);
		return NULL;
	}
	/*File descriptors passed into _fdopen are owned by the returned FILE * stream.If _fdopen is successful, do not call _close on the file descriptor.Calling fclose on the returned FILE * also closes the file descriptor.*/
	fwrite(buf, len, 1, fp);
	rewind(fp);
	return fp;
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

			// This has to get switched on depending if youre suspending too early or too late
#if 0
			if (counter == 0)
			{
				counter++;
				continue;
			}
#else
			if (GetCurrentThreadId() == entry.th32ThreadID)
				continue;
#endif


			DWORD suspendResult = SuspendThread(currentThread);
			if (suspendResult == -1)
				printf("suspend: %s\n", GetLastErrorAsString().c_str());
		}

	} while (Thread32Next(snapshotHandle, &entry));
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

	DisableTlsCallbacks();

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
	
	while (!IsDebuggerPresent()) {
		Sleep(100);
	}

	printf("running...\n");
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

	if (!SetThreadContextOrig(mainThread, &context))
		printf("could'nt overwrite thread context!\n");

	if (!SetThreadContextOrig(GetCurrentThread(), &context))
		printf("could'nt overwrite thread context!\n");

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
		}
	} while (Thread32Next(snapshotHandle, &entry));

	printf("removed all hardware bp's\n");
}
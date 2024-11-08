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
#include <intrin.h>
#include <filesystem>

#include "libs/minhook/include/MinHook.h"
#include "restorentdll.h"
#include "utils.h"
#include "systemhooks.h"
#include "exceptions.h"
#include "arxan.h"
#include "instrumentationCallbacks.h"
#include "paths.h"
#include "syscalls.h"

int main()
{
	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));

	HANDLE hFile = CreateFile("C://Windows//System32//ntdll.dll", GENERIC_READ,
		FILE_SHARE_READ, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	LARGE_INTEGER size;
	GetFileSizeEx(hFile, &size);
	ntdllSize = 4096 * ceil(size.QuadPart / 4096.0f);

	exceptionHandle = AddVectoredExceptionHandler(true, exceptionHandler);

	auto* const peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
	peb->BeingDebugged = false;
	*reinterpret_cast<PDWORD>(LPSTR(peb) + 0xBC) &= ~0x70;

	AllocConsole();
	freopen("CONIN$", "r", stdin);
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);

	printf("address %llx\n", baseAddr);
	//inputHandle = CreateThread(nullptr, 0, ConsoleInput, module, 0, &inputThreadId);
	//printf("inputThreadId: %llx\n", inputThreadId);

	SetSyscallsFromNtdll();
	RestoreNtdllDbgFunctions();
	MH_Initialize();
	InitializeSystemHooks();

	logFile = fopen("log.txt", "w+");

	// disable audio being turned on
	DWORD dwVolume;
	if (waveOutGetVolume(NULL, &dwVolume) == MMSYSERR_NOERROR)
		waveOutSetVolume(NULL, 0);

	HMODULE moduleNtdll = GetModuleHandle("ntdll.dll");

	placeHardwareBP((char*)GetProcAddress(moduleNtdll, "NtAllocateVirtualMemory")+0x12, 3, Condition::Execute);

	// arxan applies checksum checks & healing to INT2D
	NtdllAsmStub();

	// crashes the game after a while, only good if you want to know what syscalls get called from win32u & friends
	// initInstrumentation();

	return 0;
}
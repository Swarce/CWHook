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
#include "gamehooks.h"
#include "arxan.h"
#include "instrumentationCallbacks.h"

int mainThreadId = 0;
char* baseFuncAddr = nullptr;

int main()
{
	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));

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

	RestoreNtdllDbgFunctions();
	MH_Initialize();

	InitializeSystemHooks();

	logFile = fopen("log.txt", "w+");

	char* NtQueryInformationThreadAddr = (char*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtAllocateVirtualMemory");
	placeHardwareBP(NtQueryInformationThreadAddr + 0x12, 3, Condition::Execute);

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

	ntdllAsmStub();

	// crashes the game after a while, only good if you want to know what syscalls get called from win32u
	// initInstrumentation();
	
	return 0;
}
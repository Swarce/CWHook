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
#include <filesystem>

#include "libs/minhook/include/MinHook.h"

void util_copy(void* place, const void* data, const size_t length)
{
	DWORD old_protect{};
	VirtualProtect(place, length, PAGE_EXECUTE_READWRITE, &old_protect);

	std::memmove(place, data, length);

	VirtualProtect(place, length, old_protect, &old_protect);
	FlushInstructionCache(GetCurrentProcess(), place, length);
}

void RestoreNtdllDbgFunctions()
{
	static const char* functions[] = {
	"DbgBreakPoint",
	"DbgUserBreakPoint",
	"DbgUiConnectToDbg",
	"DbgUiContinue",
	"DbgUiConvertStateChangeStructure",
	"DbgUiDebugActiveProcess",
	"DbgUiGetThreadDebugObject",
	"DbgUiIssueRemoteBreakin",
	"DbgUiRemoteBreakin",
	"DbgUiSetThreadDebugObject",
	"DbgUiStopDebugging",
	"DbgUiWaitStateChange",
	"DbgPrintReturnControlC",
	"DbgPrompt",
	};

	using buffer = uint8_t[15];
	static buffer buffers[ARRAYSIZE(functions)] = {};
	static bool loaded = false;

	for (auto i = 0u; i < ARRAYSIZE(functions); ++i)
	{
		void* functionAddr = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), functions[i]);
		
		if (!functionAddr)
		{
			continue;
		}

		if (!loaded)
		{
			memcpy(buffers[i], functionAddr, sizeof(buffer));
		}
		else
		{
			util_copy(functionAddr, buffers[i], sizeof(buffer));
		}
	}

	loaded = true;
}

bool EnableDebugPrivilege()
{
	bool bResult = false;
	HANDLE hToken = NULL;
	DWORD ec = 0;

	do
	{
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
			break;

		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
			break;

		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
			break;

		bResult = true;
	} while (0);

	if (hToken)
		CloseHandle(hToken);

	return bResult;
}
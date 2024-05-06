#define PHNT_VERSION PHNT_WIN10_22H2
#include <phnt_windows.h>
#include <phnt.h>
#include <ntexapi.h>
#include <ntpsapi.h>
#include <minidumpapiset.h>

#include <TlHelp32.h>
#include <mmeapi.h>

#include <string>
#include <iostream>
#include <stdio.h>
#include <intrin.h>

#include <asmjit/core/jitruntime.h>
#include <asmjit/x86/x86assembler.h>

#include "libs/minhook/include/MinHook.h"
#include "gamehooks.h"
#include "systemhooks.h"
#include "utils.h"

const char* disconnectCvar = "disconnect\n";

CbufAddText_t CbufAddTextOrig;
SetScreen_t SetScreen;
SessionState_t SessionState;
LobbyBaseSetNetworkmode_t LobbyBaseSetNetworkmode;
LiveStorage_ParseKeysTxt_t LiveStorage_ParseKeysTxt;
LiveStorage_ParseKeysTxt2_t LiveStorage_ParseKeysTxt2;

char* config1;
char* config2;
bool multiplayerEnabled;
int multiplayerCounter;

void Cbuf_AddText(int a1, char *a2)
{
	if ((strcmp(a2, "exec gamedata/configs/common/default_720p.cfg\n") == 0) && !multiplayerEnabled)
	{
		printf("executing...\n");
		
		SetScreen(11);
		LobbyBaseSetNetworkmode(1);
		SessionState(1);

		*config1 = 1;
		*config2 = 1;

		LiveStorage_ParseKeysTxt("mp_common,1,LKBcjAtLFtrhGQqXZP3GQN2MXbGe4yBA4CJ8KK+Tmyw=\n"
			"zm_common,1,uVkxOTxN2vKCJHt2piY5tGqy33LKZ0dKlKizutZifuI=\n"
			"wz_common,1,qYOw3RHpf/4LoNqha7D8w0l1uJs1a8f1GXvz9RSlcpc=\n"
			"cp_common,1,1Xms8bivDnvtle9GlNy3IHsDBYi5q6kSJTqMJUZbUBo=");
		LiveStorage_ParseKeysTxt2("mp_common,1,LKBcjAtLFtrhGQqXZP3GQN2MXbGe4yBA4CJ8KK+Tmyw=\n"
			"zm_common,1,uVkxOTxN2vKCJHt2piY5tGqy33LKZ0dKlKizutZifuI=\n"
			"wz_common,1,qYOw3RHpf/4LoNqha7D8w0l1uJs1a8f1GXvz9RSlcpc=\n"
			"cp_common,1,1Xms8bivDnvtle9GlNy3IHsDBYi5q6kSJTqMJUZbUBo=");
	}

	if (strcmp(a2, "cmd iwr 2 1\n") == 0)
		multiplayerCounter += 1;

	if (multiplayerCounter == 2 && !multiplayerEnabled)
	{
		SetScreen(11);
		LobbyBaseSetNetworkmode(1);
		SessionState(1);

		*config1 = 1;
		*config2 = 1;

		LiveStorage_ParseKeysTxt("mp_common,1,LKBcjAtLFtrhGQqXZP3GQN2MXbGe4yBA4CJ8KK+Tmyw=\n"
			"zm_common,1,uVkxOTxN2vKCJHt2piY5tGqy33LKZ0dKlKizutZifuI=\n"
			"wz_common,1,qYOw3RHpf/4LoNqha7D8w0l1uJs1a8f1GXvz9RSlcpc=\n"
			"cp_common,1,1Xms8bivDnvtle9GlNy3IHsDBYi5q6kSJTqMJUZbUBo=");
		LiveStorage_ParseKeysTxt2("mp_common,1,LKBcjAtLFtrhGQqXZP3GQN2MXbGe4yBA4CJ8KK+Tmyw=\n"
			"zm_common,1,uVkxOTxN2vKCJHt2piY5tGqy33LKZ0dKlKizutZifuI=\n"
			"wz_common,1,qYOw3RHpf/4LoNqha7D8w0l1uJs1a8f1GXvz9RSlcpc=\n"
			"cp_common,1,1Xms8bivDnvtle9GlNy3IHsDBYi5q6kSJTqMJUZbUBo=");

		// if we call cbufaddtext in here we crash since we are basically creating an infintely loop
		a2 = (char*)disconnectCvar;

		multiplayerEnabled = true;
	}

	CbufAddTextOrig(a1,a2);
}

void setGameVariables()
{
	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));

	LobbyBaseSetNetworkmode = reinterpret_cast<LobbyBaseSetNetworkmode_t>(baseAddr + 0x9508b10 + 0x1000);
	SetScreen = reinterpret_cast<SetScreen_t>(baseAddr + 0x977e220 + 0x1000);
	SessionState = reinterpret_cast<SessionState_t>(baseAddr + 0xa6c1d90 + 0x1000);
	LiveStorage_ParseKeysTxt = reinterpret_cast<LiveStorage_ParseKeysTxt_t>(baseAddr + 0x8908280 + 0x1000);
	LiveStorage_ParseKeysTxt2 = reinterpret_cast<LiveStorage_ParseKeysTxt2_t>(baseAddr + 0x8909c30 + 0x1000);
	config1 = reinterpret_cast<char*>(baseAddr + 0x18cff450 + 0x1000);
	config2 = reinterpret_cast<char*>(baseAddr + 0x18d093e8 + 0x1000);
}

void InitializeGameHooks()
{
	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
	void* CbufAddTextAddr = reinterpret_cast<char*>(baseAddr + 0x821b8e0 + 0x1000);

	if (MH_CreateHook(CbufAddTextAddr, &Cbuf_AddText, (LPVOID*)(&CbufAddTextOrig)) != MH_OK)
	{
		printf("hook didn't work\n");
	}
	if (MH_EnableHook(CbufAddTextAddr) != MH_OK)
	{
		printf("hook didn't work\n");
	}
}

// this currently will crash the game because arxan does not like that we have threads running that didn't get spawned by the game explicitly
DWORD WINAPI ConsoleInput(LPVOID lpReserved)
{
	bool setHWBP = false;
	while (true)
	{
		std::string input;
		getline(std::cin, input);

		if (setHWBP)
		{
			uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
			uint64_t hwbpAddress = strtoll(input.c_str(), NULL, 16);
			char* bpAddr1 = reinterpret_cast<char*>(baseAddr + hwbpAddress - StartOfBinary);
			placeHardwareBP(bpAddr1, 3, Condition::Write);
			setHWBP = false;
		}

		if (strcmp(input.c_str(), "b") == 0)
		{
			printf("set breakpoint\n");
			setHWBP = true;
		}
	}
	return 0;
}

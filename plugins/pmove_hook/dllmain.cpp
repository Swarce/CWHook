#include <Windows.h>
#include <stdio.h>
#include <cstdint>

#include "../../libs/minhook/include/MinHook.h"

union DvarLimits
{
	struct
	{
		int stringCount;
		const char** strings;
	} enumeration;

	struct
	{
		int min;
		int max;
	} integer;

	struct
	{
		int64_t min;
		int64_t max;
	} integer64;

	struct
	{
		uint64_t min;
		uint64_t max;
	} unsignedInt64;

	struct
	{
		float min;
		float max;
	} value;

	struct
	{
		float min;
		float max;
	} vector;
};

struct dvar_t;

struct DvarValue
{
	union
	{
		bool enabled;
		int integer;
		uint32_t unsignedInt;
		int64_t integer64;
		uint64_t unsignedInt64;
		float value;
		float vector[4];
		const char* string;
		uint8_t color[4];
		const dvar_t* indirect[3];
	} naked;

	uint64_t encrypted;
};

struct DvarData
{
	DvarValue current;
	DvarValue latched;
	DvarValue reset;
};

struct DvarName
{
	__int64 hash;
	__int64 null;
};

enum dvarType_t : __int32
{
	DVAR_TYPE_INVALID = 0,
	DVAR_TYPE_BOOL = 1,
	DVAR_TYPE_FLOAT = 2,
	DVAR_TYPE_FLOAT_2 = 3,
	DVAR_TYPE_FLOAT_3 = 4,
	DVAR_TYPE_FLOAT_4 = 5,
	DVAR_TYPE_INT = 6,
	DVAR_TYPE_ENUM = 7,
	DVAR_TYPE_STRING = 8,
	DVAR_TYPE_COLOR = 9,
	DVAR_TYPE_INT64 = 10,
	DVAR_TYPE_UINT64 = 11,
	DVAR_TYPE_LINEAR_COLOR_RGB = 12,
	DVAR_TYPE_COLOR_XYZ = 13,
	DVAR_TYPE_COLOR_LAB = 14,
	DVAR_TYPE_SESSIONMODE_BASE_DVAR = 15,
	DVAR_TYPE_COUNT = 16,
};

struct dvar_t
{
	DvarName name;
	DvarData* value;
	dvarType_t type;
	unsigned int flags;
	DvarLimits domain;
	char padding_unk1[8];
};

HANDLE thread = nullptr;
const uint64_t StartOfBinary = 0x7FF71AA90000;

typedef float(__fastcall* BG_GetFriction_t)();
BG_GetFriction_t BG_GetFriction_Orig;
float BG_GetFriction()
{
	float friction = BG_GetFriction_Orig();

	//friction /= 0.6;

	//friction = -1000.0f;
	return friction;
}

typedef bool(__fastcall* BG_HasPerk_t)(char* playerState, uint32_t perkIndex);
BG_HasPerk_t BG_HasPerk_Orig;
bool BG_HasPerk(char* playerState, uint32_t perkIndex)
{
	bool result = BG_HasPerk_Orig(playerState, perkIndex);

	return result;
}

typedef bool(__fastcall* Jump_Check_t)(char* pm, char* pml);
Jump_Check_t Jump_Check_Orig;
bool Jump_Check(char* pm, char* pml)
{
	bool result = Jump_Check_Orig(pm, pml);

	return result;
}

typedef bool(__fastcall* PM_AirMove_t)(char* pm, char* pml);
PM_AirMove_t PM_AirMove_Orig;
void PM_AirMove(char* pm, char* pml)
{
	PM_AirMove_Orig(pm, pml);
	return;
}

typedef bool(__fastcall* PM_Accelerate_t)(char* ps, char* pml, float* wishdir, float wishspeed, float accel);
PM_Accelerate_t PM_Accelerate_Orig;
void PM_Accelerate(char* ps, char* pml, float* wishdir, float wishspeed, float accel)
{
	PM_Accelerate_Orig(ps, pml, wishdir, wishspeed, accel);
	return;
}

typedef bool(__fastcall* Dvar_GetBool_t)(__int64 a1);
Dvar_GetBool_t Dvar_GetBool;

typedef uint64_t(__fastcall* Dvar_FindVar_t)(__int64 dvar);
Dvar_FindVar_t Dvar_FindVar;

typedef void(__fastcall* Com_Frame_t)();
Com_Frame_t Com_Frame_Orig;

bool hideHud = false;
void Com_Frame()
{
	static bool initDraw2DSetFlag = false;

	if (!initDraw2DSetFlag)
	{
		dvar_t* cgdraw2dLocation = (dvar_t*)Dvar_FindVar(0x578107FC9F13DAEC);
		cgdraw2dLocation->flags = 0;
		initDraw2DSetFlag = true;
	}

	bool cg_draw2d = Dvar_GetBool(Dvar_FindVar(0x578107FC9F13DAEC));
	if (cg_draw2d)
		hideHud = false;
	else
		hideHud = true;

	Com_Frame_Orig();
}

typedef void(__fastcall* UIElement_Render_t)(unsigned int a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, float a6, float a7, float a8, float a9);
UIElement_Render_t UIElement_Render_Orig;
void UIElement_Render(unsigned int a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, float a6, float a7, float a8, float a9)
{
	if (hideHud)
		a9 = 0.0f;
		
	UIElement_Render_Orig(a1, a2, a3, a4, a5, a6, a7, a8, a9);
}

void InitializeGameHooks()
{
	printf("GetModuleHandle\n");
	uint64_t baseAddr = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));

	struct hook_t
	{
		void* addr;
		void* ourFunction;
		void** originalFunction;
		bool enabled;
	};

	Dvar_GetBool = (Dvar_GetBool_t)(char*)(baseAddr + 0x7FF71C4F8F50 - StartOfBinary);
	Dvar_FindVar = (Dvar_FindVar_t)(char*)(baseAddr + 0x7FF726B42090 - StartOfBinary);
	printf("Dvar_GetBool Dvar_FindVar\n");

	hook_t hooks[]{
		{(char*)(baseAddr + 0x7FF724121BC0 - StartOfBinary), &BG_GetFriction, (LPVOID*)(&BG_GetFriction_Orig), false},
		{(char*)(baseAddr + 0x7FF7261D2530 - StartOfBinary), &BG_HasPerk, (LPVOID*)(&BG_HasPerk_Orig), false},
		{(char*)(baseAddr + 0x7FF726E17D80 - StartOfBinary), &Jump_Check, (LPVOID*)(&Jump_Check_Orig), false},
		{(char*)(baseAddr + 0x7FF722028D90 - StartOfBinary), &PM_AirMove, (LPVOID*)(&PM_AirMove_Orig), false},
		{(char*)(baseAddr + 0x7FF7220289F0 - StartOfBinary), &PM_Accelerate, (LPVOID*)(&PM_Accelerate_Orig), false},
		{(char*)(baseAddr + 0x7FF7365769FA - StartOfBinary), &Com_Frame, (LPVOID*)(&Com_Frame_Orig), false},
		{(char*)(baseAddr + 0x7FF725865FA0 - StartOfBinary), &UIElement_Render, (LPVOID*)(&UIElement_Render_Orig), false}
	};
	
	printf("MH_Initialize...\n");
	MH_Initialize();
	size_t amountHooks = sizeof(hooks) / sizeof(hook_t);
	for (int i = 0; i < amountHooks; i++)
		if (MH_CreateHook(hooks[i].addr, hooks[i].ourFunction, hooks[i].originalFunction) != MH_OK)
			printf("game hook %d didn't work\n", i);

	for (int i = 0; i < amountHooks; i++)
		if (MH_EnableHook(hooks[i].addr) != MH_OK)
			printf("enable game hook %d didn't work\n", i);
}


DWORD WINAPI main(HMODULE hModule)
{	
	printf("main thread\n");
	static int counter = 0;

	printf("InitializeGameHooks...\n");
	InitializeGameHooks();

	return true;
}

void clean(HMODULE hModule)
{
	MH_RemoveHook(MH_ALL_HOOKS);
	MH_Uninitialize();
	printf("clean done\n");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        //thread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)main, hModule, NULL, NULL);
		main(hModule);
        break;
    case DLL_PROCESS_DETACH:
        clean(hModule);
        break;
    default:
		break;
	}
    
	return TRUE;
}


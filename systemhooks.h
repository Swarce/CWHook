#pragma once

#define PHNT_VERSION PHNT_WIN10_22H2
#include <phnt_windows.h>
#include <phnt.h>
#include <cstdint>

extern void* breakpointAddress;
extern HANDLE inputHandle;
extern DWORD inputThreadId;
enum Condition { Execute = 0, Write = 1, ReadWrite = 3 };

void InitializeSystemHooks();
void disableTlsCallbacks();
void removeAllHardwareBP();
void SuspendAllThreads();
void ManualHookFunction(uint64_t functionAddress, uint64_t setInfoOffset);
void placeHardwareBP(void* addr, int count, Condition condition);
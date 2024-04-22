#pragma once

#include <cstdint>

extern void* breakpointAddress;
enum Condition { Execute = 0, Write = 1, ReadWrite = 3 };

void InitializeSystemHooks();
void disableTlsCallbacks();
void removeAllHardwareBP();
void SuspendAllThreads();
void ManualHookFunction(uint64_t functionAddress, uint64_t setInfoOffset);
void placeHardwareBP(void* addr, int count, Condition condition);
#pragma once
#include <stdint.h>

#define PHNT_VERSION PHNT_WIN10_22H2
#include <phnt_windows.h>

extern LPVOID ntdllAsmStubLocation;

int fixChecksum(uint64_t rbpOffset, uint64_t ptrOffset, uint64_t* ptrStack, uint32_t jmpInstructionDistance, uint32_t calculatedChecksumFromArg);
void createInlineAsmStub();
void createChecksumHealingStub();
void ntdllAsmStub();
void win32uAsmStub();
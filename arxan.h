#pragma once
#include <stdint.h>

#define PHNT_VERSION PHNT_WIN10_22H2
#include <phnt_windows.h>

extern LPVOID ntdllAsmStubLocation;

int FixChecksum(uint64_t rbpOffset, uint64_t ptrOffset, uint64_t* ptrStack, uint32_t jmpInstructionDistance, uint32_t calculatedChecksumFromArg);
void CreateInlineAsmStub();
void CreateChecksumHealingStub();
void NtdllAsmStub();
void RemoveNtdllChecksumChecks();
void DbgRemove();

struct ntdllDbgLocations {
	const char* functionName;
	void* addrLocation;
	uint8_t patchedByArxanBuffer[14];
};

struct checksumHealingLocation
{
	hook::pattern checksumPattern;
	size_t length;
};
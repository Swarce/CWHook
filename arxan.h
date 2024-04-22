#pragma once
#include <stdint.h>

int fixChecksum(uint64_t rbpOffset, uint64_t ptrOffset, uint64_t* ptrStack, uint32_t jmpInstructionDistance, uint32_t calculatedChecksumFromArg);
void createInlineAsmStub();
void nopChecksumFixingMemcpy();
#pragma once
#include <stdint.h>

int fixChecksum(uint64_t rbpOffset, uint64_t ptrOffset, uint64_t* ptrStack, uint32_t jmpInstructionDistance, uint32_t calculatedChecksumFromArg);
void createInlineAsmStub();
void nopChecksumFixingMemcpy();
void nopChecksumFixingMemcpy2();
void nopChecksumFixingMemcpy3();
void nopChecksumFixingMemcpy4();
void nopChecksumFixingMemcpy5();
void nopChecksumFixingMemcpy6();
void nopChecksumFixingMemcpy7();
void nopChecksumFixingMemcpy8();
void nopChecksumFixingMemcpy9();
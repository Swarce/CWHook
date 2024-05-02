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
#include <vector>
#include <intrin.h>
#include <string>
#include <string_view>
#include <iostream>
#include <filesystem>

#include <asmjit/core/jitruntime.h>
#include <asmjit/x86/x86assembler.h>

#include "libs/patterns/Hooking.Patterns.h"
#include "libs/minhook/include/MinHook.h"
#include "gamestructs.h"
#include "winstructs.h"
#include "restorentdll.h"
#include "utils.h"
#include "systemhooks.h"
#include "arxan.h"

std::vector<intactChecksumHook> intactchecksumHooks;
std::vector<intactBigChecksumHook> intactBigchecksumHooks;
std::vector<splitChecksumHook> splitchecksumHooks;

inlineAsmStub* inlineStubs = nullptr;
size_t stubCounter = 0;

int fixChecksum(uint64_t rbpOffset, uint64_t ptrOffset, uint64_t* ptrStack, uint32_t jmpInstructionDistance, uint32_t calculatedChecksumFromArg)
{
	// get size of image from codcw
	uint64_t baseAddressStart = (uint64_t)GetModuleHandle(nullptr);
	IMAGE_DOS_HEADER* pDOSHeader = (IMAGE_DOS_HEADER*)GetModuleHandle(nullptr);
	IMAGE_NT_HEADERS* pNTHeaders =(IMAGE_NT_HEADERS*)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
	auto sizeOfImage = pNTHeaders->OptionalHeader.SizeOfImage;
	uint64_t baseAddressEnd = baseAddressStart + sizeOfImage;

	// fix checksums here, else thread true memcpy attempt
	// seems like its working but eventually dies because arxan at some fixes the checksums and checksums in general dont get called so much
	// it does make the game run almost every time now
	{
		for (int i=0; i < intactchecksumHooks.size(); i++)
		{
			DWORD old_protect{};

			if (memcmp(intactchecksumHooks[i].functionAddress, intactchecksumHooks[i].buffer, sizeof(uint8_t) * 7))
			{
				uint64_t idaAddress = (uint64_t)intactchecksumHooks[i].functionAddress - baseAddressStart + StartOfBinary;

				printf("%llx got changed\n", idaAddress);
				fprintf(logFile, "%llx got changed\n", idaAddress);
				fflush(logFile);
			}

			VirtualProtect(intactchecksumHooks[i].functionAddress, sizeof(uint8_t) * 7, PAGE_EXECUTE_READWRITE, &old_protect);
			memcpy(intactchecksumHooks[i].functionAddress, intactchecksumHooks[i].buffer, sizeof(uint8_t) * 7);
			VirtualProtect(intactchecksumHooks[i].functionAddress, sizeof(uint8_t) * 7, old_protect, &old_protect);
			FlushInstructionCache(GetCurrentProcess(), intactchecksumHooks[i].functionAddress, sizeof(uint8_t) * 7);
		}

		for (int i=0; i < intactBigchecksumHooks.size(); i++)
		{
			DWORD old_protect{};

			if (memcmp(intactBigchecksumHooks[i].functionAddress, intactBigchecksumHooks[i].buffer, sizeof(uint8_t) * 7))
			{
				uint64_t idaAddress = (uint64_t)intactBigchecksumHooks[i].functionAddress - baseAddressStart + StartOfBinary;

				printf("%llx got changed\n", idaAddress);
				fprintf(logFile, "%llx got changed\n", idaAddress);
				fflush(logFile);
			}
			
			VirtualProtect(intactBigchecksumHooks[i].functionAddress, sizeof(uint8_t) * 10, PAGE_EXECUTE_READWRITE, &old_protect);
			memcpy(intactBigchecksumHooks[i].functionAddress, intactBigchecksumHooks[i].buffer, sizeof(uint8_t) * 10);
			VirtualProtect(intactBigchecksumHooks[i].functionAddress, sizeof(uint8_t) * 10, old_protect, &old_protect);
			FlushInstructionCache(GetCurrentProcess(), intactBigchecksumHooks[i].functionAddress, sizeof(uint8_t) * 10);
		}

		for (int i=0; i < splitchecksumHooks.size(); i++)
		{
			DWORD old_protect{};

			if (memcmp(splitchecksumHooks[i].functionAddress, splitchecksumHooks[i].buffer, sizeof(uint8_t) * 7))
			{
				uint64_t idaAddress = (uint64_t)splitchecksumHooks[i].functionAddress - baseAddressStart + StartOfBinary;

				printf("%llx got changed\n", idaAddress);
				fprintf(logFile, "%llx got changed\n", idaAddress);
				fflush(logFile);
			}
			
			VirtualProtect(splitchecksumHooks[i].functionAddress, sizeof(uint8_t) * 8, PAGE_EXECUTE_READWRITE, &old_protect);
			memcpy(splitchecksumHooks[i].functionAddress, splitchecksumHooks[i].buffer, sizeof(uint8_t) * 8);
			VirtualProtect(splitchecksumHooks[i].functionAddress, sizeof(uint8_t) * 8, old_protect, &old_protect);
			FlushInstructionCache(GetCurrentProcess(), splitchecksumHooks[i].functionAddress, sizeof(uint8_t) * 8);
		}
	}

	static int fixChecksumCalls = 0;
	fixChecksumCalls++;

	//printf("rbp %llx, ptr %llx, stack %llx, distance %x, calculatedChecksum %x\n", rbpOffset, ptrOffset, ptrStack, jmpInstructionDistance, calculatedChecksumFromArg);
	//printf("rbp %llx, ptr %llx, stack %llx, distance %x, calculatedChecksum %x, fixChecksumCalls %d\n", rbpOffset, ptrOffset, ptrStack, jmpInstructionDistance, calculatedChecksumFromArg, fixChecksumCalls);
	//fprintf(logFile, "rbp %llx, ptr %llx, stack %llx, distance %x, calculatedChecksum %x, fixChecksumCalls %d\n", rbpOffset, ptrOffset, ptrStack, jmpInstructionDistance, calculatedChecksumFromArg, fixChecksumCalls);
	//fflush(logFile);

	uint32_t calculatedChecksum = calculatedChecksumFromArg;
	uint32_t reversedChecksum = reverse_bytes(calculatedChecksumFromArg);
	uint32_t* calculatedChecksumPtr = (uint32_t*)((char*)ptrStack+0x120); // 0x120 is a good starting point to decrement downwards to find the calculated checksum on the stack
	uint32_t* calculatedReversedChecksumPtr = (uint32_t*)((char*)ptrStack+0x120); // 0x120 is a good starting point to decrement downwards to find the calculated checksum on the stack

	bool doubleTextChecksum = false;
	uint64_t* previousResultPtr = nullptr;
	if (ptrOffset == 0 && rbpOffset < 0x90)
	{
		uint64_t* textPtr = (uint64_t*)((char*)ptrStack+rbpOffset + (rbpOffset % 0x8)); // make sure rbpOffset is aligned by 8 bytes
		int pointerCounter = 0;

		for (int i=0; i < 20; i++)
		{
			uint64_t derefPtr = *(uint64_t*)textPtr;

			if (derefPtr >= baseAddressStart && derefPtr <= baseAddressEnd)
			{
				uint64_t derefResult = **(uint64_t**)textPtr;
				pointerCounter++;

				//printf("result: %llx\n", derefResult);
				//fprintf(logFile, "result: %llx\n", derefResult);
				//fflush(logFile);

				// store the ptr above 0xffffffffffffffff and then use it in our originalchecksum check
				if (derefResult == 0xffffffffffffffff)
				{
					if (pointerCounter > 2)
					{
						//SuspendAllThreads();
						//__debugbreak();

						doubleTextChecksum = true;

						//printf("found double pointer text section\n", derefResult);
						//fprintf(logFile, "found double pointer text section\n", derefResult);
						//fflush(logFile);

						// because textptr will be pointing at 0xffffffffffffffff, increment it once 
						// so we are pointing to the correct checksum location

						// TODO: remove this, doesnt do anything, confirm with checksum 0x79d397c8
						// since we use previousResultPtr which doesnt rely on this
						textPtr++;
					}

					break;
				}

				previousResultPtr = textPtr;
			}

			textPtr--;
		}
	}
	else
	{	// for debugging stack traces on bigger rbp offset checksums
		uint64_t* textPtr = (uint64_t*)((char*)ptrStack+rbpOffset + (rbpOffset % 0x8)); // make sure rbpOffset is aligned by 8 bytes

		for (int i=0; i < 30; i++)
		{
			uint64_t derefPtr = *(uint64_t*)textPtr;

			if (derefPtr >= baseAddressStart && derefPtr <= baseAddressEnd)
			{
				uint64_t derefResult = **(uint64_t**)textPtr;

				//printf("result: %llx\n", derefResult);
				//fprintf(logFile, "result: %llx\n", derefResult);
				//fflush(logFile);
			}

			textPtr--;
		}
	}

	// find calculatedChecksumPtr, we will overwrite this later with the original checksum
	for (int i=0; i < 80; i++)
	{
		uint32_t derefPtr = *(uint32_t*)calculatedChecksumPtr;

		if (derefPtr == calculatedChecksum)
		{
			//printf("found calculatedChecksum on stack %llx\n", calculatedChecksumPtr);
			//fprintf(logFile, "found calculatedChecksum on stack %llx\n", calculatedChecksumPtr);
			//fflush(logFile);
			break;
		}

		calculatedChecksumPtr--;
	}

	// find calculatedReversedChecksumPtr, we will overwrite this later with the original checksum
	for (int i=0; i < 80; i++)
	{
		uint32_t derefPtr = *(uint32_t*)calculatedReversedChecksumPtr;

		if (derefPtr == reversedChecksum)
		{
			//printf("found reversedChecksum on stack %llx\n", calculatedChecksumPtr);
			//fprintf(logFile, "found reversedChecksum on stack %llx\n", calculatedReversedChecksumPtr);
			//fflush(logFile);
			break;
		}

		calculatedReversedChecksumPtr--;
	}

	uint64_t* textPtr = (uint64_t*)((char*)ptrStack+rbpOffset + (rbpOffset % 0x8)); // add remainder to align ptr
	uint32_t originalChecksum = NULL;
	uint32_t* originalChecksumPtr = nullptr;

	// searching for a .text pointer that points to the original checksum, upwards from the rbp	
	for (int i=0; i < 10; i++)
	{
		uint64_t derefPtr = *(uint64_t*)textPtr;

		if (derefPtr >= baseAddressStart && derefPtr <= baseAddressEnd)
		{
			//printf("found potential checksum location: %llx\n", derefPtr);
			//fprintf(logFile, "found potential checksum location: %llx\n", derefPtr);
			//fflush(logFile);

			if (ptrOffset == 0 && rbpOffset < 0x90)
			{
				if (doubleTextChecksum)
					originalChecksum = **(uint32_t**)previousResultPtr; 
				else
					originalChecksum = *(uint32_t*)derefPtr; 
			}
			else
			{
				originalChecksum = *(uint32_t*)((char*)derefPtr+ptrOffset*4); // if ptrOffset is used the original checksum is in a different spot
				originalChecksumPtr = (uint32_t*)((char*)derefPtr+ptrOffset*4);
			}
			
			break;
		}

		textPtr--;
	}

	*calculatedChecksumPtr = (uint32_t)originalChecksum;
	*calculatedReversedChecksumPtr = reverse_bytes((uint32_t)originalChecksum);

	// for big intact we need to keep overwriting 4 more times
	// seems to still run even if we comment this out wtf?
	uint32_t* tmpOriginalChecksumPtr = originalChecksumPtr;
	uint32_t* tmpCalculatedChecksumPtr = calculatedChecksumPtr;
	uint32_t* tmpReversedChecksumPtr = calculatedReversedChecksumPtr;
	if (originalChecksumPtr != nullptr)
	{
		for (int i=0; i <= ptrOffset; i++)
		{
			*tmpCalculatedChecksumPtr = *(uint32_t*)tmpOriginalChecksumPtr;
			*tmpReversedChecksumPtr = reverse_bytes(*(uint32_t*)tmpOriginalChecksumPtr);

			tmpOriginalChecksumPtr--;
			tmpCalculatedChecksumPtr--;
			tmpReversedChecksumPtr--;
		}
	}
	
	//fprintf(logFile, "originalChecksum: %llx\n\n", originalChecksum);
	//fflush(logFile);
	return originalChecksum;
}

void createInlineAsmStub()
{
	hook::pattern locationsIntact = hook::module_pattern(GetModuleHandle(nullptr), "89 04 8A 83 45 ? FF");
	hook::pattern locationsIntactBig = hook::module_pattern(GetModuleHandle(nullptr), "89 04 8A 83 85");
	hook::pattern locationsSplit = hook::module_pattern(GetModuleHandle(nullptr), "89 04 8A E9");
	size_t intactCount = locationsIntact.size();
	size_t intactBigCount = locationsIntactBig.size();
	size_t splitCount = locationsSplit.size();
	size_t totalCount = intactCount + intactBigCount + splitCount;

	const size_t allocationSize = sizeof(uint8_t) * 128;
	inlineStubs = (inlineAsmStub*)malloc(sizeof(inlineAsmStub) * totalCount);

	for (int i=0; i < intactCount; i++)
	{
		inlineStubs[stubCounter].functionAddress = locationsIntact.get(i).get<void*>(0);
		inlineStubs[stubCounter].type = intactSmall;
		inlineStubs[stubCounter].bufferSize = 7;
		stubCounter++;
	}

	for (int i=0; i < intactBigCount; i++)
	{
		inlineStubs[stubCounter].functionAddress = locationsIntactBig.get(i).get<void*>(0);
		inlineStubs[stubCounter].type = intactBig;
		inlineStubs[stubCounter].bufferSize = 10;
		stubCounter++;
	}

	for (int i=0; i < splitCount; i++)
	{
		inlineStubs[stubCounter].functionAddress = locationsSplit.get(i).get<void*>(0);
		inlineStubs[stubCounter].type = split;
		inlineStubs[stubCounter].bufferSize = 8;
		stubCounter++;
	}

	for (int i=0; i < stubCounter; i++)
	{
		LPVOID asmStubLocation = allocate_somewhere_near(GetModuleHandle(nullptr), allocationSize);
		memset(asmStubLocation, 0x90, allocationSize);
		void* functionAddress = inlineStubs[i].functionAddress;

		uint64_t jmpDistance = (uint64_t)asmStubLocation - (uint64_t)functionAddress - 5; // 5 bytes from relative call instruction

		// backup instructions that will get destroyed
		const int length = sizeof(uint8_t) * 8;
		uint8_t instructionBuffer[8] = {};
		memcpy(instructionBuffer, functionAddress, length);

		uint32_t instructionBufferJmpDistance = 0;
		if (instructionBuffer[3] == 0xE9)
			memcpy(&instructionBufferJmpDistance, (char*)functionAddress+0x4, 4); // 0x4 so we skip 0xE9

		uint64_t rbpOffset = 0x0;
		bool jumpDistanceNegative = instructionBufferJmpDistance >> 31; // get sign bit from jump distance
		int32_t jumpDistance = instructionBufferJmpDistance;
		
		if (inlineStubs[i].type == split)
		{
			// TODO: receive the rbpOffset by going through the jmp instruction
			// on big rbp offsets we could do the same hack we did on big intact where we do rbpOffset+0x100 if its below 0x60
			char* rbpOffsetPtr = nullptr;

			// TODO: just use jumpDistance once we got a working test case
			if (jumpDistanceNegative)
				rbpOffsetPtr = (char*)((uint64_t)functionAddress+jumpDistance+0x8);
			else
				rbpOffsetPtr = (char*)((uint64_t)functionAddress+instructionBufferJmpDistance+0x8);

			rbpOffsetPtr++;

			// depending on the rbp offset from add dword ptr we need one more byte for the rbpOffset
			if (*(unsigned char*)rbpOffsetPtr == 0x45) 		// add dword ptr [rbp+68],-01
			{
				rbpOffsetPtr++;
				rbpOffset = *(char*)rbpOffsetPtr;
			}
			else if (*(unsigned char*)rbpOffsetPtr == 0x85)	// add dword ptr [rbp+1CC],-01
			{
				rbpOffsetPtr++;
				rbpOffset = *(short*)rbpOffsetPtr;
			}
		}

		// create assembly stub content
		// TODO: we could create three different asmjit build sections for each type
		// so we don't have if statements inbetween instructions for the cost of LOC but it would be more readible
		static asmjit::JitRuntime runtime;
		asmjit::CodeHolder code;
		code.init(runtime.environment());
		asmjit::x86::Assembler a(&code);

		if (inlineStubs[i].type != split)
			rbpOffset = instructionBuffer[5];

		a.sub(asmjit::x86::rsp, 0x32);
		pushad64();

		a.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x20), asmjit::x86::rax);
		a.mov(asmjit::x86::rdx, asmjit::x86::rcx);	// offset within text section pointer (ecx*4)
		
		// we dont use rbpoffset since we only get 1 byte from the 2 byte offset (rbpOffset)
		// 0x130 is a good starting ptr to decrement downwards so we can find the original checksum
		if (inlineStubs[i].type == intactBig)
			a.mov(asmjit::x86::rcx, 0x120); 	
		else
			a.mov(asmjit::x86::rcx, rbpOffset);

		a.mov(asmjit::x86::r8, asmjit::x86::rbp);

		if (inlineStubs[i].type == split)
		{
			if (jumpDistanceNegative)
				a.mov(asmjit::x86::r9, jumpDistance);
			else
				a.mov(asmjit::x86::r9, instructionBufferJmpDistance);
		}
		else
			a.mov(asmjit::x86::r9, instructionBufferJmpDistance);	// incase we mess up a split checksum

		a.mov(asmjit::x86::rax, (uint64_t)(void*)fixChecksum);
		a.call(asmjit::x86::rax);
		a.add(asmjit::x86::rsp, 0x8*4); // so that r12-r15 registers dont get corrupt

		popad64WithoutRAX();
		a.add(asmjit::x86::rsp, 0x32);

		a.mov(ptr(asmjit::x86::rdx, asmjit::x86::rcx, 2), asmjit::x86::eax); // mov [rdx+rcx*4], eax

		if (instructionBufferJmpDistance == 0)
		{
			if (inlineStubs[i].type == intactBig)
				rbpOffset += 0x100;

			a.add(dword_ptr(asmjit::x86::rbp, rbpOffset), -1); // add dword ptr [rbp+rbpOffset], 0FFFFFFFFh
		}
		else
		{
			// jmp loc_7FF641C707A5
			// push the desired address on to the stack and then perform a 64 bit RET
			a.add(asmjit::x86::rsp, 0x8); // pop return address off the stack cause we will jump
			uint64_t addressToJump = (uint64_t)functionAddress + instructionBufferJmpDistance;
			
			if (inlineStubs[i].type == split)
			{
				// TODO: just use jumpDistance once we got a working test case
				if (jumpDistanceNegative)
					addressToJump = (uint64_t)functionAddress + jumpDistance + 0x8; // 0x8 call instruction + offset + 2 nops
				else
					addressToJump = (uint64_t)functionAddress + instructionBufferJmpDistance + 0x8; // 0x8 call instruction + offset + 2 nops
			}

			a.mov(asmjit::x86::r11, addressToJump);	// r11 is being used but should be fine based on documentation
			
			if (inlineStubs[i].type == split)
				a.add(asmjit::x86::rsp, 0x8); // since we dont pop off rax we need to sub 0x8 the rsp

			a.push(asmjit::x86::r11);
		}

		if (inlineStubs[i].type != split)
			a.add(asmjit::x86::rsp, 0x8); // since we dont pop off rax we need to sub 0x8 the rsp

		a.ret();

		void* asmjitResult = nullptr;
		runtime.add(&asmjitResult, &code);

		// copy over the content to the stub
		uint8_t* tempBuffer = (uint8_t*)malloc(sizeof(uint8_t) * code.codeSize());
		memcpy(tempBuffer, asmjitResult, code.codeSize());
		memcpy(asmStubLocation, tempBuffer, sizeof(uint8_t) * code.codeSize());

		const int callInstructionBytes = inlineStubs[i].bufferSize;
		const int callInstructionLength = sizeof(uint8_t) * callInstructionBytes;

		DWORD old_protect{};
		VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);
		memset(functionAddress, 0, callInstructionLength);
		VirtualProtect(functionAddress, callInstructionLength, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), functionAddress, callInstructionLength);

		// E8 cd CALL rel32  Call near, relative, displacement relative to next instruction
		uint8_t* jmpInstructionBuffer = (uint8_t*)malloc(sizeof(uint8_t) * callInstructionBytes);
		jmpInstructionBuffer[0] = 0xE8;
		jmpInstructionBuffer[1] = (jmpDistance >> (0 * 8));
		jmpInstructionBuffer[2] = (jmpDistance >> (1 * 8));
		jmpInstructionBuffer[3] = (jmpDistance >> (2 * 8));
		jmpInstructionBuffer[4] = (jmpDistance >> (3 * 8));
		jmpInstructionBuffer[5] = 0x90;
		jmpInstructionBuffer[6] = 0x90;

		if (inlineStubs[i].type == intactBig)
		{
			jmpInstructionBuffer[7] = 0x90;
			jmpInstructionBuffer[8] = 0x90;
			jmpInstructionBuffer[9] = 0x90;
		}

		if (inlineStubs[i].type == split)
			jmpInstructionBuffer[7] = 0x90;

		VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);
		memcpy(functionAddress, jmpInstructionBuffer, callInstructionLength);
		VirtualProtect(functionAddress, callInstructionLength, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), functionAddress, callInstructionLength);

		// store location & bytes to check if arxan is removing our hooks
		if (inlineStubs[i].type == intactSmall)
		{
			intactChecksumHook intactChecksum;
			intactChecksum.functionAddress = (uint64_t*)functionAddress;
			memcpy(intactChecksum.buffer, jmpInstructionBuffer, sizeof(uint8_t) * inlineStubs[i].bufferSize);
			inlineStubs[i].buffer = intactChecksum.buffer;
			intactchecksumHooks.push_back(intactChecksum);
		}

		if (inlineStubs[i].type == intactBig)
		{
			intactBigChecksumHook intactBigChecksum;
			intactBigChecksum.functionAddress = (uint64_t*)functionAddress;
			memcpy(intactBigChecksum.buffer, jmpInstructionBuffer, sizeof(uint8_t) * inlineStubs[i].bufferSize);
			inlineStubs[i].buffer = intactBigChecksum.buffer;
			intactBigchecksumHooks.push_back(intactBigChecksum);
		}

		if (inlineStubs[i].type == split)
		{
			splitChecksumHook splitChecksum;
			splitChecksum.functionAddress = (uint64_t*)functionAddress;
			memcpy(splitChecksum.buffer, jmpInstructionBuffer, sizeof(uint8_t) * inlineStubs[i].bufferSize);
			inlineStubs[i].buffer = splitChecksum.buffer;
			splitchecksumHooks.push_back(splitChecksum);
		}
	}

	printf("p %d\n", intactCount);
	printf("p %d\n", intactBigCount);
	printf("p %d\n", splitCount);
}

bool arxanHealingChecksum(uint64_t rbp)
{
	//printf("checksum healing called\n");
	//SuspendAllThreads();
	//__debugbreak();

	// check if rbpAddressLocationPtr is within the range of 8 bytes up & down from every checksum that we placed.
	// if true then replace rbp+0x18 with rbp+0x10, this might not work if it does something more to rbp+0x18 afterwards
	// we could also do a quick register comparison so we don't do "mov [rdx], eax"
	uint64_t rbpAddressLocationPtr = *(uint64_t*)(rbp+0x10);

	for (int i=0; i < stubCounter; i++)
	{
		if (rbpAddressLocationPtr+0x8 >= (uint64_t)inlineStubs[i].functionAddress && rbpAddressLocationPtr-0x8 <= (uint64_t)inlineStubs[i].functionAddress)
		{
			printf("checksum fixer is trying to fix our inline function: %llx\n", (uint64_t)inlineStubs[i].functionAddress);
			//SuspendAllThreads();
			//while (true)
			//	Sleep(10);

			//__debugbreak();
			return true;
		}
	}

	return false;
}

// TODO: create another checksum stub generator for
// 48 8B 45 18 48 8B 55 10 8B 00 89 02 E9

void nopChecksumFixingMemcpy()
{
	hook::pattern checksumFixers = hook::module_pattern(GetModuleHandle(nullptr), "89 02 8B 45 20 83 C0 FC E9");
	size_t checksumFixersCount = checksumFixers.size();
	const size_t allocationSize = sizeof(uint8_t) * 128;

	//SuspendAllThreads();

	for (int i=0; i < checksumFixersCount; i++)
	{	
		LPVOID asmStubLocation = allocate_somewhere_near(GetModuleHandle(nullptr), allocationSize);
		memset(asmStubLocation, 0x90, allocationSize);
		void* functionAddress = checksumFixers.get(i).get<void*>(0);

		uint64_t jmpDistance = (uint64_t)asmStubLocation - (uint64_t)functionAddress - 5;

		// backup instructions that will get destroyed
		const int length = 8;
		uint8_t instructionBuffer[length] = {};
		memcpy(instructionBuffer, functionAddress, sizeof(uint8_t) * length);

		static asmjit::JitRuntime runtime;
		asmjit::CodeHolder code;
		code.init(runtime.environment());

		using namespace asmjit::x86;
		Assembler a(&code);

/*
	mov     rax, [rbp+18h]
	mov     rdx, [rbp+10h]
	jmp     loc_7FF631D8DD25
	mov     [rdx], eax
	mov     eax, [rbp+20h]
	add     eax, 0FFFFFFFCh
*/

		a.sub(rsp, 0x32);
		pushad64_Min();
		a.mov(rcx, rbp);
		a.mov(r15, (uint64_t)(void*)arxanHealingChecksum);
		a.call(r15);
		a.mov(r15, rax);	// if arxan tries to replace our checksum set r15 to 1

		popad64_Min();
		a.add(rsp, 0x32);

		asmjit::Label L1 = a.newLabel();
		a.cmp(r15, 1);
		a.je(L1);
		a.mov(qword_ptr(rdx), eax);	// dont replace our checksum if r15 is 1
		a.bind(L1);
		a.mov(eax, qword_ptr(rbp, 0x20));
		a.add(eax, -4);
		a.ret();


		void* asmjitResult = nullptr;
		runtime.add(&asmjitResult, &code);

		// copy over the content to the stub
		uint8_t* tempBuffer = (uint8_t*)malloc(sizeof(uint8_t) * code.codeSize());
		memcpy(tempBuffer, asmjitResult, code.codeSize());
		memcpy(asmStubLocation, tempBuffer, sizeof(uint8_t) * code.codeSize());

		const int callInstructionBytes = 8;
		const int callInstructionLength = sizeof(uint8_t) * callInstructionBytes;

		DWORD old_protect{};
		VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);
		memset(functionAddress, 0, callInstructionLength);
		VirtualProtect(functionAddress, callInstructionLength, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), functionAddress, callInstructionLength);

		// E8 cd CALL rel32  Call near, relative, displacement relative to next instruction
		uint8_t* jmpInstructionBuffer = (uint8_t*)malloc(sizeof(uint8_t) * callInstructionBytes);
		jmpInstructionBuffer[0] = 0xE8;
		jmpInstructionBuffer[1] = (jmpDistance >> (0 * 8));
		jmpInstructionBuffer[2] = (jmpDistance >> (1 * 8));
		jmpInstructionBuffer[3] = (jmpDistance >> (2 * 8));
		jmpInstructionBuffer[4] = (jmpDistance >> (3 * 8));
		jmpInstructionBuffer[5] = 0x90;
		jmpInstructionBuffer[6] = 0x90;
		jmpInstructionBuffer[7] = 0x90;

		VirtualProtect(functionAddress, callInstructionLength, PAGE_EXECUTE_READWRITE, &old_protect);
		memcpy(functionAddress, jmpInstructionBuffer, callInstructionLength);
		VirtualProtect(functionAddress, callInstructionLength, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), functionAddress, callInstructionLength);
	}
}
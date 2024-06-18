#pragma once
#define PHNT_VERSION PHNT_WIN10_22H2
#include <phnt_windows.h>
#include <phnt.h>
#include <ntexapi.h>
#include <ntpsapi.h>
#include <stdint.h>

#include <share.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <filesystem>

typedef enum _WINDOWINFOCLASS {
	WindowProcess,
	WindowThread,
	WindowActiveWindow,
	WindowFocusWindow,
	WindowIsHung,
	WindowClientBase,
	WindowIsForegroundThread,
#ifdef FE_IME
	WindowDefaultImeWindow,
	WindowDefaultInputContext,
#endif
} WINDOWINFOCLASS;

const extern WCHAR* BadProcessnameList[];
const extern WCHAR* BadWindowTextList[];
const extern WCHAR* BadWindowClassList[];

const uint64_t EndOfTextSection = 0xd75c000;
const uint64_t StartOfTextSection = 0x7FF71AA91000;
const uint64_t StartOfBinary = 0x7FF71AA90000;

extern FILE* logFile;

// temporary fix until we nop out all the arxan "self healing" spots in the executable
struct intactChecksumHook
{
	uint64_t* functionAddress;
	uint8_t buffer[7];
};

struct intactBigChecksumHook
{
	uint64_t* functionAddress;
	uint8_t buffer[7+3];
};

struct splitChecksumHook
{
	uint64_t* functionAddress;
	uint8_t buffer[8];
};

enum checksumType {
	intactSmall,
	intactBig,
	split
};

struct inlineAsmStub {
	void* functionAddress;
	uint8_t* buffer;
	size_t bufferSize;
	checksumType type;
};

bool RtlUnicodeStringContains(PUNICODE_STRING Str, PUNICODE_STRING SubStr, BOOLEAN CaseInsensitive);
bool IsWindowClassNameBad(PUNICODE_STRING className);
bool IsWindowNameBad(PUNICODE_STRING windowName);
bool IsWindowBad(HWND hWnd);
void FilterHwndList(HWND* phwndFirst, PULONG pcHwndNeeded);
std::string GetLastErrorAsString();

inline void SetBits(unsigned long& dw, int lowBit, int bits, int newValue)
{
	int mask = (1 << bits) - 1; // e.g. 1 becomes 0001, 2 becomes 0011, 3 becomes 0111

	dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
}

bool remove_evil_keywords_from_string(const UNICODE_STRING& string);
FILE* fmemopen(void* buf, size_t len, const char* type);
bool is_relatively_far(const void* pointer, const void* data);
uint8_t* allocate_somewhere_near(const void* base_address, const size_t size);
uint32_t reverse_bytes(uint32_t bytes);

#define pushad64() a.push(asmjit::x86::rax); 	\
				a.push(asmjit::x86::rcx); 	\
				a.push(asmjit::x86::rdx);	\
				a.push(asmjit::x86::rbx);	\
				a.push(asmjit::x86::rsp);	\
				a.push(asmjit::x86::rbp);	\
				a.push(asmjit::x86::rsi);	\
				a.push(asmjit::x86::rdi);	\
				a.push(asmjit::x86::r8);	\
				a.push(asmjit::x86::r9);	\
				a.push(asmjit::x86::r10);	\
				a.push(asmjit::x86::r11);	\
				a.push(asmjit::x86::r12);	\
				a.push(asmjit::x86::r13);	\
				a.push(asmjit::x86::r14);	\
				a.push(asmjit::x86::r15);


#define popad64() a.pop(asmjit::x86::r15); 	\
				a.pop(asmjit::x86::r14);	\
				a.pop(asmjit::x86::r13);	\
				a.pop(asmjit::x86::r12);	\
				a.pop(asmjit::x86::r11);	\
				a.pop(asmjit::x86::r10);	\
				a.pop(asmjit::x86::r9);		\
				a.pop(asmjit::x86::r8);		\
				a.pop(asmjit::x86::rdi);	\
				a.pop(asmjit::x86::rsi);	\
				a.pop(asmjit::x86::rbp);	\
				a.pop(asmjit::x86::rsp);	\
				a.pop(asmjit::x86::rbx);	\
				a.pop(asmjit::x86::rdx);	\
				a.pop(asmjit::x86::rcx);	\
				a.pop(asmjit::x86::rax);

#define popad64WithoutRAX() a.pop(asmjit::x86::r11);	\
				a.pop(asmjit::x86::r10);	\
				a.pop(asmjit::x86::r9);		\
				a.pop(asmjit::x86::r8);		\
				a.pop(asmjit::x86::rdi);	\
				a.pop(asmjit::x86::rsi);	\
				a.pop(asmjit::x86::rbp);	\
				a.pop(asmjit::x86::rsp);	\
				a.pop(asmjit::x86::rbx);	\
				a.pop(asmjit::x86::rdx);	\
				a.pop(asmjit::x86::rcx);

// TODO: if we remove any of the r15 14 13 registers on the popad64 macro it crashes the game
// think we messed up the stack or something on the checksum stub generation
// fix it later, for now use these so we can actually use the r12-r15 registers since those are non violatile
#define pushad64_Min() a.push(asmjit::x86::rax); 	\
				a.push(asmjit::x86::rcx); 	\
				a.push(asmjit::x86::rdx);	\
				a.push(asmjit::x86::rbx);	\
				a.push(asmjit::x86::rsp);	\
				a.push(asmjit::x86::rbp);	\
				a.push(asmjit::x86::rsi);	\
				a.push(asmjit::x86::rdi);	\
				a.push(asmjit::x86::r8);	\
				a.push(asmjit::x86::r9);	\
				a.push(asmjit::x86::r10);	\
				a.push(asmjit::x86::r11);


#define popad64_Min() a.pop(asmjit::x86::r11);	\
				a.pop(asmjit::x86::r10);	\
				a.pop(asmjit::x86::r9);		\
				a.pop(asmjit::x86::r8);		\
				a.pop(asmjit::x86::rdi);	\
				a.pop(asmjit::x86::rsi);	\
				a.pop(asmjit::x86::rbp);	\
				a.pop(asmjit::x86::rsp);	\
				a.pop(asmjit::x86::rbx);	\
				a.pop(asmjit::x86::rdx);	\
				a.pop(asmjit::x86::rcx);	\
				a.pop(asmjit::x86::rax);


/*
#define pushad64() a.push(asmjit::x86::rax); 	\
				a.push(asmjit::x86::rcx); 	\
				a.push(asmjit::x86::rdx);	\
				a.push(asmjit::x86::rbx);	\
				a.push(asmjit::x86::rsp);	\
				a.push(asmjit::x86::rbp);	\
				a.push(asmjit::x86::rsi);	\
				a.push(asmjit::x86::rdi);	\
				a.push(asmjit::x86::r8);	\
				a.push(asmjit::x86::r9);	\
				a.push(asmjit::x86::r10);	\
				a.push(asmjit::x86::r11);	\
				a.push(asmjit::x86::r12);	\
				a.push(asmjit::x86::r13);	\
				a.push(asmjit::x86::r14);	\
				a.push(asmjit::x86::r15);


#define popad64() a.pop(asmjit::x86::r15); 	\
				a.pop(asmjit::x86::r14);	\
				a.pop(asmjit::x86::r13);	\
				a.pop(asmjit::x86::r12);	\
				a.pop(asmjit::x86::r11);	\
				a.pop(asmjit::x86::r10);	\
				a.pop(asmjit::x86::r9);		\
				a.pop(asmjit::x86::r8);		\
				a.pop(asmjit::x86::rdi);	\
				a.pop(asmjit::x86::rsi);	\
				a.pop(asmjit::x86::rbp);	\
				a.pop(asmjit::x86::rsp);	\
				a.pop(asmjit::x86::rbx);	\
				a.pop(asmjit::x86::rdx);	\
				a.pop(asmjit::x86::rcx);	\
				a.pop(asmjit::x86::rax);

#define popad64WithoutRAX() a.pop(asmjit::x86::r15); 	\
				a.pop(asmjit::x86::r14);	\
				a.pop(asmjit::x86::r13);	\
				a.pop(asmjit::x86::r12);	\
				a.pop(asmjit::x86::r11);	\
				a.pop(asmjit::x86::r10);	\
				a.pop(asmjit::x86::r9);		\
				a.pop(asmjit::x86::r8);		\
				a.pop(asmjit::x86::rdi);	\
				a.pop(asmjit::x86::rsi);	\
				a.pop(asmjit::x86::rbp);	\
				a.pop(asmjit::x86::rsp);	\
				a.pop(asmjit::x86::rbx);	\
				a.pop(asmjit::x86::rdx);	\
				a.pop(asmjit::x86::rcx);
*/
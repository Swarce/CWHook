#pragma once

// winver 21H1 (19043.1348)
#if 0
#define SetInformationSysCall 0xd
#define CreateThreadSysCall 0x4e
#define QueryInformationSysCall 0x25
#define CreateThreadExSysCall 0xc1
#define QueryInformationProcessSysCall 0x19
#define QuerySystemInformationSysCall 0x36
#define CreateFileSysCall 0x55
#endif

// winver 22H2 (19045.3693)
#if 0
#define SetInformationSysCall 0xd
#define CreateThreadSysCall 0x4e
#define QueryInformationSysCall 0x25
#define CreateThreadExSysCall 0xc2
#define QueryInformationProcessSysCall 0x19
#define QuerySystemInformationSysCall 0x36
#define CreateFileSysCall 0x55
#define AllocateVirtualMemorySysCall 0x18
#endif


// TODO: get the ntdll syscall number with procaddress ntdll + offset so we dont have to manually save them
void SetSyscallsFromNtdll();

extern uint64_t SetInformationSysCall;
extern uint64_t CreateThreadSysCall;
extern uint64_t QueryInformationSysCall;
extern uint64_t CreateThreadExSysCall;
extern uint64_t QueryInformationProcessSysCall;
extern uint64_t QuerySystemInformationSysCall;
extern uint64_t CreateFileSysCall;
extern uint64_t AllocateVirtualMemorySysCall;
extern uint64_t ProtectVirtualMemorySysCall;
extern uint64_t NtQueryObjectSysCall;
extern uint64_t NtCreateDebugObjectSysCall;

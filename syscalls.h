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
#define SetInformationSysCall 0xd
#define CreateThreadSysCall 0x4e
#define QueryInformationSysCall 0x25
#define CreateThreadExSysCall 0xc2
#define QueryInformationProcessSysCall 0x19
#define QuerySystemInformationSysCall 0x36
#define CreateFileSysCall 0x55
#define AllocateVirtualMemorySysCall 0x18
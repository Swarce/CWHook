#define PHNT_VERSION PHNT_WIN10_22H2
#include <phnt_windows.h>
#include <phnt.h>
#include <ntexapi.h>
#include <ntpsapi.h>
#include <minidumpapiset.h>

#include <asmjit/core/jitruntime.h>
#include <asmjit/x86/x86assembler.h>

#include <stdio.h>
#include <cstdint>

#include "instrumentationCallbacks.h"
#include "arxan.h"
#include "systemhooks.h"

DWORD tls_index;

extern "C" void InstrumentationCallbackThunk(void);
extern "C" void callbackFunc(PCONTEXT Context);

#define InstrumentationCallbackPreviousPc	0x2d8
#define InstrumentationCallbackPreviousSp	0x2e0

uint64_t ntdllStartLocation = 0;
uint64_t ntdllEndLocation = 0;

uint64_t win32uStartLocation = 0;
uint64_t win32uEndLocation = 0;

uint64_t arxanStubStartLocation = 0;
uint64_t arxanStubEndLocation = 0;

uint64_t baseAddrStart = 0;
uint64_t baseAddrEnd = 0;

bool* get_thread_data_pointer() {
    void* thread_data = nullptr;
    bool* data_pointer = nullptr;

    thread_data = TlsGetValue(tls_index);

    if (thread_data == nullptr) {
        thread_data = reinterpret_cast<void*>(LocalAlloc(LPTR, 256));

        if (thread_data == nullptr) {
            return nullptr;
        }

        RtlZeroMemory(thread_data, 256);


        if (!TlsSetValue(tls_index, thread_data)) {
            return nullptr;
        }
    }
}

bool set_thread_handling_syscall(bool value) {
    if (auto data_pointer = get_thread_data_pointer()) {
        *data_pointer = value;
        return true;
    }

    return false;
}

bool is_thread_handling_syscall() {
    if (auto data_pointer = get_thread_data_pointer()) {
        if ((uint64_t)data_pointer != 0x1)
            return *data_pointer;

        bool test = data_pointer;
        return test;
    }

    return false;
}

void callbackFunc(CONTEXT* ctx) {
    auto teb = reinterpret_cast<uint64_t>(NtCurrentTeb());
    ctx->Rip = *reinterpret_cast<uint64_t*>(teb + 0x02d8);
    ctx->Rsp = *reinterpret_cast<uint64_t*>(teb + 0x02e0);
    ctx->Rcx = ctx->R10;

    if (is_thread_handling_syscall()) {
        RtlRestoreContext(ctx, nullptr);
    }

    if (!set_thread_handling_syscall(true)) {
        RtlRestoreContext(ctx, nullptr);
    }

    auto return_address = reinterpret_cast<void*>(ctx->Rip);
    auto return_value = reinterpret_cast<void*>(ctx->Rax);
    uint64_t offset_into_function;

    bool base_b = (ctx->Rip > baseAddrStart && ctx->Rip < baseAddrEnd);
    bool arxanStub_b = (ctx->Rip > arxanStubStartLocation && ctx->Rip < arxanStubEndLocation);
    bool ntdll_b = (ctx->Rip > ntdllStartLocation && ctx->Rip < ntdllEndLocation);
    bool win32u_b = (ctx->Rip > win32uStartLocation && ctx->Rip < win32uEndLocation);

    if (!base_b && !arxanStub_b && !ntdll_b && !win32u_b)
        printf("syscall called from random location rip %llx\n", ctx->Rip);

    if (base_b)
    	printf("syscall called from base addr rip %llx\n", ctx->Rip);

    set_thread_handling_syscall(false);
    RtlRestoreContext(ctx, nullptr);
}

// if this ends up not helping us at all then i dont know what the issue is with the debugging
// shouldnt just ignore it and use cheat engines veh debugger for now and find the best time to install our checksum hooks
// fix the slow startup from virtualallocing, maybe clean up some source code and publish

uint64_t getEndOfSection(uint64_t baseAddrStart, const char* str)
{
	IMAGE_DOS_HEADER* pDOSHeader = (IMAGE_DOS_HEADER*)GetModuleHandle(str);
    IMAGE_NT_HEADERS* pNTHeaders = (IMAGE_NT_HEADERS*)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
    DWORD sizeOfImage = pNTHeaders->OptionalHeader.SizeOfImage;
    
    return baseAddrStart + sizeOfImage;
}

void initInstrumentation()
{
	printf("init instrumentation\n");

    arxanStubStartLocation = (uint64_t)ntdllAsmStubLocation;
    arxanStubEndLocation = arxanStubStartLocation + 0x1000;

    ntdllStartLocation = (uint64_t)GetModuleHandle("ntdll.dll");
    ntdllEndLocation = getEndOfSection(ntdllStartLocation, "ntdll.dll");

    win32uStartLocation = (uint64_t)GetModuleHandle("win32u.dll");
    win32uEndLocation = getEndOfSection(win32uStartLocation, "win32u.dll");
    
    baseAddrStart = (uint64_t)GetModuleHandle(nullptr);
    baseAddrEnd = getEndOfSection(baseAddrStart, nullptr);

	using asmjitFunc = void (*)();

	static asmjit::JitRuntime runtime;
	asmjit::CodeHolder code;
	code.init(runtime.environment());

	using namespace asmjit::x86;
	Assembler a(&code);

	// https://github.com/jackullrich/syscall-detect/blob/master/Thunk.asm
    Mem PreviousSp(0x2e0);
    PreviousSp.setSegment(asmjit::x86::gs);
    a.mov(PreviousSp, rsp);

    Mem PreviousPc(0x2d8);
    PreviousPc.setSegment(asmjit::x86::gs);
    a.mov(PreviousPc, r10);

    a.mov(r10, rcx);
    a.sub(rsp, 0x4d0);
    a.and_(rsp, -0x10);
    a.mov(rcx, rsp);

    a.call(RtlCaptureContext);
    a.sub(rsp, 0x20);
    a.call(callbackFunc);

    a.int3();

	asmjitFunc InstrumentationCallbackThunk;
	asmjit::Error err = runtime.add(&InstrumentationCallbackThunk, &code);

    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION Callback = { 0 };
    Callback.Version = 0;
    Callback.Reserved = 0;
    Callback.Callback = (PVOID)(ULONG_PTR)InstrumentationCallbackThunk;

    NTSTATUS result = NtSetInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)ProcessInstrumentationCallback, &Callback, sizeof(Callback));

    printf("done\n");
}
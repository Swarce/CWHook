#pragma once

/* anti debugging detection
Game uses its own veh's
Creates threads with hide from debugger flag, makes debugging impossible without using veh debugger from CE

Restore NTDLL Dbg functions
Calls CheckRemoteDebuggerPresent
Calls NtQueryInformationThread with ThreadHideFromDebugger
Calls NtSetInformationThread with ThreadHideFromDebugger
Calls NtCreateThreadEx with THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER

(old arxan build)
First call to NtAllocateVirtualMemory allocates a private allocated chunk.
Ntdll NtSetInformationThread and other functions get inserted into the chunk.
NtSetInformationThread gets called from the chunk to hide the main thread from debuggers.

Hooks KiUserApcDispatcher

Creates numerous exceptions to see if a debugger is attached
Sets peb->BeingDebugged to 0x8f, crashes the game if its not set to 0x8f
Debuggers that try to hide or don't will change BeingDebugged to 0x0 or 0x1
To be able to debug the game with visual studio you would need to modify it so it doesnt catch illegal instructions such as UD2
Arxan uses UD2 to check if a debugger is attached and will catch the exception with their VEH
Arxan detects being suspended and waking up from a breakpoint exception. 
Game usually runs for a while after a breakpoint was hit and resumed until it eventually closes itself

Cheat engine's debugger can breakpoint as well but usually ends up freezing cheat engine after too many breakpoint exceptions, VEH debugger works but will clear the 4th hwbp which is needed to bypass ntdll inline syscall arxan stuff.
Ida pro's windows debugger behaves the same way as x64dbg.
Windbg has trouble to break the application in general.

On startup & runtime will try to call NtClose with handle id's such as 0xfffffffffffffffc and 0x12345 (lol)
This will create an EXCEPTION_INVALID_HANDLE exception which arxan's VEH will intercept and detect that a debugger is attached 
Found this by creating a minimal debugger and seeing what exceptions were being caught
*/

/* anti dll injection
Reverse Kernel32ThreadInitThunkFunction function ptr being replaced
*/

/* detection methods
Calling RestoreNtdllDbgFunctions early will crash the game eventually because they check if the ntdll dbg functions got restored
    arxan will also hook ntdll debug functions and set kernel32 exitprocess to them
    will check for their checksum at runtime by getting the addr location of every dbg function
    then incrementing it and checking what the byte is

Checks for cheat engine & reclass at runtime, will close the game at around 2-5 minutes if found
*/

/* checksums
from bo3, intact & split checksums
big intact & big split checksums (rbp is bigger than 0x90)
intact & split checksums containing multiple .text pointers (last one is the correct one)
big intact and big split have those too but they dont point to the correct original checksum
*/

/* arxan self healing
arxan fixes inline stubs at runtime, examples at
7ff641fc00a3
7ff641f322bb
*/

/* arxan decrypts encrypted text section with a key that it xor's the text section with
48 BA ? ? ? ? ? ? ? ? E9

mov rdx, 0x7FA6B73DD1E72C56         // xor key gets put into rdx
mov rax,qword ptr ds:[rcx+rax+14]   // part of the encrypted text section gets put into rax
xor rax,rdx                         // text section (rax) gets decrypted with key by xor'ing
mov qword ptr ds:[rdx+rcx+14],rax   // replace part of the text section with the decrypted result
*/

/* arxan calling syscall from allocated chunks (08/30/23 Windows 7 is no longer supported?)
compares the content of the function with "81 ? 4C 8B D1 B8"
shifts the pointer 4 bytes forward so its only getting the syscall number

if ( STACK[0xAD0] && *STACK[0xAD0] == 0xB8D18B4C )
    LODWORD(STACK[0xC58]) = *(STACK[0xAD0] + 4);
else
    LODWORD(STACK[0xC58]) = 0;

*(&STACK[0x590] + SLODWORD(STACK[0x530])) = STACK[0xC58];

rax contains the address to the ntdll location from virtualalloc
0x6C505B    | mov eax, [rax + 0x4]

puts the syscall numbers in an array on the stack
0x1E37B152  | mov [rsp + rax * 4 + 0x588], ecx

// it does this for the NtQueryInformationThread syscall number too
gets the syscall number from the array on the stack
0x1CB7FF88  | mov eax, [rsp + rax + 0x588]  (NtSetInformationThread)

rdx contains a location in the game's memory
rcx is the offset
0x6C9FA4    | mov [rdx + rcx + 0xC], rax    (NtSetInformationThread)

gets the syscall number from the array on the stack
0x1CF38DC7  | mov eax, [rsp + rax + 0x588]  (NtSetInformationThread)

rdx contains a location in the game's memory
rcx is the offset
0x6CA374    | mov [rdx + rcx + 0xC], rax    (NtSetInformationThread)

gets the syscall number from the array on the stack
0x1E201F04  | mov eax, [rsp + rax + 0x588]  (NtSetInformationThread)

rdx contains a location in the game's memory
rcx is the offset
0x6CA72A    | mov [rdx + rcx + 0xC], rax    (NtSetInformationThread)


arxan on start up jmps to random ntdll function where syscall starts and jmps to it:
    it doesnt do this with win32u, gdi32, user32
        manually loads them but doesnt call anything from them????

    hook ntdll.dll, every exported function and check if syscall number is correct?
        bad for performance?
        what if syscall instruction gets inlined?
            syscall instruction never gets inlined

    use hwbp's to manually keep track of attempts of starting/settings threads as debugger hidden?

    ProcessInstrumentationCallback only tells you what rip location the syscall got called, the way they are calling ntdll syscalls wouldnt tell you what syscall got called. Need hypervisor or kernel driver with syscall hooks to know what syscall actually got called.

    arxan doesnt call syscalls from anywhere else, checked with ProcessInstrumentationCallback

    doesn't call readvirtualmemory to read process memory
*/

/*
    arxan calling windows exported functions without including them in the IAT

    at BlackOpsColdWar.exe+0xE426210
    saves address location from user32 and win32u functions
    will put them on the stack then call them from  BlackOpsColdWar.exe+0xC11DF3
                                                    BlackOpsColdWar.exe+0xB52235

    NtUserInternalGetWindowText
    NtUserGetWindowProcessHandle
    NtUserGetTopLevelWindow
    NtUserChildWindowFromPointEx
    NtUserInternalGetWindowIcon
    NtUserRealChildWindowFromPoint
    NtUserWOWFindWindow
    NtUserWindowFromDC
    NtUserWindowFromPhysicalPoint
    NtUserGetClassName

    GetWindowThreadProcessId
    EnumWindows
    GetClassNameA
    GetWindowTextA
    EnumChildWindows
    GetMenu
    GetMenuStringA
    GetSubMenu

    ZwOpenKey
    ZwQueryValueKey
*/

/*  
    not really related to arxan but minhook can be a cause for a dll unloading to crash
    since it doesnt handle when a call to suspendthread gives a "no access" error
    uncommenting out suspendthread resumethread will allow for the process to unload and load the module without crashing
*/

/*
    arxan modifies the LoadCount of the module that gets loaded into the game and sets it to -1 (0xFFFF)
    which only should happen if the module is build statically like most windows api modules such as ntdll/win32u since
    if those modules would get free'd (which shouldnt be possible) the program will crash

    this prevents an user to unload modules
*/
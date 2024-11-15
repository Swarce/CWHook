# Arxan info from reversing CW
Here are various things I've learned while working on this project. The implementation for Arxan vary based on the version of the game.
Older versions of CW are easier to bypass since the game still had support for Windows 7 which limits the approaches Arxan can take to make reverse engineering more difficult.

## Anti debugging detection
Arxan creates VEHs (Vector Exception Handlers) which Arxan uses to detect debuggers.
Illegal instructions are inserted inside of functions which their VEH will catch to increment the instruction pointer to skip over the instruction. The distance the instruction pointer will jump to is based on what RAX is set to, sometimes uses other cpu registers for the distance.

Arxan uses SEHs (Structured Exception Handling) combined with int3/ud2 instructions to detect debuggers, since a debugger on windows iirc has to catch every STATUS_BREAKPOINT exceptions.

Creates threads with NtCreateThreadEx with THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER.

Calls NtQueryInformationThread & NtSetInformationThread with ThreadHideFromDebugger.

Calls CheckRemoteDebuggerPresent.

Destroys ntdll debug functions, DbgBreakPoint DbgUserBreakPoint ...

Restoring the hooked ntdll dbg functions will crash the game.
They check it by getting a pointer to each function and check each byte for any modifications.

On an older build of CW, Arxan calls NtAllocateVirtualMemory and allocates a private allocated chunk.
NtSetInformationThread and other functions get inserted into the chunk.
NtSetInformationThread gets called from the chunk to set ThreadHideFromDebugger on numerous threads.

Hooks KiUserApcDispatcher

Sets Peb->BeingDebugged to 0x8f, crashes the game if its not set to 0x8f.
Anti debugging plugins that try to hide the debugger will set this value to 0 which means Arxan knows a debugger is attached. Debuggers without an anti debugging plugin will set this value to 1.
Arxan creates several different exceptions to see if a debugger is attached, since a regular debugger like visual studio will try to catch and handle every single one of them. This behavior can be turned off in x64dbg.

To be able to debug the executable at runtime you would need to nop out ud2 & int3 instructions cause the same exception that a debugger has to catch is the same exception that occurs when a debugger is listening for debug breakpoints.
I've tried to nop out the ud2 instructions myself even with the integrity checks and self healing (more on that later) circumvented but the game would still crash after a while. Further investigation is required for debugging to work properly.

On startup & at runtime will try to call NtClose with a handle id that is invalid. Handle id's such as 0xfffffffffffffffc (-4) and 0x12345.
Bypassing that lets you attach a debugger to the game BUT you would need to let the debuggee handle all exceptions. Breakpoints can be put down but for example x64dbg will start to listen in for STATUS_BREAKPOINT exceptions which will obviously catch the ud2/int3 from arxan as discussed previously, resulting in a crash after a while.

## Anti module injection
Arxan will replace the Kernel32ThreadInitThunkFunction function pointer within RtlUserThreadStart to its own hook. Prevents threads from starting up when a module is being loaded/injected into the process. It's also the same reason why manually mapping a module into the process also fails.

Arxan also implements TLS callbacks which will automatically get called when a module is being loaded into the process. The TLS callbacks check for if the module is signed with a valid certificate.

## Detection methods
At runtime will look for Cheat Engine, ReClass, IDA Pro, x64Dbg and probably other programs.
None of these programs have to be attached or have handles open to the game for Arxan to close the game.
In fact the game does not check for any opened handles so any program is free to read and write to the process.

## Integrity checks
BOIII's integrity check circumvention is similar to what's being done in CW.
However there is a new integrity check type added to the game. The 2 integrity check types in BOIII use a way smaller stack size where the original checksum is, and the calculated checksum from the area that it's comparing with. The integrity check stack size is about 144 bytes compared to the new one which is around 288 bytes.
The picture below is the difference between the smaller integrity check stack and the new integrity check stack.
The new integrity check has two versions, split and intact, same as the BOIII integrity checks.

##### boiii split/intact stack (rbp to 0x90)
![boiii](https://i.imgur.com/64ZeU8f.png)

##### cw split/intact stack (rbp to 0x120)
![boiii](https://i.imgur.com/GYtn4KR.png)

Initially while working on bypassing the integrity checks I had trouble finding where the checksums were being compared. CW apparently has way less integrity checks in place (CW has about 120 checks compared to BO3 which has 1219 checks). So each integrity check calculates the checksum for a bigger area. This in turn makes it extremely tedious to follow with hardware breakpoints. When I started on trying to find the location where the comparison is happening it took way too long to actually find it. It got to the point where I thought maybe they are doing something else with the checksum on the stack. However, I just had to let the game run overnight with hardware breakpoints attached to the location on the stack where the calculated checksum is at. The average time it took with hardware breakpoints was around 5-8 hours. A lot of the time is wasted on Arxan calculating the whole checksum for the code section since it compares on average 24000 bytes for one checksum. Each time a byte got read from the code section it would xor the current calculated checksum on the stack with the byte, reading and writing to the location on the stack where the checksum is at. This causes an exception which we need to handle within our own VEH. This takes a very long time to process since it happens so frequently.

In the end I did finally manage to get several locations for split and intact checksums to generate a signature. We use this signature to then create inline hooks for every integrity check location.

## Self healing code sections
After circumventing the integrity checks there was another challenge. Arxan will at runtime try to fix itself by copying over the integrity checks that I have placed. The same happens if you were to nop out the ud2/int3 instructions from the code sections. If you think that just nopping the instructions out that the self healing functions use to write to the code sections would solve the issue you would be wrong.

Arxan on purpose expect certain code sections to be malformed to then later fix them which means if you were to nop out the ability for it to write over instructions those sections will forever be malformed. Which will end up in a crash since Arxan expects those sections to be not destroyed.

The solution is to inline hook every self healing function and checking with our own inline hook if the code section it tries to fix is near an integrity check inline hook. We then don't overwrite that particular section which solves the issue of having our integrity checks overwritten.

## Encrypted code sections
Arxan decrypts encrypted code sections with a key that it xor's the code section with.

Signature for some of the encrypted code sections: 

48 BA ? ? ? ? ? ? ? ? E9

The usual encryption/decryption function looks like this

```asm
mov rdx, 0x7FA6B73DD1E72C56         ; xor key gets put into rdx
mov rax,qword ptr ds:[rcx+rax+14]   ; part of the encrypted text section gets put into rax
xor rax,rdx                         ; text section (rax) gets decrypted with key by xor'ing
mov qword ptr ds:[rdx+rcx+14],rax   ; replace part of the text section with the decrypted result
```

## Inline syscalls
Hooking ntdll functions is not enough if you want to prevent arxan from spawning/setting threads with the hide thread from debugger flag or preventing it to find reverse engineering programs. This used to work on older CW builds where you could still play on Windows 7 machines but after the [08/30/23 update](https://support.activision.com/no/articles/windows-7-support-in-call-of-duty) they seem to have changed the way they call ntdll functions. 

What Arxan does now makes more sense if you want to prevent having to worry about windows api functions being hooked, well sort off... The obvious step is to get the syscall number for the ntdll function that you want to call. Since every ntdll function call inside of it has a syscall number associated to it which the windows kernel will handle. You can look at the syscall table [here](https://j00ru.vexillium.org/syscalls/nt/64/) if you are interested.

An ntdll function looks like this internally

NtOpenFile
```asm
mov r10, rcx
mov eax, 0x33 ; 0x33 is the syscall number for the function call NtOpenFile (Windows 10 22H2)
test byte ptr ds:7FFE0308h, 1
jnz short loc_18009D665
syscall
retn
loc_18009D665:
int 0x2E	; DOS 2+ internal - EXECUTE COMMAND
		; DS:SI -> counted CR-terminated command string
retn

```

So you would essentially get the syscall number then execute the syscall instruction right after to essentially call NtOpenFile, which avoids having to call the function from within ntdll. However there is a strange thing that Arxan does which you can abuse to still hook inlined syscalls. Arxan will at startup select 4-7 different ntdll functions which it will use to jump to after putting the syscall into the RAX register. The jump occurs right at the syscall instruction within a random selected ntdll function. I have no clue why they are doing this since you can execute the syscall instruction anywhere you want, it does not have to be within the ntdll module's own text section. 

So to prevent this you can for example create inline hooks for every exported ntdll function and let those jump to a code section where you handle syscalls you want to modify the behavior of, but leave one function alone from being hooked. The function that is not inline hooked is the function Arxan will always pick to be the function to jump to after putting the syscall number into the RAX register. You can then apply an execute hardware breakpoint on the syscall instruction on the unmodified function and redirect the instruction pointer to be at the location of our own code stub. This way you will both inline hook any syscall coming from the game but also if arxan decides to call an inlined syscall function.

You can look at NtdllAsmStub inside of Arxan.cpp as an example.

## Calling windows exported functions without including them in the IAT
At runtime will gather exported functions from user32 & win32u and puts the locations on the stack.
Will then call them from different locations at runtime.

A list of functions that it gathers.

```
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
```

## Stopping windows from unloading modules
Arxan modifies the LoadCount of the module that is getting loaded into the game, for example via LoadLibrary but also through regular dll injection. The LoadCount gets set to -1 which should only be set to -1 if the library was build either statically or is an important windows dll such as ntdll, kernel32 etc. Since unloading ntdll or kernel32 would immediately crash the program.
This will prevent windows from unloading the module, since there isnt a handle counter that windows can check for if its ok to unload the module. To prevent this, we can simply force the LoadCount to be 1 again allowing the user to unload the module.
To actually fix this problem properly you would need to understand how windows loads modules and check for any function pointers being replaced by Arxan.
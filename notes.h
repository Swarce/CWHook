#pragma once

/* anti debugging detection
Game uses its own veh's
Creates threads with hide from debugger flag

Restore NTDLL Dbg functions
Hook DebugActiveProcess
Hook CheckRemoteDebuggerPresent
Hook NtQueryInformationThread to remove ThreadHideFromDebugger
Hook NtSetInformationThread to remove ThreadHideFromDebugger
Hook NtCreateThreadEx to remove THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
Hook NtCreateProcessEx
Hook CreateProcessW and CreateProcessA for DEBUG_ONLY_THIS_PROCESS and DEBUG_PROCESS

First call to NtAllocateVirtualMemory allocates a private allocated chunk.
Ntdll NtSetInformationThread and other functions get inserted into the chunk.
NtSetInformationThread gets called from the chunk to hide the main thread from debuggers.
*/

/* anti dll injection
Reverse Kernel32ThreadInitThunkFunction function ptr being replaced
*/

/* detection methods
Calling RestoreNtdllDbgFunctions early will crash the game eventually because they check if the ntdll dbg functions got restored
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
#pragma once

/* anti debugging detection

Maybe the process is debugging itself with openprocess so that it can catch int3's before ida/olly can

https://anti-debug.checkpoint.com/
Could hook more stuff to get a better picture.

Game uses its own veh's
Threads that created with hide from debug flag


attaching still possible at this bp

baseFuncAddr = reinterpret_cast<char*>(baseAddr + 0x177833f + 0x1000);
placeHardwareBP(baseFuncAddr, 0, Condition::ReadWrite);

https://learn.microsoft.com/en-us/windows/win32/debug/process-functions-for-debugging
CreateProcess DEBUG_PROCESS flag and/or DEBUG_ONLY_THIS_PROCESS flag


Things we tried:
Remove VEH's
Restore NTDLL Dbg functions
Restore our hooks after bp
Clear up tls callbacks after bp
Hook DebugActiveProcess
Hook CheckRemoteDebuggerPresent
Hook NtQueryInformationThread to remove ThreadHideFromDebugger
Hook NtSetInformationThread to remove ThreadHideFromDebugger
Hook NtCreateThreadEx to remove THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
Hook NtCreateProcessEx
Hook CreateProcessW and CreateProcessA for DEBUG_ONLY_THIS_PROCESS and DEBUG_PROCESS
SizeOfStackReserve does not get changed
reverse Kernel32ThreadInitThunkFunction function ptr being replaced
Hook NtSetInformationJobObject & NtAssignProcessToJobObject
No nt job objects get created.
Checked if SuppressDebugMsg is being set in the TEB


First call to NtAllocateVirtualMemory allocates a private allocated chunk.
Ntdll NtSetInformationThread and other functions get inserted into the chunk.
NtSetInformationThread gets called from the chunk to hide the main thread from debuggers.
*/

/* detection methods
calling RestoreNtdllDbgFunctions early will crash the game eventually 
because they check if the ntdll dbg functions got restored
*/
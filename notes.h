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

maybe openprocess fucks it? or other threads getting started??
maybe we arent cleaning up after ourselves? (anti-debug.checkpoint)

https://learn.microsoft.com/en-us/windows/win32/debug/process-functions-for-debugging
CreateProcess: This function is used to start a process and debug it. 
The fdwCreate parameter of CreateProcess is used to specify the type of debugging operation. 
If the DEBUG_PROCESS flag is specified for the parameter, a debugger debugs the new process and 
all of the process's descendants, provided that the descendants are created without the DEBUG_PROCESS flag. 
If both the DEBUG_PROCESS and DEBUG_ONLY_THIS_PROCESS flags are specified, a debugger debugs the new process 
but none of its descendants

*/

/* handle detection

CreateToolhelp32Snapshot
FindWindow
GetHandleInformation
OpenProcess
FindProcessId
GetProcessId

*/

/* window detection


*/
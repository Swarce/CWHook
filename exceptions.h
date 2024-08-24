#pragma once

#define PHNT_VERSION PHNT_WIN10_22H2
#include <phnt_windows.h>
#include <phnt.h>
#include <ntexapi.h>
#include <ntpsapi.h>
#include <minidumpapiset.h>

#define ResumeFlag 0x10000

LONG WINAPI exceptionHandler(const LPEXCEPTION_POINTERS info);
extern HANDLE exceptionHandle;
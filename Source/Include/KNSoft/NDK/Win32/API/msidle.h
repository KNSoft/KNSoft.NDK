/*
 * Inactivity Monitoring
 * See also: https://learn.microsoft.com/en-us/windows/win32/devnotes/inactivity-monitoring
 */

#pragma once

#include "../../NT/MinDef.h"

#include <WinBase.h>

EXTERN_C_START

#define STATE_USER_IDLE_BEGIN   1
#define STATE_USER_IDLE_END     2

typedef void (WINAPI* _IDLECALLBACK)(DWORD dwState);

// msidle.dll!#3
WINBASEAPI
DWORD
WINAPI
BeginIdleDetection(
    _IDLECALLBACK pfnCallback,
    DWORD dwIdleMin,
    DWORD dwReserved);

// msidle.dll!#4
WINBASEAPI
BOOL
WINAPI
EndIdleDetection(
   DWORD dwReserved);

// msidle.dll!#5, undocumented
WINBASEAPI
BOOL
WINAPI
SetIdleTimeout(
    DWORD dwIdleMin,
    DWORD dwReserved);

// msidle.dll!#6, undocumented
WINBASEAPI
VOID
WINAPI
SetIdleNotify(
    BOOL fIdleNotify);

// msidle.dll!#7, undocumented
WINBASEAPI
VOID
WINAPI
SetBusyNotify(
    BOOL fBusyNotify);

// msidle.dll!#8
WINBASEAPI
DWORD
WINAPI
GetIdleMinutes(
   DWORD dwReserved);

// msidle.dll!#9, undocumented
WINBASEAPI
DWORD
WINAPI
GetIdleSeconds(
   DWORD dwReserved);

EXTERN_C_END

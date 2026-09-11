#pragma once

#include "../../NDK.h"
#include "../../NT/NT.inl"

EXTERN_C_START

__inline
ULONG
_Inline_BaseSetLastNTError(
    _In_ NTSTATUS Status)
{
    ULONG Error = _Inline_RtlNtStatusToDosError(Status);
    _Inline_RtlSetLastWin32Error(Error);
    return Error;
}

__inline
PVOID
_Inline_BasepMapModuleHandle(
    _In_opt_ HMODULE ModuleHandle,
    _In_ BOOLEAN AsResourceFile)
{
    if (ModuleHandle == NULL)
    {
        return NtCurrentPeb()->ImageBaseAddress;
    }
    return !LDR_IS_RESOURCE(ModuleHandle) || AsResourceFile ? ModuleHandle : NULL;
}

__inline
PLARGE_INTEGER
_Inline_BaseFormatTimeOut(
    PLARGE_INTEGER Timeout,
    _In_ ULONG Milliseconds)
{
    if (Milliseconds == INFINITE)
    {
        return NULL;
    } else
    {
        Timeout->QuadPart = Int32x32To64(Milliseconds, -10000);
        return Timeout;
    }
}

EXTERN_C_END

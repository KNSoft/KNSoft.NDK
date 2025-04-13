/* KNSoft.NDK inline implementations */

#pragma once

#ifndef _KNSOFT_NDK_INLINE_IMPLEMENT
#pragma message("KNSoft.NDK: InlineImpl.inl is included but _KNSOFT_NDK_INLINE_IMPLEMENT is not defineded.")
#endif

#ifdef _KNSOFT_NDK_NO_EXTENSION
#errro("KNSoft.NDK: InlineImpl.inl conflicts with _KNSOFT_NDK_NO_EXTENSION.")
#endif

#include "NT.h"

EXTERN_C_START

/* Rtl/Process/EnvironmentBlock.h */

__inline
PPEB
NTAPI
RtlGetCurrentPeb(VOID)
{
    return NtCurrentPeb();
}

__inline
NTSTATUS
NTAPI
RtlAcquirePebLock(VOID)
{
    return RtlEnterCriticalSection(NtCurrentPeb()->FastPebLock);
}

__inline
NTSTATUS
NTAPI
RtlReleasePebLock(VOID)
{
    return RtlLeaveCriticalSection(NtCurrentPeb()->FastPebLock);
}

__inline
LOGICAL
NTAPI
RtlTryAcquirePebLock(VOID)
{
    return RtlTryEnterCriticalSection(NtCurrentPeb()->FastPebLock);
}

/* Rtl/ErrorHandling.h */

_When_(Status < 0, _Out_range_(> , 0))
_When_(Status >= 0, _Out_range_(== , 0))
__inline
ULONG
NTAPI
RtlNtStatusToDosError(
    _In_ NTSTATUS Status)
{
    NtWriteTeb(LastStatusValue, Status);
    return RtlNtStatusToDosErrorNoTeb(Status);
}

__inline
NTSTATUS
NTAPI
RtlGetLastNtStatus(VOID)
{
    return NtReadTeb(LastStatusValue);
}

__inline
ULONG
NTAPI
RtlGetLastWin32Error(VOID)
{
    return NtReadTeb(LastErrorValue);
}

__inline
VOID
NTAPI
RtlSetLastWin32Error(
    _In_ ULONG Win32Error)
{
    NtWriteTeb(LastErrorValue, Win32Error);
}

__inline
VOID
NTAPI
RtlRestoreLastWin32Error(
    _In_ ULONG Win32Error)
{
    NtWriteTeb(LastErrorValue, Win32Error);
}

__inline
VOID
NTAPI
RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
    _In_ NTSTATUS Status)
{
    return RtlSetLastWin32Error(RtlNtStatusToDosError(Status));
}

/* Rtl/Misc.h */

__inline
LOGICAL
NTAPI
RtlQueryPerformanceFrequency(
    _Out_ PLARGE_INTEGER PerformanceFrequency)
{
    if (SharedUserData->NtMajorVersion > 6 ||
        SharedUserData->NtMajorVersion == 6 && SharedUserData->NtMinorVersion >= 2)
    {
        PerformanceFrequency->QuadPart = SharedUserData->QpcFrequency;
    } else
    {
        LARGE_INTEGER PerformanceCounter;
        NtQueryPerformanceCounter(&PerformanceCounter, PerformanceFrequency);
    }
    return TRUE;
}

EXTERN_C_END

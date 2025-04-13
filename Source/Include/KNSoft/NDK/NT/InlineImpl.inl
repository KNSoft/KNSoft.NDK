/* KNSoft.NDK inline implementations */

#pragma once

#ifdef _KNSOFT_NDK_NO_EXTENSION
#errro("KNSoft.NDK: InlineImpl.inl conflicts with _KNSOFT_NDK_NO_EXTENSION.")
#endif

#include "NT.h"

EXTERN_C_START

/* Rtl/Process/EnvironmentBlock.h */

__inline
PPEB
NTAPI
_Inline_RtlGetCurrentPeb(VOID)
{
    return NtCurrentPeb();
}

__inline
NTSTATUS
NTAPI
_Inline_RtlAcquirePebLock(VOID)
{
    return RtlEnterCriticalSection(NtCurrentPeb()->FastPebLock);
}

__inline
NTSTATUS
NTAPI
_Inline_RtlReleasePebLock(VOID)
{
    return RtlLeaveCriticalSection(NtCurrentPeb()->FastPebLock);
}

__inline
LOGICAL
NTAPI
_Inline_RtlTryAcquirePebLock(VOID)
{
    return RtlTryEnterCriticalSection(NtCurrentPeb()->FastPebLock);
}

/* Rtl/ErrorHandling.h */

_When_(Status < 0, _Out_range_(>, 0))
_When_(Status >= 0, _Out_range_(==, 0))
__inline
ULONG
NTAPI
_Inline_RtlNtStatusToDosError(
    _In_ NTSTATUS Status)
{
    NtWriteTeb(LastStatusValue, Status);
    return RtlNtStatusToDosErrorNoTeb(Status);
}

__inline
NTSTATUS
NTAPI
_Inline_RtlGetLastNtStatus(VOID)
{
    return NtReadTeb(LastStatusValue);
}

__inline
ULONG
NTAPI
_Inline_RtlGetLastWin32Error(VOID)
{
    return NtReadTeb(LastErrorValue);
}

__inline
VOID
NTAPI
_Inline_RtlSetLastWin32Error(
    _In_ ULONG Win32Error)
{
    NtWriteTeb(LastErrorValue, Win32Error);
}

__inline
VOID
NTAPI
_Inline_RtlRestoreLastWin32Error(
    _In_ ULONG Win32Error)
{
    NtWriteTeb(LastErrorValue, Win32Error);
}

__inline
VOID
NTAPI
_Inline_RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
    _In_ NTSTATUS Status)
{
    _Inline_RtlSetLastWin32Error(_Inline_RtlNtStatusToDosError(Status));
}

/* Rtl/Misc.h */

__inline
LOGICAL
NTAPI
_Inline_RtlQueryPerformanceFrequency(
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

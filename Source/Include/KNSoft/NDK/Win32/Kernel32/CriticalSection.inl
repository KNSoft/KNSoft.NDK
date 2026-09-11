#pragma once

#include "Internal.inl"

EXTERN_C_START

__inline
VOID
WINAPI
_Inline_InitializeCriticalSection(
    _Out_ LPCRITICAL_SECTION lpCriticalSection)
{
    RtlInitializeCriticalSection(lpCriticalSection);
}

__inline
_Must_inspect_result_
BOOL
WINAPI
_Inline_InitializeCriticalSectionAndSpinCount(
    _Out_ LPCRITICAL_SECTION lpCriticalSection,
    _In_ DWORD dwSpinCount)
{
    if (IS_NT_VERSION_GE(NT_VERSION_VISTA))
    {
        RtlInitializeCriticalSectionAndSpinCount(lpCriticalSection, dwSpinCount);
        return TRUE;
    } else
    {
        NTSTATUS Status = RtlInitializeCriticalSectionAndSpinCount(lpCriticalSection, dwSpinCount);
        if (NT_SUCCESS(Status))
        {
            return TRUE;
        }
        _Inline_BaseSetLastNTError(Status);
        return FALSE;
    }
}

__inline
BOOL
WINAPI
_Inline_InitializeCriticalSectionEx(
    _Out_ LPCRITICAL_SECTION lpCriticalSection,
    _In_ DWORD dwSpinCount,
    _In_ DWORD Flags)
{
    NTSTATUS Status = RtlInitializeCriticalSectionEx(lpCriticalSection, dwSpinCount, Flags);
    if (NT_SUCCESS(Status))
    {
        return TRUE;
    }

    _Inline_BaseSetLastNTError(Status);
    return FALSE;
}

__inline
DWORD
WINAPI
_Inline_SetCriticalSectionSpinCount(
    _Inout_ LPCRITICAL_SECTION lpCriticalSection,
    _In_ DWORD dwSpinCount)
{
    return RtlSetCriticalSectionSpinCount(lpCriticalSection, dwSpinCount);
}

__inline
BOOL
WINAPI
_Inline_TryEnterCriticalSection(
    _Inout_ LPCRITICAL_SECTION lpCriticalSection)
{
    return RtlTryEnterCriticalSection(lpCriticalSection);
}

__inline
VOID
WINAPI
_Inline_EnterCriticalSection(
    _Inout_ LPCRITICAL_SECTION lpCriticalSection)
{
    RtlEnterCriticalSection(lpCriticalSection);
}

__inline
VOID
WINAPI
_Inline_LeaveCriticalSection(
    _Inout_ LPCRITICAL_SECTION lpCriticalSection)
{
    _Analysis_assume_lock_held_(lpCriticalSection);
    RtlLeaveCriticalSection(lpCriticalSection);
}

__inline
VOID
WINAPI
_Inline_DeleteCriticalSection(
    _Inout_ LPCRITICAL_SECTION lpCriticalSection)
{
    RtlDeleteCriticalSection(lpCriticalSection);
}

EXTERN_C_END

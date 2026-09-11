#pragma once

#include "Internal.inl"

EXTERN_C_START

__inline
DECLSPEC_NORETURN
VOID
WINAPI
_Inline_ExitProcess(
    _In_ UINT uExitCode)
{
    RtlExitUserProcess(uExitCode);
}

__inline
BOOL
WINAPI
_Inline_TerminateProcess(
    _In_ HANDLE hProcess,
    _In_ UINT uExitCode)
{
    NTSTATUS Status;

    if (hProcess != NULL)
    {
        RtlReportSilentProcessExit(hProcess, uExitCode);
        Status = NtTerminateProcess(hProcess, uExitCode);
        if (NT_SUCCESS(Status))
        {
            return TRUE;
        }
        _Inline_BaseSetLastNTError(Status);
    } else
    {
        _Inline_RtlSetLastWin32Error(ERROR_INVALID_HANDLE);
    }
    return FALSE;
}

EXTERN_C_END

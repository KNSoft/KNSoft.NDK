#pragma once

#include "Internal.inl"

EXTERN_C_START

__inline
_Check_return_
_Post_equals_last_error_
DWORD
WINAPI
_Inline_GetLastError(VOID)
{
    return _Inline_RtlGetLastWin32Error();
}

__inline
VOID
WINAPI
_Inline_SetLastError(
    _In_ DWORD dwErrCode)
{
    _Inline_RtlSetLastWin32Error(dwErrCode);
}

__inline
VOID
WINAPI
_Inline_RaiseException(
    _In_ DWORD dwExceptionCode,
    _In_ DWORD dwExceptionFlags,
    _In_ DWORD nNumberOfArguments,
    _In_reads_opt_(nNumberOfArguments) CONST ULONG_PTR* lpArguments)
{
    EXCEPTION_RECORD ExceptionRecord = { 0 };

    ExceptionRecord.ExceptionCode = dwExceptionCode;
    ExceptionRecord.ExceptionFlags = dwExceptionFlags & EXCEPTION_NONCONTINUABLE;
    ExceptionRecord.ExceptionAddress = (PVOID)_Inline_RaiseException;

    if (lpArguments != NULL)
    {
        if (nNumberOfArguments > EXCEPTION_MAXIMUM_PARAMETERS)
        {
            ExceptionRecord.NumberParameters = EXCEPTION_MAXIMUM_PARAMETERS;
        } else
        {
            ExceptionRecord.NumberParameters = nNumberOfArguments;
        }
        memcpy(ExceptionRecord.ExceptionInformation,
               lpArguments,
               ExceptionRecord.NumberParameters * sizeof(*lpArguments));
    } else
    {
        ExceptionRecord.NumberParameters = 0;
    }

    RtlRaiseException(&ExceptionRecord);
}

__inline
UINT
WINAPI
_Inline_SetErrorMode(
    _In_ UINT uMode)
{
    NTSTATUS Status;
    ULONG OldMode;

    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessDefaultHardErrorMode,
                                       &OldMode,
                                       sizeof(OldMode),
                                       NULL);
    if (NT_SUCCESS(Status))
    {
        OldMode ^= SEM_FAILCRITICALERRORS;
    } else
    {
        OldMode = 0;
        _Inline_BaseSetLastNTError(Status);
    }

    uMode ^= SEM_FAILCRITICALERRORS;
    uMode |= OldMode & SEM_NOALIGNMENTFAULTEXCEPT;
    NtSetInformationProcess(NtCurrentProcess(),
                            ProcessDefaultHardErrorMode,
                            &uMode,
                            sizeof(uMode));
    return OldMode;
}

EXTERN_C_END

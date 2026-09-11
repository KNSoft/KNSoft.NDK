#pragma once

#include "Internal.inl"

EXTERN_C_START

__inline
HANDLE
WINAPI
_Inline_GetStdHandle(
    _In_ DWORD nStdHandle)
{
    HANDLE StdHandle;
    PRTL_USER_PROCESS_PARAMETERS ProcParam = NtCurrentPeb()->ProcessParameters;

    if (nStdHandle == STD_INPUT_HANDLE)
    {
        if (IS_NT_VERSION_GE(NT_VERSION_VISTA) && ProcParam->WindowFlags & STARTF_USEHOTKEY)
        {
            return NULL;
        }
        StdHandle = ProcParam->StandardInput;
    } else if (nStdHandle == STD_OUTPUT_HANDLE)
    {
        if (IS_NT_VERSION_GE(NT_VERSION_VISTA) && ProcParam->WindowFlags & STARTF_USEMONITOR)
        {
            return NULL;
        }
        StdHandle = ProcParam->StandardOutput;
    } else if (nStdHandle == STD_ERROR_HANDLE)
    {
        StdHandle = ProcParam->StandardError;
    } else
    {
        StdHandle = INVALID_HANDLE_VALUE;
    }
    if (StdHandle == INVALID_HANDLE_VALUE)
    {
        _Inline_BaseSetLastNTError(STATUS_INVALID_HANDLE);
    }
    return StdHandle;
}

__inline
BOOL
WINAPI
_Inline_SetStdHandle(
    _In_ DWORD nStdHandle,
    _In_ HANDLE hHandle)
{
    if (nStdHandle == STD_INPUT_HANDLE)
    {
        NtCurrentPeb()->ProcessParameters->StandardInput = hHandle;
    } else if (nStdHandle == STD_OUTPUT_HANDLE)
    {
        NtCurrentPeb()->ProcessParameters->StandardOutput = hHandle;
    } else if (nStdHandle == STD_ERROR_HANDLE)
    {
        NtCurrentPeb()->ProcessParameters->StandardError = hHandle;
    } else
    {
        _Inline_BaseSetLastNTError(STATUS_INVALID_HANDLE);
        return FALSE;
    }

    return TRUE;
}

__inline
BOOL
WINAPI
_Inline_SetStdHandleEx(
    _In_ DWORD nStdHandle,
    _In_ HANDLE hHandle,
    _Out_opt_ PHANDLE phPrevValue)
{
    PHANDLE HandlePtr;

    if (phPrevValue != NULL)
    {
        *phPrevValue = NULL;
    }

    if (nStdHandle == STD_INPUT_HANDLE)
    {
        HandlePtr = &NtCurrentPeb()->ProcessParameters->StandardInput;
    } else if (nStdHandle == STD_OUTPUT_HANDLE)
    {
        HandlePtr = &NtCurrentPeb()->ProcessParameters->StandardOutput;
    } else if (nStdHandle == STD_ERROR_HANDLE)
    {
        HandlePtr = &NtCurrentPeb()->ProcessParameters->StandardError;
    } else
    {
        _Inline_BaseSetLastNTError(STATUS_INVALID_HANDLE);
        return FALSE;
    }

    if (phPrevValue != NULL)
    {
        *phPrevValue = *HandlePtr;
    }
    *HandlePtr = hHandle;
    return TRUE;
}

EXTERN_C_END

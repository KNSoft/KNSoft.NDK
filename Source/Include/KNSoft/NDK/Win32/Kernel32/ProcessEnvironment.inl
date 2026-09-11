#pragma once

#include "Internal.inl"

EXTERN_C_START

__inline
DWORD
WINAPI
_Inline_GetCurrentProcessId(VOID)
{
    return (DWORD)(ULONG_PTR)NtCurrentProcessId();
}

__inline
DWORD
WINAPI
_Inline_GetCurrentThreadId(VOID)
{
    return (DWORD)(ULONG_PTR)NtCurrentThreadId();
}

__inline
HANDLE
WINAPI
_Inline_GetCurrentProcess(VOID)
{
    return NtCurrentProcess();
}

__inline
HANDLE
WINAPI
_Inline_GetCurrentThread(VOID)
{
    return NtCurrentThread();
}

__inline
_NullNull_terminated_
LPWCH
WINAPI
_Inline_GetEnvironmentStringsW(VOID)
{
    PWCHAR pEnv, p;
    SIZE_T sSize;

    _Inline_RtlAcquirePebLock();

    pEnv = (PWCHAR)NtCurrentPeb()->ProcessParameters->Environment;
    for (p = pEnv; *p != UNICODE_NULL; p += wcslen(p) + 1);
    sSize = (p - pEnv + 1) * sizeof(WCHAR);

    p = (PWCHAR)RtlAllocateHeap(RtlProcessHeap(), 0, sSize);
    if (p)
    {
        memcpy(p, pEnv, sSize);
    } else
    {
        _Inline_BaseSetLastNTError(STATUS_NO_MEMORY);
    }

    _Inline_RtlReleasePebLock();
    return p;
}

__inline
BOOL
WINAPI
_Inline_FreeEnvironmentStringsW(
    _In_ _Pre_ _NullNull_terminated_ LPWCH penv)
{
    return RtlFreeHeap(RtlProcessHeap(), 0, penv);
}

__inline
BOOL
WINAPI
_Inline_SetEnvironmentVariableW(
    _In_ LPCWSTR lpName,
    _In_opt_ LPCWSTR lpValue)
{
    NTSTATUS Status = RtlSetEnvironmentVar(NULL,
                                           lpName,
                                           wcslen(lpName),
                                           lpValue,
                                           lpValue != NULL ? wcslen(lpValue) : 0);
    if (NT_SUCCESS(Status))
    {
        return TRUE;
    }

    _Inline_BaseSetLastNTError(Status);
    return FALSE;
}

__inline
VOID
WINAPI
_Inline_GetStartupInfoW(
    _Out_ LPSTARTUPINFOW lpStartupInfo)
{
    PRTL_USER_PROCESS_PARAMETERS ProcParam;
    ULONG WindowFlags;

    ProcParam = NtCurrentPeb()->ProcessParameters;
    lpStartupInfo->cb = sizeof(*lpStartupInfo);
    lpStartupInfo->lpReserved = ProcParam->ShellInfo.Buffer;
    lpStartupInfo->lpDesktop = ProcParam->DesktopInfo.Buffer;
    lpStartupInfo->lpTitle = ProcParam->WindowTitle.Buffer;
    lpStartupInfo->dwX = ProcParam->StartingX;
    lpStartupInfo->dwY = ProcParam->StartingY;
    lpStartupInfo->dwXSize = ProcParam->CountX;
    lpStartupInfo->dwYSize = ProcParam->CountY;
    lpStartupInfo->dwXCountChars = ProcParam->CountCharsX;
    lpStartupInfo->dwYCountChars = ProcParam->CountCharsY;
    lpStartupInfo->dwFillAttribute = ProcParam->FillAttribute;
    WindowFlags = ProcParam->WindowFlags;
    lpStartupInfo->dwFlags = WindowFlags;
    lpStartupInfo->wShowWindow = (WORD)ProcParam->ShowWindowFlags;
    lpStartupInfo->cbReserved2 = ProcParam->RuntimeData.Length;
    lpStartupInfo->lpReserved2 = (LPBYTE)ProcParam->RuntimeData.Buffer;

    if (WindowFlags & (STARTF_USESTDHANDLES | STARTF_USEHOTKEY | STARTF_USEMONITOR))
    {
        lpStartupInfo->hStdInput = ProcParam->StandardInput;
        lpStartupInfo->hStdOutput = ProcParam->StandardOutput;
        lpStartupInfo->hStdError = ProcParam->StandardError;
    }
}

__inline
BOOL
WINAPI
_Inline_IsDebuggerPresent(VOID)
{
    return NtCurrentPeb()->BeingDebugged;
}

EXTERN_C_END

#pragma once

#include "../../NT/MinDef.h"

#include <apisetcconv.h>

EXTERN_C_START

WINUSERAPI
INT
WINAPI
MessageBoxTimeoutA(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_ UINT uType,
    _In_ WORD wLanguageId,
    _In_ DWORD dwMilliseconds);

WINUSERAPI
INT
WINAPI
MessageBoxTimeoutW(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_ UINT uType,
    _In_ WORD wLanguageId,
    _In_ DWORD dwMilliseconds);

WINUSERAPI
BOOL
WINAPI
EndTask(
    HWND hWnd,
    BOOL fShutDown,
    BOOL fForce);

/* See also NtUserConsoleControl */
NTSYSCALLAPI
NTSTATUS
NTAPI
ConsoleControl(
    _In_ CONSOLECONTROL Command,
    _In_reads_bytes_(ConsoleInformationLength) PVOID ConsoleInformation,
    _In_ ULONG ConsoleInformationLength);

/* See also NtQuerySendMessage */
NTSYSCALLAPI
BOOL
NTAPI
QuerySendMessage(
    _Inout_ MSG* pMsg);

EXTERN_C_END

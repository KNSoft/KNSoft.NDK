#pragma once

#include "../../NT/MinDef.h"
#include "../../NT/Types/Basic.h"

#include <minwinbase.h>

EXTERN_C_START

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserThread(
    _In_ HANDLE hProcess,
    _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    _In_ BOOLEAN CreateSuspended,
    _In_opt_ ULONG ZeroBits,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ SIZE_T CommittedStackSize,
    _In_ LPTHREAD_START_ROUTINE StartAddress,
    _In_opt_ PVOID Parameter,
    _Out_opt_ PHANDLE hThread,
    _Out_opt_ PCLIENT_ID ClientId);

NTSYSAPI
VOID
NTAPI
RtlExitUserThread(
    _In_ NTSTATUS ExitStatus);

typedef ULONG
(NTAPI* RTLP_UNHANDLED_EXCEPTION_FILTER)(
    _In_ PEXCEPTION_POINTERS ExceptionInfo);
typedef RTLP_UNHANDLED_EXCEPTION_FILTER* PRTLP_UNHANDLED_EXCEPTION_FILTER;

NTSYSAPI
VOID
NTAPI
RtlSetUnhandledExceptionFilter(
    _In_opt_ PRTLP_UNHANDLED_EXCEPTION_FILTER TopLevelExceptionFilter);

NTSYSAPI
VOID
DECLSPEC_NORETURN
NTAPI
RtlExitUserProcess(
    _In_ NTSTATUS ExitStatus);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetCurrentDirectory_U(
    _In_ PUNICODE_STRING name);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetEnvironmentVariable(
    _In_z_ PWSTR* Environment,
    _In_ PUNICODE_STRING Name,
    _In_ PUNICODE_STRING Value);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetLastNtStatus();

NTSYSAPI
ULONG
NTAPI
RtlGetLastWin32Error();

NTSYSAPI
ULONG
NTAPI
RtlSetLastWin32Error(
    _In_ ULONG LastError);

_IRQL_requires_max_(APC_LEVEL)
_When_(Status < 0, _Out_range_(> , 0))
_When_(Status >= 0, _Out_range_(== , 0))
NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosError(
   _In_ NTSTATUS Status);

_When_(Status < 0, _Out_range_(> , 0))
_When_(Status >= 0, _Out_range_(== , 0))
NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosErrorNoTeb(
   _In_ NTSTATUS Status);

NTSYSAPI
VOID
NTAPI
RtlRaiseStatus(
    _In_ NTSTATUS Status);

NTSYSAPI
VOID
NTAPI
RtlGetCallersAddress(
    _Out_ PVOID* CallersAddress,
    _Out_ PVOID* CallersCaller);

NTSYSAPI
NTSTATUS
NTAPI
RtlWow64EnableFsRedirectionEx(
    _In_ PVOID Wow64FsEnableRedirection,
    _Out_ PVOID* OldFsRedirectionLevel);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetUserPreferredUILanguages(
    _In_ ULONG Flags,
    _In_opt_ PCWSTR LocaleName,
    _Out_ PULONG NumLanguages,
    _Out_writes_opt_z_(*LanguagesCchSize) PWSTR LanguagesBuffer,
    _Inout_ PULONG LanguagesCchSize);

NTSYSAPI
NTSTATUS
NTAPI
RtlFindMessage(
    _In_ PVOID BaseAddress,
    _In_ ULONG Type,
    _In_ ULONG Language,
    _In_ ULONG MessageId,
    _Out_ PMESSAGE_RESOURCE_ENTRY* MessageResourceEntry);

EXTERN_C_END

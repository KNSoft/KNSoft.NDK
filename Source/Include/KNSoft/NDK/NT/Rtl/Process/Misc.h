#pragma once

#include "../../MinDef.h"

EXTERN_C_START

#pragma region FLS

NTSYSAPI
NTSTATUS
NTAPI
RtlFlsAlloc(
    _In_ PFLS_CALLBACK_FUNCTION Callback,
    _Out_ PULONG FlsIndex);

NTSYSAPI
NTSTATUS
NTAPI
RtlFlsFree(
    _In_ ULONG FlsIndex);

#if (NTDDI_VERSION >= NTDDI_WIN10_MN)

NTSYSAPI
NTSTATUS
NTAPI
RtlFlsGetValue(
    _In_ ULONG FlsIndex,
    _Out_ PVOID* FlsData);

NTSYSAPI
PVOID
WINAPI
RtlFlsGetValue2(
    _In_ ULONG FlsIndex);

NTSYSAPI
NTSTATUS
NTAPI
RtlFlsSetValue(
    _In_ ULONG FlsIndex,
    _In_ PVOID FlsData);

#endif

#pragma endregion

#pragma region Protected Policies

#if (NTDDI_VERSION >= NTDDI_WINBLUE)

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryProtectedPolicy(
    _In_ PGUID PolicyGuid,
    _Out_ PULONG_PTR PolicyValue);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetProtectedPolicy(
    _In_ PGUID PolicyGuid,
    _In_ ULONG_PTR PolicyValue,
    _Out_ PULONG_PTR OldPolicyValue);

#endif

#pragma endregion

EXTERN_C_END

#pragma once

#include "../../NT/MinDef.h"
#include "../../NT/Types/Ldr.h"

EXTERN_C_START

NTSTATUS
NTAPI
LdrLockLoaderLock(
    _In_ ULONG Flags,
    _Out_opt_ PULONG Disposition,
    _Out_opt_ PULONG_PTR Cookie);

NTSTATUS
NTAPI
LdrUnlockLoaderLock(
    _In_ ULONG Flags,
    _In_opt_ ULONG Cookie);

NTSTATUS
NTAPI
LdrDisableThreadCalloutsForDll(
    _In_ PVOID BaseAddress);

NTSTATUS
NTAPI
LdrFindEntryForAddress(
    _In_ PVOID Address,
    _Out_ PLDR_DATA_TABLE_ENTRY* Module);

NTSTATUS
NTAPI
LdrEnumerateLoadedModules(
    _Reserved_ ULONG ReservedFlag,
    _In_ PLDR_ENUM_CALLBACK EnumProc,
    _In_opt_ PVOID Context);

NTSTATUS
NTAPI
LdrGetDllHandle(
    _In_opt_ PWSTR DllPath,
    _In_opt_ PULONG DllCharacteristics,
    _In_ PUNICODE_STRING DllName,
    _Out_ PVOID* DllHandle);

NTSYSAPI
NTSTATUS
NTAPI
LdrLoadDll(
    _In_opt_ PWSTR DllSearchPath,
    _In_opt_ PULONG DllCharacteristics,
    _In_ PUNICODE_STRING DllName,
    _Out_ PVOID* BaseAddress);

NTSYSAPI
NTSTATUS
NTAPI
LdrUnloadDll(
    _In_ PVOID* BaseAddress);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetProcedureAddress(
    _In_ PVOID BaseAddress,
    _In_opt_ _When_(Ordinal == 0, _Notnull_) PANSI_STRING Name,
    _In_opt_ _When_(Name == NULL, _In_range_(> , 0)) ULONG Ordinal,
    _Out_ PVOID* ProcedureAddress);

NTSYSAPI
NTSTATUS
NTAPI
LdrRegisterDllNotification(
    _In_ ULONG Flags,
    _In_ PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    _In_opt_ PVOID Context,
    _Out_ PVOID* Cookie);

NTSYSAPI
NTSTATUS
NTAPI
LdrUnregisterDllNotification(
    _In_ PVOID Cookie);

EXTERN_C_END

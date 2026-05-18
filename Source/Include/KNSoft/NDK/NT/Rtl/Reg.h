#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

NTSYSAPI
NTSTATUS
NTAPI
RtlFormatCurrentUserKeyPath(
    _Out_ PUNICODE_STRING CurrentUserKeyPath
);

NTSYSAPI
NTSTATUS
NTAPI
RtlOpenCurrentUser(
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE CurrentUserKey
);

#define RTL_REGISTRY_ABSOLUTE 0
#define RTL_REGISTRY_SERVICES 1 // \Registry\Machine\System\CurrentControlSet\Services
#define RTL_REGISTRY_CONTROL 2 // \Registry\Machine\System\CurrentControlSet\Control
#define RTL_REGISTRY_WINDOWS_NT 3 // \Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion
#define RTL_REGISTRY_DEVICEMAP 4 // \Registry\Machine\Hardware\DeviceMap
#define RTL_REGISTRY_USER 5 // \Registry\User\CurrentUser
#define RTL_REGISTRY_MAXIMUM 6
#define RTL_REGISTRY_HANDLE 0x40000000
#define RTL_REGISTRY_OPTIONAL 0x80000000

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateRegistryKey(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path
);

NTSYSAPI
NTSTATUS
NTAPI
RtlCheckRegistryKey(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path
);

_Function_class_(RTL_QUERY_REGISTRY_ROUTINE)
typedef NTSTATUS(NTAPI RTL_QUERY_REGISTRY_ROUTINE)(
    _In_ PCWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueLength,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID EntryContext
    );
typedef RTL_QUERY_REGISTRY_ROUTINE *PRTL_QUERY_REGISTRY_ROUTINE;

typedef struct _RTL_QUERY_REGISTRY_TABLE
{
    PRTL_QUERY_REGISTRY_ROUTINE QueryRoutine;
    ULONG Flags;
    PWSTR Name;
    PVOID EntryContext;
    ULONG DefaultType;
    PVOID DefaultData;
    ULONG DefaultLength;
} RTL_QUERY_REGISTRY_TABLE, *PRTL_QUERY_REGISTRY_TABLE;

#define RTL_QUERY_REGISTRY_SUBKEY 0x00000001
#define RTL_QUERY_REGISTRY_TOPKEY 0x00000002
#define RTL_QUERY_REGISTRY_REQUIRED 0x00000004
#define RTL_QUERY_REGISTRY_NOVALUE 0x00000008
#define RTL_QUERY_REGISTRY_NOEXPAND 0x00000010
#define RTL_QUERY_REGISTRY_DIRECT 0x00000020
#define RTL_QUERY_REGISTRY_DELETE 0x00000040
#define RTL_QUERY_REGISTRY_NOSTRING 0x00000080 // deprecated
#define RTL_QUERY_REGISTRY_TYPECHECK 0x00000100

#define RTL_QUERY_REGISTRY_TYPECHECK_SHIFT 24
#define RTL_QUERY_REGISTRY_TYPECHECK_MASK (0xff << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT)

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryRegistryValues(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path,
    _Inout_ _At_(*(*QueryTable).EntryContext, _Pre_unknown_) PRTL_QUERY_REGISTRY_TABLE QueryTable,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID Environment
);

#if (NTDDI_VERSION >= NTDDI_WIN8)
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryRegistryValuesEx(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path,
    _Inout_ _At_(*(*QueryTable).EntryContext, _Pre_unknown_) PRTL_QUERY_REGISTRY_TABLE QueryTable,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID Environment
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS4)
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryRegistryValueWithFallback(
    _In_opt_ HANDLE PrimaryHandle,
    _In_opt_ HANDLE FallbackHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_ ULONG ValueLength,
    _Out_opt_ PULONG ValueType,
    _Out_writes_bytes_to_(ValueLength, *ResultLength) PVOID ValueData,
    _Out_range_(<= , ValueLength) PULONG ResultLength
);
#endif

NTSYSAPI
NTSTATUS
NTAPI
RtlWriteRegistryValue(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path,
    _In_ PCWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueLength
);

NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteRegistryValue(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path,
    _In_ PCWSTR ValueName
);

typedef struct _RTL_RXACT_CONTEXT RTL_RXACT_CONTEXT, *PRTL_RXACT_CONTEXT;
// RtlpCleanupRegistryKeys
NTSYSAPI
NTSTATUS
NTAPI
RtlpCleanupRegistryKeys(
    void
    );

// RtlpCreateProcessRegistryInfo
NTSYSAPI
NTSTATUS
NTAPI
RtlpCreateProcessRegistryInfo(
    _Out_opt_ PVOID *RegistryInfo
    );

// RtlpNtCreateKey
NTSYSAPI
NTSTATUS
NTAPI
RtlpNtCreateKey(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Inout_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ ULONG CreateOptions,
    _In_opt_ ULONG ValueType,
    _Out_opt_ PULONG Disposition
    );

// RtlpNtEnumerateSubKey
NTSYSAPI
NTSTATUS
NTAPI
RtlpNtEnumerateSubKey(
    _In_ HANDLE KeyHandle,
    _Inout_ PCUNICODE_STRING SubKeyName,
    _In_ ULONG Index
    );

// RtlpNtMakeTemporaryKey
NTSYSAPI
NTSTATUS
NTAPI
RtlpNtMakeTemporaryKey(
    _In_ HANDLE KeyHandle
    );

// RtlpNtOpenKey
NTSYSAPI
NTSTATUS
NTAPI
RtlpNtOpenKey(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Inout_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes
    );

// RtlpNtQueryValueKey
NTSYSAPI
NTSTATUS
NTAPI
RtlpNtQueryValueKey(
    _In_ HANDLE KeyHandle,
    _Out_opt_ PULONG Type,
    _Out_writes_bytes_opt_(*DataLength) PVOID Data,
    _Inout_opt_ PINT DataLength
    );

// RtlpNtSetValueKey
NTSYSAPI
NTSTATUS
NTAPI
RtlpNtSetValueKey(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Type,
    _In_reads_bytes_opt_(DataLength) PVOID Data,
    _In_ ULONG DataLength
    );

// RtlAbortRXact
NTSYSAPI
NTSTATUS
NTAPI
RtlAbortRXact(
    _Inout_ PRTL_RXACT_CONTEXT RxactContext,
    _Reserved_ PVOID Reserved1,
    _Reserved_ PVOID Reserved2,
    _Reserved_ PVOID Reserved3
    );

// RtlAddActionToRXact
NTSYSAPI
NTSTATUS
NTAPI
RtlAddActionToRXact(
    _Inout_ PRTL_RXACT_CONTEXT RxactContext,
    _In_ ULONG ActionType,
    _In_ const UNICODE_STRING *Name,
    _In_ ULONG Operation,
    _In_reads_bytes_opt_(DataSize) const VOID *Data,
    _In_ SIZE_T DataSize
    );

// RtlAddAttributeActionToRXact
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAttributeActionToRXact(
    _Inout_ PRTL_RXACT_CONTEXT RxactContext,
    _In_ ULONG ActionType,
    _In_ const UNICODE_STRING *KeyName,
    _In_ LONGLONG AttributeIndex,
    _In_ const UNICODE_STRING *ValueName,
    _In_ ULONG ValueType,
    _In_reads_bytes_opt_(DataSize) const VOID *Data,
    _In_ SIZE_T DataSize
    );

// RtlApplyRXact
NTSYSAPI
NTSTATUS
NTAPI
RtlApplyRXact(
    _Inout_ PRTL_RXACT_CONTEXT RxactContext
    );

// RtlApplyRXactNoFlush
NTSYSAPI
NTSTATUS
NTAPI
RtlApplyRXactNoFlush(
    _Inout_ PRTL_RXACT_CONTEXT RxactContext
    );

// RtlInitializeRXact
//NTSYSAPI
//ULONG
//NTAPI
//RtlIncrementCorrelationVector(
//    _Inout_ PVOID CorrelationVector
//    );
//
//NTSYSAPI
//ULONG
//NTAPI
//RtlInitializeCorrelationVector(
//    _Inout_ PVOID CorrelationVector,
//    _In_ ULONG Version,
//    _In_ const GUID *Guid
//    );

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeRXact(
    _In_ HANDLE RootKeyHandle,
    _In_ CHAR OpenLog,
    _Out_ PULONGLONG RxactContext
    );

// RtlStartRXact
NTSYSAPI
NTSTATUS
NTAPI
RtlStartRXact(
    _Inout_ PVOID RxactContext
    );


EXTERN_C_END

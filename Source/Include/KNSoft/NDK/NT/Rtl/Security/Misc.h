#pragma once

#include "../../MinDef.h"

EXTERN_C_START

/* phnt */

#if (NTDDI_VERSION >= NTDDI_WIN8)

NTSYSAPI
NTSTATUS
NTAPI
RtlIsUntrustedObject(
    _In_opt_ HANDLE Handle,
    _In_opt_ PVOID Object,
    _Out_ PBOOLEAN IsUntrustedObject);

NTSYSAPI
ULONG
NTAPI
RtlQueryValidationRunlevel(
    _In_opt_ PUNICODE_STRING ComponentName);

NTSYSAPI
NTSTATUS
NTAPI
RtlNewSecurityGrantedAccess(
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PPRIVILEGE_SET NewPrivileges,
    _Inout_ PULONG Length,
    _In_opt_ HANDLE TokenHandle,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_ PACCESS_MASK RemainingDesiredAccess);

#endif

// RtlpConvertRelativeToAbsoluteSecurityAttribute
NTSYSAPI
NTSTATUS
NTAPI
RtlpConvertRelativeToAbsoluteSecurityAttribute(
    _In_ PVOID RelativeSa,
    _In_ ULONG RelativeSaLength,
    _Out_ PVOID AbsoluteSa,
    _Inout_ ULONG *AbsoluteSaLength
    );

// RtlpMergeSecurityAttributeInformation
NTSYSAPI
NTSTATUS
NTAPI
RtlpMergeSecurityAttributeInformation(
    _In_opt_ PVOID SourceSecurityDescriptor,
    _In_opt_ PVOID AdditionalSecurityDescriptor,
    _Outptr_ PUSHORT *MergedSecurityDescriptor,
    _In_ CHAR MergeMode
    );

// RtlpConvertAbsoluteToRelativeSecurityAttribute
//NTSYSAPI
//PRUNTIME_FUNCTION
//NTAPI
//RtlLookupFunctionTable(
//    _In_ ULONGLONG ControlPc,
//    _Out_ ULONGLONG *ImageBase,
//    _Out_ ULONG *Length,
//    _In_ ULONGLONG HistoryTable
//    );

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlpConvertAbsoluteToRelativeSecurityAttribute(
    _In_ PVOID AbsoluteSa,
    _Out_ PVOID RelativeSa,
    _Inout_ ULONG *RelativeSaLength
    );

// RtlMapSecurityErrorToNtStatus
NTSYSAPI
NTSTATUS
NTAPI
RtlMapSecurityErrorToNtStatus(
    _In_ LONG SecurityStatus
    );


EXTERN_C_END

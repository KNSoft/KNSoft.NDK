#pragma once

#include "../MinDef.h"
#include "../Sxs.h"
#include "Path.h"
#include "Debug.h"
#include "Feature.h"
#include "ActCtx.h"
#include "BootStatus.h"
#include "Mui.h"
#include "Reg.h"
#include "Sync.h"
#include "Time.h"
#include "Wow.h"
#include "DataStructures/RBTree.h"
#include "Security/Misc.h"
#include "../Ldr.h"
#include "../Ex/Wnf.h"

EXTERN_C_START

/* phnt private additions synced from 2cc1b9d44 */

// RtlpApplyLengthFunction
NTSYSAPI
NTSTATUS
NTAPI
RtlpApplyLengthFunction(
    _In_ ULONG Flags,
    _In_ ULONGLONG StringTypeSize,
    _Inout_ PVOID StringStruct,
    _In_ NTSTATUS (NTAPI *LengthFunction)(_In_ ULONG Flags, _In_ PVOID StringStruct, _Out_ PULONG LengthChars)
    );

// RtlpEnsureBufferSize
NTSYSAPI
NTSTATUS
NTAPI
RtlpEnsureBufferSize(
    _In_ ULONG Flags,
    _Inout_ PRTL_BUFFER BufferState,
    _In_ SIZE_T RequiredSize
    );

// RtlpGetDeviceFamilyInfoEnum
NTSYSAPI
VOID
NTAPI
RtlpGetDeviceFamilyInfoEnum(
    _Out_opt_ PULONGLONG UapInfo,
    _Out_opt_ PULONG DeviceFamily,
    _Out_opt_ PULONG DeviceForm
    );

// RtlpGetNameFromLangInfoNode
NTSYSAPI
NTSTATUS
NTAPI
RtlpGetNameFromLangInfoNode(
    _In_ PVOID RegistryInfo,
    _In_ PVOID LangInfoNode,
    _Inout_ PUNICODE_STRING Name
    );

// RtlpInitializeLangRegistryInfo
NTSYSAPI
NTSTATUS
NTAPI
RtlpInitializeLangRegistryInfo(
    _Inout_ PVOID *RegistryInfo
    );

// RtlpLoadMachineUIByPolicy
NTSYSAPI
NTSTATUS
NTAPI
RtlpLoadMachineUIByPolicy(
    _In_opt_ HANDLE PolicyRootKey,
    _In_ PVOID RegistryInfo,
    _Inout_ PVOID *LanguageList
    );

// RtlpLoadUserUIByPolicy
NTSYSAPI
NTSTATUS
NTAPI
RtlpLoadUserUIByPolicy(
    _In_opt_ HANDLE UserRootKey,
    _In_ PVOID RegistryInfo,
    _Inout_ PVOID *LanguageList
    );

// RtlpNotOwnerCriticalSection
NTSYSAPI
VOID
NTAPI
RtlpNotOwnerCriticalSection(
    _In_ PRTL_CRITICAL_SECTION CriticalSection
    );

// RtlpQueryProcessDebugInformationRemote
NTSYSAPI
VOID
NTAPI
RtlpQueryProcessDebugInformationRemote(
    _Inout_ PRTL_DEBUG_INFORMATION DebugInfo
    );

// RtlpUnWaitCriticalSection
NTSYSAPI
NTSTATUS
NTAPI
RtlpUnWaitCriticalSection(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
    );

// RtlCmDecodeMemIoResource
NTSYSAPI
ULONGLONG
NTAPI
RtlCmDecodeMemIoResource(
    _In_ const VOID *ResourceDescriptor,
    _Out_opt_ PULONGLONG TranslatedAddress
    );

// RtlCmEncodeMemIoResource
NTSYSAPI
NTSTATUS
NTAPI
RtlCmEncodeMemIoResource(
    _In_ PVOID ResourceDescriptor,
    _In_ CHAR Width,
    _In_ ULONGLONG Address,
    _In_ PVOID EncodedResource
    );

// RtlInitializeNtUserPfn
NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeNtUserPfn(
    _In_ PVOID NtUserPfnTable,
    _In_ SIZE_T NtUserPfnTableSize,
    _In_opt_ PVOID NtUserPfnTable2,
    _In_ SIZE_T NtUserPfnTable2Size,
    _In_opt_ PVOID NtUserPfnTable3,
    _In_ SIZE_T NtUserPfnTable3Size
    );

// RtlIoDecodeMemIoResource
NTSYSAPI
ULONGLONG
NTAPI
RtlIoDecodeMemIoResource(
    _In_ PVOID ResourceDescriptor,
    _Out_opt_ PULONGLONG TranslatedAddress,
    _Out_opt_ PULONGLONG StartAddress,
    _Out_opt_ PULONGLONG Length
    );

// RtlIoEncodeMemIoResource
NTSYSAPI
NTSTATUS
NTAPI
RtlIoEncodeMemIoResource(
    _In_ PVOID ResourceDescriptor,
    _In_ CHAR Width,
    _In_ ULONGLONG Address,
    _In_ ULONGLONG Length,
    _In_ PVOID StartAddress,
    _In_ PVOID EndAddress
    );

// RtlResetNtUserPfn
NTSYSAPI
NTSTATUS
NTAPI
RtlResetNtUserPfn(
    _In_opt_ PVOID NtUserPfnTable,
    _In_ ULONGLONG NtUserPfnTableSize,
    _In_opt_ PVOID NtUserPfnTable2,
    _In_ ULONGLONG NtUserPfnTable2Size
    );

// RtlRetrieveNtUserPfn
NTSYSAPI
NTSTATUS
NTAPI
RtlRetrieveNtUserPfn(
    _Out_ PULONGLONG NtUserPfnTable,
    _Out_ PULONGLONG NtUserPfnTable2,
    _Out_ PULONGLONG NtUserPfnTable3
    );

EXTERN_C_END

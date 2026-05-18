#pragma once

#include "../MinDef.h"
#include "../Sxs.h"
#include "Path.h"
#include "Debug.h"
#include "Feature.h"
#include "Sync.h"
#include "../Ex/Wnf.h"

EXTERN_C_START

/* phnt private additions synced from 2cc1b9d44 */

#define RTL_QUERY_MODULE_INFORMATION_RECORD_SIZE_IMAGE_BASE 0x8
#define RTL_QUERY_MODULE_INFORMATION_RECORD_SIZE_MODULE     0x110

typedef enum _RTL_RESOURCE_POLICY_CLASS
{
    RtlResourcePolicyPhysicalMemory = 0,
    RtlResourcePolicyDiskSpace = 1,
    RtlResourcePolicyDiskSpeed = 2,
    RtlResourcePolicyDiskWriteConstraint = 3
} RTL_RESOURCE_POLICY_CLASS, *PRTL_RESOURCE_POLICY_CLASS;

typedef struct _RTL_TRACE_DATABASE RTL_TRACE_DATABASE, *PRTL_TRACE_DATABASE;
typedef struct _TIME_FIELDS TIME_FIELDS, *PTIME_FIELDS;
typedef struct _RTL_RXACT_CONTEXT RTL_RXACT_CONTEXT, *PRTL_RXACT_CONTEXT;
typedef struct _RTL_AVL_TREE RTL_AVL_TREE, *PRTL_AVL_TREE;

// RtlAvlRemoveNode
NTSYSAPI
void
NTAPI
RtlAvlRemoveNode(
    _Inout_ PRTL_BALANCED_NODE *Root,
    _In_ PRTL_BALANCED_NODE Node
    );

// RtlRestoreThreadPreferredUILanguages
NTSYSAPI
BOOLEAN
NTAPI
RtlRestoreThreadPreferredUILanguages(
    _In_ ULONGLONG SavedState,
    _In_opt_ PVOID Context1,
    _In_opt_ PVOID Context2,
    _In_opt_ PVOID Context3
    );

// RtlSetProcessPreferredUILanguages
NTSYSAPI
NTSTATUS
NTAPI
RtlSetProcessPreferredUILanguages(
    _In_ ULONG Flags,
    _In_opt_ PUSHORT LanguagesBuffer,
    _Out_opt_ PULONG NumberOfLanguages
    );

// RtlSetThreadPreferredUILanguages
NTSYSAPI
NTSTATUS
NTAPI
RtlSetThreadPreferredUILanguages(
    _In_ ULONG Flags,
    _In_opt_ PVOID LanguagesBuffer,
    _Out_opt_ PINT NumberOfLanguages,
    _In_opt_ PVOID Reserved
    );

// RtlSetThreadPreferredUILanguages2
NTSYSAPI
NTSTATUS
NTAPI
RtlSetThreadPreferredUILanguages2(
    _In_ ULONGLONG Flags,
    _In_opt_ PVOID LanguagesBuffer,
    _Out_opt_ PINT NumberOfLanguages,
    _Out_opt_ PULONGLONG SavedState
    );

// RtlpGetLCIDFromLangInfoNode
NTSYSAPI
NTSTATUS
NTAPI
RtlpGetLCIDFromLangInfoNode(
    _In_ PVOID RegistryInfo,
    _In_ PVOID LangInfoNode,
    _Out_ PUSHORT Lcid
    );

// RtlpGetUserOrMachineUILanguage4NLS
NTSYSAPI
NTSTATUS
NTAPI
RtlpGetUserOrMachineUILanguage4NLS(
    _In_ ULONG UserOrMachine,
    _Out_writes_opt_(*LanguageCount) PWSTR LanguagesMultiSz,
    _Inout_ PULONGLONG LanguageCount
    );

// RtlpIsQualifiedLanguage
NTSYSAPI
NTSTATUS
NTAPI
RtlpIsQualifiedLanguage(
    _In_ PVOID RegistryInfo,
    _In_ PSHORT LangNode,
    _In_ BOOLEAN CheckInstallLanguage
    );

// RtlpMuiFreeLangRegistryInfo
NTSYSAPI
NTSTATUS
NTAPI
RtlpMuiFreeLangRegistryInfo(
    _In_ PVOID RegistryInfo,
    _In_ ULONG FreeMask,
    _In_opt_ PVOID Context1,
    _In_opt_ PVOID Context2
    );

// RtlpMuiRegCreateRegistryInfo
NTSYSAPI
PULONG
NTAPI
RtlpMuiRegCreateRegistryInfo(
    VOID
    );

// RtlpMuiRegFreeRegistryInfo
NTSYSAPI
NTSTATUS
NTAPI
RtlpMuiRegFreeRegistryInfo(
    _In_ PVOID RegistryInfo,
    _In_ ULONG FreeMask,
    _In_opt_ PVOID Context1,
    _In_opt_ PVOID Context2
    );

// RtlpMuiRegLoadRegistryInfo
NTSYSAPI
NTSTATUS
NTAPI
RtlpMuiRegLoadRegistryInfo(
    _Inout_ PVOID RegistryInfo,
    _In_ SHORT LoadMask,
    _In_opt_ PVOID Context1,
    _In_opt_ PVOID Context2
    );

// RtlpQueryDefaultUILanguage
NTSYSAPI
NTSTATUS
NTAPI
RtlpQueryDefaultUILanguage(
    _Out_ PUSHORT DefaultLanguage,
    _In_ BOOLEAN ForceMachinePolicy
    );

// RtlpRefreshCachedUILanguage
NTSYSAPI
NTSTATUS
NTAPI
RtlpRefreshCachedUILanguage(
    _In_ PCWSTR SourceString,
    _In_ BOOLEAN CommitImmediately
    );

// RtlpSetInstallLanguage
NTSYSAPI
NTSTATUS
NTAPI
RtlpSetInstallLanguage(
    _In_ CHAR Flags,
    _In_z_ PCWSTR Language
    );

// RtlpSetPreferredUILanguages
NTSYSAPI
NTSTATUS
NTAPI
RtlpSetPreferredUILanguages(
    _In_ ULONG Flags,
    _In_opt_z_ PWSTR LanguagesMultiSz,
    _Out_opt_ PULONG LanguagesCount,
    _In_opt_ PVOID Reserved
    );

// RtlpSetUserPreferredUILanguages
NTSYSAPI
NTSTATUS
NTAPI
RtlpSetUserPreferredUILanguages(
    _In_ ULONG Flags,
    _In_opt_z_ PWSTR LanguagesMultiSz,
    _Out_opt_ PULONG LanguagesCount
    );

// RtlpVerifyAndCommitUILanguageSettings
NTSYSAPI
NTSTATUS
NTAPI
RtlpVerifyAndCommitUILanguageSettings(
    _In_ BOOLEAN ShutdownOnFailure
    );

// LdrHotPatchNotify
NTSYSAPI
NTSTATUS
NTAPI
LdrHotPatchNotify(
    _In_ PVOID ImageBase,
    _In_ PVOID Unknown1,
    _In_ PVOID Unknown2,
    _In_ ULONGLONG Flags
    );

// LdrInitShimEngineDynamic
NTSYSAPI
NTSTATUS
NTAPI
LdrInitShimEngineDynamic(
    _In_ ULONGLONG ImageBase,
    _In_ PVOID ShimData
    );

// LdrRscIsTypeExist
NTSYSAPI
NTSTATUS
NTAPI
LdrRscIsTypeExist(
    _Inout_ PULONG RscContext,
    _In_z_ PCWSTR Type,
    _Reserved_ PVOID Reserved,
    _Inout_ PULONG Flags
    );

// LdrSetAppCompatDllRedirectionCallback
NTSYSAPI
NTSTATUS
NTAPI
LdrSetAppCompatDllRedirectionCallback(
    _In_ PVOID Callback
    );

// LdrSetMUICacheType
NTSYSAPI
NTSTATUS
NTAPI
LdrSetMUICacheType(
    _In_ ULONG MuiCacheType
    );

// RtlTraceDatabaseAdd
NTSYSAPI
BOOLEAN
NTAPI
RtlTraceDatabaseAdd(
    _In_ PRTL_TRACE_DATABASE Database,
    _In_ ULONG Count,
    _In_opt_ PVOID Trace,
    _Out_opt_ PVOID *TraceBlock
    );

// RtlTraceDatabaseCreate
NTSYSAPI
PRTL_TRACE_DATABASE
NTAPI
RtlTraceDatabaseCreate(
    _In_ ULONG Buckets,
    _In_opt_ SIZE_T MaximumSize,
    _In_ ULONG Flags,
    _In_ ULONG Tag,
    _In_opt_ PRTL_TRACE_HASH_FUNCTION HashFunction
    );

// RtlTraceDatabaseDestroy
NTSYSAPI
BOOLEAN
NTAPI
RtlTraceDatabaseDestroy(
    _In_ _Post_invalid_ PRTL_TRACE_DATABASE Database
    );

// RtlTraceDatabaseEnumerate
NTSYSAPI
BOOLEAN
NTAPI
RtlTraceDatabaseEnumerate(
    _In_ PRTL_TRACE_DATABASE Database,
    _Inout_ PVOID Enumerator,
    _Out_opt_ PULONGLONG TraceBlock
    );

// RtlTraceDatabaseFind
NTSYSAPI
BOOLEAN
NTAPI
RtlTraceDatabaseFind(
    _In_ PRTL_TRACE_DATABASE Database,
    _In_ ULONG Count,
    _In_opt_ PVOID Trace,
    _Out_opt_ PVOID *TraceBlock
    );

// RtlTraceDatabaseLock
NTSYSAPI
NTSTATUS
NTAPI
RtlTraceDatabaseLock(
    _In_ PRTL_TRACE_DATABASE Database
    );

// RtlTraceDatabaseUnlock
NTSYSAPI
NTSTATUS
NTAPI
RtlTraceDatabaseUnlock(
    _In_ PRTL_TRACE_DATABASE Database
    );

// RtlTraceDatabaseValidate
NTSYSAPI
BOOLEAN
NTAPI
RtlTraceDatabaseValidate(
    _In_ PRTL_TRACE_DATABASE Database
    );

// RtlQueryUnbiasedInterruptTimePrecise
NTSYSAPI
ULONGLONG
NTAPI
RtlQueryUnbiasedInterruptTimePrecise(
    _Out_ PLARGE_INTEGER InterruptTime
    );

// RtlCancelTimer
NTSYSAPI
NTSTATUS
NTAPI
RtlCancelTimer(
    _In_ HANDLE TimerQueueHandle,
    _In_ HANDLE Handle
    );

// RtlWow64GetCpuAreaEnabledFeatures
NTSYSAPI
ULONGLONG
NTAPI
RtlWow64GetCpuAreaEnabledFeatures(
    _Inout_ PULONG Features
    );

// RtlWow64GetCurrentCpuArea
NTSYSAPI
//NTSTATUS
//NTAPI
//RtlWow64GetCpuAreaInfo(
//    _In_ PWOW64_CPU_AREA_HEADER CpuArea,
//    _In_ USHORT MachineType,
//    _Out_ PWOW64_CPU_AREA_INFO CpuAreaInfo
//    );

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64GetCurrentCpuArea(
    _Out_opt_ PUSHORT MachineType,
    _Out_opt_ PULONGLONG ContextRecordAddress,
    _Out_opt_ PULONGLONG SharedInfoAddress
    );

// RtlWow64GetEquivalentMachineCHPE
NTSYSAPI
SHORT
NTAPI
RtlWow64GetEquivalentMachineCHPE(
    _In_ SHORT MachineType
    );

// RtlWow64LogMessageInEventLogger
NTSYSAPI
//NTSTATUS
//NTAPI
//RtlWow64GetSharedInfoProcess(
//    _In_ HANDLE ProcessHandle,
//    _Out_ PUCHAR IsWow64,
//    _Out_writes_bytes_(0x28) PWOW64_PROCESS_SHARED_INFO SharedInfo
//    );
//
//typedef struct _THREAD_DESCRIPTOR_INFORMATION
//{
//    _In_ ULONG Selector;
//    _Out_ LDT_ENTRY Entry;
//} THREAD_DESCRIPTOR_INFORMATION, *PTHREAD_DESCRIPTOR_INFORMATION;

//
//NTSYSAPI
//NTSTATUS
//NTAPI
//RtlWow64GetThreadSelectorEntry(
//    _In_ HANDLE ThreadHandle,
//    _Inout_ PTHREAD_DESCRIPTOR_INFORMATION SelectorEntry,
//    _In_ ULONG SelectorEntryLength,
//    _Out_opt_ PULONG ReturnLength
//    );

// rev
NTSYSAPI
PVOID
NTAPI
RtlWow64LogMessageInEventLogger(
    _In_ SHORT MessageId,
    _In_ ULONGLONG MessageArg,
    _In_ ULONG Flags
    );

// RtlWow64PopAllCrossProcessWorkFromWorkList
NTSYSAPI
PULONG
NTAPI
RtlWow64PopAllCrossProcessWorkFromWorkList(
    volatile signed __int64 *,
    UCHAR *
    );

// RtlWow64PopCrossProcessWorkFromFreeList
NTSYSAPI
PULONG
NTAPI
RtlWow64PopCrossProcessWorkFromFreeList(
    volatile signed __int64 *
    );

// RtlWow64PushCrossProcessWorkOntoFreeList
NTSYSAPI
BOOLEAN
NTAPI
RtlWow64PushCrossProcessWorkOntoFreeList(
    volatile signed __int64 *,
    ULONG *
    );

// RtlWow64PushCrossProcessWorkOntoWorkList
NTSYSAPI
BOOLEAN
NTAPI
RtlWow64PushCrossProcessWorkOntoWorkList(
    volatile signed __int64 *,
    ULONGLONG,
    PULONGLONG
    );

// RtlWow64RequestCrossProcessHeavyFlush
NTSYSAPI
BOOLEAN
NTAPI
RtlWow64RequestCrossProcessHeavyFlush(
    volatile signed __int64 *
    );

// RtlpQueryProcessDebugInformationFromWow64
NTSYSAPI
NTSTATUS
NTAPI
RtlpQueryProcessDebugInformationFromWow64(
    _In_ ULONG Flags,
    _Inout_ PVOID ProcessInfo
    );

// RtlpWow64CtxFromAmd64
NTSYSAPI
ULONG
NTAPI
RtlpWow64CtxFromAmd64(
    _In_ ULONG ContextFlags,
    _In_ PCONTEXT Amd64Context,
    _Inout_ PWOW64_CONTEXT Wow64Context
    );

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

// RtlpCheckDynamicTimeZoneInformation
NTSYSAPI
BOOLEAN
NTAPI
RtlpCheckDynamicTimeZoneInformation(
    _Inout_ M128A *Buf2,
    _In_ USHORT Year
    );

// RtlpCleanupRegistryKeys
NTSYSAPI
NTSTATUS
NTAPI
RtlpCleanupRegistryKeys(
    void
    );

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

// RtlpCreateProcessRegistryInfo
NTSYSAPI
NTSTATUS
NTAPI
RtlpCreateProcessRegistryInfo(
    _Out_opt_ PVOID *RegistryInfo
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

// RtlpFreezeTimeBias
NTSYSAPI
LONGLONG
NTAPI
RtlpFreezeTimeBias(
    void
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

// RtlpNotOwnerCriticalSection
NTSYSAPI
VOID
NTAPI
RtlpNotOwnerCriticalSection(
    _In_ PRTL_CRITICAL_SECTION CriticalSection
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

// RtlpQueryProcessDebugInformationRemote
NTSYSAPI
VOID
NTAPI
RtlpQueryProcessDebugInformationRemote(
    _Inout_ PRTL_DEBUG_INFORMATION DebugInfo
    );

// RtlpTimeFieldsToTime
NTSYSAPI
BOOLEAN
NTAPI
RtlpTimeFieldsToTime(
    _In_ PTIME_FIELDS TimeFields,
    _Out_ PLARGE_INTEGER Time,
    _In_opt_ PLARGE_INTEGER LeapSecondContext
    );

// RtlpTimeToTimeFields
NTSYSAPI
SHORT
NTAPI
RtlpTimeToTimeFields(
    _In_ PLARGE_INTEGER Time,
    _Out_ PTIME_FIELDS TimeFields,
    _In_opt_ PLARGE_INTEGER LeapSecondContext
    );

// RtlpUnWaitCriticalSection
NTSYSAPI
NTSTATUS
NTAPI
RtlpUnWaitCriticalSection(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
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

// RtlActivateActivationContextUnsafeFast
NTSYSAPI
VOID
NTAPI
RtlActivateActivationContextUnsafeFast(
    _Out_writes_bytes_(0x48) PVOID CallerFrame,
    _In_opt_ PVOID ActivationContext
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

// RtlAllocateActivationContextStack
NTSYSAPI
NTSTATUS
NTAPI
RtlAllocateActivationContextStack(
    _Inout_ PACTIVATION_CONTEXT_STACK* ActivationContextStack
    );

// RtlApplicationVerifierStop
NTSYSAPI
PVOID
NTAPI
RtlApplicationVerifierStop(
    _In_opt_ const VOID *Param1,
    _In_opt_z_ const CHAR *Desc1,
    _In_opt_ const VOID *Param2,
    _In_opt_z_ const CHAR *Desc2,
    _In_opt_ const VOID *Param3,
    _In_opt_z_ const CHAR *Desc3,
    _In_opt_ const VOID *Param4,
    _In_opt_z_ const CHAR *Desc4,
    _In_opt_ const VOID *Param5,
    _In_opt_z_ const CHAR *Desc5
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

// RtlAvlInsertNodeEx
NTSYSAPI
//BOOLEAN
//NTAPI
//RtlAreBitsClearEx(
//    _In_ PRTL_BITMAP_EX BitMapHeader,
//    _In_ ULONGLONG StartingIndex,
//    _In_ ULONGLONG Length
//    );

// rev
NTSYSAPI
char
NTAPI
RtlAvlInsertNodeEx(
    _Inout_ PRTL_BALANCED_NODE *Root,
    _In_opt_ PRTL_BALANCED_NODE Parent,
    _In_ BOOLEAN Right,
    _In_ PRTL_BALANCED_NODE Node
    );

// RtlCallEnclave
NTSYSAPI
NTSTATUS
NTAPI
RtlCallEnclave(
    _In_ PVOID Routine,
    _In_opt_ PVOID Reserved,
    _In_ ULONG Flags,
    _Out_ PVOID *ReturnValue
    );

// RtlCallEnclaveReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlCallEnclaveReturn(
    void
    );

// RtlCanonicalizeDomainName
NTSYSAPI
NTSTATUS
NTAPI
RtlCanonicalizeDomainName(
    _Out_ PUNICODE_STRING DestinationName,
    _In_ PCUNICODE_STRING SourceName,
    _In_ BOOLEAN AllowInvalidLabels
    );

// RtlCapabilityCheckForSingleSessionSku
NTSYSAPI
NTSTATUS
NTAPI
RtlCapabilityCheckForSingleSessionSku(
    _In_ PVOID TokenHandle,
    _In_ PCUNICODE_STRING CapabilityName,
    _Out_ PBOOLEAN IsCapable
    );

// RtlCheckSystemBootStatusIntegrity
NTSYSAPI
NTSTATUS
NTAPI
RtlCheckSystemBootStatusIntegrity(
    _In_ PVOID BootStatusContext
    );

// RtlClearThreadWorkOnBehalfTicket
NTSYSAPI
NTSTATUS
NTAPI
RtlClearThreadWorkOnBehalfTicket(
    VOID
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

// RtlConstructCrossVmEventPath
NTSYSAPI
NTSTATUS
NTAPI
RtlConstructCrossVmEventPath(
    _In_ PCUNICODE_STRING ObjectPath,
    _In_ const GUID *Guid1,
    _In_ const GUID *Guid2
    );

// RtlConstructCrossVmMutexPath
NTSYSAPI
NTSTATUS
NTAPI
RtlConstructCrossVmMutexPath(
    _In_ PCUNICODE_STRING ObjectPath,
    _In_ const GUID *Guid1,
    _In_ const GUID *Guid2
    );

// RtlDeactivateActivationContextUnsafeFast
NTSYSAPI
//ULONG
//NTAPI
//RtlConvertDeviceFamilyInfoToString(
//    _Inout_ PULONG DeviceFamilyBufferSize,
//    _Inout_ PULONG DeviceFormBufferSize,
//    _Out_writes_bytes_opt_(*DeviceFamilyBufferSize) PWSTR DeviceFamily,
//    _Out_writes_bytes_opt_(*DeviceFormBufferSize) PWSTR DeviceForm
//    );
//
//NTSYSAPI
//VOID
//NTAPI
//RtlGetDeviceFamilyInfoEnum(
//    _Out_opt_ PULONGLONG UapInfo,
//    _Out_opt_ PULONG DeviceFamily,
//    _Out_opt_ PULONG DeviceForm
//    );

// rev
NTSYSAPI
VOID
NTAPI
RtlDeactivateActivationContextUnsafeFast(
    _Inout_updates_bytes_(0x48) PVOID CallerFrame
    );

// RtlConvertHostPerfCounterToPerfCounter
NTSYSAPI
NTSTATUS
NTAPI
RtlConvertHostPerfCounterToPerfCounter(
    _In_ ULONGLONG HostCounter,
    _In_ ULONGLONG MaxDelta,
    _Out_ ULONGLONG *PerfCounterOut
    );

// RtlCreateSystemVolumeInformationFolder
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateSystemVolumeInformationFolder(
    _In_ PCUNICODE_STRING RootPath
    );

// RtlCreateUserFiberShadowStack
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserFiberShadowStack(
    _In_ PVOID ShadowStackInfo,
    _In_ ULONGLONG ReserveSize,
    _Out_ PVOID *ShadowStackOut
    );

// RtlDisownModuleHeapAllocation
NTSYSAPI
NTSTATUS
NTAPI
RtlDisownModuleHeapAllocation(
    void
    );

// RtlEnclaveCallDispatchReturn
NTSYSAPI
//ULONG
//NTAPI
//RtlDrainNonVolatileFlush(
//    _In_ PVOID NvToken
//    );

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlEnclaveCallDispatchReturn(
    _In_ PVOID EnclaveTarget,
    _In_opt_ PVOID LeafRoutine,
    _In_ ULONG LeafNumber,
    _Inout_opt_ PVOID *DispatchContext
    );

// RtlExtendMemoryZone
NTSYSAPI
//PSTR
//NTAPI
//RtlEthernetAddressToStringA(
//    _In_reads_(6) const UCHAR *Addr,
//    _Out_writes_(18) PSTR S
//    );
//
//NTSYSAPI
//PWSTR
//NTAPI
//RtlEthernetAddressToStringW(
//    _In_reads_(6) const UCHAR *Addr,
//    _Out_writes_(18) PWSTR S
//    );
//
//NTSYSAPI
//LONG
//NTAPI
//RtlEthernetStringToAddressA(
//    _In_z_ PCSTR S,
//    _Outptr_ PCSTR *Terminator,
//    _Out_writes_(6) UCHAR *Addr
//    );
//
//NTSYSAPI
//LONG
//NTAPI
//RtlEthernetStringToAddressW(
//    _In_z_ PCWSTR S,
//    _Outptr_ PCWSTR *Terminator,
//    _Out_writes_(6) UCHAR *Addr
//    );
//
//NTSYSAPI
//ULONG
//NTAPI
//RtlExtendCorrelationVector(
//    _Inout_ PVOID CorrelationVector
//    );

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlExtendMemoryZone(
    _Inout_ PVOID MemoryZone,
    _In_ SIZE_T RequestedSize
    );

// RtlFreeActivationContextStack
NTSYSAPI
//ULONG
//NTAPI
//RtlFillNonVolatileMemory(
//    _In_ PVOID NvToken,
//    _Out_writes_bytes_(Size) PVOID NvDestination,
//    _In_ SIZE_T Size,
//    _In_ BYTE Value,
//    _In_ ULONG Flags
//    );

// rev
NTSYSAPI
VOID
NTAPI
RtlFreeActivationContextStack(
    _Inout_opt_ PACTIVATION_CONTEXT_STACK ActivationContextStack
    );

// RtlFreeThreadActivationContextStack
NTSYSAPI
//NTSTATUS
//NTAPI
//RtlFlushNonVolatileMemory(
//    _In_ UCHAR NvToken,
//    _In_ PVOID BaseAddress,
//    _In_ SIZE_T Length,
//    _In_ UCHAR Flags
//    );
//
//NTSYSAPI
//NTSTATUS
//NTAPI
//RtlFlushNonVolatileMemoryRanges(
//    _In_ UCHAR NvToken,
//    _In_reads_(PairCount) const ULONGLONG *AddressLengthPairs,
//    _In_ SIZE_T PairCount,
//    _In_ UCHAR Flags
//    );

// NTSYSAPI
// NTSTATUS
// NTAPI
// RtlFreeNonVolatileToken(
//     _In_ PVOID NvToken
//     );

// rev
NTSYSAPI
VOID
NTAPI
RtlFreeThreadActivationContextStack(
    void
    );

// RtlFreeUserFiberShadowStack
NTSYSAPI
NTSTATUS
NTAPI
RtlFreeUserFiberShadowStack( // NtSetInformationProcess(ProcessFreeFiberShadowStackAllocation)
    _In_ PVOID AllocationBase
    );

// RtlGetFeatureToggleConfiguration
NTSYSAPI
ULONGLONG
NTAPI
RtlGetFeatureToggleConfiguration(
    _In_ ULONG FeatureId,
    _In_ ULONGLONG ConfigurationType
    );

// RtlGetThreadWorkOnBehalfTicket
NTSYSAPI
//ULONG
//NTAPI
//RtlGetNonVolatileToken(
//    _In_ PVOID NvBuffer,
//    _In_ SIZE_T Size,
//    _Outptr_ PVOID *NvToken
//    );
//
//NTSYSAPI
//NTSTATUS
//NTAPI
//RtlGetThreadLangIdByIndex(
//    _In_ ULONG Flags,
//    _In_ ULONG Index,
//    _Out_ PULONG LangId,
//    _Out_opt_ PULONG TotalLanguages
//    );

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlGetThreadWorkOnBehalfTicket(
    _Out_ PULONGLONG Ticket,
    _In_ ULONG Flags
    );

// RtlGetSystemBootStatusEx
NTSYSAPI
NTSTATUS
NTAPI
RtlGetSystemBootStatusEx(
    _Out_writes_bytes_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength,
    _Out_opt_ PULONG ReturnLength
    );

// RtlHeapTrkInitialize
NTSYSAPI
NTSTATUS
NTAPI
RtlHeapTrkInitialize(
    _In_ HANDLE SectionHandle
    );

// RtlInitializeRXact
NTSYSAPI
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

// RtlInitializeAtomPackage
NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeAtomPackage(
    _In_opt_ PVOID Callback
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

// RtlIsFeatureEnabledForEnterprise
NTSYSAPI
BOOLEAN
NTAPI
RtlIsFeatureEnabledForEnterprise(
    _In_ ULONG FeatureId
    );

// RtlIsNameLegalDOS8Dot3
NTSYSAPI
BOOLEAN
NTAPI
RtlIsNameLegalDOS8Dot3(
    _In_ PCUNICODE_STRING Name,
    _Out_opt_ POEM_STRING OemName,
    _Out_opt_ PBOOLEAN NameContainsSpaces
    );

// RtlLogStackBackTrace
NTSYSAPI
//ULONGLONG
//NTAPI
//RtlLengthCurrentClearRunBackwardEx(
//    _In_ PRTL_BITMAP_EX BitMapHeader,
//    _In_ ULONGLONG StartingIndex,
//    _In_ ULONGLONG MaximumLength
//    );
//
//NTSYSAPI
//ULONGLONG
//NTAPI
//RtlLengthCurrentClearRunForwardEx(
//    _In_ PRTL_BITMAP_EX BitMapHeader,
//    _In_ ULONGLONG StartingIndex,
//    _In_ ULONGLONG MaximumLength
//    );

// rev
NTSYSAPI
ULONG
NTAPI
RtlLogStackBackTrace(
    void
    );

// RtlLogUnexpectedCodepath
NTSYSAPI
NTSTATUS
NTAPI
RtlLogUnexpectedCodepath(
    void
    );

// RtlpConvertAbsoluteToRelativeSecurityAttribute
NTSYSAPI
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

// RtlOpenCrossProcessEmulatorWorkConnection
NTSYSAPI
// PVOID
// NTAPI
// RtlMoveMemory(
//     _Out_writes_bytes_all_(Length) PVOID Destination,
//     _In_reads_bytes_(Length) const VOID *Source,
//     _In_ SIZE_T Length
//     );

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlOpenCrossProcessEmulatorWorkConnection(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE SectionHandle,
    _Outptr_ PVOID *ViewBase
    );

// RtlQueryDynamicTimeZoneInformation
NTSYSAPI
// ULONG
// NTAPI
// RtlOsDeploymentState(
//     _In_ ULONG Flags
//     );

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryDynamicTimeZoneInformation(
    _Out_ PVOID DynamicTimeZoneInformation
    );

// RtlQueryInternalFeatureConfiguration
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryInternalFeatureConfiguration(
    _In_ ULONGLONG FeatureId,
    _In_ ULONG QueryFlags,
    _Out_opt_ PULONGLONG ChangeStamp,
    _Out_ PVOID FeatureConfiguration
    );

// RtlQueryModuleInformation
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryModuleInformation(
    _Inout_ PULONG BufferSize,
    _In_ ULONG UnitSize, // RTL_QUERY_MODULE_INFORMATION_RECORD_SIZE_*
    _Out_writes_bytes_opt_(*BufferSize) PVOID ModuleInformation
    );

// RtlQueryResourcePolicy
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryResourcePolicy(
    _In_ RTL_RESOURCE_POLICY_CLASS PolicyClass,
    _Reserved_ ULONG Reserved,
    _Out_ PULONG PolicyValue,
    _In_ ULONG ValueSize
    );

// RtlRegisterForWnfMetaNotification
NTSYSAPI
//ULONG
//NTAPI
//RtlRaiseCustomSystemEventTrigger(
//    _In_ PVOID TriggerConfig
//    );

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlRegisterForWnfMetaNotification(
    _Out_ PULONGLONG SubscriptionHandle,
    _In_opt_ PVOID Callback,
    _In_ ULONG DeliveryFlags,
    _In_ ULONG CallbackFlags,
    _In_opt_ PVOID CallbackContext
    );

// RtlReportSqmEscalation
NTSYSAPI
NTSTATUS
NTAPI
RtlReportSqmEscalation(
    _In_ PVOID Callback
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

// RtlSetDynamicTimeZoneInformation
NTSYSAPI
NTSTATUS
NTAPI
RtlSetDynamicTimeZoneInformation(
    _In_ PDYNAMIC_TIME_ZONE_INFORMATION DynamicTimeZoneInformation
    );

// RtlSetSystemBootStatusEx
NTSYSAPI
NTSTATUS
NTAPI
RtlSetSystemBootStatusEx(
    _In_ PVOID Buffer,
    _In_ ULONG BufferLength,
    _In_opt_ PVOID Reserved
    );

// RtlSetThreadWorkOnBehalfTicket
NTSYSAPI
NTSTATUS
NTAPI
RtlSetThreadWorkOnBehalfTicket(
    _In_ PULONGLONG Ticket
    );

// RtlStartRXact
NTSYSAPI
NTSTATUS
NTAPI
RtlStartRXact(
    _Inout_ PVOID RxactContext
    );

// RtlTestAndPublishWnfStateData
NTSYSAPI
//ULONG
//NTAPI
//RtlSwitchedVVI(
//    _In_ PRTL_OSVERSIONINFOEXW VersionInfo,
//    _In_ ULONG TypeMask,
//    _In_ ULONGLONG ConditionMask
//    );

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlTestAndPublishWnfStateData(
    _In_ ULONGLONG StateName,
    _In_opt_ PVOID TypeId,
    _In_reads_bytes_opt_(BufferSize) const VOID *Buffer,
    _In_ ULONG BufferSize,
    _In_opt_ PVOID ExplicitScope,
    _In_ ULONG MatchingChangeStamp
    );

// RtlTryConvertSRWLockSharedToExclusiveOrRelease
NTSYSAPI
BOOLEAN
NTAPI
RtlTryConvertSRWLockSharedToExclusiveOrRelease(
    _Inout_ volatile RTL_SRWLOCK *SRWLock
    );

// RtlUdiv128
NTSYSAPI
ULONGLONG
NTAPI
RtlUdiv128(
    _In_ ULONGLONG DividendHigh,
    _In_ ULONGLONG DividendLow,
    _In_ ULONGLONG Divisor,
    _Out_opt_ PLONGLONG Remainder
    );

// RtlUmsThreadYield
NTSYSAPI
NTSTATUS
NTAPI
RtlUmsThreadYield(
    void
    );

// RtlUserFiberStart
NTSYSAPI
//VOID
//NTAPI
//RtlUnwindEx(
//    void
//    );

// rev
DECLSPEC_NORETURN
NTSYSAPI
VOID
NTAPI
RtlUserFiberStart(
    void
    );

// RtlWaitForWnfMetaNotification
NTSYSAPI
//ULONG
//NTAPI
//RtlValidateCorrelationVector(
//    _In_ PVOID CorrelationVector
//    );
//
//NTSYSAPI
//PEXCEPTION_ROUTINE
//NTAPI
//RtlVirtualUnwind(
//    _In_ ULONG HandlerType,
//    _In_ ULONGLONG ImageBase,
//    _In_ ULONGLONG ControlPc,
//    _In_ PRUNTIME_FUNCTION FunctionEntry,
//    _Inout_ PCONTEXT ContextRecord,
//    _Outptr_ PVOID *HandlerData,
//    _Out_ PULONGLONG EstablisherFrame,
//    _Inout_opt_ PVOID ContextPointers
//    );
//
//NTSYSAPI
//NTSTATUS
//NTAPI
//RtlVirtualUnwind2(
//    _In_ ULONG HandlerType,
//    _In_ ULONGLONG ImageBase,
//    _In_ char *ControlPc,
//    _In_ PULONG FunctionEntry,
//    _Inout_ PULONG ContextRecord,
//    _Inout_opt_ PUCHAR UnwindHistoryTable,
//    _Inout_opt_ PULONGLONG HandlerData,
//    _Inout_opt_ char ***EstablisherFrame,
//    _In_opt_ PVOID ContextPointers,
//    _In_opt_ PVOID Reserved1,
//    _In_opt_ PVOID Reserved2,
//    _Inout_opt_ PULONGLONG MachineFrameUnwound,
//    _In_ ULONG Flags
//    );

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlWaitForWnfMetaNotification(
    _In_ ULONGLONG StateName,
    _In_ ULONG WaitFlags,
    _In_ ULONG TimeoutMs,
    _In_opt_ PVOID Reserved,
    _Out_ PINT ResultFlags
    );

// RtlXRestore
NTSYSAPI
//ULONG
//NTAPI
//RtlWriteNonVolatileMemory(
//    _In_ PVOID NvToken,
//    _Out_writes_bytes_(Size) PVOID NvDestination,
//    _In_reads_bytes_(Size) const VOID *Source,
//    _In_ SIZE_T Size,
//    _In_ ULONG Flags
//    );

// rev
NTSYSAPI
ULONGLONG
NTAPI
RtlXRestore(
    _In_ PVOID XStateContext,
    _In_ ULONGLONG FeatureMask
    );

// RtlXSave
NTSYSAPI
ULONGLONG
NTAPI
RtlXSave(
    _Inout_ PULONG XStateContext,
    _In_ ULONGLONG FeatureMask
    );

// RtlAllocateWnfSerializationGroup
NTSYSAPI
ULONG
NTAPI
RtlAllocateWnfSerializationGroup(
    void
    );

// RtlQueryWnfMetaNotification
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryWnfMetaNotification(
    _Out_ PULONG Result,
    _In_ WNF_STATE_NAME_INFORMATION NameInfoClass,
    _In_ WNF_STATE_NAME StateName,
    _In_opt_ PCSID ExplicitScope
    );

// RtlQueryWnfStateDataWithExplicitScope
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryWnfStateDataWithExplicitScope(
    _Out_ PULONG ChangeStamp,
    _In_ ULONGLONG StateName,
    _In_opt_ const VOID *ExplicitScope,
    _In_ NTSTATUS (NTAPI *TypeDecoder)(_In_ ULONGLONG, _In_ ULONGLONG, _In_ ULONGLONG, _In_ ULONGLONG, _In_reads_bytes_(BufferLength) UCHAR *, _In_ ULONG BufferLength),
    _In_ ULONGLONG CallbackContext,
    _In_opt_ const VOID *TypeId
    );

// RtlUnsubscribeWnfNotificationWaitForCompletion
NTSYSAPI
NTSTATUS
NTAPI
RtlUnsubscribeWnfNotificationWaitForCompletion(
    _In_ HANDLE SubscriptionHandle
    );

// RtlUnsubscribeWnfNotificationWithCompletionCallback
NTSYSAPI
NTSTATUS
NTAPI
RtlUnsubscribeWnfNotificationWithCompletionCallback(
    _In_ HANDLE SubscriptionHandle,
    _In_opt_ PVOID CompletionCallback,
    _In_opt_ PVOID CompletionContext
    );

EXTERN_C_END

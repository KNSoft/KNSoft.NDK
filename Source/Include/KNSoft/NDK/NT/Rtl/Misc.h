﻿#pragma once

#include "../MinDef.h"
#include "../Io/Info.h"
#include "../Ex/Wnf.h"

#include <minwinbase.h>

EXTERN_C_START

/* phnt */

#pragma region Thread Profiling

NTSYSAPI
NTSTATUS
NTAPI
RtlEnableThreadProfiling(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG Flags,
    _In_ ULONG64 HardwareCounters,
    _Out_ PVOID* PerformanceDataHandle);

NTSYSAPI
NTSTATUS
NTAPI
RtlDisableThreadProfiling(
    _In_ PVOID PerformanceDataHandle);

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryThreadProfiling(
    _In_ HANDLE ThreadHandle,
    _Out_ PBOOLEAN Enabled);

NTSYSAPI
NTSTATUS
NTAPI
RtlReadThreadProfilingData(
    _In_ HANDLE PerformanceDataHandle,
    _In_ ULONG Flags,
    _Out_ PPERFORMANCE_DATA PerformanceData);

#pragma endregion

#pragma region Timer

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateTimerQueue(
    _Out_ PHANDLE TimerQueueHandle);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateTimer(
    _In_ HANDLE TimerQueueHandle,
    _Out_ PHANDLE Handle,
    _In_ WAITORTIMERCALLBACKFUNC Function,
    _In_opt_ PVOID Context,
    _In_ ULONG DueTime,
    _In_ ULONG Period,
    _In_ ULONG Flags);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetTimer(
    _In_ HANDLE TimerQueueHandle,
    _Out_ PHANDLE Handle,
    _In_ WAITORTIMERCALLBACKFUNC Function,
    _In_opt_ PVOID Context,
    _In_ ULONG DueTime,
    _In_ ULONG Period,
    _In_ ULONG Flags);

NTSYSAPI
NTSTATUS
NTAPI
RtlUpdateTimer(
    _In_ HANDLE TimerQueueHandle,
    _In_ HANDLE TimerHandle,
    _In_ ULONG DueTime,
    _In_ ULONG Period);

#define RTL_TIMER_DELETE_WAIT_FOR_COMPLETION ((HANDLE)(LONG_PTR)-1)

NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteTimer(
    _In_ HANDLE TimerQueueHandle,
    _In_ HANDLE TimerToCancel,
    _In_opt_ HANDLE Event // optional: RTL_TIMER_DELETE_WAIT_FOR_COMPLETION
);

NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteTimerQueue(
    _In_ HANDLE TimerQueueHandle);

NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteTimerQueueEx(
    _In_ HANDLE TimerQueueHandle,
    _In_opt_ HANDLE Event);

#pragma endregion

#pragma region QPC

NTSYSAPI
LOGICAL
NTAPI
RtlQueryPerformanceCounter(
    _Out_ PLARGE_INTEGER PerformanceCounter);

NTSYSAPI
LOGICAL
NTAPI
RtlQueryPerformanceFrequency(
    _Out_ PLARGE_INTEGER PerformanceFrequency);

#pragma endregion

#pragma region Transactions

NTSYSAPI
HANDLE
NTAPI
RtlGetCurrentTransaction(
    _In_opt_ PCWSTR ExistingFileName,
    _In_opt_ PCWSTR NewFileName);

NTSYSAPI
LOGICAL
NTAPI
RtlSetCurrentTransaction(
    _In_opt_ HANDLE TransactionHandle);

#pragma endregion

#pragma region Pointer Encode/Decode

NTSYSAPI
PVOID
NTAPI
RtlEncodePointer(
    _In_ PVOID Ptr);

NTSYSAPI
PVOID
NTAPI
RtlDecodePointer(
    _In_ PVOID Ptr);

NTSYSAPI
PVOID
NTAPI
RtlEncodeSystemPointer(
    _In_ PVOID Ptr);

NTSYSAPI
PVOID
NTAPI
RtlDecodeSystemPointer(
    _In_ PVOID Ptr);

#if (NTDDI_VERSION >= NTDDI_WIN10)

NTSYSAPI
NTSTATUS
NTAPI
RtlEncodeRemotePointer(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID Pointer,
    _Out_ PVOID* EncodedPointer);

NTSYSAPI
NTSTATUS
NTAPI
RtlDecodeRemotePointer(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID Pointer,
    _Out_ PVOID* DecodedPointer);

#endif

#pragma endregion

#pragma region Session

NTSYSAPI
ULONG
NTAPI
RtlGetCurrentServiceSessionId(VOID);

NTSYSAPI
ULONG
NTAPI
RtlGetActiveConsoleId(VOID);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
NTSYSAPI
LONGLONG
NTAPI
RtlGetConsoleSessionForegroundProcessId(VOID);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN11_ZN)
NTSYSAPI
NTSTATUS
NTAPI
RtlGetSessionProperties(
    _In_ ULONG SessionId,
    _Out_ PULONG SharedUserSessionId);
#endif

#pragma endregion

#pragma region Lock/Unlock TEB/Stack/Module Section

NTSYSAPI
NTSTATUS
NTAPI
RtlLockCurrentThread(VOID);

NTSYSAPI
NTSTATUS
NTAPI
RtlUnlockCurrentThread(VOID);

NTSYSAPI
NTSTATUS
NTAPI
RtlLockModuleSection(
    _In_ PVOID Address);

NTSYSAPI
NTSTATUS
NTAPI
RtlUnlockModuleSection(
    _In_ PVOID Address);

#pragma endregion

#pragma region Place Holder

#if (NTDDI_VERSION >= NTDDI_WIN10_RS3)

NTSYSAPI
BOOLEAN
NTAPI
RtlIsCloudFilesPlaceholder(
    _In_ ULONG FileAttributes,
    _In_ ULONG ReparseTag);

NTSYSAPI
BOOLEAN
NTAPI
RtlIsPartialPlaceholder(
    _In_ ULONG FileAttributes,
    _In_ ULONG ReparseTag);

NTSYSAPI
NTSTATUS
NTAPI
RtlIsPartialPlaceholderFileHandle(
    _In_ HANDLE FileHandle,
    _Out_ PBOOLEAN IsPartialPlaceholder);

NTSYSAPI
NTSTATUS
NTAPI
RtlIsPartialPlaceholderFileInfo(
    _In_ PVOID InfoBuffer,
    _In_ FILE_INFORMATION_CLASS InfoClass,
    _Out_ PBOOLEAN IsPartialPlaceholder);

#undef PHCM_MAX
#define PHCM_APPLICATION_DEFAULT ((CHAR)0)
#define PHCM_DISGUISE_PLACEHOLDERS ((CHAR)1)
#define PHCM_EXPOSE_PLACEHOLDERS ((CHAR)2)
#define PHCM_MAX ((CHAR)2)

#define PHCM_ERROR_INVALID_PARAMETER ((CHAR)-1)
#define PHCM_ERROR_NO_TEB ((CHAR)-2)

NTSYSAPI
CHAR
NTAPI
RtlQueryThreadPlaceholderCompatibilityMode(VOID);

NTSYSAPI
CHAR
NTAPI
RtlSetThreadPlaceholderCompatibilityMode(
    _In_ CHAR Mode);

#endif

#undef PHCM_MAX
#define PHCM_DISGUISE_FULL_PLACEHOLDERS ((CHAR)3)
#define PHCM_MAX ((CHAR)3)
#define PHCM_ERROR_NO_PEB ((CHAR)-3)

#if (NTDDI_VERSION >= NTDDI_WIN10_RS4)

NTSYSAPI
CHAR
NTAPI
RtlQueryProcessPlaceholderCompatibilityMode(VOID);

NTSYSAPI
CHAR
NTAPI
RtlSetProcessPlaceholderCompatibilityMode(
    _In_ CHAR Mode);

#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
NTSYSAPI
BOOLEAN
NTAPI
RtlIsNonEmptyDirectoryReparsePointAllowed(
    _In_ ULONG ReparseTag);
#endif

#pragma endregion

#pragma region AppX

#if (NTDDI_VERSION >= NTDDI_WIN8)
NTSYSAPI
NTSTATUS
NTAPI
RtlAppxIsFileOwnedByTrustedInstaller(
    _In_ HANDLE FileHandle,
    _Out_ PBOOLEAN IsFileOwnedByTrustedInstaller);
#endif

// Windows Internals book
#define PSM_ACTIVATION_TOKEN_PACKAGED_APPLICATION       0x00000001UL // AppX package format
#define PSM_ACTIVATION_TOKEN_SHARED_ENTITY              0x00000002UL // Shared token, multiple binaries in the same package
#define PSM_ACTIVATION_TOKEN_FULL_TRUST                 0x00000004UL // Trusted (Centennial), converted Win32 application
#define PSM_ACTIVATION_TOKEN_NATIVE_SERVICE             0x00000008UL // Packaged service created by SCM
//#define PSM_ACTIVATION_TOKEN_DEVELOPMENT_APP          0x00000010UL
#define PSM_ACTIVATION_TOKEN_MULTIPLE_INSTANCES_ALLOWED 0x00000010UL
#define PSM_ACTIVATION_TOKEN_BREAKAWAY_INHIBITED        0x00000020UL // Cannot create non-packaged child processes
#define PSM_ACTIVATION_TOKEN_RUNTIME_BROKER             0x00000040UL // rev
#define PSM_ACTIVATION_TOKEN_UNIVERSAL_CONSOLE          0x00000200UL // rev
#define PSM_ACTIVATION_TOKEN_WIN32ALACARTE_PROCESS      0x00010000UL // rev

// PackageOrigin appmodel.h
//#define PackageOrigin_Unknown           0
//#define PackageOrigin_Unsigned          1
//#define PackageOrigin_Inbox             2
//#define PackageOrigin_Store             3
//#define PackageOrigin_DeveloperUnsigned 4
//#define PackageOrigin_DeveloperSigned   5
//#define PackageOrigin_LineOfBusiness    6

#define PSMP_MINIMUM_SYSAPP_CLAIM_VALUES 2
#define PSMP_MAXIMUM_SYSAPP_CLAIM_VALUES 4

typedef struct _PS_PKG_CLAIM
{
    ULONG Flags;  // PSM_ACTIVATION_TOKEN_*
    ULONG Origin; // PackageOrigin
} PS_PKG_CLAIM, *PPS_PKG_CLAIM;

#if (NTDDI_VERSION >= NTDDI_WIN10)
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryPackageClaims(
    _In_ HANDLE TokenHandle,
    _Out_writes_bytes_to_opt_(*PackageSize, *PackageSize) PWSTR PackageFullName,
    _Inout_opt_ PSIZE_T PackageSize,
    _Out_writes_bytes_to_opt_(*AppIdSize, *AppIdSize) PWSTR AppId,
    _Inout_opt_ PSIZE_T AppIdSize,
    _Out_opt_ PGUID DynamicId,
    _Out_opt_ PPS_PKG_CLAIM PkgClaim,
    _Out_opt_ PULONG64 AttributesPresent);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN8)
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryPackageIdentity(
    _In_ HANDLE TokenHandle,
    _Out_writes_bytes_to_(*PackageSize, *PackageSize) PWSTR PackageFullName,
    _Inout_ PSIZE_T PackageSize,
    _Out_writes_bytes_to_opt_(*AppIdSize, *AppIdSize) PWSTR AppId,
    _Inout_opt_ PSIZE_T AppIdSize,
    _Out_opt_ PBOOLEAN Packaged);
#endif

#if (NTDDI_VERSION >= NTDDI_WINBLUE)
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryPackageIdentityEx(
    _In_ HANDLE TokenHandle,
    _Out_writes_bytes_to_(*PackageSize, *PackageSize) PWSTR PackageFullName,
    _Inout_ PSIZE_T PackageSize,
    _Out_writes_bytes_to_opt_(*AppIdSize, *AppIdSize) PWSTR AppId,
    _Inout_opt_ PSIZE_T AppIdSize,
    _Out_opt_ PGUID DynamicId,
    _Out_opt_ PULONG64 Flags);
#endif

#pragma endregion

#pragma region Wnf

#if (NTDDI_VERSION >= NTDDI_WIN10)

#define WNF_STATE_KEY 0x41C64E6DA3BC0074

_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlEqualWnfChangeStamps(
    _In_ WNF_CHANGE_STAMP ChangeStamp1,
    _In_ WNF_CHANGE_STAMP ChangeStamp2
);

_Always_(_Post_satisfies_(return == STATUS_NO_MEMORY || return == STATUS_RETRY || return == STATUS_SUCCESS))
typedef _Function_class_(WNF_USER_CALLBACK)
NTSTATUS NTAPI WNF_USER_CALLBACK(
    _In_ WNF_STATE_NAME StateName,
    _In_ WNF_CHANGE_STAMP ChangeStamp,
    _In_opt_ PWNF_TYPE_ID TypeId,
    _In_opt_ PVOID CallbackContext,
    _In_reads_bytes_opt_(Length) const VOID* Buffer,
    _In_ ULONG Length
);
typedef WNF_USER_CALLBACK *PWNF_USER_CALLBACK;

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryWnfStateData(
    _Out_ PWNF_CHANGE_STAMP ChangeStamp,
    _In_ WNF_STATE_NAME StateName,
    _In_ PWNF_USER_CALLBACK Callback,
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PWNF_TYPE_ID TypeId
);

NTSYSAPI
NTSTATUS
NTAPI
RtlPublishWnfStateData(
    _In_ WNF_STATE_NAME StateName,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_reads_bytes_opt_(Length) const VOID * Buffer,
    _In_opt_ ULONG Length,
    _In_opt_ const VOID * ExplicitScope
);

NTSYSAPI
NTSTATUS
NTAPI
RtlSubscribeWnfStateChangeNotification(
    _Outptr_ PVOID * SubscriptionHandle, // PWNF_USER_SUBSCRIPTION
    _In_ WNF_STATE_NAME StateName,
    _In_ WNF_CHANGE_STAMP ChangeStamp,
    _In_ PWNF_USER_CALLBACK Callback,
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_opt_ ULONG SerializationGroup,
    _Reserved_ ULONG Flags
);

NTSYSAPI
NTSTATUS
NTAPI
RtlUnsubscribeWnfStateChangeNotification(
    _In_ PWNF_USER_CALLBACK Callback
);

NTSYSAPI
NTSTATUS
NTAPI
RtlWnfDllUnloadCallback(
    _In_ PVOID DllBase
);

#endif

#pragma endregion

#pragma region Unload Event Trace

#define RTL_UNLOAD_EVENT_TRACE_NUMBER 64

typedef struct _RTL_UNLOAD_EVENT_TRACE
{
    PVOID BaseAddress;
    ULONG_PTR SizeOfImage;
    ULONG Sequence;
    ULONG TimeDateStamp;
    ULONG CheckSum;
    WCHAR ImageName[32];
    ULONG Version[2];
} RTL_UNLOAD_EVENT_TRACE, *PRTL_UNLOAD_EVENT_TRACE;

typedef struct _RTL_UNLOAD_EVENT_TRACE64
{
    VOID* POINTER_64 BaseAddress;
    ULONGLONG SizeOfImage;
    ULONG Sequence;
    ULONG TimeDateStamp;
    ULONG CheckSum;
    WCHAR ImageName[32];
    ULONG Version[2];
} RTL_UNLOAD_EVENT_TRACE64, *PRTL_UNLOAD_EVENT_TRACE64;

typedef struct _RTL_UNLOAD_EVENT_TRACE32
{
    VOID* POINTER_32 BaseAddress;
    ULONG SizeOfImage;
    ULONG Sequence;
    ULONG TimeDateStamp;
    ULONG CheckSum;
    WCHAR ImageName[32];
    ULONG Version[2];
} RTL_UNLOAD_EVENT_TRACE32, *PRTL_UNLOAD_EVENT_TRACE32;

NTSYSAPI
PRTL_UNLOAD_EVENT_TRACE
NTAPI
RtlGetUnloadEventTrace(VOID);

NTSYSAPI
PRTL_UNLOAD_EVENT_TRACE
NTAPI
RtlGetUnloadEventTraceEx(
    _Out_ PULONG * ElementSize,
    _Out_ PULONG * ElementCount,
    _Out_ PVOID * EventTrace // works across all processes
);

#pragma endregion

#pragma region State Isolation

typedef enum _STATE_LOCATION_TYPE
{
    LocationTypeRegistry,
    LocationTypeFileSystem,
    LocationTypeMaximum
} STATE_LOCATION_TYPE, *PSTATE_LOCATION_TYPE;

#if (NTDDI_VERSION >= NTDDI_WIN10_RS3)

NTSYSAPI
BOOLEAN
NTAPI
RtlIsStateSeparationEnabled(VOID);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetPersistedStateLocation(
    _In_ PCWSTR SourceID,
    _In_opt_ PCWSTR CustomValue,
    _In_opt_ PCWSTR DefaultPath,
    _In_ STATE_LOCATION_TYPE StateLocationType,
    _Out_writes_bytes_to_opt_(BufferLengthIn, *BufferLengthOut) PWCHAR TargetPath,
    _In_ ULONG BufferLengthIn,
    _Out_opt_ PULONG BufferLengthOut);

#endif

#pragma region Property Store

#if (NTDDI_VERSION >= NTDDI_WIN11_ZN)

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryPropertyStore(
    _In_ ULONG_PTR Key,
    _Out_ PULONG_PTR Context);

NTSYSAPI
NTSTATUS
NTAPI
RtlRemovePropertyStore(
    _In_ ULONG_PTR Key,
    _Out_ PULONG_PTR Context);

NTSYSAPI
NTSTATUS
NTAPI
RtlCompareExchangePropertyStore(
    _In_ ULONG_PTR Key,
    _In_ PULONG_PTR Comperand,
    _In_opt_ PULONG_PTR Exchange,
    _Out_ PULONG_PTR Context);

#endif

#pragma endregion

#pragma region Thread Pool (Old)

NTSYSAPI
NTSTATUS
NTAPI
RtlRegisterWait(
    _Out_ PHANDLE WaitHandle,
    _In_ HANDLE Handle,
    _In_ WAITORTIMERCALLBACKFUNC Function,
    _In_opt_ PVOID Context,
    _In_ ULONG Milliseconds,
    _In_ ULONG Flags);

NTSYSAPI
NTSTATUS
NTAPI
RtlDeregisterWait(
    _In_ HANDLE WaitHandle);

#define RTL_WAITER_DEREGISTER_WAIT_FOR_COMPLETION ((HANDLE)(LONG_PTR)-1)

NTSYSAPI
NTSTATUS
NTAPI
RtlDeregisterWaitEx(
    _In_ HANDLE WaitHandle,
    _In_opt_ HANDLE CompletionEvent // optional: RTL_WAITER_DEREGISTER_WAIT_FOR_COMPLETION
);

NTSYSAPI
NTSTATUS
NTAPI
RtlQueueWorkItem(
    _In_ WORKERCALLBACKFUNC Function,
    _In_opt_ PVOID Context,
    _In_ ULONG Flags);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetIoCompletionCallback(
    _In_ HANDLE FileHandle,
    _In_ APC_CALLBACK_FUNCTION CompletionProc,
    _In_ ULONG Flags);

typedef
_Function_class_(RTL_START_POOL_THREAD)
NTSTATUS
NTAPI
RTL_START_POOL_THREAD(
    _In_ PTHREAD_START_ROUTINE Function,
    _In_ PVOID Parameter,
    _Out_ PHANDLE ThreadHandle);
typedef RTL_START_POOL_THREAD *PRTL_START_POOL_THREAD;

typedef
_Function_class_(RTL_EXIT_POOL_THREAD)
NTSTATUS
NTAPI
RTL_EXIT_POOL_THREAD(
    _In_ NTSTATUS ExitStatus);
typedef RTL_EXIT_POOL_THREAD *PRTL_EXIT_POOL_THREAD;

NTSYSAPI
NTSTATUS
NTAPI
RtlSetThreadPoolStartFunc(
    _In_ PRTL_START_POOL_THREAD StartPoolThread,
    _In_ PRTL_EXIT_POOL_THREAD ExitPoolThread);

#pragma endregion

#define RTL_IMPORT_TABLE_HASH_REVISION 1

NTSYSAPI
NTSTATUS
NTAPI
RtlComputeImportTableHash(
    _In_ HANDLE FileHandle,
    _Out_writes_bytes_(16) PCHAR Hash,
    _In_ ULONG ImportTableHashRevision);

NTSYSAPI
ULONG32
NTAPI
RtlComputeCrc32(
    _In_ ULONG32 PartialCrc,
    _In_ PVOID Buffer,
    _In_ ULONG Length);

EXTERN_C_END

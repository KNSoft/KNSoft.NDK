﻿#pragma once

#include "../../MinDef.h"
#include "../../Ps/Basic.h"
#include "../../Mm/Info.h"
#include "../../Ex/SysInfo.h"

#include <minwinbase.h>

EXTERN_C_START

/* phnt & PDB */

// private
typedef struct _RTL_PROCESS_LOCK_INFORMATION
{
    PVOID Address;
    USHORT Type;
    USHORT CreatorBackTraceIndex;
    HANDLE OwningThread;
    LONG LockCount;
    ULONG ContentionCount;
    ULONG EntryCount;
    LONG RecursionCount;
    ULONG NumberOfWaitingShared;
    ULONG NumberOfWaitingExclusive;
} RTL_PROCESS_LOCK_INFORMATION, *PRTL_PROCESS_LOCK_INFORMATION;

// private
typedef struct _RTL_PROCESS_LOCKS
{
    ULONG NumberOfLocks;
    _Field_size_(NumberOfLocks) RTL_PROCESS_LOCK_INFORMATION Locks[1];
} RTL_PROCESS_LOCKS, *PRTL_PROCESS_LOCKS;

// private
typedef struct _RTL_PROCESS_BACKTRACE_INFORMATION
{
    PCHAR SymbolicBackTrace;
    ULONG TraceCount;
    USHORT Index;
    USHORT Depth;
    PVOID BackTrace[32];
} RTL_PROCESS_BACKTRACE_INFORMATION, *PRTL_PROCESS_BACKTRACE_INFORMATION;

// private
typedef struct _RTL_PROCESS_BACKTRACES
{
    ULONG CommittedMemory;
    ULONG ReservedMemory;
    ULONG NumberOfBackTraceLookups;
    ULONG NumberOfBackTraces;
    _Field_size_(NumberOfBackTraces) RTL_PROCESS_BACKTRACE_INFORMATION BackTraces[1];
} RTL_PROCESS_BACKTRACES, *PRTL_PROCESS_BACKTRACES;

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateProcessParameters(
    _Out_ PRTL_USER_PROCESS_PARAMETERS *ProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateProcessParametersEx(
    _Out_ PRTL_USER_PROCESS_PARAMETERS *ProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS4)
// private
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateProcessParametersWithTemplate(
    _Out_ PRTL_USER_PROCESS_PARAMETERS *ProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_opt_ PUNICODE_STRING RedirectionDllName,
    _In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
);
#endif

NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyProcessParameters(
    _In_ _Post_invalid_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

NTSYSAPI
PRTL_USER_PROCESS_PARAMETERS
NTAPI
RtlNormalizeProcessParams(
    _Inout_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

NTSYSAPI
PRTL_USER_PROCESS_PARAMETERS
NTAPI
RtlDeNormalizeProcessParams(
    _Inout_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

typedef struct _RTL_USER_PROCESS_INFORMATION
{
    ULONG Length;
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

/**
 * Creates a new process and its primary thread. The new process runs in the security context of the calling process.
 *
 * @param NtImagePathName The path of the image to be executed.
 * @param ExtendedParameters Reserved
 * @param ProcessParameters The process parameter information.
 * @param ProcessSecurityDescriptor The security descriptor for the new process. If NULL, the process gets a default security descriptor.
 * @param ThreadSecurityDescriptor The security descriptor for the initial thread. If NULL, the thread gets a default security descriptor.
 * @param ParentProcess The handle of a process to use (instead of the calling process) as the parent for the process being created.
 * @param InheritHandles If this parameter is TRUE, each inheritable handle in the calling process is inherited by the new process.
 * @param DebugPort The handle of an ALPC port for debug messages. If NULL, the process gets a default port. (WindowsErrorReportingServicePort)
 * @param TokenHandle The handle of a Token to use as the security context.
 * @param ProcessInformation The user process information.
 * @return NTSTATUS Successful or errant status.
 * @sa https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserProcess(
    _In_ PUNICODE_STRING NtImagePathName,
    _In_ ULONG AttributesDeprecated,
    _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    _In_opt_ PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    _In_opt_ HANDLE ParentProcess,
    _In_ BOOLEAN InheritHandles,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle, // used to be ExceptionPort
    _Out_ PRTL_USER_PROCESS_INFORMATION ProcessInformation);

#define RTL_USER_PROCESS_EXTENDED_PARAMETERS_VERSION 1

typedef struct _RTL_USER_PROCESS_EXTENDED_PARAMETERS
{
    USHORT Version;
    USHORT NodeNumber;
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor;
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor;
    HANDLE ParentProcess;
    HANDLE DebugPort;
    HANDLE TokenHandle;
    HANDLE JobHandle;
} RTL_USER_PROCESS_EXTENDED_PARAMETERS, *PRTL_USER_PROCESS_EXTENDED_PARAMETERS;

#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserProcessEx(
    _In_ PUNICODE_STRING NtImagePathName,
    _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    _In_ BOOLEAN InheritHandles,
    _In_opt_ PRTL_USER_PROCESS_EXTENDED_PARAMETERS ProcessExtendedParameters,
    _Out_ PRTL_USER_PROCESS_INFORMATION ProcessInformation);
#endif

/**
 * Ends the calling process and all its threads.
 *
 * \param ExitStatus The exit status for the process and all threads.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess
 * \remarks This function does not return to the caller. It terminates the process and all threads immediately.
 */
_Analysis_noreturn_
DECLSPEC_NORETURN
NTSYSAPI
VOID
NTAPI
RtlExitUserProcess(
    _In_ NTSTATUS ExitStatus);

#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED    0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES     0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE      0x00000004 // don't update synchronization objects

/**
 * Creates a new process from the current process.
 *
 * @param ProcessFlags The path of the image to be executed.
 * @param ProcessSecurityDescriptor The security descriptor for the new process. If NULL, the process gets a default security descriptor.
 * @param ThreadSecurityDescriptor The security descriptor for the initial thread. If NULL, the thread gets a default security descriptor.
 * @param DebugPort The handle of an ALPC port for debug messages. If NULL, the process gets a default port. (WindowsErrorReportingServicePort)
 * @param ProcessInformation The new process information.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCloneUserProcess(
    _In_ ULONG ProcessFlags,
    _In_opt_ PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    _In_opt_ HANDLE DebugPort,
    _Out_ PRTL_USER_PROCESS_INFORMATION ProcessInformation);

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlPrepareForProcessCloning(VOID);

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlCompleteProcessCloning(
    _In_ LOGICAL Completed);

NTSYSAPI
VOID
NTAPI
RtlUpdateClonedCriticalSection(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection);

NTSYSAPI
VOID
NTAPI
RtlUpdateClonedSRWLock(
    _Inout_ PRTL_SRWLOCK SRWLock,
    _In_ LOGICAL Shared // TRUE to set to shared acquire
);

// rev RtlCloneUserProcess Flags
#define RTL_PROCESS_REFLECTION_FLAGS_CREATE_SUSPENDED 0x00000001
#define RTL_PROCESS_REFLECTION_FLAGS_INHERIT_HANDLES  0x00000002
#define RTL_PROCESS_REFLECTION_FLAGS_NO_SUSPEND       0x00000004
#define RTL_PROCESS_REFLECTION_FLAGS_NO_SYNCHRONIZE   0x00000008
#define RTL_PROCESS_REFLECTION_FLAGS_NO_CLOSE_EVENT   0x00000010

typedef struct _RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION
{
    HANDLE ReflectionProcessHandle;
    HANDLE ReflectionThreadHandle;
    CLIENT_ID ReflectionClientId;
} RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION, *PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;

typedef RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION PROCESS_REFLECTION_INFORMATION, *PPROCESS_REFLECTION_INFORMATION;

/**
 * The RtlCreateProcessReflection function creates a lightweight copy of a process for debugging or snapshot purposes.
 *
 * \param ProcessHandle Handle to the process to reflect.
 * \param Flags Flags that control the behavior of the reflection. See RTL_PROCESS_REFLECTION_FLAGS_*.
 * \param StartRoutine Optional pointer to a routine to execute in the reflected process.
 * \param StartContext Optional pointer to context to pass to the start routine.
 * \param EventHandle Optional handle to an event to signal when the reflection is complete.
 * \param ReflectionInformation Optional pointer to a structure that receives information about the reflected process.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateProcessReflection(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG Flags, // RTL_PROCESS_REFLECTION_FLAGS_*
    _In_opt_ PVOID StartRoutine,
    _In_opt_ PVOID StartContext,
    _In_opt_ HANDLE EventHandle,
    _Out_opt_ PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION ReflectionInformation);

/**
 * The RtlSetProcessIsCritical function sets or clears the critical status of the current process.
 *
 * \param NewValue TRUE to mark the process as critical, FALSE to clear.
 * \param OldValue Optional pointer to receive the previous critical status.
 * \param CheckFlag If TRUE, checks for certain conditions before setting.
 * \return NTSTATUS Successful or errant status.
 * \remarks A critical process will cause a system bugcheck if terminated.
 */
NTSYSAPI
NTSTATUS
STDAPIVCALLTYPE
RtlSetProcessIsCritical(
    _In_ BOOLEAN NewValue,
    _Out_opt_ PBOOLEAN OldValue,
    _In_ BOOLEAN CheckFlag);

/**
 * The RtlSetThreadIsCritical function sets or clears the critical status of the current thread.
 *
 * \param NewValue TRUE to mark the thread as critical, FALSE to clear.
 * \param OldValue Optional pointer to receive the previous critical status.
 * \param CheckFlag If TRUE, checks for certain conditions before setting.
 * \return NTSTATUS Successful or errant status.
 * \remarks A critical thread will cause a system bugcheck if terminated.
 */
NTSYSAPI
NTSTATUS
STDAPIVCALLTYPE
RtlSetThreadIsCritical(
    _In_ BOOLEAN NewValue,
    _Out_opt_ PBOOLEAN OldValue,
    _In_ BOOLEAN CheckFlag);

// rev
/**
 * The RtlSetThreadSubProcessTag function sets the sub-process tag for the current thread.
 *
 * @param SubProcessTag Pointer to the tag value to set.
 * @return The previous sub-process tag value.
 */
NTSYSAPI
PVOID
NTAPI
RtlSetThreadSubProcessTag(
    _In_ PVOID SubProcessTag);

// rev
/**
 * Validates the process protection level.
 *
 * @param ProcessProtection Pointer to a PS_PROTECTION structure describing the protection.
 * @return TRUE if the protection level is valid, FALSE otherwise.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlValidProcessProtection(
    _In_ PS_PROTECTION ProcessProtection);

// rev
/**
 * Tests whether a source protection level can access a target protection level.
 *
 * @param Source Pointer to a PS_PROTECTION structure for the source.
 * @param Target Pointer to a PS_PROTECTION structure for the target.
 * @return TRUE if access is allowed, FALSE otherwise.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlTestProtectedAccess(
    _In_ PS_PROTECTION Source,
    _In_ PS_PROTECTION Target);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS3)

// rev NtCompareObjects(NtCurrentProcess(), ProcessHandle)
NTSYSAPI
BOOLEAN
NTAPI
RtlIsCurrentProcess(
    _In_ HANDLE ProcessHandle);

// rev NtCompareObjects(NtCurrentThread(), ThreadHandle)
NTSYSAPI
BOOLEAN
NTAPI
RtlIsCurrentThread(
    _In_ HANDLE ThreadHandle);

#endif

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserThread(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    _In_ BOOLEAN CreateSuspended,
    _In_opt_ ULONG ZeroBits,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ SIZE_T CommittedStackSize,
    _In_ PUSER_THREAD_START_ROUTINE StartAddress,
    _In_opt_ PVOID Parameter,
    _Out_opt_ PHANDLE ThreadHandle,
    _Out_opt_ PCLIENT_ID ClientId);

NTSYSAPI
VOID
NTAPI
RtlUserThreadStart(
    _In_ PUSER_THREAD_START_ROUTINE Function,
    _In_ PVOID Parameter);

_Analysis_noreturn_
DECLSPEC_NORETURN
NTSYSAPI
VOID
NTAPI
RtlExitUserThread(
    _In_ NTSTATUS ExitStatus);

NTSYSAPI
BOOLEAN
NTAPI
RtlIsCurrentThreadAttachExempt(VOID);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserStack(
    _In_opt_ SIZE_T CommittedStackSize,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ ULONG_PTR ZeroBits,
    _In_ SIZE_T PageSize,
    _In_ ULONG_PTR ReserveAlignment,
    _Out_ PINITIAL_TEB InitialTeb);

NTSYSAPI
NTSTATUS
NTAPI
RtlFreeUserStack(
    _In_ PVOID AllocationBase);

NTSYSAPI
NTSTATUS
NTAPI
RtlRemoteCall(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE ThreadHandle,
    _In_ PVOID CallSite,
    _In_ ULONG ArgumentCount,
    _In_opt_ PULONG_PTR Arguments,
    _In_ BOOLEAN PassContext,
    _In_ BOOLEAN AlreadySuspended);

#ifdef _WIN64

typedef enum _FUNCTION_TABLE_TYPE
{
    RF_SORTED,
    RF_UNSORTED,
    RF_CALLBACK,
    RF_KERNEL_DYNAMIC
} FUNCTION_TABLE_TYPE;

typedef struct _DYNAMIC_FUNCTION_TABLE
{
    LIST_ENTRY ListEntry;
    PRUNTIME_FUNCTION FunctionTable;
    LARGE_INTEGER TimeStamp;
    ULONG64 MinimumAddress;
    ULONG64 MaximumAddress;
    ULONG64 BaseAddress;
    PGET_RUNTIME_FUNCTION_CALLBACK Callback;
    PVOID Context;
    PWSTR OutOfProcessCallbackDll;
    FUNCTION_TABLE_TYPE Type;
    ULONG EntryCount;
    RTL_BALANCED_NODE TreeNodeMin;
    RTL_BALANCED_NODE TreeNodeMax;
} DYNAMIC_FUNCTION_TABLE, *PDYNAMIC_FUNCTION_TABLE;

NTSYSAPI
PLIST_ENTRY
NTAPI
RtlGetFunctionTableListHead(VOID);

#endif

NTSYSAPI
BOOLEAN
NTAPI
RtlIsThreadWithinLoaderCallout(VOID);

/**
 * Gets a value indicating whether the process is currently in the shutdown phase.
 *
 * @return TRUE if a shutdown of the current dll process is in progress; otherwise, FALSE.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlDllShutdownInProgress(VOID);

#if (NTDDI_VERSION >= NTDDI_WIN8)
NTSYSAPI
ULONG
NTAPI
RtlSetProxiedProcessId(
    _In_ ULONG ProxiedProcessId);
#endif

NTSYSAPI
NTSTATUS
NTAPI
RtlDelayExecution(
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER DelayInterval);

NTSYSAPI
USHORT
NTAPI
RtlGetCurrentThreadPrimaryGroup(VOID);

#if (NTDDI_VERSION >= NTDDI_WIN11_GE)

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryProcessAvailableCpus(
    _In_ HANDLE ProcessHandle,
    _In_ PKAFFINITY_EX Affinity,
    _In_ ULONG64 ObservedSequenceNumber,
    _Out_opt_ PULONG64 SequenceNumber
);

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryProcessAvailableCpusCount(
    _In_ HANDLE ProcessHandle,
    _Out_ PULONG AvailableCpusCount,
    _Out_opt_ PULONG64 SequenceNumber
);

#endif

EXTERN_C_END

#pragma once

#include "../MinDef.h"
#include "../Ps/PsApi.h"

EXTERN_C_START

// RtlOpenCrossProcessEmulatorWorkConnection
NTSYSAPI
NTSTATUS
NTAPI
RtlOpenCrossProcessEmulatorWorkConnection(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE SectionHandle,
    _Outptr_ PVOID *ViewBase
    );

/* phnt */

#ifdef _WIN64

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64GetThreadContext(
    _In_ HANDLE ThreadHandle,
    _Inout_ PWOW64_CONTEXT ThreadContext
);

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64SetThreadContext(
    _In_ HANDLE ThreadHandle,
    _In_ PWOW64_CONTEXT ThreadContext
);

#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
// rev from Wow64DetermineEnvironment
NTSYSAPI
USHORT
NTAPI
RtlWow64GetCurrentMachine(
    VOID
);

// rev from Wow64DetermineEnvironment
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64IsWowGuestMachineSupported(
    _In_ USHORT NativeMachine,
    _Out_ PBOOLEAN IsWowGuestMachineSupported
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_NI)
// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64GetProcessMachines(
    _In_ HANDLE ProcessHandle,
    _Out_ PUSHORT ProcessMachine,
    _Out_ PUSHORT NativeMachine
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN11_ZN)

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64ChangeProcessState(
    _In_ HANDLE ProcessStateChangeHandle,
    _In_ HANDLE ProcessHandle,
    _In_ PROCESS_STATE_CHANGE_TYPE StateChangeType
);

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64ChangeThreadState(
    _In_ HANDLE ThreadStateChangeHandle,
    _In_ HANDLE ThreadHandle,
    _In_ THREAD_STATE_CHANGE_TYPE StateChangeType
);

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64SuspendProcess(
    _In_ HANDLE ProcessHandle
);

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64SuspendThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG SuspendCount
);

#endif

// WOW64

NTSYSAPI
NTSTATUS
NTAPI
RtlGetNativeSystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _In_ PVOID NativeSystemInformation,
    _In_ ULONG InformationLength,
    _Out_opt_ PULONG ReturnLength
);

NTSYSAPI
NTSTATUS
NTAPI
RtlQueueApcWow64Thread(
    _In_ HANDLE ThreadHandle,
    _In_ PPS_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
);

/**
 * The RtlWow64EnableFsRedirection routine enables or disables file system redirection for the calling thread.
 *
 * \param Wow64FsEnableRedirection If TRUE, requests redirection be enabled; if FALSE, requests redirection be disabled.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-wow64enablewow64fsredirection
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64EnableFsRedirection(
    _In_ BOOLEAN Wow64FsEnableRedirection
);

/**
 * The RtlWow64EnableFsRedirectionEx routine enables or disables file system redirection for the calling thread.
 *
 * \param Wow64FsEnableRedirection If TRUE, requests redirection be enabled; if FALSE, requests redirection be disabled.
 * \param OldFsRedirectionLevel The WOW64 file system redirection value. The system uses this parameter to store information
 *  necessary to revert (re-enable) file system redirection.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-wow64disablewow64fsredirection
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64EnableFsRedirectionEx(
    _In_ PVOID Wow64FsEnableRedirection,
    _Out_ PVOID* OldFsRedirectionLevel
);

// RtlWow64GetCpuAreaEnabledFeatures
NTSYSAPI
ULONGLONG
NTAPI
RtlWow64GetCpuAreaEnabledFeatures(
    _Inout_ PULONG Features
    );

// RtlWow64GetCurrentCpuArea
//NTSYSAPI
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
//NTSYSAPI
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

EXTERN_C_END

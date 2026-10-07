#pragma once

#include "../MinDef.h"
#include "../Ps/PsApi.h"

EXTERN_C_START

#if defined(_M_X64) && !defined(_M_ARM64EC)

// RtlIsEcCode is exported by x64 ntdll.dll on Windows on ARM64 but not declared by recent SDKs for x64.
/**
 * The RtlIsEcCode routine determines whether the specified code pointer refers to ARM64EC (emulation-compatible) code.
 *
 * \param CodePointer The code address to test.
 * \return Returns `TRUE` if the address refers to ARM64EC code, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsEcCode(
    _In_ DWORD64 CodePointer
);

#endif

// RtlOpenCrossProcessEmulatorWorkConnection
/**
 * The RtlOpenCrossProcessEmulatorWorkConnection routine opens a shared-memory connection used to exchange cross-process
 * emulator work items.
 *
 * \param ProcessHandle A handle to the target process.
 * \param SectionHandle Receives a handle to the shared section.
 * \param ViewBase Receives the base address of the mapped view.
 * \return NTSTATUS Successful or errant status.
 */
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
/**
 * The RtlWow64GetThreadContext routine retrieves the WOW64 (32-bit) context of the specified thread.
 *
 * \param ThreadHandle A handle to the thread whose context is retrieved.
 * \param ThreadContext A pointer to a WOW64_CONTEXT structure that receives the thread context.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64GetThreadContext(
    _In_ HANDLE ThreadHandle,
    _Inout_ PWOW64_CONTEXT ThreadContext
);

// rev
/**
 * The RtlWow64SetThreadContext routine sets the WOW64 (32-bit) context of the specified thread.
 *
 * \param ThreadHandle A handle to the thread whose context is set.
 * \param ThreadContext A pointer to a WOW64_CONTEXT structure that contains the thread context.
 * \return NTSTATUS Successful or errant status.
 */
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
/**
 * The RtlWow64GetCurrentMachine routine returns the machine architecture of the current process image.
 *
 * \return USHORT An IMAGE_FILE_MACHINE_* value identifying the current machine.
 */
NTSYSAPI
USHORT
NTAPI
RtlWow64GetCurrentMachine(
    VOID
);

// rev from Wow64DetermineEnvironment
/**
 * The RtlWow64IsWowGuestMachineSupported routine determines whether the specified guest machine architecture is
 * supported for WOW64 emulation on the current host.
 *
 * \param NativeMachine The native (host) machine architecture (an IMAGE_FILE_MACHINE_* value).
 * \param IsWowGuestMachineSupported A pointer to a variable that receives whether the guest machine is supported.
 * \return NTSTATUS Successful or errant status.
 */
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
/**
 * The RtlWow64GetProcessMachines routine retrieves the process and native machine architectures for the specified
 * process.
 *
 * \param ProcessHandle A handle to the process to query.
 * \param ProcessMachine A pointer to a variable that receives the process machine architecture (an IMAGE_FILE_MACHINE_*
 * value).
 * \param NativeMachine An optional pointer to a variable that receives the native machine architecture.
 * \return NTSTATUS Successful or errant status.
 */
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
/**
 * The RtlWow64ChangeProcessState routine applies a process state change to a target process through a process state
 * change handle.
 *
 * \param ProcessStateChangeHandle A handle to the process state change object.
 * \param ProcessHandle A handle to the process whose state is changed.
 * \param StateChangeType The PROCESS_STATE_CHANGE_TYPE that specifies the state change to apply.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64ChangeProcessState(
    _In_ HANDLE ProcessStateChangeHandle,
    _In_ HANDLE ProcessHandle,
    _In_ PROCESS_STATE_CHANGE_TYPE StateChangeType
);

// rev
/**
 * The RtlWow64ChangeThreadState routine applies a thread state change to a target thread through a thread state change
 * handle.
 *
 * \param ThreadStateChangeHandle A handle to the thread state change object.
 * \param ThreadHandle A handle to the thread whose state is changed.
 * \param StateChangeType The THREAD_STATE_CHANGE_TYPE that specifies the state change to apply.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64ChangeThreadState(
    _In_ HANDLE ThreadStateChangeHandle,
    _In_ HANDLE ThreadHandle,
    _In_ THREAD_STATE_CHANGE_TYPE StateChangeType
);

// rev
/**
 * The RtlWow64SuspendProcess routine suspends all threads in the specified process.
 *
 * \param ProcessHandle A handle to the process to suspend.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64SuspendProcess(
    _In_ HANDLE ProcessHandle
);

// rev
/**
 * The RtlWow64SuspendThread routine suspends the specified thread.
 *
 * \param ThreadHandle A handle to the thread to suspend.
 * \param SuspendCount An optional pointer to a variable that receives the thread's previous suspend count.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64SuspendThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG SuspendCount
);

#endif

// WOW64

/**
 * The RtlGetNativeSystemInformation routine retrieves native system information, returning 64-bit data from a WOW64
 * process where applicable.
 *
 * \param SystemInformationClass The system information class to query.
 * \param NativeSystemInformation A buffer that receives the requested information.
 * \param InformationLength The size, in bytes, of the buffer.
 * \param ReturnLength An optional pointer that receives the number of bytes returned.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetNativeSystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _In_ PVOID NativeSystemInformation,
    _In_ ULONG InformationLength,
    _Out_opt_ PULONG ReturnLength
);

/**
 * The RtlQueueApcWow64Thread routine queues a user-mode APC to a WOW64 (32-bit) thread from a native (64-bit) process.
 *
 * \param ThreadHandle A handle to the target WOW64 thread.
 * \param ApcRoutine The APC routine to execute in the target thread.
 * \param ApcArgument1 An optional first argument passed to the APC routine.
 * \param ApcArgument2 An optional second argument passed to the APC routine.
 * \param ApcArgument3 An optional third argument passed to the APC routine.
 * \return NTSTATUS Successful or errant status.
 */
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
/**
 * The RtlWow64GetCpuAreaEnabledFeatures routine returns the extended processor features enabled in the WoW64 CPU area.
 *
 * \param Features A pointer to a variable that on input specifies and on output receives the feature flags.
 * \return ULONGLONG The mask of enabled extended features in the CPU area.
 */
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

/**
 * The RtlWow64GetCurrentCpuArea routine retrieves information about the CPU area for the current WoW64 thread.
 *
 * \param MachineType An optional pointer to a variable that receives the machine architecture of the CPU area.
 * \param ContextRecordAddress An optional pointer to a variable that receives the address of the context record.
 * \param SharedInfoAddress An optional pointer to a variable that receives the address of the shared CPU area
 * information.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlWow64GetCurrentCpuArea(
    _Out_opt_ PUSHORT MachineType,
    _Out_opt_ PULONGLONG ContextRecordAddress,
    _Out_opt_ PULONGLONG SharedInfoAddress
    );

// RtlWow64GetEquivalentMachineCHPE
/**
 * The RtlWow64GetEquivalentMachineCHPE routine returns the compiled-hybrid (CHPE) machine type equivalent to a given
 * machine type.
 *
 * \param MachineType The source machine architecture.
 * \return SHORT The equivalent CHPE machine architecture.
 */
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
/**
 * The RtlWow64LogMessageInEventLogger routine writes a WOW64 subsystem message to the system event logger.
 *
 * \param StringCount The number of strings in the Strings array.
 * \param Strings An array of pointers to unicode strings to log.
 * \param EventId The event identifier to log.
 */
NTSYSAPI
VOID
NTAPI
RtlWow64LogMessageInEventLogger(
    _In_ USHORT StringCount,
    _In_reads_(StringCount) PCWSTR *Strings,
    _In_ ULONG EventId
    );

// RtlWow64PopAllCrossProcessWorkFromWorkList
/**
 * Header of a WOW64 cross-process work list.
 */
typedef union _WOW64_CROSS_PROCESS_WORK_HDR
{
    ULONG64 Value;
    struct
    {
        ULONG FirstEntry : 31;   // byte offset from header base to first entry (0 == list empty)
        ULONG Flag       : 1;    // status/reset flag (surfaced via ResetFlag)
        ULONG Counter;           // ABA sequence counter, incremented on each CAS
    } s;
} WOW64_CROSS_PROCESS_WORK_HDR;

/**
 * Represents a single entry in a WOW64 cross-process work list.
 */
typedef struct _WOW64_CROSS_PROCESS_WORK_ENTRY
{
    ULONG NextEntry;            // byte offset to next entry(0 == end of chain)
    ULONG Command;              // work command/type (== 8 in the coalesce path of the pusher)
    ULONG64 BaseAddress;        // target base address
    ULONG64 RegionSize;         // region size
    ULONG64 Reserved0;
    ULONG64 Reserved1;
} WOW64_CROSS_PROCESS_WORK_ENTRY, *PWOW64_CROSS_PROCESS_WORK_ENTRY;

/**
 * The RtlWow64PopAllCrossProcessWorkFromWorkList routine atomically detaches all pending work
 * items from the shared WOW64 cross-process work list and returns them as a self-contained,
 * base-relative singly-linked chain.
 *
 * The 64-bit header at *WorkList is a bitfield:
 *   [63]    Busy flag (set by a concurrent producer)
 *   [62:32] Epoch counter (incremented on each successful pop)
 *   [30:0]  Offset from WorkList to the first list entry (0 = empty)
 *
 * \param WorkList Pointer to the shared 64-bit work-list header.
 * \param BusyFlag Receives the busy flag from the original header snapshot.
 * \return Head of the detached work chain, or NULL if the list was empty or busy.
 *         Each entry's first ULONG is a relative offset to the next entry.
 */
NTSYSAPI
PWOW64_CROSS_PROCESS_WORK_ENTRY
NTAPI
RtlWow64PopAllCrossProcessWorkFromWorkList(
    _In_ volatile WOW64_CROSS_PROCESS_WORK_HDR* WorkList,
    _Out_ BOOLEAN *BusyFlag
    );

// RtlWow64PopCrossProcessWorkFromFreeList
/**
 * The RtlWow64PopCrossProcessWorkFromFreeList routine atomically pop a single entry from the head of a free list.
 *
 * \details CAS-replaces the head with \c head->NextEntry (preserving \c Flag,
 * bumping \c Counter). The popped entry's \c NextEntry field is zeroed before return.
 * \param[in,out] FreeList Pointer to the atomic free-list head.
 * \return Pointer to the detached entry, or \c NULL if the list was empty.
 * \exception STATUS_INVALID_PARAMETER (0xC000000D) if the head entry is out of range.
 */
_Ret_maybenull_
NTSYSAPI
PWOW64_CROSS_PROCESS_WORK_ENTRY
NTAPI
RtlWow64PopCrossProcessWorkFromFreeList(
    _Inout_ volatile WOW64_CROSS_PROCESS_WORK_HDR *FreeList
    );

// RtlWow64PushCrossProcessWorkOntoFreeList
/**
 * The RtlWow64PushCrossProcessWorkOntoFreeList routine atomically push a work entry onto the head of a free list.
 *
 * \details Links \p Entry at the head of \p FreeList, writing \c Entry->NextEntry
 * to the prior head offset and CAS-installing \p Entry's relative offset
 * as the new head. The \c Flag bit and \c Counter are preserved/bumped.
 * \p Entry is range-checked against the shared window before use.
 * \param[in,out] FreeList  Pointer to the atomic free-list head.
 * \param[in,out] Entry Entry to release onto the free list; its \c NextEntry field is overwritten to link it into the
 * chain.
 * \return \c TRUE on success.
 * \exception STATUS_INVALID_PARAMETER (0xC000000D) if \p Entry lies outside the shared region.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlWow64PushCrossProcessWorkOntoFreeList(
    _Inout_ volatile WOW64_CROSS_PROCESS_WORK_HDR *FreeList,
    _Inout_ WOW64_CROSS_PROCESS_WORK_ENTRY *Entry
    );

// RtlWow64PushCrossProcessWorkOntoWorkList
/**
 * The RtlWow64PushCrossProcessWorkOntoWorkList routine atomically push a work entry onto the head of the active work
 * list, coalescing with an adjacent existing entry where possible.
 * \details If the current head entry describes a region immediately adjacent to
 * \p Entry (matching \c Command == 8 and contiguous
 * \c BaseAddress / \c RegionSize), the two are merged in place instead
 * of linking a new node. The pre-merge state is snapshotted so the CAS
 * can be safely retried on contention.
 * \param[in,out] WorkList Pointer to the atomic work-list head.
 * \param[in] Entry Address of the entry to enqueue. Passed by value as a \c ULONGLONG in the raw ABI (RDX).
 * \param[out] ReclaimEntry Receives the prior head/merge target address, or 0.
 * \return \c TRUE on success.
 * \exception STATUS_INVALID_PARAMETER (0xC000000D) on range-check failure.  // rev
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlWow64PushCrossProcessWorkOntoWorkList(
    _Inout_  volatile WOW64_CROSS_PROCESS_WORK_HDR *WorkList,
    _In_ WOW64_CROSS_PROCESS_WORK_ENTRY *Entry,
    _Out_ WOW64_CROSS_PROCESS_WORK_ENTRY **ReclaimEntry
    );

// RtlWow64RequestCrossProcessHeavyFlush
/**
 * The RtlWow64RequestCrossProcessHeavyFlush routine requests a cross-process "heavy" flush by setting the work-list
 * flag bit.
 *
 * \details Atomically sets bit 31 (@c Flag) of the head word and bumps
 * \c Counter, without dequeuing anything. The flag is later consumed by
 * \ref RtlWow64PopAllCrossProcessWorkFromWorkList via its \c ResetFlag output.
 * \param[in,out] WorkList Pointer to the atomic work-list head.
 * \return TRUE on success.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlWow64RequestCrossProcessHeavyFlush(
    _Inout_ volatile WOW64_CROSS_PROCESS_WORK_HDR *WorkList
    );

// RtlpQueryProcessDebugInformationFromWow64
/**
 * Describes the owner of a critical section in a 32-bit process being debugged.
 */
typedef struct _RTL_QUERY_PROCESS_DEBUG_CS_OWNER32
{
    ULONG CriticalSectionHandle;      // in  -> RTL_DEBUG_INFORMATION.CriticalSectionHandle
    ULONG CriticalSectionOwnerThread; // out <- RTL_DEBUG_INFORMATION.CriticalSectionOwnerThread
} RTL_QUERY_PROCESS_DEBUG_CS_OWNER32, *PRTL_QUERY_PROCESS_DEBUG_CS_OWNER32;

/**
 * Receives debug information for a 32-bit (WOW64) process.
 */
typedef struct _RTL_QUERY_PROCESS_DEBUG_INFO_WOW64
{
    ULONG UniqueProcessId; // Target PID
    ULONG Padding;
    ULONG32 DebugInformation; // 32-bit Wow64 pointer to RTL_QUERY_PROCESS_DEBUG_CS_OWNER32
} RTL_QUERY_PROCESS_DEBUG_INFO_WOW64, *PRTL_QUERY_PROCESS_DEBUG_INFO_WOW64;

/**
 * The RtlpQueryProcessDebugInformationFromWow64 routine is a WOW64 thunk that queries critical-section owner debug
 * information for a
 * target process on behalf of a 32-bit caller.
 *
 * \details Creates a debug buffer, forwards to RtlQueryProcessDebugInformation
 * for the requested process, and marshals the resulting CriticalSectionHandle
 * and CriticalSectionOwnerThread back into the WOW64 request block.
 * \param[in] Flags Query flags; must be RTL_QUERY_PROCESS_CS_OWNER (0x400)
 * (0x800 is also accepted).
 * \param[in,out] Wow64Info WOW64 request block carrying the target process id
 * and a pointer to the caller's result sink.
 * \return
 * - STATUS_SUCCESS on success (and the underlying query status otherwise).
 * - STATUS_INVALID_PARAMETER (0xC000000D) if \p Flags is not 0x400/0x800.
 * - STATUS_NO_MEMORY (0xC0000017) if the debug buffer cannot be allocated.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpQueryProcessDebugInformationFromWow64(
    _In_ ULONG Flags,
    _Inout_ PRTL_QUERY_PROCESS_DEBUG_INFO_WOW64 Wow64Info
    );

// RtlpWow64CtxFromAmd64
/**
 * The RtlpWow64CtxFromAmd64 routine down-converts a native AMD64 CONTEXT into a WOW64 (x86) context.
 *
 * \details Populates \p Wow64Context from \p Context, copying each register
 * group (control, integer, segments, floating-point, debug, extended/legacy
 * XMM, and XSTATE) only when the group is both requested in \p ContextFlags and
 * present in the source context's ContextFlags. WOW64 segment selectors are
 * applied as constants. Bit 0x40000000 reconciles the destination ContextFlags
 * against the source.
 * \param[in] ContextFlags x86 (CONTEXT_i386) context flags selecting which
 * register groups to convert.
 * \param[in] Context The source native AMD64 CONTEXT.
 * \param[in,out] Wow64Context The destination WOW64_CONTEXT to populate.
 * \return STATUS_SUCCESS, or a failure status propagated from the XSTATE copy.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpWow64CtxFromAmd64(
    _In_ ULONG ContextFlags,
    _In_ PCONTEXT Context,
    _Inout_ PWOW64_CONTEXT Wow64Context
    );

EXTERN_C_END

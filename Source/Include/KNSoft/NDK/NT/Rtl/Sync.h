#pragma once

#include "../MinDef.h"

EXTERN_C_START

#pragma region Critical Section

/**
 * The RtlInitializeCriticalSection routine initializes a critical section object.
 *
 * \param CriticalSection A pointer to the critical section object.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsection
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeCriticalSection(
    _Out_ PRTL_CRITICAL_SECTION CriticalSection
);

/**
 * The RtlInitializeCriticalSectionAndSpinCount routine initializes a critical section object and sets the spin count for the critical section.
 *
 * \param CriticalSection A pointer to the critical section object.
 * \param SpinCount The spin count for the critical section object. On single-processor systems, the spin count is ignored.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsectionandspincount
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeCriticalSectionAndSpinCount(
    _Out_ PRTL_CRITICAL_SECTION CriticalSection,
    _In_ ULONG SpinCount
);

/**
 * The RtlInitializeCriticalSectionEx routine initializes a critical section object and sets the spin count for the critical section with flags.
 *
 * \param CriticalSection A pointer to the critical section object.
 * \param SpinCount The spin count for the critical section object. On single-processor systems, the spin count is ignored.
 * \param Flags This parameter can be 0 or the CRITICAL_SECTION_NO_DEBUG_INFO flag.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsectionex
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeCriticalSectionEx(
    _Out_ PRTL_CRITICAL_SECTION CriticalSection,
    _In_ ULONG SpinCount,
    _In_ ULONG Flags
);

/**
 * The RtlDeleteCriticalSection routine releases all resources used by a critical section object that is no longer
 * needed.
 *
 * \param CriticalSection A pointer to the critical section object to delete.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteCriticalSection(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
);

/**
 * The RtlEnterCriticalSection routine waits for ownership of the specified critical section object, blocking the
 * calling thread until the object is available.
 *
 * \param CriticalSection A pointer to the critical section object.
 * \return NTSTATUS Successful or errant status.
 */
_Acquires_exclusive_lock_(*CriticalSection)
NTSYSAPI
NTSTATUS
NTAPI
RtlEnterCriticalSection(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
);

/**
 * The RtlLeaveCriticalSection routine releases ownership of the specified critical section object.
 *
 * \param CriticalSection A pointer to the critical section object.
 * \return NTSTATUS Successful or errant status.
 */
_Releases_exclusive_lock_(*CriticalSection)
NTSYSAPI
NTSTATUS
NTAPI
RtlLeaveCriticalSection(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
);

/**
 * The RtlTryEnterCriticalSection routine attempts to enter a critical section without blocking the calling thread.
 *
 * \param CriticalSection A pointer to the critical section object.
 * \return A nonzero value if the critical section was successfully entered, otherwise zero.
 */
_When_(return != 0, _Acquires_exclusive_lock_(*CriticalSection))
NTSYSAPI
LOGICAL
NTAPI
RtlTryEnterCriticalSection(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
);

/**
 * The RtlIsCriticalSectionLocked routine determines whether a critical section is currently owned by any thread.
 *
 * \param CriticalSection A pointer to the critical section object.
 * \return A nonzero value if the critical section is locked, otherwise zero.
 */
NTSYSAPI
LOGICAL
NTAPI
RtlIsCriticalSectionLocked(
    _In_ PRTL_CRITICAL_SECTION CriticalSection
);

/**
 * The RtlIsCriticalSectionLockedByThread routine determines whether a critical section is currently owned by the
 * calling thread.
 *
 * \param CriticalSection A pointer to the critical section object.
 * \return A nonzero value if the critical section is owned by the calling thread, otherwise zero.
 */
NTSYSAPI
LOGICAL
NTAPI
RtlIsCriticalSectionLockedByThread(
    _In_ PRTL_CRITICAL_SECTION CriticalSection
);

/**
 * The RtlGetCriticalSectionRecursionCount routine returns the recursion (re-entry) count of a critical section owned by
 * the calling thread.
 *
 * \param CriticalSection A pointer to the critical section object.
 * \return The recursion count of the critical section.
 */
NTSYSAPI
ULONG
NTAPI
RtlGetCriticalSectionRecursionCount(
    _In_ PRTL_CRITICAL_SECTION CriticalSection
);

/**
 * The RtlSetCriticalSectionSpinCount routine sets the spin count for a critical section object.
 *
 * \param CriticalSection A pointer to the critical section object.
 * \param SpinCount The spin count for the critical section object.
 * \return The previous spin count for the critical section object.
 */
NTSYSAPI
ULONG
NTAPI
RtlSetCriticalSectionSpinCount(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection,
    _In_ ULONG SpinCount
);

/**
 * The RtlQueryCriticalSectionOwner routine returns the thread that owns the critical section associated with the
 * specified event handle.
 *
 * \param EventHandle A handle to the event used by the critical section's lock semaphore.
 * \param ExactMatchOwnerAddress If `TRUE`, requires an exact match of the owner address.
 * \return A handle to the owning thread, or `NULL` if the critical section is not owned.
 */
NTSYSAPI
HANDLE
NTAPI
RtlQueryCriticalSectionOwner(
    _In_ HANDLE EventHandle,
    _In_ BOOLEAN ExactMatchOwnerAddress
);

/**
 * The RtlCheckForOrphanedCriticalSections routine checks whether the specified thread owns any critical sections that
 * would be orphaned if the thread terminated.
 *
 * \param ThreadHandle A handle to the thread to check.
 */
NTSYSAPI
VOID
NTAPI
RtlCheckForOrphanedCriticalSections(
    _In_ HANDLE ThreadHandle
);

/**
 * Enables the creation of early critical section events.
 *
 * This function allows the system to create critical section events early in the process
 * initialization. It is typically used to ensure that critical sections are properly
 * initialized and can be used safely during the early stages of process startup.
 * @remarks This function sets the FLG_CRITSEC_EVENT_CREATION flag in the PEB flags field.
 * @return A pointer to the Process Environment Block (PEB).
 */
NTSYSAPI
PPEB
NTAPI
RtlEnableEarlyCriticalSectionEventCreation(VOID);

#pragma region RTL_CRITICAL_SECTION[_DEBUG](64/32)

typedef struct _RTL_CRITICAL_SECTION64 RTL_CRITICAL_SECTION64, *PRTL_CRITICAL_SECTION64;
typedef struct _RTL_CRITICAL_SECTION32 RTL_CRITICAL_SECTION32, *PRTL_CRITICAL_SECTION32;

typedef struct _RTL_CRITICAL_SECTION_DEBUG64
{
    WORD Type;
    WORD CreatorBackTraceIndex;
    RTL_CRITICAL_SECTION64* POINTER_64 CriticalSection;
    LIST_ENTRY64 ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD Identifier;
} RTL_CRITICAL_SECTION_DEBUG64, *PRTL_CRITICAL_SECTION_DEBUG64, RTL_RESOURCE_DEBUG64, *PRTL_RESOURCE_DEBUG64;

typedef struct _RTL_CRITICAL_SECTION_DEBUG32
{
    WORD Type;
    WORD CreatorBackTraceIndex;
    RTL_CRITICAL_SECTION32* POINTER_32 CriticalSection;
    LIST_ENTRY32 ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD Identifier;
} RTL_CRITICAL_SECTION_DEBUG32, *PRTL_CRITICAL_SECTION_DEBUG32, RTL_RESOURCE_DEBUG32, *PRTL_RESOURCE_DEBUG32;

struct _RTL_CRITICAL_SECTION64
{
    RTL_CRITICAL_SECTION_DEBUG64* POINTER_64 DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    VOID* POINTER_64 OwningThread;
    VOID* POINTER_64 LockSemaphore;
    ULONGLONG SpinCount;
};

struct _RTL_CRITICAL_SECTION32
{
    RTL_CRITICAL_SECTION_DEBUG32* POINTER_32 DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    VOID* POINTER_32 OwningThread;
    VOID* POINTER_32 LockSemaphore;
    ULONG SpinCount;
};

#pragma endregion

#pragma endregion phnt & KNSoft.NDK

#pragma region Run Once

typedef
_Function_class_(RTL_RUN_ONCE_INIT_FN)
_IRQL_requires_same_
LOGICAL
NTAPI
RTL_RUN_ONCE_INIT_FN(
/**
 * Pointer to an RTL_RUN_ONCE_INIT_FN callback.
 */
    _Inout_ PRTL_RUN_ONCE RunOnce,
    _Inout_opt_ PVOID Parameter,
    _Inout_opt_ PVOID *Context);
typedef RTL_RUN_ONCE_INIT_FN *PRTL_RUN_ONCE_INIT_FN;

/**
 * The RtlRunOnceInitialize routine initializes a one-time initialization (RTL_RUN_ONCE) structure.
 *
 * \param RunOnce A pointer to the RTL_RUN_ONCE structure to initialize.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlrunonceinitialize
 */
NTSYSAPI
VOID
NTAPI
RtlRunOnceInitialize(
    _Out_ PRTL_RUN_ONCE RunOnce
);

/**
 * The RtlRunOnceExecuteOnce routine executes a one-time initialization routine, ensuring it runs exactly once across
 * threads.
 *
 * \param RunOnce The run-once structure that tracks initialization state.
 * \param InitFn The initialization routine to execute.
 * \param Parameter An optional parameter passed to the initialization routine.
 * \param Context An optional pointer that receives the context produced by initialization.
 * \return NTSTATUS Successful or errant status.
 */
_Maybe_raises_SEH_exception_
NTSYSAPI
NTSTATUS
NTAPI
RtlRunOnceExecuteOnce(
    _Inout_ PRTL_RUN_ONCE RunOnce,
    _In_ __callback PRTL_RUN_ONCE_INIT_FN InitFn,
    _Inout_opt_ PVOID Parameter,
    _Outptr_opt_result_maybenull_ PVOID* Context
);

/**
 * The RtlRunOnceBeginInitialize routine begins a one-time initialization, optionally in asynchronous mode.
 *
 * \param RunOnce The run-once structure that tracks initialization state.
 * \param Flags Flags controlling the initialization (for example, RTL_RUN_ONCE_CHECK_ONLY).
 * \param Context An optional pointer that receives the context associated with the completed initialization.
 * \return NTSTATUS Successful or errant status.
 */
_Must_inspect_result_
NTSYSAPI
NTSTATUS
NTAPI
RtlRunOnceBeginInitialize(
    _Inout_ PRTL_RUN_ONCE RunOnce,
    _In_ ULONG Flags,
    _Outptr_opt_result_maybenull_ PVOID* Context
);

/**
 * The RtlRunOnceComplete routine completes a one-time initialization begun with RtlRunOnceBeginInitialize.
 *
 * \param RunOnce The run-once structure that tracks initialization state.
 * \param Flags Flags controlling completion (for example, RTL_RUN_ONCE_INIT_FAILED).
 * \param Context An optional context value to associate with the completed initialization.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlRunOnceComplete(
    _Inout_ PRTL_RUN_ONCE RunOnce,
    _In_ ULONG Flags,
    _In_opt_ PVOID Context
);

#pragma endregion ntddk.h

#pragma region Resource

/**
 * Represents a reader/writer resource synchronization object.
 */
typedef struct _RTL_RESOURCE
{
    RTL_CRITICAL_SECTION CriticalSection;

    HANDLE SharedSemaphore;
    volatile ULONG NumberOfWaitingShared;
    HANDLE ExclusiveSemaphore;
    volatile ULONG NumberOfWaitingExclusive;

    volatile LONG NumberOfActive; // negative: exclusive acquire; zero: not acquired; positive: shared acquire(s)
    HANDLE ExclusiveOwnerThread;

    ULONG Flags; // RTL_RESOURCE_FLAG_*

    PRTL_RESOURCE_DEBUG DebugInfo;
} RTL_RESOURCE, *PRTL_RESOURCE;

/**
 * Flag indicating that an RTL_RESOURCE is held for a long term.
 */
#define RTL_RESOURCE_FLAG_LONG_TERM ((ULONG)0x00000001)

/**
 * The RtlInitializeResource routine initializes a resource variable.
 *
 * \param Resource A pointer to the resource variable to initialize.
 */
NTSYSAPI
VOID
NTAPI
RtlInitializeResource(
    _Out_ PRTL_RESOURCE Resource
);

/**
 * The RtlDeleteResource routine releases all resources used by a resource variable that is no longer needed.
 *
 * \param Resource A pointer to the resource variable to delete.
 */
NTSYSAPI
VOID
NTAPI
RtlDeleteResource(
    _Inout_ PRTL_RESOURCE Resource
);

/**
 * The RtlAcquireResourceShared routine acquires the specified resource variable for shared access.
 *
 * \param Resource A pointer to the resource variable.
 * \param Wait If `TRUE`, the calling thread waits until the resource can be acquired; if `FALSE`, the routine returns
 * immediately.
 * \return `TRUE` if the resource was acquired, otherwise `FALSE`.
 */
_When_(return != 0, _Acquires_shared_lock_(*Resource))
NTSYSAPI
BOOLEAN
NTAPI
RtlAcquireResourceShared(
    _Inout_ PRTL_RESOURCE Resource,
    _In_ BOOLEAN Wait
);

/**
 * The RtlAcquireResourceExclusive routine acquires the specified resource variable for exclusive access.
 *
 * \param Resource A pointer to the resource variable.
 * \param Wait If `TRUE`, the calling thread waits until the resource can be acquired; if `FALSE`, the routine returns
 * immediately.
 * \return `TRUE` if the resource was acquired, otherwise `FALSE`.
 */
_When_(return != 0, _Acquires_exclusive_lock_(*Resource))
NTSYSAPI
BOOLEAN
NTAPI
RtlAcquireResourceExclusive(
    _Inout_ PRTL_RESOURCE Resource,
    _In_ BOOLEAN Wait
);

/**
 * The RtlReleaseResource routine releases a resource variable that was acquired for shared or exclusive access.
 *
 * \param Resource A pointer to the resource variable.
 */
_Releases_lock_(*Resource)
NTSYSAPI
VOID
NTAPI
RtlReleaseResource(
    _Inout_ PRTL_RESOURCE Resource
);

/**
 * The RtlConvertSharedToExclusive routine converts shared access of a resource variable to exclusive access.
 *
 * \param Resource A pointer to the resource variable.
 */
NTSYSAPI
VOID
NTAPI
RtlConvertSharedToExclusive(
    _Inout_ PRTL_RESOURCE Resource
);

/**
 * The RtlConvertExclusiveToShared routine converts exclusive access of a resource variable to shared access.
 *
 * \param Resource A pointer to the resource variable.
 */
NTSYSAPI
VOID
NTAPI
RtlConvertExclusiveToShared(
    _Inout_ PRTL_RESOURCE Resource
);

/**
 * The RtlDumpResource routine dumps diagnostic information about the specified resource variable.
 *
 * \param Resource A pointer to the resource variable.
 * \return The number of threads currently waiting on the resource.
 */
NTSYSAPI
ULONG
NTAPI
RtlDumpResource(
    _Inout_ PRTL_RESOURCE Resource
);

#pragma endregion phnt

#pragma region SRW Lock

typedef struct _RTL_SRWLOCK64
{
    VOID* POINTER_64 Ptr;
} RTL_SRWLOCK64, *PRTL_SRWLOCK64;

typedef struct _RTL_SRWLOCK32
{
    VOID* POINTER_32 Ptr;
} RTL_SRWLOCK32, *PRTL_SRWLOCK32;

// winbase:InitializeSRWLock
/**
 * The RtlInitializeSRWLock routine initializes a slim reader/writer (SRW) lock.
 *
 * \param SRWLock A pointer to the SRW lock.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializesrwlock
 */
NTSYSAPI
VOID
NTAPI
RtlInitializeSRWLock(
    _Out_ PRTL_SRWLOCK SRWLock
);

// winbase:AcquireSRWLockExclusive
/**
 * The RtlAcquireSRWLockExclusive routine acquires a slim reader/writer (SRW) lock in exclusive mode.
 *
 * \param SRWLock A pointer to the SRW lock.
 */
_Acquires_exclusive_lock_(*SRWLock)
NTSYSAPI
VOID
NTAPI
RtlAcquireSRWLockExclusive(
    _Inout_ PRTL_SRWLOCK SRWLock
);

// winbase:AcquireSRWLockShared
/**
 * The RtlAcquireSRWLockShared routine acquires a slim reader/writer (SRW) lock in shared mode.
 *
 * \param SRWLock A pointer to the SRW lock.
 */
_Acquires_shared_lock_(*SRWLock)
NTSYSAPI
VOID
NTAPI
RtlAcquireSRWLockShared(
    _Inout_ PRTL_SRWLOCK SRWLock
);

// winbase:ReleaseSRWLockExclusive
/**
 * The RtlReleaseSRWLockExclusive routine releases a slim reader/writer (SRW) lock that was acquired in exclusive mode.
 *
 * \param SRWLock A pointer to the SRW lock.
 */
_Releases_exclusive_lock_(*SRWLock)
NTSYSAPI
VOID
NTAPI
RtlReleaseSRWLockExclusive(
    _Inout_ PRTL_SRWLOCK SRWLock
);

// winbase:ReleaseSRWLockShared
/**
 * The RtlReleaseSRWLockShared routine releases a slim reader/writer (SRW) lock that was acquired in shared mode.
 *
 * \param SRWLock A pointer to the SRW lock.
 */
_Releases_shared_lock_(*SRWLock)
NTSYSAPI
VOID
NTAPI
RtlReleaseSRWLockShared(
    _Inout_ PRTL_SRWLOCK SRWLock
);

// winbase:TryAcquireSRWLockExclusive
/**
 * The RtlTryAcquireSRWLockExclusive routine attempts to acquire a slim reader/writer (SRW) lock in exclusive mode
 * without blocking.
 *
 * \param SRWLock A pointer to the SRW lock.
 * \return `TRUE` if the lock was acquired, otherwise `FALSE`.
 */
_When_(return != 0, _Acquires_exclusive_lock_(*SRWLock))
NTSYSAPI
BOOLEAN
NTAPI
RtlTryAcquireSRWLockExclusive(
    _Inout_ PRTL_SRWLOCK SRWLock
);

// winbase:TryAcquireSRWLockShared
/**
 * The RtlTryAcquireSRWLockShared routine attempts to acquire a slim reader/writer (SRW) lock in shared mode without
 * blocking.
 *
 * \param SRWLock A pointer to the SRW lock.
 * \return `TRUE` if the lock was acquired, otherwise `FALSE`.
 */
_When_(return != 0, _Acquires_shared_lock_(*SRWLock))
NTSYSAPI
BOOLEAN
NTAPI
RtlTryAcquireSRWLockShared(
    _Inout_ PRTL_SRWLOCK SRWLock
);

// rev
/**
 * The RtlAcquireReleaseSRWLockExclusive routine acquires and immediately releases a slim reader/writer (SRW) lock in
 * exclusive mode, which can be used to drain pending exclusive waiters.
 *
 * \param SRWLock A pointer to the SRW lock.
 */
_Requires_lock_not_held_(*SRWLock)
NTSYSAPI
VOID
NTAPI
RtlAcquireReleaseSRWLockExclusive(
    _Inout_ PRTL_SRWLOCK SRWLock
);

#if (NTDDI_VERSION >= NTDDI_WIN10)
// rev
/**
 * The RtlConvertSRWLockExclusiveToShared routine converts a slim reader/writer (SRW) lock held in exclusive mode to
 * shared mode.
 *
 * \param SRWLock A pointer to the SRW lock.
 * \return `TRUE` if the conversion succeeded, otherwise `FALSE`.
 */
_Requires_exclusive_lock_held_(*SRWLock)
NTSYSAPI
BOOLEAN
NTAPI
RtlConvertSRWLockExclusiveToShared(
    _Inout_ PRTL_SRWLOCK SRWLock
);
#endif

#pragma endregion phnt

#pragma region Condition Variable

// winbase:InitializeConditionVariable
/**
 * The RtlInitializeConditionVariable routine initializes a condition variable.
 *
 * \param ConditionVariable A pointer to the condition variable to initialize.
 */
NTSYSAPI
VOID
NTAPI
RtlInitializeConditionVariable(
    _Out_ PRTL_CONDITION_VARIABLE ConditionVariable
);

// private
/**
 * The RtlSleepConditionVariableCS routine sleeps on a condition variable and releases the specified critical section as
 * an atomic operation.
 *
 * \param ConditionVariable A pointer to the condition variable.
 * \param CriticalSection A pointer to the critical section associated with the condition variable.
 * \param Timeout An optional pointer to the time-out interval. If `NULL`, the routine waits indefinitely.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSleepConditionVariableCS(
    _Inout_ PRTL_CONDITION_VARIABLE ConditionVariable,
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection,
    _In_opt_ PLARGE_INTEGER Timeout
);

// private
/**
 * The RtlSleepConditionVariableSRW routine sleeps on a condition variable and releases the specified slim reader/writer
 * (SRW) lock as an atomic operation.
 *
 * \param ConditionVariable A pointer to the condition variable.
 * \param SRWLock A pointer to the SRW lock associated with the condition variable.
 * \param Timeout An optional pointer to the time-out interval. If `NULL`, the routine waits indefinitely.
 * \param Flags If RTL_CONDITION_VARIABLE_LOCKMODE_SHARED is set, the SRW lock is held in shared mode; otherwise it is
 * held in exclusive mode.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSleepConditionVariableSRW(
    _Inout_ PRTL_CONDITION_VARIABLE ConditionVariable,
    _Inout_ PRTL_SRWLOCK SRWLock,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_ ULONG Flags
);

// winbase:WakeConditionVariable
/**
 * The RtlWakeConditionVariable routine wakes a single thread waiting on the specified condition variable.
 *
 * \param ConditionVariable A pointer to the condition variable.
 */
NTSYSAPI
VOID
NTAPI
RtlWakeConditionVariable(
    _Inout_ PRTL_CONDITION_VARIABLE ConditionVariable
);

// winbase:WakeAllConditionVariable
/**
 * The RtlWakeAllConditionVariable routine wakes all threads waiting on the specified condition variable.
 *
 * \param ConditionVariable A pointer to the condition variable.
 */
NTSYSAPI
VOID
NTAPI
RtlWakeAllConditionVariable(
    _Inout_ PRTL_CONDITION_VARIABLE ConditionVariable
);

#pragma endregion phnt

#pragma region Barrier

/**
 * Flags controlling barrier wait behavior.
 */
#define RTL_BARRIER_FLAGS_SPIN_ONLY     0x00000001 // never block on event - always spin
#define RTL_BARRIER_FLAGS_BLOCK_ONLY    0x00000002 // always block on event - never spin
#define RTL_BARRIER_FLAGS_NO_DELETE     0x00000004 // use if barrier will never be deleted

/**
 * The RtlInitBarrier routine initializes a synchronization barrier for a specified number of threads.
 *
 * \param Barrier A pointer to the barrier to initialize.
 * \param TotalThreads The maximum number of threads that participate in the barrier.
 * \param SpinCount The number of times a thread spins while waiting for other threads to reach the barrier.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlInitBarrier(
    _Out_ PRTL_BARRIER Barrier,
    _In_ ULONG TotalThreads,
    _In_ ULONG SpinCount
);

/**
 * The RtlDeleteBarrier routine releases all resources used by a synchronization barrier that is no longer needed.
 *
 * \param Barrier A pointer to the barrier to delete.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteBarrier(
    _In_ PRTL_BARRIER Barrier
);

/**
 * The RtlBarrier routine causes the calling thread to wait at a synchronization barrier until the required number of
 * threads have reached it.
 *
 * \param Barrier A pointer to the barrier.
 * \param Flags Flags that control the barrier behavior.
 * \return `TRUE` for the last thread to reach the barrier, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlBarrier(
    _Inout_ PRTL_BARRIER Barrier,
    _In_ ULONG Flags
);

/**
 * The RtlBarrierForDelete routine waits at a synchronization barrier in preparation for deleting it.
 *
 * \param Barrier A pointer to the barrier.
 * \param Flags Flags that control the barrier behavior.
 * \return `TRUE` for the last thread to reach the barrier, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlBarrierForDelete(
    _Inout_ PRTL_BARRIER Barrier,
    _In_ ULONG Flags
);

#pragma endregion phnt

#pragma region Wait on Address

#if (NTDDI_VERSION >= NTDDI_WIN8)

/**
 * The RtlWaitOnAddress routine waits for the value at the specified address to change.
 *
 * @param Address The address on which to wait.
 * @param CompareAddress A pointer to the location of the previously observed value at Address.
 * @param AddressSize The size of the value, in bytes. This parameter can be 1, 2, 4, or 8.
 * @param Timeout A pointer to the time-out value, in units of 100 nanoseconds. If this parameter is NULL, the thread waits indefinitely.
 * - A negative value specifies an interval relative to the current time.
 * - A positive value specifies an absolute time, measured in 100-nanosecond intervals since January 1, 1601 (UTC).
 * @remarks WaitOnAddress is guaranteed to return when the address is signaled, but it is also allowed to return for other reasons.
 * For this reason, the caller should compare the new value with the original undesired value to confirm that the value has actually changed.
 * @sa https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitonaddress
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlWaitOnAddress(
    _In_reads_bytes_(AddressSize) volatile VOID * Address,
    _In_reads_bytes_(AddressSize) PVOID CompareAddress,
    _In_ SIZE_T AddressSize,
    _In_opt_ PLARGE_INTEGER Timeout
);

NTSYSAPI
VOID
NTAPI
RtlWakeAddressAll(
    _In_ PVOID Address
);

NTSYSAPI
VOID
NTAPI
RtlWakeAddressAllNoFence(
    _In_ PVOID Address
);

NTSYSAPI
VOID
NTAPI
RtlWakeAddressSingle(
    _In_ PVOID Address
);

NTSYSAPI
VOID
NTAPI
RtlWakeAddressSingleNoFence(
    _In_ PVOID Address
);

#endif

#pragma endregion phnt

#pragma region RCU

//
// Read-Copy Update.
//
// RCU synchronization allows concurrent access to shared data structures,
// such as linked lists, trees, or hash tables, without using traditional locking methods
// in scenarios where read operations are frequent and need to be fast.
// It is particularly useful in multi-threaded environments where multiple threads
// may read from the same data structure while one or more threads may modify it.
// @remarks RCU synchronization is not for general-purpose synchronization.
// Teb->Rcu is used to store the RCU state.

#if (NTDDI_VERSION >= NTDDI_WIN11_ZN)

/**
 * Represents a per-thread registration entry within a read-copy-update (RCU) domain.
 */
typedef struct _RTL_RCU_THREAD_ENTRY
{
    volatile long long RefCount;
    ULONG SessionId;
    ULONG ThreadId;
    volatile long long ObservedEpoch;
    struct _RTL_RCU_THREAD_ENTRY* Next;
} RTL_RCU_THREAD_ENTRY, *PRTL_RCU_THREAD_ENTRY;

/**
 * Represents a hash bucket array of registered RCU thread entries.
 */
typedef struct _RTL_RCU_BUCKET_ARRAY
{
    ULONG Count;
    ULONG Reserved;
    PRTL_RCU_THREAD_ENTRY Slots[ANYSIZE_ARRAY];
    //struct _RTL_RCU_BUCKET_ARRAY* Next; // after Slots
} RTL_RCU_BUCKET_ARRAY, *PRTL_RCU_BUCKET_ARRAY;

/**
 * Represents the state of a read-copy-update (RCU) synchronization domain.
 */
typedef struct _RTL_RCU_STATE
{
    struct _RTL_RCU_STATE* Flink;
    struct _RTL_RCU_STATE* Blink;
    volatile long long Epoch;
    RTL_RCU_BUCKET_ARRAY* Buckets;
    PRTL_RCU_THREAD_ENTRY ThreadListHead;
    PRTL_RCU_THREAD_ENTRY BucketCache[10];
    RTL_SRWLOCK Lock;
    ULONG Options;
    ULONG ReservedTail;
} RTL_RCU_STATE, *PRTL_RCU_STATE;

/**
 * The RtlRcuAllocate routine allocates and initializes a read-copy-update (RCU) synchronization state.
 *
 * \param Options Options that control the created RCU state.
 * \return A pointer to the allocated RCU state, or `NULL` on failure.
 */
NTSYSAPI
PRTL_RCU_STATE
NTAPI
RtlRcuAllocate(
    _In_ ULONG Options
);

/**
 * The RtlRcuFree routine frees a read-copy-update (RCU) synchronization state previously allocated by RtlRcuAllocate.
 *
 * \param State A pointer to the RCU state to free.
 */
NTSYSAPI
VOID
NTAPI
RtlRcuFree(
    _In_ PRTL_RCU_STATE State
);

// Note: ThreadData can be NULL when it falls back to SRW share-lock.
/**
 * The RtlRcuReadLock routine enters a read-copy-update (RCU) read-side critical section.
 *
 * \param State A pointer to the RCU state.
 * \param ThreadData A pointer to a variable that receives the per-thread RCU entry associated with the read lock.
 */
_Acquires_lock_(*State)
NTSYSAPI
VOID
FASTCALL
RtlRcuReadLock(
    _Inout_ PRTL_RCU_STATE State,
    _Outptr_result_maybenull_ PRTL_RCU_THREAD_ENTRY* ThreadData
    );

/**
 * The RtlRcuReadUnlock routine leaves a read-copy-update (RCU) read-side critical section.
 *
 * \param State A pointer to the RCU state.
 * \param ThreadData A pointer to the per-thread RCU entry returned by RtlRcuReadLock.
 */
_Releases_lock_(*State)
NTSYSAPI
VOID
FASTCALL
RtlRcuReadUnlock(
    _Inout_ PRTL_RCU_STATE State,
    _In_ PRTL_RCU_THREAD_ENTRY* ThreadData
    );

/**
 * The RtlRcuSynchronize routine waits until all pre-existing read-copy-update (RCU) read-side critical sections have
 * completed.
 *
 * \param State A pointer to the RCU state.
 */
_Requires_lock_not_held_(*State)
NTSYSAPI
VOID
NTAPI
RtlRcuSynchronize(
    _Inout_ PRTL_RCU_STATE State
);

#endif // NTDDI_VERSION >= NTDDI_WIN11_ZN

#pragma endregion phnt

// RtlClearThreadWorkOnBehalfTicket
/**
 * The RtlClearThreadWorkOnBehalfTicket routine clears the work-on-behalf-of ticket associated with the current thread.
 *
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlClearThreadWorkOnBehalfTicket(
    VOID
    );

// RtlSetThreadWorkOnBehalfTicket
/**
 * The RtlSetThreadWorkOnBehalfTicket routine sets the work-on-behalf-of ticket associated with the current thread.
 *
 * \param Ticket A pointer to the work-on-behalf-of ticket to set.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetThreadWorkOnBehalfTicket(
    _In_ PULONGLONG Ticket
    );

// RtlTryConvertSRWLockSharedToExclusiveOrRelease
/**
 * The RtlTryConvertSRWLockSharedToExclusiveOrRelease routine attempts to upgrade a slim reader/writer (SRW) lock from
 * shared to exclusive mode, releasing the shared lock if the upgrade cannot be performed.
 *
 * \param SRWLock A pointer to the SRW lock to convert.
 * \return Returns `TRUE` if the lock was upgraded to exclusive mode, otherwise `FALSE`.
 */
_Requires_shared_lock_held_(*SRWLock)
NTSYSAPI
BOOLEAN
NTAPI
RtlTryConvertSRWLockSharedToExclusiveOrRelease(
    _Inout_ volatile RTL_SRWLOCK *SRWLock
    );

EXTERN_C_END

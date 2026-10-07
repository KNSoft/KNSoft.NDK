#pragma once

#include "../MinDef.h"
#include "../Io/Io.h"
#include "../Lpc/Base.h"

EXTERN_C_START

/* phnt */

#define WORKER_FACTORY_RELEASE_WORKER 0x0001
#define WORKER_FACTORY_WAIT 0x0002
#define WORKER_FACTORY_SET_INFORMATION 0x0004
#define WORKER_FACTORY_QUERY_INFORMATION 0x0008
#define WORKER_FACTORY_READY_WORKER 0x0010
#define WORKER_FACTORY_SHUTDOWN 0x0020

#define WORKER_FACTORY_ALL_ACCESS ( \
    STANDARD_RIGHTS_REQUIRED | \
    WORKER_FACTORY_RELEASE_WORKER | \
    WORKER_FACTORY_WAIT | \
    WORKER_FACTORY_SET_INFORMATION | \
    WORKER_FACTORY_QUERY_INFORMATION | \
    WORKER_FACTORY_READY_WORKER | \
    WORKER_FACTORY_SHUTDOWN \
    )

/**
 * The WORKERFACTORYINFOCLASS enumeration defines the information classes for querying and setting worker factory
 * information.
 */
typedef enum _WORKERFACTORYINFOCLASS
{
    WorkerFactoryTimeout,               // qs: LARGE_INTEGER
    WorkerFactoryRetryTimeout,          // qs: LARGE_INTEGER
    WorkerFactoryIdleTimeout,           // qs: LARGE_INTEGER
    WorkerFactoryBindingCount,          // qs: ULONG
    WorkerFactoryThreadMinimum,         // qs: ULONG
    WorkerFactoryThreadMaximum,         // qs: ULONG
    WorkerFactoryPaused,                // qs: ULONG or BOOLEAN
    WorkerFactoryBasicInformation,      // q: WORKER_FACTORY_BASIC_INFORMATION
    WorkerFactoryAdjustThreadGoal,      // s: ULONG
    WorkerFactoryCallbackType,          // qs: ULONG
    WorkerFactoryStackInformation,      // qs: ULONG/ULONG_PTR // 10
    WorkerFactoryThreadBasePriority,    // qs: ULONG
    WorkerFactoryTimeoutWaiters,        // qs: ULONG // since THRESHOLD
    WorkerFactoryFlags,                 // qs: ULONG
    WorkerFactoryThreadSoftMaximum,     // qs: ULONG
    WorkerFactoryThreadCpuSets,         // qs: ULONG[] // since REDSTONE5
    MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, *PWORKERFACTORYINFOCLASS;

/**
 * The WORKER_FACTORY_BASIC_INFORMATION structure contains basic information about a worker factory object.
 */
typedef struct _WORKER_FACTORY_BASIC_INFORMATION
{
    LARGE_INTEGER Timeout;
    LARGE_INTEGER RetryTimeout;
    LARGE_INTEGER IdleTimeout;
    BOOLEAN Paused;
    BOOLEAN TimerSet;
    BOOLEAN QueuedToExWorker;
    BOOLEAN MayCreate;
    BOOLEAN CreateInProgress;
    BOOLEAN InsertedIntoQueue;
    BOOLEAN Shutdown;
    ULONG BindingCount;
    ULONG ThreadMinimum;
    ULONG ThreadMaximum;
    ULONG PendingWorkerCount;
    ULONG WaitingWorkerCount;
    ULONG TotalWorkerCount;
    ULONG ReleaseCount;
    LONGLONG InfiniteWaitGoal;
    PVOID StartRoutine;
    PVOID StartParameter;
    HANDLE ProcessId;
    SIZE_T StackReserve;
    SIZE_T StackCommit;
    NTSTATUS LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION, *PWORKER_FACTORY_BASIC_INFORMATION;

/**
 * The NtCreateWorkerFactory routine creates a worker factory object that manages a pool of worker threads bound to an
 * I/O completion port.
 *
 * \param WorkerFactoryHandleReturn A pointer to a variable that receives a handle to the new worker factory object.
 * \param DesiredAccess The access mask that specifies the requested access to the worker factory object.
 * \param ObjectAttributes A pointer to an OBJECT_ATTRIBUTES structure that specifies the object attributes. This
 * parameter is optional.
 * \param CompletionPortHandle A handle to the I/O completion port that the worker factory is associated with.
 * \param WorkerProcessHandle A handle to the process in which the worker threads are created.
 * \param StartRoutine A pointer to the routine that is executed by each worker thread.
 * \param StartParameter A pointer to the parameter passed to the start routine. This parameter is optional.
 * \param MaxThreadCount The maximum number of worker threads that the factory can create. This parameter is optional.
 * \param StackReserve The amount of stack space to reserve for each worker thread, in bytes. This parameter is
 * optional.
 * \param StackCommit The amount of stack space to commit for each worker thread, in bytes. This parameter is optional.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateWorkerFactory(
    _Out_ PHANDLE WorkerFactoryHandleReturn,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE CompletionPortHandle,
    _In_ HANDLE WorkerProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID StartParameter,
    _In_opt_ ULONG MaxThreadCount,
    _In_opt_ SIZE_T StackReserve,
    _In_opt_ SIZE_T StackCommit);

/**
 * The NtQueryInformationWorkerFactory routine retrieves information about the specified worker factory.
 *
 * \param WorkerFactoryHandle A handle to the worker factory object.
 * \param WorkerFactoryInformationClass The type of information to be retrieved.
 * \param WorkerFactoryInformation A pointer to a buffer that receives the requested information.
 * \param WorkerFactoryInformationLength The size of the \c WorkerFactoryInformation buffer, in bytes.
 * \param ReturnLength A pointer to a variable that receives the number of bytes written to the \c
 * WorkerFactoryInformation buffer. This parameter is optional.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationWorkerFactory(
    _In_ HANDLE WorkerFactoryHandle,
    _In_ WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    _Out_writes_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
    _In_ ULONG WorkerFactoryInformationLength,
    _Out_opt_ PULONG ReturnLength);

/**
 * The NtSetInformationWorkerFactory routine sets information for the specified worker factory.
 *
 * \param WorkerFactoryHandle A handle to the worker factory object.
 * \param WorkerFactoryInformationClass The type of information to be set.
 * \param WorkerFactoryInformation A pointer to a buffer that contains the information to set.
 * \param WorkerFactoryInformationLength The size of the \c WorkerFactoryInformation buffer, in bytes.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationWorkerFactory(
    _In_ HANDLE WorkerFactoryHandle,
    _In_ WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    _In_reads_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
    _In_ ULONG WorkerFactoryInformationLength);

/**
 * The NtShutdownWorkerFactory routine shuts down the specified worker factory and wakes its worker threads.
 *
 * \param WorkerFactoryHandle A handle to the worker factory object.
 * \param PendingWorkerCount A pointer to a variable that receives the number of worker threads that are still pending.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtShutdownWorkerFactory(
    _In_ HANDLE WorkerFactoryHandle,
    _Inout_ volatile LONG *PendingWorkerCount);

/**
 * The NtReleaseWorkerFactoryWorker routine releases a worker thread of the worker factory so that it can process work.
 *
 * \param WorkerFactoryHandle A handle to the worker factory object.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtReleaseWorkerFactoryWorker(
    _In_ HANDLE WorkerFactoryHandle);

/**
 * The NtWorkerFactoryWorkerReady routine notifies the worker factory that the calling worker thread has finished its
 * current work and is ready for more.
 *
 * \param WorkerFactoryHandle A handle to the worker factory object.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtWorkerFactoryWorkerReady(
    _In_ HANDLE WorkerFactoryHandle);

/**
 * The WORKER_FACTORY_DEFERRED_WORK structure describes deferred work to be submitted to a worker factory.
 */
typedef struct _WORKER_FACTORY_DEFERRED_WORK
{
    PPORT_MESSAGE AlpcSendMessage;
    PVOID AlpcSendMessagePort;
    ULONG AlpcSendMessageFlags;
    ULONG Flags;
} WORKER_FACTORY_DEFERRED_WORK, *PWORKER_FACTORY_DEFERRED_WORK;

#if (NT_VERSION_MIN >= NT_VERSION_WIN8)

/**
 * The NtWaitForWorkViaWorkerFactory routine waits for work to be dispatched to the calling worker thread through the
 * worker factory and retrieves the completion packets.
 *
 * \param WorkerFactoryHandle A handle to the worker factory object.
 * \param MiniPackets A pointer to a buffer that receives the I/O completion packets associated with the dispatched
 * work.
 * \param Count The number of entries in the \c MiniPackets buffer.
 * \param PacketsReturned A pointer to a variable that receives the number of completion packets returned.
 * \param DeferredWork A pointer to a WORKER_FACTORY_DEFERRED_WORK structure that describes deferred work to be
 * performed.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtWaitForWorkViaWorkerFactory(
    _In_ HANDLE WorkerFactoryHandle,
    _Out_writes_to_(Count, *PacketsReturned) PFILE_IO_COMPLETION_INFORMATION MiniPackets,
    _In_ ULONG Count,
    _Out_ PULONG PacketsReturned,
    _In_ PWORKER_FACTORY_DEFERRED_WORK DeferredWork);

#else

/**
 * The NtWaitForWorkViaWorkerFactory routine waits for work to be dispatched to the calling worker thread through the
 * worker factory and retrieves the completion packet.
 *
 * \param WorkerFactoryHandle A handle to the worker factory object.
 * \param MiniPacket A pointer to a variable that receives the I/O completion packet associated with the dispatched
 * work.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtWaitForWorkViaWorkerFactory(
    _In_ HANDLE WorkerFactoryHandle,
    _Out_ PFILE_IO_COMPLETION_INFORMATION MiniPacket);

#endif

EXTERN_C_END

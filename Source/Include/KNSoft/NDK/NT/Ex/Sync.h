#pragma once

#include "../MinDef.h"
#include "../Ke/Ke.h"
#include "../Po/Po.h"

EXTERN_C_START

/* phnt */

#pragma region Event

#ifndef EVENT_QUERY_STATE
#define EVENT_QUERY_STATE 0x0001
#endif

#ifndef EVENT_MODIFY_STATE
#define EVENT_MODIFY_STATE 0x0002
#endif

#ifndef EVENT_ALL_ACCESS
#define EVENT_ALL_ACCESS (EVENT_QUERY_STATE|EVENT_MODIFY_STATE|STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE)
#endif

/**
 * The EVENT_INFORMATION_CLASS specifies the type of information to be retrieved about an event object.
 */
typedef enum _EVENT_INFORMATION_CLASS
{
    EventBasicInformation
} EVENT_INFORMATION_CLASS;

/**
 * The EVENT_BASIC_INFORMATION structure contains basic information about an event object.
 */
typedef struct _EVENT_BASIC_INFORMATION
{
    EVENT_TYPE EventType;   // The type of the event object (NotificationEvent or SynchronizationEvent).
    LONG EventState;        // The current state of the event object. Nonzero if the event is signaled; zero if not signaled.
} EVENT_BASIC_INFORMATION, *PEVENT_BASIC_INFORMATION;

/**
 * The NtCreateEvent routine creates an event object, sets the initial state of the event to the specified value,
 * and opens a handle to the object with the specified desired access.
 *
 * @param EventHandle A pointer to a variable that receives the event object handle.
 * @param DesiredAccess The access mask that specifies the requested access to the event object.
 * @param ObjectAttributes A pointer to an OBJECT_ATTRIBUTES structure that specifies the object attributes.
 * @param EventType The type of the event, which can be SynchronizationEvent or a NotificationEvent.
 * @param InitialState The initial state of the event object.
 * @return NTSTATUS Successful or errant status.
 * @see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwcreateevent
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateEvent(
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ EVENT_TYPE EventType,
    _In_ BOOLEAN InitialState
);

/**
 * The NtOpenEvent routine opens a handle to an existing event object.
 *
 * @param EventHandle A pointer to a variable that receives the event object handle.
 * @param DesiredAccess The access mask that specifies the requested access to the event object.
 * @param ObjectAttributes A pointer to an OBJECT_ATTRIBUTES structure that specifies the object attributes.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenEvent(
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
);

/**
 * The NtSetEvent routine sets an event object to the signaled state.
 *
 * @param EventHandle A handle to the event object.
 * @param PreviousState A pointer to a variable that receives the previous state of the event object.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetEvent(
    _In_ HANDLE EventHandle,
    _Out_opt_ PLONG PreviousState
);

#if (NTDDI_VERSION >= NTDDI_WIN11_ZN)
/**
 * The NtSetEventEx routine sets an event object to the signaled state and optionally acquires a lock.
 *
 * @param ThreadId A handle to the thread.
 * @param Lock A pointer to an RTL_SRWLOCK structure that specifies the lock to acquire.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetEventEx(
    _In_ HANDLE ThreadId,
    _In_opt_ PRTL_SRWLOCK Lock
);
#endif

/**
 * The NtSetEventBoostPriority routine sets an event object to the signaled state and boosts the priority of threads waiting on the event.
 *
 * @param EventHandle A handle to the event object.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetEventBoostPriority(
    _In_ HANDLE EventHandle
);

/**
 * The NtClearEvent routine sets an event object to the not-signaled state.
 *
 * @param EventHandle A handle to the event object.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtClearEvent(
    _In_ HANDLE EventHandle
);

/**
 * The NtResetEvent routine sets an event object to the not-signaled state and optionally returns the previous state.
 *
 * @param EventHandle A handle to the event object.
 * @param PreviousState A pointer to a variable that receives the previous state of the event object.
 * @return NTSTATUS Successful or errant status.
 * @see https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-resetevent
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtResetEvent(
    _In_ HANDLE EventHandle,
    _Out_opt_ PLONG PreviousState
);

/**
 * The NtPulseEvent routine sets an event object to the signaled state and then resets it to the not-signaled state after releasing the appropriate number of waiting threads.
 *
 * @param EventHandle A handle to the event object.
 * @param PreviousState A pointer to a variable that receives the previous state of the event object.
 * @return NTSTATUS Successful or errant status.
 * @see https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-pulseevent
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtPulseEvent(
    _In_ HANDLE EventHandle,
    _Out_opt_ PLONG PreviousState
);

/**
 * The NtQueryEvent routine retrieves information about an event object.
 *
 * @param EventHandle A handle to the event object.
 * @param EventInformationClass The type of information to be retrieved.
 * @param EventInformation A pointer to a buffer that receives the requested information.
 * @param EventInformationLength The size of the buffer pointed to by EventInformation.
 * @param ReturnLength A pointer to a variable that receives the size of the data returned in the buffer.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryEvent(
    _In_ HANDLE EventHandle,
    _In_ EVENT_INFORMATION_CLASS EventInformationClass,
    _Out_writes_bytes_(EventInformationLength) PVOID EventInformation,
    _In_ ULONG EventInformationLength,
    _Out_opt_ PULONG ReturnLength
);

#pragma endregion

#pragma region Event Pair

#define EVENT_PAIR_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE)

/**
 * The NtCreateEventPair routine creates an event pair object and opens a handle to the object with the specified desired access.
 *
 * @param EventPairHandle A pointer to a variable that receives the event pair object handle.
 * @param DesiredAccess The access mask that specifies the requested access to the event pair object.
 * @param ObjectAttributes A pointer to an OBJECT_ATTRIBUTES structure that specifies the object attributes.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateEventPair(
    _Out_ PHANDLE EventPairHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes);

/**
 * The NtOpenEventPair routine opens a handle to an existing event pair object.
 *
 * @param EventPairHandle A pointer to a variable that receives the event pair object handle.
 * @param DesiredAccess The access mask that specifies the requested access to the event pair object.
 * @param ObjectAttributes A pointer to an OBJECT_ATTRIBUTES structure that specifies the object attributes.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenEventPair(
    _Out_ PHANDLE EventPairHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes);

/**
 * The NtSetLowEventPair routine sets the low event in an event pair to the signaled state.
 *
 * @param EventPairHandle A handle to the event pair object.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetLowEventPair(
    _In_ HANDLE EventPairHandle);

/**
 * The NtSetHighEventPair routine sets the high event in an event pair to the signaled state.
 *
 * @param EventPairHandle A handle to the event pair object.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetHighEventPair(
    _In_ HANDLE EventPairHandle);

/**
 * The NtWaitLowEventPair routine waits for the low event in an event pair to be set to the signaled state.
 *
 * @param EventPairHandle A handle to the event pair object.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtWaitLowEventPair(
    _In_ HANDLE EventPairHandle);

/**
 * The NtWaitHighEventPair routine waits for the high event in an event pair to be set to the signaled state.
 *
 * @param EventPairHandle A handle to the event pair object.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtWaitHighEventPair(
    _In_ HANDLE EventPairHandle);

/**
 * The NtSetLowWaitHighEventPair routine sets the low event in an event pair to the signaled state and waits for the high event to be set to the signaled state.
 *
 * @param EventPairHandle A handle to the event pair object.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetLowWaitHighEventPair(
    _In_ HANDLE EventPairHandle);

/**
 * The NtSetHighWaitLowEventPair routine sets the high event in an event pair to the signaled state and waits for the low event to be set to the signaled state.
 *
 * @param EventPairHandle A handle to the event pair object.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetHighWaitLowEventPair(
    _In_ HANDLE EventPairHandle);

#pragma endregion

#pragma region Mutant

#ifndef MUTANT_QUERY_STATE
#define MUTANT_QUERY_STATE 0x0001
#endif

#ifndef MUTANT_ALL_ACCESS
#define MUTANT_ALL_ACCESS (MUTANT_QUERY_STATE|STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE)
#endif

typedef enum _MUTANT_INFORMATION_CLASS
{
    MutantBasicInformation, // MUTANT_BASIC_INFORMATION
    MutantOwnerInformation // MUTANT_OWNER_INFORMATION
} MUTANT_INFORMATION_CLASS;

/**
 * The MUTANT_BASIC_INFORMATION structure contains basic information about a mutant object.
 */
typedef struct _MUTANT_BASIC_INFORMATION
{
    LONG CurrentCount;
    BOOLEAN OwnedByCaller;
    BOOLEAN AbandonedState;
} MUTANT_BASIC_INFORMATION, *PMUTANT_BASIC_INFORMATION;

/**
 * The MUTANT_OWNER_INFORMATION structure contains information about the owner of a mutant object.
 */
typedef struct _MUTANT_OWNER_INFORMATION
{
    CLIENT_ID ClientId;
} MUTANT_OWNER_INFORMATION, *PMUTANT_OWNER_INFORMATION;

/**
 * The NtCreateMutant routine creates a mutant object, sets the initial state of the mutant to the specified value,
 * and opens a handle to the object with the specified desired access.
 *
 * @param MutantHandle A pointer to a variable that receives the mutant object handle.
 * @param DesiredAccess The access mask that specifies the requested access to the mutant object.
 * @param ObjectAttributes A pointer to an OBJECT_ATTRIBUTES structure that specifies the object attributes.
 * @param InitialOwner If TRUE, the calling thread is the initial owner of the mutant object.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateMutant(
    _Out_ PHANDLE MutantHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_ BOOLEAN InitialOwner);

/**
 * The NtOpenMutant routine opens a handle to an existing mutant object.
 *
 * @param MutantHandle A pointer to a variable that receives the mutant object handle.
 * @param DesiredAccess The access mask that specifies the requested access to the mutant object.
 * @param ObjectAttributes A pointer to an OBJECT_ATTRIBUTES structure that specifies the object attributes.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenMutant(
    _Out_ PHANDLE MutantHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes);

/**
 * The NtReleaseMutant routine releases ownership of a mutant object.
 *
 * @param MutantHandle A handle to the mutant object.
 * @param PreviousCount A pointer to a variable that receives the previous count of the mutant object.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtReleaseMutant(
    _In_ HANDLE MutantHandle,
    _Out_opt_ PLONG PreviousCount);

/**
 * The NtQueryMutant routine retrieves information about a mutant object.
 *
 * @param MutantHandle A handle to the mutant object.
 * @param MutantInformationClass The type of information to be retrieved.
 * @param MutantInformation A pointer to a buffer that receives the requested information.
 * @param MutantInformationLength The size of the buffer pointed to by MutantInformation.
 * @param ReturnLength A pointer to a variable that receives the size of the data returned in the buffer.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryMutant(
    _In_ HANDLE MutantHandle,
    _In_ MUTANT_INFORMATION_CLASS MutantInformationClass,
    _Out_writes_bytes_(MutantInformationLength) PVOID MutantInformation,
    _In_ ULONG MutantInformationLength,
    _Out_opt_ PULONG ReturnLength);

#pragma endregion

#pragma region Semaphore

#ifndef SEMAPHORE_QUERY_STATE
#define SEMAPHORE_QUERY_STATE 0x0001
#endif

#ifndef SEMAPHORE_MODIFY_STATE
#define SEMAPHORE_MODIFY_STATE 0x0002
#endif

#ifndef SEMAPHORE_ALL_ACCESS
#define SEMAPHORE_ALL_ACCESS (SEMAPHORE_QUERY_STATE|SEMAPHORE_MODIFY_STATE|STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE)
#endif

typedef enum _SEMAPHORE_INFORMATION_CLASS
{
    SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS;

/**
 * The SEMAPHORE_BASIC_INFORMATION structure contains basic information about a semaphore object.
 */
typedef struct _SEMAPHORE_BASIC_INFORMATION
{
    LONG CurrentCount;
    LONG MaximumCount;
} SEMAPHORE_BASIC_INFORMATION, *PSEMAPHORE_BASIC_INFORMATION;

/**
 * The NtCreateSemaphore routine creates a semaphore object, sets the initial count of the semaphore to the specified value,
 * and opens a handle to the object with the specified desired access.
 *
 * @param SemaphoreHandle A pointer to a variable that receives the semaphore object handle.
 * @param DesiredAccess The access mask that specifies the requested access to the semaphore object.
 * @param ObjectAttributes A pointer to an OBJECT_ATTRIBUTES structure that specifies the object attributes.
 * @param InitialCount The initial count of the semaphore object.
 * @param MaximumCount The maximum count of the semaphore object.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateSemaphore(
    _Out_ PHANDLE SemaphoreHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_ LONG InitialCount,
    _In_ LONG MaximumCount);

/**
 * The NtOpenSemaphore routine opens a handle to an existing semaphore object.
 *
 * @param SemaphoreHandle A pointer to a variable that receives the semaphore object handle.
 * @param DesiredAccess The access mask that specifies the requested access to the semaphore object.
 * @param ObjectAttributes A pointer to an OBJECT_ATTRIBUTES structure that specifies the object attributes.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenSemaphore(
    _Out_ PHANDLE SemaphoreHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes);

/**
 * The NtReleaseSemaphore routine increases the count of the specified semaphore object by a specified amount.
 *
 * @param SemaphoreHandle A handle to the semaphore object.
 * @param ReleaseCount The amount by which the semaphore object's count is to be increased.
 * @param PreviousCount A pointer to a variable that receives the previous count of the semaphore object.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtReleaseSemaphore(
    _In_ HANDLE SemaphoreHandle,
    _In_ LONG ReleaseCount,
    _Out_opt_ PLONG PreviousCount);

/**
 * The NtQuerySemaphore routine retrieves information about a semaphore object.
 *
 * @param SemaphoreHandle A handle to the semaphore object.
 * @param SemaphoreInformationClass The type of information to be retrieved.
 * @param SemaphoreInformation A pointer to a buffer that receives the requested information.
 * @param SemaphoreInformationLength The size of the buffer pointed to by SemaphoreInformation.
 * @param ReturnLength A pointer to a variable that receives the size of the data returned in the buffer.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySemaphore(
    _In_ HANDLE SemaphoreHandle,
    _In_ SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
    _Out_writes_bytes_(SemaphoreInformationLength) PVOID SemaphoreInformation,
    _In_ ULONG SemaphoreInformationLength,
    _Out_opt_ PULONG ReturnLength);

#pragma endregion

#pragma region Timer

#ifndef TIMER_QUERY_STATE
#define TIMER_QUERY_STATE 0x0001
#endif

#ifndef TIMER_MODIFY_STATE
#define TIMER_MODIFY_STATE 0x0002
#endif

#ifndef TIMER_ALL_ACCESS
#define TIMER_ALL_ACCESS (TIMER_QUERY_STATE|TIMER_MODIFY_STATE|STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE)
#endif

typedef enum _TIMER_INFORMATION_CLASS
{
    TimerBasicInformation // TIMER_BASIC_INFORMATION
} TIMER_INFORMATION_CLASS;

typedef struct _TIMER_BASIC_INFORMATION
{
    LARGE_INTEGER RemainingTime;
    BOOLEAN TimerState;
} TIMER_BASIC_INFORMATION, *PTIMER_BASIC_INFORMATION;

typedef
_Function_class_(TIMER_APC_ROUTINE)
VOID
NTAPI
TIMER_APC_ROUTINE(
    _In_ PVOID TimerContext,
    _In_ ULONG TimerLowValue,
    _In_ LONG TimerHighValue);
typedef TIMER_APC_ROUTINE* PTIMER_APC_ROUTINE;

typedef enum _TIMER_SET_INFORMATION_CLASS
{
    TimerSetCoalescableTimer, // TIMER_SET_COALESCABLE_TIMER_INFO
    MaxTimerInfoClass
} TIMER_SET_INFORMATION_CLASS;

typedef struct _TIMER_SET_COALESCABLE_TIMER_INFO
{
    _In_ LARGE_INTEGER DueTime;
    _In_opt_ PTIMER_APC_ROUTINE TimerApcRoutine;
    _In_opt_ PVOID TimerContext;
    _In_opt_ PCOUNTED_REASON_CONTEXT WakeContext;
    _In_opt_ ULONG Period;
    _In_ ULONG TolerableDelay;
    _Out_opt_ PBOOLEAN PreviousState;
} TIMER_SET_COALESCABLE_TIMER_INFO, *PTIMER_SET_COALESCABLE_TIMER_INFO;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateTimer(
    _Out_ PHANDLE TimerHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_ TIMER_TYPE TimerType
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenTimer(
    _Out_ PHANDLE TimerHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetTimer(
    _In_ HANDLE TimerHandle,
    _In_ PLARGE_INTEGER DueTime,
    _In_opt_ PTIMER_APC_ROUTINE TimerApcRoutine,
    _In_opt_ PVOID TimerContext,
    _In_ BOOLEAN ResumeTimer,
    _In_opt_ LONG Period,
    _Out_opt_ PBOOLEAN PreviousState
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetTimerEx(
    _In_ HANDLE TimerHandle,
    _In_ TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
    _Inout_updates_bytes_opt_(TimerSetInformationLength) PVOID TimerSetInformation,
    _In_ ULONG TimerSetInformationLength
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCancelTimer(
    _In_ HANDLE TimerHandle,
    _Out_opt_ PBOOLEAN CurrentState
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryTimer(
    _In_ HANDLE TimerHandle,
    _In_ TIMER_INFORMATION_CLASS TimerInformationClass,
    _Out_writes_bytes_(TimerInformationLength) PVOID TimerInformation,
    _In_ ULONG TimerInformationLength,
    _Out_opt_ PULONG ReturnLength
);

#if (NTDDI_VERSION >= NTDDI_WIN8)

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateIRTimer(
    _Out_ PHANDLE TimerHandle,
    _In_ PVOID Reserved,
    _In_ ACCESS_MASK DesiredAccess
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetIRTimer(
    _In_ HANDLE TimerHandle,
    _In_opt_ PLARGE_INTEGER DueTime
);

#endif

#if (NTDDI_VERSION >= NTDDI_WIN10)
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateTimer2(
    _Out_ PHANDLE TimerHandle,
    _In_opt_ PVOID Reserved1,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG Attributes, // TIMER_TYPE
    _In_ ACCESS_MASK DesiredAccess
);
#endif

typedef struct _T2_SET_PARAMETERS_V0
{
    ULONG Version;
    ULONG Reserved;
    LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, *PT2_SET_PARAMETERS;

typedef PVOID PT2_CANCEL_PARAMETERS;

#if (NTDDI_VERSION >= NTDDI_WIN10)

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetTimer2(
    _In_ HANDLE TimerHandle,
    _In_ PLARGE_INTEGER DueTime,
    _In_opt_ PLARGE_INTEGER Period,
    _In_ PT2_SET_PARAMETERS Parameters
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCancelTimer2(
    _In_ HANDLE TimerHandle,
    _In_ PT2_CANCEL_PARAMETERS Parameters
);

#endif

#pragma endregion

#pragma region Profile

#define PROFILE_CONTROL 0x0001
#define PROFILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | PROFILE_CONTROL)

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateProfile(
    _Out_ PHANDLE ProfileHandle,
    _In_opt_ HANDLE Process,
    _In_ PVOID ProfileBase,
    _In_ SIZE_T ProfileSize,
    _In_ ULONG BucketSize,
    _In_reads_bytes_(BufferSize) PULONG Buffer,
    _In_ ULONG BufferSize,
    _In_ KPROFILE_SOURCE ProfileSource,
    _In_ KAFFINITY Affinity
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateProfileEx(
    _Out_ PHANDLE ProfileHandle,
    _In_opt_ HANDLE Process,
    _In_ PVOID ProfileBase,
    _In_ SIZE_T ProfileSize,
    _In_ ULONG BucketSize,
    _In_reads_bytes_(BufferSize) PULONG Buffer,
    _In_ ULONG BufferSize,
    _In_ KPROFILE_SOURCE ProfileSource,
    _In_ USHORT GroupCount,
    _In_reads_(GroupCount) PGROUP_AFFINITY GroupAffinity
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtStartProfile(
    _In_ HANDLE ProfileHandle
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtStopProfile(
    _In_ HANDLE ProfileHandle
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryIntervalProfile(
    _In_ KPROFILE_SOURCE ProfileSource,
    _Out_ PULONG Interval
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetIntervalProfile(
    _In_ ULONG Interval,
    _In_ KPROFILE_SOURCE Source
);

#pragma endregion

#pragma region Keyed Event

#define KEYEDEVENT_WAIT 0x0001
#define KEYEDEVENT_WAKE 0x0002
#define KEYEDEVENT_ALL_ACCESS \
    (STANDARD_RIGHTS_REQUIRED | KEYEDEVENT_WAIT | KEYEDEVENT_WAKE)

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateKeyedEvent(
    _Out_ PHANDLE KeyedEventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _Reserved_ ULONG Flags
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenKeyedEvent(
    _Out_ PHANDLE KeyedEventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtReleaseKeyedEvent(
    _In_opt_ HANDLE KeyedEventHandle,
    _In_ PVOID KeyValue,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtWaitForKeyedEvent(
    _In_opt_ HANDLE KeyedEventHandle,
    _In_ PVOID KeyValue,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
);

#pragma endregion

#pragma region Cross Vm

#if (NTDDI_VERSION >= NTDDI_WIN10_MN)

// rev
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateCrossVmEvent(
    _Out_ PHANDLE CrossVmEvent,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG CrossVmEventFlags,
    _In_ LPCGUID VMID,
    _In_ LPCGUID ServiceID
);

// rev
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateCrossVmMutant(
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG CrossVmEventFlags,
    _In_ LPCGUID VMID,
    _In_ LPCGUID ServiceID
);

// rev
NTSYSCALLAPI
NTSTATUS
NTAPI
NtAcquireCrossVmMutant(
    _In_ HANDLE CrossVmMutant,
    _In_ PLARGE_INTEGER Timeout
);

#endif

#pragma endregion

EXTERN_C_END

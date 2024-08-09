#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* wdm.h */
typedef enum _KINTERRUPT_MODE
{
    LevelSensitive,
    Latched
} KINTERRUPT_MODE;

/* phnt */

typedef enum _KPROFILE_SOURCE
{
    ProfileTime,
    ProfileAlignmentFixup,
    ProfileTotalIssues,
    ProfilePipelineDry,
    ProfileLoadInstructions,
    ProfilePipelineFrozen,
    ProfileBranchInstructions,
    ProfileTotalNonissues,
    ProfileDcacheMisses,
    ProfileIcacheMisses,
    ProfileCacheMisses,
    ProfileBranchMispredictions,
    ProfileStoreInstructions,
    ProfileFpInstructions,
    ProfileIntegerInstructions,
    Profile2Issue,
    Profile3Issue,
    Profile4Issue,
    ProfileSpecialInstructions,
    ProfileTotalCycles,
    ProfileIcacheIssues,
    ProfileDcacheAccesses,
    ProfileMemoryBarrierCycles,
    ProfileLoadLinkedIssues,
    ProfileMaximum
} KPROFILE_SOURCE;

/* wdm.h */

typedef LONG KPRIORITY;

#define LOW_PRIORITY 0              // Lowest thread priority level
#define LOW_REALTIME_PRIORITY 16    // Lowest realtime priority level
#define HIGH_PRIORITY 31            // Highest thread priority level
#define MAXIMUM_PRIORITY 32         // Number of thread priority levels

#define MAXIMUM_WAIT_OBJECTS 64     // Maximum number of wait objects

#define MAXIMUM_SUSPEND_COUNT MAXCHAR // Maximum times thread can be suspended

/* phnt */

typedef enum _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    MaximumThreadState
} KTHREAD_STATE, *PKTHREAD_STATE;

typedef enum _KHETERO_CPU_POLICY
{
    KHeteroCpuPolicyAll = 0,
    KHeteroCpuPolicyLarge = 1,
    KHeteroCpuPolicyLargeOrIdle = 2,
    KHeteroCpuPolicySmall = 3,
    KHeteroCpuPolicySmallOrIdle = 4,
    KHeteroCpuPolicyDynamic = 5,
    KHeteroCpuPolicyStaticMax = 5, // valid
    KHeteroCpuPolicyBiasedSmall = 6,
    KHeteroCpuPolicyBiasedLarge = 7,
    KHeteroCpuPolicyDefault = 8,
    KHeteroCpuPolicyMax = 9
} KHETERO_CPU_POLICY, *PKHETERO_CPU_POLICY;

typedef enum _KWAIT_REASON
{
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    WrAlertByThreadId,
    WrDeferredPreempt,
    WrPhysicalFault,
    WrIoRing,
    WrMdlCache,
    WrRcu,
    MaximumWaitReason
} KWAIT_REASON, *PKWAIT_REASON;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCallbackReturn(
    _In_reads_bytes_opt_(OutputLength) PVOID OutputBuffer,
    _In_ ULONG OutputLength,
    _In_ NTSTATUS Status);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtFlushProcessWriteBuffers(VOID);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtYieldExecution(VOID);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDelayExecution(
    _In_ BOOLEAN Alertable,
    _In_ PLARGE_INTEGER DelayInterval);

EXTERN_C_END

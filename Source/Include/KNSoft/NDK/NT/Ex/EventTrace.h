#pragma once

#include "../MinDef.h"
#include "../Ke/Ke.h"

#include <timezoneapi.h>
#include <evntrace.h>

EXTERN_C_START

/**
 * The EVENT_TRACE_INFORMATION_CLASS enumeration defines the information classes used with event tracing (ETW).
 */
typedef enum _EVENT_TRACE_INFORMATION_CLASS
{
    EventTraceKernelVersionInformation,                 // q: EVENT_TRACE_VERSION_INFORMATION
    EventTraceGroupMaskInformation,                     // qs: EVENT_TRACE_GROUPMASK_INFORMATION
    EventTracePerformanceInformation,                   // q: EVENT_TRACE_PERFORMANCE_INFORMATION
    EventTraceTimeProfileInformation,                   // qs: EVENT_TRACE_TIME_PROFILE_INFORMATION
    EventTraceSessionSecurityInformation,               // s: EVENT_TRACE_SESSION_SECURITY_INFORMATION
    EventTraceSpinlockInformation,                      // s: EVENT_TRACE_SPINLOCK_INFORMATION
    EventTraceStackTracingInformation,                  // s: EVENT_TRACE_STACK_TRACING_INFORMATION
    EventTraceExecutiveResourceInformation,             // s: EVENT_TRACE_EXECUTIVE_RESOURCE_INFORMATION
    EventTraceHeapTracingInformation,                   // s: EVENT_TRACE_HEAP_TRACING_INFORMATION
    EventTraceHeapSummaryTracingInformation,            // s: EVENT_TRACE_HEAP_TRACING_INFORMATION
    EventTracePoolTagFilterInformation,                 // s: EVENT_TRACE_POOLTAG_FILTER_INFORMATION
    EventTracePebsTracingInformation,                   // s: EVENT_TRACE_PEBS_TRACING_INFORMATION
    EventTraceProfileConfigInformation,                 // s: EVENT_TRACE_PROFILE_CONFIG_INFORMATION
    EventTraceProfileSourceListInformation,             // q: EVENT_TRACE_PROFILE_LIST_INFORMATION
    EventTraceProfileEventListInformation,              // s: EVENT_TRACE_PROFILE_EVENT_INFORMATION
    EventTraceProfileCounterListInformation,            // s: EVENT_TRACE_PROFILE_COUNTER_INFORMATION
    EventTraceStackCachingInformation,                  // s: EVENT_TRACE_STACK_CACHING_INFORMATION
    EventTraceObjectTypeFilterInformation,              // s: EVENT_TRACE_OBJECT_TYPE_FILTER_INFORMATION
    EventTraceSoftRestartInformation,                   // s: EVENT_TRACE_SOFT_RESTART_INFORMATION
    EventTraceLastBranchConfigurationInformation,       // s: EVENT_TRACE_LAST_BRANCH_CONFIGURATION_INFORMATION // REDSTONE3
    EventTraceLastBranchEventListInformation,           // s: EVENT_TRACE_PROFILE_EVENT_INFORMATION
    EventTraceProfileSourceAddInformation,              // s: EVENT_TRACE_PROFILE_ADD_INFORMATION // REDSTONE4
    EventTraceProfileSourceRemoveInformation,           // s: EVENT_TRACE_PROFILE_REMOVE_INFORMATION
    EventTraceProcessorTraceConfigurationInformation,   // s: EVENT_TRACE_PROCESSOR_TRACE_CONFIGURATION_INFORMATION
    EventTraceProcessorTraceEventListInformation,       // s: EVENT_TRACE_PROFILE_EVENT_INFORMATION
    EventTraceCoverageSamplerInformation,               // s: EVENT_TRACE_COVERAGE_SAMPLER_INFORMATION
    EventTraceUnifiedStackCachingInformation,           // s: EVENT_TRACE_STACK_CACHING_INFORMATION // since 21H1
    EventTraceContextRegisterTraceInformation,          // s: EVENT_TRACE_CONTEXT_REGISTER_INFO // 24H2
    MaxEventTraceInfoClass
} EVENT_TRACE_INFORMATION_CLASS;

/**
 * The EVENT_TRACE_VERSION_INFORMATION structure contains event trace version information.
 */
typedef struct _EVENT_TRACE_VERSION_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    ULONG EventTraceKernelVersion;
} EVENT_TRACE_VERSION_INFORMATION, *PEVENT_TRACE_VERSION_INFORMATION;

/**
 * The EVENT_TRACE_GROUPMASK_INFORMATION structure contains event trace groupmask information.
 */
typedef struct _EVENT_TRACE_GROUPMASK_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    TRACEHANDLE TraceHandle;
    ULONG Masks[8]; // PERFINFO_GROUPMASK
} EVENT_TRACE_GROUPMASK_INFORMATION, *PEVENT_TRACE_GROUPMASK_INFORMATION;

#define EVENT_TRACE_LAST_BRANCH_EVENT_OPCODE 0x20
#define EVENT_TRACE_LAST_BRANCH_MAXIMUM_EVENTS 4

#define EVENT_TRACE_LAST_BRANCH_CONFIGURATION_NONE                  0x00000000
#define EVENT_TRACE_LAST_BRANCH_CONFIGURATION_EXCLUDE_KERNEL        0x00000001
#define EVENT_TRACE_LAST_BRANCH_CONFIGURATION_EXCLUDE_USER          0x00000002
#define EVENT_TRACE_LAST_BRANCH_CONFIGURATION_EXCLUDE_JCC           0x00000004
#define EVENT_TRACE_LAST_BRANCH_CONFIGURATION_EXCLUDE_NEAR_REL_CALL 0x00000008
#define EVENT_TRACE_LAST_BRANCH_CONFIGURATION_EXCLUDE_NEAR_IND_CALL 0x00000010
#define EVENT_TRACE_LAST_BRANCH_CONFIGURATION_EXCLUDE_NEAR_RET      0x00000020
#define EVENT_TRACE_LAST_BRANCH_CONFIGURATION_EXCLUDE_NEAR_IND_JMP  0x00000040
#define EVENT_TRACE_LAST_BRANCH_CONFIGURATION_EXCLUDE_NEAR_REL_JMP  0x00000080
#define EVENT_TRACE_LAST_BRANCH_CONFIGURATION_EXCLUDE_FAR_BRANCH    0x00000100
#define EVENT_TRACE_LAST_BRANCH_CONFIGURATION_CALLSTACK_ENABLE      0x00000200
#define EVENT_TRACE_LAST_BRANCH_CONFIGURATION_SAMPLED               0x00000400

/**
 * The EVENT_TRACE_LAST_BRANCH_EVENT_ID structure describes the event trace last branch event id.
 */
typedef struct _EVENT_TRACE_LAST_BRANCH_EVENT_ID
{
    GUID EventGuid;
    UCHAR Type;
    UCHAR Reserved[7];
} EVENT_TRACE_LAST_BRANCH_EVENT_ID, *PEVENT_TRACE_LAST_BRANCH_EVENT_ID;

/**
 * The EVENT_TRACE_LAST_BRANCH_CONFIGURATION_INFORMATION structure contains event trace last branch configuration
 * information.
 */
typedef struct _EVENT_TRACE_LAST_BRANCH_CONFIGURATION_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    ULONG LbrConfiguration; // EVENT_TRACE_LAST_BRANCH_CONFIGURATION_* flags
    ULONG EventCount; // Number of valid entries in Events, up to EVENT_TRACE_LAST_BRANCH_MAXIMUM_EVENTS.
    EVENT_TRACE_LAST_BRANCH_EVENT_ID Events[EVENT_TRACE_LAST_BRANCH_MAXIMUM_EVENTS];
} EVENT_TRACE_LAST_BRANCH_CONFIGURATION_INFORMATION, *PEVENT_TRACE_LAST_BRANCH_CONFIGURATION_INFORMATION;

/**
 * The EVENT_TRACE_PROCESSOR_TRACE_CONFIGURATION_INFORMATION structure contains event trace processor trace
 * configuration information.
 */
typedef struct _EVENT_TRACE_PROCESSOR_TRACE_CONFIGURATION_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    TRACEHANDLE TraceHandle;
    PVOID Callback; // Kernel-mode processor trace configuration callback passed to the ETW hardware trace extension.
} EVENT_TRACE_PROCESSOR_TRACE_CONFIGURATION_INFORMATION, *PEVENT_TRACE_PROCESSOR_TRACE_CONFIGURATION_INFORMATION;

/**
 * The EVENT_TRACE_PERFORMANCE_INFORMATION structure contains event trace performance information.
 */
typedef struct _EVENT_TRACE_PERFORMANCE_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    LARGE_INTEGER LogfileBytesWritten;
} EVENT_TRACE_PERFORMANCE_INFORMATION, *PEVENT_TRACE_PERFORMANCE_INFORMATION;

/**
 * The EVENT_TRACE_TIME_PROFILE_INFORMATION structure contains event trace time profile information.
 */
typedef struct _EVENT_TRACE_TIME_PROFILE_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    ULONG ProfileInterval;
} EVENT_TRACE_TIME_PROFILE_INFORMATION, *PEVENT_TRACE_TIME_PROFILE_INFORMATION;

/**
 * The EVENT_TRACE_SESSION_SECURITY_INFORMATION structure contains event trace session security information.
 */
typedef struct _EVENT_TRACE_SESSION_SECURITY_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    ULONG SecurityInformation;
    TRACEHANDLE TraceHandle;
    UCHAR SecurityDescriptor[1];
} EVENT_TRACE_SESSION_SECURITY_INFORMATION, *PEVENT_TRACE_SESSION_SECURITY_INFORMATION;

/**
 * The EVENT_TRACE_SPINLOCK_INFORMATION structure contains event trace spinlock information.
 */
typedef struct _EVENT_TRACE_SPINLOCK_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    ULONG SpinLockSpinThreshold;
    ULONG SpinLockAcquireSampleRate;
    ULONG SpinLockContentionSampleRate;
    ULONG SpinLockHoldThreshold;
} EVENT_TRACE_SPINLOCK_INFORMATION, *PEVENT_TRACE_SPINLOCK_INFORMATION;

/**
 * The EVENT_TRACE_SYSTEM_EVENT_INFORMATION structure contains event trace system event information.
 */
typedef struct _EVENT_TRACE_SYSTEM_EVENT_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    TRACEHANDLE TraceHandle;
    ULONG HookId[1];
} EVENT_TRACE_SYSTEM_EVENT_INFORMATION, *PEVENT_TRACE_SYSTEM_EVENT_INFORMATION;

typedef EVENT_TRACE_SYSTEM_EVENT_INFORMATION EVENT_TRACE_STACK_TRACING_INFORMATION, *PEVENT_TRACE_STACK_TRACING_INFORMATION;
typedef EVENT_TRACE_SYSTEM_EVENT_INFORMATION EVENT_TRACE_PEBS_TRACING_INFORMATION, *PEVENT_TRACE_PEBS_TRACING_INFORMATION;
typedef EVENT_TRACE_SYSTEM_EVENT_INFORMATION EVENT_TRACE_PROFILE_EVENT_INFORMATION, *PEVENT_TRACE_PROFILE_EVENT_INFORMATION;

/**
 * The EVENT_TRACE_EXECUTIVE_RESOURCE_INFORMATION structure contains event trace executive resource information.
 */
typedef struct _EVENT_TRACE_EXECUTIVE_RESOURCE_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    ULONG ReleaseSamplingRate;
    ULONG ContentionSamplingRate;
    ULONG NumberOfExcessiveTimeouts;
} EVENT_TRACE_EXECUTIVE_RESOURCE_INFORMATION, *PEVENT_TRACE_EXECUTIVE_RESOURCE_INFORMATION;

/**
 * The EVENT_TRACE_HEAP_TRACING_INFORMATION structure contains event trace heap tracing information.
 */
typedef struct _EVENT_TRACE_HEAP_TRACING_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    ULONG ProcessId[1];
} EVENT_TRACE_HEAP_TRACING_INFORMATION, *PEVENT_TRACE_HEAP_TRACING_INFORMATION;

/**
 * The EVENT_TRACE_TAG_FILTER_INFORMATION structure contains event trace tag filter information.
 */
typedef struct _EVENT_TRACE_TAG_FILTER_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    TRACEHANDLE TraceHandle;
    ULONG Filter[1];
} EVENT_TRACE_TAG_FILTER_INFORMATION, *PEVENT_TRACE_TAG_FILTER_INFORMATION;

typedef EVENT_TRACE_TAG_FILTER_INFORMATION EVENT_TRACE_POOLTAG_FILTER_INFORMATION, *PEVENT_TRACE_POOLTAG_FILTER_INFORMATION;
typedef EVENT_TRACE_TAG_FILTER_INFORMATION EVENT_TRACE_OBJECT_TYPE_FILTER_INFORMATION, *PEVENT_TRACE_OBJECT_TYPE_FILTER_INFORMATION;

// ProfileSource
#define ETW_MAX_PROFILING_SOURCES 4
#define ETW_MAX_PMC_EVENTS        4
#define ETW_MAX_PMC_COUNTERS      4

/**
 * The EVENT_TRACE_PROFILE_COUNTER_INFORMATION structure contains event trace profile counter information.
 */
typedef struct _EVENT_TRACE_PROFILE_COUNTER_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    TRACEHANDLE TraceHandle;
    ULONG ProfileSource[1];
} EVENT_TRACE_PROFILE_COUNTER_INFORMATION, *PEVENT_TRACE_PROFILE_COUNTER_INFORMATION;

typedef EVENT_TRACE_PROFILE_COUNTER_INFORMATION EVENT_TRACE_PROFILE_CONFIG_INFORMATION, *PEVENT_TRACE_PROFILE_CONFIG_INFORMATION;

//_Struct_size_bytes_(NextEntryOffset)
//typedef struct _PROFILE_SOURCE_INFO
//{
//    ULONG NextEntryOffset;
//    ULONG Source;
//    ULONG MinInterval;
//    ULONG MaxInterval;
//    PVOID Reserved;
//    WCHAR Description[1];
//} PROFILE_SOURCE_INFO, *PPROFILE_SOURCE_INFO;

typedef struct _PROFILE_SOURCE_INFO *PPROFILE_SOURCE_INFO;

/**
 * The EVENT_TRACE_PROFILE_LIST_INFORMATION structure contains event trace profile list information.
 */
typedef struct _EVENT_TRACE_PROFILE_LIST_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    ULONG Spare;
    PPROFILE_SOURCE_INFO Profile[1];
} EVENT_TRACE_PROFILE_LIST_INFORMATION, *PEVENT_TRACE_PROFILE_LIST_INFORMATION;

/**
 * The EVENT_TRACE_STACK_CACHING_INFORMATION structure contains event trace stack caching information.
 */
typedef struct _EVENT_TRACE_STACK_CACHING_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    TRACEHANDLE TraceHandle;
    BOOLEAN Enabled;
    UCHAR Reserved[3];
    ULONG CacheSize;
    ULONG BucketCount;
} EVENT_TRACE_STACK_CACHING_INFORMATION, *PEVENT_TRACE_STACK_CACHING_INFORMATION;

/**
 * The EVENT_TRACE_SOFT_RESTART_INFORMATION structure contains event trace soft restart information.
 */
typedef struct _EVENT_TRACE_SOFT_RESTART_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    TRACEHANDLE TraceHandle;
    BOOLEAN PersistTraceBuffers;
    WCHAR FileName[1];
} EVENT_TRACE_SOFT_RESTART_INFORMATION, *PEVENT_TRACE_SOFT_RESTART_INFORMATION;

/**
 * The EVENT_TRACE_PROFILE_ADD_INFORMATION_VERSIONS enumeration defines the supported versions of event trace profile
 * add information.
 */
typedef enum _EVENT_TRACE_PROFILE_ADD_INFORMATION_VERSIONS
{
    EventTraceProfileAddInformationMinVersion = 0x2,
    EventTraceProfileAddInformationV2 = 0x2,
    EventTraceProfileAddInformationV3 = 0x3,
    EventTraceProfileAddInformationMaxVersion = 0x3,
} EVENT_TRACE_PROFILE_ADD_INFORMATION_VERSIONS;

/**
 * The EVENT_TRACE_PROFILE_ADD_INFORMATION_V2 union contains event trace profile add information.
 */
typedef union _EVENT_TRACE_PROFILE_ADD_INFORMATION_V2
{
    struct
    {
        UCHAR PerfEvtEventSelect;
        UCHAR PerfEvtUnitSelect;
        UCHAR PerfEvtCMask;
        UCHAR PerfEvtCInv;
        UCHAR PerfEvtAnyThread;
        UCHAR PerfEvtEdgeDetect;
    } Intel;
    struct
    {
        UCHAR PerfEvtEventSelect;
        UCHAR PerfEvtUnitSelect;
    } Amd;
    struct
    {
        ULONG PerfEvtType;
        UCHAR AllowsHalt;
    } Arm;
} EVENT_TRACE_PROFILE_ADD_INFORMATION_V2;

/**
 * The EVENT_TRACE_PROFILE_ADD_INFORMATION_V3 union contains event trace profile add information.
 */
typedef union _EVENT_TRACE_PROFILE_ADD_INFORMATION_V3
{
    struct
    {
        UCHAR PerfEvtEventSelect;
        UCHAR PerfEvtUnitSelect;
        UCHAR PerfEvtCMask;
        UCHAR PerfEvtCInv;
        UCHAR PerfEvtAnyThread;
        UCHAR PerfEvtEdgeDetect;
    } Intel;
    struct
    {
        USHORT PerfEvtEventSelect;
        UCHAR PerfEvtUnitSelect;
        UCHAR PerfEvtCMask;
        UCHAR PerfEvtCInv;
        UCHAR PerfEvtEdgeDetect;
        UCHAR PerfEvtHostGuest;
        UCHAR PerfPmuType;
    } Amd;
    struct
    {
        ULONG PerfEvtType;
        UCHAR AllowsHalt;
    } Arm;
} EVENT_TRACE_PROFILE_ADD_INFORMATION_V3;

/**
 * The EVENT_TRACE_PROFILE_ADD_INFORMATION structure contains event trace profile add information.
 */
typedef struct _EVENT_TRACE_PROFILE_ADD_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    UCHAR Version;
    union
    {
        EVENT_TRACE_PROFILE_ADD_INFORMATION_V2 V2;
        EVENT_TRACE_PROFILE_ADD_INFORMATION_V3 V3;
    } DUMMYUNIONNAME;
    ULONG CpuInfoHierarchy[0x3];
    ULONG InitialInterval;
    BOOLEAN Persist;
    WCHAR ProfileSourceDescription[0x1];
} EVENT_TRACE_PROFILE_ADD_INFORMATION, *PEVENT_TRACE_PROFILE_ADD_INFORMATION;

/**
 * The EVENT_TRACE_PROFILE_REMOVE_INFORMATION structure contains event trace profile remove information.
 */
typedef struct _EVENT_TRACE_PROFILE_REMOVE_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    KPROFILE_SOURCE ProfileSource;
    ULONG CpuInfoHierarchy[0x3];
} EVENT_TRACE_PROFILE_REMOVE_INFORMATION, *PEVENT_TRACE_PROFILE_REMOVE_INFORMATION;

/**
 * The EVENT_TRACE_COVERAGE_SAMPLER_INFORMATION structure contains event trace coverage sampler information.
 */
typedef struct _EVENT_TRACE_COVERAGE_SAMPLER_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    UCHAR CoverageSamplerInformationClass;
    UCHAR MajorVersion;
    UCHAR MinorVersion;
    UCHAR Reserved;
    HANDLE SamplerHandle;
} EVENT_TRACE_COVERAGE_SAMPLER_INFORMATION, *PEVENT_TRACE_COVERAGE_SAMPLER_INFORMATION;

// typedef enum _ETW_CONTEXT_REGISTER_TYPES
// {
//     EtwContextRegisterTypeNone = 0,
//     EtwContextRegisterTypeControl = 0x1,
//     EtwContextRegisterTypeInteger = 0x2
// } ETW_CONTEXT_REGISTER_TYPES;
//
// typedef struct _EVENT_TRACE_CONTEXT_REGISTER_INFO
// {
//     ETW_CONTEXT_REGISTER_TYPES RegisterTypes;
//     ULONG Reserved;
// } EVENT_TRACE_CONTEXT_REGISTER_INFO, *PEVENT_TRACE_CONTEXT_REGISTER_INFO;

EXTERN_C_END

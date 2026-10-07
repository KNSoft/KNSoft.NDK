#pragma once

#include "../MinDef.h"
#include "../Ldr.h"
#include "Process/Process.h"

EXTERN_C_START

/* phnt */

/**
 * Specifies Application Verifier options for a process.
 */
typedef struct _RTL_PROCESS_VERIFIER_OPTIONS
{
    ULONG SizeStruct;
    ULONG Option;
    UCHAR OptionData[1];
} RTL_PROCESS_VERIFIER_OPTIONS, *PRTL_PROCESS_VERIFIER_OPTIONS;

// private
/**
 * Contains the state used to capture and hold process debug information snapshots.
 */
typedef struct _RTL_DEBUG_INFORMATION
{
    HANDLE SectionHandleClient;
    PVOID ViewBaseClient;
    PVOID ViewBaseTarget;
    ULONG_PTR ViewBaseDelta;
    HANDLE EventPairClient;
    HANDLE EventPairTarget;
    HANDLE TargetProcessId;
    HANDLE TargetThreadHandle;
    ULONG Flags;
    SIZE_T OffsetFree;
    SIZE_T CommitSize;
    SIZE_T ViewSize;
    union
    {
        PRTL_PROCESS_MODULES Modules;
        PRTL_PROCESS_MODULE_INFORMATION_EX ModulesEx;
    };
    PRTL_PROCESS_BACKTRACES BackTraces;
    PVOID Heaps;
    PRTL_PROCESS_LOCKS Locks;
    PVOID SpecificHeap;
    HANDLE TargetProcessHandle;
    PRTL_PROCESS_VERIFIER_OPTIONS VerifierOptions;
    PVOID ProcessHeap;
    HANDLE CriticalSectionHandle;
    HANDLE CriticalSectionOwnerThread;
    PVOID Reserved[4];
} RTL_DEBUG_INFORMATION, *PRTL_DEBUG_INFORMATION;

/**
 * Application-defined hash function used to index stack-trace entries in a trace database.
 *
 * \param Count The number of entries in the Trace array.
 * \param Trace An array of Count captured return addresses.
 * \return The hash value for the supplied stack trace.
 */
typedef _Function_class_(RTL_TRACE_HASH_FUNCTION)
ULONG
NTAPI
RTL_TRACE_HASH_FUNCTION(
/**
 * Pointer to an RTL_TRACE_HASH_FUNCTION callback.
 */
    _In_ ULONG Count,
    _In_reads_(Count) PVOID* Trace);
typedef RTL_TRACE_HASH_FUNCTION* PRTL_TRACE_HASH_FUNCTION;

/**
 * Record sizes used when querying loaded module information.
 */
#define RTL_QUERY_MODULE_INFORMATION_RECORD_SIZE_IMAGE_BASE 0x8
#define RTL_QUERY_MODULE_INFORMATION_RECORD_SIZE_MODULE     0x110

/**
 * The RtlCreateQueryDebugBuffer routine allocates and initializes a debug information buffer for use with the
 * RtlQueryProcessDebugInformation routine.
 *
 * \param MaximumCommit The maximum number of bytes to commit for the buffer, or zero for the default.
 * \param UseEventPair A boolean that specifies whether an event pair is used to synchronize with the target process.
 * \return PRTL_DEBUG_INFORMATION A pointer to the allocated debug buffer, or NULL on failure.
 */
NTSYSAPI
PRTL_DEBUG_INFORMATION
NTAPI
RtlCreateQueryDebugBuffer(
    _In_opt_ ULONG MaximumCommit,
    _In_ BOOLEAN UseEventPair
    );

/**
 * The RtlDestroyQueryDebugBuffer routine frees a debug information buffer previously allocated by
 * RtlCreateQueryDebugBuffer.
 *
 * \param Buffer A pointer to the debug buffer to free.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyQueryDebugBuffer(
    _In_ PRTL_DEBUG_INFORMATION Buffer
    );

// private
/**
 * The RtlCommitDebugInfo routine allocates a block within an RTL_DEBUG_INFORMATION buffer.
 *
 * \param Buffer The debug information buffer to allocate from.
 * \param Size The number of bytes to allocate.
 * \return A pointer to the allocated block, or NULL on failure.
 */
NTSYSAPI
PVOID
NTAPI
RtlCommitDebugInfo(
    _Inout_ PRTL_DEBUG_INFORMATION Buffer,
    _In_ SIZE_T Size
    );

// private
/**
 * The RtlDeCommitDebugInfo routine frees a block previously allocated within an RTL_DEBUG_INFORMATION buffer.
 *
 * \param Buffer The debug information buffer that owns the block.
 * \param p The block to free.
 * \param Size The size, in bytes, of the block.
 */
NTSYSAPI
VOID
NTAPI
RtlDeCommitDebugInfo(
    _Inout_ PRTL_DEBUG_INFORMATION Buffer,
    _In_ PVOID p,
    _In_ SIZE_T Size
    );

/**
 * Flags for RtlQueryProcessDebugInformation and related debug information queries.
 */
#define RTL_QUERY_PROCESS_MODULES 0x00000001
#define RTL_QUERY_PROCESS_BACKTRACES 0x00000002
#define RTL_QUERY_PROCESS_HEAP_SUMMARY 0x00000004
#define RTL_QUERY_PROCESS_HEAP_TAGS 0x00000008
#define RTL_QUERY_PROCESS_HEAP_ENTRIES 0x00000010
#define RTL_QUERY_PROCESS_LOCKS 0x00000020
#define RTL_QUERY_PROCESS_MODULES32 0x00000040
#define RTL_QUERY_PROCESS_VERIFIER_OPTIONS 0x00000080 // rev
#define RTL_QUERY_PROCESS_MODULESEX 0x00000100 // rev
#define RTL_QUERY_PROCESS_HEAP_SEGMENTS 0x00000200
#define RTL_QUERY_PROCESS_CS_OWNER 0x00000400 // rev
#define RTL_QUERY_PROCESS_USE_CURRENT_PROCESS 0x40000000 // rev
#define RTL_QUERY_PROCESS_NONINVASIVE 0x80000000
#define RTL_QUERY_PROCESS_NONINVASIVE_CS_OWNER 0x80000800 // WIN11

/**
 * The RtlQueryProcessDebugInformation routine retrieves debug information, such as heaps, modules, and locks, for the
 * specified process.
 *
 * \param UniqueProcessId The unique process identifier of the process to query.
 * \param Flags Flags that specify which classes of debug information are collected.
 * \param Buffer A pointer to a debug buffer, allocated by RtlCreateQueryDebugBuffer, that receives the information.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryProcessDebugInformation(
    _In_ HANDLE UniqueProcessId,
    _In_ ULONG Flags,
    _Inout_ PRTL_DEBUG_INFORMATION Buffer
    );

// rev
/**
 * The RtlSetProcessDebugInformation routine sets debug information for the specified process.
 *
 * \param UniqueProcessId The unique process identifier of the target process.
 * \param Flags Flags that specify which classes of debug information are set.
 * \param Buffer A pointer to a debug buffer, allocated by RtlCreateQueryDebugBuffer, that contains the information.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetProcessDebugInformation(
    _In_ HANDLE UniqueProcessId,
    _In_ ULONG Flags,
    _Inout_ PRTL_DEBUG_INFORMATION Buffer
    );

// RtlQueryModuleInformation
/**
 * The RtlQueryModuleInformation routine retrieves information about the modules loaded in the system.
 *
 * \param BufferSize On input specifies the buffer size; on output receives the required or written size, in bytes.
 * \param UnitSize The size, in bytes, of each module information record (RTL_QUERY_MODULE_INFORMATION_RECORD_SIZE_*).
 * \param ModuleInformation An optional buffer that receives the module information records.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryModuleInformation(
    _Inout_ PULONG BufferSize,
    _In_ ULONG UnitSize, // RTL_QUERY_MODULE_INFORMATION_RECORD_SIZE_*
    _Out_writes_bytes_opt_(*BufferSize) PVOID ModuleInformation
    );

// rev
/**
 * The RtlDebugPrintTimes routine prints the accumulated timing statistics collected by the run-time library to the
 * debugger.
 *
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDebugPrintTimes(VOID);


typedef struct _RTL_TRACE_DATABASE RTL_TRACE_DATABASE, *PRTL_TRACE_DATABASE;

// RtlTraceDatabaseAdd
/**
 * The RtlTraceDatabaseAdd routine adds a stack trace to a trace database.
 *
 * \param Database The trace database to modify.
 * \param Count The number of entries in the Trace array.
 * \param Trace An optional array of captured return addresses.
 * \param TraceBlock An optional pointer that receives the trace block that stores the trace.
 * \return TRUE if the trace was added; otherwise, FALSE.
 */
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
/**
 * The RtlTraceDatabaseCreate routine creates a trace database used to record stack traces and other trace entries.
 *
 * \param Buckets The number of hash buckets in the trace database.
 * \param MaximumSize An optional maximum size, in bytes, for the trace database.
 * \param Flags Flags that control the trace database behavior.
 * \param Tag A tag value associated with the trace database.
 * \param HashFunction An optional hash function used to index trace entries.
 * \return PRTL_TRACE_DATABASE A pointer to the created trace database, or NULL on failure.
 */
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
/**
 * The RtlTraceDatabaseDestroy routine destroys a trace database previously created by RtlTraceDatabaseCreate.
 *
 * \param Database A pointer to the trace database to destroy.
 * \return `TRUE` if the trace database was destroyed, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlTraceDatabaseDestroy(
    _In_ _Post_invalid_ PRTL_TRACE_DATABASE Database
    );

// RtlTraceDatabaseEnumerate
/**
 * The RtlTraceDatabaseEnumerate routine enumerates the stack traces recorded in a trace database.
 *
 * \param Database The trace database to enumerate.
 * \param Enumerator An enumeration cursor advanced across calls.
 * \param TraceBlock An optional pointer that receives the current trace block.
 * \return TRUE if a trace was returned; FALSE when enumeration is complete.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlTraceDatabaseEnumerate(
    _In_ PRTL_TRACE_DATABASE Database,
    _Inout_ PVOID Enumerator,
    _Out_opt_ PULONGLONG TraceBlock
    );

// RtlTraceDatabaseFind
/**
 * The RtlTraceDatabaseFind routine finds a stack trace within a trace database.
 *
 * \param Database The trace database to search.
 * \param Count The number of entries in the Trace array.
 * \param Trace An optional array of captured return addresses to match.
 * \param TraceBlock An optional pointer that receives the matching trace block.
 * \return TRUE if the trace was found; otherwise, FALSE.
 */
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
/**
 * The RtlTraceDatabaseLock routine acquires the lock that serializes access to the specified trace database.
 *
 * \param Database A pointer to the trace database to lock.
 * \return NTSTATUS Successful or errant status.
 */
_Acquires_lock_(Database)
NTSYSAPI
NTSTATUS
NTAPI
RtlTraceDatabaseLock(
    _In_ PRTL_TRACE_DATABASE Database
    );

// RtlTraceDatabaseUnlock
/**
 * The RtlTraceDatabaseUnlock routine releases the lock on the specified trace database previously acquired with
 * RtlTraceDatabaseLock.
 *
 * \param Database A pointer to the trace database to unlock.
 * \return NTSTATUS Successful or errant status.
 */
_Releases_lock_(Database)
NTSYSAPI
NTSTATUS
NTAPI
RtlTraceDatabaseUnlock(
    _In_ PRTL_TRACE_DATABASE Database
    );

// RtlTraceDatabaseValidate
/**
 * The RtlTraceDatabaseValidate routine validates the integrity of the specified trace database.
 *
 * \param Database A pointer to the trace database to validate.
 * \return `TRUE` if the trace database is valid, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlTraceDatabaseValidate(
    _In_ PRTL_TRACE_DATABASE Database
    );

// RtlApplicationVerifierStop
/**
 * The RtlApplicationVerifierStop routine reports an Application Verifier stop, breaking into the debugger with the
 * supplied diagnostic parameters.
 *
 * \param Param1 An optional first diagnostic value.
 * \param Desc1 An optional description of the first value.
 * \param Param2 An optional second diagnostic value.
 * \param Desc2 An optional description of the second value.
 * \param Param3 An optional third diagnostic value.
 * \param Desc3 An optional description of the third value.
 * \param Param4 An optional fourth diagnostic value.
 * \param Desc4 An optional description of the fourth value.
 * \param Param5 An optional fifth diagnostic value.
 * \param Desc5 An optional description of the fifth value.
 * \return Implementation-defined; typically NULL.
 */
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

// RtlLogUnexpectedCodepath
/**
 * The RtlLogUnexpectedCodepath routine records that an unexpected code path was reached for diagnostic purposes.
 *
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlLogUnexpectedCodepath(
    VOID
    );

// RtlReportSqmEscalation
/**
 * The RtlReportSqmEscalation routine reports a Software Quality Metrics (SQM) escalation event.
 *
 * \param Callback A callback that supplies the escalation data.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlReportSqmEscalation(
    _In_ PVOID Callback
    );
EXTERN_C_END

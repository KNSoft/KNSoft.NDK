#pragma once

#include "../MinDef.h"
#include "../Ldr.h"
#include "Process/Process.h"

EXTERN_C_START

/* phnt */

typedef struct _RTL_PROCESS_VERIFIER_OPTIONS
{
    ULONG SizeStruct;
    ULONG Option;
    UCHAR OptionData[1];
} RTL_PROCESS_VERIFIER_OPTIONS, *PRTL_PROCESS_VERIFIER_OPTIONS;

// private
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

typedef _Function_class_(RTL_TRACE_HASH_FUNCTION)
ULONG
NTAPI
RTL_TRACE_HASH_FUNCTION(
    _In_ ULONG Count,
    _In_reads_(Count) PVOID* Trace);
typedef RTL_TRACE_HASH_FUNCTION* PRTL_TRACE_HASH_FUNCTION;

#define RTL_QUERY_MODULE_INFORMATION_RECORD_SIZE_IMAGE_BASE 0x8
#define RTL_QUERY_MODULE_INFORMATION_RECORD_SIZE_MODULE     0x110

NTSYSAPI
PRTL_DEBUG_INFORMATION
NTAPI
RtlCreateQueryDebugBuffer(
    _In_opt_ ULONG MaximumCommit,
    _In_ BOOLEAN UseEventPair
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyQueryDebugBuffer(
    _In_ PRTL_DEBUG_INFORMATION Buffer
    );

// private
NTSYSAPI
PVOID
NTAPI
RtlCommitDebugInfo(
    _Inout_ PRTL_DEBUG_INFORMATION Buffer,
    _In_ SIZE_T Size
    );

// private
NTSYSAPI
VOID
NTAPI
RtlDeCommitDebugInfo(
    _Inout_ PRTL_DEBUG_INFORMATION Buffer,
    _In_ PVOID p,
    _In_ SIZE_T Size
    );

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

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryProcessDebugInformation(
    _In_ HANDLE UniqueProcessId,
    _In_ ULONG Flags,
    _Inout_ PRTL_DEBUG_INFORMATION Buffer
    );

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlSetProcessDebugInformation(
    _In_ HANDLE UniqueProcessId,
    _In_ ULONG Flags,
    _Inout_ PRTL_DEBUG_INFORMATION Buffer
    );

// RtlQueryModuleInformation
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryModuleInformation(
    _Inout_ PULONG BufferSize,
    _In_ ULONG UnitSize, // RTL_QUERY_MODULE_INFORMATION_RECORD_SIZE_*
    _Out_writes_bytes_opt_(*BufferSize) PVOID ModuleInformation
    );

// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlDebugPrintTimes(VOID);


typedef struct _RTL_TRACE_DATABASE RTL_TRACE_DATABASE, *PRTL_TRACE_DATABASE;

// RtlTraceDatabaseAdd
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
NTSYSAPI
BOOLEAN
NTAPI
RtlTraceDatabaseDestroy(
    _In_ _Post_invalid_ PRTL_TRACE_DATABASE Database
    );

// RtlTraceDatabaseEnumerate
NTSYSAPI
BOOLEAN
NTAPI
RtlTraceDatabaseEnumerate(
    _In_ PRTL_TRACE_DATABASE Database,
    _Inout_ PVOID Enumerator,
    _Out_opt_ PULONGLONG TraceBlock
    );

// RtlTraceDatabaseFind
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
NTSYSAPI
NTSTATUS
NTAPI
RtlTraceDatabaseLock(
    _In_ PRTL_TRACE_DATABASE Database
    );

// RtlTraceDatabaseUnlock
NTSYSAPI
NTSTATUS
NTAPI
RtlTraceDatabaseUnlock(
    _In_ PRTL_TRACE_DATABASE Database
    );

// RtlTraceDatabaseValidate
NTSYSAPI
BOOLEAN
NTAPI
RtlTraceDatabaseValidate(
    _In_ PRTL_TRACE_DATABASE Database
    );

// RtlApplicationVerifierStop
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
NTSYSAPI
NTSTATUS
NTAPI
RtlLogUnexpectedCodepath(
    void
    );

// RtlReportSqmEscalation
NTSYSAPI
NTSTATUS
NTAPI
RtlReportSqmEscalation(
    _In_ PVOID Callback
    );
EXTERN_C_END

#pragma once

#include "../MinDef.h"
#include "../Io/Io.h"

EXTERN_C_START

/* phnt */

/**
 * The SYSDBG_COMMAND enumeration specifies the type of system debugger
 * operation requested through NtSystemDebugControl.
 */
typedef enum _SYSDBG_COMMAND
{
    SysDbgQueryModuleInformation,       // q: DBGKD_DEBUG_DATA_HEADER64
    SysDbgQueryTraceInformation,        // q: DBGKD_TRACE_DATA
    SysDbgSetTracepoint,                // s: PVOID
    SysDbgSetSpecialCall,               // s: PVOID
    SysDbgClearSpecialCalls,            // s: void
    SysDbgQuerySpecialCalls,            // q: PVOID[]
    SysDbgBreakPoint,                   // s: void
    SysDbgQueryVersion,                 // q: DBGKD_GET_VERSION64
    SysDbgReadVirtual,                  // q: SYSDBG_VIRTUAL
    SysDbgWriteVirtual,                 // s: SYSDBG_VIRTUAL
    SysDbgReadPhysical,                 // q: SYSDBG_PHYSICAL // 10
    SysDbgWritePhysical,                // s: SYSDBG_PHYSICAL
    SysDbgReadControlSpace,             // q: SYSDBG_CONTROL_SPACE
    SysDbgWriteControlSpace,            // s: SYSDBG_CONTROL_SPACE
    SysDbgReadIoSpace,                  // q: SYSDBG_IO_SPACE
    SysDbgWriteIoSpace,                 // s: SYSDBG_IO_SPACE
    SysDbgReadMsr,                      // q: SYSDBG_MSR
    SysDbgWriteMsr,                     // s: SYSDBG_MSR
    SysDbgReadBusData,                  // q: SYSDBG_BUS_DATA
    SysDbgWriteBusData,                 // s: SYSDBG_BUS_DATA
    SysDbgCheckLowMemory,               // q: ULONG // 20
    SysDbgEnableKernelDebugger,         // s: void
    SysDbgDisableKernelDebugger,        // s: void
    SysDbgGetAutoKdEnable,              // q: ULONG
    SysDbgSetAutoKdEnable,              // s: ULONG
    SysDbgGetPrintBufferSize,           // q: ULONG
    SysDbgSetPrintBufferSize,           // s: ULONG
    SysDbgGetKdUmExceptionEnable,       // q: ULONG
    SysDbgSetKdUmExceptionEnable,       // s: ULONG
    SysDbgGetTriageDump,                // q: SYSDBG_TRIAGE_DUMP
    SysDbgGetKdBlockEnable,             // q: ULONG // 30
    SysDbgSetKdBlockEnable,             // s: ULONG
    SysDbgRegisterForUmBreakInfo,       // s: HANDLE
    SysDbgGetUmBreakPid,                // q: ULONG
    SysDbgClearUmBreakPid,              // s: void
    SysDbgGetUmAttachPid,               // q: ULONG
    SysDbgClearUmAttachPid,             // s: void
    SysDbgGetLiveKernelDump,            // q: SYSDBG_LIVEDUMP_CONTROL
    SysDbgKdPullRemoteFile,             // q: SYSDBG_KD_PULL_REMOTE_FILE
    SysDbgMaxInfoClass
} SYSDBG_COMMAND, *PSYSDBG_COMMAND;

/**
 * The SYSDBG_VIRTUAL structure describes a request to read or write virtual
 * memory through the system debugger interface.
 */
typedef struct _SYSDBG_VIRTUAL
{
    PVOID Address;
    PVOID Buffer;
    ULONG Request;
} SYSDBG_VIRTUAL, *PSYSDBG_VIRTUAL;

/**
 * The SYSDBG_PHYSICAL structure describes a request to read or write physical
 * memory through the system debugger interface.
 */
typedef struct _SYSDBG_PHYSICAL
{
    PHYSICAL_ADDRESS Address;
    PVOID Buffer;
    ULONG Request;
} SYSDBG_PHYSICAL, *PSYSDBG_PHYSICAL;

/**
 * The SYSDBG_CONTROL_SPACE structure describes a request to access processor
 * control space through the system debugger interface.
 */
typedef struct _SYSDBG_CONTROL_SPACE
{
    ULONG64 Address;
    PVOID Buffer;
    ULONG Request;
    ULONG Processor;
} SYSDBG_CONTROL_SPACE, *PSYSDBG_CONTROL_SPACE;

typedef enum _INTERFACE_TYPE INTERFACE_TYPE;

/**
 * The SYSDBG_IO_SPACE structure describes a request to access I/O space
 * through the system debugger interface.
 */
typedef struct _SYSDBG_IO_SPACE
{
    ULONG64 Address;
    PVOID Buffer;
    ULONG Request;
    INTERFACE_TYPE InterfaceType;
    ULONG BusNumber;
    ULONG AddressSpace;
} SYSDBG_IO_SPACE, *PSYSDBG_IO_SPACE;

/**
 * The SYSDBG_MSR structure describes a request to read or write a model-specific
 * register (MSR) through the system debugger interface.
 */
typedef struct _SYSDBG_MSR
{
    ULONG Msr;
    ULONG64 Data;
} SYSDBG_MSR, *PSYSDBG_MSR;

typedef enum _BUS_DATA_TYPE BUS_DATA_TYPE;

/**
 * The SYSDBG_BUS_DATA structure describes a request to access bus-specific
 * configuration data through the system debugger interface.
 */
typedef struct _SYSDBG_BUS_DATA
{
    ULONG Address;
    PVOID Buffer;
    ULONG Request;
    BUS_DATA_TYPE BusDataType;
    ULONG BusNumber;
    ULONG SlotNumber;
} SYSDBG_BUS_DATA, *PSYSDBG_BUS_DATA;

/**
 * The SYSDBG_TRIAGE_DUMP structure describes parameters used when generating
 * a triage dump through the system debugger interface.
 */
typedef struct _SYSDBG_TRIAGE_DUMP
{
    ULONG Flags;
    ULONG BugCheckCode;
    ULONG_PTR BugCheckParam1;
    ULONG_PTR BugCheckParam2;
    ULONG_PTR BugCheckParam3;
    ULONG_PTR BugCheckParam4;
    ULONG ProcessHandles;
    ULONG ThreadHandles;
    PHANDLE Handles;
} SYSDBG_TRIAGE_DUMP, *PSYSDBG_TRIAGE_DUMP;

/**
 * The SYSDBG_LIVEDUMP_CONTROL_FLAGS union specifies control flags used when
 * generating a live kernel dump.
 */
typedef union _SYSDBG_LIVEDUMP_CONTROL_FLAGS
{
    struct
    {
        ULONG UseDumpStorageStack : 1;
        ULONG CompressMemoryPagesData : 1;
        ULONG IncludeUserSpaceMemoryPages : 1;
        ULONG AbortIfMemoryPressure : 1; // REDSTONE4
        ULONG SelectiveDump : 1; // WIN11
        ULONG Reserved : 27;
    };
    ULONG AsUlong;
} SYSDBG_LIVEDUMP_CONTROL_FLAGS, *PSYSDBG_LIVEDUMP_CONTROL_FLAGS;

/**
 * The SYSDBG_LIVEDUMP_CONTROL_ADDPAGES union specifies additional page
 * categories to include when generating a live kernel dump.
 */
typedef union _SYSDBG_LIVEDUMP_CONTROL_ADDPAGES
{
    struct
    {
        ULONG HypervisorPages : 1;
        ULONG NonEssentialHypervisorPages : 1; // since WIN11
        ULONG Reserved : 30;
    };
    ULONG AsUlong;
} SYSDBG_LIVEDUMP_CONTROL_ADDPAGES, *PSYSDBG_LIVEDUMP_CONTROL_ADDPAGES;

#define SYSDBG_LIVEDUMP_SELECTIVE_CONTROL_VERSION 1

// rev
/**
 * The SYSDBG_LIVEDUMP_SELECTIVE_CONTROL structure specifies selective dump
 * options for live kernel dump generation.
 */
typedef struct _SYSDBG_LIVEDUMP_SELECTIVE_CONTROL
{
    ULONG Version;
    ULONG Size;
    union
    {
        ULONGLONG Flags;
        struct
        {
            ULONGLONG ThreadKernelStacks : 1;
            ULONGLONG ReservedFlags : 63;
        };
    };
    ULONGLONG Reserved[4];
} SYSDBG_LIVEDUMP_SELECTIVE_CONTROL, *PSYSDBG_LIVEDUMP_SELECTIVE_CONTROL;

#define SYSDBG_LIVEDUMP_CONTROL_VERSION_1 1
#define SYSDBG_LIVEDUMP_CONTROL_VERSION_2 2
#define SYSDBG_LIVEDUMP_CONTROL_VERSION SYSDBG_LIVEDUMP_CONTROL_VERSION_2

/**
 * The SYSDBG_LIVEDUMP_CONTROL_V1 structure describes parameters used when
 * generating a live kernel dump (version 1).
 */
typedef struct _SYSDBG_LIVEDUMP_CONTROL_V1
{
    ULONG Version;
    ULONG BugCheckCode;
    ULONG_PTR BugCheckParam1;
    ULONG_PTR BugCheckParam2;
    ULONG_PTR BugCheckParam3;
    ULONG_PTR BugCheckParam4;
    HANDLE DumpFileHandle;
    HANDLE CancelEventHandle;
    SYSDBG_LIVEDUMP_CONTROL_FLAGS Flags;
    SYSDBG_LIVEDUMP_CONTROL_ADDPAGES AddPagesControl;
} SYSDBG_LIVEDUMP_CONTROL_V1, *PSYSDBG_LIVEDUMP_CONTROL_V1;

/**
 * The SYSDBG_LIVEDUMP_CONTROL structure describes parameters used when
 * generating a live kernel dump (current version).
 */
typedef struct _SYSDBG_LIVEDUMP_CONTROL
{
    ULONG Version;
    ULONG BugCheckCode;
    ULONG_PTR BugCheckParam1;
    ULONG_PTR BugCheckParam2;
    ULONG_PTR BugCheckParam3;
    ULONG_PTR BugCheckParam4;
    HANDLE DumpFileHandle;
    HANDLE CancelEventHandle;
    SYSDBG_LIVEDUMP_CONTROL_FLAGS Flags;
    SYSDBG_LIVEDUMP_CONTROL_ADDPAGES AddPagesControl;
    PSYSDBG_LIVEDUMP_SELECTIVE_CONTROL SelectiveControl; // since WIN11
} SYSDBG_LIVEDUMP_CONTROL, *PSYSDBG_LIVEDUMP_CONTROL;

/**
 * The SYSDBG_KD_PULL_REMOTE_FILE structure describes a request to retrieve
 * a remote file through the kernel debugger transport.
 */
typedef struct _SYSDBG_KD_PULL_REMOTE_FILE
{
    UNICODE_STRING ImageFileName;
} SYSDBG_KD_PULL_REMOTE_FILE, *PSYSDBG_KD_PULL_REMOTE_FILE;

/**
 * The NtSystemDebugControl routine provides system debugging and diagnostic control of the system.
 *
 * \param[in] Command The debug control command to execute (of type SYSDBG_COMMAND).
 * \param[in] InputBuffer Optional pointer to a buffer containing input data for the command.
 * \param[in] InputBufferLength Length, in bytes, of the input buffer.
 * \param[out] OutputBuffer Optional pointer to a buffer that receives output data from the command.
 * \param[in] OutputBufferLength Length, in bytes, of the output buffer.
 * \param[out] ReturnLength Optional pointer to a variable that receives the number of bytes returned in the output buffer.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSystemDebugControl(
    _In_ SYSDBG_COMMAND Command,
    _Inout_updates_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_opt_ PULONG ReturnLength
    );

EXTERN_C_END

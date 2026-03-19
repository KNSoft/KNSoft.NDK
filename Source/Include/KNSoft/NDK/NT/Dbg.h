#pragma once

#include "MinDef.h"

#include <minwinbase.h>
#include <dpfilter.h>

EXTERN_C_START

#pragma region Debug Break

/**
 * Causes a user-mode breakpoint to occur.
 */
NTSYSAPI
VOID
NTAPI
DbgUserBreakPoint(VOID);

/**
 * Causes a breakpoint to occur.
 */
NTSYSAPI
VOID
NTAPI
DbgBreakPoint(VOID);

#define DBG_STATUS_CONTROL_C 1
#define DBG_STATUS_SYSRQ 2
#define DBG_STATUS_BUGCHECK_FIRST 3
#define DBG_STATUS_BUGCHECK_SECOND 4
#define DBG_STATUS_FATAL 5
#define DBG_STATUS_DEBUG_CONTROL 6
#define DBG_STATUS_WORKER 7

/**
 * Causes a breakpoint to occur with a specific status.
 *
 * \param Status The status code to associate with the breakpoint.
 */
NTSYSAPI
VOID
NTAPI
DbgBreakPointWithStatus(
    _In_ ULONG Status);

#pragma endregion phnt

#pragma region Debug Print

/* ntddk.h */

/**
 * Prompts the user for input.
 *
 * \param Prompt A pointer to the prompt string.
 * \param Response A pointer to the buffer that receives the user response.
 * \param Length The length of the response buffer, in bytes.
 * \return ULONG The number of characters in the response.
 */
NTSYSAPI
ULONG
NTAPI
DbgPrompt(
    _In_z_ PCCH Prompt,
    _Out_writes_bytes_(Length) PCH Response,
    _In_ ULONG Length);

/* wdm.h */

/**
 * Sends a message to the kernel debugger.
 *
 * \param Format A pointer to a printf-style format string.
 * \param ... Arguments for the format string.
 * \return ULONG The number of characters printed.
 */
NTSYSAPI
ULONG
__cdecl
DbgPrint(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...);

/**
 * Sends a message to the kernel debugger with a component ID and level.
 *
 * \param ComponentId The ID of the component sending the message.
 * \param Level The importance level of the message.
 * \param Format A pointer to a printf-style format string.
 * \param ... Arguments for the format string.
 * \return ULONG The number of characters printed.
 */
NTSYSAPI
ULONG
__cdecl
DbgPrintEx(
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...);

/**
 * Sends a message to the kernel debugger with a component ID and level (va_list version).
 *
 * \param ComponentId The ID of the component sending the message.
 * \param Level The importance level of the message.
 * \param Format A pointer to the format string.
 * \param arglist A list of arguments for the format string.
 * \return ULONG The number of characters printed.
 */
NTSYSAPI
ULONG
NTAPI
vDbgPrintEx(
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_z_ PCCH Format,
    _In_ va_list arglist);

/**
 * Sends a message to the kernel debugger with a prefix, component ID, and level.
 */
NTSYSAPI
ULONG
NTAPI
vDbgPrintExWithPrefix(
    _In_z_ PCCH Prefix,
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_z_ PCCH Format,
    _In_ va_list arglist);

/**
 * Sends a message to the kernel debugger and returns Control-C status.
 */
NTSYSAPI
ULONG
__cdecl
DbgPrintReturnControlC(
    _In_z_ _Printf_format_string_ PCCH Format,
    ...);

/**
 * Queries the debug filter state for a component.
 */
NTSYSAPI
NTSTATUS
NTAPI
DbgQueryDebugFilterState(
    _In_ ULONG ComponentId,
    _In_ ULONG Level);

/**
 * Sets the debug filter state for a component.
 */
NTSYSAPI
NTSTATUS
NTAPI
DbgSetDebugFilterState(
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_ BOOLEAN State);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryDebugFilterState(
    _In_ ULONG ComponentId,
    _In_ ULONG Level);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetDebugFilterState(
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_ BOOLEAN State);

#pragma endregion

#pragma region Debugging

/**
 * The DBGKM_EXCEPTION structure contains exception information for a debug event.
 */
typedef struct _DBGKM_EXCEPTION
{
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

/**
 * The DBGKM_CREATE_THREAD structure contains information about a newly created thread.
 */
typedef struct _DBGKM_CREATE_THREAD
{
    ULONG SubSystemKey;
    PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

/**
 * The DBGKM_CREATE_PROCESS structure contains information about a newly created process.
 */
typedef struct _DBGKM_CREATE_PROCESS
{
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

/**
 * The DBGKM_EXIT_THREAD structure contains the exit status of a thread.
 */
typedef struct _DBGKM_EXIT_THREAD
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

/**
 * The DBGKM_EXIT_PROCESS structure contains the exit status of a process.
 */
typedef struct _DBGKM_EXIT_PROCESS
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

/**
 * The DBGKM_LOAD_DLL structure contains information about a loaded DLL.
 */
typedef struct _DBGKM_LOAD_DLL
{
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

/**
 * The DBGKM_UNLOAD_DLL structure contains the base address of an unloaded DLL.
 */
typedef struct _DBGKM_UNLOAD_DLL
{
    PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

/**
 * The DBG_STATE enumeration defines the state of a debug object.
 */
typedef enum _DBG_STATE
{
    DbgIdle,
    DbgReplyPending,
    DbgCreateThreadStateChange,
    DbgCreateProcessStateChange,
    DbgExitThreadStateChange,
    DbgExitProcessStateChange,
    DbgExceptionStateChange,
    DbgBreakpointStateChange,
    DbgSingleStepStateChange,
    DbgLoadDllStateChange,
    DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

/**
 * The DBGUI_CREATE_THREAD structure contains UI-level information about a newly created thread.
 */
typedef struct _DBGUI_CREATE_THREAD
{
    HANDLE HandleToThread;
    DBGKM_CREATE_THREAD NewThread;
} DBGUI_CREATE_THREAD, *PDBGUI_CREATE_THREAD;

/**
 * The DBGUI_CREATE_PROCESS structure contains UI-level information about a newly created process.
 */
typedef struct _DBGUI_CREATE_PROCESS
{
    HANDLE HandleToProcess;
    HANDLE HandleToThread;
    DBGKM_CREATE_PROCESS NewProcess;
} DBGUI_CREATE_PROCESS, *PDBGUI_CREATE_PROCESS;

/**
 * The DBGUI_WAIT_STATE_CHANGE structure contains information about a debug state change.
 */
typedef struct _DBGUI_WAIT_STATE_CHANGE
{
    DBG_STATE NewState;
    CLIENT_ID AppClientId;
    union
    {
        DBGKM_EXCEPTION Exception;
        DBGUI_CREATE_THREAD CreateThread;
        DBGUI_CREATE_PROCESS CreateProcessInfo;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    } StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;

#define DEBUG_READ_EVENT 0x0001
#define DEBUG_PROCESS_ASSIGN 0x0002
#define DEBUG_SET_INFORMATION 0x0004
#define DEBUG_QUERY_INFORMATION 0x0008
#define DEBUG_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
    DEBUG_READ_EVENT | DEBUG_PROCESS_ASSIGN | DEBUG_SET_INFORMATION | \
    DEBUG_QUERY_INFORMATION)

#define DEBUG_KILL_ON_CLOSE 0x1

/**
 * The DEBUGOBJECTINFOCLASS enumeration defines the information classes for debug objects.
 */
typedef enum _DEBUGOBJECTINFOCLASS
{
    DebugObjectUnusedInformation,
    DebugObjectKillProcessOnExitInformation, // s: ULONG
    MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;

/**
 * Creates a debug object.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateDebugObject(
    _Out_ PHANDLE DebugObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG Flags);

/**
 * Attaches a debugger to an active process.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtDebugActiveProcess(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle);

/**
 * Continues a thread that was stopped by a debug event.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtDebugContinue(
    _In_ HANDLE DebugObjectHandle,
    _In_ PCLIENT_ID ClientId,
    _In_ NTSTATUS ContinueStatus);

/**
 * Stops debugging a process.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtRemoveProcessDebug(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle);

/**
 * Sets information for a debug object.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationDebugObject(
    _In_ HANDLE DebugObjectHandle,
    _In_ DEBUGOBJECTINFOCLASS DebugObjectInformationClass,
    _In_reads_bytes_(DebugInformationLength) PVOID DebugInformation,
    _In_ ULONG DebugInformationLength,
    _Out_opt_ PULONG ReturnLength);

/**
 * Waits for a debug event to occur.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtWaitForDebugEvent(
    _In_ HANDLE DebugObjectHandle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout,
    _Out_ PDBGUI_WAIT_STATE_CHANGE WaitStateChange);

/**
 * Connects the current thread to the debugger.
 */
NTSYSAPI
NTSTATUS
NTAPI
DbgUiConnectToDbg(VOID);

/**
 * Retrieves the debug object handle for the current thread.
 */
NTSYSAPI
HANDLE
NTAPI
DbgUiGetThreadDebugObject(VOID);

/**
 * Sets the debug object handle for the current thread.
 */
NTSYSAPI
VOID
NTAPI
DbgUiSetThreadDebugObject(
    _In_ HANDLE DebugObject);

/**
 * Waits for a debug state change.
 */
NTSYSAPI
NTSTATUS
NTAPI
DbgUiWaitStateChange(
    _Out_ PDBGUI_WAIT_STATE_CHANGE StateChange,
    _In_opt_ PLARGE_INTEGER Timeout);

/**
 * Continues a debug state change.
 */
NTSYSAPI
NTSTATUS
NTAPI
DbgUiContinue(
    _In_ PCLIENT_ID AppClientId,
    _In_ NTSTATUS ContinueStatus);

/**
 * Stops debugging a process.
 */
NTSYSAPI
NTSTATUS
NTAPI
DbgUiStopDebugging(
    _In_ HANDLE Process);

/**
 * Attaches a debugger to an active process.
 */
NTSYSAPI
NTSTATUS
NTAPI
DbgUiDebugActiveProcess(
    _In_ HANDLE Process);

/**
 * Remotely triggers a breakpoint in a process.
 */
NTSYSAPI
VOID
NTAPI
DbgUiRemoteBreakin(
    _In_ PVOID Context);

/**
 * Issues a remote breakpoint in a process.
 */
NTSYSAPI
NTSTATUS
NTAPI
DbgUiIssueRemoteBreakin(
    _In_ HANDLE Process);

/**
 * Converts a state change structure to a debug event structure.
 */
NTSYSAPI
NTSTATUS
NTAPI
DbgUiConvertStateChangeStructure(
    _In_ PDBGUI_WAIT_STATE_CHANGE StateChange,
    _Out_ LPDEBUG_EVENT DebugEvent);

/**
 * Converts a state change structure to a debug event structure (extended).
 */
NTSYSAPI
NTSTATUS
NTAPI
DbgUiConvertStateChangeStructureEx(
    _In_ PDBGUI_WAIT_STATE_CHANGE StateChange,
    _Out_ LPDEBUG_EVENT DebugEvent);

#pragma endregion phnt

EXTERN_C_END

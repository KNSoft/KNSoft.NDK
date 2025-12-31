#pragma once

#include "MinDef.h"

EXTERN_C_START

/* fltKernel.h */

#define FLT_PORT_CONNECT 0x0001
#define FLT_PORT_ALL_ACCESS (FLT_PORT_CONNECT | STANDARD_RIGHTS_ALL)

#if (NTDDI_VERSION >= NTDDI_WIN10_MN)
// rev
NTSYSCALLAPI
NTSTATUS
NTAPI
NtDirectGraphicsCall(
    _In_ ULONG InputBufferLength,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _Out_ PULONG ReturnLength);
#endif

//
// Direct3D Kernel Mode Thunk (D3DKMT)
//

/**
 * The D3DKMT_GET_PROCESS_LIST structure is used for retrieving a list of process handles using a graphics adapter.
 * \remarks The caller is responsible for closing the returned process handles.
 */
// rev
typedef struct _D3DKMT_GET_PROCESS_LIST
{
    LUID AdapterLuid;          // [in] The locally unique identifier (LUID) for the graphics adapter.
    ULONG DesiredAccess;       // [in] The access rights to request for the process handles. This must be `PROCESS_QUERY_INFORMATION` (0x400).
    ULONG ProcessHandleCount;  // [in, out] On input, specifies the number of handles the `ProcessHandle` member can hold. On output, receives the number of handles returned.
    HANDLE ProcessHandle;      // [out] The first element of an array that receives the process handles.
} D3DKMT_GET_PROCESS_LIST, *PD3DKMT_GET_PROCESS_LIST;

// rev
/**
 * The D3DKMTGetProcessList function retrieves a list of processes that are using a specific graphics adapter.
 *
 * \param[in,out] GetProcessList A pointer to a \ref D3DKMT_GET_PROCESS_LIST structure that contains the processes using the graphics adapter.
 * \return NTSTATUS Successful or errant status.
 */
NTSTATUS
NTAPI
D3DKMTGetProcessList(
    _Inout_ PD3DKMT_GET_PROCESS_LIST GetProcessList
    );

// rev
/**
 * The D3DKMT_ENUM_PROCESS_LIST structure is used for retrieving a list of process identifiers using a graphics adapter.
 */
typedef struct _D3DKMT_ENUM_PROCESS_LIST
{
    LUID AdapterLuid;          // [in] The locally unique identifier (LUID) for the graphics adapter.
    PULONG ProcessIdBuffer;    // [out] A pointer to a buffer that receives the list of process identifiers (PIDs).
    SIZE_T ProcessIdCount;     // [in, out] On input, specifies the number of elements the `ProcessIdBuffer` can hold. On output, receives the number of process IDs returned.
} D3DKMT_ENUM_PROCESS_LIST, *PD3DKMT_ENUM_PROCESS_LIST;

// rev
/**
 * The D3DKMTEnumProcesses function provides a list of process IDs (PIDs) rather than handles that are using a specific graphics adapter, 
 * which can be more efficient for monitoring purposes.
 *
 * \param[in,out] EnumProcessList A pointer to a \ref D3DKMT_ENUM_PROCESS_LIST structure that contains the processes using the graphics adapter.
 * \return NTSTATUS Successful or errant status.
 */
NTSTATUS
NTAPI
D3DKMTEnumProcesses(
    _Inout_ PD3DKMT_ENUM_PROCESS_LIST EnumProcessList
    );

EXTERN_C_END

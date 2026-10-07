#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

// Process KeepAlive (also WakeCounter)

/**
 * The PROCESS_ACTIVITY_TYPE enumeration identifies the type of process activity for NtAcquireProcessActivityReference.
 */
typedef enum _PROCESS_ACTIVITY_TYPE 
{ 
    ProcessActivityTypeAudio = 0, 
    ProcessActivityTypeMax = 1 
} PROCESS_ACTIVITY_TYPE, *PPROCESS_ACTIVITY_TYPE;

#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
// rev
/**
 * The NtAcquireProcessActivityReference routine acquires an activity reference on a process to keep it active.
 *
 * \param[out] ActivityReferenceHandle Pointer to a variable that receives a handle to the activity reference.
 * \param[in] ParentProcessHandle Handle to the process on which to acquire the activity reference.
 * \param[in] ProcessActivityType The type of process activity (PROCESS_ACTIVITY_TYPE).
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtAcquireProcessActivityReference(
    _Out_ PHANDLE ActivityReferenceHandle,
    _In_ HANDLE ParentProcessHandle,
    _In_ PROCESS_ACTIVITY_TYPE ProcessActivityType);
#endif

EXTERN_C_END

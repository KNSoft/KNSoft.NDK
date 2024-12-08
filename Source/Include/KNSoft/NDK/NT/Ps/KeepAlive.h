#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

// Process KeepAlive (also WakeCounter)

typedef enum _PROCESS_ACTIVITY_TYPE 
{ 
    ProcessActivityTypeAudio = 0, 
    ProcessActivityTypeMax = 1 
} PROCESS_ACTIVITY_TYPE, *PPROCESS_ACTIVITY_TYPE;

// rev
NTSYSCALLAPI
NTSTATUS
NTAPI
NtAcquireProcessActivityReference(
    _Out_ PHANDLE ActivityReferenceHandle,
    _In_ HANDLE ParentProcessHandle,
    _Reserved_ PROCESS_ACTIVITY_TYPE Reserved);

EXTERN_C_END

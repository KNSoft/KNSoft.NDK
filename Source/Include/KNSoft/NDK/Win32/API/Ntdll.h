#pragma once

#include "../../NT/MinDef.h"

EXTERN_C_START

#if (NTDDI_VERSION >= NTDDI_WIN11)
NTSYSAPI
NTSTATUS
NTAPI
ApiSetGetImplementationHost(
    _In_ PCSTR ApiSetName,
    _Out_ PBOOLEAN Resolved,
    _Out_ PUNICODE_STRING HostName);
#endif

NTSYSAPI
LOGICAL
NTAPI
ApiSetQueryApiSetPresence(
    _In_ PCUNICODE_STRING Namespace,
    _Out_ PBOOLEAN Present);

NTSYSAPI
LOGICAL
NTAPI
ApiSetQueryApiSetPresenceEx(
    _In_ PCUNICODE_STRING Namespace,
    _Out_ PBOOLEAN IsInSchema,
    _Out_ PBOOLEAN Present);

typedef
_Function_class_(SWITCH_BACK_PROCEDURE)
PVOID
NTAPI
SWITCH_BACK_PROCEDURE(
    _In_opt_ PVOID Context);
typedef SWITCH_BACK_PROCEDURE *PSWITCH_BACK_PROCEDURE;

NTSYSAPI
PSWITCH_BACK_PROCEDURE
NTAPI
SbSelectProcedure(
    ULONG Signature,        // 0xABABABAB
    ULONG Unknown,          // 0? 1?
    PVOID ScenarioTable,
    ULONG ScenarioIndex);

NTSYSAPI
PVOID
NTAPI
SbExecuteProcedure(
    ULONG Signature,        // 0xABABABAB
    ULONG Unknown,          // 0? 1?
    PVOID ScenarioTable,
    ULONG ScenarioIndex,
    PVOID Context);

EXTERN_C_END

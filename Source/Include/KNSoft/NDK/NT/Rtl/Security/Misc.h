#pragma once

#include "../../MinDef.h"

EXTERN_C_START

/* phnt */

#if (NTDDI_VERSION >= NTDDI_WIN8)

NTSYSAPI
NTSTATUS
NTAPI
RtlIsUntrustedObject(
    _In_opt_ HANDLE Handle,
    _In_opt_ PVOID Object,
    _Out_ PBOOLEAN IsUntrustedObject);

NTSYSAPI
ULONG
NTAPI
RtlQueryValidationRunlevel(
    _In_opt_ PUNICODE_STRING ComponentName);

#endif

EXTERN_C_END

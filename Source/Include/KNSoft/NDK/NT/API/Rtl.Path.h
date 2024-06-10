#pragma once

#include "../../NT/MinDef.h"
#include "../../NT/Types/Rtl.h"

EXTERN_C_START

NTSYSAPI
BOOLEAN
NTAPI
RtlDosPathNameToNtPathName_U(
    _In_opt_z_ LPCWSTR DosName,
    _Out_ PUNICODE_STRING NtName,
    _Out_opt_ LPCWSTR* PartName,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName);

NTSYSAPI
NTSTATUS
NTAPI
RtlDosPathNameToNtPathName_U_WithStatus(
    _In_opt_z_ LPCWSTR DosName,
    _Out_ PUNICODE_STRING NtName,
    _Out_opt_ LPCWSTR* PartName,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName);

NTSYSAPI
VOID
NTAPI
RtlReleaseRelativeName(
    _In_ PRTL_RELATIVE_NAME_U RelativeName);

EXTERN_C_END

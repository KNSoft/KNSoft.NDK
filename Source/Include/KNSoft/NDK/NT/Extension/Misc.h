#pragma once

#include "../MinDef.h"

FORCEINLINE
NTSTATUS
MAKE_NTSTATUS(
    _In_ ULONG Severity,
    _In_ ULONG Facility,
    _In_ ULONG Code)
{
    return (NTSTATUS)(((Severity & NT_SEVERITY_MASK) << NT_SEVERITY_SHIFT) |
                      ((Facility & NT_FACILITY_MASK) << NT_FACILITY_SHIFT) |
                      (Code & NT_CODE_MASK));
}

#define MAKEDWORD2(ll, lh, hl, hh) (((DWORD)MAKEWORD(hl, hh) << 16) & (DWORD)MAKEWORD(ll, lh))

#pragma region Alignments

#define CODE_ALIGNMENT 0x10
#define STRING_ALIGNMENT 0x4

#pragma endregion

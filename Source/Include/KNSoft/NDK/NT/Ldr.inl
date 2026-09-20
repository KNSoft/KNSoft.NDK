#pragma once

#include "../NDK.h"

EXTERN_C_START

__inline
NTSTATUS
NTAPI
_Inline_LdrGetDllHandle(
    _In_opt_ PCWSTR DllPath,
    _In_opt_ PULONG DllCharacteristics,
    _In_ PUNICODE_STRING DllName,
    _Out_ PVOID* DllHandle)
{
    return LdrGetDllHandleEx(LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT,
                             DllPath,
                             DllCharacteristics,
                             DllName,
                             DllHandle);
}

/* Matches the x86/x64 ntdll 10.0.26100.9278 relocation helpers.
   These routines do not validate the relocation targets or the HIGHADJ companion WORD. */

__inline
ULONG
NTAPI
_Inline_LdrpGenericProcessRelocation(
    _In_ PUSHORT NextOffset,
    _In_ ULONG_PTR VA,
    _In_ LONGLONG Diff)
{
    PVOID Target = (PVOID)(VA + (*NextOffset & 0xFFF));
    ULONG Type = *NextOffset >> 12;
    ULONG Value;

    if (Type == IMAGE_REL_BASED_DIR64)
    {
        *(ULONGLONG UNALIGNED*)Target += (ULONGLONG)Diff;
    } else if (Type == IMAGE_REL_BASED_HIGHLOW)
    {
        *(ULONG UNALIGNED*)Target += (ULONG)Diff;
    } else if (Type == IMAGE_REL_BASED_ABSOLUTE)
    {
        return 1;
    } else if (Type == IMAGE_REL_BASED_HIGH)
    {
        Value = ((ULONG)*(USHORT UNALIGNED*)Target << 16) + (ULONG)Diff;
        *(USHORT UNALIGNED*)Target = (USHORT)(Value >> 16);
    } else if (Type == IMAGE_REL_BASED_LOW)
    {
        *(USHORT UNALIGNED*)Target += (USHORT)Diff;
    } else if (Type == IMAGE_REL_BASED_HIGHADJ)
    {
        /* Windows zero-extends the companion WORD, then rounds the 32-bit sum. */
        Value = ((ULONG)*(USHORT UNALIGNED*)Target << 16) + (ULONG)Diff + NextOffset[1] + 0x8000;
        *(USHORT UNALIGNED*)Target = (USHORT)(Value >> 16);
        return 2;
    } else
    {
        return 0;
    }
    return 1;
}

__inline
ULONG
NTAPI
_Inline_LdrpArmProcessRelocation(
    _In_ PUSHORT NextOffset,
    _In_ ULONG_PTR VA,
    _In_ LONGLONG Diff)
{
    ULONG UNALIGNED* Target = (ULONG UNALIGNED*)(VA + (*NextOffset & 0xFFC));
    ULONG Low, High, Value;

    if ((*NextOffset >> 12) != IMAGE_REL_BASED_ARM_MOV32)
    {
        return 0;
    }
    Low = Target[0];
    High = Target[1];
    Value = (Low & 0xFFF) | ((Low >> 4) & 0xF000) |
            ((High & 0xFFF) << 16) | ((High & 0xF0000) << 12);
    Value += (ULONG)Diff;
    Target[0] = (Low & 0xFFF0F000) | (Value & 0xFFF) | ((Value & 0xF000) << 4);
    Value >>= 16;
    Target[1] = (High & 0xFFF0F000) | (Value & 0xFFF) | ((Value & 0xF000) << 4);
    return 1;
}

__inline
ULONG
NTAPI
_Inline_LdrpThumbProcessRelocation(
    _In_ PUSHORT NextOffset,
    _In_ ULONG_PTR VA,
    _In_ LONGLONG Diff)
{
    USHORT UNALIGNED* Target = (USHORT UNALIGNED*)(VA + (*NextOffset & 0xFFE));
    USHORT Low1, Low2, High1, High2;
    ULONG Value;

    if ((*NextOffset >> 12) == IMAGE_REL_BASED_THUMB_MOV32)
    {
        Low1 = Target[0];
        Low2 = Target[1];
        High1 = Target[2];
        High2 = Target[3];
        Value = ((Low1 & 0xF) << 12) | ((Low1 & 0x400) << 1) | ((Low2 & 0x7000) >> 4) | (Low2 & 0xFF) |
                ((ULONG)(High1 & 0xF) << 28) | ((High1 & 0x400) << 17) |
                ((High2 & 0x7000) << 12) | ((High2 & 0xFF) << 16);
        Value += (ULONG)Diff;
        Target[0] = (USHORT)((Low1 & 0xFBF0) | ((Value >> 12) & 0xF) | ((Value >> 1) & 0x400));
        Target[1] = (USHORT)((Low2 & 0x8F00) | ((Value << 4) & 0x7000) | (Value & 0xFF));
        Value >>= 16;
        Target[2] = (USHORT)((High1 & 0xFBF0) | ((Value >> 12) & 0xF) | ((Value >> 1) & 0x400));
        Target[3] = (USHORT)((High2 & 0x8F00) | ((Value << 4) & 0x7000) | (Value & 0xFF));
    } else if ((*NextOffset >> 12) == IMAGE_REL_BASED_ARM_MOV32)
    {
        return _Inline_LdrpArmProcessRelocation(NextOffset, VA, Diff);
    } else
    {
        return 0;
    }
    return 1;
}

/* SizeOfBlock is a count of WORD entries, not a byte size. */
_Must_inspect_result_
_Maybenull_
__inline
PIMAGE_BASE_RELOCATION
NTAPI
_Inline_LdrProcessRelocationBlockLongLong(
    _In_ USHORT Machine,
    _In_ ULONG_PTR VA,
    _In_ ULONG SizeOfBlock,
    _In_ PUSHORT NextOffset,
    _In_ LONGLONG Diff)
{
    ULONG_PTR End = (ULONG_PTR)NextOffset + (ULONG_PTR)SizeOfBlock * sizeof(USHORT);
    ULONG Count, Type;

    while ((ULONG_PTR)NextOffset < End)
    {
        Type = *NextOffset >> 12;
        if (Type != IMAGE_REL_BASED_MACHINE_SPECIFIC_5 && Type != IMAGE_REL_BASED_MACHINE_SPECIFIC_7 &&
            Type != IMAGE_REL_BASED_MACHINE_SPECIFIC_8 && Type != IMAGE_REL_BASED_MACHINE_SPECIFIC_9)
        {
            Count = _Inline_LdrpGenericProcessRelocation(NextOffset, VA, Diff);
        } else if (Machine == IMAGE_FILE_MACHINE_ARMNT || Machine == IMAGE_FILE_MACHINE_THUMB)
        {
            Count = _Inline_LdrpThumbProcessRelocation(NextOffset, VA, Diff);
        } else if (Machine == IMAGE_FILE_MACHINE_ARM)
        {
            Count = _Inline_LdrpArmProcessRelocation(NextOffset, VA, Diff);
        } else
        {
            return NULL;
        }
        if (Count == 0)
        {
            return NULL;
        }
        NextOffset = (PUSHORT)((ULONG_PTR)NextOffset + Count * sizeof(USHORT));
    }
    return (PIMAGE_BASE_RELOCATION)NextOffset;
}

_Must_inspect_result_
_Maybenull_
__inline
PIMAGE_BASE_RELOCATION
NTAPI
_Inline_LdrProcessRelocationBlock(
    _In_ ULONG_PTR VA,
    _In_ ULONG SizeOfBlock,
    _In_ PUSHORT NextOffset,
    _In_ LONG_PTR Diff)
{
    return _Inline_LdrProcessRelocationBlockLongLong(MACHINE_TYPE, VA, SizeOfBlock, NextOffset, (LONGLONG)Diff);
}

_Must_inspect_result_
_Maybenull_
__inline
PIMAGE_BASE_RELOCATION
NTAPI
_Inline_LdrProcessRelocationBlockEx(
    _In_ ULONG Machine,
    _In_ ULONG_PTR VA,
    _In_ ULONG SizeOfBlock,
    _In_ PUSHORT NextOffset,
    _In_ LONG_PTR Diff)
{
    return _Inline_LdrProcessRelocationBlockLongLong((USHORT)Machine, VA, SizeOfBlock, NextOffset, (LONGLONG)Diff);
}

EXTERN_C_END

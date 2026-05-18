#pragma once

#include "../../../NDK.h"

EXTERN_C_START

__inline
VOID
NTAPI
_Inline_RtlInitializeBitMap(
    _Out_ PRTL_BITMAP BitMapHeader,
    _In_opt_ __drv_aliasesMem PULONG BitMapBuffer,
    _In_opt_ ULONG SizeOfBitMap)
{
    BitMapHeader->SizeOfBitMap = SizeOfBitMap;
    BitMapHeader->Buffer = BitMapBuffer;
}

__inline
VOID
NTAPI
_Inline_RtlSetBit(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG BitNumber)
{
    ((PUCHAR)BitMapHeader->Buffer)[BitNumber >> 3] |= (UCHAR)(1u << (BitNumber & 7));
}

__inline
BOOLEAN
NTAPI
_Inline_RtlTestBit(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG BitNumber)
{
    return (BOOLEAN)((((const UCHAR*)BitMapHeader->Buffer)[BitNumber >> 3] >> (BitNumber & 7)) & 0x1);
}

EXTERN_C_END

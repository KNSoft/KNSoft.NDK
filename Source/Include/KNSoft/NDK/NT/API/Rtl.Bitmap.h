#pragma once

#include "../../NT/MinDef.h"
#include "../../NT/Types/Rtl.h"

EXTERN_C_START

NTSYSAPI
VOID
NTAPI
RtlInitializeBitMap(
    _Out_ PRTL_BITMAP BitMapHeader,
    _In_opt_ __drv_aliasesMem PULONG BitMapBuffer,
    _In_opt_ ULONG SizeOfBitMap);

NTSYSAPI
VOID
NTAPI
RtlClearBit(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG BitNumber);

NTSYSAPI
VOID
NTAPI
RtlSetBit(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG BitNumber);

_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlTestBit(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG BitNumber);

NTSYSAPI
VOID
NTAPI
RtlClearAllBits(
    _In_ PRTL_BITMAP BitMapHeader);

NTSYSAPI
VOID
NTAPI
RtlSetAllBits(
    _In_ PRTL_BITMAP BitMapHeader);

_Success_(return != -1)
_Ret_range_(<=, BitMapHeader->SizeOfBitMap - NumberToFind)
_Must_inspect_result_
NTSYSAPI
ULONG
NTAPI
RtlFindClearBits(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG NumberToFind,
    _In_ ULONG HintIndex);

_Success_(return != -1)
_Ret_range_(<=, BitMapHeader->SizeOfBitMap - NumberToFind)
_Must_inspect_result_
NTSYSAPI
ULONG
NTAPI
RtlFindSetBits(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG NumberToFind,
    _In_ ULONG HintIndex);

_Success_(return != -1)
_Ret_range_(<=, BitMapHeader->SizeOfBitMap - NumberToFind)
NTSYSAPI
ULONG
NTAPI
RtlFindClearBitsAndSet(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG NumberToFind,
    _In_ ULONG HintIndex);

_Success_(return != -1)
_Ret_range_(<=, BitMapHeader->SizeOfBitMap - NumberToFind)
NTSYSAPI
ULONG
NTAPI
RtlFindSetBitsAndClear(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG NumberToFind,
    _In_ ULONG HintIndex);

NTSYSAPI
VOID
NTAPI
RtlClearBits(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(0, BitMapHeader->SizeOfBitMap - NumberToClear) ULONG StartingIndex,
    _In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToClear);

NTSYSAPI
VOID
NTAPI
RtlSetBits(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(0, BitMapHeader->SizeOfBitMap - NumberToSet) ULONG StartingIndex,
    _In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToSet);

EXTERN_C_END

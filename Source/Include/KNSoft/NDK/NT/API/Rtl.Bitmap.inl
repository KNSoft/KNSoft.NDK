#pragma once

#include "../../NT/MinDef.h"
#include "../../NT/Types/Rtl.h"

VOID
FORCEINLINE
NTAPI_INLINE
RtlInitializeBitMap(
    _Out_ PRTL_BITMAP BitMapHeader,
    _In_opt_ __drv_aliasesMem PULONG BitMapBuffer,
    _In_opt_ ULONG SizeOfBitMap)
{
    BitMapHeader->SizeOfBitMap = SizeOfBitMap;
    BitMapHeader->Buffer = BitMapBuffer;
}

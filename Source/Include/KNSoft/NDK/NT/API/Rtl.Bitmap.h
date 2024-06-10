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

EXTERN_C_END

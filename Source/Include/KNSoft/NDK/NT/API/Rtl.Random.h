#pragma once

#include "../../NT/MinDef.h"

EXTERN_C_START

_IRQL_requires_max_(APC_LEVEL)
_Ret_range_(<= , MAXLONG)
NTSYSAPI
ULONG
NTAPI
RtlRandom(
    _Inout_ PULONG Seed);

_IRQL_requires_max_(APC_LEVEL)
_Ret_range_(<= , MAXLONG)
NTSYSAPI
ULONG
NTAPI
RtlRandomEx(
    _Inout_ PULONG Seed);

EXTERN_C_END

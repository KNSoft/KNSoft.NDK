#pragma once

#include "MinDef.h"

EXTERN_C_START

#pragma region CSRSS

/* microsoft/terminal ntcsrmsg.h & KNSoft.NDK */

#define CSR_MAKE_API_NUMBER(DllIndex, ApiIndex) ((ULONG)(((DllIndex) << 16) | (ApiIndex)))
typedef PVOID PCSR_API_MSG;
typedef PVOID PCSR_CAPTURE_HEADER;

#pragma endregion

EXTERN_C_END

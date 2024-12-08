#pragma once

#include "../../NT/MinDef.h"

EXTERN_C_START

NTSYSAPI
BOOL 
NTAPI 
ApiSetQueryApiSetPresence(
    _In_ PCUNICODE_STRING Namespace,
    _Out_ PBOOLEAN Present);

NTSYSAPI
BOOL 
NTAPI 
ApiSetQueryApiSetPresenceEx(
    _In_ PCUNICODE_STRING Namespace,
    _Out_ PBOOLEAN IsInSchema,
    _Out_ PBOOLEAN Present);

EXTERN_C_END

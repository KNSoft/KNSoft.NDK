#pragma once

#include "Nls.h"

EXTERN_C_START

/* Private ntdll helpers; Table is an optional 8:4:4 case-mapping table. */

__inline
WCHAR
NTAPI
_Inline_NLS_UPCASE(
    _In_opt_ const USHORT* Table,
    _In_ WCHAR Character)
{
    if (Character < L'a')
    {
        return Character;
    }
    if (Character <= L'z')
    {
        return Character - (L'a' - L'A');
    }
    if (Table == NULL || Character < 0xC0)
    {
        return Character;
    }
    return (WCHAR)(Character + Table[Table[Table[Character >> 8] + ((Character >> 4) & 0xF)] + (Character & 0xF)]);
}

__inline
WCHAR
NTAPI
_Inline_NLS_DOWNCASE(
    _In_opt_ const USHORT* Table,
    _In_ WCHAR Character)
{
    if (Character < L'A')
    {
        return Character;
    }
    if (Character <= L'Z')
    {
        return Character + (L'a' - L'A');
    }
    if (Table == NULL || Character < 0xC0)
    {
        return Character;
    }
    return (WCHAR)(Character + Table[Table[Table[Character >> 8] + ((Character >> 4) & 0xF)] + (Character & 0xF)]);
}

EXTERN_C_END

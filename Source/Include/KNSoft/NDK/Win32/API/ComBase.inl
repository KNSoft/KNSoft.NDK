#pragma once

#include "../../NDK.h"

EXTERN_C_START

__inline
UINT32
STDAPICALLTYPE
_Inline_WindowsGetStringLen(
    _In_opt_ HSTRING string)
{
    return string != NULL ? ((PHSTRING_INTERNAL)string)->Length : 0;
}

__inline
PCWSTR
STDAPICALLTYPE
_Inline_WindowsGetStringRawBuffer(
    _In_opt_ HSTRING string,
    _Out_opt_ UINT32* length)
{
    PHSTRING_INTERNAL p = (PHSTRING_INTERNAL)string;
    PCWSTR psz;
    
    if (string != NULL)
    {
        psz = p->Buffer;
    } else
    {
        psz = L"";
    }
    if (length != NULL)
    {
        *length = string != NULL ? p->Length : 0;
    }
    return psz;
}

__inline
BOOL
STDAPICALLTYPE
_Inline_WindowsIsStringEmpty(
    _In_opt_ HSTRING string)
{
    return string != NULL ? ((PHSTRING_INTERNAL)string)->Length == 0 : TRUE;
}

__inline
HRESULT
STDAPICALLTYPE
_Inline_WindowsDeleteString(
    _In_opt_ HSTRING string)
{
    if (string != NULL &&
        (*(PBYTE)string & 1) == 0 &&
        _InterlockedDecrement(&((PHSTRING_INTERNAL)string)->RefCount) == 0)
    {
        RtlFreeHeap(RtlProcessHeap(), 0, string);
    }
    return S_OK;
}

EXTERN_C_END

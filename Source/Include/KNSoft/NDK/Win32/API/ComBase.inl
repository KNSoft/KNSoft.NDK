#pragma once

#include "../../NDK.h"
#include "Kernel32.inl"

EXTERN_C_START

__inline
HRESULT
STDAPICALLTYPE
_Inline_WindowsPreallocateStringBuffer(
    _In_ ULONG length,
    _Outptr_result_buffer_(length + 1) WCHAR** charBuffer,
    _Outptr_ _Result_nullonfailure_ HSTRING_BUFFER* bufferHandle)
{
    HSTRING p;

    if (charBuffer == NULL || bufferHandle == NULL)
    {
        return E_POINTER;
    }
    *charBuffer = NULL;
    *bufferHandle = NULL;
    if (length > (MAXULONG - sizeof(HSTRING__)) / sizeof(WCHAR))
    {
        return MEM_E_INVALID_SIZE;
    }
    p = (HSTRING)RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(*p) + (SIZE_T)length * sizeof(WCHAR));
    if (p == NULL)
    {
        return E_OUTOFMEMORY;
    }
    p->Header.Flags = (WINDOWS_RUNTIME_HSTRING_FLAGS)HSTRING_BUFFER_SIGNATURE;
    p->Header.Length = length;
    p->Header.Buffer = p->Data;
    p->RefCount = 1;
    p->Data[length] = UNICODE_NULL;
    *charBuffer = p->Data;
    *bufferHandle = (HSTRING_BUFFER)p;
    return S_OK;
}

__inline
HRESULT
STDAPICALLTYPE
_Inline_WindowsCreateString(
    _In_reads_opt_(length) PCNZWCH sourceString,
    _In_ ULONG length,
    _Outptr_result_maybenull_ _Result_nullonfailure_ HSTRING* string)
{
    HRESULT hr;
    PWSTR Buffer;
    HSTRING_BUFFER Handle;

    if (string == NULL)
    {
        return E_INVALIDARG;
    }
    *string = NULL;
    if (length == 0)
    {
        return S_OK;
    }
    if (sourceString == NULL)
    {
        return E_POINTER;
    }
    hr = _Inline_WindowsPreallocateStringBuffer(length, &Buffer, &Handle);
    if (SUCCEEDED(hr))
    {
        RtlCopyMemory(Buffer, sourceString, (SIZE_T)length * sizeof(WCHAR));
        ((HSTRING)Handle)->Header.Flags = WRHF_NONE;
        *string = (HSTRING)Handle;
    }
    return hr;
}

__inline
HRESULT
STDAPICALLTYPE
_Inline_WindowsCreateStringReference(
    _In_reads_opt_(length + 1) PCWSTR sourceString,
    _In_ ULONG length,
    _Out_ HSTRING_HEADER* hstringHeader,
    _Outptr_result_maybenull_ _Result_nullonfailure_ HSTRING* string)
{
    if (string == NULL || hstringHeader == NULL)
    {
        return E_INVALIDARG;
    }
    *string = NULL;
    if (length == MAXULONG)
    {
        return E_INVALIDARG;
    }
    if (sourceString == NULL)
    {
        if (length == 0)
        {
            return S_OK;
        }
        return E_POINTER;
    }
    if (sourceString[length] != UNICODE_NULL)
    {
        return E_STRING_NOT_NULL_TERMINATED;
    }
    if (length != 0)
    {
        hstringHeader->Flags = WRHF_STRING_REFERENCE;
        hstringHeader->Length = length;
        hstringHeader->Buffer = sourceString;
        *string = (HSTRING)hstringHeader;
    }
    return S_OK;
}

__inline
ULONG
STDAPICALLTYPE
_Inline_WindowsGetStringLen(
    _In_opt_ HSTRING string)
{
    return string != NULL ? string->Header.Length : 0;
}

__inline
PCWSTR
STDAPICALLTYPE
_Inline_WindowsGetStringRawBuffer(
    _In_opt_ HSTRING string,
    _Out_opt_ ULONG* length)
{
    HSTRING p = string;
    PCWSTR psz;
    
    if (string != NULL)
    {
        psz = p->Header.Buffer;
    } else
    {
        psz = L"";
    }
    if (length != NULL)
    {
        *length = string != NULL ? p->Header.Length : 0;
    }
    return psz;
}

__inline
BOOL
STDAPICALLTYPE
_Inline_WindowsIsStringEmpty(
    _In_opt_ HSTRING string)
{
    return _Inline_WindowsGetStringLen(string) == 0;
}

__inline
HRESULT
STDAPICALLTYPE
_Inline_WindowsDeleteString(
    _In_opt_ HSTRING string)
{
    if (string != NULL &&
        (string->Header.Flags & WRHF_STRING_REFERENCE) == 0 &&
        _InterlockedDecrement(&string->RefCount) == 0)
    {
        RtlFreeHeap(RtlProcessHeap(), 0, string);
    }
    return S_OK;
}

__inline
HRESULT
STDAPICALLTYPE
_Inline_WindowsDuplicateString(
    _In_opt_ HSTRING string,
    _Outptr_result_maybenull_ _Result_nullonfailure_ HSTRING* newString)
{
    HSTRING p = string;

    if (newString == NULL)
    {
        return E_INVALIDARG;
    }
    *newString = NULL;
    if (p != NULL)
    {
        if ((p->Header.Flags & WRHF_STRING_REFERENCE) != 0)
        {
            return _Inline_WindowsCreateString(p->Header.Buffer, p->Header.Length, newString);
        }
        _InterlockedIncrement(&p->RefCount);
        *newString = string;
    }
    return S_OK;
}

__inline
HRESULT
STDAPICALLTYPE
_Inline_WindowsPromoteStringBuffer(
    _In_ HSTRING_BUFFER bufferHandle,
    _Outptr_result_maybenull_ _Result_nullonfailure_ HSTRING* string)
{
    HSTRING p = (HSTRING)bufferHandle;

    if (string == NULL)
    {
        return E_POINTER;
    }
    *string = NULL;
    if (p != NULL)
    {
        if ((ULONG)p->Header.Flags != HSTRING_BUFFER_SIGNATURE || p->Header.Buffer[p->Header.Length] != UNICODE_NULL)
        {
            return E_INVALIDARG;
        }
        if (p->Header.Length == 0)
        {
            _Inline_WindowsDeleteString((HSTRING)p);
        } else
        {
            p->Header.Flags = WRHF_NONE;
            *string = (HSTRING)p;
        }
    }
    return S_OK;
}

__inline
HRESULT
STDAPICALLTYPE
_Inline_WindowsDeleteStringBuffer(
    _In_opt_ HSTRING_BUFFER bufferHandle)
{
    if (bufferHandle != NULL && ((PHSTRING_HEADER)bufferHandle)->Flags != HSTRING_BUFFER_SIGNATURE)
    {
        _Inline_RaiseException(STATUS_INVALID_PARAMETER, EXCEPTION_NONCONTINUABLE, 0, NULL);
    }
    return _Inline_WindowsDeleteString((HSTRING)bufferHandle);
}

__inline
HRESULT
STDAPICALLTYPE
_Inline_WindowsStringHasEmbeddedNull(
    _In_opt_ HSTRING string,
    _Out_ BOOL* hasEmbedNull)
{
    HSTRING p = string;
    ULONG Flags;
    ULONG Index;

    if (hasEmbedNull == NULL)
    {
        return E_INVALIDARG;
    }
    if (p != NULL && p->Header.Length != 0)
    {
        Flags = p->Header.Flags;
        if ((Flags & WRHF_EMBEDDED_NULLS_COMPUTED) == 0)
        {
            Flags = WRHF_EMBEDDED_NULLS_COMPUTED;
            for (Index = 0; Index < p->Header.Length; Index++)
            {
                if (p->Header.Buffer[Index] == UNICODE_NULL)
                {
                    Flags |= WRHF_HAS_EMBEDDED_NULLS;
                    break;
                }
            }
            // Preserve other cached flags when readers share an owning HSTRING.
            Flags |= (ULONG)_InterlockedOr((volatile LONG*)&p->Header.Flags, (LONG)Flags);
        }
        *hasEmbedNull = (Flags & WRHF_HAS_EMBEDDED_NULLS) != 0;
    } else
    {
        *hasEmbedNull = FALSE;
    }
    return S_OK;
}

__inline
HRESULT
STDAPICALLTYPE
_Inline_WindowsCompareStringOrdinal(
    _In_opt_ HSTRING string1,
    _In_opt_ HSTRING string2,
    _Out_ INT32* result)
{
    INT Value;

    if (result == NULL)
    {
        return E_INVALIDARG;
    } else if (string1 == string2)
    {
        *result = 0;
        return S_OK;
    } else if (string1 == NULL)
    {
        *result = _Inline_WindowsIsStringEmpty(string2) ? 0 : -1;
        return S_OK;
    } else if (string2 == NULL)
    {
        *result = _Inline_WindowsIsStringEmpty(string1) ? 0 : 1;
        return S_OK;
    }
    Value = CompareStringOrdinal(_Inline_WindowsGetStringRawBuffer(string1, NULL),
                                 _Inline_WindowsGetStringLen(string1),
                                 _Inline_WindowsGetStringRawBuffer(string2, NULL),
                                 _Inline_WindowsGetStringLen(string2),
                                 FALSE);
    *result = Value == CSTR_LESS_THAN ? -1 : (Value == CSTR_GREATER_THAN ? 1 : 0);
    return S_OK;
}

__inline
HRESULT
STDAPICALLTYPE
_Inline_WindowsSubstring(
    _In_opt_ HSTRING string,
    _In_ ULONG startIndex,
    _Outptr_result_maybenull_ _Result_nullonfailure_ HSTRING* newString)
{
    ULONG Length = _Inline_WindowsGetStringLen(string);

    if (newString == NULL)
    {
        return E_INVALIDARG;
    }
    *newString = NULL;
    if (startIndex > Length)
    {
        return E_BOUNDS;
    }
    return _Inline_WindowsCreateString(_Inline_WindowsGetStringRawBuffer(string, NULL) + startIndex,
                                      Length - startIndex,
                                      newString);
}

__inline
HRESULT
STDAPICALLTYPE
_Inline_WindowsSubstringWithSpecifiedLength(
    _In_opt_ HSTRING string,
    _In_ ULONG startIndex,
    _In_ ULONG length,
    _Outptr_result_maybenull_ _Result_nullonfailure_ HSTRING* newString)
{
    ULONG Length = _Inline_WindowsGetStringLen(string);

    if (newString == NULL)
    {
        return E_INVALIDARG;
    }
    *newString = NULL;
    if (startIndex > Length)
    {
        return E_BOUNDS;
    }
    if (length > MAXULONG - startIndex)
    {
        return HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
    }
    if (length > Length - startIndex)
    {
        return E_BOUNDS;
    }
    return _Inline_WindowsCreateString(_Inline_WindowsGetStringRawBuffer(string, NULL) + startIndex, length, newString);
}

EXTERN_C_END

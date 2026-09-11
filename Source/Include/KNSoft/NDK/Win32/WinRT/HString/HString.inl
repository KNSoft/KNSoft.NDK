#pragma once

#include "../../../NDK.h"
#include "../../Kernel32/ErrorHandling.inl"

EXTERN_C_START

// CHSTRINGUtil::CreateString also accepts a NULL source for a nonzero length.
__inline
HRESULT
_Inline_HStringCreate(
    _In_reads_opt_(length) PCNZWCH sourceString,
    _In_ ULONG length,
    _Outptr_result_maybenull_ _Result_nullonfailure_ HSTRING* string)
{
    HSTRING p;

    *string = NULL;
    if (length == 0)
    {
        return S_OK;
    }
    if (length > (MAXULONG - sizeof(HSTRING__)) / sizeof(WCHAR))
    {
        return MEM_E_INVALID_SIZE;
    }
    p = (HSTRING)RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(*p) + (SIZE_T)length * sizeof(WCHAR));
    *string = p;
    if (p == NULL)
    {
        return E_OUTOFMEMORY;
    }
    if (sourceString != NULL)
    {
        RtlCopyMemory(p->Data, sourceString, (SIZE_T)length * sizeof(WCHAR));
    }
    p->Data[length] = UNICODE_NULL;
    p->Header.Flags = WRHF_NONE;
    p->Header.Buffer = p->Data;
    p->Header.Length = length;
    p->RefCount = 1;
    *string = p;
    return S_OK;
}

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
    *bufferHandle = (HSTRING_BUFFER)p;
    *charBuffer = p->Data;
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
    if (string == NULL)
    {
        return E_INVALIDARG;
    }
    *string = NULL;
    if (sourceString == NULL && length != 0)
    {
        return E_POINTER;
    }
    return _Inline_HStringCreate(sourceString, length, string);
}

// The caller must keep both the header and source buffer alive and unchanged until the reference is abandoned.
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
#if defined(_WIN64)
        hstringHeader->Padding[0] = 0;
        hstringHeader->Padding[1] = 0;
#endif
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
    LONG RefCount;

    if (string != NULL && (string->Header.Flags & WRHF_STRING_REFERENCE) == 0)
    {
        RefCount = _InterlockedExchangeAdd(&string->RefCount, -1);
        // Windows checks the signed count before and after the decrement.
        if (RefCount <= 1 && (LONG)((ULONG)RefCount - 1) >= 0)
        {
            RtlFreeHeap(RtlProcessHeap(), 0, string);
        }
    }
    return S_OK;
}

// Retain a borrowed HSTRING through the returned handle; duplicating a fast-pass string copies its contents.
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
            return _Inline_HStringCreate(p->Header.Buffer, p->Header.Length, newString);
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
    PCWSTR Buffer, End;

    if (hasEmbedNull == NULL)
    {
        return E_INVALIDARG;
    }
    *hasEmbedNull = FALSE;
    if (p != NULL && p->Header.Length != 0)
    {
        Flags = p->Header.Flags;
        if ((Flags & WRHF_EMBEDDED_NULLS_COMPUTED) == 0)
        {
            Buffer = p->Header.Buffer;
            End = Buffer + p->Header.Length;
            for (; Buffer < End; Buffer++)
            {
                if (*Buffer == UNICODE_NULL)
                {
                    Flags |= WRHF_HAS_EMBEDDED_NULLS;
                    break;
                }
            }
            Flags |= WRHF_EMBEDDED_NULLS_COMPUTED;
            p->Header.Flags = (WINDOWS_RUNTIME_HSTRING_FLAGS)Flags;
        }
        *hasEmbedNull = (Flags & WRHF_HAS_EMBEDDED_NULLS) != 0;
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
    ULONG Length;
    PCWSTR Buffer;

    if (newString == NULL)
    {
        return E_INVALIDARG;
    }
    *newString = NULL;
    // Preserve the output reset if reading the input header raises an exception.
    _ReadWriteBarrier();
    Length = string != NULL ? ((volatile HSTRING_HEADER*)string)->Length : 0;
    Buffer = Length != 0 ? ((volatile HSTRING_HEADER*)string)->Buffer : NULL;
    if (startIndex > Length)
    {
        return E_BOUNDS;
    }
    if (Length == 0 || startIndex == Length)
    {
        return S_OK;
    }
    return _Inline_HStringCreate((PCWSTR)((ULONG_PTR)Buffer + (SIZE_T)startIndex * sizeof(WCHAR)),
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
    ULONG Length;
    PCWSTR Buffer;

    if (newString == NULL)
    {
        return E_INVALIDARG;
    }
    *newString = NULL;
    // Preserve the output reset if reading the input header raises an exception.
    _ReadWriteBarrier();
    Length = string != NULL ? ((volatile HSTRING_HEADER*)string)->Length : 0;
    Buffer = Length != 0 ? ((volatile HSTRING_HEADER*)string)->Buffer : NULL;
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
    if (Length == 0 || length == 0)
    {
        return S_OK;
    }
    return _Inline_HStringCreate((PCWSTR)((ULONG_PTR)Buffer + (SIZE_T)startIndex * sizeof(WCHAR)),
                                length,
                                newString);
}

EXTERN_C_END

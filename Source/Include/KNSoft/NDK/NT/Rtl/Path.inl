#pragma once

#include "../../NDK.h"

EXTERN_C_START

EXTERN_C CONST DECLSPEC_SELECTANY PCWSTR _Inline_RtlNtdllName = L"ntdll.dll";
EXTERN_C CONST DECLSPEC_SELECTANY UNICODE_STRING _Inline_RtlDosPathSeperatorsString = RTL_CONSTANT_STRING(L"\\/");
EXTERN_C CONST DECLSPEC_SELECTANY UNICODE_STRING _Inline_RtlAlternateDosPathSeperatorString = RTL_CONSTANT_STRING(L"/");
EXTERN_C CONST DECLSPEC_SELECTANY UNICODE_STRING _Inline_RtlNtPathSeperatorString = RTL_CONSTANT_STRING(L"\\");
EXTERN_C CONST DECLSPEC_SELECTANY UNICODE_STRING _Inline_RtlDosPathPrefix = RTL_CONSTANT_STRING(L"\\??\\");
EXTERN_C CONST DECLSPEC_SELECTANY UNICODE_STRING _Inline_RtlUncPathPrefix = RTL_CONSTANT_STRING(L"\\??\\UNC\\");

__inline
RTL_PATH_TYPE
NTAPI
_Inline_RtlDetermineDosPathNameType_Ustr(
    _In_ PCUNICODE_STRING DosFileName)
{
    PCWSTR Buffer = DosFileName->Buffer;
    USHORT Length = DosFileName->Length;

    if (Length < 2)
    {
        return RtlPathTypeRelative;
    }
    if (Buffer[0] == L'\\' || Buffer[0] == L'/')
    {
        if (Length < 4 || (Buffer[1] != L'\\' && Buffer[1] != L'/'))
        {
            return RtlPathTypeRooted;
        }
        if (Length >= 6 && (Buffer[2] == L'.' || Buffer[2] == L'?'))
        {
            if (Length >= 8 && (Buffer[3] == L'\\' || Buffer[3] == L'/'))
            {
                return RtlPathTypeLocalDevice;
            }
            if (Length == 6)
            {
                return RtlPathTypeRootLocalDevice;
            }
        }
        return RtlPathTypeUncAbsolute;
    }
    if (Length >= 4 && Buffer[0] != UNICODE_NULL && Buffer[1] == L':')
    {
        return Length >= 6 && (Buffer[2] == L'\\' || Buffer[2] == L'/') ?
            RtlPathTypeDriveAbsolute :
            RtlPathTypeDriveRelative;
    }
    return RtlPathTypeRelative;
}

EXTERN_C_END

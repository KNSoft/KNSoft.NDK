﻿#pragma once

#include "../../NDK.h"

EXTERN_C_START

__inline
VOID
NTAPI
_Inline_RtlInitString(
    _Out_ PSTRING DestinationString,
    _In_opt_z_ PCSTR SourceString)
{
    if (SourceString)
    {
        SIZE_T Size = strlen(SourceString);
        if (Size > (MAXUSHORT - sizeof(CHAR)))
        {
            Size = MAXUSHORT - sizeof(CHAR);
        }
        DestinationString->Length = (USHORT)Size;
        DestinationString->MaximumLength = (USHORT)Size + sizeof(CHAR);
    }
    else
    {
        DestinationString->Length = DestinationString->MaximumLength = 0;
    }
    DestinationString->Buffer = (PCHAR)SourceString;
}

__inline
NTSTATUS
NTAPI
_Inline_RtlInitStringEx(
    _Out_ PSTRING DestinationString,
    _In_opt_z_ PCSZ SourceString)
{
    if (SourceString)
    {
        SIZE_T Size = strlen(SourceString);
        if (Size > (MAXUSHORT - sizeof(CHAR)))
        {
            return STATUS_NAME_TOO_LONG;
        }
        DestinationString->Length = (USHORT)Size;
        DestinationString->MaximumLength = (USHORT)Size + sizeof(CHAR);
    }
    else
    {
        DestinationString->Length = DestinationString->MaximumLength = 0;
    }
    DestinationString->Buffer = (PCHAR)SourceString;
    return STATUS_SUCCESS;
}

__inline
VOID
NTAPI
_Inline_RtlInitAnsiString(
    _Out_ PANSI_STRING DestinationString,
    _In_opt_z_ PCSTR SourceString)
{
    _Inline_RtlInitString(DestinationString, SourceString);
}

__inline
NTSTATUS
NTAPI
_Inline_RtlInitAnsiStringEx(
    _Out_ PANSI_STRING DestinationString,
    _In_opt_z_ PCSZ SourceString)
{
    return _Inline_RtlInitStringEx(DestinationString, SourceString);
}

__inline
VOID
NTAPI
_Inline_RtlInitUTF8String(
    _Out_ PUTF8_STRING DestinationString,
    _In_opt_z_ PCSZ SourceString)
{
    _Inline_RtlInitString(DestinationString, SourceString);
}

__inline
NTSTATUS
NTAPI
_Inline_RtlInitUTF8StringEx(
    _Out_ PUTF8_STRING DestinationString,
    _In_opt_z_ PCSZ SourceString)
{
    return _Inline_RtlInitStringEx(DestinationString, SourceString);
}

__inline
VOID
NTAPI
_Inline_RtlInitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_z_ PCWSTR SourceString)
{
    SIZE_T MaxSize = (MAXUSHORT & ~1) - sizeof(UNICODE_NULL);
 
    if (SourceString)
    {
        SIZE_T Size = wcslen(SourceString) * sizeof(WCHAR);
 
        if (Size > MaxSize)
        {
            Size = MaxSize;
        }
        DestinationString->Length = (USHORT)Size;
        DestinationString->MaximumLength = (USHORT)Size + sizeof(UNICODE_NULL);
    }
    else
    {
        DestinationString->Length = DestinationString->MaximumLength = 0;
    }
    DestinationString->Buffer = (PWCHAR)SourceString;
}

__inline
NTSTATUS
NTAPI
_Inline_RtlInitUnicodeStringEx(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_z_ PCWSTR SourceString)
{
    if (SourceString)
    {
        SIZE_T Size = wcslen(SourceString) * sizeof(WCHAR);
        if (Size > (MAXUSHORT & ~1) - sizeof(WCHAR))
        {
            return STATUS_NAME_TOO_LONG;
        }
        DestinationString->Length = (USHORT)Size;
        DestinationString->MaximumLength = (USHORT)Size + sizeof(WCHAR);
    }
    else
    {
        DestinationString->Length = DestinationString->MaximumLength = 0;
    }
    DestinationString->Buffer = (PWCHAR)SourceString;
    return STATUS_SUCCESS;
}

__inline
VOID
NTAPI
_Inline_RtlEraseUnicodeString(
    _Inout_ PUNICODE_STRING String)
{
    if (String->Buffer != NULL && String->MaximumLength)
    {
        memset(String->Buffer, 0, String->MaximumLength);
        String->Length = 0;
    }
}

EXTERN_C_END

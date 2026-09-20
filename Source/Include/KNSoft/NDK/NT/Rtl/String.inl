#pragma once

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
        if (Size > ANSI_STRING_MAX_BYTES - sizeof(ANSI_NULL))
        {
            Size = ANSI_STRING_MAX_BYTES - sizeof(ANSI_NULL);
        }
        DestinationString->Length = (USHORT)Size;
        DestinationString->MaximumLength = DestinationString->Length + sizeof(ANSI_NULL);
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
        if (Size > ANSI_STRING_MAX_BYTES - sizeof(ANSI_NULL))
        {
            return STATUS_NAME_TOO_LONG;
        }
        DestinationString->Length = (USHORT)Size;
        DestinationString->MaximumLength = DestinationString->Length + sizeof(ANSI_NULL);
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
    if (SourceString)
    {
        SIZE_T Size = wcslen(SourceString) * sizeof(WCHAR);
        if (Size > UNICODE_STRING_MAX_BYTES - sizeof(UNICODE_NULL))
        {
            Size = UNICODE_STRING_MAX_BYTES - sizeof(UNICODE_NULL);
        }
        DestinationString->Length = (USHORT)Size;
        DestinationString->MaximumLength = DestinationString->Length + sizeof(UNICODE_NULL);
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
    if (String->Buffer != NULL && String->MaximumLength != 0)
    {
        memset(String->Buffer, 0, String->MaximumLength);
        String->Length = 0;
    }
}

__inline
CHAR
NTAPI
_Inline_RtlUpperChar(
    _In_ CHAR Character)
{
    /* RtlpIsUtf8Process supplies a barrier; its result is unused by RtlUpperChar. */
    MemoryBarrier();
    if ((UCHAR)(Character - 'a') <= 'z' - 'a')
    {
        return Character ^ ('a' - 'A');
    }
    return Character;
}

__inline
BOOLEAN
NTAPI
_Inline_RtlEqualString(
    _In_ const STRING* String1,
    _In_ const STRING* String2,
    _In_ BOOLEAN CaseInSensitive)
{
    USHORT i;

    if (String1->Length != String2->Length)
    {
        return FALSE;
    }
    if (!CaseInSensitive)
    {
        return RtlCompareMemory(String1->Buffer, String2->Buffer, String1->Length) == String1->Length;
    }
    for (i = 0; i < String1->Length; i++)
    {
        if (String1->Buffer[i] != String2->Buffer[i] &&
            _Inline_RtlUpperChar(String1->Buffer[i]) != _Inline_RtlUpperChar(String2->Buffer[i]))
        {
            return FALSE;
        }
    }
    return TRUE;
}

__inline
BOOLEAN
NTAPI
_Inline_RtlEqualUnicodeString(
    _In_ PCUNICODE_STRING String1,
    _In_ PCUNICODE_STRING String2,
    _In_ BOOLEAN CaseInSensitive)
{
    USHORT i;

    if (String1->Length != String2->Length)
    {
        return FALSE;
    }
    if (!CaseInSensitive)
    {
        return RtlEqualMemory(String1->Buffer, String2->Buffer, String1->Length);
    }
    for (i = 0; (SIZE_T)i * sizeof(WCHAR) < String1->Length; i++)
    {
        if (String1->Buffer[i] != String2->Buffer[i] &&
            RtlUpcaseUnicodeChar(String1->Buffer[i]) != RtlUpcaseUnicodeChar(String2->Buffer[i]))
        {
            return FALSE;
        }
    }
    return TRUE;
}

EXTERN_C_END

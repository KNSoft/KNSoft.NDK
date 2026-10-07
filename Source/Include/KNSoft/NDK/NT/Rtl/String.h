#pragma once

#include "../MinDef.h"
#include "../Nls.h"
#include "DataStructures/GenericTable.h"

EXTERN_C_START

/* phnt & wdm.h */

NTSYSAPI
VOID
NTAPI
RtlInitString(
    _Out_ PSTRING DestinationString,
    _In_opt_z_ PCSTR SourceString
);

#if (NTDDI_VERSION >= NTDDI_WIN10)
NTSYSAPI
NTSTATUS
NTAPI
RtlInitStringEx(
    _Out_ PSTRING DestinationString,
    _In_opt_z_ PCSZ SourceString
);
#endif

NTSYSAPI
VOID
NTAPI
RtlInitAnsiString(
    _Out_ PANSI_STRING DestinationString,
    _In_opt_z_ PCSTR SourceString
);

NTSYSAPI
NTSTATUS
NTAPI
RtlInitAnsiStringEx(
    _Out_ PANSI_STRING DestinationString,
    _In_opt_z_ PCSZ SourceString
);

/**
 * The RtlInitEmptyUnicodeString routine initializes a UNICODE_STRING with a caller-supplied buffer and zero length.
 *
 * \param UnicodeString A pointer to the UNICODE_STRING structure to initialize.
 * \param Buffer A pointer to the caller-allocated buffer that backs the string.
 * \param BufferSize The size, in bytes, of the buffer.
 */
_At_(UnicodeString->Buffer, _Post_equal_to_(Buffer))
_At_(UnicodeString->Length, _Post_equal_to_(0))
_At_(UnicodeString->MaximumLength, _Post_equal_to_(BufferSize))
FORCEINLINE
VOID
RtlInitEmptyUnicodeString(
    _Out_ PUNICODE_STRING UnicodeString,
    _Writable_bytes_(BufferSize)
    _When_(BufferSize != 0, _Notnull_)
    __drv_aliasesMem PWCHAR Buffer,
    _In_ USHORT BufferSize
    )
{
    memset(UnicodeString, 0, sizeof(*UnicodeString));
    UnicodeString->MaximumLength = BufferSize;
    UnicodeString->Buffer = Buffer;
}

/**
 * The RtlInitEmptyAnsiString routine initializes an ANSI_STRING with a caller-supplied buffer and zero length.
 *
 * \param AnsiString A pointer to the ANSI_STRING structure to initialize.
 * \param Buffer A pointer to the caller-allocated buffer that backs the string.
 * \param MaximumLength The size, in bytes, of the buffer.
 */
_At_(AnsiString->Buffer, _Post_equal_to_(Buffer))
_At_(AnsiString->Length, _Post_equal_to_(0))
_At_(AnsiString->MaximumLength, _Post_equal_to_(BufferSize))
FORCEINLINE
VOID
RtlInitEmptyAnsiString(
    _Out_ PANSI_STRING AnsiString,
    _Pre_maybenull_ _Pre_readable_size_(BufferSize) __drv_aliasesMem PCHAR Buffer,
    _In_ USHORT BufferSize
    )
{
    memset(AnsiString, 0, sizeof(*AnsiString));
    AnsiString->MaximumLength = BufferSize;
    AnsiString->Buffer = Buffer;
}

#pragma prefast(push)
#pragma prefast(disable : 6101, "Out parameter is not written fully or at all.")

/**
 * The RtlSanitizeUnicodeStringPadding routine zeroes the structure padding of a UNICODE_STRING to avoid leaking
 * uninitialized memory.
 *
 * \param String A pointer to the UNICODE_STRING whose padding is cleared.
 */
FORCEINLINE
VOID
RtlSanitizeUnicodeStringPadding(
    _Out_ PUNICODE_STRING String
    )
{
#if defined(_WIN64)

    ULONG PaddingSize;
    ULONG PaddingStart;

    PaddingStart = FIELD_OFFSET(UNICODE_STRING, MaximumLength) +
                   sizeof(String->MaximumLength);

    PaddingSize = FIELD_OFFSET(UNICODE_STRING, Buffer) - PaddingStart;

    memset((PCH)String + PaddingStart, 0, PaddingSize);

#else

    UNREFERENCED_PARAMETER(String);

#endif

}

#pragma prefast(pop)

NTSYSAPI
VOID
NTAPI
RtlFreeAnsiString(
    _Inout_ _At_(AnsiString->Buffer, _Frees_ptr_opt_) PANSI_STRING AnsiString
);

#if (NTDDI_VERSION >= NTDDI_WIN10_MN)
/**
 * The RtlInitUTF8String routine initializes a counted UTF-8 string.
 *
 * \param DestinationString A pointer to the UTF8_STRING structure to initialize.
 * \param SourceString An optional pointer to a null-terminated string used to initialize the counted string.
 */
NTSYSAPI
VOID
NTAPI
RtlInitUTF8String(
    _Out_ PUTF8_STRING DestinationString,
    _In_opt_z_ PCSZ SourceString
);

/**
 * The RtlInitUTF8StringEx routine initializes a counted UTF-8 string and validates the length of the source string.
 *
 * \param DestinationString A pointer to the UTF8_STRING structure to initialize.
 * \param SourceString An optional pointer to a null-terminated string used to initialize the counted string.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlInitUTF8StringEx(
    _Out_ PUTF8_STRING DestinationString,
    _In_opt_z_ PCSZ SourceString
);

/**
 * The RtlFreeUTF8String routine releases storage that was allocated by RtlUnicodeStringToUTF8String.
 *
 * \param Utf8String A pointer to the UTF-8 string whose buffer is freed.
 */
NTSYSAPI
VOID
NTAPI
RtlFreeUTF8String(
    _Inout_ _At_(Utf8String->Buffer, _Frees_ptr_opt_) PUTF8_STRING Utf8String
);
#endif

NTSYSAPI
VOID
NTAPI
RtlFreeOemString(
    _Inout_ POEM_STRING OemString
);

/**
 * The RtlCopyString routine copies a source string to a destination string.
 *
 * \param DestinationString A pointer to the destination counted string.
 * \param SourceString An optional pointer to the source counted string. If `NULL`, the destination length is set to
 * zero.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlcopystring
 */
NTSYSAPI
VOID
NTAPI
RtlCopyString(
    _In_ PSTRING DestinationString,
    _In_opt_ PSTRING SourceString
);

/**
 * The RtlUpperChar routine converts the specified character to uppercase.
 *
 * \param Character The character to convert.
 * \return The uppercase equivalent of the specified character.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlupperchar
 */
NTSYSAPI
CHAR
NTAPI
RtlUpperChar(
    _In_ CHAR Character
);

/**
 * The RtlCompareString routine compares two counted strings.
 *
 * \param String1 A pointer to the first counted string.
 * \param String2 A pointer to the second counted string.
 * \param CaseInSensitive If `TRUE`, case is ignored when comparing the strings.
 * \return A signed value that is negative, zero, or positive if String1 is less than, equal to, or greater than
 * String2.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlcomparestring
 */
_Must_inspect_result_
NTSYSAPI
LONG
NTAPI
RtlCompareString(
    _In_ PSTRING String1,
    _In_ PSTRING String2,
    _In_ BOOLEAN CaseInSensitive
);

/**
 * The RtlEqualString routine compares two counted strings to determine whether they are equal.
 *
 * \param String1 A pointer to the first counted string.
 * \param String2 A pointer to the second counted string.
 * \param CaseInSensitive If `TRUE`, case is ignored when comparing the strings.
 * \return `TRUE` if the strings are equal, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlequalstring
 */
_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlEqualString(
    _In_ PSTRING String1,
    _In_ PSTRING String2,
    _In_ BOOLEAN CaseInSensitive
);

/**
 * The RtlPrefixString routine determines whether one counted string is a prefix of another.
 *
 * \param String1 A pointer to the counted string that is the potential prefix.
 * \param String2 A pointer to the counted string to search.
 * \param CaseInSensitive If `TRUE`, case is ignored when comparing the strings.
 * \return `TRUE` if String1 is a prefix of String2, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlprefixstring
 */
_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlPrefixString(
    _In_ PSTRING String1,
    _In_ PSTRING String2,
    _In_ BOOLEAN CaseInSensitive
);

/**
 * The RtlAppendStringToString routine concatenates two counted strings.
 *
 * \param Destination A pointer to the destination counted string.
 * \param Source A pointer to the source counted string to append.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlappendstringtostring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAppendStringToString(
    _Inout_ PSTRING Destination,
    _In_ PSTRING Source
);

/**
 * The RtlAppendAsciizToString routine concatenates a null-terminated string to a counted string.
 *
 * \param Destination A pointer to the destination counted string.
 * \param Source An optional pointer to the null-terminated source string to append.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlappendasciiztostring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAppendAsciizToString(
    _Inout_ PSTRING Destination,
    _In_opt_z_ PCSTR Source
);

/**
 * The RtlUpperString routine copies a source string to a destination string, converting each character to uppercase.
 *
 * \param DestinationString A pointer to the destination counted string.
 * \param SourceString A pointer to the source counted string.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlupperstring
 */
NTSYSAPI
VOID
NTAPI
RtlUpperString(
    _Inout_ PSTRING DestinationString,
    _In_ const STRING* SourceString
);

/**
 * The RtlIsNullOrEmptyUnicodeString routine determines whether a UNICODE_STRING pointer is NULL or refers to a
 * zero-length string.
 *
 * \param String An optional pointer to the UNICODE_STRING to test.
 * \return Returns `TRUE` if the string is NULL or empty, otherwise `FALSE`.
 */
FORCEINLINE
BOOLEAN
RtlIsNullOrEmptyUnicodeString(
    _In_opt_ PUNICODE_STRING String
)
{
    return !String || String->Length == 0;
}

NTSYSAPI
VOID
NTAPI
RtlInitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_z_ PCWSTR SourceString
);

/**
 * The RtlInitUnicodeStringEx routine initializes a counted Unicode string and validates the length of the source
 * string.
 *
 * \param DestinationString A pointer to the UNICODE_STRING structure to initialize.
 * \param SourceString An optional pointer to a null-terminated Unicode string used to initialize the counted string.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitunicodestringex
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlInitUnicodeStringEx(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_z_ PCWSTR SourceString
);

/**
 * The RtlCreateUnicodeString routine creates a new counted Unicode string.
 *
 * \param DestinationString Pointer to the newly allocated and initialized Unicode string.
 * \param SourceString Pointer to a null-terminated Unicode string with which to initialize the new string.
 * \return TRUE if the Unicode string was successfully created, FALSE otherwise.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateunicodestring
 */
_Success_(return != 0)
_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlCreateUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_z_ PCWSTR SourceString
);

/**
 * The RtlCreateUnicodeStringFromAsciiz routine allocates and initializes a counted Unicode string from a
 * null-terminated ANSI string.
 *
 * \param DestinationString A pointer to the UNICODE_STRING structure that receives the newly allocated string.
 * \param SourceString A pointer to the null-terminated ANSI source string.
 * \return `TRUE` if the Unicode string was successfully created, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateunicodestringfromasciiz
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlCreateUnicodeStringFromAsciiz(
    _Out_ PUNICODE_STRING DestinationString,
    _In_z_ PCSTR SourceString
);

/**
 * The RtlFreeUnicodeString routine releases storage that was allocated by RtlAnsiStringToUnicodeString or RtlUpcaseUnicodeString.
 *
 * \param UnicodeString A pointer to the string buffer.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfreeunicodestring
 */
NTSYSAPI
VOID
NTAPI
RtlFreeUnicodeString(
    _Inout_ _At_(UnicodeString->Buffer, _Frees_ptr_opt_) PUNICODE_STRING UnicodeString
);

/**
 * Flags for RtlDuplicateUnicodeString.
 */
#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE (0x00000001)
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING (0x00000002)

/**
 * The RtlDuplicateUnicodeString routine creates a copy of a counted Unicode string.
 *
 * \param Flags Flags that control how the string is duplicated.
 * \param StringIn A pointer to the source Unicode string.
 * \param StringOut A pointer to the UNICODE_STRING structure that receives the duplicated string.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlduplicateunicodestring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDuplicateUnicodeString(
    _In_ ULONG Flags,
    _In_ PUNICODE_STRING StringIn,
    _Out_ PUNICODE_STRING StringOut
);

/**
 * The RtlCopyUnicodeString routine copies a source string to a destination string.
 *
 * \param[in] DestinationString A pointer to the destination string buffer.
 * \param[in] SourceString A pointer to the source string buffer.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopyunicodestring
 */
NTSYSAPI
VOID
NTAPI
RtlCopyUnicodeString(
    _In_ PUNICODE_STRING DestinationString,
    _In_opt_ PCUNICODE_STRING SourceString
);

/**
 * The RtlUpcaseUnicodeChar routine converts the specified Unicode character to uppercase.
 *
 * \param[in] SourceCharacter Specifies the character to convert.
 * \return The uppercase version of the specified Unicode character.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlupcaseunicodechar
 */
NTSYSAPI
WCHAR
NTAPI
RtlUpcaseUnicodeChar(
    _In_ WCHAR SourceCharacter
);

/**
 * The RtlDowncaseUnicodeChar routine converts the specified Unicode character to lowercase.
 *
 * \param[in] SourceCharacter Specifies the character to convert.
 * \return The lowercase version of the specified Unicode character.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtldowncaseunicodechar
 */
NTSYSAPI
WCHAR
NTAPI
RtlDowncaseUnicodeChar(
    _In_ WCHAR SourceCharacter
);

/**
 * The RtlCompareUnicodeString routine compares two Unicode strings.
 *
 * \param[in] String1 Pointer to the first string.
 * \param[in] String2 Pointer to the second string.
 * \param[in] CaseInSensitive If TRUE, case should be ignored when doing the comparison.
 * \return A signed value that gives the results of the comparison.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcompareunicodestring
 */
_Must_inspect_result_
NTSYSAPI
LONG
NTAPI
RtlCompareUnicodeString(
    _In_ PUNICODE_STRING String1,
    _In_ PUNICODE_STRING String2,
    _In_ BOOLEAN CaseInSensitive
);

/**
 * The RtlCompareUnicodeStrings routine compares two Unicode strings.
 *
 * \param[in] String1 Pointer to the first string.
 * \param[in] String1Length The length, in bytes, of the first string.
 * \param[in] String2 Pointer to the second string.
 * \param[in] String2Length The length, in bytes, of the second string.
 * \param[in] CaseInSensitive If TRUE, case should be ignored when doing the comparison.
 * \return A signed value that gives the results of the comparison.
 */
_Must_inspect_result_
NTSYSAPI
LONG
NTAPI
RtlCompareUnicodeStrings(
    _In_reads_(String1Length) PCWCH String1,
    _In_ SIZE_T String1Length,
    _In_reads_(String2Length) PCWCH String2,
    _In_ SIZE_T String2Length,
    _In_ BOOLEAN CaseInSensitive
);

/**
 * The RtlEqualUnicodeString routine compares two Unicode strings to determine whether they are equal.
 *
 * \param[in] String1 Pointer to the first Unicode string.
 * \param[in] String2 Pointer to the second Unicode string.
 * \param[in] CaseInSensitive If TRUE, case should be ignored when doing the comparison.
 * \return TRUE if the two Unicode strings are equal; otherwise, it returns FALSE.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlequalunicodestring
 */
_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlEqualUnicodeString(
    _In_ PUNICODE_STRING String1,
    _In_ PUNICODE_STRING String2,
    _In_ BOOLEAN CaseInSensitive
);

/**
 * String hashing algorithm identifiers for RtlHashUnicodeString.
 */
#define HASH_STRING_ALGORITHM_DEFAULT 0
#define HASH_STRING_ALGORITHM_X65599 1
#define HASH_STRING_ALGORITHM_INVALID 0xffffffff

/**
 * The RtlHashUnicodeString routine creates a hash value from a given Unicode string and hash algorithm.
 *
 * \param[in] String A pointer to a UNICODE_STRING structure that contains the Unicode string to be converted to a hash value.
 * \param[in] CaseInSensitive Specifies whether to treat the Unicode string as case sensitive when computing the hash value. If CaseInSensitive is TRUE, a lowercase and uppercase string hash to the same value.
 * \param[in] HashAlgorithm The hash algorithm to use.
 * \param[out] HashValue A pointer to a ULONG variable that receives the hash value.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlhashunicodestring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlHashUnicodeString(
    _In_ PUNICODE_STRING String,
    _In_ BOOLEAN CaseInSensitive,
    _In_ ULONG HashAlgorithm,
    _Out_ PULONG HashValue
);

/**
 * The RtlValidateUnicodeString routine validates that a counted Unicode string is well formed.
 *
 * \param Flags Reserved. Must be zero.
 * \param String A pointer to the Unicode string to validate.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlValidateUnicodeString(
    _In_ ULONG Flags,
    _In_ PUNICODE_STRING String
);

/**
 * The RtlPrefixUnicodeString routine compares two Unicode strings to determine whether one string is a prefix of the other.
 *
 * \param[in] String1 Pointer to the first string, which might be a prefix of the buffered Unicode string at String2.
 * \param[in] String2 Pointer to the second string.
 * \param[in] CaseInSensitive TRUE, case should be ignored when doing the comparison.
 * \return TRUE if String1 is a prefix of String2.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlprefixunicodestring
 */
_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlPrefixUnicodeString(
    _In_ PUNICODE_STRING String1,
    _In_ PUNICODE_STRING String2,
    _In_ BOOLEAN CaseInSensitive
);

#if defined(_KERNEL_MODE) && NTDDI_VERSION >= NTDDI_WIN10
/**
 * The RtlSuffixUnicodeString routine determines whether one counted Unicode string is a suffix of another.
 *
 * \param String1 A pointer to the Unicode string that is the potential suffix.
 * \param String2 A pointer to the Unicode string to search.
 * \param CaseInSensitive If `TRUE`, case is ignored when comparing the strings.
 * \return `TRUE` if String1 is a suffix of String2, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsuffixunicodestring
 */
_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlSuffixUnicodeString(
    _In_ PUNICODE_STRING String1,
    _In_ PUNICODE_STRING String2,
    _In_ BOOLEAN CaseInSensitive
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10)
/**
 * The RtlFindUnicodeSubstring routine searches for the first occurrence of a substring within a counted Unicode string.
 *
 * \param FullString A pointer to the Unicode string to search.
 * \param SearchString A pointer to the Unicode substring to find.
 * \param CaseInSensitive If `TRUE`, case is ignored when comparing the strings.
 * \return A pointer to the first occurrence of the substring, or `NULL` if it was not found.
 */
_Must_inspect_result_
NTSYSAPI
PWCHAR
NTAPI
RtlFindUnicodeSubstring(
    _In_ PUNICODE_STRING FullString,
    _In_ PUNICODE_STRING SearchString,
    _In_ BOOLEAN CaseInSensitive
);
#endif

/**
 * Flags for RtlFindCharInUnicodeString.
 */
#define RTL_FIND_CHAR_IN_UNICODE_STRING_START_AT_END 0x00000001
#define RTL_FIND_CHAR_IN_UNICODE_STRING_COMPLEMENT_CHAR_SET 0x00000002
#define RTL_FIND_CHAR_IN_UNICODE_STRING_CASE_INSENSITIVE 0x00000004

/**
 * The RtlFindCharInUnicodeString routine searches for the first occurrence of any character from a character set within
 * a counted Unicode string.
 *
 * \param Flags Flags that control how the search is performed.
 * \param StringToSearch A pointer to the Unicode string to search.
 * \param CharSet A pointer to a Unicode string that contains the set of characters to find.
 * \param NonInclusivePrefixLength A pointer to a variable that receives the length, in bytes, of the prefix that
 * precedes the found character.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindcharinunicodestring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlFindCharInUnicodeString(
    _In_ ULONG Flags,
    _In_ PUNICODE_STRING StringToSearch,
    _In_ PUNICODE_STRING CharSet,
    _Out_ PUSHORT NonInclusivePrefixLength
);

/**
 * The RtlAppendUnicodeStringToString routine concatenates two counted Unicode strings.
 *
 * \param Destination A pointer to the destination Unicode string.
 * \param Source A pointer to the source Unicode string to append.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlappendunicodestringtostring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAppendUnicodeStringToString(
    _Inout_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
);

/**
 * The RtlAppendUnicodeToString routine concatenates a null-terminated Unicode string to a counted Unicode string.
 *
 * \param Destination A pointer to the destination Unicode string.
 * \param Source An optional pointer to the null-terminated Unicode source string to append.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlappendunicodetostring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAppendUnicodeToString(
    _Inout_ PUNICODE_STRING Destination,
    _In_opt_z_ PCWSTR Source
);

/**
 * The RtlUpcaseUnicodeString routine converts a counted Unicode string to uppercase.
 *
 * \param DestinationString A pointer to the destination Unicode string. If AllocateDestinationString is `TRUE`, the
 * buffer is allocated by the routine.
 * \param SourceString A pointer to the source Unicode string.
 * \param AllocateDestinationString If `TRUE`, the routine allocates the destination string buffer.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodestring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeString(
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) PUNICODE_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
);

/**
 * The RtlDowncaseUnicodeString routine converts a counted Unicode string to lowercase.
 *
 * \param DestinationString A pointer to the destination Unicode string. If AllocateDestinationString is `TRUE`, the
 * buffer is allocated by the routine.
 * \param SourceString A pointer to the source Unicode string.
 * \param AllocateDestinationString If `TRUE`, the routine allocates the destination string buffer.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldowncaseunicodestring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDowncaseUnicodeString(
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) PUNICODE_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
);

/**
 * The RtlEraseUnicodeString routine securely zeroes the buffer of a counted Unicode string.
 *
 * \param String A pointer to the Unicode string to erase.
 */
NTSYSAPI
VOID
NTAPI
RtlEraseUnicodeString(
    _Inout_ PUNICODE_STRING String
);

NTSYSAPI
NTSTATUS
NTAPI
RtlAnsiStringToUnicodeString(
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) PUNICODE_STRING DestinationString,
    _In_ PCANSI_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
);

/**
 * The RtlxAnsiStringToUnicodeSize routine computes the number of bytes required to hold the Unicode translation of a
 * counted ANSI string.
 *
 * \param AnsiString A pointer to the ANSI string.
 * \return The size, in bytes, required for the Unicode translation, including the terminating null character.
 */
NTSYSAPI
ULONG
NTAPI
RtlxAnsiStringToUnicodeSize(
    _In_ PCANSI_STRING AnsiString
);

NTSYSAPI
ULONG
NTAPI
RtlxUnicodeStringToAnsiSize(
    _In_ PCUNICODE_STRING UnicodeString
);

NTSYSAPI
ULONG
NTAPI
RtlxUnicodeStringToOemSize(
    _In_ PCUNICODE_STRING UnicodeString
);

NTSYSAPI
ULONG
NTAPI
RtlxOemStringToUnicodeSize(
    _In_ PCUNICODE_STRING UnicodeString
);

NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeStringToAnsiString(
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) PANSI_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
);

// rev
/**
 * The RtlUnicodeStringToAnsiSize routine computes the number of bytes required to hold the ANSI translation of a
 * counted Unicode string.
 *
 * \param SourceString A pointer to the Unicode string.
 * \return The size, in bytes, required for the ANSI translation, including the terminating null character.
 */
NTSYSAPI
ULONG
NTAPI
RtlUnicodeStringToAnsiSize(
    _In_ PUNICODE_STRING SourceString
);

#if (NTDDI_VERSION >= NTDDI_WIN10_MN)
/**
 * The RtlUnicodeStringToUTF8String routine converts a counted Unicode string to a counted UTF-8 string.
 *
 * \param DestinationString A pointer to the destination UTF-8 string. If AllocateDestinationString is `TRUE`, the
 * buffer is allocated by the routine.
 * \param SourceString A pointer to the source Unicode string.
 * \param AllocateDestinationString If `TRUE`, the routine allocates the destination string buffer.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeStringToUTF8String(
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) PUTF8_STRING DestinationString,
    _In_ PCUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
);

/**
 * The RtlUTF8StringToUnicodeString routine converts a counted UTF-8 string to a counted Unicode string.
 *
 * \param DestinationString A pointer to the destination Unicode string. If AllocateDestinationString is `TRUE`, the
 * buffer is allocated by the routine.
 * \param SourceString A pointer to the source UTF-8 string.
 * \param AllocateDestinationString If `TRUE`, the routine allocates the destination string buffer.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUTF8StringToUnicodeString(
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) PUNICODE_STRING DestinationString,
    _In_ PUTF8_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
);
#endif

/**
 * The RtlAnsiCharToUnicodeChar routine converts the next ANSI (multibyte) character to a Unicode character and advances
 * the source pointer.
 *
 * \param SourceCharacter A pointer to a variable that points to the ANSI character to convert. On return, the variable
 * is advanced past the converted character.
 * \return The Unicode equivalent of the source character.
 */
NTSYSAPI
WCHAR
NTAPI
RtlAnsiCharToUnicodeChar(
    _Inout_ PUCHAR * SourceCharacter
);

/**
 * The RtlUpcaseUnicodeStringToAnsiString routine converts a counted Unicode string to an uppercase counted ANSI string.
 *
 * \param DestinationString A pointer to the destination ANSI string. If AllocateDestinationString is `TRUE`, the buffer
 * is allocated by the routine.
 * \param SourceString A pointer to the source Unicode string.
 * \param AllocateDestinationString If `TRUE`, the routine allocates the destination string buffer.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodestringtoansistring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeStringToAnsiString(
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) PANSI_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
);

/**
 * The RtlOemStringToUnicodeString routine converts a counted OEM string to a counted Unicode string.
 *
 * \param DestinationString A pointer to the destination Unicode string. If AllocateDestinationString is `TRUE`, the
 * buffer is allocated by the routine.
 * \param SourceString A pointer to the source OEM string.
 * \param AllocateDestinationString If `TRUE`, the routine allocates the destination string buffer.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtloemstringtounicodestring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlOemStringToUnicodeString(
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) PUNICODE_STRING DestinationString,
    _In_ POEM_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
);

NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeStringToOemString(
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) POEM_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
);

/**
 * The RtlUpcaseUnicodeStringToOemString routine converts a counted Unicode string to an uppercase counted OEM string.
 *
 * \param DestinationString A pointer to the destination OEM string. If AllocateDestinationString is `TRUE`, the buffer
 * is allocated by the routine.
 * \param SourceString A pointer to the source Unicode string.
 * \param AllocateDestinationString If `TRUE`, the routine allocates the destination string buffer.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodestringtooemstring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeStringToOemString(
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) POEM_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
);

/**
 * The RtlOemStringToCountedUnicodeString routine converts a counted OEM string to a counted Unicode string that is not
 * null-terminated.
 *
 * \param DestinationString A pointer to the destination Unicode string. If AllocateDestinationString is `TRUE`, the
 * buffer is allocated by the routine.
 * \param SourceString A pointer to the source OEM string.
 * \param AllocateDestinationString If `TRUE`, the routine allocates the destination string buffer.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtloemstringtocountedunicodestring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlOemStringToCountedUnicodeString(
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) PUNICODE_STRING DestinationString,
    _In_ PCOEM_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
);

/**
 * The RtlUnicodeStringToCountedOemString routine converts a counted Unicode string to a counted OEM string that is not
 * null-terminated.
 *
 * \param DestinationString A pointer to the destination OEM string. If AllocateDestinationString is `TRUE`, the buffer
 * is allocated by the routine.
 * \param SourceString A pointer to the source Unicode string.
 * \param AllocateDestinationString If `TRUE`, the routine allocates the destination string buffer.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodestringtocountedoemstring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeStringToCountedOemString(
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) POEM_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
);

/**
 * The RtlUpcaseUnicodeStringToCountedOemString routine converts a counted Unicode string to an uppercase counted OEM
 * string that is not null-terminated.
 *
 * \param DestinationString A pointer to the destination OEM string. If AllocateDestinationString is `TRUE`, the buffer
 * is allocated by the routine.
 * \param SourceString A pointer to the source Unicode string.
 * \param AllocateDestinationString If `TRUE`, the routine allocates the destination string buffer.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodestringtocountedoemstring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeStringToCountedOemString(
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) POEM_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
);

/**
 * The RtlMultiByteToUnicodeN routine translates the specified source string into a Unicode string, using the current system ANSI code page (ACP).
 * The source string is not necessarily from a multibyte character set.
 *
 * \param UnicodeString Pointer to a caller-allocated buffer that receives the translated string. UnicodeString buffer must not overlap with MultiByteString buffer.
 * \param MaxBytesInUnicodeString Maximum number of bytes to be written at UnicodeString. If this value causes the translated string to be truncated, RtlMultiByteToUnicodeN does not return an error status.
 * \param BytesInUnicodeString Pointer to a caller-allocated variable that receives the length, in bytes, of the translated string. This parameter can be NULL.
 * \param MultiByteString Pointer to the string to be translated.
 * \param BytesInMultiByteString Size, in bytes, of the string at MultiByteString.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlmultibytetounicoden
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlMultiByteToUnicodeN(
    _Out_writes_bytes_to_(MaxBytesInUnicodeString, *BytesInUnicodeString) PWCH UnicodeString,
    _In_ ULONG MaxBytesInUnicodeString,
    _Out_opt_ PULONG BytesInUnicodeString,
    _In_reads_bytes_(BytesInMultiByteString) PCSTR MultiByteString,
    _In_ ULONG BytesInMultiByteString
);

/**
 * The RtlMultiByteToUnicodeSize routine determines the number of bytes that are required to store the Unicode translation for the specified source string.
 * The translation is assumed to use the current system ANSI code page (ACP). The source string is not necessarily from a multibyte character set.
 *
 * \param BytesInUnicodeString Pointer to a caller-allocated variable that receives the number of bytes that are required to store the translated string.
 * \param MultiByteString Pointer to the source string for which the Unicode length is to be calculated.
 * \param BytesInMultiByteString Length, in bytes, of the source string.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlmultibytetounicodesize
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlMultiByteToUnicodeSize(
    _Out_ PULONG BytesInUnicodeString,
    _In_reads_bytes_(BytesInMultiByteString) PCSTR MultiByteString,
    _In_ ULONG BytesInMultiByteString
);

/**
 * The RtlUnicodeToMultiByteN routine translates the specified Unicode string into a new character string, using the current system ANSI code page (ACP).
 * The source string is not necessarily from a multibyte character set.
 *
 * \param MultiByteString Pointer to a caller-allocated buffer to receive the translated string. MultiByteString buffer must not overlap with UnicodeString buffer.
 * \param MaxBytesInMultiByteString Maximum number of bytes to be written to MultiByteString. If this value causes the translated string to be truncated, RtlUnicodeToMultiByteN does not return an error status.
 * \param BytesInMultiByteString Pointer to a caller-allocated variable that receives the length, in bytes, of the translated string. This parameter is optional and can be NULL.
 * \param UnicodeString Pointer to the Unicode source string to be translated.
 * \param BytesInUnicodeString Size, in bytes, of the string at UnicodeString.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodetomultibyten
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToMultiByteN(
    _Out_writes_bytes_to_(MaxBytesInMultiByteString, *BytesInMultiByteString) PCHAR MultiByteString,
    _In_ ULONG MaxBytesInMultiByteString,
    _Out_opt_ PULONG BytesInMultiByteString,
    _In_reads_bytes_(BytesInUnicodeString) PCWCH UnicodeString,
    _In_ ULONG BytesInUnicodeString
);

/**
 * The RtlUnicodeToMultiByteSize routine determines the number of bytes that are required to store the multibyte translation for the specified Unicode string.
 * The translation is assumed to use the current system ANSI code page (ACP). The source string is not necessarily from a multibyte character set.
 *
 * \param BytesInMultiByteString Pointer to a caller-allocated variable that receives the number of bytes required to store the translated string.
 * \param UnicodeString Pointer to the Unicode string for which the multibyte length is to be calculated.
 * \param BytesInUnicodeString Length, in bytes, of the source string.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodetomultibytesize
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToMultiByteSize(
    _Out_ PULONG BytesInMultiByteString,
    _In_reads_bytes_(BytesInUnicodeString) PCWCH UnicodeString,
    _In_ ULONG BytesInUnicodeString
);

/**
 * The RtlUpcaseUnicodeToMultiByteN routine translates the specified Unicode string into a new uppercase character string, using the current system ANSI code page (ACP).
 * The translated string is not necessarily from a multibyte character set.
 *
 * \param MultiByteString Pointer to a caller-allocated buffer to receive the translated string.
 * \param MaxBytesInMultiByteString Maximum number of bytes to be written at MultiByteString. If this value causes the translated string to be truncated, RtlUpcaseUnicodeToMultiByteN does not return an error status.
 * \param BytesInMultiByteString Pointer to a caller-allocated variable that receives the length, in bytes, of the translated string. This parameter can be NULL.
 * \param UnicodeString Pointer to the Unicode source string to be translated.
 * \param BytesInUnicodeString Size, in bytes, of the string at UnicodeString.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodetomultibyten
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeToMultiByteN(
    _Out_writes_bytes_to_(MaxBytesInMultiByteString, *BytesInMultiByteString) PCHAR MultiByteString,
    _In_ ULONG MaxBytesInMultiByteString,
    _Out_opt_ PULONG BytesInMultiByteString,
    _In_reads_bytes_(BytesInUnicodeString) PCWCH UnicodeString,
    _In_ ULONG BytesInUnicodeString
);

/**
 * The RtlOemToUnicodeN routine converts an OEM string to a Unicode string.
 *
 * \param UnicodeString A pointer to a buffer that receives the translated Unicode string.
 * \param MaxBytesInUnicodeString The maximum number of bytes to write to UnicodeString.
 * \param BytesInUnicodeString An optional pointer to a variable that receives the number of bytes written to
 * UnicodeString.
 * \param OemString A pointer to the OEM source string.
 * \param BytesInOemString The number of bytes in the OEM source string.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtloemtounicoden
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlOemToUnicodeN(
    _Out_writes_bytes_to_(MaxBytesInUnicodeString, *BytesInUnicodeString) PWSTR UnicodeString,
    _In_ ULONG MaxBytesInUnicodeString,
    _Out_opt_ PULONG BytesInUnicodeString,
    _In_reads_bytes_(BytesInOemString) PCCH OemString,
    _In_ ULONG BytesInOemString
);

/**
 * The RtlUnicodeToOemN routine converts a Unicode string to an OEM string.
 *
 * \param OemString A pointer to a buffer that receives the translated OEM string.
 * \param MaxBytesInOemString The maximum number of bytes to write to OemString.
 * \param BytesInOemString An optional pointer to a variable that receives the number of bytes written to OemString.
 * \param UnicodeString A pointer to the Unicode source string.
 * \param BytesInUnicodeString The number of bytes in the Unicode source string.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodetooemn
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToOemN(
    _Out_writes_bytes_to_(MaxBytesInOemString, *BytesInOemString) PCHAR OemString,
    _In_ ULONG MaxBytesInOemString,
    _Out_opt_ PULONG BytesInOemString,
    _In_reads_bytes_(BytesInUnicodeString) PCWCH UnicodeString,
    _In_ ULONG BytesInUnicodeString
);

/**
 * The RtlUpcaseUnicodeToOemN routine converts a Unicode string to an uppercase OEM string.
 *
 * \param OemString A pointer to a buffer that receives the translated OEM string.
 * \param MaxBytesInOemString The maximum number of bytes to write to OemString.
 * \param BytesInOemString An optional pointer to a variable that receives the number of bytes written to OemString.
 * \param UnicodeString A pointer to the Unicode source string.
 * \param BytesInUnicodeString The number of bytes in the Unicode source string.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodetooemn
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeToOemN(
    _Out_writes_bytes_to_(MaxBytesInOemString, *BytesInOemString) PCHAR OemString,
    _In_ ULONG MaxBytesInOemString,
    _Out_opt_ PULONG BytesInOemString,
    _In_reads_bytes_(BytesInUnicodeString) PCWCH UnicodeString,
    _In_ ULONG BytesInUnicodeString
);

/**
 * The RtlConsoleMultiByteToUnicodeN routine converts a console multibyte string to a Unicode string, reporting whether
 * any special characters were encountered.
 *
 * \param UnicodeString A pointer to a buffer that receives the translated Unicode string.
 * \param MaxBytesInUnicodeString The maximum number of bytes to write to UnicodeString.
 * \param BytesInUnicodeString An optional pointer to a variable that receives the number of bytes written to
 * UnicodeString.
 * \param MultiByteString A pointer to the multibyte source string.
 * \param BytesInMultiByteString The number of bytes in the multibyte source string.
 * \param pdwSpecialChar A pointer to a variable that receives a value indicating whether a special character was
 * encountered.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlConsoleMultiByteToUnicodeN(
    _Out_writes_bytes_to_(MaxBytesInUnicodeString, *BytesInUnicodeString) PWCH UnicodeString,
    _In_ ULONG MaxBytesInUnicodeString,
    _Out_opt_ PULONG BytesInUnicodeString,
    _In_reads_bytes_(BytesInMultiByteString) PCCH MultiByteString,
    _In_ ULONG BytesInMultiByteString,
    _Out_ PULONG pdwSpecialChar
);

/**
 * The RtlUTF8ToUnicodeN routine translates the specified source string into a Unicode string, using the 8-bit Unicode Transformation Format (UTF-8) code page.
 *
 * \param UnicodeStringDestination Pointer to a caller-allocated buffer to receive the translated string.
 * \param UnicodeStringMaxByteCount Maximum number of bytes to be written at MultiByteString. If this value causes the translated string to be truncated, RtlUpcaseUnicodeToMultiByteN does not return an error status.
 * \param UnicodeStringActualByteCount Pointer to a caller-allocated variable that receives the length, in bytes, of the translated string. This parameter can be NULL.
 * \param UTF8StringSource Pointer to the Unicode source string to be translated.
 * \param UTF8StringByteCount Size, in bytes, of the string at UnicodeString.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlutf8tounicoden
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUTF8ToUnicodeN(
    _Out_writes_bytes_to_(UnicodeStringMaxByteCount, *UnicodeStringActualByteCount) PWSTR UnicodeStringDestination,
    _In_ ULONG UnicodeStringMaxByteCount,
    _Out_opt_ PULONG UnicodeStringActualByteCount,
    _In_reads_bytes_(UTF8StringByteCount) PCCH UTF8StringSource,
    _In_ ULONG UTF8StringByteCount
);

/**
 * The RtlUnicodeToUTF8N routine translates the specified Unicode string into a new character string, using the 8-bit Unicode Transformation Format (UTF-8) code page.
 *
 * \param UTF8StringDestination Pointer to a caller-allocated buffer to receive the translated string.
 * \param UTF8StringMaxByteCount Maximum number of bytes to be written to UTF8StringDestination. If this value causes the translated string to be truncated, RtlUnicodeToUTF8N returns an error status.
 * \param UTF8StringActualByteCount A pointer to a caller-allocated variable that receives the length, in bytes, of the translated string. This parameter is optional and can be NULL. If the string is truncated then the returned number counts the actual truncated string count.
 * \param UnicodeStringSource A pointer to the Unicode source string to be translated.
 * \param UnicodeStringByteCount Specifies the number of bytes in the Unicode source string that the UnicodeStringSource parameter points to.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlunicodetoutf8n
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToUTF8N(
    _Out_writes_bytes_to_(UTF8StringMaxByteCount, *UTF8StringActualByteCount) PCHAR UTF8StringDestination,
    _In_ ULONG UTF8StringMaxByteCount,
    _Out_opt_ PULONG UTF8StringActualByteCount,
    _In_reads_bytes_(UnicodeStringByteCount) PCWCH UnicodeStringSource,
    _In_ ULONG UnicodeStringByteCount
);

/**
 * The RtlCustomCPToUnicodeN routine converts a string in a custom code page to a Unicode string.
 *
 * \param CustomCP A pointer to the code page table that describes the custom code page.
 * \param UnicodeString A pointer to a buffer that receives the translated Unicode string.
 * \param MaxBytesInUnicodeString The maximum number of bytes to write to UnicodeString.
 * \param BytesInUnicodeString An optional pointer to a variable that receives the number of bytes written to
 * UnicodeString.
 * \param CustomCPString A pointer to the custom code page source string.
 * \param BytesInCustomCPString The number of bytes in the custom code page source string.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCustomCPToUnicodeN(
    _In_ PCPTABLEINFO CustomCP,
    _Out_writes_bytes_to_(MaxBytesInUnicodeString, *BytesInUnicodeString) PWCH UnicodeString,
    _In_ ULONG MaxBytesInUnicodeString,
    _Out_opt_ PULONG BytesInUnicodeString,
    _In_reads_bytes_(BytesInCustomCPString) PCH CustomCPString,
    _In_ ULONG BytesInCustomCPString
);

/**
 * The RtlUnicodeToCustomCPN routine converts a Unicode string to a string in a custom code page.
 *
 * \param CustomCP A pointer to the code page table that describes the custom code page.
 * \param CustomCPString A pointer to a buffer that receives the translated custom code page string.
 * \param MaxBytesInCustomCPString The maximum number of bytes to write to CustomCPString.
 * \param BytesInCustomCPString An optional pointer to a variable that receives the number of bytes written to
 * CustomCPString.
 * \param UnicodeString A pointer to the Unicode source string.
 * \param BytesInUnicodeString The number of bytes in the Unicode source string.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToCustomCPN(
    _In_ PCPTABLEINFO CustomCP,
    _Out_writes_bytes_to_(MaxBytesInCustomCPString, *BytesInCustomCPString) PCH CustomCPString,
    _In_ ULONG MaxBytesInCustomCPString,
    _Out_opt_ PULONG BytesInCustomCPString,
    _In_reads_bytes_(BytesInUnicodeString) PWCH UnicodeString,
    _In_ ULONG BytesInUnicodeString
);

/**
 * The RtlUpcaseUnicodeToCustomCPN routine converts a Unicode string to an uppercase string in a custom code page.
 *
 * \param CustomCP A pointer to the code page table that describes the custom code page.
 * \param CustomCPString A pointer to a buffer that receives the translated custom code page string.
 * \param MaxBytesInCustomCPString The maximum number of bytes to write to CustomCPString.
 * \param BytesInCustomCPString An optional pointer to a variable that receives the number of bytes written to
 * CustomCPString.
 * \param UnicodeString A pointer to the Unicode source string.
 * \param BytesInUnicodeString The number of bytes in the Unicode source string.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeToCustomCPN(
    _In_ PCPTABLEINFO CustomCP,
    _Out_writes_bytes_to_(MaxBytesInCustomCPString, *BytesInCustomCPString) PCH CustomCPString,
    _In_ ULONG MaxBytesInCustomCPString,
    _Out_opt_ PULONG BytesInCustomCPString,
    _In_reads_bytes_(BytesInUnicodeString) PWCH UnicodeString,
    _In_ ULONG BytesInUnicodeString
);

/**
 * The RtlInitCodePageTable routine initializes a code page table structure from a raw code page table image.
 *
 * \param TableBase A pointer to the raw code page table data.
 * \param CodePageTable A pointer to the CPTABLEINFO structure that receives the initialized code page table.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitcodepagetable
 */
NTSYSAPI
VOID
NTAPI
RtlInitCodePageTable(
    _In_reads_opt_(2) PUSHORT TableBase,
    _Inout_ PCPTABLEINFO CodePageTable
);

/**
 * The RtlInitNlsTables routine initializes an NLS (National Language Support) table information structure from the
 * specified ANSI, OEM, and language code page tables.
 *
 * \param AnsiNlsBase A pointer to the ANSI code page NLS data.
 * \param OemNlsBase A pointer to the OEM code page NLS data.
 * \param LanguageNlsBase A pointer to the language (case-mapping) NLS data.
 * \param TableInfo A pointer to the NLSTABLEINFO structure that receives the initialized table information.
 */
NTSYSAPI
VOID
NTAPI
RtlInitNlsTables(
    _In_ PUSHORT AnsiNlsBase,
    _In_ PUSHORT OemNlsBase,
    _In_ PUSHORT LanguageNlsBase,
    _Out_ PNLSTABLEINFO TableInfo // PCPTABLEINFO?
);

/**
 * The RtlResetRtlTranslations routine resets the code page translation tables used by the run-time library to those
 * described by the specified NLS table information.
 *
 * \param TableInfo A pointer to the NLSTABLEINFO structure that describes the translation tables.
 */
NTSYSAPI
VOID
NTAPI
RtlResetRtlTranslations(
    _In_ PNLSTABLEINFO TableInfo
);

/**
 * The RtlIsTextUnicode routine applies heuristics to determine whether a buffer likely contains Unicode (UTF-16) text.
 *
 * \param Buffer The buffer to examine.
 * \param Size The size, in bytes, of the buffer.
 * \param Result On input specifies which tests to apply (or NULL for all); on output receives the tests that passed.
 * \return TRUE if the buffer is likely Unicode text; otherwise, FALSE.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsTextUnicode(
    _In_ PVOID Buffer,
    _In_ ULONG Size,
    _Inout_opt_ PULONG Result
);

/**
 * Identifies the Unicode normalization form applied by string normalization routines.
 */
typedef enum _RTL_NORM_FORM
{
    NormOther = 0x0,
    NormC = 0x1,
    NormD = 0x2,
    NormKC = 0x5,
    NormKD = 0x6,
    NormIdna = 0xd,
    DisallowUnassigned = 0x100,
    NormCDisallowUnassigned = 0x101,
    NormDDisallowUnassigned = 0x102,
    NormKCDisallowUnassigned = 0x105,
    NormKDDisallowUnassigned = 0x106,
    NormIdnaDisallowUnassigned = 0x10d
} RTL_NORM_FORM;

/**
 * The RtlNormalizeString routine normalizes a Unicode string according to the specified Unicode normalization form.
 *
 * \param NormForm The normalization form to apply (RTL_NORM_FORM).
 * \param SourceString A pointer to the source Unicode string.
 * \param SourceStringLength The length, in characters, of the source string, or -1 if the string is null-terminated.
 * \param DestinationString A buffer that receives the normalized string.
 * \param DestinationStringLength On input, the size of the destination buffer in characters; on output, the number of
 * characters written or required.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlnormalizestring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlNormalizeString(
    _In_ ULONG NormForm, // RTL_NORM_FORM
    _In_ PCWSTR SourceString,
    _In_ LONG SourceStringLength,
    _Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
    _Inout_ PLONG DestinationStringLength
);

/**
 * The RtlIsNormalizedString routine determines whether a Unicode string is already in the specified normalization form.
 *
 * \param NormForm The normalization form to test against (RTL_NORM_FORM).
 * \param SourceString A pointer to the source Unicode string.
 * \param SourceStringLength The length, in characters, of the source string, or -1 if the string is null-terminated.
 * \param Normalized A pointer to a variable that receives `TRUE` if the string is normalized, otherwise `FALSE`.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlisnormalizedstring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIsNormalizedString(
    _In_ ULONG NormForm, // RTL_NORM_FORM
    _In_ PCWSTR SourceString,
    _In_ LONG SourceStringLength,
    _Out_ PBOOLEAN Normalized
);

// ntifs:FsRtlIsNameInExpression
/**
 * The RtlIsNameInExpression routine determines whether a Unicode string matches the specified pattern.
 *
 * \param Expression A pointer to the pattern string. This string can contain wildcard characters. If the IgnoreCase parameter is TRUE, the string must contain only uppercase characters.
 * \param Name Maximum number of bytes to be written to UTF8StringDestination. If this value causes the translated string to be truncated, RtlUnicodeToUTF8N returns an error status.
 * \param IgnoreCase TRUE for case-insensitive matching, or FALSE for case-sensitive matching.
 * \param UpcaseTable An optional pointer to an uppercase character table to use for case-insensitive matching. If this parameter is NULL, the default system uppercase character table is used.
 * \return TRUE if the string matches the pattern. If the string does not match the pattern, this function returns FALSE.
 * \sa https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlisnameinexpression
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsNameInExpression(
    _In_ PUNICODE_STRING Expression,
    _In_ PUNICODE_STRING Name,
    _In_ BOOLEAN IgnoreCase,
    _In_opt_ PWCH UpcaseTable
);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS4)
// rev
/**
 * The RtlIsNameInUnUpcasedExpression routine determines whether a name matches a wildcard expression, using a
 * caller-supplied upcase table rather than upcasing the expression.
 *
 * \param Expression A pointer to the wildcard expression, which must already be uppercase when IgnoreCase is `TRUE`.
 * \param Name A pointer to the name to test against the expression.
 * \param IgnoreCase If `TRUE`, the comparison is case-insensitive.
 * \param UpcaseTable An optional pointer to an upcase translation table used to upcase the name.
 * \return `TRUE` if the name matches the expression, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsNameInUnUpcasedExpression(
    _In_ PUNICODE_STRING Expression,
    _In_ PUNICODE_STRING Name,
    _In_ BOOLEAN IgnoreCase,
    _In_opt_ PWCH UpcaseTable
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_19H1)
/**
 * The RtlDoesNameContainWildCards routine determines whether a Unicode string contains wildcard characters.
 *
 * \param Name A pointer to the string to be checked.
 * \return TRUE if one or more wildcard characters were found, FALSE otherwise.
 * \remarks The following are wildcard characters: *, ?, ANSI_DOS_STAR, ANSI_DOS_DOT, and ANSI_DOS_QM.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-_fsrtl_advanced_fcb_header-fsrtldoesnamecontainwildcards
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlDoesNameContainWildCards(
    _In_ PUNICODE_STRING Expression
);
#endif

/**
 * The RtlEqualDomainName routine compares two domain names for equality.
 *
 * \param String1 A pointer to the first domain name.
 * \param String2 A pointer to the second domain name.
 * \return `TRUE` if the domain names are equal, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlequaldomainname
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlEqualDomainName(
    _In_ PUNICODE_STRING String1,
    _In_ PUNICODE_STRING String2
);

/**
 * The RtlEqualComputerName routine compares two computer names for equality.
 *
 * \param String1 A pointer to the first computer name.
 * \param String2 A pointer to the second computer name.
 * \return `TRUE` if the computer names are equal, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlequalcomputername
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlEqualComputerName(
    _In_ PUNICODE_STRING String1,
    _In_ PUNICODE_STRING String2
);

/**
 * The RtlDnsHostNameToComputerName routine converts a DNS host name to a NetBIOS computer name.
 *
 * \param ComputerNameString A pointer to the string that receives the computer name.
 * \param DnsHostNameString A pointer to the DNS host name to convert.
 * \param AllocateComputerNameString If `TRUE`, the routine allocates the computer name string buffer.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDnsHostNameToComputerName(
    _Out_ PUNICODE_STRING ComputerNameString,
    _In_ PUNICODE_STRING DnsHostNameString,
    _In_ BOOLEAN AllocateComputerNameString
);

/**
 * The RtlCompareAltitudes routine compares two filter driver altitude strings.
 *
 * \param Altitude1 A pointer to the first altitude string.
 * \param Altitude2 A pointer to the second altitude string.
 * \return A signed value that is negative, zero, or positive if Altitude1 is less than, equal to, or greater than
 * Altitude2.
 */
NTSYSAPI
LONG
NTAPI
RtlCompareAltitudes(
    _In_ PUNICODE_STRING Altitude1,
    _In_ PUNICODE_STRING Altitude2
);

/**
 * The RtlIdnToAscii routine converts an internationalized domain name (IDN) to its ASCII (Punycode) representation.
 *
 * \param Flags Flags that control the conversion.
 * \param SourceString A pointer to the source Unicode string.
 * \param SourceStringLength The length, in characters, of the source string, or -1 if the string is null-terminated.
 * \param DestinationString A buffer that receives the converted string.
 * \param DestinationStringLength On input, the size of the destination buffer in characters; on output, the number of
 * characters written or required.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlidntoascii
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIdnToAscii(
    _In_ ULONG Flags,
    _In_ PCWSTR SourceString,
    _In_ LONG SourceStringLength,
    _Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
    _Inout_ PLONG DestinationStringLength
);

/**
 * The RtlIdnToUnicode routine converts an ASCII (Punycode) internationalized domain name to its Unicode representation.
 *
 * \param Flags Flags that control the conversion.
 * \param SourceString A pointer to the source string.
 * \param SourceStringLength The length, in characters, of the source string, or -1 if the string is null-terminated.
 * \param DestinationString A buffer that receives the converted string.
 * \param DestinationStringLength On input, the size of the destination buffer in characters; on output, the number of
 * characters written or required.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlidntounicode
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIdnToUnicode(
    _In_ ULONG Flags,
    _In_ PCWSTR SourceString,
    _In_ LONG SourceStringLength,
    _Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
    _Inout_ PLONG DestinationStringLength
);

/**
 * The RtlIdnToNameprepUnicode routine applies the nameprep algorithm to an internationalized domain name and returns
 * the result in Unicode.
 *
 * \param Flags Flags that control the conversion.
 * \param SourceString A pointer to the source Unicode string.
 * \param SourceStringLength The length, in characters, of the source string, or -1 if the string is null-terminated.
 * \param DestinationString A buffer that receives the converted string.
 * \param DestinationStringLength On input, the size of the destination buffer in characters; on output, the number of
 * characters written or required.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlidntonameprepunicode
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIdnToNameprepUnicode(
    _In_ ULONG Flags,
    _In_ PCWSTR SourceString,
    _In_ LONG SourceStringLength,
    _Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
    _Inout_ PLONG DestinationStringLength
);

/**
 * The RtlIntegerToChar routine converts an unsigned integer to its character-string representation in the specified
 * base.
 *
 * \param Value The unsigned integer to convert.
 * \param Base The numeric base for the conversion, or zero for base 10.
 * \param OutputLength The size, in characters, of the output buffer. A negative value pads the result to the given
 * width.
 * \param String A buffer that receives the converted character string.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIntegerToChar(
    _In_ ULONG Value,
    _In_opt_ ULONG Base,
    _In_ LONG OutputLength, // negative to pad to width
    _Out_ PSTR String
);

NTSYSAPI
NTSTATUS
NTAPI
RtlCharToInteger(
    _In_z_ PCSTR String,
    _In_opt_ ULONG Base,
    _Out_ PULONG Value
);

/**
 * The RtlLargeIntegerToChar routine converts a large integer to its character-string representation in the specified
 * base.
 *
 * \param Value A pointer to the large integer to convert.
 * \param Base The numeric base for the conversion, or zero for base 10.
 * \param OutputLength The size, in characters, of the output buffer. A negative value pads the result to the given
 * width.
 * \param String A buffer that receives the converted character string.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlLargeIntegerToChar(
    _In_ PLARGE_INTEGER Value,
    _In_opt_ ULONG Base,
    _In_ LONG OutputLength,
    _Out_ PSTR String
);

/**
 * The RtlIntegerToUnicodeString routine converts an unsigned integer to its Unicode-string representation in the
 * specified base.
 *
 * \param Value The unsigned integer to convert.
 * \param Base The numeric base for the conversion, or zero for base 10.
 * \param String A pointer to a UNICODE_STRING that receives the converted string.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlintegertounicodestring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIntegerToUnicodeString(
    _In_ ULONG Value,
    _In_opt_ ULONG Base,
    _Inout_ PUNICODE_STRING String
);

/**
 * The RtlInt64ToUnicodeString routine converts an unsigned 64-bit integer to its Unicode-string representation in the
 * specified base.
 *
 * \param Value The unsigned 64-bit integer to convert.
 * \param Base The numeric base for the conversion, or zero for base 10.
 * \param String A pointer to a UNICODE_STRING that receives the converted string.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlint64tounicodestring
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlInt64ToUnicodeString(
    _In_ ULONGLONG Value,
    _In_opt_ ULONG Base,
    _Inout_ PUNICODE_STRING String
);

#ifdef _WIN64
/**
 * Maps RtlIntPtrToUnicodeString to the appropriate 32- or 64-bit conversion routine.
 */
#define RtlIntPtrToUnicodeString(Value, Base, String) RtlInt64ToUnicodeString(Value, Base, String)
#else
#define RtlIntPtrToUnicodeString(Value, Base, String) RtlIntegerToUnicodeString(Value, Base, String)
#endif

NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeStringToInteger(
    _In_ PUNICODE_STRING String,
    _In_opt_ ULONG Base,
    _Out_ PULONG Value
);

// IPv4/6 conversion

typedef struct in_addr IN_ADDR, *PIN_ADDR;
typedef struct in6_addr IN6_ADDR, *PIN6_ADDR;
typedef IN_ADDR const *PCIN_ADDR;
typedef IN6_ADDR const *PCIN6_ADDR;

/**
 * Converts an IPv4 address to a null-terminated ANSI string in standard
 * dotted-decimal notation.
 *
 * \param Address The IPv4 address in network byte order.
 * \param AddressString A caller-supplied buffer that receives the string form.
 * The buffer should be able to hold at least 16 characters.
 * \return A pointer to the terminating null character written to AddressString.
 * \remarks This is a convenience routine that does not require Winsock to be loaded.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4addresstostringa
 */
NTSYSAPI
PSTR
NTAPI
RtlIpv4AddressToStringA(
    _In_ PCIN_ADDR Address,
    _Out_writes_(16) PSTR AddressString
);

/**
 * Converts an IPv4 address to a null-terminated Unicode string in standard dotted-decimal notation.
 *
 * \param Address The IPv4 address in network byte order.
 * \param AddressString A caller-supplied buffer that receives the string form.
 * The buffer should be able to hold at least 16 wide characters.
 * \return A pointer to the terminating null character written to AddressString.
 * \remarks This is a convenience routine that does not require Winsock to be loaded.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4addresstostringw
 */
NTSYSAPI
PWSTR
NTAPI
RtlIpv4AddressToStringW(
    _In_ PCIN_ADDR Address,
    _Out_writes_(16) PWSTR AddressString
);

/**
 * Converts an IPv4 address and port to a null-terminated ANSI string.
 *
 * \param Address The IPv4 address in network byte order.
 * \param Port The port number in network byte order.
 * \param AddressString A caller-supplied output buffer.
 * \param AddressStringLength On input, the size of AddressString. On output,
 * receives the required size if the buffer is too small.
 * \return STATUS_SUCCESS on success, or an error status such as
 * STATUS_INVALID_PARAMETER if the buffer is too small.
 * \remarks The resulting string uses dotted-decimal notation followed by a
 * colon and port number.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4addresstostringexa
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIpv4AddressToStringExA(
    _In_ PCIN_ADDR Address,
    _In_ USHORT Port,
    _Out_writes_to_(*AddressStringLength, *AddressStringLength) PSTR AddressString,
    _Inout_ PULONG AddressStringLength
);

NTSYSAPI
NTSTATUS
NTAPI
RtlIpv4AddressToStringExW(
    _In_ PCIN_ADDR Address,
    _In_ USHORT Port,
    _Out_writes_to_(*AddressStringLength, *AddressStringLength) PWSTR AddressString,
    _Inout_ PULONG AddressStringLength
);

/**
 * Converts an IPv6 address to a null-terminated ANSI string in standard IPv6 text format.
 *
 * \param Address The IPv6 address in network byte order.
 * \param AddressString A caller-supplied buffer that receives the string form.
 * The buffer should be able to hold at least 46 characters.
 * \return A pointer to the terminating null character written to AddressString.
 * \remarks This is a convenience routine that does not require Winsock to be loaded.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv6addresstostringa
 */
NTSYSAPI
PSTR
NTAPI
RtlIpv6AddressToStringA(
    _In_ PCIN6_ADDR Address,
    _Out_writes_(46) PSTR AddressString
);

/**
 * Converts an IPv6 address to a null-terminated Unicode string in standard IPv6 text format.
 *
 * \param Address The IPv6 address in network byte order.
 * \param AddressString A caller-supplied buffer that receives the string form.
 * The buffer should be able to hold at least 46 wide characters.
 * \return A pointer to the terminating null character written to AddressString.
 * \remarks This is a convenience routine that does not require Winsock to be loaded.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv6addresstostringw
 */
NTSYSAPI
PWSTR
NTAPI
RtlIpv6AddressToStringW(
    _In_ PCIN6_ADDR Address,
    _Out_writes_(46) PWSTR AddressString
);

/**
 * Converts an IPv6 address, scope ID, and port to a null-terminated ANSI string.
 *
 * \param Address The IPv6 address in network byte order.
 * \param ScopeId The IPv6 scope identifier.
 * \param Port The port number in network byte order.
 * \param AddressString A caller-supplied output buffer.
 * \param AddressStringLength On input, the size of AddressString. On output,
 * receives the required size if the buffer is too small.
 * \return STATUS_SUCCESS on success or an error status on failure.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv6addresstostringexa
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIpv6AddressToStringExA(
    _In_ PCIN6_ADDR Address,
    _In_ ULONG ScopeId,
    _In_ USHORT Port,
    _Out_writes_to_(*AddressStringLength, *AddressStringLength) PSTR AddressString,
    _Inout_ PULONG AddressStringLength
    );

/**
 * Converts an IPv4 address and port to a null-terminated Unicode string.
 *
 * \param Address The IPv4 address in network byte order.
 * \param Port The port number in network byte order.
 * \param AddressString A caller-supplied output buffer.
 * \param AddressStringLength On input, the size of AddressString. On output,
 * receives the required size if the buffer is too small.
 * \return STATUS_SUCCESS on success, or an error status such as
 * STATUS_INVALID_PARAMETER if the buffer is too small.
 * \remarks The resulting string uses dotted-decimal notation followed by a
 * colon and port number.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4addresstostringexw
 */
/**
 * Converts an IPv6 address, scope ID, and port to a null-terminated Unicode string.
 *
 * \param Address The IPv6 address in network byte order.
 * \param ScopeId The IPv6 scope identifier.
 * \param Port The port number in network byte order.
 * \param AddressString A caller-supplied output buffer.
 * \param AddressStringLength On input, the size of AddressString. On output,
 * receives the required size if the buffer is too small.
 * \return STATUS_SUCCESS on success or an error status on failure.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv6addresstostringexw
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIpv6AddressToStringExW(
    _In_ PCIN6_ADDR Address,
    _In_ ULONG ScopeId,
    _In_ USHORT Port,
    _Out_writes_to_(*AddressStringLength, *AddressStringLength) PWSTR AddressString,
    _Inout_ PULONG AddressStringLength
);

/**
 * Parses an ANSI IPv4 address string into a binary IPv4 address.
 *
 * \param AddressString The null-terminated IPv4 address string to parse.
 * \param Strict If TRUE, requires strict four-part dotted-decimal notation.
 * If FALSE, additional legacy forms are accepted.
 * \param Terminator On success, receives a pointer to the character that
 * terminated the parsed address.
 * \param Address Receives the parsed IPv4 address in network byte order.
 * \return STATUS_SUCCESS on success or STATUS_INVALID_PARAMETER if parsing fails.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4stringtoaddressa
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIpv4StringToAddressA(
    _In_ PCSTR AddressString,
    _In_ BOOLEAN Strict,
    _Out_ PCSTR* Terminator,
    _Out_ PIN_ADDR Address
);

/**
 * Parses a Unicode IPv4 address string into a binary IPv4 address.
 *
 * \param AddressString The null-terminated IPv4 address string to parse.
 * \param Strict If TRUE, requires strict four-part dotted-decimal notation.
 * If FALSE, additional legacy forms are accepted.
 * \param Terminator On success, receives a pointer to the character that
 * terminated the parsed address.
 * \param Address Receives the parsed IPv4 address in network byte order.
 * \return STATUS_SUCCESS on success or STATUS_INVALID_PARAMETER if parsing fails.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4stringtoaddressw
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIpv4StringToAddressW(
    _In_ PCWSTR AddressString,
    _In_ BOOLEAN Strict,
    _Out_ LPCWSTR* Terminator,
    _Out_ PIN_ADDR Address
);

/**
 * Parses an ANSI IPv4 address string and optional port into binary values.
 *
 * \param AddressString The null-terminated IPv4 address string, optionally
 * followed by a colon and port number.
 * \param Strict If TRUE, requires strict four-part dotted-decimal notation.
 * If FALSE, additional legacy forms are accepted.
 * \param Address Receives the parsed IPv4 address in network byte order.
 * \param Port Receives the parsed port in network byte order, or zero if not present.
 * \return STATUS_SUCCESS on success or STATUS_INVALID_PARAMETER on failure.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4stringtoaddressexa
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIpv4StringToAddressExA(
    _In_ PCSTR AddressString,
    _In_ BOOLEAN Strict,
    _Out_ PIN_ADDR Address,
    _Out_ PUSHORT Port
);

/**
 * Parses a Unicode IPv4 address string and optional port into binary values.
 *
 * \param AddressString The null-terminated IPv4 address string, optionally
 * followed by a colon and port number.
 * \param Strict If TRUE, requires strict four-part dotted-decimal notation.
 * If FALSE, additional legacy forms are accepted.
 * \param Address Receives the parsed IPv4 address in network byte order.
 * \param Port Receives the parsed port in network byte order, or zero if not present.
 * \return STATUS_SUCCESS on success or STATUS_INVALID_PARAMETER on failure.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4stringtoaddressexw
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIpv4StringToAddressExW(
    _In_ PCWSTR AddressString,
    _In_ BOOLEAN Strict,
    _Out_ PIN_ADDR Address,
    _Out_ PUSHORT Port
);

/**
 * Parses an ANSI IPv6 address string into a binary IPv6 address.
 *
 * \param AddressString The null-terminated IPv6 address string to parse.
 * \param Terminator On success, receives a pointer to the character that
 * terminated the parsed address.
 * \param Address Receives the parsed IPv6 address in network byte order.
 * \return STATUS_SUCCESS on success or STATUS_INVALID_PARAMETER on failure.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv6stringtoaddressa
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIpv6StringToAddressA(
    _In_ PCSTR AddressString,
    _Out_ PCSTR* Terminator,
    _Out_ PIN6_ADDR Address
);

/**
 * Parses a Unicode IPv6 address string into a binary IPv6 address.
 *
 * \param AddressString The null-terminated IPv6 address string to parse.
 * \param Terminator On success, receives a pointer to the character that
 * terminated the parsed address.
 * \param Address Receives the parsed IPv6 address in network byte order.
 * \return STATUS_SUCCESS on success or STATUS_INVALID_PARAMETER on failure.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv6stringtoaddressw
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIpv6StringToAddressW(
    _In_ PCWSTR AddressString,
    _Out_ PCWSTR* Terminator,
    _Out_ PIN6_ADDR Address
);

/**
 * Parses an ANSI IPv6 address string with optional scope ID and port.
 *
 * \param AddressString The null-terminated IPv6 address string to parse.
 * \param Address Receives the parsed IPv6 address in network byte order.
 * \param ScopeId Receives the parsed scope identifier.
 * \param Port Receives the parsed port in network byte order.
 * \return STATUS_SUCCESS on success or STATUS_INVALID_PARAMETER on failure.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv6stringtoaddressexa
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIpv6StringToAddressExA(
    _In_ PCSTR AddressString,
    _Out_ PIN6_ADDR Address,
    _Out_ PULONG ScopeId,
    _Out_ PUSHORT Port
);

/**
 * Parses a Unicode IPv6 address string with optional scope ID and port.
 *
 * \param AddressString The null-terminated IPv6 address string to parse.
 * \param Address Receives the parsed IPv6 address in network byte order.
 * \param ScopeId Receives the parsed scope identifier.
 * \param Port Receives the parsed port in network byte order.
 * \return STATUS_SUCCESS on success or STATUS_INVALID_PARAMETER on failure.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv6stringtoaddressexw
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIpv6StringToAddressExW(
    _In_ PCWSTR AddressString,
    _Out_ PIN6_ADDR Address,
    _Out_ PULONG ScopeId,
    _Out_ PUSHORT Port
);

#define RtlIpv4AddressToString RtlIpv4AddressToStringW
#define RtlIpv4AddressToStringEx RtlIpv4AddressToStringExW
#define RtlIpv6AddressToString RtlIpv6AddressToStringW
#define RtlIpv6AddressToStringEx RtlIpv6AddressToStringExW
#define RtlIpv4StringToAddress RtlIpv4StringToAddressW
#define RtlIpv4StringToAddressEx RtlIpv4StringToAddressExW
#define RtlIpv6StringToAddress RtlIpv6StringToAddressW
#define RtlIpv6StringToAddressEx RtlIpv6StringToAddressExW

#pragma region Prefix

/**
 * Represents an entry in an ANSI prefix table.
 */
typedef struct _PREFIX_TABLE_ENTRY
{
    CSHORT NodeTypeCode;
    CSHORT NameLength;
    struct _PREFIX_TABLE_ENTRY *NextPrefixTree;
    RTL_SPLAY_LINKS Links;
    PSTRING Prefix;
} PREFIX_TABLE_ENTRY, *PPREFIX_TABLE_ENTRY;

/**
 * Represents an ANSI prefix table used for longest-prefix name lookups.
 */
typedef struct _PREFIX_TABLE
{
    CSHORT NodeTypeCode;
    CSHORT NameLength;
    PPREFIX_TABLE_ENTRY NextPrefixTree;
} PREFIX_TABLE, *PPREFIX_TABLE;

/**
 * The PfxInitialize routine initializes a prefix table used to hold ANSI string prefixes.
 *
 * \param PrefixTable A pointer to the prefix table to initialize.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-pfxinitialize
 */
NTSYSAPI
VOID
NTAPI
PfxInitialize(
    _Out_ PPREFIX_TABLE PrefixTable
);

/**
 * The PfxInsertPrefix routine inserts a prefix into a prefix table.
 *
 * \param PrefixTable A pointer to the prefix table.
 * \param Prefix A pointer to the counted string that is the prefix to insert.
 * \param PrefixTableEntry A pointer to the prefix table entry that describes the inserted prefix.
 * \return `TRUE` if the prefix was inserted, otherwise `FALSE` if a matching prefix already exists.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-pfxinsertprefix
 */
NTSYSAPI
BOOLEAN
NTAPI
PfxInsertPrefix(
    _In_ PPREFIX_TABLE PrefixTable,
    _In_ PSTRING Prefix,
    _Out_ PPREFIX_TABLE_ENTRY PrefixTableEntry
);

/**
 * The PfxRemovePrefix routine removes a prefix from a prefix table.
 *
 * \param PrefixTable A pointer to the prefix table.
 * \param PrefixTableEntry A pointer to the prefix table entry to remove.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-pfxremoveprefix
 */
NTSYSAPI
VOID
NTAPI
PfxRemovePrefix(
    _In_ PPREFIX_TABLE PrefixTable,
    _In_ PPREFIX_TABLE_ENTRY PrefixTableEntry
);

/**
 * The PfxFindPrefix routine searches a prefix table for the longest prefix of the specified name.
 *
 * \param PrefixTable A pointer to the prefix table.
 * \param FullName A pointer to the counted string to search for a prefix.
 * \return A pointer to the matching prefix table entry, or `NULL` if no prefix was found.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-pfxfindprefix
 */
NTSYSAPI
PPREFIX_TABLE_ENTRY
NTAPI
PfxFindPrefix(
    _In_ PPREFIX_TABLE PrefixTable,
    _In_ PSTRING FullName
);

/**
 * Represents an entry in a Unicode prefix table.
 */
typedef struct _UNICODE_PREFIX_TABLE_ENTRY
{
    CSHORT NodeTypeCode;
    CSHORT NameLength;
    struct _UNICODE_PREFIX_TABLE_ENTRY *NextPrefixTree;
    struct _UNICODE_PREFIX_TABLE_ENTRY *CaseMatch;
    RTL_SPLAY_LINKS Links;
    PUNICODE_STRING Prefix;
} UNICODE_PREFIX_TABLE_ENTRY, *PUNICODE_PREFIX_TABLE_ENTRY;

/**
 * Represents a Unicode prefix table used for longest-prefix name lookups.
 */
typedef struct _UNICODE_PREFIX_TABLE
{
    CSHORT NodeTypeCode;
    CSHORT NameLength;
    PUNICODE_PREFIX_TABLE_ENTRY NextPrefixTree;
    PUNICODE_PREFIX_TABLE_ENTRY LastNextEntry;
} UNICODE_PREFIX_TABLE, *PUNICODE_PREFIX_TABLE;

/**
 * The RtlInitializeUnicodePrefix routine initializes a Unicode prefix table.
 *
 * \param PrefixTable A pointer to the Unicode prefix table to initialize.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitializeunicodeprefix
 */
NTSYSAPI
VOID
NTAPI
RtlInitializeUnicodePrefix(
    _Out_ PUNICODE_PREFIX_TABLE PrefixTable
);

/**
 * The RtlInsertUnicodePrefix routine inserts a prefix into a Unicode prefix table.
 *
 * \param PrefixTable A pointer to the Unicode prefix table.
 * \param Prefix A pointer to the Unicode string that is the prefix to insert.
 * \param PrefixTableEntry A pointer to the prefix table entry that describes the inserted prefix.
 * \return `TRUE` if the prefix was inserted, otherwise `FALSE` if a matching prefix already exists.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinsertunicodeprefix
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlInsertUnicodePrefix(
    _In_ PUNICODE_PREFIX_TABLE PrefixTable,
    _In_ PUNICODE_STRING Prefix,
    _Out_ PUNICODE_PREFIX_TABLE_ENTRY PrefixTableEntry
);

/**
 * The RtlRemoveUnicodePrefix routine removes a prefix from a Unicode prefix table.
 *
 * \param PrefixTable A pointer to the Unicode prefix table.
 * \param PrefixTableEntry A pointer to the prefix table entry to remove.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlremoveunicodeprefix
 */
NTSYSAPI
VOID
NTAPI
RtlRemoveUnicodePrefix(
    _In_ PUNICODE_PREFIX_TABLE PrefixTable,
    _In_ PUNICODE_PREFIX_TABLE_ENTRY PrefixTableEntry
);

/**
 * The RtlFindUnicodePrefix routine searches a Unicode prefix table for the longest prefix of the specified name.
 *
 * \param PrefixTable A pointer to the Unicode prefix table.
 * \param FullName A pointer to the Unicode string to search for a prefix.
 * \param CaseInsensitiveIndex The number of leading characters to compare case-insensitively.
 * \return A pointer to the matching prefix table entry, or `NULL` if no prefix was found.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlfindunicodeprefix
 */
NTSYSAPI
PUNICODE_PREFIX_TABLE_ENTRY
NTAPI
RtlFindUnicodePrefix(
    _In_ PUNICODE_PREFIX_TABLE PrefixTable,
    _In_ PUNICODE_STRING FullName,
    _In_ ULONG CaseInsensitiveIndex
);

/**
 * The RtlNextUnicodePrefix routine enumerates the entries in a Unicode prefix table.
 *
 * \param PrefixTable A pointer to the Unicode prefix table.
 * \param Restart If `TRUE`, the enumeration restarts from the first entry.
 * \return A pointer to the next prefix table entry, or `NULL` when the enumeration is complete.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlnextunicodeprefix
 */
NTSYSAPI
PUNICODE_PREFIX_TABLE_ENTRY
NTAPI
RtlNextUnicodePrefix(
    _In_ PUNICODE_PREFIX_TABLE PrefixTable,
    _In_ BOOLEAN Restart
);

#pragma endregion

#pragma region Encode/Decode

/**
 * The RtlRunEncodeUnicodeString routine obfuscates a Unicode string in place using a simple run-based encoding seeded
 * by the specified value.
 *
 * \param Seed A pointer to the seed byte; the routine updates it with the seed actually used.
 * \param String A pointer to the UNICODE_STRING to encode in place.
 */
NTSYSAPI
VOID
NTAPI
RtlRunEncodeUnicodeString(
    _Inout_ PUCHAR Seed,
    _Inout_ PUNICODE_STRING String);

/**
 * The RtlRunDecodeUnicodeString routine reverses the encoding performed by RtlRunEncodeUnicodeString, restoring a
 * Unicode string in place.
 *
 * \param Seed The seed byte that was used to encode the string.
 * \param String A pointer to the UNICODE_STRING to decode in place.
 */
NTSYSAPI
VOID
NTAPI
RtlRunDecodeUnicodeString(
    _In_ UCHAR Seed,
    _Inout_ PUNICODE_STRING String);

/**
 * The RtlFindClosestEncodableLength routine finds the closest length that can be encoded for the specified source
 * length.
 *
 * \param SourceLength The source length to encode.
 * \param TargetLength A pointer to a variable that receives the closest encodable length.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlFindClosestEncodableLength(
    _In_ ULONGLONG SourceLength,
    _Out_ PULONGLONG TargetLength);

#pragma endregion

typedef struct _RTL_UNICODE_STRING_BUFFER RTL_UNICODE_STRING_BUFFER, *PRTL_UNICODE_STRING_BUFFER;

/**
 * The RtlMultiAppendUnicodeStringBuffer routine appends multiple counted Unicode strings to a Unicode string buffer.
 *
 * \param Buffer A pointer to the Unicode string buffer.
 * \param BufferCount The number of source strings in the array.
 * \param Source A pointer to an array of Unicode strings to append.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlMultiAppendUnicodeStringBuffer(
    _Inout_ PRTL_UNICODE_STRING_BUFFER Buffer,
    _In_ ULONG BufferCount,
    _In_ PCUNICODE_STRING Source);

/**
 * The RtlAppendPathElement routine appends a path element to a Unicode string buffer, inserting a path separator as
 * needed.
 *
 * \param Flags Flags that control how the path element is appended.
 * \param Buffer A pointer to the Unicode string buffer.
 * \param Source A pointer to the path element to append.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAppendPathElement(
    _In_ ULONG Flags,
    _Inout_ PRTL_UNICODE_STRING_BUFFER Buffer,
    _In_ PCUNICODE_STRING Source);

EXTERN_C_END

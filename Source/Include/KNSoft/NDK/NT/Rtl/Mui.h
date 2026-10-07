#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

/**
 * Holds the cached MUI (multilingual user interface) registry state used for language resolution.
 */
typedef struct _RTL_MUI_REGISTRY_INFO
{
    ULONG Flags;                                  // +0x00 ownership mask (0x400 = self-owned)
    ULONG Reserved0;                              // +0x04
    PVOID Reserved1;                              // +0x08
    PVOID Reserved2;                              // +0x10
    PVOID SerializedData;                         // +0x18 (0x001) RtlFreeHeap
    PVOID StringPool;                             // +0x20 (0x002) RtlpMuiRegFreeStringPool
    PVOID UserLanguageConfigList;                 // +0x28 (0x004) RtlpMuiRegFreeLanguageConfigList
    PVOID MachineLanguageConfigList;              // +0x30 (0x008) RtlpMuiRegFreeLanguageConfigList
    PVOID LanguageList10;                         // +0x38 (0x010) RtlpMuiRegFreeLanguageList
    PVOID LanguageList20;                         // +0x40 (0x020) RtlpMuiRegFreeLanguageList
    PVOID Reserved3;                              // +0x48
    PVOID LanguageList80;                         // +0x50 (0x080) RtlpMuiRegFreeLanguageList
    PVOID LanguageList40;                         // +0x58 (0x040) RtlpMuiRegFreeLanguageList
    PVOID LanguageList200;                        // +0x60 (0x200) RtlpMuiRegFreeLanguageList
    struct _RTL_MUI_REGISTRY_INFO *Alternate;     // +0x68 nested (recursive free + RtlFreeHeap)
    PVOID Reserved4;                              // +0x70
    PVOID Reserved5;                              // +0x78
    PVOID Reserved6;                              // +0x80
    PVOID FallbackData;                           // +0x88 (0x800) RtlFreeHeap
    PVOID Reserved7;                              // +0x90
    PVOID Reserved8;                              // +0x98
    PVOID Reserved9;                              // +0xA0
} RTL_MUI_REGISTRY_INFO, *PRTL_MUI_REGISTRY_INFO;

// private
/**
 * The RtlConvertLCIDToString routine converts a locale identifier (LCID) to its string representation.
 *
 * \param LcidValue The locale identifier to convert.
 * \param Base The numeric base used for the conversion.
 * \param Padding The minimum width, in characters, to which the resulting string is padded.
 * \param pResultBuf A buffer that receives the resulting string.
 * \param Size The size, in characters, of the result buffer.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlConvertLCIDToString(
    _In_ LCID LcidValue,
    _In_ ULONG Base,
    _In_ ULONG Padding, // string is padded to this width
    _Out_writes_(Size) PWSTR pResultBuf,
    _In_ ULONG Size
);

// private
/**
 * The RtlIsValidLocaleName routine determines whether the specified locale name is valid.
 *
 * \param LocaleName A pointer to the locale name to validate.
 * \param Flags Flags that control the validation.
 * \return `TRUE` if the locale name is valid, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsValidLocaleName(
    _In_ PCWSTR LocaleName,
    _In_ ULONG Flags
);

// private
/**
 * The RtlGetParentLocaleName routine returns the parent locale name of the specified locale.
 *
 * \param LocaleName A pointer to the locale name to query.
 * \param ParentLocaleName A pointer to the string that receives the parent locale name. If AllocateDestinationString is
 * `TRUE`, the buffer is allocated by the routine.
 * \param Flags Flags that control the operation.
 * \param AllocateDestinationString If `TRUE`, the routine allocates the destination string buffer.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetParentLocaleName(
    _In_ PCWSTR LocaleName,
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) PUNICODE_STRING ParentLocaleName,
    _In_ ULONG Flags,
    _In_ BOOLEAN AllocateDestinationString
);

// private
/**
 * The RtlLcidToLocaleName routine converts a locale identifier (LCID) to a locale name.
 *
 * \param lcid The locale identifier to convert.
 * \param LocaleName A pointer to the string that receives the locale name. If AllocateDestinationString is `TRUE`, the
 * buffer is allocated by the routine.
 * \param Flags Flags that control the operation.
 * \param AllocateDestinationString If `TRUE`, the routine allocates the destination string buffer.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlLcidToLocaleName(
    _In_ LCID lcid, // sic
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) PUNICODE_STRING LocaleName,
    _In_ ULONG Flags,
    _In_ BOOLEAN AllocateDestinationString
);

// private
/**
 * The RtlLocaleNameToLcid routine converts a locale name to a locale identifier (LCID).
 *
 * \param LocaleName A pointer to the locale name to convert.
 * \param lcid A pointer to a variable that receives the locale identifier.
 * \param Flags Flags that control the operation.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlLocaleNameToLcid(
    _In_ PCWSTR LocaleName,
    _Out_ PLCID lcid,
    _In_ ULONG Flags
);

// private
/**
 * The RtlLCIDToCultureName routine converts a locale identifier (LCID) to its culture name.
 *
 * \param Lcid The locale identifier to convert.
 * \param String A pointer to the string that receives the culture name.
 * \return `TRUE` if the conversion succeeded, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlLCIDToCultureName(
    _In_ LCID Lcid,
    _Inout_ PUNICODE_STRING String
);

// private
/**
 * The RtlCultureNameToLCID routine converts a culture name to a locale identifier (LCID).
 *
 * \param String A pointer to the culture name to convert.
 * \param Lcid A pointer to a variable that receives the locale identifier.
 * \return `TRUE` if the conversion succeeded, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlCultureNameToLCID(
    _In_ PUNICODE_STRING String,
    _Out_ PLCID Lcid
);

// rev
/**
 * The RtlpConvertLCIDsToCultureNames routine converts an array of locale identifiers (LCIDs) to an array of culture
 * names.
 *
 * \param Lcids A pointer to the array of locale identifiers, in string form.
 * \param CultureNames A pointer to a variable that receives the array of culture names.
 * \return `TRUE` if the conversion succeeded, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlpConvertLCIDsToCultureNames(
    _In_ PCWSTR Lcids, // array
    _Out_ PCWSTR* CultureNames
);

// rev
/**
 * The RtlpConvertCultureNamesToLCIDs routine converts an array of culture names to an array of locale identifiers
 * (LCIDs).
 *
 * \param CultureNames A pointer to the array of culture names.
 * \param Lcids A pointer to a variable that receives the array of locale identifiers, in string form.
 * \return `TRUE` if the conversion succeeded, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlpConvertCultureNamesToLCIDs(
    _In_ PCWSTR CultureNames, // array
    _Out_ PCWSTR* Lcids
);

// private
/**
 * The RtlCleanUpTEBLangLists routine cleans up the preferred UI language lists stored in the thread environment block
 * (TEB) of the calling thread.
 */
NTSYSAPI
VOID
NTAPI
RtlCleanUpTEBLangLists(
    VOID
);

// rev from GetThreadPreferredUILanguages
/**
 * The RtlGetThreadPreferredUILanguages routine retrieves the preferred UI languages for the calling thread.
 *
 * \param Flags Flags that control the format of the returned languages (for example, MUI_LANGUAGE_NAME).
 * \param NumberOfLanguages A pointer to a variable that receives the number of languages returned.
 * \param Languages An optional buffer that receives the double-null-terminated list of languages.
 * \param ReturnLength On input, the size of the buffer in characters; on output, the number of characters returned or
 * required.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetThreadPreferredUILanguages(
    _In_ ULONG Flags, // MUI_LANGUAGE_NAME
    _Out_ PULONG NumberOfLanguages,
    _Out_writes_opt_(*ReturnLength) PZZWSTR Languages,
    _Inout_ PULONG ReturnLength
);

// rev from GetProcessPreferredUILanguages
/**
 * The RtlGetProcessPreferredUILanguages routine retrieves the preferred UI languages for the current process.
 *
 * \param Flags Flags that control the format of the returned languages (for example, MUI_LANGUAGE_NAME).
 * \param NumberOfLanguages A pointer to a variable that receives the number of languages returned.
 * \param Languages An optional buffer that receives the double-null-terminated list of languages.
 * \param ReturnLength On input, the size of the buffer in characters; on output, the number of characters returned or
 * required.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetProcessPreferredUILanguages(
    _In_ ULONG Flags, // MUI_LANGUAGE_NAME
    _Out_ PULONG NumberOfLanguages,
    _Out_writes_opt_(*ReturnLength) PZZWSTR Languages,
    _Inout_ PULONG ReturnLength
);

// rev from GetSystemPreferredUILanguages
/**
 * The RtlGetSystemPreferredUILanguages routine retrieves the preferred UI languages for the system.
 *
 * \param Flags Flags that control the format of the returned languages (for example, MUI_LANGUAGE_NAME).
 * \param LocaleName An optional pointer to a locale name that scopes the query.
 * \param NumberOfLanguages A pointer to a variable that receives the number of languages returned.
 * \param Languages An optional buffer that receives the double-null-terminated list of languages.
 * \param ReturnLength On input, the size of the buffer in characters; on output, the number of characters returned or
 * required.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetSystemPreferredUILanguages(
    _In_ ULONG Flags, // MUI_LANGUAGE_NAME
    _In_opt_ PCWSTR LocaleName,
    _Out_ PULONG NumberOfLanguages,
    _Out_writes_opt_(*ReturnLength) PZZWSTR Languages,
    _Inout_ PULONG ReturnLength
);

// rev from GetSystemDefaultUILanguage
/**
 * The RtlpGetSystemDefaultUILanguage routine retrieves the system default UI language.
 *
 * \param DefaultUILanguageId The default UI language identifier.
 * \param Lcid A pointer to a variable that receives the corresponding locale identifier.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpGetSystemDefaultUILanguage(
    _Out_ LANGID DefaultUILanguageId,
    _Inout_ PLCID Lcid
);

// rev from GetUserPreferredUILanguages
/**
 * The RtlGetUserPreferredUILanguages routine retrieves the preferred UI languages for the current user.
 *
 * \param Flags Flags that control the format of the returned languages (for example, MUI_LANGUAGE_NAME).
 * \param LocaleName An optional pointer to a locale name that scopes the query.
 * \param NumberOfLanguages A pointer to a variable that receives the number of languages returned.
 * \param Languages An optional buffer that receives the double-null-terminated list of languages.
 * \param ReturnLength On input, the size of the buffer in characters; on output, the number of characters returned or
 * required.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetUserPreferredUILanguages(
    _In_ ULONG Flags, // MUI_LANGUAGE_NAME
    _In_opt_ PCWSTR LocaleName,
    _Out_ PULONG NumberOfLanguages,
    _Out_writes_opt_(*ReturnLength) PZZWSTR Languages,
    _Inout_ PULONG ReturnLength
);

// rev from GetUILanguageInfo
/**
 * The RtlGetUILanguageInfo routine retrieves fallback and attribute information for a set of UI languages.
 *
 * \param Flags Flags that control the operation.
 * \param Languages A pointer to a double-null-terminated list of languages to query.
 * \param FallbackLanguages An optional buffer that receives the double-null-terminated list of fallback languages.
 * \param NumberOfFallbackLanguages On input, the size of the fallback buffer in characters; on output, the number of
 * characters returned or required.
 * \param Attributes A pointer to a variable that receives the language attributes.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetUILanguageInfo(
    _In_ ULONG Flags,
    _In_ PCZZWSTR Languages,
    _Out_writes_opt_(*NumberOfFallbackLanguages) PZZWSTR FallbackLanguages,
    _Inout_opt_ PULONG NumberOfFallbackLanguages,
    _Out_ PULONG Attributes
);

// rev
/**
 * Retrieves the base address of the memory-mapped NLS locale data file, mapping and caching it on first use.
 *
 * \param BaseAddress A pointer to a variable that receives the base address of the mapped locale data file.
 * \param DefaultLocaleId A pointer to a variable that receives the default system locale identifier.
 * \param DefaultCasingTableSize An optional pointer to a variable that receives the size, in bytes, of the default
 * casing table.
 * \param CurrentNLSVersion An optional pointer to a variable that receives the current NLS version.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetLocaleFileMappingAddress(
    _Out_ PVOID *BaseAddress,
    _Out_ PLCID DefaultLocaleId,
    _Out_opt_ PLARGE_INTEGER DefaultCasingTableSize,
    _Out_opt_ PULONG CurrentNLSVersion
    );

/**
 * The RtlFindMessage routine locates a message resource entry within a module's message table.
 *
 * \param DllHandle The base address of the module containing the message table.
 * \param MessageTableId The identifier of the message table resource.
 * \param MessageLanguageId The language identifier of the message.
 * \param MessageId The identifier of the message to locate.
 * \param MessageEntry Receives a pointer to the message resource entry.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlFindMessage(
    _In_ PVOID DllHandle,
    _In_ ULONG MessageTableId,
    _In_ ULONG MessageLanguageId,
    _In_ ULONG MessageId,
    _Out_ PMESSAGE_RESOURCE_ENTRY *MessageEntry
);

/**
 * The RtlFormatMessage routine formats a message string, substituting the supplied insert arguments.
 *
 * \param MessageFormat A pointer to the message format string.
 * \param MaximumWidth The maximum line width, in characters, or zero for no limit.
 * \param IgnoreInserts A boolean that specifies whether insert sequences are left unexpanded.
 * \param ArgumentsAreAnsi A boolean that specifies whether the arguments are ANSI strings.
 * \param ArgumentsAreAnArray A boolean that specifies whether the arguments are supplied as an array rather than a
 * va_list.
 * \param Arguments A pointer to the insert arguments.
 * \param Buffer A buffer that receives the formatted message.
 * \param Length The size, in bytes, of the output buffer.
 * \param ReturnLength An optional pointer to a variable that receives the length, in bytes, of the formatted message.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlFormatMessage(
    _In_ PCWSTR MessageFormat,
    _In_ ULONG MaximumWidth,
    _In_ BOOLEAN IgnoreInserts,
    _In_ BOOLEAN ArgumentsAreAnsi,
    _In_ BOOLEAN ArgumentsAreAnArray,
    _In_ va_list *Arguments,
    _Out_writes_bytes_to_(Length, *ReturnLength) PWSTR Buffer,
    _In_ ULONG Length,
    _Out_opt_ PULONG ReturnLength
);

/**
 * Maintains state used while parsing a message with RtlFormatMessage-style routines.
 */
typedef struct _PARSE_MESSAGE_CONTEXT
{
    ULONG fFlags;
    ULONG cwSavColumn;
    SIZE_T iwSrc;
    SIZE_T iwDst;
    SIZE_T iwDstSpace;
    va_list lpvArgStart;
} PARSE_MESSAGE_CONTEXT, *PPARSE_MESSAGE_CONTEXT;

/**
 * Helper macros for initializing and testing a message parse context.
 */
#define INIT_PARSE_MESSAGE_CONTEXT(ctx) { (ctx)->fFlags = 0; }
#define TEST_PARSE_MESSAGE_CONTEXT_FLAG(ctx, flag) ((ctx)->fFlags & (flag))
#define SET_PARSE_MESSAGE_CONTEXT_FLAG(ctx, flag) ((ctx)->fFlags |= (flag))
#define CLEAR_PARSE_MESSAGE_CONTEXT_FLAG(ctx, flag) ((ctx)->fFlags &= ~(flag))

/**
 * The RtlFormatMessageEx routine formats a message string, substituting the supplied insert arguments, with an extended
 * parse context.
 *
 * \param MessageFormat A pointer to the message format string.
 * \param MaximumWidth The maximum line width, in characters, or zero for no limit.
 * \param IgnoreInserts A boolean that specifies whether insert sequences are left unexpanded.
 * \param ArgumentsAreAnsi A boolean that specifies whether the arguments are ANSI strings.
 * \param ArgumentsAreAnArray A boolean that specifies whether the arguments are supplied as an array rather than a
 * va_list.
 * \param Arguments A pointer to the insert arguments.
 * \param Buffer A buffer that receives the formatted message.
 * \param Length The size, in bytes, of the output buffer.
 * \param ReturnLength An optional pointer to a variable that receives the length, in bytes, of the formatted message.
 * \param ParseContext An optional pointer to a parse-message context that receives extended parse information.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlFormatMessageEx(
    _In_ PCWSTR MessageFormat,
    _In_ ULONG MaximumWidth,
    _In_ BOOLEAN IgnoreInserts,
    _In_ BOOLEAN ArgumentsAreAnsi,
    _In_ BOOLEAN ArgumentsAreAnArray,
    _In_ va_list *Arguments,
    _Out_writes_bytes_to_(Length, *ReturnLength) PWSTR Buffer,
    _In_ ULONG Length,
    _Out_opt_ PULONG ReturnLength,
    _Out_opt_ PPARSE_MESSAGE_CONTEXT ParseContext
);

/**
 * The RtlGetFileMUIPath routine retrieves the path of the MUI (Multilingual User Interface) resource file associated
 * with the specified file.
 *
 * \param Flags Flags that control the MUI path lookup.
 * \param FilePath A pointer to the path of the language-neutral (LN) file.
 * \param Language A pointer to a buffer that contains, on input, the desired language and receives, on output, the
 * resolved language.
 * \param LanguageLength A pointer to a variable that specifies and receives the length, in characters, of the language
 * buffer.
 * \param FileMUIPath An optional buffer that receives the resolved MUI file path.
 * \param FileMUIPathLength A pointer to a variable that specifies and receives the length, in characters, of the MUI
 * path buffer.
 * \param Enumerator A pointer to a variable that maintains enumeration state across successive calls.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetFileMUIPath(
    _In_ ULONG Flags,
    _In_ PCWSTR FilePath,
    _Inout_opt_ PWSTR Language,
    _Inout_ PULONG LanguageLength,
    _Out_opt_ PWSTR FileMUIPath,
    _Inout_ PULONG FileMUIPathLength,
    _Inout_ PULONGLONG Enumerator
);

// private
/**
 * The RtlLoadString routine loads a string resource from a module.
 *
 * \param DllHandle The base address of the module containing the string resource.
 * \param StringId The identifier of the string to load.
 * \param StringLanguage An optional language name selecting the string; NULL uses the default.
 * \param Flags Flags controlling the load.
 * \param ReturnString Receives a pointer to the loaded string.
 * \param ReturnStringLen An optional pointer that receives the length, in characters, of the string.
 * \param ReturnLanguageName A buffer that receives the language name of the loaded string.
 * \param ReturnLanguageLen On input specifies the buffer length; on output receives the language name length.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlLoadString(
    _In_ PVOID DllHandle,
    _In_ ULONG StringId,
    _In_opt_ PCWSTR StringLanguage,
    _In_ ULONG Flags,
    _Out_ PCWSTR *ReturnString,
    _Out_opt_ PUSHORT ReturnStringLen,
    _Out_writes_(ReturnLanguageLen) PWSTR ReturnLanguageName,
    _Inout_opt_ PULONG ReturnLanguageLen
);

// RtlRestoreThreadPreferredUILanguages
/**
 * Restores the thread preferred UI language state previously captured by RtlSetThreadPreferredUILanguages2 and releases
 * the saved-state block.
 *
 * \param State A pointer to the opaque saved-state block returned through the SavedState parameter of
 * RtlSetThreadPreferredUILanguages2.
 * \return BOOLEAN TRUE if the saved state was restored and freed; otherwise the routine raises a critical failure when
 * the state does not belong to the current thread.
 * \remarks Prototype reconstructed from disassembly. The saved-state block records the previous PreferredLanguages,
 * MergedPrefLanguages and UserPrefLanguages lists together with the owning thread id.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlRestoreThreadPreferredUILanguages(
    _In_ PVOID State
    );

// RtlSetProcessPreferredUILanguages
/**
 * The RtlSetProcessPreferredUILanguages routine sets the preferred UI languages for the current process.
 *
 * \param Flags Flags that control the operation.
 * \param LanguagesBuffer An optional pointer to the double-null-terminated list of languages to set.
 * \param NumberOfLanguages An optional pointer to a variable that receives the number of languages set.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetProcessPreferredUILanguages(
    _In_ ULONG Flags,
    _In_opt_ PUSHORT LanguagesBuffer,
    _Out_opt_ PULONG NumberOfLanguages
    );

// RtlSetThreadPreferredUILanguages
/**
 * Sets the preferred UI languages for the current thread.
 *
 * \param Flags Flags controlling the language format and matching behavior (MUI_LANGUAGE_ID, MUI_LANGUAGE_NAME, etc.).
 * \param LanguagesBuffer An optional null-null terminated multi-string of preferred UI languages. When NULL the thread
 * language list is cleared.
 * \param NumberOfLanguages An optional pointer to a variable that receives the number of languages that were set.
 * \return NTSTATUS Successful or errant status.
 * \remarks Prototype reconstructed from disassembly; the trailing Reserved parameter present in earlier headers does
 * not exist.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetThreadPreferredUILanguages(
    _In_ ULONG Flags,
    _In_opt_ PCZZWSTR LanguagesBuffer,
    _Out_opt_ PULONG NumberOfLanguages
    );

// RtlSetThreadPreferredUILanguages2
/**
 * Sets the preferred UI languages for the current thread and optionally captures the previous state for later
 * restoration.
 *
 * \param Flags Flags controlling the language format and matching behavior (MUI_LANGUAGE_ID, MUI_LANGUAGE_NAME, etc.).
 * \param LanguagesBuffer An optional null-null terminated multi-string of preferred UI languages.
 * \param NumberOfLanguages An optional pointer to a variable that receives the number of languages that were set.
 * \param SavedState An optional pointer to a variable that receives an opaque saved-state block to be passed to
 * RtlRestoreThreadPreferredUILanguages.
 * \return NTSTATUS Successful or errant status.
 * \remarks Prototype reconstructed from disassembly; SavedState receives a pointer (not a scalar cookie).
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetThreadPreferredUILanguages2(
    _In_ ULONG Flags,
    _In_opt_ PCZZWSTR LanguagesBuffer,
    _Out_opt_ PULONG NumberOfLanguages,
    _Out_opt_ PVOID *SavedState
    );

// RtlpGetLCIDFromLangInfoNode
/**
 * Resolves the locale identifier associated with a language-info node using the MUI registry information string pool.
 *
 * \param RegistryInfo The MUI registry information block that owns the string pool referenced by the node.
 * \param LangInfoNode A pointer to the language-info node to resolve.
 * \param Lcid A pointer to a variable that receives the resolved locale identifier.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpGetLCIDFromLangInfoNode(
    _In_ PRTL_MUI_REGISTRY_INFO RegistryInfo,
    _In_ PVOID LangInfoNode,
    _Out_ PUSHORT Lcid
    );

// RtlpGetUserOrMachineUILanguage4NLS
/**
 * The RtlpGetUserOrMachineUILanguage4NLS routine retrieves the user or machine UI languages for use by NLS.
 *
 * \param UserOrMachine A value that selects whether the user or machine languages are retrieved.
 * \param LanguagesMultiSz An optional buffer that receives the double-null-terminated list of languages.
 * \param LanguageCount On input, the size of the buffer; on output, the number of languages returned or required.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpGetUserOrMachineUILanguage4NLS(
    _In_ ULONG UserOrMachine,
    _Out_writes_opt_(*LanguageCount) PWSTR LanguagesMultiSz,
    _Inout_ PULONGLONG LanguageCount
    );

// RtlpIsQualifiedLanguage
/**
 * Determines whether a language node qualifies against the installed and parent language set.
 *
 * \param RegistryInfo Context describing the installed language set to validate against.
 * \param LangNode A pointer to the language node (culture identifier) to test.
 * \param CheckInstallLanguage When TRUE the install language is included in the qualification check.
 * \return NTSTATUS STATUS_SUCCESS (with the qualified result encoded by the routine) or an errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpIsQualifiedLanguage(
    _In_ PVOID RegistryInfo,
    _In_ PSHORT LangNode,
    _In_ BOOLEAN CheckInstallLanguage
    );

// RtlpMuiFreeLangRegistryInfo
/**
 * Frees every sub-allocation owned by an MUI registry information block and releases the block itself.
 *
 * \param RegistryInfo The MUI registry information block to free.
 * \return NTSTATUS Successful or errant status.
 * \remarks Prototype reconstructed from disassembly; this is a full-teardown wrapper around
 * RtlpMuiRegFreeRegistryInfo(RegistryInfo, 0xFFF) followed by RtlFreeHeap.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpMuiFreeLangRegistryInfo(
    _In_ PRTL_MUI_REGISTRY_INFO RegistryInfo
    );

// RtlpMuiRegCreateRegistryInfo
/**
 * Allocates and zero-initializes an empty MUI registry information block.
 *
 * \return A pointer to the newly allocated MUI registry information block, or NULL on allocation failure.
 */
NTSYSAPI
PRTL_MUI_REGISTRY_INFO
NTAPI
RtlpMuiRegCreateRegistryInfo(
    VOID
    );

// RtlpMuiRegFreeRegistryInfo
/**
 * Selectively frees the sub-allocations owned by an MUI registry information block according to a free mask.
 *
 * \param RegistryInfo The MUI registry information block to operate on.
 * \param FreeMask A bitmask selecting which owned members to release (0xFFF frees all standard categories).
 * \return NTSTATUS Successful or errant status.
 * \remarks Prototype reconstructed from disassembly; the block itself is not freed, only its selected members.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpMuiRegFreeRegistryInfo(
    _Inout_ PRTL_MUI_REGISTRY_INFO RegistryInfo,
    _In_ ULONG FreeMask
    );

// RtlpMuiRegLoadRegistryInfo
/**
 * Loads the requested categories of MUI registry information into an existing block.
 *
 * \param RegistryInfo The MUI registry information block to populate.
 * \param LoadMask A bitmask selecting which categories to load (installed languages, license information, fallback and
 * language-configuration lists).
 * \return NTSTATUS Successful or errant status.
 * \remarks Prototype reconstructed from disassembly.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpMuiRegLoadRegistryInfo(
    _Inout_ PRTL_MUI_REGISTRY_INFO RegistryInfo,
    _In_ SHORT LoadMask
    );

// RtlpQueryDefaultUILanguage
/**
 * The RtlpQueryDefaultUILanguage routine queries the default UI language.
 *
 * \param DefaultLanguage A pointer to a variable that receives the default UI language identifier.
 * \param ForceMachinePolicy If `TRUE`, the machine policy is used to determine the default language.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpQueryDefaultUILanguage(
    _Out_ PUSHORT DefaultLanguage,
    _In_ BOOLEAN ForceMachinePolicy
    );

// RtlpRefreshCachedUILanguage
/**
 * The RtlpRefreshCachedUILanguage routine refreshes the cached UI language value.
 *
 * \param SourceString A pointer to the language string used to refresh the cache.
 * \param CommitImmediately If `TRUE`, the refreshed value is committed immediately.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpRefreshCachedUILanguage(
    _In_ PCWSTR SourceString,
    _In_ BOOLEAN CommitImmediately
    );

// RtlpSetInstallLanguage
/**
 * The RtlpSetInstallLanguage routine sets the install language.
 *
 * \param Flags Flags that control the operation.
 * \param Language A pointer to the null-terminated install language string.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpSetInstallLanguage(
    _In_ CHAR Flags,
    _In_z_ PCWSTR Language
    );

// RtlpSetPreferredUILanguages
/**
 * Applies a preferred UI language multi-string to the current process or thread scope selected by Flags.
 *
 * \param Flags Flags controlling the target scope and language format.
 * \param LanguagesMultiSz An optional null-null terminated multi-string of preferred UI languages.
 * \param LanguagesCount An optional pointer to a variable that receives the number of languages that were applied.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpSetPreferredUILanguages(
    _In_ ULONG Flags,
    _In_opt_z_ PCWSTR LanguagesMultiSz,
    _Out_opt_ PULONG LanguagesCount
    );

// RtlpSetUserPreferredUILanguages
/**
 * The RtlpSetUserPreferredUILanguages routine sets the preferred UI languages for the current user using the specified
 * multi-string language list.
 *
 * \param Flags Flags that control the operation.
 * \param LanguagesMultiSz An optional pointer to the double-null-terminated list of languages to set.
 * \param LanguagesCount An optional pointer to a variable that receives the number of languages set.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpSetUserPreferredUILanguages(
    _In_ ULONG Flags,
    _In_opt_z_ PWSTR LanguagesMultiSz,
    _Out_opt_ PULONG LanguagesCount
    );

// RtlpVerifyAndCommitUILanguageSettings
/**
 * The RtlpVerifyAndCommitUILanguageSettings routine verifies and commits the pending UI language settings.
 *
 * \param ShutdownOnFailure If `TRUE`, the process is shut down if the settings cannot be committed.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpVerifyAndCommitUILanguageSettings(
    _In_ BOOLEAN ShutdownOnFailure
    );


/**
 * The RtlGetThreadLangIdByIndex routine retrieves the language identifier for a thread by index.
 *
 * \param Reserved Reserved; must be zero.
 * \param Index The index of the language in the thread's preferred-language list.
 * \param LanguageId Pointer to a variable that receives the language identifier.
 * \param Count Optional pointer to a variable that receives the number of preferred languages.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
LONG
NTAPI
RtlGetThreadLangIdByIndex(
    _Reserved_ ULONG Reserved,
    _In_ ULONG Index,
    _Out_ PULONG LanguageId,
    _Out_opt_ PULONG Count
    );

EXTERN_C_END

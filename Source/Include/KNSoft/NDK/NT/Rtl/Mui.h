#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

// private
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
NTSYSAPI
BOOLEAN
NTAPI
RtlIsValidLocaleName(
    _In_ PCWSTR LocaleName,
    _In_ ULONG Flags
);

// private
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
NTSYSAPI
NTSTATUS
NTAPI
RtlLocaleNameToLcid(
    _In_ PCWSTR LocaleName,
    _Out_ PLCID lcid,
    _In_ ULONG Flags
);

// private
NTSYSAPI
BOOLEAN
NTAPI
RtlLCIDToCultureName(
    _In_ LCID Lcid,
    _Inout_ PUNICODE_STRING String
);

// private
NTSYSAPI
BOOLEAN
NTAPI
RtlCultureNameToLCID(
    _In_ PUNICODE_STRING String,
    _Out_ PLCID Lcid
);

// rev
NTSYSAPI
BOOLEAN
NTAPI
RtlpConvertLCIDsToCultureNames(
    _In_ PCWSTR Lcids, // array
    _Out_ PCWSTR* CultureNames
);

// rev
NTSYSAPI
BOOLEAN
NTAPI
RtlpConvertCultureNamesToLCIDs(
    _In_ PCWSTR CultureNames, // array
    _Out_ PCWSTR* Lcids
);

// private
NTSYSAPI
VOID
NTAPI
RtlCleanUpTEBLangLists(
    VOID
);

// rev from GetThreadPreferredUILanguages
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
NTSYSAPI
NTSTATUS
NTAPI
RtlpGetSystemDefaultUILanguage(
    _Out_ LANGID DefaultUILanguageId,
    _Inout_ PLCID Lcid
);

// rev from GetUserPreferredUILanguages
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
NTSYSAPI
NTSTATUS
NTAPI
RtlGetLocaleFileMappingAddress(
    _Out_ PVOID *BaseAddress,
    _Out_ PLCID DefaultLocaleId,
    _Out_ PLARGE_INTEGER DefaultCasingTableSize,
    _Out_opt_ PULONG CurrentNLSVersion
);

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

typedef struct _PARSE_MESSAGE_CONTEXT
{
    ULONG fFlags;
    ULONG cwSavColumn;
    SIZE_T iwSrc;
    SIZE_T iwDst;
    SIZE_T iwDstSpace;
    va_list lpvArgStart;
} PARSE_MESSAGE_CONTEXT, *PPARSE_MESSAGE_CONTEXT;

#define INIT_PARSE_MESSAGE_CONTEXT(ctx) { (ctx)->fFlags = 0; }
#define TEST_PARSE_MESSAGE_CONTEXT_FLAG(ctx, flag) ((ctx)->fFlags & (flag))
#define SET_PARSE_MESSAGE_CONTEXT_FLAG(ctx, flag) ((ctx)->fFlags |= (flag))
#define CLEAR_PARSE_MESSAGE_CONTEXT_FLAG(ctx, flag) ((ctx)->fFlags &= ~(flag))

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
NTSYSAPI
BOOLEAN
NTAPI
RtlRestoreThreadPreferredUILanguages(
    _In_ ULONGLONG SavedState,
    _In_opt_ PVOID Context1,
    _In_opt_ PVOID Context2,
    _In_opt_ PVOID Context3
    );

// RtlSetProcessPreferredUILanguages
NTSYSAPI
NTSTATUS
NTAPI
RtlSetProcessPreferredUILanguages(
    _In_ ULONG Flags,
    _In_opt_ PUSHORT LanguagesBuffer,
    _Out_opt_ PULONG NumberOfLanguages
    );

// RtlSetThreadPreferredUILanguages
NTSYSAPI
NTSTATUS
NTAPI
RtlSetThreadPreferredUILanguages(
    _In_ ULONG Flags,
    _In_opt_ PVOID LanguagesBuffer,
    _Out_opt_ PINT NumberOfLanguages,
    _In_opt_ PVOID Reserved
    );

// RtlSetThreadPreferredUILanguages2
NTSYSAPI
NTSTATUS
NTAPI
RtlSetThreadPreferredUILanguages2(
    _In_ ULONGLONG Flags,
    _In_opt_ PVOID LanguagesBuffer,
    _Out_opt_ PINT NumberOfLanguages,
    _Out_opt_ PULONGLONG SavedState
    );

// RtlpGetLCIDFromLangInfoNode
NTSYSAPI
NTSTATUS
NTAPI
RtlpGetLCIDFromLangInfoNode(
    _In_ PVOID RegistryInfo,
    _In_ PVOID LangInfoNode,
    _Out_ PUSHORT Lcid
    );

// RtlpGetUserOrMachineUILanguage4NLS
NTSYSAPI
NTSTATUS
NTAPI
RtlpGetUserOrMachineUILanguage4NLS(
    _In_ ULONG UserOrMachine,
    _Out_writes_opt_(*LanguageCount) PWSTR LanguagesMultiSz,
    _Inout_ PULONGLONG LanguageCount
    );

// RtlpIsQualifiedLanguage
NTSYSAPI
NTSTATUS
NTAPI
RtlpIsQualifiedLanguage(
    _In_ PVOID RegistryInfo,
    _In_ PSHORT LangNode,
    _In_ BOOLEAN CheckInstallLanguage
    );

// RtlpMuiFreeLangRegistryInfo
NTSYSAPI
NTSTATUS
NTAPI
RtlpMuiFreeLangRegistryInfo(
    _In_ PVOID RegistryInfo,
    _In_ ULONG FreeMask,
    _In_opt_ PVOID Context1,
    _In_opt_ PVOID Context2
    );

// RtlpMuiRegCreateRegistryInfo
NTSYSAPI
PULONG
NTAPI
RtlpMuiRegCreateRegistryInfo(
    VOID
    );

// RtlpMuiRegFreeRegistryInfo
NTSYSAPI
NTSTATUS
NTAPI
RtlpMuiRegFreeRegistryInfo(
    _In_ PVOID RegistryInfo,
    _In_ ULONG FreeMask,
    _In_opt_ PVOID Context1,
    _In_opt_ PVOID Context2
    );

// RtlpMuiRegLoadRegistryInfo
NTSYSAPI
NTSTATUS
NTAPI
RtlpMuiRegLoadRegistryInfo(
    _Inout_ PVOID RegistryInfo,
    _In_ SHORT LoadMask,
    _In_opt_ PVOID Context1,
    _In_opt_ PVOID Context2
    );

// RtlpQueryDefaultUILanguage
NTSYSAPI
NTSTATUS
NTAPI
RtlpQueryDefaultUILanguage(
    _Out_ PUSHORT DefaultLanguage,
    _In_ BOOLEAN ForceMachinePolicy
    );

// RtlpRefreshCachedUILanguage
NTSYSAPI
NTSTATUS
NTAPI
RtlpRefreshCachedUILanguage(
    _In_ PCWSTR SourceString,
    _In_ BOOLEAN CommitImmediately
    );

// RtlpSetInstallLanguage
NTSYSAPI
NTSTATUS
NTAPI
RtlpSetInstallLanguage(
    _In_ CHAR Flags,
    _In_z_ PCWSTR Language
    );

// RtlpSetPreferredUILanguages
NTSYSAPI
NTSTATUS
NTAPI
RtlpSetPreferredUILanguages(
    _In_ ULONG Flags,
    _In_opt_z_ PWSTR LanguagesMultiSz,
    _Out_opt_ PULONG LanguagesCount,
    _In_opt_ PVOID Reserved
    );

// RtlpSetUserPreferredUILanguages
NTSYSAPI
NTSTATUS
NTAPI
RtlpSetUserPreferredUILanguages(
    _In_ ULONG Flags,
    _In_opt_z_ PWSTR LanguagesMultiSz,
    _Out_opt_ PULONG LanguagesCount
    );

// RtlpVerifyAndCommitUILanguageSettings
NTSYSAPI
NTSTATUS
NTAPI
RtlpVerifyAndCommitUILanguageSettings(
    _In_ BOOLEAN ShutdownOnFailure
    );


EXTERN_C_END

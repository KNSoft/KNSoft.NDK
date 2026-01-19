#pragma once

#include "MinDef.h"

EXTERN_C_START

#pragma region NLS

/* ntnls.h */

#define MAXIMUM_LEADBYTES   12
/*
 * This structure is the data from the raw codepage files.
 * Note that we set the "Codepage" field last, so any threads accessing this pointers in this structure
 * should check to see if that is CP_UTF8 (65001) first. If so, they should not use the pointers.
 * MemoryBarrier might be warranted before checking CodePage to protect out-of-order reads of the pointers.
 * 
 * See also: https://learn.microsoft.com/en-us/previous-versions/mt791523(v=vs.85)
 */
typedef struct _CPTABLEINFO
{
    USHORT CodePage;                    // code page number (For UTF-8 the rest of the structure is unused)
    USHORT MaximumCharacterSize;        // max length (bytes) of a char
    USHORT DefaultChar;                 // default character (MB)
    USHORT UniDefaultChar;              // default character (Unicode)
    USHORT TransDefaultChar;            // translation of default char (Unicode)
    USHORT TransUniDefaultChar;         // translation of Unic default char (MB)
    USHORT DBCSCodePage;                // Non 0 for DBCS code pages
    UCHAR  LeadByte[MAXIMUM_LEADBYTES]; // lead byte ranges
    PUSHORT MultiByteTable;             // pointer to MB->Unicode translation table
    PVOID   WideCharTable;              // pointer to WC (Unicode->CodePage) translation table
    PUSHORT DBCSRanges;                 // pointer to DBCS ranges (UNUSED, DO NOT SET)
    PUSHORT DBCSOffsets;                // pointer to DBCS offsets
} CPTABLEINFO, *PCPTABLEINFO;

/* See also: https://learn.microsoft.com/en-us/previous-versions/mt791531(v=vs.85) */
typedef struct _NLSTABLEINFO
{
    CPTABLEINFO OemTableInfo;   // OEM table
    CPTABLEINFO AnsiTableInfo;  // ANSI table
    PUSHORT UpperCaseTable;     // 844 format upcase table
    PUSHORT LowerCaseTable;     // 844 format lower case table
} NLSTABLEINFO, *PNLSTABLEINFO;

typedef struct _RTL_NLS_STATE
{
    CPTABLEINFO DefaultAcpTableInfo;
    CPTABLEINFO DefaultOemTableInfo;
    PUSHORT ActiveCodePageData;
    PUSHORT OemCodePageData;
    PUSHORT LeadByteInfo;
    PUSHORT OemLeadByteInfo;
    PUSHORT CaseMappingData;
    PUSHORT UnicodeUpcaseTable844;
    PUSHORT UnicodeLowercaseTable844;
} RTL_NLS_STATE, *PRTL_NLS_STATE;

/* phnt */

/* Data exports (ntdll.lib/ntdllp.lib) */
#if !defined(_KERNEL_MODE)
NTSYSAPI USHORT NlsAnsiCodePage;
NTSYSAPI BOOLEAN NlsMbCodePageTag;
NTSYSAPI BOOLEAN NlsMbOemCodePageTag;
#endif

NTSYSCALLAPI
NTSTATUS
NTAPI
NtInitializeNlsFiles(
    _Out_ PVOID *BaseAddress,
    _Out_ PLCID DefaultLocaleId,
    _Out_ PLARGE_INTEGER DefaultCasingTableSize,
    _Out_opt_ PULONG CurrentNLSVersion);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtGetNlsSectionPtr(
    _In_ ULONG SectionType,
    _In_ ULONG SectionData,
    _In_ PVOID ContextData,
    _Out_ PVOID *SectionPointer,
    _Out_ PULONG SectionSize);

/**
 * The `What` flags for NtMapCMFModule.
 * The `What` parameter is a bitfield controlling:
 *   - Which CMF section to map
 *   - Access rights for CMFCheckAccess()
 *   - Whether to update CMF global flags
 *   - Page protection mode
 *   - CMF cache mode bits (propagate into CMFFlagsCache)
 *
 * These determine what access rights are checked and influence whether the mapping is allowed.
 */
#define CMF_ACCESS_DIRECTORY 0x00000002     // Access check for directory section.
#define CMF_ACCESS_SEGMENT 0x00000004       // Access check for segment section.
#define CMF_ACCESS_HITS 0x00000008          // Access check for hits section.
/**
 * The `What` flags for NtMapCMFModule.
 * These determine which CMF section is mapped and directly control the BaseAddress and ViewSizeOut outputs.
 */
#define CMF_OP_DIRECTORY 0x00000010 // Map directory section (Index ignored) // Affects: BaseAddress, ViewSizeOut
#define CMF_OP_SEGMENT 0x00000020   // Map segment section at Index // Affects: BaseAddress, ViewSizeOut
#define CMF_OP_HITS 0x00000100      // Map hits section (Index ignored) // Affects: BaseAddress, ViewSizeOut
/**
 * The `What` flags for NtMapCMFModule.
 * This affects the protection flags passed to MmMapViewOfSection,
 * which ultimately influences the memory protections of the BaseAddress parameter.
 */
#define CMF_PROTECT_SPECIAL 0x00000040      // Changes protection from PAGE_READONLY to PAGE_WRITECOPY
/**
 * The `What` flags for NtMapCMFModule.
 * When this bit is set, the function does not map anything.
 * Instead, it updates CMFFlagsCache and optionally modifies the directory header.
 */
#define CMF_UPDATE_FLAGS 0x00020000      // Enter flag-update mode // CacheFlagsOut parameter
/**
 * The `What` flags for NtMapCMFModule.
 * These bits are extracted from What and written into CMFFlagsCache.
 * They determine global CMF behavior, including which modules are valid.
 */
#define CMF_FLAG_A 0x00040000 // May trigger directory header update
#define CMF_FLAG_B 0x00080000 // Enables directory update path
#define CMF_FLAG_C 0x00100000 // Enables segment unmap path
/**
 * Flags for NtMapCMFModule.
 * These bits strip all bits outside this mask:
 */
#define CMF_ALLOWED_MASK 0xFFFFFECF // All valid bits for What
/**
 * Flags for NtMapCMFModule.
 */
typedef enum _CMF_WHAT_FLAGS
{
    // ---- Access rights (used by CMFCheckAccess) ----
    CmfAccessDirectory = 0x00000002, // Access check for directory
    CmfAccessSegment = 0x00000004, // Access check for segment[Index]
    CmfAccessHits = 0x00000008, // Access check for hits
    // ---- Operation selection (controls BaseAddress + ViewSizeOut) ----
    CmfDirectoryOp = 0x00000010, // Map directory section
    CmfSegmentOp = 0x00000020, // Map segment section at Index
    CmfHitsOp = 0x00000100, // Map hits section
    // ---- Memory protection modifier ----
    CmfSpecialProtect = 0x00000040, // Changes protection for MmMapViewOfSection
    // ---- Flag update mode (affects CacheFlagsOut only) ----
    CmfUpdateFlags = 0x00020000, // Update CMFFlagsCache instead of mapping
    // ---- CMF cache mode bits (propagate into CMFFlagsCache) ----
    CmfFlagA = 0x00040000, // May trigger directory header update
    CmfFlagB = 0x00080000, // Enables directory update path
    CmfFlagC = 0x00100000, // Enables segment unmap path
} CMF_WHAT_FLAGS;
DEFINE_ENUM_FLAG_OPERATORS(CMF_WHAT_FLAGS);

/**
 * The NtMapCMFModule routine maps a Code Map File (CMF) module into memory
 * and returns information about the cached view.
 *
 * \param What Specifies the CMF operation to perform.
 * \param Index The module index to map. Only valid for CmfSegmentOp operations.
 * \param CacheIndexOut Optional pointer that receives the cache index.
 * \param CacheFlagsOut Optional pointer that receives cache flags.
 * \param ViewSizeOut Optional pointer that receives the size of the mapped view.
 * \param BaseAddress Optional pointer that receives the base address of the mapped module.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtMapCMFModule(
    _In_ ULONG What,
    _In_ ULONG Index,
    _Out_opt_ PULONG CacheIndexOut,
    _Out_opt_ PULONG CacheFlagsOut,
    _Out_opt_ PULONG ViewSizeOut,
    _Out_opt_ PVOID *BaseAddress);

/**
 * Flags for NtGetMUIRegistryInfo.
 * Only the values below are supported. Any other bit results in STATUS_INVALID_PARAMETER.
 */
typedef enum _MUI_REGISTRY_INFO_FLAGS
{
    MUIRegInfoQuery = 0x1,      // Query or load the MUI registry info.
    MUIRegInfoClear = 0x2,      // Clear the cached MUI registry info.
    MUIRegInfoCommit = 0x8      // Commit/update state (increments counter).
} MUI_REGISTRY_INFO_FLAGS;
DEFINE_ENUM_FLAG_OPERATORS(MUI_REGISTRY_INFO_FLAGS);

/**
 * Flags for NtGetMUIRegistryInfo.
 * Only the values below are supported. Any other bit results in STATUS_INVALID_PARAMETER.
 */
#define MUI_REGINFO_QUERY 0x1   // Query or load the MUI registry info.
#define MUI_REGINFO_CLEAR 0x2   // Clear the cached MUI registry info.
#define MUI_REGINFO_COMMIT 0x8  // Commit/update state (increments counter).

/**
 * The NtGetMUIRegistryInfo routine retrieves Multilingual User Interface (MUI)
 * configuration data from the system registry.
 *
 * \param Flags Flags that control the type of MUI information returned.
 * \param DataSize On input, the size of the buffer pointed to by Data.
 * On output, the required or actual size of the data returned.
 * \param Data A pointer to the MUI registry information.
 * \return NTSTATUS Successful or errant status.
 * \remarks This routine is private and subject to change.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtGetMUIRegistryInfo(
    _In_ ULONG Flags,
    _Inout_ PULONG DataSize,
    _Out_ PVOID Data);

#pragma endregion

#pragma region Locale & MUI

/**
 * The NtQueryDefaultLocale routine retrieves the default locale identifier for either the user profile or the system.
 *
 * \param UserProfile If TRUE, retrieves the user default locale; otherwise, retrieves the system default locale.
 * \param DefaultLocaleId A pointer that receives the resulting locale identifier (LCID).
 * \return NTSTATUS Successful or errant status.
 * \see https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getsystemdefaultlocale
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getuserdefaultlocale
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryDefaultLocale(
    _In_ BOOLEAN UserProfile,
    _Out_ PLCID DefaultLocaleId);

/**
 * The NtSetDefaultLocale routine sets the default locale identifier for either
 * the user profile or the system.
 *
 * \param UserProfile If TRUE, sets the user default locale; otherwise, sets the system default locale.
 * \param DefaultLocaleId The locale identifier (LCID) to set.
 * \return NTSTATUS Successful or errant status.
 * \see https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-setthreadlocale
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetDefaultLocale(
    _In_ BOOLEAN UserProfile,
    _In_ LCID DefaultLocaleId);

/**
 * The NtQueryInstallUILanguage routine retrieves the system's installed UI language identifier.
 *
 * \param InstallUILanguageId A pointer that receives the installed UI language identifier (LANGID).
 * \return NTSTATUS Successful or errant status.
 * \see https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getsystemdefaultuilanguage
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInstallUILanguage(
    _Out_ LANGID* InstallUILanguageId);

/**
 * The NtFlushInstallUILanguage routine updates the system's installed UI
 * language and optionally commits the change.
 *
 * \param InstallUILanguage The UI language identifier (LANGID) to set.
 * \param SetComittedFlag If nonzero, commits the language change.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtFlushInstallUILanguage(
    _In_ LANGID InstallUILanguage,
    _In_ ULONG SetComittedFlag);

/**
 * The NtQueryDefaultUILanguage routine retrieves the system's default UI language identifier.
 *
 * \param DefaultUILanguageId A pointer that receives the default UI language identifier (LANGID).
 * \return NTSTATUS Successful or errant status.
 * \see https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getsystemdefaultuilanguage
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryDefaultUILanguage(
    _Out_ LANGID* DefaultUILanguageId);

/**
 * The NtSetDefaultUILanguage routine sets the system's default UI language identifier.
 *
 * \param DefaultUILanguageId The UI language identifier (LANGID) to set.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetDefaultUILanguage(
    _In_ LANGID DefaultUILanguageId);

/**
 * The NtIsUILanguageComitted routine determines whether the system UI language has been committed.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtIsUILanguageComitted(VOID);

#pragma endregion phnt

EXTERN_C_END

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

/* Private locale.nls layouts observed from Windows. */

#define NLS_LOCALE_HEADER_MAGIC 0x5344534E // 'NSDS'
#define NLS_LOCALE_DATA_SIZE_V7 0x148

typedef struct _NLS_LOCALE_FILE_HEADER
{
    ULONG CTypeTableOffset;
    ULONG Reserved0[3];
    ULONG LocaleTableOffset;
    ULONG CharMapTableOffset;
    ULONG GeoIdTableOffset;
    ULONG ScriptTableOffset;
} NLS_LOCALE_FILE_HEADER, *PNLS_LOCALE_FILE_HEADER;
typedef const NLS_LOCALE_FILE_HEADER* PCNLS_LOCALE_FILE_HEADER;

typedef struct _NLS_CTYPE_HEADER
{
    USHORT DataSize;
    // Offset from the IndexTableOffset field to the character-type index table.
    USHORT IndexTableOffset;
    WORD TypeTable[ANYSIZE_ARRAY];
} NLS_CTYPE_HEADER, *PNLS_CTYPE_HEADER;
typedef const NLS_CTYPE_HEADER* PCNLS_CTYPE_HEADER;

typedef struct _NLS_CTYPE_TABLE
{
    const WORD* TypeTable; // CT_CTYPE1, CT_CTYPE2, CT_CTYPE3 values.
    PCUCHAR IndexTable; // Index mapping Unicode code points to TypeTable entries.
} NLS_CTYPE_TABLE, *PNLS_CTYPE_TABLE;
typedef const NLS_CTYPE_TABLE* PCNLS_CTYPE_TABLE;

typedef struct _NLS_LOCALE_DATA
{
    ULONG SNameOffset;                          // LOCALE_SNAME
    ULONG SOpenTypeLanguageTagOffset;           // LOCALE_SOPENTYPELANGUAGETAG
    USHORT ILanguage;                           // LOCALE_ILANGUAGE
    USHORT Reserved0;
    USHORT IDigits;                             // LOCALE_IDIGITS
    USHORT INegNumber;                          // LOCALE_INEGNUMBER
    USHORT ICurrDigits;                         // LOCALE_ICURRDIGITS
    USHORT ICurrency;                           // LOCALE_ICURRENCY
    USHORT INegCurr;                            // LOCALE_INEGCURR
    USHORT ILZero;                              // LOCALE_ILZERO
    USHORT INeutral;                            // LOCALE_INEUTRAL
    USHORT IFirstDayOfWeek;                     // LOCALE_IFIRSTDAYOFWEEK
    USHORT IFirstWeekOfYear;                    // LOCALE_IFIRSTWEEKOFYEAR
    USHORT ICountry;                            // LOCALE_ICOUNTRY
    USHORT IMeasure;                            // LOCALE_IMEASURE
    USHORT IDigitSubstitution;                  // LOCALE_IDIGITSUBSTITUTION
    ULONG SGroupingOffset;                      // LOCALE_SGROUPING
    ULONG SMonGroupingOffset;                   // LOCALE_SMONGROUPING
    ULONG SListOffset;                          // LOCALE_SLIST
    ULONG SDecimalOffset;                       // LOCALE_SDECIMAL
    ULONG SThousandOffset;                      // LOCALE_STHOUSAND
    ULONG SCurrencyOffset;                      // LOCALE_SCURRENCY
    ULONG SMonDecimalSepOffset;                 // LOCALE_SMONDECIMALSEP
    ULONG SMonThousandSepOffset;                // LOCALE_SMONTHOUSANDSEP
    ULONG SPositiveSignOffset;                  // LOCALE_SPOSITIVESIGN
    ULONG SNegativeSignOffset;                  // LOCALE_SNEGATIVESIGN
    ULONG S1159Offset;                          // LOCALE_S1159
    ULONG S2359Offset;                          // LOCALE_S2359
    ULONG SNativeDigitsOffset;                  // LOCALE_SNATIVEDIGITS
    ULONG STimeFormatOffset;                    // LOCALE_STIMEFORMAT
    ULONG SShortDateOffset;                     // LOCALE_SSHORTDATE
    ULONG SLongDateOffset;                      // LOCALE_SLONGDATE
    ULONG SYearMonthOffset;                     // LOCALE_SYEARMONTH
    ULONG SDurationOffset;                      // LOCALE_SDURATION
    USHORT IDefaultLanguage;                    // LOCALE_IDEFAULTLANGUAGE
    USHORT IDefaultAnsiCodePage;                // LOCALE_IDEFAULTANSICODEPAGE
    USHORT IDefaultCodePage;                    // LOCALE_IDEFAULTCODEPAGE
    USHORT IDefaultMacCodePage;                 // LOCALE_IDEFAULTMACCODEPAGE
    USHORT IDefaultEbcdicCodePage;              // LOCALE_IDEFAULTEBCDICCODEPAGE
    USHORT Reserved1;
    USHORT IPaperSize;                          // LOCALE_IPAPERSIZE
    UCHAR Reserved2[2];
    ULONG SCalendarTypeOffset;                  // LOCALE_ICALENDARTYPE
    ULONG SAbbrevLangNameOffset;                // LOCALE_SABBREVLANGNAME
    ULONG SIso639LangNameOffset;                // LOCALE_SISO639LANGNAME
    ULONG SEnglishLanguageOffset;               // LOCALE_SENGLANGUAGE
    ULONG SNativeLangNameOffset;                // LOCALE_SNATIVELANGNAME
    ULONG SEnglishCountryOffset;                // LOCALE_SENGCOUNTRY
    ULONG SNativeCtryNameOffset;                // LOCALE_SNATIVECTRYNAME
    ULONG SAbbrevCtryNameOffset;                // LOCALE_SABBREVCTRYNAME
    ULONG SIso3166CtryNameOffset;               // LOCALE_SISO3166CTRYNAME
    ULONG SIntlSymbolOffset;                    // LOCALE_SINTLSYMBOL
    ULONG SEnglishCurrNameOffset;               // LOCALE_SENGCURRNAME
    ULONG SNativeCurrNameOffset;                // LOCALE_SNATIVECURRNAME
    ULONG FontSignatureOffset;                  // LOCALE_FONTSIGNATURE
    ULONG SIso639LangName2Offset;               // LOCALE_SISO639LANGNAME2
    ULONG SIso3166CtryName2Offset;              // LOCALE_SISO3166CTRYNAME2
    ULONG SParentOffset;                        // LOCALE_SPARENT
    ULONG SDayNameOffset;                       // LOCALE_SDAYNAME1
    ULONG SAbbrevDayNameOffset;                 // LOCALE_SABBREVDAYNAME1
    ULONG SMonthNameOffset;                     // LOCALE_SMONTHNAME1
    ULONG SAbbrevMonthNameOffset;               // LOCALE_SABBREVMONTHNAME1
    ULONG SGenitiveMonthOffset;                 // LOCALE_SMONTHNAME1 genitive form
    ULONG SAbbrevGenitiveMonthOffset;           // LOCALE_SABBREVMONTHNAME1 genitive form
    ULONG CalendarNamesOffset;
    ULONG CustomSortsOffset;
    USHORT INegativePercent;                    // LOCALE_INEGATIVEPERCENT
    USHORT IPositivePercent;                    // LOCALE_IPOSITIVEPERCENT
    USHORT Reserved3;
    USHORT IReadingLayout;                      // LOCALE_IREADINGLAYOUT
    USHORT Reserved4[2];
    ULONG Reserved5;
    ULONG SEnglishDisplayNameOffset;            // LOCALE_SENGLISHDISPLAYNAME
    ULONG SNativeDisplayNameOffset;             // LOCALE_SNATIVEDISPLAYNAME
    ULONG SPercentOffset;                       // LOCALE_SPERCENT
    ULONG SNanOffset;                           // LOCALE_SNAN
    ULONG SPositiveInfinityOffset;              // LOCALE_SPOSINFINITY
    ULONG SNegativeInfinityOffset;              // LOCALE_SNEGINFINITY
    ULONG Reserved6;
    ULONG SEraStringOffset;                     // CAL_SERASTRING
    ULONG SAbbrevEraStringOffset;               // CAL_SABBREVERASTRING
    ULONG Reserved7;
    ULONG SConsoleFallbackNameOffset;           // LOCALE_SCONSOLEFALLBACKNAME
    ULONG SShortTimeOffset;                     // LOCALE_SSHORTTIME
    ULONG SShortestDayNameOffset;               // LOCALE_SSHORTESTDAYNAME1
    ULONG Reserved8;
    ULONG SSortLocaleOffset;                    // LOCALE_SSORTLOCALE
    ULONG SKeyboardsToInstallOffset;            // LOCALE_SKEYBOARDSTOINSTALL
    ULONG SScriptsOffset;                       // LOCALE_SSCRIPTS
    ULONG SRelativeLongDateOffset;              // LOCALE_SRELATIVELONGDATE
    ULONG IGeoId;                               // LOCALE_IGEOID
    ULONG SShortestAmOffset;                    // LOCALE_SSHORTESTAM
    ULONG SShortestPmOffset;                    // LOCALE_SSHORTESTPM
    ULONG SMonthDayOffset;                      // LOCALE_SMONTHDAY
    ULONG KeyboardLayout;
} NLS_LOCALE_DATA, *PNLS_LOCALE_DATA;
typedef const NLS_LOCALE_DATA* PCNLS_LOCALE_DATA;

typedef struct _NLS_LOCALE_LCID_INDEX
{
    ULONG LocaleId;
    USHORT LocaleIndex;
    USHORT LocaleNameOffset;
} NLS_LOCALE_LCID_INDEX, *PNLS_LOCALE_LCID_INDEX;
typedef const NLS_LOCALE_LCID_INDEX* PCNLS_LOCALE_LCID_INDEX;

typedef struct _NLS_LOCALE_NAME_INDEX
{
    USHORT LocaleNameOffset;
    USHORT LocaleIndex;
    ULONG LocaleId;
} NLS_LOCALE_NAME_INDEX, *PNLS_LOCALE_NAME_INDEX;
typedef const NLS_LOCALE_NAME_INDEX* PCNLS_LOCALE_NAME_INDEX;

typedef struct _NLS_LOCALE_HEADER
{
    ULONG VersionOffset;
    ULONG Reserved0;
    ULONG Version;
    ULONG Magic;
    ULONG Reserved1[3];
    USHORT HeaderSize;
    USHORT LocaleIdCount;
    USHORT LocaleCount;
    USHORT LocaleDataSize;
    ULONG LocaleDataOffset;
    USHORT LocaleNameCount;
    USHORT Reserved2;
    ULONG LocaleIdIndexOffset;
    ULONG LocaleNameIndexOffset;
    ULONG Reserved3;
    USHORT CalendarCount;
    USHORT CalendarDataSize;
    ULONG CalendarDataOffset;
    ULONG StringTableOffset;
    USHORT Reserved4[4];
} NLS_LOCALE_HEADER, *PNLS_LOCALE_HEADER;
typedef const NLS_LOCALE_HEADER* PCNLS_LOCALE_HEADER;

/* phnt */

/* Data exports (ntdll.lib/ntdllp.lib) */
#if !defined(_KERNEL_MODE)
NTSYSAPI USHORT NlsAnsiCodePage;
NTSYSAPI BOOLEAN NlsMbCodePageTag;
NTSYSAPI BOOLEAN NlsMbOemCodePageTag;
#endif

_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtInitializeNlsFiles(
    _Out_ PVOID *BaseAddress,
    _Out_ PLCID DefaultLocaleId,
    _Out_opt_ PLARGE_INTEGER DefaultCasingTableSize);

_Kernel_entry_
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
_Kernel_entry_
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
_Kernel_entry_
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
_Kernel_entry_
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
_Kernel_entry_
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
_Kernel_entry_
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
_Kernel_entry_
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
_Kernel_entry_
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
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetDefaultUILanguage(
    _In_ LANGID DefaultUILanguageId);

/**
 * The NtIsUILanguageComitted routine determines whether the system UI language has been committed.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtIsUILanguageComitted(VOID);

#pragma endregion phnt

EXTERN_C_END

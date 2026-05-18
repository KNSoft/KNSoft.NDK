#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

// rev
typedef struct _RTL_OSVERSIONINFOEX2
{
    ULONG OSVersionInfoSize;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG BuildNumber;
    ULONG PlatformId;
    WCHAR CSDVersion[128];
    USHORT ServicePackMajor;
    USHORT ServicePackMinor;
    USHORT SuiteMask;
    UCHAR ProductType;
    UCHAR Reserved;
    ULONG SuiteMaskEx;
    ULONG Reserved2;
} RTL_OSVERSIONINFOEX2, *PRTL_OSVERSIONINFOEX2;

// rev
//
// Input:
// - OSVersionInfoSize must be set to sizeof(RTL_OSVERSIONINFOEX3).
// - Input.LayerNumber selects which build layer to query.
// - Input.AttribSelector selects which attribute to return for that layer.
//
// Output:
// - MajorVersion/MinorVersion/BuildNumber identify the selected layer.
// - LayerAttrib contains the string for the selected attribute.
// - LayerCount returns the number of available build layers.
// - LayerFlags contains per-layer flags; bit 0 is top-level and bit 1 is checked.

#define RTL_OSVERSIONINFO_ATTRIB_LAYER_NAME    0
#define RTL_OSVERSIONINFO_ATTRIB_BUILD_STAMP   1
#define RTL_OSVERSIONINFO_ATTRIB_BUILD_BRANCH  2 // HKLM\Software\Microsoft\Windows NT\CurrentVersion\BuildBranch
#define RTL_OSVERSIONINFO_ATTRIB_BUILD_ARCH    3
#define RTL_OSVERSIONINFO_ATTRIB_BUILD_LAB     4 // HKLM\Software\Microsoft\Windows NT\CurrentVersion\BuildLab
#define RTL_OSVERSIONINFO_ATTRIB_BUILD_LAB_EX  5 // HKLM\Software\Microsoft\Windows NT\CurrentVersion\BuildLabEx

/**
 * Further-extended operating system version information used by newer
 * Windows builds.
 */
typedef struct _RTL_OSVERSIONINFOEX3
{
    //
    // Input: Set to sizeof(RTL_OSVERSIONINFOEX3) before calling RtlGetVersion.
    //
    ULONG OSVersionInfoSize;

    //
    // Output: Version numbers for the selected build layer.
    //
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG BuildNumber;

    //
    // Output: A QFE/build-layer numeric field.
    //
    union
    {
        ULONG PlatformId;
        ULONG QfeNumber;
    };

    //
    // Output: Contains the string for the selected attribute.
    //
    union
    {
        WCHAR CSDVersion[128];
        WCHAR LayerAttrib[128];
    };

    //
    // Output: Operating system version information
    //
    USHORT ServicePackMajor;
    USHORT ServicePackMinor;
    USHORT SuiteMask;
    UCHAR ProductType;
    UCHAR Reserved;
    ULONG SuiteMaskEx;
    ULONG Reserved2;

    //
    // Input LayerNumber:
    //   Which build layer to query, in the range [0, LayerCount).
    //
    // Input AttribSelector:
    //   Which value to retrieve for that layer:
    //     0 = layer display name
    //     1 = BuildStamp
    //     2 = BuildBranch
    //     3 = BuildArch
    //     4 = BuildLab
    //     5 = BuildLabEx
    //
    union
    {
        USHORT RawInput16;
        struct
        {
            USHORT LayerNumber : 12;
            USHORT AttribSelector : 4;
        };
    } Input;

    //
    // Output: total number of available build layers.
    //
    USHORT LayerCount;

    //
    // Output: flags for the selected layer.
    //
    union
    {
        ULONG LayerFlags;
        struct
        {
            ULONG IsTopLevel : 1;
            ULONG IsChecked : 1;
            ULONG Spare : 30;
        };
    };
} RTL_OSVERSIONINFOEX3, *PRTL_OSVERSIONINFOEX3;

/* wdm.h */

NTSYSAPI
NTSTATUS
NTAPI
RtlGetVersion(
    _Out_
    _At_(lpVersionInformation->dwOSVersionInfoSize, _Pre_ _Valid_)
    _When_(lpVersionInformation->dwOSVersionInfoSize == sizeof(RTL_OSVERSIONINFOEXW),
           _At_((PRTL_OSVERSIONINFOEXW)lpVersionInformation, _Out_))
        PRTL_OSVERSIONINFOW lpVersionInformation);

/**
 * Compares specified operating system version requirements against the
 * currently running operating system.
 *
 * \param VersionInformation A pointer to an RTL_OSVERSIONINFOEX-compatible
 * structure that describes the required operating system attributes.
 * \param TypeMask A bitwise OR of VER_* flags that selects which members of
 * VersionInformation participate in the comparison.
 * \param ConditionMask A comparison mask built with VER_SET_CONDITION that
 * specifies how each selected member is compared.
 * \return STATUS_SUCCESS if the current operating system satisfies the
 * specified requirements, STATUS_INVALID_PARAMETER for invalid input, or
 * STATUS_REVISION_MISMATCH if the version check fails.
 * \remarks This routine is the native equivalent of VerifyVersionInfo. It is
 * intended for version and feature gating, and is more reliable than comparing
 * major/minor version numbers alone. Version comparisons for major version,
 * minor version, and service pack fields are evaluated sequentially, so a
 * higher major version satisfies the check without testing lower-order fields.
 * To verify a version range, call RtlVerifyVersionInfo separately for the lower
 * and upper bounds.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlverifyversioninfo
 */
_Must_inspect_result_
NTSYSAPI
NTSTATUS
NTAPI
RtlVerifyVersionInfo(
    _In_ PRTL_OSVERSIONINFOEXW VersionInfo,
    _In_ ULONG TypeMask,
    _In_ ULONGLONG  ConditionMask);

/* ntddk.h */

/**
 * The RtlGetEnabledExtendedFeatures routine returns a mask of extended processor features that are enabled by the system.
 *
 * \param FeatureMask A 64-bit feature mask. This parameter indicates a set of extended processor features for which the caller
 * requests information about whether the features are enabled.
 * \return A 64-bitmask of enabled extended processor features. The routine calculates this mask as the intersection (bitwise AND)
 * between all enabled features and the value of the FeatureMask parameter.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlgetenabledextendedfeatures
 */
NTSYSAPI
ULONG64
NTAPI
RtlGetEnabledExtendedFeatures(
    _In_ ULONG64 FeatureMask);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
NTSYSAPI
BOOLEAN
NTAPI
RtlGetNtProductType(
    _Out_ PNT_PRODUCT_TYPE NtProductType);
#endif

// private
NTSYSAPI
BOOLEAN
NTAPI
RtlGetProductInfo(
    _In_ ULONG OSMajorVersion,
    _In_ ULONG OSMinorVersion,
    _In_ ULONG SpMajorVersion,
    _In_ ULONG SpMinorVersion,
    _Out_ PULONG ReturnedProductType);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
NTSYSAPI
ULONG
NTAPI
RtlGetSuiteMask(VOID);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlIsMultiSessionSku(VOID);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlIsMultiUsersInSessionSku(VOID);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
_Must_inspect_result_
NTSYSAPI
NTSTATUS
NTAPI
RtlIsApiSetImplemented(
    _In_ PCSTR apiSetName);
#endif

/* phnt */

NTSYSAPI
VOID
NTAPI
RtlGetNtVersionNumbers(
    _Out_opt_ PULONG NtMajorVersion,
    _Out_opt_ PULONG NtMinorVersion,
    _Out_opt_ PULONG NtBuildNumber);

NTSYSAPI
ULONG
NTAPI
RtlGetNtGlobalFlags(VOID);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
NTSYSAPI
BOOLEAN
NTAPI
RtlIsEnclaveFeaturePresent(
    _In_ ULONG FeatureMask);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10)
// rev
/**
 * The RtlIsProcessorFeaturePresent routine determines whether the specified processor feature is supported by the current computer.
 *
 * \param ProcessorFeature The processor feature to be tested.
 * \return If the feature is supported, the return value is a nonzero value.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsProcessorFeaturePresent(
    _In_ ULONG ProcessorFeature);
#endif

// rev
/**
 * The RtlGetCurrentProcessorNumber routine retrieves the number of the processor the current thread was running
 * on during the call to this function.
 *
 * \return The function returns the current processor number.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessornumber
 */
NTSYSAPI
ULONG
NTAPI
RtlGetCurrentProcessorNumber(VOID);

// rev
/**
 * The RtlGetCurrentProcessorNumberEx routine retrieves the processor group and number of the logical processor
 * in which the calling thread is running.
 *
 * \param ProcessorNumber A pointer to a PROCESSOR_NUMBER structure that receives the processor group and number
 * of the logical processor the calling thread is running.
 * \return This function does not return a value.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessornumberex
 */
NTSYSAPI
VOID
NTAPI
RtlGetCurrentProcessorNumberEx(
    _Out_ PPROCESSOR_NUMBER ProcessorNumber);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS4)

NTSYSAPI
ULONG64
NTAPI
RtlGetEnabledExtendedAndSupervisorFeatures(
    _In_ ULONG64 FeatureMask);

_Ret_maybenull_
_Success_(return != NULL)
NTSYSAPI
PVOID
NTAPI
RtlLocateSupervisorFeature(
    _In_ PXSAVE_AREA_HEADER XStateHeader,
    _In_range_(XSTATE_AVX, MAXIMUM_XSTATE_FEATURES - 1) ULONG FeatureId,
    _Out_opt_ PULONG Length);

#endif

#define ELEVATION_FLAG_TOKEN_CHECKS 0x00000001
#define ELEVATION_FLAG_VIRTUALIZATION 0x00000002
#define ELEVATION_FLAG_SHORTCUT_REDIR 0x00000004
#define ELEVATION_FLAG_NO_SIGNATURE_CHECK 0x00000008

// private
typedef struct _RTL_ELEVATION_FLAGS
{
    union
    {
        ULONG Flags;
        struct
        {
            ULONG ElevationEnabled : 1;
            ULONG VirtualizationEnabled : 1;
            ULONG InstallerDetectEnabled : 1;
            ULONG AdminApprovalModeType : 2;
            ULONG ReservedBits : 27;
        };
    };
} RTL_ELEVATION_FLAGS, *PRTL_ELEVATION_FLAGS;

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryElevationFlags(
    _Out_ PRTL_ELEVATION_FLAGS Flags);

EXTERN_C_END

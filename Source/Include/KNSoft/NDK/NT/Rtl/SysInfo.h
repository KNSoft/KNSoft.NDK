#pragma once

#include "../MinDef.h"

EXTERN_C_START

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

_Must_inspect_result_
NTSYSAPI
NTSTATUS
NTAPI
RtlVerifyVersionInfo(
    _In_ PRTL_OSVERSIONINFOEXW VersionInfo,
    _In_ ULONG TypeMask,
    _In_ ULONGLONG  ConditionMask);

/* ntddk.h */

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTSYSAPI
ULONG64
NTAPI
RtlGetEnabledExtendedFeatures(
    _In_ ULONG64 FeatureMask);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
NTSYSAPI
BOOLEAN
NTAPI
RtlGetNtProductType(
    _Out_ PNT_PRODUCT_TYPE NtProductType);
#endif

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
NTSYSAPI
BOOLEAN
NTAPI
RtlIsProcessorFeaturePresent(
    _In_ ULONG ProcessorFeature);
#endif

NTSYSAPI
ULONG
NTAPI
RtlGetCurrentProcessorNumber(VOID);

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

typedef union _RTL_ELEVATION_FLAGS
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
} RTL_ELEVATION_FLAGS, *PRTL_ELEVATION_FLAGS;

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryElevationFlags(
    _Out_ PRTL_ELEVATION_FLAGS Flags);

EXTERN_C_END

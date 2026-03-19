#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

typedef enum _RTL_BSD_ITEM_TYPE
{
    RtlBsdItemVersionNumber,                    // qs: ULONG
    RtlBsdItemProductType,                      // qs: NT_PRODUCT_TYPE (ULONG)
    RtlBsdItemAabEnabled,                       // qs: BOOLEAN // AutoAdvancedBoot
    RtlBsdItemAabTimeout,                       // qs: UCHAR // AdvancedBootMenuTimeout
    RtlBsdItemBootGood,                         // qs: BOOLEAN // LastBootSucceeded
    RtlBsdItemBootShutdown,                     // qs: BOOLEAN // LastBootShutdown
    RtlBsdSleepInProgress,                      // qs: BOOLEAN // SleepInProgress
    RtlBsdPowerTransition,                      // qs: RTL_BSD_DATA_POWER_TRANSITION
    RtlBsdItemBootAttemptCount,                 // qs: UCHAR // BootAttemptCount
    RtlBsdItemBootCheckpoint,                   // qs: UCHAR // LastBootCheckpoint
    RtlBsdItemBootId,                           // qs: ULONG (USER_SHARED_DATA->BootId) // 10
    RtlBsdItemShutdownBootId,                   // qs: ULONG
    RtlBsdItemReportedAbnormalShutdownBootId,   // qs: ULONG
    RtlBsdItemErrorInfo,                        // qs: RTL_BSD_DATA_ERROR_INFO
    RtlBsdItemPowerButtonPressInfo,             // qs: RTL_BSD_POWER_BUTTON_PRESS_INFO
    RtlBsdItemChecksum,                         // q: UCHAR
    RtlBsdPowerTransitionExtension,             // qs: RTL_BSD_DATA_POWER_TRANSITION_EXTENSION
    RtlBsdItemFeatureConfigurationState,        // qs: ULONG
    RtlBsdItemRevocationListInfo,               // qs: RTL_BSD_ITEM_REVOCATION_LIST // 24H2
    RtlBsdItemMax
} RTL_BSD_ITEM_TYPE;

typedef struct _RTL_BSD_DATA_POWER_TRANSITION
{
    UCHAR PowerButton : 1;
    UCHAR SleepButton : 1;
    UCHAR LidClose : 1;
    UCHAR SystemIdle : 1;
    UCHAR UserPresent : 1;
    UCHAR ApmBattery : 1;
    UCHAR Reserved : 2;
} RTL_BSD_DATA_POWER_TRANSITION, *PRTL_BSD_DATA_POWER_TRANSITION;

typedef struct _RTL_BSD_DATA_ERROR_INFO
{
    ULONG BootId;
    ULONG RepeatCount;
    ULONG OtherErrorCount;
} RTL_BSD_DATA_ERROR_INFO, *PRTL_BSD_DATA_ERROR_INFO;

typedef struct _RTL_BSD_POWER_BUTTON_PRESS_INFO
{
    ULONG LastPressBootId;
    ULONG LastPressTime;
    ULONG LastReleaseTime;
    ULONG ButtonPressCount;
    ULONG CoalescedPressTime;
    ULONG CoalescedPressCount;
} RTL_BSD_POWER_BUTTON_PRESS_INFO, *PRTL_BSD_POWER_BUTTON_PRESS_INFO;

typedef struct _RTL_BSD_DATA_POWER_TRANSITION_EXTENSION
{
    UCHAR SystemIdleTransition : 1;
    UCHAR FanError : 1;
    UCHAR ThermalShutdown : 1;
    UCHAR Reserved : 5;
} RTL_BSD_DATA_POWER_TRANSITION_EXTENSION, *PRTL_BSD_DATA_POWER_TRANSITION_EXTENSION;

typedef struct _RTL_BSD_ITEM
{
    RTL_BSD_ITEM_TYPE Type;
    PVOID DataBuffer;
    ULONG DataLength;
} RTL_BSD_ITEM, *PRTL_BSD_ITEM;

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateBootStatusDataFile(VOID);

NTSYSAPI
NTSTATUS
NTAPI
RtlLockBootStatusData(
    _Out_ PHANDLE FileHandle);

NTSYSAPI
NTSTATUS
NTAPI
RtlUnlockBootStatusData(
    _In_ HANDLE FileHandle);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetSetBootStatusData(
    _In_ HANDLE FileHandle,
    _In_ BOOLEAN Read,
    _In_ RTL_BSD_ITEM_TYPE DataClass,
    _In_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG ReturnLength);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)

NTSYSAPI
NTSTATUS
NTAPI
RtlCheckBootStatusIntegrity(
    _In_ HANDLE FileHandle,
    _Out_ PBOOLEAN Verified);

NTSYSAPI
NTSTATUS
NTAPI
RtlRestoreBootStatusDefaults(
    _In_ HANDLE FileHandle);

#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS3)

NTSYSAPI
NTSTATUS
NTAPI
RtlRestoreSystemBootStatusDefaults(VOID);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetSystemBootStatus(
    _In_ RTL_BSD_ITEM_TYPE BootStatusInformationClass,
    _Out_ PVOID DataBuffer,
    _In_ ULONG DataLength,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetSystemBootStatus(
    _In_ RTL_BSD_ITEM_TYPE BootStatusInformationClass,
    _In_ PVOID DataBuffer,
    _In_ ULONG DataLength,
    _Out_opt_ PULONG ReturnLength);

#endif

#if (NTDDI_VERSION >= NTDDI_WIN8)

NTSYSAPI
NTSTATUS
NTAPI
RtlCheckPortableOperatingSystem(
    _Out_ PBOOLEAN IsPortable);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetPortableOperatingSystem(
    _In_ BOOLEAN IsPortable);

#endif

EXTERN_C_END

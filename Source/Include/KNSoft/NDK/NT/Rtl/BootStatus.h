#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

/**
 * Identifies an item stored in the Boot Status Data (BSD).
 */
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

/**
 * Describes a power transition record stored in the Boot Status Data.
 */
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

/**
 * Describes boot error information stored in the Boot Status Data.
 */
typedef struct _RTL_BSD_DATA_ERROR_INFO
{
    ULONG BootId;
    ULONG RepeatCount;
    ULONG OtherErrorCount;
} RTL_BSD_DATA_ERROR_INFO, *PRTL_BSD_DATA_ERROR_INFO;

/**
 * Describes power button press information stored in the Boot Status Data.
 */
typedef struct _RTL_BSD_POWER_BUTTON_PRESS_INFO
{
    ULONG LastPressBootId;
    ULONG LastPressTime;
    ULONG LastReleaseTime;
    ULONG ButtonPressCount;
    ULONG CoalescedPressTime;
    ULONG CoalescedPressCount;
} RTL_BSD_POWER_BUTTON_PRESS_INFO, *PRTL_BSD_POWER_BUTTON_PRESS_INFO;

/**
 * Extends a Boot Status Data power transition record with additional fields.
 */
typedef struct _RTL_BSD_DATA_POWER_TRANSITION_EXTENSION
{
    UCHAR SystemIdleTransition : 1;
    UCHAR FanError : 1;
    UCHAR ThermalShutdown : 1;
    UCHAR Reserved : 5;
} RTL_BSD_DATA_POWER_TRANSITION_EXTENSION, *PRTL_BSD_DATA_POWER_TRANSITION_EXTENSION;

/**
 * Represents an item read from or written to the Boot Status Data.
 */
typedef struct _RTL_BSD_ITEM
{
    RTL_BSD_ITEM_TYPE Type;
    PVOID DataBuffer;
    ULONG DataLength;
} RTL_BSD_ITEM, *PRTL_BSD_ITEM;

/**
 * The RtlCreateBootStatusDataFile routine creates the boot status data file used to track boot progress and recovery
 * state.
 *
 * \param BootStatusFileName An optional path to the boot status data file.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateBootStatusDataFile(
    _In_opt_ PCWSTR BootStatusFileName
    );

/**
 * The RtlLockBootStatusData routine opens and locks the boot status data file for access.
 *
 * \param FileHandle A pointer to a variable that receives a handle to the locked boot status data file. The caller
 * releases it with RtlUnlockBootStatusData.
 * \return NTSTATUS Successful or errant status.
 */
_Acquires_lock_(*FileHandle)
NTSYSAPI
NTSTATUS
NTAPI
RtlLockBootStatusData(
    _Out_ PHANDLE FileHandle);

/**
 * The RtlUnlockBootStatusData routine unlocks and closes the boot status data file previously locked by
 * RtlLockBootStatusData.
 *
 * \param FileHandle A handle to the boot status data file returned by RtlLockBootStatusData.
 * \return NTSTATUS Successful or errant status.
 */
_Releases_lock_(FileHandle)
NTSYSAPI
NTSTATUS
NTAPI
RtlUnlockBootStatusData(
    _In_ HANDLE FileHandle);

/**
 * The RtlGetSetBootStatusData routine reads or writes an item of boot status data (BSD) using an open BSD file handle.
 *
 * \param FileHandle A handle to the boot status data file.
 * \param Read TRUE to read the item; FALSE to write it.
 * \param DataClass The boot status item to read or write.
 * \param Buffer A buffer that receives or supplies the item data.
 * \param BufferSize The size, in bytes, of Buffer.
 * \param ReturnLength An optional pointer that receives the number of bytes transferred.
 * \return NTSTATUS Successful or errant status.
 */
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

/**
 * The RtlCheckBootStatusIntegrity routine verifies the integrity of the boot status data file.
 *
 * \param FileHandle A handle to the boot status data file returned by RtlLockBootStatusData.
 * \param Verified A pointer to a variable that receives whether the boot status data integrity was verified.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCheckBootStatusIntegrity(
    _In_ HANDLE FileHandle,
    _Out_ PBOOLEAN Verified);

/**
 * The RtlRestoreBootStatusDefaults routine restores the boot status data file to its default values.
 *
 * \param FileHandle A handle to the boot status data file returned by RtlLockBootStatusData.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlRestoreBootStatusDefaults(
    _In_ HANDLE FileHandle);

#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS3)

/**
 * The RtlRestoreSystemBootStatusDefaults routine restores the system boot status data to its default values.
 *
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlRestoreSystemBootStatusDefaults(VOID);

/**
 * The RtlGetSystemBootStatus routine retrieves an item of boot status data (BSD).
 *
 * \param BootStatusInformationClass The boot status item to retrieve.
 * \param DataBuffer A buffer that receives the item data.
 * \param DataLength The size, in bytes, of the buffer.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetSystemBootStatus(
    _In_ RTL_BSD_ITEM_TYPE BootStatusInformationClass,
    _Out_ PVOID DataBuffer,
    _In_ ULONG DataLength,
    _Out_opt_ PULONG ReturnLength);

/**
 * The RtlSetSystemBootStatus routine sets an item of boot status data (BSD).
 *
 * \param BootStatusInformationClass The boot status item to set.
 * \param DataBuffer A buffer containing the item data to set.
 * \param DataLength The size, in bytes, of the buffer.
 * \return NTSTATUS Successful or errant status.
 */
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

/**
 * The RtlCheckPortableOperatingSystem routine determines whether the operating system is running as a portable (Windows
 * To Go) installation.
 *
 * \param IsPortable A pointer to a variable that receives whether the operating system is portable.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCheckPortableOperatingSystem(
    _Out_ PBOOLEAN IsPortable);

/**
 * The RtlSetPortableOperatingSystem routine sets whether the operating system is marked as a portable (Windows To Go)
 * installation.
 *
 * \param IsPortable Set to `TRUE` to mark the operating system as portable, or `FALSE` otherwise.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetPortableOperatingSystem(
    _In_ BOOLEAN IsPortable);

#endif

// RtlCheckSystemBootStatusIntegrity
/**
 * The RtlCheckSystemBootStatusIntegrity routine validates the integrity of the boot status data (BSD) context.
 *
 * \param BootStatusContext The boot status data context to validate.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCheckSystemBootStatusIntegrity(
    _In_ PVOID BootStatusContext
    );

// RtlGetSystemBootStatusEx
/**
 * The RtlGetSystemBootStatusEx routine retrieves extended boot status data (BSD) information.
 *
 * \param Buffer A buffer that receives the boot status data.
 * \param BufferLength The size, in bytes, of the buffer.
 * \param ReturnLength An optional pointer to a variable that receives the number of bytes returned.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetSystemBootStatusEx(
    _Out_writes_bytes_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength,
    _Out_opt_ PULONG ReturnLength
    );

// RtlSetSystemBootStatusEx
/**
 * The RtlSetSystemBootStatusEx routine sets extended boot status data (BSD) information.
 *
 * \param Buffer A buffer containing the boot status data to set.
 * \param BufferLength The size, in bytes, of the buffer.
 * \param Reserved Reserved; must be NULL.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetSystemBootStatusEx(
    _In_ PVOID Buffer,
    _In_ ULONG BufferLength,
    _In_opt_ PVOID Reserved
    );


EXTERN_C_END

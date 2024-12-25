#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* treevariableservice.h & UEFI Specification & phnt */

// The firmware environment variable is stored in non-volatile memory (e.g. NVRAM).
#define EFI_VARIABLE_NON_VOLATILE                           0x00000001
// The firmware environment variable can be accessed during boot service.
#define EFI_VARIABLE_BOOTSERVICE_ACCESS                     0x00000002
// The firmware environment variable can be accessed at runtime.
#define EFI_VARIABLE_RUNTIME_ACCESS                         0x00000004
// Indicates hardware related errors encountered at runtime.
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD                  0x00000008
// Indicates an authentication requirement that must be met before writing to this firmware environment variable.
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS             0x00000010
// Indicates authentication and time stamp requirements that must be met before writing to this firmware environment variable.
// When this attribute is set, the buffer, represented by Buffer, will begin with an instance of a complete (and serialized) EFI_VARIABLE_AUTHENTICATION_2 descriptor.
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS  0x00000020
// Append an existing environment variable with the value of Buffer. If the firmware does not support the operation, the function returns ERROR_INVALID_FUNCTION.
#define EFI_VARIABLE_APPEND_WRITE                           0x00000040
// The firmware environment variable will return metadata in addition to variable data.
#define EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS          0x00000080

/**
 * Retrieves the value of the specified firmware environment variable.
 * The user account that the app is running under must have the SE_SYSTEM_ENVIRONMENT_NAME privilege.
 *
 * @param VariableName The name of the firmware environment variable. The pointer must not be NULL.
 * @param VariableValue A pointer to a buffer that receives the value of the specified firmware environment variable.
 * @param ValueLength The size of the \c VariableValue buffer, in bytes.
 * @param ReturnLength If the function succeeds, the return length is the number of bytes stored in the \c VariableValue buffer.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySystemEnvironmentValue(
    _In_ PUNICODE_STRING VariableName,
    _Out_writes_bytes_(ValueLength) PWSTR VariableValue,
    _In_ USHORT ValueLength,
    _Out_opt_ PUSHORT ReturnLength);

/**
 * Retrieves the value of the specified firmware environment variable and its attributes.
 * The user account that the app is running under must have the SE_SYSTEM_ENVIRONMENT_NAME privilege.
 *
 * @param VariableName The name of the firmware environment variable. The pointer must not be NULL.
 * @param VendorGuid The GUID that represents the namespace of the firmware environment variable.
 * @param Buffer A pointer to a buffer that receives the value of the specified firmware environment variable.
 * @param BufferLength The size of the \c Buffer, in bytes.
 * @param Attributes Bitmask identifying UEFI variable attributes associated with the variable.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySystemEnvironmentValueEx(
    _In_ PUNICODE_STRING VariableName,
    _In_ PCGUID VendorGuid,
    _Out_writes_bytes_opt_(*BufferLength) PVOID Buffer,
    _Inout_ PULONG BufferLength,
    _Out_opt_ PULONG Attributes // EFI_VARIABLE_*
);

/**
 * Sets the value of the specified firmware environment variable.
 * The user account that the app is running under must have the SE_SYSTEM_ENVIRONMENT_NAME privilege.
 *
 * @param VariableName The name of the firmware environment variable. The pointer must not be NULL.
 * @param VariableValue A pointer to the new value for the firmware environment variable.
 * If this parameter is zero, the firmware environment variable is deleted.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetSystemEnvironmentValue(
    _In_ PUNICODE_STRING VariableName,
    _In_ PUNICODE_STRING VariableValue);

/**
 * Sets the value of the specified firmware environment variable and the attributes that indicate how this variable is stored and maintained.
 * The user account that the app is running under must have the SE_SYSTEM_ENVIRONMENT_NAME privilege.
 *
 * @param VariableName The name of the firmware environment variable. The pointer must not be NULL.
 * @param VendorGuid The GUID that represents the namespace of the firmware environment variable.
 * @param Buffer A pointer to the new value for the firmware environment variable.
 * @param BufferLength The size of the pValue buffer, in bytes.
 * Unless the VARIABLE_ATTRIBUTE_APPEND_WRITE, VARIABLE_ATTRIBUTE_AUTHENTICATED_WRITE_ACCESS,
 * or VARIABLE_ATTRIBUTE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS variable attribute is set via dwAttributes,
 * setting this value to zero will result in the deletion of this variable.
 * @param Attributes Bitmask to set UEFI variable attributes associated with the variable.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetSystemEnvironmentValueEx(
    _In_ PUNICODE_STRING VariableName,
    _In_ PCGUID VendorGuid,
    _In_reads_bytes_opt_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength, // 0 = delete variable
    _In_ ULONG Attributes // EFI_VARIABLE_*
);

typedef enum _SYSTEM_ENVIRONMENT_INFORMATION_CLASS
{
    SystemEnvironmentNameInformation = 1, // q: VARIABLE_NAME
    SystemEnvironmentValueInformation = 2, // q: VARIABLE_NAME_AND_VALUE
    MaxSystemEnvironmentInfoClass
} SYSTEM_ENVIRONMENT_INFORMATION_CLASS;

typedef struct _VARIABLE_NAME
{
    ULONG NextEntryOffset;
    GUID VendorGuid;
    WCHAR Name[ANYSIZE_ARRAY];
} VARIABLE_NAME, *PVARIABLE_NAME;

typedef struct _VARIABLE_NAME_AND_VALUE
{
    ULONG NextEntryOffset;
    ULONG ValueOffset;
    ULONG ValueLength;
    ULONG Attributes;
    GUID VendorGuid;
    WCHAR Name[ANYSIZE_ARRAY];
    //BYTE Value[ANYSIZE_ARRAY];
} VARIABLE_NAME_AND_VALUE, *PVARIABLE_NAME_AND_VALUE;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtEnumerateSystemEnvironmentValuesEx(
    _In_ ULONG InformationClass, // SYSTEM_ENVIRONMENT_INFORMATION_CLASS
    _Out_ PVOID Buffer,
    _Inout_ PULONG BufferLength);

typedef struct _BOOT_ENTRY
{
    ULONG Version;
    ULONG Length;
    ULONG Id;
    ULONG Attributes;
    ULONG FriendlyNameOffset;
    ULONG BootFilePathOffset;
    ULONG OsOptionsLength;
    _Field_size_bytes_(OsOptionsLength) UCHAR OsOptions[ANYSIZE_ARRAY];
} BOOT_ENTRY, *PBOOT_ENTRY;

typedef struct _BOOT_ENTRY_LIST
{
    ULONG NextEntryOffset;
    BOOT_ENTRY BootEntry;
} BOOT_ENTRY_LIST, *PBOOT_ENTRY_LIST;

typedef struct _BOOT_OPTIONS
{
    ULONG Version;
    ULONG Length;
    ULONG Timeout;
    ULONG CurrentBootEntryId;
    ULONG NextBootEntryId;
    WCHAR HeadlessRedirection[1];
} BOOT_OPTIONS, *PBOOT_OPTIONS;

typedef struct _FILE_PATH
{
    ULONG Version;
    ULONG Length;
    ULONG Type;
    _Field_size_bytes_(Length) UCHAR FilePath[ANYSIZE_ARRAY];
} FILE_PATH, *PFILE_PATH;

typedef struct _EFI_DRIVER_ENTRY
{
    ULONG Version;
    ULONG Length;
    ULONG Id;
    ULONG FriendlyNameOffset;
    ULONG DriverFilePathOffset;
} EFI_DRIVER_ENTRY, *PEFI_DRIVER_ENTRY;

typedef struct _EFI_DRIVER_ENTRY_LIST
{
    ULONG NextEntryOffset;
    EFI_DRIVER_ENTRY DriverEntry;
} EFI_DRIVER_ENTRY_LIST, *PEFI_DRIVER_ENTRY_LIST;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAddBootEntry(
    _In_ PBOOT_ENTRY BootEntry,
    _Out_opt_ PULONG Id);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDeleteBootEntry(
    _In_ ULONG Id);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtModifyBootEntry(
    _In_ PBOOT_ENTRY BootEntry);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtEnumerateBootEntries(
    _Out_writes_bytes_opt_(*BufferLength) PVOID Buffer,
    _Inout_ PULONG BufferLength);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryBootEntryOrder(
    _Out_writes_opt_(*Count) PULONG Ids,
    _Inout_ PULONG Count);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetBootEntryOrder(
    _In_reads_(Count) PULONG Ids,
    _In_ ULONG Count);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryBootOptions(
    _Out_writes_bytes_opt_(*BootOptionsLength) PBOOT_OPTIONS BootOptions,
    _Inout_ PULONG BootOptionsLength);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetBootOptions(
    _In_ PBOOT_OPTIONS BootOptions,
    _In_ ULONG FieldsToChange);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtTranslateFilePath(
    _In_ PFILE_PATH InputFilePath,
    _In_ ULONG OutputType,
    _Out_writes_bytes_opt_(*OutputFilePathLength) PFILE_PATH OutputFilePath,
    _Inout_opt_ PULONG OutputFilePathLength);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAddDriverEntry(
    _In_ PEFI_DRIVER_ENTRY DriverEntry,
    _Out_opt_ PULONG Id);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDeleteDriverEntry(
    _In_ ULONG Id);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtModifyDriverEntry(
    _In_ PEFI_DRIVER_ENTRY DriverEntry);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtEnumerateDriverEntries(
    _Out_writes_bytes_opt_(*BufferLength) PVOID Buffer,
    _Inout_ PULONG BufferLength);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryDriverEntryOrder(
    _Out_writes_opt_(*Count) PULONG Ids,
    _Inout_ PULONG Count);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetDriverEntryOrder(
    _In_reads_(Count) PULONG Ids,
    _In_ ULONG Count);

typedef enum _FILTER_BOOT_OPTION_OPERATION
{
    FilterBootOptionOperationOpenSystemStore,
    FilterBootOptionOperationSetElement,
    FilterBootOptionOperationDeleteElement,
    FilterBootOptionOperationMax
} FILTER_BOOT_OPTION_OPERATION;

#if (NTDDI_VERSION >= NTDDI_WIN8)
NTSYSCALLAPI
NTSTATUS
NTAPI
NtFilterBootOption(
    _In_ FILTER_BOOT_OPTION_OPERATION FilterOperation,
    _In_ ULONG ObjectType,
    _In_ ULONG ElementType,
    _In_reads_bytes_opt_(DataSize) PVOID Data,
    _In_ ULONG DataSize);
#endif

typedef enum _SHUTDOWN_ACTION
{
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff,
    ShutdownRebootForRecovery // since WIN11
} SHUTDOWN_ACTION;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtShutdownSystem(
    _In_ SHUTDOWN_ACTION Action);

#pragma region Boot Display

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDisplayString(
    _In_ PUNICODE_STRING String);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDrawText(
    _In_ PUNICODE_STRING Text);

#pragma endregion

EXTERN_C_END

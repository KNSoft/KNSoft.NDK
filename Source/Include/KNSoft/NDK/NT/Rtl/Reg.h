#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

typedef struct _RTL_MUI_REGISTRY_INFO RTL_MUI_REGISTRY_INFO, *PRTL_MUI_REGISTRY_INFO;

/**
 * The RtlFormatCurrentUserKeyPath routine builds the registry path of the current user's key under HKEY_USERS.
 *
 * \param CurrentUserKeyPath A pointer to a UNICODE_STRING that receives the allocated current-user key path.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlFormatCurrentUserKeyPath(
    _Out_ PUNICODE_STRING CurrentUserKeyPath
);

/**
 * The RtlOpenCurrentUser routine opens the registry key for the current user (equivalent to HKEY_CURRENT_USER).
 *
 * \param DesiredAccess The access mask requested on the key.
 * \param CurrentUserKey A pointer to a variable that receives the handle to the opened key.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlOpenCurrentUser(
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE CurrentUserKey
);

/**
 * Registry path base and flag values for RtlQueryRegistryValues and related routines.
 */
#define RTL_REGISTRY_ABSOLUTE 0
#define RTL_REGISTRY_SERVICES 1 // \Registry\Machine\System\CurrentControlSet\Services
#define RTL_REGISTRY_CONTROL 2 // \Registry\Machine\System\CurrentControlSet\Control
#define RTL_REGISTRY_WINDOWS_NT 3 // \Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion
#define RTL_REGISTRY_DEVICEMAP 4 // \Registry\Machine\Hardware\DeviceMap
#define RTL_REGISTRY_USER 5 // \Registry\User\CurrentUser
#define RTL_REGISTRY_MAXIMUM 6
#define RTL_REGISTRY_HANDLE 0x40000000
#define RTL_REGISTRY_OPTIONAL 0x80000000

/**
 * The RtlCreateRegistryKey routine creates a registry key relative to one of the predefined RTL_REGISTRY_ locations.
 *
 * \param RelativeTo A flag that specifies the base location the Path is relative to.
 * \param Path A pointer to the null-terminated path of the key to create.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcreateregistrykey
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateRegistryKey(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path
);

/**
 * The RtlCheckRegistryKey routine determines whether a registry key exists relative to one of the predefined
 * RTL_REGISTRY_ locations.
 *
 * \param RelativeTo A flag that specifies the base location the Path is relative to.
 * \param Path A pointer to the null-terminated path of the key to check.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcheckregistrykey
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCheckRegistryKey(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path
);

_Function_class_(RTL_QUERY_REGISTRY_ROUTINE)
typedef NTSTATUS(NTAPI RTL_QUERY_REGISTRY_ROUTINE)(
    _In_ PCWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueLength,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID EntryContext
    );
/**
 * Pointer to an RTL_QUERY_REGISTRY_ROUTINE callback.
 */
typedef RTL_QUERY_REGISTRY_ROUTINE *PRTL_QUERY_REGISTRY_ROUTINE;

/**
 * Describes a registry value to be queried or enumerated by RtlQueryRegistryValues.
 */
typedef struct _RTL_QUERY_REGISTRY_TABLE
{
    PRTL_QUERY_REGISTRY_ROUTINE QueryRoutine;
    ULONG Flags;
    PWSTR Name;
    PVOID EntryContext;
    ULONG DefaultType;
    PVOID DefaultData;
    ULONG DefaultLength;
} RTL_QUERY_REGISTRY_TABLE, *PRTL_QUERY_REGISTRY_TABLE;

/**
 * Flags controlling RtlQueryRegistryValues behavior.
 */
#define RTL_QUERY_REGISTRY_SUBKEY 0x00000001
#define RTL_QUERY_REGISTRY_TOPKEY 0x00000002
#define RTL_QUERY_REGISTRY_REQUIRED 0x00000004
#define RTL_QUERY_REGISTRY_NOVALUE 0x00000008
#define RTL_QUERY_REGISTRY_NOEXPAND 0x00000010
#define RTL_QUERY_REGISTRY_DIRECT 0x00000020
#define RTL_QUERY_REGISTRY_DELETE 0x00000040
#define RTL_QUERY_REGISTRY_NOSTRING 0x00000080 // deprecated
#define RTL_QUERY_REGISTRY_TYPECHECK 0x00000100

/**
 * Constants for the registry value type-check field.
 */
#define RTL_QUERY_REGISTRY_TYPECHECK_SHIFT 24
#define RTL_QUERY_REGISTRY_TYPECHECK_MASK (0xff << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT)

/**
 * The RtlQueryRegistryValues routine queries multiple registry values in a single call using a query table.
 *
 * \param RelativeTo Specifies how Path is interpreted (RTL_REGISTRY_*).
 * \param Path The registry path to query, relative to RelativeTo.
 * \param QueryTable A table describing the values to query and their handlers.
 * \param Context An optional context value passed to the query-table callbacks.
 * \param Environment An optional environment block used to expand REG_EXPAND_SZ values.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryRegistryValues(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path,
    _Inout_ _At_(*(*QueryTable).EntryContext, _Pre_unknown_) PRTL_QUERY_REGISTRY_TABLE QueryTable,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID Environment
);

#if (NTDDI_VERSION >= NTDDI_WIN8)
/**
 * The RtlQueryRegistryValuesEx routine queries multiple registry values using a query table, with extended validation.
 *
 * \param RelativeTo Specifies how Path is interpreted (RTL_REGISTRY_*).
 * \param Path The registry path to query, relative to RelativeTo.
 * \param QueryTable A table describing the values to query and their handlers.
 * \param Context An optional context value passed to the query-table callbacks.
 * \param Environment An optional environment block used to expand REG_EXPAND_SZ values.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryRegistryValuesEx(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path,
    _Inout_ _At_(*(*QueryTable).EntryContext, _Pre_unknown_) PRTL_QUERY_REGISTRY_TABLE QueryTable,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID Environment
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS4)
/**
 * The RtlQueryRegistryValueWithFallback routine queries a registry value from a primary key, falling back to a
 * secondary key if absent.
 *
 * \param PrimaryHandle An optional handle to the primary key to query.
 * \param FallbackHandle An optional handle to the fallback key.
 * \param ValueName The name of the value to query.
 * \param ValueLength The size, in bytes, of the ValueData buffer.
 * \param ValueType An optional pointer that receives the value type (REG_*).
 * \param ValueData A buffer that receives the value data.
 * \param ResultLength Receives the size, in bytes, of the value data.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryRegistryValueWithFallback(
    _In_opt_ HANDLE PrimaryHandle,
    _In_opt_ HANDLE FallbackHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_ ULONG ValueLength,
    _Out_opt_ PULONG ValueType,
    _Out_writes_bytes_to_(ValueLength, *ResultLength) PVOID ValueData,
    _Out_range_(<= , ValueLength) PULONG ResultLength
);
#endif

/**
 * The RtlWriteRegistryValue routine writes a single registry value.
 *
 * \param RelativeTo Specifies how Path is interpreted (RTL_REGISTRY_*).
 * \param Path The registry path to write to, relative to RelativeTo.
 * \param ValueName The name of the value to write.
 * \param ValueType The type of the value (REG_*).
 * \param ValueData A buffer containing the value data to write.
 * \param ValueLength The size, in bytes, of ValueData.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlWriteRegistryValue(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path,
    _In_ PCWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueLength
);

/**
 * The RtlDeleteRegistryValue routine deletes a value from a registry key relative to one of the predefined
 * RTL_REGISTRY_ locations.
 *
 * \param RelativeTo A flag that specifies the base location the Path is relative to.
 * \param Path A pointer to the null-terminated path of the key that contains the value.
 * \param ValueName A pointer to the null-terminated name of the value to delete.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtldeleteregistryvalue
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteRegistryValue(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path,
    _In_ PCWSTR ValueName
);

typedef struct _RTL_RXACT_CONTEXT RTL_RXACT_CONTEXT, *PRTL_RXACT_CONTEXT;
// RtlpCleanupRegistryKeys
/**
 * The RtlpCleanupRegistryKeys routine removes stale MUI UI-language subkeys for the process, retaining only
 * the current/installed UI language, and invalidates cached MUI registry state.
 *
 * \details Enumerates the subkeys of
 * \\Registry\\Machine\\System\\CurrentControlSet\\Control\\MUI\\UILanguages and
 * collects those that are neither a currently installed language nor match the
 * system default UI language's culture name. Because keys cannot be deleted
 * during enumeration, the matching subkey handles are gathered into a growable
 * array and deleted in a second pass (NtDeleteKey + NtClose). If any key was
 * deleted, the process's cached MUI registry information (g_RegInfo) and TEB
 * language lists are released under RegistryInfoCritSect.
 * \return STATUS_SUCCESS on success; otherwise the first failing NTSTATUS
 * (e.g. STATUS_NO_MEMORY (0xC0000017), STATUS_UNSUCCESSFUL (0xC0000001)).
 * STATUS_NO_MORE_ENTRIES from the enumeration terminator is normalized to
 * STATUS_SUCCESS.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpCleanupRegistryKeys(
    VOID
    );

// RtlpCreateProcessRegistryInfo
/**
 * The RtlpCreateProcessRegistryInfo routine lazily creates and loads the process-wide MUI registry information cache,
 * returning a pointer to it.
 *
 * \details On first use, initializes \c g_RegInfo via \c RtlpMuiRegCreateAndLoadRegistryInfo under \c
 * RegistryInfoCritSect
 * using double-checked locking. Subsequent calls return the cached pointer without locking.
 * \param[out] RegistryInfo Optional. Receives the cached MUI registry-info pointer on success, or NULL on failure.
 * \return STATUS_SUCCESS on success; otherwise the status from the underlying load (e.g. STATUS_NO_MEMORY, 0xC0000017).
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpCreateProcessRegistryInfo(
    _Out_opt_ PRTL_MUI_REGISTRY_INFO *RegistryInfo
    );

// RtlpNtCreateKey
/**
 * The RtlpNtCreateKey routine is an internal helper that creates or opens a registry key using simplified parameters.
 *
 * \param KeyHandle A pointer to a variable that receives the handle to the created or opened key.
 * \param DesiredAccess The access mask requested on the key.
 * \param ObjectAttributes An optional pointer to the OBJECT_ATTRIBUTES that specify the key name and attributes.
 * \param CreateOptions Optional flags that control the creation of the key.
 * \param ValueType An optional value type associated with the key.
 * \param Disposition An optional pointer to a variable that receives whether the key was created or opened.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpNtCreateKey(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Inout_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ ULONG CreateOptions,
    _In_opt_ ULONG ValueType,
    _Out_opt_ PULONG Disposition
    );

// RtlpNtEnumerateSubKey
/**
 * The RtlpNtEnumerateSubKey routine is an internal helper that enumerates the subkeys of a registry key by index.
 *
 * \param KeyHandle A handle to the key whose subkeys are enumerated.
 * \param SubKeyName A pointer to a UNICODE_STRING that receives the name of the subkey.
 * \param Index The zero-based index of the subkey to retrieve.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpNtEnumerateSubKey(
    _In_ HANDLE KeyHandle,
    _Inout_ PCUNICODE_STRING SubKeyName,
    _In_ ULONG Index
    );

// RtlpNtMakeTemporaryKey
/**
 * The RtlpNtMakeTemporaryKey routine is an internal helper that marks a registry key as temporary so that it is deleted
 * when its last handle closes.
 *
 * \param KeyHandle A handle to the key to mark temporary.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpNtMakeTemporaryKey(
    _In_ HANDLE KeyHandle
    );

// RtlpNtOpenKey
/**
 * The RtlpNtOpenKey routine is an internal helper that opens a registry key using simplified parameters.
 *
 * \param KeyHandle A pointer to a variable that receives the handle to the opened key.
 * \param DesiredAccess The access mask requested on the key.
 * \param ObjectAttributes An optional pointer to the OBJECT_ATTRIBUTES that specify the key name and attributes.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpNtOpenKey(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Inout_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes
    );

// RtlpNtQueryValueKey
/**
 * The RtlpNtQueryValueKey routine queries the type and data of a registry key value (internal helper for the Rtl
 * registry APIs).
 *
 * \param KeyHandle A handle to the registry key.
 * \param Type An optional pointer to a variable that receives the value type (REG_*).
 * \param Data An optional buffer that receives the value data.
 * \param DataLength On input specifies the buffer size; on output receives the data size, in bytes.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpNtQueryValueKey(
    _In_ HANDLE KeyHandle,
    _Out_opt_ PULONG Type,
    _Out_writes_bytes_opt_(*DataLength) PVOID Data,
    _Inout_opt_ PINT DataLength
    );

// RtlpNtSetValueKey
/**
 * The RtlpNtSetValueKey routine sets the type and data of a registry key value (internal helper for the Rtl registry
 * APIs).
 *
 * \param KeyHandle A handle to the registry key.
 * \param Type The value type (REG_*).
 * \param Data An optional buffer containing the value data.
 * \param DataLength The size, in bytes, of Data.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpNtSetValueKey(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Type,
    _In_reads_bytes_opt_(DataLength) PVOID Data,
    _In_ ULONG DataLength
    );

// RtlAbortRXact
/**
 * The RtlAbortRXact routine aborts a registry transaction (RXact), discarding its pending changes.
 *
 * \param RxactContext The RXact context to abort.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAbortRXact(
    _Inout_ PRTL_RXACT_CONTEXT RxactContext
    );

// RtlAddActionToRXact
/**
 * The RtlAddActionToRXact routine adds a registry action to a registry transaction (RXACT) context.
 *
 * \param RxactContext A pointer to the RTL_RXACT_CONTEXT to modify.
 * \param ActionType The type of action to add.
 * \param Name A pointer to the Unicode string that names the registry key affected by the action.
 * \param Operation The operation code for the action.
 * \param Data An optional pointer to the data associated with the action.
 * \param DataSize The size, in bytes, of the data.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddActionToRXact(
    _Inout_ PRTL_RXACT_CONTEXT RxactContext,
    _In_ ULONG ActionType,
    _In_ const UNICODE_STRING *Name,
    _In_ ULONG Operation,
    _In_reads_bytes_opt_(DataSize) const VOID *Data,
    _In_ SIZE_T DataSize
    );

// RtlAddAttributeActionToRXact
/**
 * The RtlAddAttributeActionToRXact routine adds a registry value attribute action to a registry transaction (RXACT)
 * context.
 *
 * \param RxactContext A pointer to the RTL_RXACT_CONTEXT to modify.
 * \param ActionType The type of action to add.
 * \param KeyName A pointer to the Unicode string that names the registry key.
 * \param AttributeIndex The index of the attribute affected by the action.
 * \param ValueName A pointer to the Unicode string that names the registry value.
 * \param ValueType The type of the registry value.
 * \param Data An optional pointer to the data associated with the action.
 * \param DataSize The size, in bytes, of the data.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAttributeActionToRXact(
    _Inout_ PRTL_RXACT_CONTEXT RxactContext,
    _In_ ULONG ActionType,
    _In_ const UNICODE_STRING *KeyName,
    _In_ LONGLONG AttributeIndex,
    _In_ const UNICODE_STRING *ValueName,
    _In_ ULONG ValueType,
    _In_reads_bytes_opt_(DataSize) const VOID *Data,
    _In_ SIZE_T DataSize
    );

// RtlApplyRXact
/**
 * The RtlApplyRXact routine commits the actions accumulated in a registry transaction (RXACT) context and flushes the
 * affected keys.
 *
 * \param RxactContext A pointer to the RTL_RXACT_CONTEXT to commit.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlApplyRXact(
    _Inout_ PRTL_RXACT_CONTEXT RxactContext
    );

// RtlApplyRXactNoFlush
/**
 * The RtlApplyRXactNoFlush routine commits the actions accumulated in a registry transaction (RXACT) context without
 * flushing the affected keys.
 *
 * \param RxactContext A pointer to the RTL_RXACT_CONTEXT to commit.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlApplyRXactNoFlush(
    _Inout_ PRTL_RXACT_CONTEXT RxactContext
    );

// RtlInitializeRXact
//NTSYSAPI
//ULONG
//NTAPI
//RtlIncrementCorrelationVector(
//    _Inout_ PVOID CorrelationVector
//    );
//
//NTSYSAPI
//ULONG
//NTAPI
//RtlInitializeCorrelationVector(
//    _Inout_ PVOID CorrelationVector,
//    _In_ ULONG Version,
//    _In_ const GUID *Guid
//    );

// rev
/**
 * The RtlInitializeRXact routine initializes a registry transaction (RXACT) context rooted at a registry key.
 *
 * \param RootKeyHandle A handle to the registry key that serves as the transaction root.
 * \param CommitIfNecessary If TRUE, any pending transaction log found under the root key is committed during
 * initialization.
 * \param RxactContext A pointer to a variable that receives the initialized transaction context.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeRXact(
    _In_ HANDLE RootKeyHandle,
    _In_ BOOLEAN CommitIfNecessary,
    _Out_ PRTL_RXACT_CONTEXT *RxactContext
    );

// RtlStartRXact
/**
 * The RtlStartRXact routine begins a registry transaction (RXact), allocating and initializing its context.
 *
 * \param RxactContext The RXact context whose transaction buffer is allocated and initialized.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlStartRXact(
    _Inout_ PRTL_RXACT_CONTEXT RxactContext
    );


EXTERN_C_END

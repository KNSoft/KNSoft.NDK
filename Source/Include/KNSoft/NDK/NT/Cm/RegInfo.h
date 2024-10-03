#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

typedef enum _KEY_INFORMATION_CLASS
{
    KeyBasicInformation, // KEY_BASIC_INFORMATION
    KeyNodeInformation, // KEY_NODE_INFORMATION
    KeyFullInformation, // KEY_FULL_INFORMATION
    KeyNameInformation, // KEY_NAME_INFORMATION
    KeyCachedInformation, // KEY_CACHED_INFORMATION
    KeyFlagsInformation, // KEY_FLAGS_INFORMATION
    KeyVirtualizationInformation, // KEY_VIRTUALIZATION_INFORMATION
    KeyHandleTagsInformation, // KEY_HANDLE_TAGS_INFORMATION
    KeyTrustInformation, // KEY_TRUST_INFORMATION
    KeyLayerInformation, // KEY_LAYER_INFORMATION
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef struct _KEY_BASIC_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    _Field_size_bytes_(NameLength) WCHAR Name[ANYSIZE_ARRAY];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef struct _KEY_NODE_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG NameLength;
    _Field_size_bytes_(NameLength) WCHAR Name[ANYSIZE_ARRAY];
    // ...
    // WCHAR Class[1];
} KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

typedef struct _KEY_FULL_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG SubKeys;
    ULONG MaxNameLength;
    ULONG MaxClassLength;
    ULONG Values;
    ULONG MaxValueNameLength;
    ULONG MaxValueDataLength;
    WCHAR Class[1];
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

typedef struct _KEY_NAME_INFORMATION
{
    ULONG NameLength;
    _Field_size_bytes_(NameLength) WCHAR Name[ANYSIZE_ARRAY];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef struct _KEY_CACHED_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG SubKeys;
    ULONG MaxNameLength;
    ULONG Values;
    ULONG MaxValueNameLength;
    ULONG MaxValueDataLength;
    ULONG NameLength;
    _Field_size_bytes_(NameLength) WCHAR Name[ANYSIZE_ARRAY];
} KEY_CACHED_INFORMATION, *PKEY_CACHED_INFORMATION;

#define REG_FLAG_VOLATILE 0x0001
#define REG_FLAG_LINK 0x0002

#define REG_KEY_DONT_VIRTUALIZE 0x0002
#define REG_KEY_DONT_SILENT_FAIL 0x0004
#define REG_KEY_RECURSE_FLAG 0x0008

typedef struct _KEY_FLAGS_INFORMATION
{
    ULONG Wow64Flags;
    ULONG KeyFlags; // REG_FLAG_*
    ULONG ControlFlags; // REG_KEY_*
} KEY_FLAGS_INFORMATION, *PKEY_FLAGS_INFORMATION;

/**
 * The KEY_VIRTUALIZATION_INFORMATION structure contains information about the virtualization state of a key.
 * 
 * The flags include:
 * - VirtualizationCandidate: The key is part of the virtualization namespace scope (only HKLM\Software for now).
 * - VirtualizationEnabled: Virtualization is enabled on this key. Can be 1 only if VirtualizationCandidate is 1.
 * - VirtualTarget: The key is a virtual key. Can be 1 only if VirtualizationCandidate and VirtualizationEnabled are 0. Valid only on the virtual store key handles.
 * - VirtualStore: The key is a part of the virtual store path. Valid only on the virtual store key handles.
 * - VirtualSource: The key has ever been virtualized, can be 1 only if VirtualizationCandidate is 1.
 * - Reserved: Reserved bits.
 */
typedef struct _KEY_VIRTUALIZATION_INFORMATION
{
    ULONG VirtualizationCandidate : 1;
    ULONG VirtualizationEnabled : 1;
    ULONG VirtualTarget : 1;
    ULONG VirtualStore : 1;
    ULONG VirtualSource : 1;
    ULONG Reserved : 27;
} KEY_VIRTUALIZATION_INFORMATION, *PKEY_VIRTUALIZATION_INFORMATION;

// private
/**
 * The KEY_TRUST_INFORMATION structure contains information about the trust status of a key.
 * 
 * The flags include:
 * - TrustedKey: Indicates whether the key is trusted. When set, this flag signifies that the key is considered 
 *   to be secure and reliable.
 * - Reserved: Reserved bits.
 */
typedef struct _KEY_TRUST_INFORMATION
{
    ULONG TrustedKey : 1;
    ULONG Reserved : 31;
} KEY_TRUST_INFORMATION, *PKEY_TRUST_INFORMATION;

// private
/**
 * The KEY_LAYER_INFORMATION structure contains information about a key layer.
 * 
 * The flags include:
 * - IsTombstone: Indicates whether the key layer is a tombstone. A tombstone is a marker that indicates 
 *   that the key has been deleted but not yet purged from the registry. It is used to maintain the 
 *   integrity of the registry and ensure that deleted keys are not immediately reused.
 * - IsSupersedeLocal: Indicates whether the key layer supersedes the local key. When set, this flag 
 *   indicates that the key layer should replace the local key's information, effectively overriding 
 *   any local changes or settings.
 * - IsSupersedeTree: Indicates whether the key layer supersedes the entire key tree. When set, this flag 
 *   indicates that the key layer should replace the entire subtree of keys, overriding any changes or 
 *   settings in the subtree.
 * - ClassIsInherited: Indicates whether the key layer's class is inherited. When set, this flag indicates 
 *   that the class information of the key layer is inherited from its parent key, rather than being 
 *   explicitly defined.
 * - Reserved: Reserved bits.
 */
typedef struct _KEY_LAYER_INFORMATION
{
    ULONG IsTombstone : 1;
    ULONG IsSupersedeLocal : 1;
    ULONG IsSupersedeTree : 1;
    ULONG ClassIsInherited : 1;
    ULONG Reserved : 28;
} KEY_LAYER_INFORMATION, *PKEY_LAYER_INFORMATION;

typedef enum _KEY_SET_INFORMATION_CLASS
{
    KeyWriteTimeInformation, // KEY_WRITE_TIME_INFORMATION
    KeyWow64FlagsInformation, // KEY_WOW64_FLAGS_INFORMATION
    KeyControlFlagsInformation, // KEY_CONTROL_FLAGS_INFORMATION
    KeySetVirtualizationInformation, // KEY_SET_VIRTUALIZATION_INFORMATION
    KeySetDebugInformation,
    KeySetHandleTagsInformation, // KEY_HANDLE_TAGS_INFORMATION
    KeySetLayerInformation, // KEY_SET_LAYER_INFORMATION
    MaxKeySetInfoClass
} KEY_SET_INFORMATION_CLASS;

/**
 * Structure representing the last write time of a registry key.
 * 
 * The values include:
 * - LastWriteTime: Contains the timestamp of the last write operation performed on a registry key.
 */
typedef struct _KEY_WRITE_TIME_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
} KEY_WRITE_TIME_INFORMATION, *PKEY_WRITE_TIME_INFORMATION;

/**
 * The KEY_WOW64_FLAGS_INFORMATION structure contains information about the WOW64 flags for a key.
 * 
 * The fields include:
 * - UserFlags: A set of user-defined flags associated with the key. These flags are used to store 
 *   additional information about the key in the context of WOW64 (Windows 32-bit on Windows 64-bit).
 */
typedef struct _KEY_WOW64_FLAGS_INFORMATION
{
    ULONG UserFlags;
} KEY_WOW64_FLAGS_INFORMATION, *PKEY_WOW64_FLAGS_INFORMATION;

/**
 * The KEY_HANDLE_TAGS_INFORMATION structure contains information about the handle tags for a key.
 * 
 * The fields include:
 * - HandleTags: A set of tags associated with the key handle. These tags are used to store additional 
 *   metadata or state information about the key handle.
 */
typedef struct _KEY_HANDLE_TAGS_INFORMATION
{
    ULONG HandleTags;
} KEY_HANDLE_TAGS_INFORMATION, *PKEY_HANDLE_TAGS_INFORMATION;

/**
 * The KEY_SET_LAYER_INFORMATION structure contains information about a key layer.
 * 
 * The flags include:
 * - IsTombstone: Indicates whether the key layer is a tombstone. A tombstone is a marker that indicates 
 *   that the key has been deleted but not yet purged from the registry. It is used to maintain the 
 *   integrity of the registry and ensure that deleted keys are not immediately reused.
 * - IsSupersedeLocal: Indicates whether the key layer supersedes the local key. When set, this flag 
 *   indicates that the key layer should replace the local key's information, effectively overriding 
 *   any local changes or settings.
 * - IsSupersedeTree: Indicates whether the key layer supersedes the entire key tree. When set, this flag 
 *   indicates that the key layer should replace the entire subtree of keys, overriding any changes or 
 *   settings in the subtree.
 * - ClassIsInherited: Indicates whether the key layer's class is inherited. When set, this flag indicates 
 *   that the class information of the key layer is inherited from its parent key, rather than being 
 *   explicitly defined.
 * - Reserved: Reserved bits.
 */
typedef struct _KEY_SET_LAYER_INFORMATION
{
    ULONG IsTombstone : 1;
    ULONG IsSupersedeLocal : 1;
    ULONG IsSupersedeTree : 1;
    ULONG ClassIsInherited : 1;
    ULONG Reserved : 28;
} KEY_SET_LAYER_INFORMATION, *PKEY_SET_LAYER_INFORMATION;

/**
 * The KEY_CONTROL_FLAGS_INFORMATION structure contains control flags for a key.
 * 
 * The fields include:
 * - ControlFlags: A set of control flags associated with the key. These flags are used to store 
 *   additional control information about the key, which can affect its behavior or state.
 */
typedef struct _KEY_CONTROL_FLAGS_INFORMATION
{
    ULONG ControlFlags;
} KEY_CONTROL_FLAGS_INFORMATION, *PKEY_CONTROL_FLAGS_INFORMATION;

typedef struct _KEY_SET_VIRTUALIZATION_INFORMATION
{
    ULONG VirtualTarget : 1;
    ULONG VirtualStore : 1;
    ULONG VirtualSource : 1; // true if key has been virtualized at least once
    ULONG Reserved : 29;
} KEY_SET_VIRTUALIZATION_INFORMATION, *PKEY_SET_VIRTUALIZATION_INFORMATION;

typedef enum _KEY_VALUE_INFORMATION_CLASS
{
    KeyValueBasicInformation, // KEY_VALUE_BASIC_INFORMATION
    KeyValueFullInformation, // KEY_VALUE_FULL_INFORMATION
    KeyValuePartialInformation, // KEY_VALUE_PARTIAL_INFORMATION
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,  // KEY_VALUE_PARTIAL_INFORMATION_ALIGN64
    KeyValueLayerInformation, // KEY_VALUE_LAYER_INFORMATION
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_BASIC_INFORMATION
{
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    _Field_size_bytes_(NameLength) WCHAR Name[ANYSIZE_ARRAY];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION
{
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    _Field_size_bytes_(NameLength) WCHAR Name[ANYSIZE_ARRAY];
    // ...
    // UCHAR Data[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION
{
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    _Field_size_bytes_(DataLength) UCHAR Data[ANYSIZE_ARRAY];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION_ALIGN64
{
    ULONG Type;
    ULONG DataLength;
    _Field_size_bytes_(DataLength) UCHAR Data[ANYSIZE_ARRAY];
} KEY_VALUE_PARTIAL_INFORMATION_ALIGN64, *PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64;

typedef struct _KEY_VALUE_LAYER_INFORMATION
{
    ULONG IsTombstone : 1;
    ULONG Reserved : 31;
} KEY_VALUE_LAYER_INFORMATION, *PKEY_VALUE_LAYER_INFORMATION;

typedef struct _KEY_VALUE_ENTRY
{
    PUNICODE_STRING ValueName;
    ULONG DataLength;
    ULONG DataOffset;
    ULONG Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

typedef enum _REG_ACTION
{
    KeyAdded,
    KeyRemoved,
    KeyModified
} REG_ACTION;

typedef struct _REG_NOTIFY_INFORMATION
{
    ULONG NextEntryOffset;
    REG_ACTION Action;
    ULONG KeyLength;
    _Field_size_bytes_(KeyLength) WCHAR Key[ANYSIZE_ARRAY];
} REG_NOTIFY_INFORMATION, *PREG_NOTIFY_INFORMATION;

typedef struct _KEY_PID_ARRAY
{
    HANDLE ProcessId;
    UNICODE_STRING KeyName;
} KEY_PID_ARRAY, *PKEY_PID_ARRAY;

typedef struct _KEY_OPEN_SUBKEYS_INFORMATION
{
    ULONG Count;
    _Field_size_(Count) KEY_PID_ARRAY KeyArray[ANYSIZE_ARRAY];
} KEY_OPEN_SUBKEYS_INFORMATION, *PKEY_OPEN_SUBKEYS_INFORMATION;

/**
 * Queries information about a registry key.
 * 
 * @param[in] KeyHandle A handle to the key to be queried.
 * @param[in] KeyInformationClass The type of information to be queried.
 * @param[out] KeyInformation A pointer to a buffer that receives the key information.
 * @param[in] Length The size of the buffer.
 * @param[out] ResultLength A pointer to a variable that receives the size of the data returned.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryKey(
    _In_ HANDLE KeyHandle,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_to_opt_(Length, *ResultLength) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    );

/**
 * Sets information for a registry key.
 * 
 * @param[in] KeyHandle A handle to the key to be modified.
 * @param[in] KeySetInformationClass The type of information to be set.
 * @param[in] KeySetInformation A pointer to a buffer that contains the key information.
 * @param[in] KeySetInformationLength The size of the buffer.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationKey(
    _In_ HANDLE KeyHandle,
    _In_ KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    _In_reads_bytes_(KeySetInformationLength) PVOID KeySetInformation,
    _In_ ULONG KeySetInformationLength
    );

/**
 * Queries the value of a registry key.
 * 
 * @param[in] KeyHandle A handle to the key to be queried.
 * @param[in] ValueName A pointer to a UNICODE_STRING structure that specifies the name of the value to be queried.
 * @param[in] KeyValueInformationClass The type of information to be queried.
 * @param[out] KeyValueInformation A pointer to a buffer that receives the value information.
 * @param[in] Length The size of the buffer.
 * @param[out] ResultLength A pointer to a variable that receives the size of the data returned.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryValueKey(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_to_opt_(Length, *ResultLength) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    );

/**
 * Sets the value of a registry key.
 * 
 * @param[in] KeyHandle A handle to the key to be modified.
 * @param[in] ValueName A pointer to a UNICODE_STRING structure that specifies the name of the value to be set.
 * @param[in, optional] TitleIndex Reserved.
 * @param[in] Type The type of the value.
 * @param[in] Data A pointer to a buffer that contains the value data.
 * @param[in] DataSize The size of the buffer.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetValueKey(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_opt_ ULONG TitleIndex,
    _In_ ULONG Type,
    _In_reads_bytes_opt_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    );

/**
 * Queries multiple values of a registry key.
 * 
 * @param[in] KeyHandle A handle to the key to be queried.
 * @param[in, out] ValueEntries A pointer to an array of KEY_VALUE_ENTRY structures that specify the values to be queried.
 * @param[in] EntryCount The number of entries in the array.
 * @param[out] ValueBuffer A pointer to a buffer that receives the value data.
 * @param[in, out] BufferLength A pointer to a variable that specifies the size of the buffer and receives the size of the data returned.
 * @param[out, optional] RequiredBufferLength A pointer to a variable that receives the size of the buffer required to hold the data.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryMultipleValueKey(
    _In_ HANDLE KeyHandle,
    _Inout_updates_(EntryCount) PKEY_VALUE_ENTRY ValueEntries,
    _In_ ULONG EntryCount,
    _Out_writes_bytes_(*BufferLength) PVOID ValueBuffer,
    _Inout_ PULONG BufferLength,
    _Out_opt_ PULONG RequiredBufferLength
    );

/**
 * Enumerates the subkeys of a registry key.
 * 
 * @param[in] KeyHandle A handle to the key to be enumerated.
 * @param[in] Index The index of the subkey to be enumerated.
 * @param[in] KeyInformationClass The type of information to be queried.
 * @param[out] KeyInformation A pointer to a buffer that receives the key information.
 * @param[in] Length The size of the buffer.
 * @param[out] ResultLength A pointer to a variable that receives the size of the data returned.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtEnumerateKey(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_to_opt_(Length, *ResultLength) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    );

/**
 * Enumerates the values of a registry key.
 * 
 * @param[in] KeyHandle A handle to the key to be enumerated.
 * @param[in] Index The index of the value to be enumerated.
 * @param[in] KeyValueInformationClass The type of information to be queried.
 * @param[out] KeyValueInformation A pointer to a buffer that receives the value information.
 * @param[in] Length The size of the buffer.
 * @param[out] ResultLength A pointer to a variable that receives the size of the data returned.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtEnumerateValueKey(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_to_opt_(Length, *ResultLength) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    );

EXTERN_C_END

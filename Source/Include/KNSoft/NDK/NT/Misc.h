#pragma once

#include "MinDef.h"

EXTERN_C_START

/* fltKernel.h */

#define FLT_PORT_CONNECT 0x0001
#define FLT_PORT_ALL_ACCESS (FLT_PORT_CONNECT | STANDARD_RIGHTS_ALL)

//
// Performance Counters for Windows
//

/**
 * PCW Handle Types
 */
DECLARE_HANDLE(HPCW_REGISTRATION);
DECLARE_HANDLE(HPCW_QUERY);
DECLARE_HANDLE(HPCW_NOTIFIER);

/**
 * PCW Callback Types
 */
typedef enum _PCW_CALLBACK_TYPE
{
    PcwCallbackAddCounter = 0,
    PcwCallbackRemoveCounter = 1,
    PcwCallbackEnumerateEvents = 2,
    PcwCallbackCollectData = 3,
} PCW_CALLBACK_TYPE;

typedef struct _PCW_CALLBACK_INFORMATION
{
    PCW_CALLBACK_TYPE Type;
    union
    {
        struct
        {
            PUNICODE_STRING InstanceName;
            PVOID InstanceData;
            ULONG InstanceId;
        } AddCounter;
        struct
        {
            PVOID InstanceContext;
        } RemoveCounter;
        struct
        {
            PVOID CancelEvent;
        } CollectData;
    } DUMMYUNIONNAME;
} PCW_CALLBACK_INFORMATION, *PPCW_CALLBACK_INFORMATION;

typedef _Function_class_(PCW_CALLBACK)
NTSTATUS NTAPI PCW_CALLBACK(
    _In_ PCW_CALLBACK_TYPE Type,
    _In_ PPCW_CALLBACK_INFORMATION Info,
    _In_opt_ PVOID Context
    );
typedef PCW_CALLBACK* PPCW_CALLBACK;

/**
 * Creates a new Performance Counters for Windows (PCW) query object.
 *
 * \param[out] QueryHandle Receives the created `HPCW_QUERY` handle on success.
 * \param[in,opt] CancelEventHandle Optional event handle that the kernel monitors to detect
 * cancellation of long-running operations (for example, during `PcwCollectData`).
 * The kernel only reads this handle; it may be `NULL` if cancellation support is not required.
 * \return NTSTATUS Returns `STATUS_SUCCESS` on success; otherwise an appropriate NTSTATUS error code.
 * \remark Usermode requests cancellation by signaling `CancelEventHandle` from another thread.
 */
NTSYSAPI
NTSTATUS
NTAPI
PcwCreateQuery(
    _Out_ HPCW_QUERY* QueryHandle,
    _In_opt_ HANDLE CancelEventHandle
    );

typedef enum _PCW_ADD_QUERY_ITEM_FLAGS
{
    PCW_ADD_QUERY_ITEM_NONE = 0x0,
    PCW_ADD_QUERY_ITEM_INSTANCE_WILDCARD = 0x1,
} PCW_ADD_QUERY_ITEM_FLAGS;

// Adds a counterset to a query
NTSYSAPI
NTSTATUS
NTAPI
PcwAddQueryItem(
    _Out_ PULONG ItemId,
    _In_ HPCW_QUERY QueryHandle,
    _In_ PCW_ADD_QUERY_ITEM_FLAGS Flags,
    _In_ PCUNICODE_STRING CounterSetPath,
    _In_ PCUNICODE_STRING InstanceName,
    _In_ ULONG InstanceId,
    _In_ ULONG64 CounterMask,
    _In_opt_ PVOID UserData
    );

// Triggers data collection for a query
NTSYSAPI
NTSTATUS
NTAPI
PcwCollectData(
    _In_ HPCW_QUERY QueryHandle,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesReturned
    );

// Removes an item from a query
NTSYSAPI
NTSTATUS
NTAPI
PcwRemoveQueryItem(
    _In_ HPCW_QUERY QueryHandle,
    _In_ ULONG ItemId
    );

// Associates user data with a query item
NTSYSAPI
NTSTATUS
NTAPI
PcwSetQueryItemUserData(
    _In_ HPCW_QUERY QueryHandle,
    _In_ ULONG ItemId,
    _In_ PVOID UserData
    );

// HPCW_NOTIFIER APIs
// Creates a notifier object for consumers
NTSYSAPI
NTSTATUS
NTAPI
PcwCreateNotifier(
    _Out_ HPCW_NOTIFIER* NotifierHandle,
    _In_ PCUNICODE_STRING Name
    );

// Checks if a notifier is still active
NTSYSAPI
BOOLEAN
NTAPI
PcwIsNotifierAlive(
    _In_ HPCW_NOTIFIER NotifierHandle
    );

// Retrieves data from a notifier
NTSYSAPI
NTSTATUS
NTAPI
PcwReadNotificationData(
    _In_ HPCW_NOTIFIER NotifierHandle,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesReturned
    );

// Completes a pending notification
NTSYSAPI
NTSTATUS
NTAPI
PcwCompleteNotification(
    _In_ HPCW_NOTIFIER NotifierHandle,
    _In_ NTSTATUS Status,
    _In_opt_ PVOID UserData,
    _In_ ULONG UserDataSize
    );

// Other PCW APIs
// Registers a provider counterset
NTSYSAPI
NTSTATUS
NTAPI
PcwRegisterCounterSet(
    _Out_ HPCW_REGISTRATION* Registration,
    _In_ PCUNICODE_STRING Name,
    _In_ PPCW_CALLBACK Callback,
    _In_opt_ PVOID UserData
    );

// Closes a registration handle
NTSYSAPI
VOID
NTAPI
PcwDisconnectCounterSet(
    _In_ HPCW_REGISTRATION RegistrationHandle
    );

// Lists instances of a counterset
NTSYSAPI
NTSTATUS
NTAPI
PcwEnumerateInstances(
    _In_ HPCW_REGISTRATION RegistrationHandle,
    _In_ PCUNICODE_STRING CounterSetPath,
    _In_ PCUNICODE_STRING InstanceName,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesReturned
    );

// Queries security descriptor for a counterset
NTSYSAPI
NTSTATUS
NTAPI
PcwQueryCounterSetSecurity(
    _In_ PCUNICODE_STRING Name,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _Out_writes_bytes_opt_(BufferSize) PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesReturned
    );

// Sends a notification to consumers
NTSYSAPI
NTSTATUS
NTAPI
PcwSendNotification(
    _In_ HPCW_REGISTRATION RegistrationHandle,
    _In_ ULONG NotificationType,
    _In_opt_ PVOID NotificationData,
    _In_opt_ PCUNICODE_STRING InstanceName,
    _In_ ULONG InstanceId,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_opt_ PULONG BytesReturned
    );

// Sends a notification without a registration handle
NTSYSAPI
NTSTATUS
NTAPI
PcwSendStatelessNotification(
    _In_ PCUNICODE_STRING CounterSetName,
    _In_ ULONG NotificationType,
    _In_opt_ PVOID NotificationData,
    _In_opt_ PCUNICODE_STRING InstanceName,
    _In_ ULONG InstanceId,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_opt_ PULONG BytesReturned
    );

// Sets security descriptor for a counterset
NTSYSAPI
NTSTATUS
NTAPI
PcwSetCounterSetSecurity(
    _In_ PCUNICODE_STRING Name,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor
    );

// Clears security descriptor for a counterset
NTSYSAPI
NTSTATUS
NTAPI
PcwClearCounterSetSecurity(
    _In_ PCUNICODE_STRING Name
    );

EXTERN_C_END

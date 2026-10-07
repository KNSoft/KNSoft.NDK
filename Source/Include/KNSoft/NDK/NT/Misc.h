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

/**
 * The PCW_CALLBACK_INFORMATION structure contains the information passed to a Performance Counters for Windows (PCW)
 * callback.
 */
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

/**
 * The PCW_ADD_QUERY_ITEM_FLAGS enumeration defines the flags used when adding a query item to a PCW query.
 */
typedef enum _PCW_ADD_QUERY_ITEM_FLAGS
{
    PCW_ADD_QUERY_ITEM_NONE = 0x0,
    PCW_ADD_QUERY_ITEM_INSTANCE_WILDCARD = 0x1,
} PCW_ADD_QUERY_ITEM_FLAGS;

/**
 * The PcwAddQueryItem routine adds a counter query item to a Performance Counters for Windows (PCW) query.
 *
 * \param[out] ItemId Pointer to a variable that receives the identifier assigned to the query item.
 * \param[in] QueryHandle Handle to the PCW query.
 * \param[in] Flags Flags that control the query item.
 * \param[in] CounterSetPath The path of the counter set to query.
 * \param[in] InstanceName The name of the instance to query.
 * \param[in] InstanceId The identifier of the instance to query.
 * \param[in] CounterMask A bitmask that selects the counters to include.
 * \param[in, optional] UserData Caller-defined data to associate with the query item.
 * \return NTSTATUS Successful or errant status.
 */
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

/**
 * The PcwCollectData routine collects counter data for a Performance Counters for Windows (PCW) query.
 *
 * \param[in] QueryHandle Handle to the PCW query.
 * \param[out] Buffer Pointer to a buffer that receives the collected counter data.
 * \param[in] BufferSize The size, in bytes, of the buffer.
 * \param[out] BytesReturned Pointer to a variable that receives the number of bytes written.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
PcwCollectData(
    _In_ HPCW_QUERY QueryHandle,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesReturned
    );

/**
 * The PcwRemoveQueryItem routine removes a counter query item from a Performance Counters for Windows (PCW) query.
 *
 * \param[in] QueryHandle Handle to the PCW query.
 * \param[in] ItemId The identifier of the query item to remove.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
PcwRemoveQueryItem(
    _In_ HPCW_QUERY QueryHandle,
    _In_ ULONG ItemId
    );

// Associates user data with a query item
/**
 * The PcwSetQueryItemUserData routine sets the caller-defined data associated with a PCW query item.
 *
 * \param[in] QueryHandle Handle to the PCW query.
 * \param[in] ItemId The identifier of the query item.
 * \param[in] UserData The caller-defined data to associate with the query item.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
PcwSetQueryItemUserData(
    _In_ HPCW_QUERY QueryHandle,
    _In_ ULONG ItemId,
    _In_ PVOID UserData
    );

// HPCW_NOTIFIER APIs
/**
 * The PcwCreateNotifier routine creates a Performance Counters for Windows (PCW) notifier.
 *
 * \param[out] NotifierHandle Pointer to a variable that receives the notifier handle.
 * \param[in] Name The name of the notifier.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
PcwCreateNotifier(
    _Out_ HPCW_NOTIFIER* NotifierHandle,
    _In_ PCUNICODE_STRING Name
    );

/**
 * The PcwIsNotifierAlive routine determines whether a Performance Counters for Windows (PCW) notifier is still alive.
 *
 * \param[out] Alive Pointer to a boolean receiving whether the notifier is alive.
 * \param[in] Registration Handle to the PCW registration.
 * \param[in] NotificationId Pointer to the notification ID.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
PcwIsNotifierAlive(
    _Out_ PBOOLEAN Alive,
    _In_ HANDLE Registration,
    _In_ const ULONGLONG *NotificationId
    );

/**
 * The PcwReadNotificationData routine reads pending notification data from a Performance Counters for Windows (PCW)
 * notifier.
 *
 * \param[in] NotifierHandle Handle to the PCW notifier.
 * \param[out] Buffer Pointer to a buffer that receives the notification data.
 * \param[in] BufferSize The size, in bytes, of the buffer.
 * \param[out] BytesReturned Pointer to a variable that receives the number of bytes written.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
PcwReadNotificationData(
    _In_ HPCW_NOTIFIER NotifierHandle,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesReturned
    );

/**
 * The PcwCompleteNotification routine completes a pending Performance Counters for Windows (PCW) notification.
 *
 * \param[out] Result Pointer to a boolean receiving the result.
 * \param[in] Notifier Handle to the PCW notifier.
 * \param[in] Status The completion status of the notification.
 * \param[in, optional] UserData Caller-defined data associated with the completion.
 * \param[in] UserDataSize The size, in bytes, of the user data.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
PcwCompleteNotification(
    _Out_ PBOOLEAN Result,
    _In_ HANDLE Notifier,
    _In_ NTSTATUS Status,
    _In_opt_ PVOID UserData,
    _In_ ULONG UserDataSize
    );

/**
 * The PcwRegisterCounterSet routine registers a Performance Counters for Windows (PCW) counter set.
 *
 * \param[out] Registration Pointer to a variable that receives the registration handle.
 * \param[in] Name The name of the counter set.
 * \param[in, optional] NotificationFile Optional handle to the notification file.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
PcwRegisterCounterSet(
    _Out_ PHANDLE Registration,
    _In_ PCUNICODE_STRING Name,
    _In_opt_ HANDLE NotificationFile
    );

/**
 * The PcwDisconnectCounterSet routine disconnects a registered Performance Counters for Windows (PCW) counter set.
 *
 * \param[out] Result Pointer to a boolean receiving the result.
 * \param[in] Registration Handle to the PCW counter set registration.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
PcwDisconnectCounterSet(
    _Out_ PBOOLEAN Result,
    _In_ HANDLE Registration
    );

/**
 * The PcwEnumerateInstances routine enumerates the instances of a registered Performance Counters for Windows (PCW)
 * counter set.
 *
 * \param[in] RegistrationHandle Handle to the PCW counter set registration.
 * \param[in] CounterSetPath The path of the counter set.
 * \param[in] InstanceName The name of the instance to enumerate.
 * \param[out] Buffer Pointer to a buffer that receives the enumerated instance data.
 * \param[in] BufferSize The size, in bytes, of the buffer.
 * \param[out] BytesReturned Pointer to a variable that receives the number of bytes written.
 * \return NTSTATUS Successful or errant status.
 */
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

/**
 * The PcwQueryCounterSetSecurity routine queries the security descriptor of a Performance Counters for Windows (PCW)
 * counter set.
 *
 * \param[in] Name The name of the counter set.
 * \param[in] SecurityInformation The security information to query.
 * \param[out, optional] SecurityDescriptor Pointer to a buffer that receives the security descriptor.
 * \param[in] BufferSize The size, in bytes, of the buffer.
 * \param[out] BytesReturned Pointer to a variable that receives the number of bytes required or written.
 * \return NTSTATUS Successful or errant status.
 */
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

/**
 * The PcwSendNotification routine sends a notification to a registered Performance Counters for Windows (PCW) counter
 * set.
 *
 * \param[in] RegistrationHandle Handle to the PCW counter set registration.
 * \param[in] NotificationType The type of notification to send.
 * \param[in, optional] NotificationData Pointer to the notification data.
 * \param[in, optional] InstanceName The name of the instance associated with the notification.
 * \param[in] InstanceId The identifier of the instance.
 * \param[out, optional] OutputBuffer Pointer to a buffer that receives the notification response.
 * \param[in] OutputBufferSize The size, in bytes, of the output buffer.
 * \param[out, optional] BytesReturned Pointer to a variable that receives the number of bytes written.
 * \return NTSTATUS Successful or errant status.
 */
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

/**
 * The PcwSendStatelessNotification routine sends a stateless notification to a Performance Counters for Windows (PCW)
 * counter set.
 *
 * \param[in] CounterSetName The name of the counter set.
 * \param[in] NotificationType The type of notification to send.
 * \param[in, optional] NotificationData Pointer to the notification data.
 * \param[in, optional] InstanceName The name of the instance associated with the notification.
 * \param[in] InstanceId The identifier of the instance.
 * \param[out, optional] OutputBuffer Pointer to a buffer that receives the notification response.
 * \param[in] OutputBufferSize The size, in bytes, of the output buffer.
 * \param[out, optional] BytesReturned Pointer to a variable that receives the number of bytes written.
 * \return NTSTATUS Successful or errant status.
 */
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

/**
 * The PcwSetCounterSetSecurity routine sets the security descriptor of a Performance Counters for Windows (PCW) counter
 * set.
 *
 * \param[in] Name The name of the counter set.
 * \param[in] SecurityInformation The security information to set.
 * \param[in] SecurityDescriptor Pointer to the security descriptor to apply.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
PcwSetCounterSetSecurity(
    _In_ PCUNICODE_STRING Name,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor
    );

/**
 * The PcwClearCounterSetSecurity routine clears the security descriptor of a Performance Counters for Windows (PCW)
 * counter set, restoring the default.
 *
 * \param[in] Name The name of the counter set.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
PcwClearCounterSetSecurity(
    _In_ PCUNICODE_STRING Name
    );

//
// PCW Buffer Structures and Parsing Helpers
//

/**
 * PCW query snapshot - represents a data collection snapshot
 */
typedef struct _PCW_QUERY_SNAPSHOT
{
    PVOID RawBuffer;
    ULONG64 Reserved08;
    ULONG64 TimestampA;
    ULONG64 TimestampB;
} PCW_QUERY_SNAPSHOT, *PPCW_QUERY_SNAPSHOT;

/**
 * Root header for PCW result data
 */
typedef struct _PCW_RESULT_ROOT
{
    ULONG HeaderSize;
    ULONG HeaderOffset;
} PCW_RESULT_ROOT, *PPCW_RESULT_ROOT;

/**
 * Header describing PCW counter set results
 */
typedef struct _PCW_RESULT_HEADER
{
    ULONG Size;
    ULONG InstanceListOffset;
    ULONG InstanceCount;
} PCW_RESULT_HEADER, *PPCW_RESULT_HEADER;

/**
 * PCW instance buffer - contains instance data and counter values
 */
typedef struct _PCW_INSTANCE_BUFFER
{
    ULONG Size;
    ULONG Index;
    ULONG CounterDataOffset;
    ULONG Reserved0C;
    WCHAR InstanceName[ANYSIZE_ARRAY];
} PCW_INSTANCE_BUFFER, *PPCW_INSTANCE_BUFFER;

/**
 * PCW counter record - single counter value
 */
typedef struct _PCW_COUNTER_RECORD
{
    ULONG Size;
    union
    {
        ULONG CounterIdAndValueSize;
        struct
        {
            USHORT CounterId;
            USHORT ValueSize;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    ULONG64 Value;
} PCW_COUNTER_RECORD, *PPCW_COUNTER_RECORD;

/**
 * PCW counter trailer - metadata following counter data
 */
typedef struct _PCW_COUNTER_TRAILER
{
    ULONG Size;
    union
    {
        ULONG CounterIdAndValueSize;
        struct
        {
            USHORT CounterId;
            USHORT ValueSize;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    ULONG TickCount;
} PCW_COUNTER_TRAILER, *PPCW_COUNTER_TRAILER;

/**
 * PCW enumerate instances header
 */
typedef struct _PCW_ENUMERATE_INSTANCES_HEADER
{
    ULONG InstanceCount;
    ULONG FirstInstanceOffset;
} PCW_ENUMERATE_INSTANCES_HEADER, *PPCW_ENUMERATE_INSTANCES_HEADER;

/**
 * PCW enumerated instance
 */
typedef struct _PCW_ENUMERATE_INSTANCE
{
    ULONG Size;
    ULONG InstanceId;
    WCHAR InstanceName[ANYSIZE_ARRAY];
} PCW_ENUMERATE_INSTANCE, *PPCW_ENUMERATE_INSTANCE;

//
// PCW Buffer Parsing Helper Functions
//

/**
 * Retrieves the header from a PCW query snapshot buffer.
 */
FORCEINLINE
PPCW_RESULT_HEADER
NTAPI
PcwQueryGetHeader(
    _In_ PPCW_QUERY_SNAPSHOT Snapshot
    )
{
    PPCW_RESULT_ROOT root;

    root = (PPCW_RESULT_ROOT)Snapshot->RawBuffer;
    return (PPCW_RESULT_HEADER)Add2Ptr(Snapshot->RawBuffer, root->HeaderOffset);
}

/**
 * Retrieves the first instance from a PCW result header.
 */
FORCEINLINE
PPCW_INSTANCE_BUFFER
NTAPI
PcwHeaderGetFirstInstance(
    _In_ PPCW_RESULT_HEADER Header
    )
{
    return (PPCW_INSTANCE_BUFFER)Add2Ptr(Header, Header->InstanceListOffset);
}

/**
 * Retrieves the next instance in a PCW instance sequence.
 */
FORCEINLINE
PPCW_INSTANCE_BUFFER
NTAPI
PcwInstanceGetNext(
    _In_ PPCW_INSTANCE_BUFFER Instance
    )
{
    return (PPCW_INSTANCE_BUFFER)Add2Ptr(Instance, Instance->Size);
}

/**
 * Retrieves the first counter record from a PCW instance.
 */
FORCEINLINE
PPCW_COUNTER_RECORD
NTAPI
PcwInstanceGetFirstCounter(
    _In_ PPCW_INSTANCE_BUFFER Instance
    )
{
    return (PPCW_COUNTER_RECORD)Add2Ptr(Instance, Instance->CounterDataOffset);
}

/**
 * Retrieves the next counter record in a PCW counter sequence.
 */
FORCEINLINE
PPCW_COUNTER_RECORD
NTAPI
PcwCounterGetNext(
    _In_ PPCW_COUNTER_RECORD Counter
    )
{
    return (PPCW_COUNTER_RECORD)Add2Ptr(Counter, Counter->Size);
}

/**
 * Retrieves the trailer following a PCW counter record.
 */
FORCEINLINE
PPCW_COUNTER_TRAILER
NTAPI
PcwCounterGetTrailer(
    _In_ PPCW_COUNTER_RECORD Counter
    )
{
    return (PPCW_COUNTER_TRAILER)Add2Ptr(Counter, Counter->Size);
}

/**
 * Retrieves the first enumerated instance from a PCW enumerate header.
 */
FORCEINLINE
PPCW_ENUMERATE_INSTANCE
NTAPI
PcwEnumerateHeaderGetFirstInstance(
    _In_ PPCW_ENUMERATE_INSTANCES_HEADER Header
    )
{
    return (PPCW_ENUMERATE_INSTANCE)Add2Ptr(Header, Header->FirstInstanceOffset);
}

/**
 * Retrieves the next enumerated instance.
 */
FORCEINLINE
PPCW_ENUMERATE_INSTANCE
NTAPI
PcwEnumerateInstanceGetNext(
    _In_ PPCW_ENUMERATE_INSTANCE Instance
    )
{
    return (PPCW_ENUMERATE_INSTANCE)Add2Ptr(Instance, Instance->Size);
}

EXTERN_C_END

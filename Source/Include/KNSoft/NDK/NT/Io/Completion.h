#pragma once

#include "../MinDef.h"

EXTERN_C_START

#pragma region I/O Completion Port

// private
typedef struct _FILE_IO_COMPLETION_INFORMATION
{
    PVOID KeyContext;
    PVOID ApcContext;
    IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, *PFILE_IO_COMPLETION_INFORMATION;

#ifndef IO_COMPLETION_QUERY_STATE
#define IO_COMPLETION_QUERY_STATE 0x0001
#endif

#ifndef IO_COMPLETION_MODIFY_STATE
#define IO_COMPLETION_MODIFY_STATE 0x0002
#endif

#ifndef IO_COMPLETION_ALL_ACCESS
#define IO_COMPLETION_ALL_ACCESS (IO_COMPLETION_QUERY_STATE|IO_COMPLETION_MODIFY_STATE|STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE)
#endif

/**
 * The IO_COMPLETION_INFORMATION_CLASS enumeration type specifies the type of I/O completion information to be queried.
 */
typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
    IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS;

/**
 * The IO_COMPLETION_BASIC_INFORMATION structure contains the depth of an I/O completion port.
 */
typedef struct _IO_COMPLETION_BASIC_INFORMATION
{
    LONG Depth;
} IO_COMPLETION_BASIC_INFORMATION, *PIO_COMPLETION_BASIC_INFORMATION;

/**
 * The NtCreateIoCompletion routine creates an I/O completion port and associates it with a specified file handle,
 * or creates an I/O completion port that is not yet associated with a file handle, allowing association at a later time.
 *
 * \param[out] IoCompletionHandle Pointer to a variable that receives a handle to the I/O completion port.
 * \param[in] DesiredAccess The requested access to the object.
 * \param[in] ObjectAttributes Pointer to an OBJECT_ATTRIBUTES structure that contains the name to an existing I/O completion port or NULL.
 * \param[out] NumberOfConcurrentThreads The maximum number of threads that the operating system can allow to concurrently process
 * I/O completion packets for the I/O completion port. This parameter is ignored if the ExistingCompletionPort parameter is not NULL.
 * If this parameter is zero, the system allows as many concurrently running threads as there are processors in the system.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/fileio/createiocompletionport
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateIoCompletion(
    _Out_ PHANDLE IoCompletionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ ULONG Count);

/**
 * The NtOpenIoCompletion routine opens an existing I/O completion port object.
 *
 * \param[out] IoCompletionHandle Pointer to a variable that receives a handle to the I/O completion port.
 * \param[in] DesiredAccess The requested access to the object.
 * \param[in] ObjectAttributes Pointer to an OBJECT_ATTRIBUTES structure that specifies the name and other attributes.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/fileio/createiocompletionport
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenIoCompletion(
    _Out_ PHANDLE IoCompletionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

/**
 * The NtQueryIoCompletion routine queries information about an I/O completion port.
 *
 * \param[in] IoCompletionHandle Handle to the I/O completion port.
 * \param[in] IoCompletionInformationClass The type of information to query.
 * \param[out] IoCompletionInformation Pointer to a buffer that receives the information.
 * \param[in] IoCompletionInformationLength The size of the buffer.
 * \param[out, optional] ReturnLength Pointer to a variable that receives the number of bytes returned.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryIoCompletion(
    _In_ HANDLE IoCompletionHandle,
    _In_ IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
    _Out_writes_bytes_(IoCompletionInformationLength) PVOID IoCompletionInformation,
    _In_ ULONG IoCompletionInformationLength,
    _Out_opt_ PULONG ReturnLength);

/**
 * The NtSetIoCompletion routine queues an I/O completion packet to an I/O completion port.
 *
 * \param[in] IoCompletionHandle Handle to the I/O completion port.
 * \param[in, optional] KeyContext The value specified when the port was associated with a file handle.
 * \param[in, optional] ApcContext The value specified when the I/O operation was issued.
 * \param[in] IoStatus The completion status for the I/O operation.
 * \param[in] IoStatusInformation The number of bytes transferred or other information.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiet-postqueuedcompletionstatus
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetIoCompletion(
    _In_ HANDLE IoCompletionHandle,
    _In_opt_ PVOID KeyContext,
    _In_opt_ PVOID ApcContext,
    _In_ NTSTATUS IoStatus,
    _In_ ULONG_PTR IoStatusInformation);

/**
 * The NtSetIoCompletionEx routine queues an I/O completion packet to an I/O completion port using a completion packet.
 *
 * \param[in] IoCompletionHandle Handle to the I/O completion port.
 * \param[in] IoCompletionPacketHandle Handle to a completion packet.
 * \param[in, optional] KeyContext The value specified when the port was associated with a file handle.
 * \param[in, optional] ApcContext The value specified when the I/O operation was issued.
 * \param[in] IoStatus The completion status for the I/O operation.
 * \param[in] IoStatusInformation The number of bytes transferred or other information.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetIoCompletionEx(
    _In_ HANDLE IoCompletionHandle,
    _In_ HANDLE IoCompletionPacketHandle,
    _In_opt_ PVOID KeyContext,
    _In_opt_ PVOID ApcContext,
    _In_ NTSTATUS IoStatus,
    _In_ ULONG_PTR IoStatusInformation);

/**
 * The NtRemoveIoCompletion routine removes an entry from an I/O completion port.
 *
 * \param[in] IoCompletionHandle Handle to the I/O completion port.
 * \param[out] KeyContext Pointer to a variable that receives the key context.
 * \param[out] ApcContext Pointer to a variable that receives the APC context.
 * \param[out] IoStatusBlock Pointer to an IO_STATUS_BLOCK structure that receives the completion status.
 * \param[in, optional] Timeout Optional pointer to a timeout value.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/devnotes/ntremoveiocompletion
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtRemoveIoCompletion(
    _In_ HANDLE IoCompletionHandle,
    _Out_ PVOID *KeyContext,
    _Out_ PVOID *ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER Timeout);

/**
 * The NtRemoveIoCompletionEx routine removes multiple entries from an I/O completion port.
 *
 * \param[in] IoCompletionHandle Handle to the I/O completion port.
 * \param[out] IoCompletionInformation Pointer to an array of FILE_IO_COMPLETION_INFORMATION structures.
 * \param[in] Count The number of entries to remove.
 * \param[out] NumEntriesRemoved Pointer to a variable that receives the number of entries removed.
 * \param[in, optional] Timeout Optional pointer to a timeout value.
 * \param[in] Alertable Whether the wait is alertable.
 * \return NTSTATUS Successful or errant status.
 * \remarks If Count > 16, allocates temp kernel buffer (ExAllocatePool2) and caps fallback behavior if allocation fails.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiet-getqueuedcompletionstatusex
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtRemoveIoCompletionEx(
    _In_ HANDLE IoCompletionHandle,
    _Out_writes_to_(Count, *NumEntriesRemoved) PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
    _In_ ULONG Count,
    _Out_ PULONG NumEntriesRemoved,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_ BOOLEAN Alertable);

#pragma endregion

#pragma region Wait Completion Packet

#if (NTDDI_VERSION >= NTDDI_WIN8)

#ifndef WAIT_COMPLETION_PACKET_SET_STATE
#define WAIT_COMPLETION_PACKET_SET_STATE 0x0001
#endif

#ifndef WAIT_COMPLETION_PACKET_ALL_ACCESS
#define WAIT_COMPLETION_PACKET_ALL_ACCESS (WAIT_COMPLETION_PACKET_SET_STATE | STANDARD_RIGHTS_REQUIRED)
#endif

/**
 * The NtCreateWaitCompletionPacket routine creates a wait completion packet object.
 *
 * A wait completion packet is a kernel object that can be associated with wait
 * or I/O completion sources and later queried via I/O completion mechanisms.
 *
 * \param WaitCompletionPacketHandle Pointer to a variable that receives a handle
 *        to the newly created wait completion packet object.
 * \param DesiredAccess The access mask that specifies the requested access to
 *        the wait completion packet object.
 * \param ObjectAttributes Optional pointer to an OBJECT_ATTRIBUTES structure that
 *        supplies the object name and other attributes. May be NULL.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateWaitCompletionPacket(
    _Out_ PHANDLE WaitCompletionPacketHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes);

/**
 * The NtAssociateWaitCompletionPacket routine associates a wait completion packet
 * with an I/O completion port or other target object so that a completion packet
 * will be queued when the target object becomes signaled or an I/O completes.
 *
 * This routine links the specified wait completion packet with the target
 * completion object so the packet will carry the supplied context and status
 * information when it is delivered.
 *
 * \param[in] WaitCompletionPacketHandle Handle to the wait completion packet object.
 * \param[in] IoCompletionHandle Handle to an I/O completion port (or compatible object)
 *        with which the wait completion packet should be associated.
 * \param[in] TargetObjectHandle Handle to the object to watch for completion or
 *        signalling (for example, a waitable kernel object).
 * \param[in] KeyContext Optional pointer to caller-specified context that will be
 *        stored in the completion packet and returned to the consumer.
 * \param[in] ApcContext Optional pointer to caller-specified APC/context value that
 *        will be stored in the completion packet and returned to the consumer.
 * \param[in] IoStatus The NTSTATUS value to be placed in the completion packet.
 * \param[in] IoStatusInformation Additional information ( ULONG_PTR ) to be placed
 *        in the completion packet (commonly used for number of bytes transferred).
 * \param[out] AlreadySignaled Optional pointer to a BOOLEAN that, on return, is set
 *        to TRUE if the packet was already signaled at the time of association;
 *        otherwise FALSE. May be NULL.
 * \return NTSTATUS Successful or errant status.
 * \remarks Use this routine to arrange for notification of a target object's
 *          completion by queuing a wait completion packet containing the
 *          supplied context and status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtAssociateWaitCompletionPacket(
    _In_ HANDLE WaitCompletionPacketHandle,
    _In_ HANDLE IoCompletionHandle,
    _In_ HANDLE TargetObjectHandle,
    _In_opt_ PVOID KeyContext,
    _In_opt_ PVOID ApcContext,
    _In_ NTSTATUS IoStatus,
    _In_ ULONG_PTR IoStatusInformation,
    _Out_opt_ PBOOLEAN AlreadySignaled);

/**
 * The NtCancelWaitCompletionPacket routine cancels a previously associated wait
 * completion packet or removes a signaled packet from its queue.
 *
 * \param[in] WaitCompletionPacketHandle Handle to the wait completion packet object to cancel.
 * \param[in] RemoveSignaledPacket If TRUE and the packet is already signaled, remove
 *        the signaled packet from the target queue; if FALSE, cancellation will
 *        prevent future signaling but will not remove an already queued packet.
 * \return NTSTATUS Successful or errant status.
 * \remarks After successful cancellation, the wait completion packet will no
 *          longer be delivered as a result of the previously associated target.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCancelWaitCompletionPacket(
    _In_ HANDLE WaitCompletionPacketHandle,
    _In_ BOOLEAN RemoveSignaledPacket);

#endif

#pragma endregion

EXTERN_C_END

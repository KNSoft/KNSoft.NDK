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

typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
    IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS;

typedef struct _IO_COMPLETION_BASIC_INFORMATION
{
    LONG Depth;
} IO_COMPLETION_BASIC_INFORMATION, *PIO_COMPLETION_BASIC_INFORMATION;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateIoCompletion(
    _Out_ PHANDLE IoCompletionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ ULONG Count);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenIoCompletion(
    _Out_ PHANDLE IoCompletionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryIoCompletion(
    _In_ HANDLE IoCompletionHandle,
    _In_ IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
    _Out_writes_bytes_(IoCompletionInformationLength) PVOID IoCompletionInformation,
    _In_ ULONG IoCompletionInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetIoCompletion(
    _In_ HANDLE IoCompletionHandle,
    _In_opt_ PVOID KeyContext,
    _In_opt_ PVOID ApcContext,
    _In_ NTSTATUS IoStatus,
    _In_ ULONG_PTR IoStatusInformation);

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

NTSYSCALLAPI
NTSTATUS
NTAPI
NtRemoveIoCompletion(
    _In_ HANDLE IoCompletionHandle,
    _Out_ PVOID *KeyContext,
    _Out_ PVOID *ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER Timeout);

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
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCancelWaitCompletionPacket(
    _In_ HANDLE WaitCompletionPacketHandle,
    _In_ BOOLEAN RemoveSignaledPacket);

#endif

#pragma endregion

EXTERN_C_END

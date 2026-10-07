#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

#if (NTDDI_VERSION >= NTDDI_WIN11_GA)

// rev
/**
 * The NtOpenCpuPartition routine opens a handle to an existing CPU partition object.
 *
 * \param[out] CpuPartitionHandle Pointer to a variable that receives a handle to the CPU partition object.
 * \param[in] DesiredAccess The requested access to the CPU partition object.
 * \param[in, optional] ObjectAttributes Pointer to an OBJECT_ATTRIBUTES structure that specifies the object attributes.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenCpuPartition(
    _Out_ PHANDLE CpuPartitionHandle, 
    _In_ ACCESS_MASK DesiredAccess, 
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes);

// rev
/**
 * The NtCreateCpuPartition routine creates a CPU partition object.
 *
 * \param[out] CpuPartitionHandle Pointer to a variable that receives a handle to the CPU partition object.
 * \param[in] DesiredAccess The requested access to the CPU partition object.
 * \param[in, optional] ObjectAttributes Pointer to an OBJECT_ATTRIBUTES structure that specifies the object attributes.
 * \param[in, optional] ExtendedParameters Pointer to an array of extended parameters.
 * \param[in] ExtendedParameterCount Number of extended parameters.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateCpuPartition(
    _Out_ PHANDLE CpuPartitionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_reads_opt_(ExtendedParameterCount) PVOID ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    );

// rev
/**
 * The NtSetInformationCpuPartition routine sets information for a CPU partition object.
 *
 * \param[in] CpuPartitionHandle Handle to the CPU partition object.
 * \param[in] CpuPartitionInformationClass The type of information to set.
 * \param[in] CpuPartitionInformation Pointer to a buffer that contains the information to set.
 * \param[in] CpuPartitionInformationLength The size, in bytes, of the information buffer.
 * \remarks The remaining parameters are reserved.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationCpuPartition(
    _In_ HANDLE CpuPartitionHandle, 
    _In_ ULONG CpuPartitionInformationClass, 
    _In_reads_bytes_(CpuPartitionInformationLength) PVOID CpuPartitionInformation, 
    _In_ ULONG CpuPartitionInformationLength, 
    _Reserved_ PVOID, 
    _Reserved_ ULONG, 
    _Reserved_ ULONG);

// rev
/**
 * The NtQueryInformationCpuPartition routine queries information about a CPU partition object.
 *
 * \param[in] CpuPartitionHandle Handle to the CPU partition object.
 * \param[in] CpuPartitionInformationClass The type of information to query.
 * \param[out, optional] CpuPartitionInformation Pointer to a buffer that receives the information.
 * \param[in] CpuPartitionInformationLength The size, in bytes, of the information buffer.
 * \param[out, optional] ReturnLength Pointer to a variable that receives the number of bytes returned.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationCpuPartition(
    _In_ HANDLE CpuPartitionHandle,
    _In_ ULONG CpuPartitionInformationClass,
    _Out_writes_bytes_opt_(CpuPartitionInformationLength) PVOID CpuPartitionInformation,
    _In_ ULONG CpuPartitionInformationLength,
    _Out_opt_ PULONG ReturnLength);

#endif

EXTERN_C_END

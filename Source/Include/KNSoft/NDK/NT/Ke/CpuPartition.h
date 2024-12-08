#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

// rev
NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenCpuPartition(
    _Out_ PHANDLE CpuPartitionHandle, 
    _In_ ACCESS_MASK DesiredAccess, 
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes);

// rev
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateCpuPartition(
    _Out_ PHANDLE CpuPartitionHandle, 
    _In_ ACCESS_MASK DesiredAccess, 
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes);

// rev
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

EXTERN_C_END

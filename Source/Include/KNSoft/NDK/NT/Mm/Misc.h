#pragma once

#include "../MinDef.h"

#include <minwinbase.h>

/* phnt */

typedef enum _MMLISTS
{
    ZeroedPageList = 0,
    FreePageList = 1,
    StandbyPageList = 2,
    ModifiedPageList = 3,
    ModifiedNoWritePageList = 4,
    BadPageList = 5,
    ActiveAndValid = 6,
    TransitionPage = 7
} MMLISTS, *PMMLISTS;

typedef enum _MMPFNUSE
{
    ProcessPrivatePage,
    MemoryMappedFilePage,
    PageFileMappedPage,
    PageTablePage,
    PagedPoolPage,
    NonPagedPoolPage,
    SystemPTEPage,
    SessionPrivatePage,
    MetafilePage,
    AWEPage,
    DriverLockedPage,
    KernelStackPage
} MMPFNUSE, *PMMPFNUSE;

// private
typedef struct _MEMORY_FRAME_INFORMATION
{
    ULONGLONG UseDescription : 4; // MMPFNUSE_*
    ULONGLONG ListDescription : 3; // MMPFNLIST_*
    ULONGLONG Cold : 1; // 19H1
    ULONGLONG Pinned : 1; // 1 - pinned, 0 - not pinned
    ULONGLONG DontUse : 48; // *_INFORMATION overlay
    ULONGLONG Priority : 3;
    ULONGLONG NonTradeable : 1;
    ULONGLONG Reserved : 3;
} MEMORY_FRAME_INFORMATION;

// private
typedef struct _FILEOFFSET_INFORMATION
{
    ULONGLONG DontUse : 9; // MEMORY_FRAME_INFORMATION overlay
    ULONGLONG Offset : 48; // mapped files
    ULONGLONG Reserved : 7;
} FILEOFFSET_INFORMATION;

// private
typedef struct _PAGEDIR_INFORMATION
{
    ULONGLONG DontUse : 9; // MEMORY_FRAME_INFORMATION overlay
    ULONGLONG PageDirectoryBase : 48; // private pages
    ULONGLONG Reserved : 7;
} PAGEDIR_INFORMATION;

// private
typedef struct _UNIQUE_PROCESS_INFORMATION
{
    ULONGLONG DontUse : 9; // MEMORY_FRAME_INFORMATION overlay
    ULONGLONG UniqueProcessKey : 48; // ProcessId
    ULONGLONG Reserved : 7;
} UNIQUE_PROCESS_INFORMATION, *PUNIQUE_PROCESS_INFORMATION;

// private
typedef struct _MMPFN_IDENTITY
{
    union
    {
        MEMORY_FRAME_INFORMATION e1; // all
        FILEOFFSET_INFORMATION e2; // mapped files
        PAGEDIR_INFORMATION e3; // private pages
        UNIQUE_PROCESS_INFORMATION e4; // owning process
    } u1;
    ULONG_PTR PageFrameIndex; // all
    union
    {
        struct
        {
            ULONG_PTR Image : 1;
            ULONG_PTR Mismatch : 1;
        } e1;
        struct
        {
            ULONG_PTR CombinedPage;
        } e2;
        ULONG_PTR FileObject; // mapped files
        ULONG_PTR UniqueFileObjectKey;
        ULONG_PTR ProtoPteAddress;
        ULONG_PTR VirtualAddress;  // everything else
    } u2;
} MMPFN_IDENTITY, *PMMPFN_IDENTITY;

typedef struct _MMPFN_MEMSNAP_INFORMATION
{
    ULONG_PTR InitialPageFrameIndex;
    ULONG_PTR Count;
} MMPFN_MEMSNAP_INFORMATION, *PMMPFN_MEMSNAP_INFORMATION;

#define MEM_EXECUTE_OPTION_ENABLE 0x1
#define MEM_EXECUTE_OPTION_DISABLE 0x2
#define MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION 0x4
#define MEM_EXECUTE_OPTION_PERMANENT 0x8
#define MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE 0x10
#define MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE 0x20
#define MEM_EXECUTE_OPTION_DISABLE_EXCEPTION_CHAIN_VALIDATION 0x40
#define MEM_EXECUTE_OPTION_VALID_FLAGS 0x7f

#pragma region Virtual memory

#if !defined(_KERNEL_MODE)

_Must_inspect_result_
_When_(return == 0, __drv_allocatesMem(mem))
NTSYSCALLAPI
NTSTATUS
NTAPI
NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID * BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
_Must_inspect_result_
_When_(return == 0, __drv_allocatesMem(mem))
NTSYSCALLAPI
NTSTATUS
NTAPI
NtAllocateVirtualMemoryEx(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID * BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount);
#endif

NTSYSCALLAPI
NTSTATUS
NTAPI
NtFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtReadVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead);

#if (NTDDI_VERSION >= NTDDI_WIN11_ZN)
NTSYSCALLAPI
NTSTATUS
NTAPI
NtReadVirtualMemoryEx(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead,
    _In_ ULONG Flags);
#endif

NTSYSCALLAPI
NTSTATUS
NTAPI
NtWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtFlushVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _Out_ PIO_STATUS_BLOCK IoStatus);

#endif

#if !defined(_KERNEL_MODE)

#define MAP_PROCESS 1
#define MAP_SYSTEM 2

NTSYSCALLAPI
NTSTATUS
NTAPI
NtLockVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG MapType);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtUnlockVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG MapType);

#endif

#pragma endregion

#pragma region Section

#define SEC_DRIVER_IMAGE 0x00100000 // rev

#if !defined(_KERNEL_MODE)
typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;
#endif

#if !defined(_KERNEL_MODE)

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateSectionEx(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount);
#endif

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtMapViewOfSection(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID * BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
NTSYSCALLAPI
NTSTATUS
NTAPI
NtMapViewOfSectionEx(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID * BaseAddress,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount);
#endif

NTSYSCALLAPI
NTSTATUS
NTAPI
NtUnmapViewOfSection(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress);

#if (NTDDI_VERSION >= NTDDI_WIN8)
NTSYSCALLAPI
NTSTATUS
NTAPI
NtUnmapViewOfSectionEx(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ ULONG Flags);
#endif

NTSYSCALLAPI
NTSTATUS
NTAPI
NtExtendSection(
    _In_ HANDLE SectionHandle,
    _Inout_ PLARGE_INTEGER NewSectionSize);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAreMappedFilesTheSame(
    _In_ PVOID File1MappedAsAnImage,
    _In_ PVOID File2MappedAsFile);

#endif

#pragma endregion

#pragma region Partitions

#if !defined(_KERNEL_MODE)

#if (NTDDI_VERSION >= NTDDI_WIN10)

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreatePartition(
    _In_opt_ HANDLE ParentPartitionHandle,
    _Out_ PHANDLE PartitionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG PreferredNode);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenPartition(
    _Out_ PHANDLE PartitionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

#endif

#endif

#pragma endregion

#pragma region User physical pages

#if !defined(_KERNEL_MODE)

NTSYSCALLAPI
NTSTATUS
NTAPI
NtMapUserPhysicalPages(
    _In_ PVOID VirtualAddress,
    _In_ ULONG_PTR NumberOfPages,
    _In_reads_opt_(NumberOfPages) PULONG_PTR UserPfnArray);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtMapUserPhysicalPagesScatter(
    _In_reads_(NumberOfPages) PVOID* VirtualAddresses,
    _In_ ULONG_PTR NumberOfPages,
    _In_reads_opt_(NumberOfPages) PULONG_PTR UserPfnArray);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAllocateUserPhysicalPages(
    _In_ HANDLE ProcessHandle,
    _Inout_ PULONG_PTR NumberOfPages,
    _Out_writes_(*NumberOfPages) PULONG_PTR UserPfnArray);

#if (NTDDI_VERSION >= NTDDI_WIN10)
NTSYSCALLAPI
NTSTATUS
NTAPI
NtAllocateUserPhysicalPagesEx(
    _In_ HANDLE ProcessHandle,
    _Inout_ PULONG_PTR NumberOfPages,
    _Out_writes_(*NumberOfPages) PULONG_PTR UserPfnArray,
    _Inout_updates_opt_(ParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
);
#endif

NTSYSCALLAPI
NTSTATUS
NTAPI
NtFreeUserPhysicalPages(
    _In_ HANDLE ProcessHandle,
    _Inout_ PULONG_PTR NumberOfPages,
    _In_reads_(*NumberOfPages) PULONG_PTR UserPfnArray);

#endif

#pragma endregion

// Misc.

#if !defined(_KERNEL_MODE)

NTSYSCALLAPI
NTSTATUS
NTAPI
NtGetWriteWatch(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG Flags,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _Out_writes_(*EntriesInUserAddressArray) PVOID* UserAddressArray,
    _Inout_ PULONG_PTR EntriesInUserAddressArray,
    _Out_ PULONG Granularity);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtResetWriteWatch(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreatePagingFile(
    _In_ PUNICODE_STRING PageFileName,
    _In_ PLARGE_INTEGER MinimumSize,
    _In_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG Priority);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtFlushInstructionCache(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ SIZE_T Length);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtFlushWriteBuffer(VOID);

#endif

#pragma region Enclave

#if (NTDDI_VERSION >= NTDDI_WIN10)

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateEnclave(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T Size,
    _In_ SIZE_T InitialCommitment,
    _In_ ULONG EnclaveType,
    _In_reads_bytes_(EnclaveInformationLength) PVOID EnclaveInformation,
    _In_ ULONG EnclaveInformationLength,
    _Out_opt_ PULONG EnclaveError);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtLoadEnclaveData(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _In_ ULONG Protect,
    _In_reads_bytes_(PageInformationLength) PVOID PageInformation,
    _In_ ULONG PageInformationLength,
    _Out_opt_ PSIZE_T NumberOfBytesWritten,
    _Out_opt_ PULONG EnclaveError);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtInitializeEnclave(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_reads_bytes_(EnclaveInformationLength) PVOID EnclaveInformation,
    _In_ ULONG EnclaveInformationLength,
    _Out_opt_ PULONG EnclaveError);

#define TERMINATE_ENCLAVE_FLAG_NO_WAIT    0x00000001ul
#define TERMINATE_ENCLAVE_FLAG_WAIT_ERROR 0x00000004ul // STATUS_PENDING -> STATUS_ENCLAVE_NOT_TERMINATED
#define TERMINATE_ENCLAVE_VALID_FLAGS     0x00000005ul

NTSYSCALLAPI
NTSTATUS
NTAPI
NtTerminateEnclave(
    _In_ PVOID BaseAddress,
    _In_ ULONG Flags // TERMINATE_ENCLAVE_FLAG_*
);

#if !defined(_KERNEL_MODE)

#define ENCLAVE_CALL_VALID_FLAGS  0x00000001ul
#define ENCLAVE_CALL_FLAG_NO_WAIT 0x00000001ul

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCallEnclave(
    _In_ PENCLAVE_ROUTINE Routine,
    _In_ PVOID Reserved,              // reserved for dispatch (RtlEnclaveCallDispatch)
    _In_ ULONG Flags,                 // ENCLAVE_CALL_FLAG_*
    _Inout_ PVOID* RoutineParamReturn // input routine parameter, output routine return value
);
#endif

#endif

#pragma endregion

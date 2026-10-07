#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

/**
 * Describes a single heap block returned when walking a heap.
 */
typedef struct _RTL_HEAP_ENTRY
{
    SIZE_T Size;
    USHORT Flags;
    USHORT AllocatorBackTraceIndex;
    union
    {
        struct
        {
            SIZE_T Settable;
            ULONG Tag;
        } s1;
        struct
        {
            SIZE_T CommittedSize;
            PVOID FirstBlock;
        } s2;
    } u;
} RTL_HEAP_ENTRY, *PRTL_HEAP_ENTRY;

/**
 * Flags describing the state of a heap entry returned by RtlWalkHeap.
 */
#define RTL_HEAP_BUSY (USHORT)0x0001
#define RTL_HEAP_SEGMENT (USHORT)0x0002
#define RTL_HEAP_SETTABLE_VALUE (USHORT)0x0010
#define RTL_HEAP_SETTABLE_FLAG1 (USHORT)0x0020
#define RTL_HEAP_SETTABLE_FLAG2 (USHORT)0x0040
#define RTL_HEAP_SETTABLE_FLAG3 (USHORT)0x0080
#define RTL_HEAP_SETTABLE_FLAGS (USHORT)0x00e0
#define RTL_HEAP_UNCOMMITTED_RANGE (USHORT)0x1000
#define RTL_HEAP_PROTECTED_ENTRY (USHORT)0x2000
#define RTL_HEAP_LARGE_ALLOC (USHORT)0x4000
#define RTL_HEAP_LFH_ALLOC (USHORT)0x8000

/**
 * Describes a heap allocation tag and its associated statistics.
 */
typedef struct _RTL_HEAP_TAG
{
    ULONG NumberOfAllocations;
    ULONG NumberOfFrees;
    SIZE_T BytesAllocated;
    USHORT TagIndex;
    USHORT CreatorBackTraceIndex;
    WCHAR TagName[24];
} RTL_HEAP_TAG, *PRTL_HEAP_TAG;

// Windows 7/8/10
/**
 * Describes a single heap (version 1) in a process heap information snapshot.
 */
typedef struct _RTL_HEAP_INFORMATION_V1
{
    PVOID BaseAddress;
    ULONG Flags;
    USHORT EntryOverhead;
    USHORT CreatorBackTraceIndex;
    SIZE_T BytesAllocated;
    SIZE_T BytesCommitted;
    ULONG NumberOfTags;
    ULONG NumberOfEntries;
    ULONG NumberOfPseudoTags;
    ULONG PseudoTagGranularity;
    ULONG Reserved[5];
    PRTL_HEAP_TAG Tags;
    PRTL_HEAP_ENTRY Entries;
} RTL_HEAP_INFORMATION_V1, *PRTL_HEAP_INFORMATION_V1;

// Windows 11 > 22000
/**
 * Describes a single heap (version 2) in a process heap information snapshot.
 */
typedef struct _RTL_HEAP_INFORMATION_V2
{
    PVOID BaseAddress;
    ULONG Flags;
    USHORT EntryOverhead;
    USHORT CreatorBackTraceIndex;
    SIZE_T BytesAllocated;
    SIZE_T BytesCommitted;
    ULONG NumberOfTags;
    ULONG NumberOfEntries;
    ULONG NumberOfPseudoTags;
    ULONG PseudoTagGranularity;
    ULONG Reserved[5];
    PRTL_HEAP_TAG Tags;
    PRTL_HEAP_ENTRY Entries;
    ULONG64 HeapTag;
} RTL_HEAP_INFORMATION_V2, *PRTL_HEAP_INFORMATION_V2;

/**
 * Signature values identifying heap information structures.
 */
#define RTL_HEAP_SIGNATURE 0xFFEEFFEEUL
#define RTL_HEAP_SEGMENT_SIGNATURE 0xDDEEDDEEUL

/**
 * Contains version 1 information about all heaps in a process.
 */
typedef struct _RTL_PROCESS_HEAPS_V1
{
    ULONG NumberOfHeaps;
    _Field_size_(NumberOfHeaps) RTL_HEAP_INFORMATION_V1 Heaps[1];
} RTL_PROCESS_HEAPS_V1, *PRTL_PROCESS_HEAPS_V1;

/**
 * Contains version 2 information about all heaps in a process.
 */
typedef struct _RTL_PROCESS_HEAPS_V2
{
    ULONG NumberOfHeaps;
    _Field_size_(NumberOfHeaps) RTL_HEAP_INFORMATION_V2 Heaps[1];
} RTL_PROCESS_HEAPS_V2, *PRTL_PROCESS_HEAPS_V2;

// Segment heap parameters.

/**
 * Identifies the type of memory backing a heap allocation.
 */
typedef enum _RTL_MEMORY_TYPE
{
    MemoryTypePaged,
    MemoryTypeNonPaged,
    MemoryType64KPage,
    MemoryTypeLargePage,
    MemoryTypeHugePage,
    MemoryTypeCustom,
    MemoryTypeMax
} RTL_MEMORY_TYPE, *PRTL_MEMORY_TYPE;

/**
 * Identifies the class of heap memory information being queried.
 */
typedef enum _HEAP_MEMORY_INFO_CLASS
{
    HeapMemoryBasicInformation
} HEAP_MEMORY_INFO_CLASS;

typedef NTSTATUS ALLOCATE_VIRTUAL_MEMORY_EX_CALLBACK(
    _Inout_ HANDLE CallbackContext,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
);

/**
 * Pointer to an ALLOCATE_VIRTUAL_MEMORY_EX_CALLBACK callback.
 */
typedef ALLOCATE_VIRTUAL_MEMORY_EX_CALLBACK *PALLOCATE_VIRTUAL_MEMORY_EX_CALLBACK;

typedef NTSTATUS FREE_VIRTUAL_MEMORY_EX_CALLBACK(
    _Inout_ HANDLE CallbackContext,
    _In_ HANDLE ProcessHandle,
    _Inout_ __drv_freesMem(Mem) PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
);

/**
 * Pointer to a FREE_VIRTUAL_MEMORY_EX_CALLBACK callback.
 */
typedef FREE_VIRTUAL_MEMORY_EX_CALLBACK *PFREE_VIRTUAL_MEMORY_EX_CALLBACK;

typedef NTSTATUS QUERY_VIRTUAL_MEMORY_CALLBACK(
    _Inout_ HANDLE CallbackContext,
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ HEAP_MEMORY_INFO_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

/**
 * Pointer to a QUERY_VIRTUAL_MEMORY_CALLBACK callback.
 */
typedef QUERY_VIRTUAL_MEMORY_CALLBACK *PQUERY_VIRTUAL_MEMORY_CALLBACK;

/**
 * Specifies callbacks used by a segment heap to manage its virtual address space.
 */
typedef struct _RTL_SEGMENT_HEAP_VA_CALLBACKS
{
    HANDLE CallbackContext;
    PALLOCATE_VIRTUAL_MEMORY_EX_CALLBACK AllocateVirtualMemory;
    PFREE_VIRTUAL_MEMORY_EX_CALLBACK FreeVirtualMemory;
    PQUERY_VIRTUAL_MEMORY_CALLBACK QueryVirtualMemory;
} RTL_SEGMENT_HEAP_VA_CALLBACKS, *PRTL_SEGMENT_HEAP_VA_CALLBACKS;

/**
 * Value selecting any NUMA node for a segment heap memory source.
 */
#define RTL_SEGHEAP_MEM_SOURCE_ANY_NODE ((ULONG)-1)

/**
 * Describes the memory source used to back a segment heap.
 */
typedef struct _RTL_SEGMENT_HEAP_MEMORY_SOURCE
{
    ULONG Flags;
    ULONG MemoryTypeMask; // Mask of RTL_MEMORY_TYPE members.
    ULONG NumaNode;
    union
    {
        HANDLE PartitionHandle;
        RTL_SEGMENT_HEAP_VA_CALLBACKS *Callbacks;
    } DUMMYUNIONNAME;
    SIZE_T Reserved[2];
} RTL_SEGMENT_HEAP_MEMORY_SOURCE, *PRTL_SEGMENT_HEAP_MEMORY_SOURCE;

/**
 * Version and flag values for segment heap parameters.
 */
#define SEGMENT_HEAP_PARAMETERS_VERSION         3
#define SEGMENT_HEAP_FLG_USE_PAGE_HEAP          0x1
#define SEGMENT_HEAP_FLG_NO_LFH                 0x2
#define SEGMENT_HEAP_PARAMS_VALID_FLAGS         0x3

/**
 * Specifies configuration parameters for a segment heap.
 */
typedef struct _RTL_SEGMENT_HEAP_PARAMETERS
{
    USHORT Version;
    USHORT Size;
    ULONG Flags;
    RTL_SEGMENT_HEAP_MEMORY_SOURCE MemorySource;
    SIZE_T Reserved[4];
} RTL_SEGMENT_HEAP_PARAMETERS, *PRTL_SEGMENT_HEAP_PARAMETERS;

// Heap parameters.

typedef
_Function_class_(RTL_HEAP_COMMIT_ROUTINE)
NTSTATUS
NTAPI
RTL_HEAP_COMMIT_ROUTINE(
    _In_ PVOID Base,
    _Inout_ PVOID* CommitAddress,
    _Inout_ PSIZE_T CommitSize
);

/**
 * Pointer to an RTL_HEAP_COMMIT_ROUTINE callback.
 */
typedef RTL_HEAP_COMMIT_ROUTINE* PRTL_HEAP_COMMIT_ROUTINE;

/**
 * Specifies configuration parameters for a heap created by RtlCreateHeap.
 */
typedef struct _RTL_HEAP_PARAMETERS
{
    ULONG Length;
    SIZE_T SegmentReserve;
    SIZE_T SegmentCommit;
    SIZE_T DeCommitFreeBlockThreshold;
    SIZE_T DeCommitTotalFreeThreshold;
    SIZE_T MaximumAllocationSize;
    SIZE_T VirtualMemoryThreshold;
    SIZE_T InitialCommit;
    SIZE_T InitialReserve;
    PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
    SIZE_T Reserved[2];
} RTL_HEAP_PARAMETERS, *PRTL_HEAP_PARAMETERS;

/**
 * Flags controlling heap allocation behavior.
 */
#define HEAP_SETTABLE_USER_VALUE 0x00000100
#define HEAP_SETTABLE_USER_FLAG1 0x00000200
#define HEAP_SETTABLE_USER_FLAG2 0x00000400
#define HEAP_SETTABLE_USER_FLAG3 0x00000800
#define HEAP_SETTABLE_USER_FLAGS 0x00000e00

/**
 * Heap class identifiers encoded in the heap creation flags.
 */
#define HEAP_CLASS_0 0x00000000 // Process heap
#define HEAP_CLASS_1 0x00001000 // Private heap
#define HEAP_CLASS_2 0x00002000 // Kernel heap
#define HEAP_CLASS_3 0x00003000 // GDI heap
#define HEAP_CLASS_4 0x00004000 // User heap
#define HEAP_CLASS_5 0x00005000 // Console heap
#define HEAP_CLASS_6 0x00006000 // User desktop heap
#define HEAP_CLASS_7 0x00007000 // CSR shared heap
#define HEAP_CLASS_8 0x00008000 // CSR port heap
#define HEAP_CLASS_MASK 0x0000f000

#define HEAP_MAXIMUM_TAG 0x0FFF
#define HEAP_GLOBAL_TAG 0x0800
#define HEAP_PSEUDO_TAG_FLAG 0x8000
#define HEAP_TAG_SHIFT 18
#define HEAP_TAG_MASK (HEAP_MAXIMUM_TAG << HEAP_TAG_SHIFT)

#define HEAP_CREATE_SEGMENT_HEAP 0x00000100
//
// Only applies to segment heap. Applies pointer obfuscation which is
// generally excessive and unnecessary but is necessary for certain insecure
// heaps in win32k.
//
// Specifying HEAP_CREATE_HARDENED prevents the heap from using locks as
// pointers would potentially be exposed in heap metadata lock variables.
// Callers are therefore responsible for synchronizing access to hardened heaps.
//
#define HEAP_CREATE_HARDENED 0x00000200

_Must_inspect_result_
NTSYSAPI
HANDLE
NTAPI
RtlCreateHeap(
    _In_ ULONG Flags,
    _In_opt_ PVOID HeapBase,
    _In_opt_ SIZE_T ReserveSize,
    _In_opt_ SIZE_T CommitSize,
    _In_opt_ PVOID Lock,
    _When_((Flags & HEAP_CREATE_SEGMENT_HEAP) != 0, _In_reads_bytes_opt_(sizeof(RTL_SEGMENT_HEAP_PARAMETERS)))
    _When_((Flags & HEAP_CREATE_SEGMENT_HEAP) == 0, _In_reads_bytes_opt_(sizeof(RTL_HEAP_PARAMETERS)))
    _In_opt_ PVOID Parameters
);

NTSYSAPI
PVOID
NTAPI
RtlDestroyHeap(
    _In_ _Post_invalid_ HANDLE HeapHandle
);

_Success_(return != 0)
_Must_inspect_result_
_Ret_maybenull_
_Post_writable_byte_size_(Size)
NTSYSAPI
DECLSPEC_ALLOCATOR
DECLSPEC_NOALIAS
DECLSPEC_RESTRICT
PVOID
NTAPI
RtlAllocateHeap(
    _In_ HANDLE HeapHandle,
    _In_opt_ ULONG Flags,
    _In_ SIZE_T Size
);

#if (NT_VERSION_MIN >= NT_VERSION_WIN8)
/**
 * The RtlFreeHeap routine frees a memory block allocated from a heap.
 *
 * \param HeapHandle A handle to the heap from which the block was allocated.
 * \param Flags Heap free flags (for example, HEAP_NO_SERIALIZE).
 * \param BaseAddress The block to free.
 * \return TRUE if the block was freed; otherwise, FALSE.
 */
_Success_(return != 0)
NTSYSAPI
LOGICAL
NTAPI
RtlFreeHeap(
    _In_ HANDLE HeapHandle,
    _In_opt_ ULONG Flags,
    _Frees_ptr_opt_ _Post_invalid_ PVOID BaseAddress
);
#else
_Success_(return)
NTSYSAPI
BOOLEAN
NTAPI
RtlFreeHeap(
    _In_ HANDLE HeapHandle,
    _In_opt_ ULONG Flags,
    _Frees_ptr_opt_ PVOID BaseAddress
);
#endif

/**
 * The RtlSizeHeap routine returns the size, in bytes, of a memory block allocated from a heap.
 *
 * \param HeapHandle A handle to the heap from which the block was allocated.
 * \param Flags Heap access flags (for example, HEAP_NO_SERIALIZE).
 * \param BaseAddress A pointer to the memory block whose size is queried.
 * \return SIZE_T The size, in bytes, of the memory block, or (SIZE_T)-1 if the block is invalid.
 */
NTSYSAPI
SIZE_T
NTAPI
RtlSizeHeap(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Flags,
    _In_ PVOID BaseAddress
);

/**
 * The RtlZeroHeap routine zeroes the memory of the specified heap.
 *
 * \param HeapHandle A handle to the heap to zero.
 * \param Flags Heap access flags (for example, HEAP_NO_SERIALIZE).
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlZeroHeap(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Flags
);

/**
 * The RtlProtectHeap routine makes the specified heap read-only or read-write.
 *
 * \param HeapHandle A handle to the heap to protect.
 * \param MakeReadOnly A boolean that specifies whether the heap is made read-only (`TRUE`) or read-write (`FALSE`).
 */
NTSYSAPI
VOID
NTAPI
RtlProtectHeap(
    _In_ HANDLE HeapHandle,
    _In_ BOOLEAN MakeReadOnly
);

/**
 * The RtlLockHeap routine acquires exclusive access to the specified heap, serializing access from other threads.
 *
 * \param HeapHandle A handle to the heap to lock.
 * \return `TRUE` if the heap was locked, otherwise `FALSE`.
 */
_When_(return != 0, _Acquires_lock_(HeapHandle))
NTSYSAPI
BOOLEAN
NTAPI
RtlLockHeap(
    _In_ HANDLE HeapHandle
);

/**
 * The RtlUnlockHeap routine releases exclusive access to the specified heap previously acquired with RtlLockHeap.
 *
 * \param HeapHandle A handle to the heap to unlock.
 * \return `TRUE` if the heap was unlocked, otherwise `FALSE`.
 */
_When_(return != 0, _Releases_lock_(HeapHandle))
NTSYSAPI
BOOLEAN
NTAPI
RtlUnlockHeap(
    _In_ HANDLE HeapHandle
);

/**
 * The RtlReAllocateHeap routine reallocates a memory block from a heap, changing its size.
 *
 * \param HeapHandle A handle to the heap from which the block was allocated.
 * \param Flags Heap allocation flags (for example, HEAP_ZERO_MEMORY).
 * \param BaseAddress The block to reallocate.
 * \param Size The new size, in bytes, of the block.
 * \return A pointer to the reallocated block, or NULL on failure.
 */
_Success_(return != 0)
_Must_inspect_result_
_Ret_maybenull_
_Post_writable_byte_size_(Size)
_When_(Size > 0, __drv_allocatesMem(Mem))
NTSYSAPI
DECLSPEC_ALLOCATOR
DECLSPEC_NOALIAS
DECLSPEC_RESTRICT
PVOID
NTAPI
RtlReAllocateHeap(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Flags,
    _Frees_ptr_opt_ PVOID BaseAddress,
    _In_ SIZE_T Size
);

/**
 * The RtlGetUserInfoHeap routine retrieves the user value and user flags associated with a heap block.
 *
 * \param HeapHandle A handle to the heap.
 * \param Flags Heap flags.
 * \param BaseAddress The heap block to query.
 * \param UserValue An optional pointer that receives the user value.
 * \param UserFlags An optional pointer that receives the user flags.
 * \return TRUE if the information was retrieved; otherwise, FALSE.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlGetUserInfoHeap(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Flags,
    _In_ PVOID BaseAddress,
    _Out_opt_ PVOID * UserValue,
    _Out_opt_ PULONG UserFlags
);

/**
 * The RtlSetUserValueHeap routine associates a user value with a heap block.
 *
 * \param HeapHandle A handle to the heap.
 * \param Flags Heap flags.
 * \param BaseAddress The heap block to modify.
 * \param UserValue The user value to associate with the block.
 * \return TRUE if the value was set; otherwise, FALSE.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlSetUserValueHeap(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Flags,
    _In_ PVOID BaseAddress,
    _In_ PVOID UserValue
);

/**
 * The RtlSetUserFlagsHeap routine modifies the user flags associated with a heap block.
 *
 * \param HeapHandle A handle to the heap.
 * \param Flags Heap flags.
 * \param BaseAddress The heap block to modify.
 * \param UserFlagsReset The user flags to clear.
 * \param UserFlagsSet The user flags to set.
 * \return TRUE if the flags were modified; otherwise, FALSE.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlSetUserFlagsHeap(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Flags,
    _In_ PVOID BaseAddress,
    _In_ ULONG UserFlagsReset,
    _In_ ULONG UserFlagsSet
);

/**
 * Receives allocation statistics for a heap tag.
 */
typedef struct _RTL_HEAP_TAG_INFO
{
    ULONG NumberOfAllocations;
    ULONG NumberOfFrees;
    SIZE_T BytesAllocated;
} RTL_HEAP_TAG_INFO, *PRTL_HEAP_TAG_INFO;

/**
 * Constructs a heap tag value from a tag base and index.
 */
#define RTL_HEAP_MAKE_TAG HEAP_MAKE_TAG_FLAGS

/**
 * The RtlCreateTagHeap routine creates a set of allocation tags used to track allocations within the specified heap.
 *
 * \param HeapHandle A handle to the heap for which tags are created.
 * \param Flags Flags that control tag creation.
 * \param TagPrefix An optional prefix applied to each created tag name.
 * \param TagNames A pointer to a multi-string containing the tag names to create.
 * \return ULONG The base tag index for the created tags.
 */
NTSYSAPI
ULONG
NTAPI
RtlCreateTagHeap(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Flags,
    _In_opt_ PCWSTR TagPrefix,
    _In_ PCWSTR TagNames
);

/**
 * The RtlQueryTagHeap routine retrieves usage statistics and the name for a heap allocation tag.
 *
 * \param HeapHandle A handle to the heap to query.
 * \param Flags Flags that control the query.
 * \param TagIndex The index of the tag to query.
 * \param ResetCounters A boolean that specifies whether the tag usage counters are reset after the query.
 * \param TagInfo An optional pointer to a structure that receives the tag usage information.
 * \return PWSTR A pointer to the tag name string.
 */
NTSYSAPI
PWSTR
NTAPI
RtlQueryTagHeap(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Flags,
    _In_ USHORT TagIndex,
    _In_ BOOLEAN ResetCounters,
    _Out_opt_ PRTL_HEAP_TAG_INFO TagInfo
);

/**
 * The RtlExtendHeap routine extends a heap by adding a caller-supplied memory region.
 *
 * \param HeapHandle A handle to the heap to extend.
 * \param Flags Heap flags.
 * \param Base The base address of the memory region to add.
 * \param Size The size, in bytes, of the memory region.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlExtendHeap(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Flags,
    _In_ PVOID Base,
    _In_ SIZE_T Size
);

/**
 * The RtlCompactHeap routine coalesces adjacent free blocks in the specified heap and returns the size of the largest
 * committed free block.
 *
 * \param HeapHandle A handle to the heap to compact.
 * \param Flags Heap access flags (for example, HEAP_NO_SERIALIZE).
 * \return SIZE_T The size, in bytes, of the largest committed free block.
 */
NTSYSAPI
SIZE_T
NTAPI
RtlCompactHeap(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Flags
);

/**
 * The RtlValidateHeap routine validates the internal consistency of a heap or a single heap allocation.
 *
 * \param HeapHandle An optional handle to the heap; NULL validates all process heaps.
 * \param Flags Heap flags.
 * \param BaseAddress An optional specific allocation to validate; NULL validates the whole heap.
 * \return TRUE if the heap (or allocation) is valid; otherwise, FALSE.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlValidateHeap(
    _In_opt_ HANDLE HeapHandle,
    _In_ ULONG Flags,
    _In_opt_ PVOID BaseAddress
);

/**
 * The RtlValidateProcessHeaps routine validates the integrity of all heaps in the current process.
 *
 * \return `TRUE` if all heaps are valid, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlValidateProcessHeaps(
    VOID
);

/**
 * The RtlGetProcessHeaps routine retrieves handles to the heaps currently active in the process.
 *
 * \param NumberOfHeaps The capacity, in entries, of the ProcessHeaps array.
 * \param ProcessHeaps A buffer that receives the heap handles.
 * \return The number of heaps active in the process.
 */
NTSYSAPI
ULONG
NTAPI
RtlGetProcessHeaps(
    _In_ ULONG NumberOfHeaps,
    _Out_ PVOID* ProcessHeaps
);

typedef
_Function_class_(RTL_ENUM_HEAPS_ROUTINE)
NTSTATUS
NTAPI
RTL_ENUM_HEAPS_ROUTINE(
    _In_ HANDLE HeapHandle,
    _In_ PVOID Parameter
    );
/**
 * Pointer to an RTL_ENUM_HEAPS_ROUTINE callback.
 */
typedef RTL_ENUM_HEAPS_ROUTINE *PRTL_ENUM_HEAPS_ROUTINE;

/**
 * The RtlEnumProcessHeaps routine enumerates the heaps of the process, invoking a callback for each.
 *
 * \param EnumRoutine The callback invoked for each process heap.
 * \param Parameter A caller-defined value passed to the callback.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlEnumProcessHeaps(
    _In_ PRTL_ENUM_HEAPS_ROUTINE EnumRoutine,
    _In_ PVOID Parameter
);

/**
 * Describes the usage of a single allocated heap block.
 */
typedef struct _RTL_HEAP_USAGE_ENTRY
{
    struct _RTL_HEAP_USAGE_ENTRY *Next;
    PVOID Address;
    SIZE_T Size;
    USHORT AllocatorBackTraceIndex;
    USHORT TagIndex;
} RTL_HEAP_USAGE_ENTRY, *PRTL_HEAP_USAGE_ENTRY;

/**
 * Describes the overall usage of a heap, including a list of allocated blocks.
 */
typedef struct _RTL_HEAP_USAGE
{
    ULONG Length;
    SIZE_T BytesAllocated;
    SIZE_T BytesCommitted;
    SIZE_T BytesReserved;
    SIZE_T BytesReservedMaximum;
    PRTL_HEAP_USAGE_ENTRY Entries;
    PRTL_HEAP_USAGE_ENTRY AddedEntries;
    PRTL_HEAP_USAGE_ENTRY RemovedEntries;
    ULONG_PTR Reserved[8];
} RTL_HEAP_USAGE, *PRTL_HEAP_USAGE;

/**
 * Flags for RtlUsageHeap.
 */
#define HEAP_USAGE_ALLOCATED_BLOCKS HEAP_REALLOC_IN_PLACE_ONLY
#define HEAP_USAGE_FREE_BUFFER HEAP_ZERO_MEMORY

/**
 * The RtlUsageHeap routine retrieves usage information for the specified heap.
 *
 * \param HeapHandle A handle to the heap to query.
 * \param Flags Flags that control the query.
 * \param Usage A pointer to a structure that receives the heap usage information.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUsageHeap(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Flags,
    _Inout_ PRTL_HEAP_USAGE Usage
);

/**
 * Describes a single entry returned when walking a heap with RtlWalkHeap.
 */
typedef struct _RTL_HEAP_WALK_ENTRY
{
    PVOID DataAddress;
    SIZE_T DataSize;
    UCHAR OverheadBytes;
    UCHAR SegmentIndex;
    USHORT Flags;
    union
    {
        struct
        {
            SIZE_T Settable;
            USHORT TagIndex;
            USHORT AllocatorBackTraceIndex;
            ULONG Reserved[2];
        } Block;
        struct
        {
            ULONG CommittedSize;
            ULONG UnCommittedSize;
            PVOID FirstEntry;
            PVOID LastEntry;
        } Segment;
    };
} RTL_HEAP_WALK_ENTRY, *PRTL_HEAP_WALK_ENTRY;

/**
 * The RtlWalkHeap routine enumerates the allocated and free blocks of the specified heap.
 *
 * \param HeapHandle A handle to the heap to enumerate.
 * \param Entry A pointer to a structure that receives the next heap block and maintains enumeration state.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlWalkHeap(
    _In_ HANDLE HeapHandle,
    _Inout_ PRTL_HEAP_WALK_ENTRY Entry
);

typedef enum _HEAP_INFORMATION_CLASS
{
    HeapCompatibilityInformation = 0, // q; s: ULONG
    HeapEnableTerminationOnCorruption = 1, // q; s: NULL
    HeapExtendedInformation = 2, // q; s: HEAP_EXTENDED_INFORMATION
    HeapOptimizeResources = 3, // q; s: HEAP_OPTIMIZE_RESOURCES_INFORMATION
    HeapTaggingInformation = 4, // q: RTLP_HEAP_TAGGING_INFO
    HeapStackDatabase = 5, // q: RTL_HEAP_STACK_QUERY; s: RTL_HEAP_STACK_CONTROL
    HeapMemoryLimit = 6, // q: since 19H2
    HeapTag = 7, // q: since 20H1
    HeapDetailedFailureInformation = 0x80000001,
    HeapSetDebuggingInformation = 0x80000002 // q; s: HEAP_DEBUGGING_INFORMATION
} HEAP_INFORMATION_CLASS;

/* HeapCompatibilityInformation */

#define HEAP_STANDARD   0UL
#define HEAP_LAL        1UL // Lookaside list heap (LAL) compatibility mode.
#define HEAP_LFH        2UL // Low-fragmentation heap (LFH) compatibility mode.

/**
 * Describes a heap tagging information entry.
 */
typedef struct _RTLP_TAG_INFO
{
    GUID Id;
    SIZE_T CurrentAllocatedBytes;
} RTLP_TAG_INFO, *PRTLP_TAG_INFO;

/**
 * Version number of the heap tagging information structure.
 */
#define RTLP_HEAP_TAGGING_INFO_VERSION 0x1

/**
 * Contains heap tagging information for a heap.
 */
typedef struct _RTLP_HEAP_TAGGING_INFO
{
    USHORT Version;
    USHORT Flags; // 1: Multiple Tags, 2: Single Tag + Hash
    HANDLE ProcessHandle;
    SIZE_T EntriesCount;
    RTLP_TAG_INFO Entries[1];
} RTLP_HEAP_TAGGING_INFO, *PRTLP_HEAP_TAGGING_INFO;

/**
 * Contains summary heap information for a process.
 */
typedef struct _PROCESS_HEAP_INFORMATION
{
    SIZE_T ReserveSize;
    SIZE_T CommitSize;
    ULONG NumberOfHeaps;
    ULONG_PTR FirstHeapInformationOffset;
} PROCESS_HEAP_INFORMATION, *PPROCESS_HEAP_INFORMATION;

/**
 * Describes a memory region belonging to a heap.
 */
typedef struct _HEAP_REGION_INFORMATION
{
    PVOID Address;
    SIZE_T ReserveSize;
    SIZE_T CommitSize;
    ULONG_PTR FirstRangeInformationOffset;
    ULONG_PTR NextRegionInformationOffset;
} HEAP_REGION_INFORMATION, *PHEAP_REGION_INFORMATION;

/**
 * Describes a range of memory within a heap region.
 */
typedef struct _HEAP_RANGE_INFORMATION
{
    PVOID Address;
    SIZE_T Size;
    ULONG Type;
    ULONG Protection;
    ULONG_PTR FirstBlockInformationOffset;
    ULONG_PTR NextRangeInformationOffset;
} HEAP_RANGE_INFORMATION, *PHEAP_RANGE_INFORMATION;

/**
 * Describes a single block within a heap range.
 */
typedef struct _HEAP_BLOCK_INFORMATION
{
    PVOID Address;
    ULONG Flags;
    SIZE_T DataSize;
    ULONG_PTR OverheadSize;
    ULONG_PTR NextBlockInformationOffset;
} HEAP_BLOCK_INFORMATION, *PHEAP_BLOCK_INFORMATION;

/**
 * Describes a heap and its associated regions, ranges, and blocks.
 */
typedef struct _HEAP_INFORMATION
{
    PVOID Address;
    ULONG Mode;
    SIZE_T ReserveSize;
    SIZE_T CommitSize;
    ULONG_PTR FirstRegionInformationOffset;
    ULONG_PTR NextHeapInformationOffset;
} HEAP_INFORMATION, *PHEAP_INFORMATION;

/**
 * Contains performance counters for a segment heap.
 */
typedef struct _SEGMENT_HEAP_PERFORMANCE_COUNTER_INFORMATION
{
    SIZE_T SegmentReserveSize;
    SIZE_T SegmentCommitSize;
    SIZE_T SegmentCount;
    SIZE_T AllocatedSize;
    SIZE_T LargeAllocReserveSize;
    SIZE_T LargeAllocCommitSize;
} SEGMENT_HEAP_PERFORMANCE_COUNTER_INFORMATION, *PSEGMENT_HEAP_PERFORMANCE_COUNTER_INFORMATION;

/**
 * Version numbers of the heap performance counter information structures.
 */
#define HeapPerformanceCountersInformationStandardHeapVersion 0x1
#define HeapPerformanceCountersInformationSegmentHeapVersion 0x2

/**
 * Contains performance counters describing heap activity.
 */
typedef struct _HEAP_PERFORMANCE_COUNTERS_INFORMATION
{
    ULONG Size;
    ULONG Version;
    ULONG HeapIndex;
    ULONG LastHeapIndex;
    PVOID BaseAddress;
    SIZE_T ReserveSize;
    SIZE_T CommitSize;
    ULONG SegmentCount;
    SIZE_T LargeUCRMemory;
    ULONG UCRLength;
    SIZE_T AllocatedSpace;
    SIZE_T FreeSpace;
    ULONG FreeListLength;
    ULONG Contention;
    ULONG VirtualBlocks;
    ULONG CommitRate;
    ULONG DecommitRate;
    SEGMENT_HEAP_PERFORMANCE_COUNTER_INFORMATION SegmentHeapPerfInformation; // since WIN8
} HEAP_PERFORMANCE_COUNTERS_INFORMATION, *PHEAP_PERFORMANCE_COUNTERS_INFORMATION;

/**
 * Describes a single item in an extended heap information query.
 */
typedef struct _HEAP_INFORMATION_ITEM
{
    ULONG Level;
    SIZE_T Size;
    union
    {
        PROCESS_HEAP_INFORMATION ProcessHeapInformation;
        HEAP_INFORMATION HeapInformation;
        HEAP_REGION_INFORMATION HeapRegionInformation;
        HEAP_RANGE_INFORMATION HeapRangeInformation;
        HEAP_BLOCK_INFORMATION HeapBlockInformation;
        HEAP_PERFORMANCE_COUNTERS_INFORMATION HeapPerfInformation;
        ULONG_PTR DynamicStart;
    };
} HEAP_INFORMATION_ITEM, *PHEAP_INFORMATION_ITEM;

/**
 * Pointer to an RTL_HEAP_EXTENDED_ENUMERATION_ROUTINE callback.
 */
typedef NTSTATUS(NTAPI *PRTL_HEAP_EXTENDED_ENUMERATION_ROUTINE)(
    _In_ PHEAP_INFORMATION_ITEM Information,
    _In_opt_ PVOID Context
    );

// HEAP_EXTENDED_INFORMATION Level
/**
 * Information levels for extended heap information queries.
 */
#define HeapExtendedProcessHeapInformationLevel 0x1
#define HeapExtendedHeapInformationLevel 0x2
#define HeapExtendedHeapRegionInformationLevel 0x3
#define HeapExtendedHeapRangeInformationLevel 0x4
#define HeapExtendedHeapBlockInformationLevel 0x5
#define HeapExtendedHeapHeapPerfInformationLevel 0x80000000

/**
 * Contains extended information about a heap returned by a heap information query.
 */
typedef struct _HEAP_EXTENDED_INFORMATION
{
    HANDLE ProcessHandle;
    HANDLE HeapHandle;
    ULONG Level;
    PRTL_HEAP_EXTENDED_ENUMERATION_ROUTINE CallbackRoutine;
    PVOID CallbackContext;
    union
    {
        PROCESS_HEAP_INFORMATION ProcessHeapInformation;
        HEAP_INFORMATION HeapInformation;
    };
} HEAP_EXTENDED_INFORMATION, *PHEAP_EXTENDED_INFORMATION;

// rev
// Information points to one of: RTLP_HEAP_STACK_TRACE_SERIALIZATION_INIT,
// RTLP_HEAP_STACK_TRACE_SERIALIZATION_HEADER, RTLP_HEAP_STACK_TRACE_SERIALIZATION_ALLOCATION.
// A null Information/Size signals end-of-stream.
typedef NTSTATUS(NTAPI *RTL_HEAP_STACK_WRITE_ROUTINE)(
    _In_ PVOID Information,
    _In_ ULONG Size,
    _In_opt_ PVOID Context
    );

// rev - written first; Flags == 0x80001
/**
 * Describes the initialization record of a serialized heap stack-trace database.
 */
typedef struct _RTLP_HEAP_STACK_TRACE_SERIALIZATION_INIT
{
    ULONG Count;
    ULONG Total;
    ULONG Flags;
} RTLP_HEAP_STACK_TRACE_SERIALIZATION_INIT, *PRTLP_HEAP_STACK_TRACE_SERIALIZATION_INIT;

// rev - written per-heap; Version == 2, Flags/Version field == 0x80002
/**
 * Header of a serialized heap stack-trace database.
 */
typedef struct _RTLP_HEAP_STACK_TRACE_SERIALIZATION_HEADER
{
    USHORT Version;
    USHORT PointerSize;
    PVOID Heap;
    SIZE_T TotalCommit;
    SIZE_T TotalReserve;
} RTLP_HEAP_STACK_TRACE_SERIALIZATION_HEADER, *PRTLP_HEAP_STACK_TRACE_SERIALIZATION_HEADER;

// rev - written per live allocation
/**
 * Describes a serialized heap allocation record within a stack-trace database.
 */
typedef struct _RTLP_HEAP_STACK_TRACE_SERIALIZATION_ALLOCATION
{
    PVOID Address;
    ULONG Flags;
    SIZE_T DataSize;
} RTLP_HEAP_STACK_TRACE_SERIALIZATION_ALLOCATION, *PRTLP_HEAP_STACK_TRACE_SERIALIZATION_ALLOCATION;

// rev - written as end-of-heap sentinel; Address == 0x1234CDEF, DataSize == -1
/**
 * Marks the end of a serialized heap stack-trace database.
 */
typedef struct _RTLP_HEAP_STACK_TRACE_SERIALIZATION_TERMINATOR
{
    PVOID Address; // 0x1234CDEF
    ULONG Flags;
    SIZE_T DataSize; // -1
} RTLP_HEAP_STACK_TRACE_SERIALIZATION_TERMINATOR, *PRTLP_HEAP_STACK_TRACE_SERIALIZATION_TERMINATOR;

// rev - variable-length block; Max depth is 0xC0 (192).
// Determine frame count from Size / sizeof(PVOID).
/**
 * Describes a single stack frame in a serialized heap stack-trace record.
 */
typedef struct _RTLP_HEAP_STACK_TRACE_SERIALIZATION_STACKFRAME
{
    PVOID StackFrame[ANYSIZE_ARRAY]; // actual count: Size / sizeof(PVOID)
} RTLP_HEAP_STACK_TRACE_SERIALIZATION_STACKFRAME, *PRTLP_HEAP_STACK_TRACE_SERIALIZATION_STACKFRAME;

/**
 * Version number of the heap stack query structure.
 */
#define HEAP_STACK_QUERY_VERSION 0x2

/**
 * Specifies parameters for querying heap stack-trace information.
 */
typedef struct _RTL_HEAP_STACK_QUERY
{
    ULONG Version;
    HANDLE ProcessHandle;
    RTL_HEAP_STACK_WRITE_ROUTINE WriteRoutine;
    PVOID SerializationContext;
    UCHAR QueryLevel;
    UCHAR Flags;
} RTL_HEAP_STACK_QUERY, *PRTL_HEAP_STACK_QUERY;

/**
 * Version and flag values for heap stack-trace control.
 */
#define HEAP_STACK_CONTROL_VERSION 0x1
#define HEAP_STACK_CONTROL_FLAGS_STACKTRACE_ENABLE 0x1
#define HEAP_STACK_CONTROL_FLAGS_STACKTRACE_DISABLE 0x2

/**
 * Specifies parameters that control heap stack-trace collection.
 */
typedef struct _RTL_HEAP_STACK_CONTROL
{
    USHORT Version;
    USHORT Flags;
    HANDLE ProcessHandle;
} RTL_HEAP_STACK_CONTROL, *PRTL_HEAP_STACK_CONTROL;

//#define HEAP_MEMORY_USAGE_INFO_CURRENT_VERSION 0x1
//
//typedef struct _HEAP_MEMORY_USAGE_ENTRY
//{
//    PVOID HeapHandle;
//    SIZE_T TotalCommittedBytes;
//    SIZE_T TotalReservedBytes;
//} HEAP_MEMORY_USAGE_ENTRY, *PHEAP_MEMORY_USAGE_ENTRY;
//
//typedef struct _HEAP_MEMORY_USAGE_INFORMATION
//{
//    USHORT Version;
//    SIZE_T EntryCount;
//    HEAP_MEMORY_USAGE_ENTRY Entries[ANYSIZE_ARRAY];
//} HEAP_MEMORY_USAGE_INFORMATION, *PHEAP_MEMORY_USAGE_INFORMATION;

// rev
typedef
_Function_class_(RTL_HEAP_DEBUGGING_INTERCEPTOR_ROUTINE)
NTSTATUS
NTAPI
RTL_HEAP_DEBUGGING_INTERCEPTOR_ROUTINE(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Action,
    _In_ ULONG StackFramesToCapture,
    _In_ PVOID* StackTrace
    );
/**
 * Pointer to an RTL_HEAP_DEBUGGING_INTERCEPTOR_ROUTINE callback.
 */
typedef RTL_HEAP_DEBUGGING_INTERCEPTOR_ROUTINE* PRTL_HEAP_DEBUGGING_INTERCEPTOR_ROUTINE;

// rev
typedef
_Function_class_(RTL_HEAP_LEAK_ENUMERATION_ROUTINE)
NTSTATUS
NTAPI
RTL_HEAP_LEAK_ENUMERATION_ROUTINE(
    _In_ LONG Reserved,
    _In_ HANDLE HeapHandle,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T BlockSize,
    _In_ ULONG StackTraceDepth,
    _In_ PVOID* StackTrace
    );
/**
 * Pointer to an RTL_HEAP_LEAK_ENUMERATION_ROUTINE callback.
 */
typedef RTL_HEAP_LEAK_ENUMERATION_ROUTINE* PRTL_HEAP_LEAK_ENUMERATION_ROUTINE;

// rev
// ExtendedOptions valid values are 0..3 (low 2 bits).
/**
 * Extended debugging option flags for a heap.
 */
#define HEAP_DEBUG_EXTENDED_OPTION_NONE                                0x0
#define HEAP_DEBUG_EXTENDED_OPTION_LFH_SUBSEGMENT_COMMIT               0x1
#define HEAP_DEBUG_EXTENDED_OPTION_PAD_ALLOCATIONS_WITH_HEADER_BLOCK   0x2
#define HEAP_DEBUG_EXTENDED_OPTION_VALID_MASK                          0x3

// symbols
/**
 * Contains debugging information and callbacks for a heap.
 */
typedef struct _HEAP_DEBUGGING_INFORMATION
{
    PRTL_HEAP_DEBUGGING_INTERCEPTOR_ROUTINE InterceptorFunction;
    USHORT InterceptorValue;
    ULONG ExtendedOptions; // HEAP_DEBUG_EXTENDED_OPTION_*
    ULONG StackTraceDepth;
    SIZE_T MinTotalBlockSize;
    SIZE_T MaxTotalBlockSize;
    PRTL_HEAP_LEAK_ENUMERATION_ROUTINE HeapLeakEnumerationRoutine;
} HEAP_DEBUGGING_INFORMATION, *PHEAP_DEBUGGING_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryHeapInformation(
    _In_opt_ HANDLE HeapHandle,
    _In_ HEAP_INFORMATION_CLASS HeapInformationClass,
    _Out_opt_ PVOID HeapInformation,
    _In_opt_ SIZE_T HeapInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetHeapInformation(
    _In_opt_ HANDLE HeapHandle,
    _In_ HEAP_INFORMATION_CLASS HeapInformationClass,
    _In_opt_ PVOID HeapInformation,
    _In_opt_ SIZE_T HeapInformationLength
);

NTSYSAPI
ULONG
NTAPI
RtlMultipleAllocateHeap(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Flags,
    _In_ SIZE_T Size,
    _In_ ULONG Count,
    _Out_ PVOID* Array
);

NTSYSAPI
ULONG
NTAPI
RtlMultipleFreeHeap(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Flags,
    _In_ ULONG Count,
    _In_ PVOID* Array
);

NTSYSAPI
VOID
NTAPI
RtlDetectHeapLeaks(
    VOID
);

NTSYSAPI
VOID
NTAPI
RtlFlushHeaps(
    VOID
);


// RtlDisownModuleHeapAllocation
/**
 * The RtlDisownModuleHeapAllocation routine relinquishes ownership of a module's heap allocation so that it is not
 * freed when the module unloads.
 *
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDisownModuleHeapAllocation(
    VOID
    );

// RtlHeapTrkInitialize
/**
 * The RtlHeapTrkInitialize routine initializes heap allocation tracking using a shared section.
 *
 * \param SectionHandle A handle to the section used to record heap tracking information.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlHeapTrkInitialize(
    _In_ HANDLE SectionHandle
    );
EXTERN_C_END

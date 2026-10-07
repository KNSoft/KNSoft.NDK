#pragma once

#include "../MinDef.h"

EXTERN_C_START

#pragma region Non-Temporal

#define RtlCopyBytes RtlCopyMemory
#define RtlZeroBytes RtlZeroMemory
#define RtlFillBytes RtlFillMemory

#if defined(_M_AMD64) || defined(_M_ARM64)

/**
 * The RtlCopyMemoryNonTemporal routine copies the contents of one memory block to another using non-temporal store
 * operations that bypass the CPU cache.
 *
 * \param Destination A pointer to the destination memory block.
 * \param Source A pointer to the source memory block.
 * \param Length The number of bytes to copy.
 */
NTSYSAPI
VOID
NTAPI
RtlCopyMemoryNonTemporal(
   _Out_writes_bytes_all_(Length) VOID UNALIGNED *Destination,
   _In_reads_bytes_(Length) CONST VOID UNALIGNED *Source,
   _In_ SIZE_T Length);

/**
 * The RtlFillMemoryNonTemporal routine fills a block of memory with the specified byte value using non-temporal store
 * operations that bypass the CPU cache.
 *
 * \param Destination A pointer to the memory block to fill.
 * \param Length The number of bytes to fill.
 * \param Value The byte value to write to each byte of the memory block.
 */
NTSYSAPI
VOID
NTAPI
RtlFillMemoryNonTemporal(
   _Out_writes_bytes_all_(Length) VOID UNALIGNED *Destination,
   _In_ SIZE_T Length,
   _In_ CONST UCHAR Value);

#else

#define RtlCopyMemoryNonTemporal RtlCopyMemory
#define RtlFillMemoryNonTemporal RtlFillMemory

#endif

#pragma endregion wdm.h

#pragma region Memory

/**
 * The RtlCompareMemoryUlong routine compares a block of memory against a repeating ULONG pattern.
 *
 * \param Source The memory to compare.
 * \param Length The number of bytes to compare.
 * \param Pattern The ULONG pattern to compare against.
 * \return The number of leading bytes that match the pattern.
 */
_Must_inspect_result_
NTSYSAPI
SIZE_T
NTAPI
RtlCompareMemoryUlong(
    _In_reads_bytes_(Length) PVOID Source,
    _In_ SIZE_T Length,
    _In_ ULONG Pattern);

#if defined(_M_AMD64) && !defined(_M_ARM64EC)

/**
 * The RtlFillMemoryUlong routine fills a block of memory with a repeating ULONG pattern.
 *
 * \param Destination The buffer to fill.
 * \param Length The number of bytes to fill.
 * \param Pattern The ULONG pattern written across the buffer.
 */
FORCEINLINE
VOID
RtlFillMemoryUlong(
    _Out_writes_bytes_all_(Length) PVOID Destination,
    _In_ SIZE_T Length,
    _In_ ULONG Pattern)
{

    PULONG Address = (PULONG)Destination;

    //
    // If the number of DWORDs is not zero, then fill the specified buffer
    // with the specified pattern.
    //
    if ((Length /= 4) != 0)
    {

        //
        // If the destination is not quadword aligned (ignoring low bits),
        // then align the destination by storing one DWORD.
        //
        if (((ULONG64)Address & 4) != 0)
        {
            *Address = Pattern;
            if ((Length -= 1) == 0)
            {
                return;
            }

            Address += 1;
        }

        //
        // If the number of QWORDs is not zero, then fill the destination
        // buffer a QWORD at a time.
        //
        __stosq((PULONG64)(Address),
                Pattern | ((ULONG64)Pattern << 32),
                Length / 2);

        if ((Length & 1) != 0)
        {
            Address[Length - 1] = Pattern;
        }
    }

    return;
}

/**
 * The RtlFillMemoryUlonglong routine fills a block of memory with a repeating ULONGLONG pattern.
 *
 * \param Destination The buffer to fill.
 * \param Length The number of bytes to fill.
 * \param Pattern The ULONGLONG pattern written across the buffer.
 */
#define RtlFillMemoryUlonglong(Destination, Length, Pattern)                \
    __stosq((PULONG64)(Destination), Pattern, (Length) / 8)

#else

NTSYSAPI
VOID
NTAPI
RtlFillMemoryUlong(
    _Out_writes_bytes_all_(Length) PVOID Destination,
    _In_ SIZE_T Length,
    _In_ ULONG Pattern);

NTSYSAPI
VOID
NTAPI
RtlFillMemoryUlonglong(
   _Out_writes_bytes_all_(Length) PVOID Destination,
   _In_ SIZE_T Length,
   _In_ ULONGLONG Pattern);

#endif // defined(_M_AMD64) && !defined(_M_ARM64EC)

#pragma endregion ntifs.h

#pragma region Memory Cache

_Function_class_(RTL_SECURE_MEMORY_CACHE_CALLBACK)
typedef NTSTATUS(NTAPI RTL_SECURE_MEMORY_CACHE_CALLBACK)(
    _In_ PVOID Address,
    _In_ SIZE_T Length
    );
/**
 * Pointer to an RTL_SECURE_MEMORY_CACHE_CALLBACK callback.
 */
typedef RTL_SECURE_MEMORY_CACHE_CALLBACK *PRTL_SECURE_MEMORY_CACHE_CALLBACK;

/**
 * The RtlRegisterSecureMemoryCacheCallback routine registers a callback that is invoked when a secured memory range is
 * freed or its protections are changed.
 *
 * \param Callback A pointer to the secure memory cache callback routine to register.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlRegisterSecureMemoryCacheCallback(
    _In_ PRTL_SECURE_MEMORY_CACHE_CALLBACK Callback
);

/**
 * The RtlDeregisterSecureMemoryCacheCallback routine removes a secure memory cache callback previously registered by
 * RtlRegisterSecureMemoryCacheCallback.
 *
 * \param Callback A pointer to the secure memory cache callback routine to deregister.
 * \return BOOLEAN TRUE if the callback was deregistered, FALSE otherwise.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlDeregisterSecureMemoryCacheCallback(
    _In_ PRTL_SECURE_MEMORY_CACHE_CALLBACK Callback
    );

// ros
/**
 * The RtlFlushSecureMemoryCache routine flushes a region from the secure memory cache.
 *
 * \param MemoryCache The base address of the secure memory region to flush.
 * \param MemoryLength An optional length, in bytes, of the region to flush.
 * \return TRUE if the cache was flushed; otherwise, FALSE.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlFlushSecureMemoryCache(
    _In_ PVOID MemoryCache,
    _In_opt_ SIZE_T MemoryLength
);

#pragma endregion phnt

#pragma region Memory Zones

/**
 * Describes a single segment within a memory zone.
 */
typedef struct _RTL_MEMORY_ZONE_SEGMENT
{
    struct _RTL_MEMORY_ZONE_SEGMENT *NextSegment;
    SIZE_T Size;
    PVOID Next;
    PVOID Limit;
} RTL_MEMORY_ZONE_SEGMENT, *PRTL_MEMORY_ZONE_SEGMENT;

/**
 * Represents a memory zone, a fast suballocator carved from larger reserved segments.
 */
typedef struct _RTL_MEMORY_ZONE
{
    RTL_MEMORY_ZONE_SEGMENT Segment;
    RTL_SRWLOCK Lock;
    ULONG LockCount;
    PRTL_MEMORY_ZONE_SEGMENT FirstSegment;
} RTL_MEMORY_ZONE, *PRTL_MEMORY_ZONE;

/**
 * The RtlCreateMemoryZone routine creates a memory zone, a fast lock-free suballocator backed by committed memory.
 *
 * \param MemoryZone Receives the newly created memory zone.
 * \param InitialSize The initial number of bytes to reserve for the zone.
 * \param Flags Reserved; must be zero.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateMemoryZone(
    _Out_ PRTL_MEMORY_ZONE *MemoryZone,
    _In_ SIZE_T InitialSize,
    _Reserved_ ULONG Flags
    );

/**
 * The RtlDestroyMemoryZone routine destroys a memory zone and releases its backing memory.
 *
 * \param MemoryZone The memory zone to destroy.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyMemoryZone(
    _In_ _Post_invalid_ PRTL_MEMORY_ZONE MemoryZone
    );

/**
 * The RtlAllocateMemoryZone routine allocates a block from a memory zone.
 *
 * \param MemoryZone The memory zone to allocate from.
 * \param BlockSize The number of bytes to allocate.
 * \param Block Receives a pointer to the allocated block.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAllocateMemoryZone(
    _In_ PRTL_MEMORY_ZONE MemoryZone,
    _In_ SIZE_T BlockSize,
    _Out_ PVOID *Block
    );

/**
 * The RtlResetMemoryZone routine resets a memory zone, freeing all allocations while retaining its backing memory.
 *
 * \param MemoryZone The memory zone to reset.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlResetMemoryZone(
    _In_ PRTL_MEMORY_ZONE MemoryZone
    );

/**
 * The RtlLockMemoryZone routine locks the memory backing a memory zone into the working set.
 *
 * \param MemoryZone The memory zone to lock.
 * \return NTSTATUS Successful or errant status.
 */
_Acquires_lock_(MemoryZone)
NTSYSAPI
NTSTATUS
NTAPI
RtlLockMemoryZone(
    _In_ PRTL_MEMORY_ZONE MemoryZone
    );

/**
 * The RtlUnlockMemoryZone routine unlocks the memory backing a memory zone previously locked with RtlLockMemoryZone.
 *
 * \param MemoryZone The memory zone to unlock.
 * \return NTSTATUS Successful or errant status.
 */
_Releases_lock_(MemoryZone)
NTSYSAPI
NTSTATUS
NTAPI
RtlUnlockMemoryZone(
    _In_ PRTL_MEMORY_ZONE MemoryZone
    );

#pragma endregion phnt

#pragma region Memory Block Lookaside List

/**
 * The RtlCreateMemoryBlockLookaside routine creates a memory block lookaside list for fast fixed-range block
 * allocation.
 *
 * \param MemoryBlockLookaside Receives the newly created lookaside.
 * \param Flags Reserved; must be zero.
 * \param InitialSize The initial number of bytes to reserve.
 * \param MinimumBlockSize The minimum block size served by the lookaside.
 * \param MaximumBlockSize The maximum block size served by the lookaside.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateMemoryBlockLookaside(
    _Out_ PVOID *MemoryBlockLookaside,
    _Reserved_ ULONG Flags,
    _In_ ULONG InitialSize,
    _In_ ULONG MinimumBlockSize,
    _In_ ULONG MaximumBlockSize
);

/**
 * The RtlDestroyMemoryBlockLookaside routine destroys a memory block lookaside and releases its backing memory.
 *
 * \param MemoryBlockLookaside The lookaside to destroy.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyMemoryBlockLookaside(
    _In_ PVOID MemoryBlockLookaside
);

/**
 * The RtlAllocateMemoryBlockLookaside routine allocates a block from a memory block lookaside.
 *
 * \param MemoryBlockLookaside The lookaside to allocate from.
 * \param BlockSize The number of bytes to allocate.
 * \param Block Receives a pointer to the allocated block.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAllocateMemoryBlockLookaside(
    _In_ PVOID MemoryBlockLookaside,
    _In_ ULONG BlockSize,
    _Out_ PVOID *Block
);

/**
 * The RtlFreeMemoryBlockLookaside routine returns a block to a memory block lookaside.
 *
 * \param MemoryBlockLookaside The lookaside that owns the block.
 * \param Block The block to free.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlFreeMemoryBlockLookaside(
    _In_ PVOID MemoryBlockLookaside,
    _In_ PVOID Block
);

/**
 * The RtlExtendMemoryBlockLookaside routine extends the capacity of a memory block lookaside.
 *
 * \param MemoryBlockLookaside The lookaside to extend.
 * \param Increment The number of additional blocks to make available.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlExtendMemoryBlockLookaside(
    _In_ PVOID MemoryBlockLookaside,
    _In_ ULONG Increment
);

/**
 * The RtlResetMemoryBlockLookaside routine resets a memory block lookaside, returning all outstanding blocks to the
 * free list.
 *
 * \param MemoryBlockLookaside The lookaside to reset.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlResetMemoryBlockLookaside(
    _In_ PVOID MemoryBlockLookaside
);

/**
 * The RtlLockMemoryBlockLookaside routine locks the memory backing a memory block lookaside into the working set.
 *
 * \param MemoryBlockLookaside The lookaside to lock.
 * \return NTSTATUS Successful or errant status.
 */
_Acquires_lock_(MemoryBlockLookaside)
NTSYSAPI
NTSTATUS
NTAPI
RtlLockMemoryBlockLookaside(
    _In_ PVOID MemoryBlockLookaside
);

/**
 * The RtlUnlockMemoryBlockLookaside routine unlocks the memory backing a memory block lookaside.
 *
 * \param MemoryBlockLookaside The lookaside to unlock.
 * \return NTSTATUS Successful or errant status.
 */
_Releases_lock_(MemoryBlockLookaside)
NTSYSAPI
NTSTATUS
NTAPI
RtlUnlockMemoryBlockLookaside(
    _In_ PVOID MemoryBlockLookaside
);

#pragma endregion phnt

/* phnt */
#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
NTSYSAPI
BOOLEAN
NTAPI
RtlIsZeroMemory(
    _In_ PVOID Buffer,
    _In_ SIZE_T Length);
#endif

/**
 * The RtlCopyMappedMemory routine copies memory, tolerating faults that may occur when reading mapped memory.
 *
 * \param Destination The destination buffer.
 * \param Source The source memory to copy from.
 * \param Length The number of bytes to copy.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCopyMappedMemory(
    _Out_writes_bytes_all_(Length) PVOID Destination,
    _In_reads_bytes_(Length) PVOID Source,
    _In_ SIZE_T Length);


EXTERN_C_END

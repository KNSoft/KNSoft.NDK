#pragma once

#include "../../MinDef.h"

EXTERN_C_START

/* ntddk.h */

//
// The hash table header structure can either be allocated
// by the caller, or by the hash table creation function itself.
// This flag indicates what was done at creation time.
//
/**
 * Flags and reserved values for dynamic hash table entries.
 */
#define RTL_HASH_ALLOCATED_HEADER            0x00000001

//
// The RTL_HASH_RESERVED_SIGNATURE is the signature used internally for
// enumerators. A caller can never assign this signature to
// valid entries.
//
#define RTL_HASH_RESERVED_SIGNATURE 0

/**
 * Represents an entry stored in a dynamically sizing hash table.
 */
typedef struct _RTL_DYNAMIC_HASH_TABLE_ENTRY
{
    LIST_ENTRY Linkage;
    ULONG_PTR Signature;
} RTL_DYNAMIC_HASH_TABLE_ENTRY, *PRTL_DYNAMIC_HASH_TABLE_ENTRY;


//
// Some components want to see the actual signature and can use
// this macro to encapsulate that operation.
//
/**
 * Retrieves the key (signature) of a dynamic hash table entry.
 */
#define HASH_ENTRY_KEY(x)    ((x)->Signature)

//
// Brief background on each of the parameters and their
// justification:
// 1. ChainHead stores the pointer to a bucket. This is needed since
//    our hash chains are doubly-linked circular lists, and there is
//    is no way to determine whether we've reached the end of the
//    chain unless we store the pointer to the bucket itself. This
//    is particularly used in walking the sub-list of entries returned
//    by a lookup. We need to know when the sub-list has been
//    completely returned.
// 2. PrevLinkage stores a pointer to the entry before the entry
//    under consideration. The reason for storing the previous entry
//    instead of the entry itself is for cases where a lookup fails
//    and PrevLinkage actually stores the entry that would have been
//    the previous entry, had the looked up entry existed. This can
//    then be used to actually insert the entry at that place.
// 3. Signature is used primarily as a safety check in insertion.
//    This field must match the Signature of the entry being inserted.
//
/**
 * Caches a lookup position within a dynamic hash table to accelerate subsequent operations.
 */
typedef struct _RTL_DYNAMIC_HASH_TABLE_CONTEXT
{
    PLIST_ENTRY ChainHead;
    PLIST_ENTRY PrevLinkage;
    ULONG_PTR Signature;
} RTL_DYNAMIC_HASH_TABLE_CONTEXT, *PRTL_DYNAMIC_HASH_TABLE_CONTEXT;

/**
 * Maintains the state required to enumerate the entries of a dynamic hash table.
 */
typedef struct _RTL_DYNAMIC_HASH_TABLE_ENUMERATOR
{
    union
    {
        RTL_DYNAMIC_HASH_TABLE_ENTRY HashEntry;
        PLIST_ENTRY CurEntry;
    };
    PLIST_ENTRY ChainHead;
    ULONG BucketIndex;
} RTL_DYNAMIC_HASH_TABLE_ENUMERATOR, *PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR;

/**
 * Represents a dynamically sizing (expanding and contracting) hash table.
 */
typedef struct _RTL_DYNAMIC_HASH_TABLE
{
    // Entries initialized at creation
    ULONG Flags;
    ULONG Shift;

    // Entries used in bucket computation.
    ULONG TableSize;
    ULONG Pivot;
    ULONG DivisorMask;

    // Counters
    ULONG NumEntries;
    ULONG NonEmptyBuckets;
    ULONG NumEnumerators;

    // The directory. This field is for internal use only.
    PVOID Directory;

} RTL_DYNAMIC_HASH_TABLE, *PRTL_DYNAMIC_HASH_TABLE;

//
// Inline functions first.
//

/**
 * The RtlInitHashTableContext routine initializes a dynamic hash table context for use in subsequent lookup operations.
 *
 * \param Context A pointer to the dynamic hash table context to initialize.
 */
FORCEINLINE
VOID
RtlInitHashTableContext(
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context)
{
    Context->ChainHead = NULL;
    Context->PrevLinkage = NULL;
}

/**
 * The RtlInitHashTableContextFromEnumerator routine initializes a dynamic hash table context from an active enumerator.
 *
 * \param Context A pointer to the dynamic hash table context to initialize.
 * \param Enumerator A pointer to the enumerator whose position initializes the context.
 */
FORCEINLINE
VOID
RtlInitHashTableContextFromEnumerator(
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context,
    _In_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator)
{
    Context->ChainHead = Enumerator->ChainHead;
    Context->PrevLinkage = Enumerator->HashEntry.Linkage.Blink;
}

FORCEINLINE
void
/**
 * The RtlReleaseHashTableContext routine releases any resources associated with a dynamic hash table context.
 *
 * \param Context A pointer to the dynamic hash table context to release.
 */
RtlReleaseHashTableContext(
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context)
{
    UNREFERENCED_PARAMETER(Context);
    return;
}

/**
 * The RtlTotalBucketsHashTable routine returns the total number of buckets in a dynamic hash table.
 *
 * \param HashTable A pointer to the dynamic hash table to query.
 * \return ULONG The total number of buckets in the hash table.
 */
FORCEINLINE
ULONG
RtlTotalBucketsHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable)
{
    return HashTable->TableSize;
}

/**
 * The RtlNonEmptyBucketsHashTable routine returns the number of non-empty buckets in a dynamic hash table.
 *
 * \param HashTable A pointer to the dynamic hash table to query.
 * \return ULONG The number of non-empty buckets in the hash table.
 */
FORCEINLINE
ULONG
RtlNonEmptyBucketsHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable)
{
    return HashTable->NonEmptyBuckets;
}

/**
 * The RtlEmptyBucketsHashTable routine returns the number of empty buckets in a dynamic hash table.
 *
 * \param HashTable A pointer to the dynamic hash table to query.
 * \return ULONG The number of empty buckets in the hash table.
 */
FORCEINLINE
ULONG
RtlEmptyBucketsHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable)
{
    return HashTable->TableSize - HashTable->NonEmptyBuckets;
}

/**
 * The RtlTotalEntriesHashTable routine returns the total number of entries in a dynamic hash table.
 *
 * \param HashTable A pointer to the dynamic hash table to query.
 * \return ULONG The total number of entries in the hash table.
 */
FORCEINLINE
ULONG
RtlTotalEntriesHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable)
{
    return HashTable->NumEntries;
}

/**
 * The RtlActiveEnumeratorsHashTable routine returns the number of active enumerators on a dynamic hash table.
 *
 * \param HashTable A pointer to the dynamic hash table to query.
 * \return ULONG The number of active enumerators on the hash table.
 */
FORCEINLINE
ULONG
RtlActiveEnumeratorsHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable)
{
    return HashTable->NumEnumerators;
}

//
// Almost all the hash functions take in a Context.
// If a valid context is passed in, it will be used
// in executing the operation if possible. If a
// blank context is passed in, it will be initialized
// appropriately.
//

#if (NTDDI_VERSION >= NTDDI_WIN8)
/**
 * The RtlCreateHashTableEx routine creates and initializes a dynamic hash table with an initial size.
 *
 * \param HashTable A pointer to a variable that receives the created hash table. If the variable is `NULL`, the routine
 * allocates the hash table.
 * \param InitialSize The initial number of buckets to allocate for the hash table.
 * \param Shift The number of reserved low-order bits of the hash value, used to control the number of buckets.
 * \param Flags Reserved. Must be zero.
 * \return `TRUE` if the hash table was created successfully, otherwise `FALSE`.
 */
_Must_inspect_result_
_Success_(return != 0)
NTSYSAPI
BOOLEAN
NTAPI
RtlCreateHashTableEx(
    _Inout_ _When_(NULL == *HashTable, _At_(*HashTable, __drv_allocatesMem(Mem)))
        PRTL_DYNAMIC_HASH_TABLE* HashTable,
    _In_ ULONG InitialSize,
    _In_ ULONG Shift,
    _Reserved_ ULONG Flags);
#endif

/**
 * The RtlCreateHashTable routine creates and initializes a dynamic hash table.
 *
 * \param HashTable A pointer to a variable that receives the created hash table. If the variable is `NULL`, the routine
 * allocates the hash table.
 * \param Shift The number of reserved low-order bits of the hash value, used to control the number of buckets.
 * \param Flags Reserved. Must be zero.
 * \return `TRUE` if the hash table was created successfully, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlcreatehashtable
 */
_Must_inspect_result_
_Success_(return != 0)
NTSYSAPI
BOOLEAN
NTAPI
RtlCreateHashTable(
    _Inout_ _When_(NULL == *HashTable, _At_(*HashTable, __drv_allocatesMem(Mem)))
        PRTL_DYNAMIC_HASH_TABLE* HashTable,
    _In_ ULONG Shift,
    _Reserved_ ULONG Flags);

/**
 * The RtlDeleteHashTable routine deletes a dynamic hash table and frees the resources allocated for it.
 *
 * \param HashTable A pointer to the dynamic hash table to delete.
 * \return `TRUE` if the hash table was deleted successfully, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtldeletehashtable
 */
NTSYSAPI
VOID
NTAPI
RtlDeleteHashTable(
    _In_ _When_((HashTable->Flags & RTL_HASH_ALLOCATED_HEADER), __drv_freesMem(Mem) _Post_invalid_)
        PRTL_DYNAMIC_HASH_TABLE HashTable);

/**
 * The RtlInsertEntryHashTable routine inserts an entry into a dynamic hash table.
 *
 * \param HashTable A pointer to the dynamic hash table.
 * \param Entry A pointer to the entry to insert.
 * \param Signature The signature (hash value) for the entry.
 * \param Context An optional pointer to a context structure that can be used to optimize the insertion.
 * \return `TRUE` if the entry was inserted successfully, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlinsertentryhashtable
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlInsertEntryHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _In_ __drv_aliasesMem PRTL_DYNAMIC_HASH_TABLE_ENTRY Entry,
    _In_ ULONG_PTR Signature,
    _Inout_opt_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context);

/**
 * The RtlRemoveEntryHashTable routine removes an entry from a dynamic hash table.
 *
 * \param HashTable A pointer to the dynamic hash table.
 * \param Entry A pointer to the entry to remove.
 * \param Context An optional pointer to a context structure that can be used to optimize the removal.
 * \return `TRUE` if the entry was removed successfully, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlremoveentryhashtable
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlRemoveEntryHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _In_ PRTL_DYNAMIC_HASH_TABLE_ENTRY Entry,
    _Inout_opt_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context);

/**
 * The RtlLookupEntryHashTable routine looks up an entry in a dynamic hash table.
 *
 * \param HashTable A pointer to the dynamic hash table.
 * \param Signature The signature (hash value) of the entry to look up.
 * \param Context An optional pointer to a context structure that receives information used to enumerate matching
 * entries.
 * \return A pointer to the first matching entry, or `NULL` if no matching entry was found.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtllookupentryhashtable
 */
_Must_inspect_result_
NTSYSAPI
PRTL_DYNAMIC_HASH_TABLE_ENTRY
NTAPI
RtlLookupEntryHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _In_ ULONG_PTR Signature,
    _Out_opt_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context);

/**
 * The RtlGetNextEntryHashTable routine retrieves the next entry that matches a previous lookup in a dynamic hash table.
 *
 * \param HashTable A pointer to the dynamic hash table.
 * \param Context A pointer to a context structure initialized by a previous call to RtlLookupEntryHashTable.
 * \return A pointer to the next matching entry, or `NULL` if there are no more matching entries.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlgetnextentryhashtable
 */
_Must_inspect_result_
NTSYSAPI
PRTL_DYNAMIC_HASH_TABLE_ENTRY
NTAPI
RtlGetNextEntryHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _In_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context);

/**
 * The RtlInitEnumerationHashTable routine initializes an enumerator for a strong enumeration of a dynamic hash table.
 *
 * \param HashTable A pointer to the dynamic hash table.
 * \param Enumerator A pointer to the enumerator structure to initialize.
 * \return `TRUE` if the enumerator was initialized successfully, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlinitenumerationhashtable
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlInitEnumerationHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Out_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

/**
 * The RtlEnumerateEntryHashTable routine retrieves the next entry in a dynamic hash table enumeration.
 *
 * \param HashTable A pointer to the dynamic hash table.
 * \param Enumerator A pointer to the enumerator initialized by RtlInitEnumerationHashTable.
 * \return A pointer to the next entry in the enumeration, or `NULL` if the enumeration is complete.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlenumerateentryhashtable
 */
_Must_inspect_result_
NTSYSAPI
PRTL_DYNAMIC_HASH_TABLE_ENTRY
NTAPI
RtlEnumerateEntryHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

/**
 * The RtlEndEnumerationHashTable routine terminates an enumeration of a dynamic hash table and releases the resources
 * associated with the enumerator.
 *
 * \param HashTable A pointer to the dynamic hash table.
 * \param Enumerator A pointer to the enumerator to terminate.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlendenumerationhashtable
 */
NTSYSAPI
VOID
NTAPI
RtlEndEnumerationHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

/**
 * The RtlInitWeakEnumerationHashTable routine initializes an enumerator for a weak enumeration of a dynamic hash table.
 *
 * \param HashTable A pointer to the dynamic hash table.
 * \param Enumerator A pointer to the enumerator structure to initialize.
 * \return `TRUE` if the enumerator was initialized successfully, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlinitweakenumerationhashtable
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlInitWeakEnumerationHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Out_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

/**
 * The RtlWeaklyEnumerateEntryHashTable routine retrieves the next entry in a weak enumeration of a dynamic hash table.
 *
 * \param HashTable A pointer to the dynamic hash table.
 * \param Enumerator A pointer to the enumerator initialized by RtlInitWeakEnumerationHashTable.
 * \return A pointer to the next entry in the enumeration, or `NULL` if the enumeration is complete.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlweaklyenumerateentryhashtable
 */
_Must_inspect_result_
NTSYSAPI
PRTL_DYNAMIC_HASH_TABLE_ENTRY
NTAPI
RtlWeaklyEnumerateEntryHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

/**
 * The RtlEndWeakEnumerationHashTable routine terminates a weak enumeration of a dynamic hash table and releases the
 * resources associated with the enumerator.
 *
 * \param HashTable A pointer to the dynamic hash table.
 * \param Enumerator A pointer to the enumerator to terminate.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlendweakenumerationhashtable
 */
NTSYSAPI
VOID
NTAPI
RtlEndWeakEnumerationHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

/**
 * The RtlExpandHashTable routine expands a dynamic hash table by increasing the number of buckets.
 *
 * \param HashTable A pointer to the dynamic hash table.
 * \return `TRUE` if the hash table was expanded, otherwise `FALSE` if no expansion was performed.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlexpandhashtable
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlExpandHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable);

/**
 * The RtlContractHashTable routine contracts a dynamic hash table by reducing the number of buckets.
 *
 * \param HashTable A pointer to the dynamic hash table.
 * \return `TRUE` if the hash table was contracted, otherwise `FALSE` if no contraction was performed.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlcontracthashtable
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlContractHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable);

#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)

/**
 * The RtlInitStrongEnumerationHashTable routine initializes an enumerator for a strong enumeration of a dynamic hash
 * table.
 *
 * \param HashTable A pointer to the dynamic hash table.
 * \param Enumerator A pointer to the enumerator structure to initialize.
 * \return `TRUE` if the enumerator was initialized successfully, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlinitstrongenumerationhashtable
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlInitStrongEnumerationHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Out_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

/**
 * The RtlStronglyEnumerateEntryHashTable routine retrieves the next entry in a strong enumeration of a dynamic hash
 * table.
 *
 * \param HashTable A pointer to the dynamic hash table.
 * \param Enumerator A pointer to the enumerator initialized by RtlInitStrongEnumerationHashTable.
 * \return A pointer to the next entry in the enumeration, or `NULL` if the enumeration is complete.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlstronglyenumerateentryhashtable
 */
_Must_inspect_result_
NTSYSAPI
PRTL_DYNAMIC_HASH_TABLE_ENTRY
NTAPI
RtlStronglyEnumerateEntryHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

/**
 * The RtlEndStrongEnumerationHashTable routine terminates a strong enumeration of a dynamic hash table and releases the
 * resources associated with the enumerator.
 *
 * \param HashTable A pointer to the dynamic hash table.
 * \param Enumerator A pointer to the enumerator to terminate.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlendstrongenumerationhashtable
 */
NTSYSAPI
VOID
NTAPI
RtlEndStrongEnumerationHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

#endif

EXTERN_C_END

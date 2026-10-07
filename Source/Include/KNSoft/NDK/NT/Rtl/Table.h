#pragma once

#include "../MinDef.h"
#include "../Ex/Atom.h"

EXTERN_C_START

/* phnt */

#pragma region Handle Table

/**
 * Represents a single entry in an RTL handle table.
 */
typedef struct _RTL_HANDLE_TABLE_ENTRY
{
    union
    {
        ULONG Flags; // allocated entries have the low bit set
        struct _RTL_HANDLE_TABLE_ENTRY *NextFree;
    };
} RTL_HANDLE_TABLE_ENTRY, *PRTL_HANDLE_TABLE_ENTRY;

/**
 * Flag marking an RTL handle table entry as allocated.
 */
#define RTL_HANDLE_ALLOCATED (USHORT)0x0001

/**
 * Represents a user-mode handle table managed by the RTL handle package.
 */
typedef struct _RTL_HANDLE_TABLE
{
    ULONG MaximumNumberOfHandles;
    ULONG SizeOfHandleTableEntry;
    ULONG Reserved[2];
    PRTL_HANDLE_TABLE_ENTRY FreeHandles;
    PRTL_HANDLE_TABLE_ENTRY CommittedHandles;
    PRTL_HANDLE_TABLE_ENTRY UnCommittedHandles;
    PRTL_HANDLE_TABLE_ENTRY MaxReservedHandles;
} RTL_HANDLE_TABLE, *PRTL_HANDLE_TABLE;

/**
 * The RtlInitializeHandleTable routine initializes a handle table for allocating and tracking fixed-size handle
 * entries.
 *
 * \param MaximumNumberOfHandles The maximum number of handles the table can contain.
 * \param SizeOfHandleTableEntry The size, in bytes, of each handle table entry.
 * \param HandleTable A pointer to the RTL_HANDLE_TABLE to initialize.
 */
NTSYSAPI
VOID
NTAPI
RtlInitializeHandleTable(
    _In_ ULONG MaximumNumberOfHandles,
    _In_ ULONG SizeOfHandleTableEntry,
    _Out_ PRTL_HANDLE_TABLE HandleTable
    );

/**
 * The RtlDestroyHandleTable routine destroys a handle table and releases the memory it allocated.
 *
 * \param HandleTable A pointer to the RTL_HANDLE_TABLE to destroy.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyHandleTable(
    _Inout_ PRTL_HANDLE_TABLE HandleTable
    );

/**
 * The RtlAllocateHandle routine allocates a handle from a handle table.
 *
 * \param HandleTable A pointer to the RTL_HANDLE_TABLE from which to allocate.
 * \param HandleIndex An optional pointer to a variable that receives the index of the allocated handle.
 * \return PRTL_HANDLE_TABLE_ENTRY A pointer to the allocated handle table entry, or `NULL` on failure.
 */
NTSYSAPI
PRTL_HANDLE_TABLE_ENTRY
NTAPI
RtlAllocateHandle(
    _In_ PRTL_HANDLE_TABLE HandleTable,
    _Out_opt_ PULONG HandleIndex
    );

/**
 * The RtlFreeHandle routine returns a previously allocated handle to a handle table.
 *
 * \param HandleTable A pointer to the RTL_HANDLE_TABLE that owns the handle.
 * \param Handle A pointer to the handle table entry to free.
 * \return Returns `TRUE` if the handle was freed successfully, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlFreeHandle(
    _In_ PRTL_HANDLE_TABLE HandleTable,
    _In_ PRTL_HANDLE_TABLE_ENTRY Handle
    );

/**
 * The RtlIsValidHandle routine determines whether a handle table entry is currently valid and allocated.
 *
 * \param HandleTable A pointer to the RTL_HANDLE_TABLE that owns the handle.
 * \param Handle A pointer to the handle table entry to validate.
 * \return Returns `TRUE` if the handle is valid, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsValidHandle(
    _In_ PRTL_HANDLE_TABLE HandleTable,
    _In_ PRTL_HANDLE_TABLE_ENTRY Handle
    );

/**
 * The RtlIsValidIndexHandle routine determines whether a handle identified by index is valid and returns the
 * corresponding entry.
 *
 * \param HandleTable A pointer to the RTL_HANDLE_TABLE that owns the handle.
 * \param HandleIndex The zero-based index of the handle to validate.
 * \param Handle A pointer to a variable that receives the handle table entry for the index.
 * \return Returns `TRUE` if the indexed handle is valid, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsValidIndexHandle(
    _In_ PRTL_HANDLE_TABLE HandleTable,
    _In_ ULONG HandleIndex,
    _Out_ PRTL_HANDLE_TABLE_ENTRY *Handle
    );

#pragma endregion

#pragma region Atom Table

/**
 * Constants describing atom table limits and reserved values.
 */
#define RTL_ATOM_MAXIMUM_INTEGER_ATOM (RTL_ATOM)0xc000
#define RTL_ATOM_INVALID_ATOM (RTL_ATOM)0x0000
#define RTL_ATOM_TABLE_DEFAULT_NUMBER_OF_BUCKETS 37
#define RTL_ATOM_MAXIMUM_NAME_LENGTH 255
#define RTL_ATOM_PINNED 0x01

/**
 * The RtlCreateAtomTable routine creates an atom table.
 *
 * \param NumberOfBuckets The number of hash buckets; zero selects a default.
 * \param AtomTableHandle Receives the newly created atom table.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateAtomTable(
    _In_ ULONG NumberOfBuckets,
    _Inout_ PVOID *AtomTableHandle
    );

/**
 * The RtlDestroyAtomTable routine destroys an atom table.
 *
 * \param AtomTableHandle The atom table to destroy.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyAtomTable(
    _In_ _Post_invalid_ PVOID AtomTableHandle
    );

/**
 * The RtlEmptyAtomTable routine removes atoms from an atom table.
 *
 * \param AtomTableHandle The atom table to empty.
 * \param IncludePinnedAtoms TRUE to also remove pinned atoms; FALSE to retain them.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlEmptyAtomTable(
    _In_ PVOID AtomTableHandle,
    _In_ BOOLEAN IncludePinnedAtoms
    );

/**
 * The RtlAddAtomToAtomTable routine adds a named atom to an atom table.
 *
 * \param AtomTableHandle The atom table to modify.
 * \param AtomName The name of the atom to add.
 * \param Atom On input may specify an integer atom; receives the resulting atom.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAtomToAtomTable(
    _In_ PVOID AtomTableHandle,
    _In_ PCWSTR AtomName,
    _Inout_opt_ PRTL_ATOM Atom
    );

/**
 * The RtlLookupAtomInAtomTable routine looks up a named atom in an atom table.
 *
 * \param AtomTableHandle The atom table to search.
 * \param AtomName The name of the atom to find.
 * \param Atom An optional pointer that receives the atom.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlLookupAtomInAtomTable(
    _In_ PVOID AtomTableHandle,
    _In_ PCWSTR AtomName,
    _Out_opt_ PRTL_ATOM Atom
    );

/**
 * The RtlDeleteAtomFromAtomTable routine removes an atom from an atom table.
 *
 * \param AtomTableHandle The atom table to modify.
 * \param Atom The atom to remove.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteAtomFromAtomTable(
    _In_ PVOID AtomTableHandle,
    _In_ RTL_ATOM Atom
    );

/**
 * The RtlPinAtomInAtomTable routine pins an atom in an atom table so that it cannot be deleted by reference counting.
 *
 * \param AtomTableHandle The atom table containing the atom.
 * \param Atom The atom to pin.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlPinAtomInAtomTable(
    _In_ PVOID AtomTableHandle,
    _In_ RTL_ATOM Atom
    );

/**
 * The RtlQueryAtomInAtomTable routine retrieves information about an atom in an atom table.
 *
 * \param AtomTableHandle The atom table to query.
 * \param Atom The atom to query.
 * \param AtomUsage An optional pointer that receives the atom reference count.
 * \param AtomFlags An optional pointer that receives the atom flags.
 * \param AtomName An optional buffer that receives the atom name.
 * \param AtomNameLength On input specifies the buffer size; on output receives the name length.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryAtomInAtomTable(
    _In_ PVOID AtomTableHandle,
    _In_ RTL_ATOM Atom,
    _Out_opt_ PULONG AtomUsage,
    _Out_opt_ PULONG AtomFlags,
    _Inout_updates_bytes_to_opt_(*AtomNameLength, *AtomNameLength) PWSTR AtomName,
    _Inout_opt_ PULONG AtomNameLength
    );

// rev
/**
 * The RtlGetIntegerAtom routine converts an atom name string into its integer atom value.
 *
 * \param AtomName A pointer to the null-terminated atom name to convert.
 * \param IntegerAtom An optional pointer to a variable that receives the integer atom value.
 * \return Returns `TRUE` if the name represents a valid integer atom, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlGetIntegerAtom(
    _In_ PCWSTR AtomName,
    _Out_opt_ PUSHORT IntegerAtom
    );

#pragma endregion

EXTERN_C_END

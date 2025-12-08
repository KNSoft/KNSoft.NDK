#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

typedef USHORT RTL_ATOM, *PRTL_ATOM;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAddAtom(
    _In_reads_bytes_opt_(Length) PCWSTR AtomName,
    _In_ ULONG Length,
    _Out_opt_ PRTL_ATOM Atom);

#if (NTDDI_VERSION >= NTDDI_WIN8)

#define ATOM_FLAG_GLOBAL 0x2

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAddAtomEx(
    _In_reads_bytes_opt_(Length) PCWSTR AtomName,
    _In_ ULONG Length,
    _Out_opt_ PRTL_ATOM Atom,
    _In_ ULONG Flags);

#endif

NTSYSCALLAPI
NTSTATUS
NTAPI
NtFindAtom(
    _In_reads_bytes_opt_(Length) PCWSTR AtomName,
    _In_ ULONG Length,
    _Out_opt_ PRTL_ATOM Atom);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDeleteAtom(
    _In_ RTL_ATOM Atom);

typedef enum _ATOM_INFORMATION_CLASS
{
    AtomBasicInformation,
    AtomTableInformation
} ATOM_INFORMATION_CLASS;

/**
 * The ATOM_BASIC_INFORMATION structure contains basic information about an Atom.
 */
typedef struct _ATOM_BASIC_INFORMATION
{
    USHORT UsageCount;   // The number of times the atom is referenced.
    USHORT Flags;        // Flags associated with the atom. */
    USHORT NameLength;   // Length, in bytes, of the atom's name.
    _Field_size_bytes_(NameLength) WCHAR Name[1]; // The atom's name (not null-terminated).
} ATOM_BASIC_INFORMATION, *PATOM_BASIC_INFORMATION;

/**
 * The ATOM_TABLE_INFORMATION structure contains information about all Atoms from the system atom table.
 */
typedef struct _ATOM_TABLE_INFORMATION
{
    ULONG NumberOfAtoms; // The number of atoms in the atom table.
    _Field_size_(NumberOfAtoms) RTL_ATOM Atoms[1]; // Array of atom identifiers.
} ATOM_TABLE_INFORMATION, *PATOM_TABLE_INFORMATION;

/**
 * The NtQueryInformationAtom routine retrieves information about a specified atom in the system atom table.
 *
 * \param Atom The atom identifier for which information is being queried.
 * \param AtomInformationClass Specifies the type of information to retrieve. This is an ATOM_INFORMATION_CLASS value.
 * \param AtomInformation A pointer to a buffer that receives the requested information.
 * \param AtomInformationLength The size, in bytes, of the AtomInformation buffer.
 * \param ReturnLength Optional pointer to a variable that receives the number of bytes written to the AtomInformation buffer.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationAtom(
    _In_ RTL_ATOM Atom,
    _In_ ATOM_INFORMATION_CLASS AtomInformationClass,
    _Out_writes_bytes_(AtomInformationLength) PVOID AtomInformation,
    _In_ ULONG AtomInformationLength,
    _Out_opt_ PULONG ReturnLength);

EXTERN_C_END

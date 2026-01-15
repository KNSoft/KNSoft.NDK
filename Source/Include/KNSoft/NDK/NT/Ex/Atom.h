#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

typedef USHORT RTL_ATOM, *PRTL_ATOM;

/**
 * The NtAddAtom routine adds a Unicode string to the system atom table and
 * returns the corresponding atom identifier.
 *
 * \param AtomName A pointer to a Unicode string containing the atom name.
 * \param Length The length, in bytes, of the string pointed to by AtomName.
 * \param Atom An optional pointer that receives the resulting atom identifier.
 * \return NTSTATUS Successful or errant status.
 * \remarks If the atom already exists, its reference count is incremented and
 * the existing atom identifier is returned.
 * \see https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-addatomw
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtAddAtom(
    _In_reads_bytes_opt_(Length) PCWSTR AtomName,
    _In_ ULONG Length,
    _Out_opt_ PRTL_ATOM Atom);

#if (NTDDI_VERSION >= NTDDI_WIN8)

/**
 * ATOM_FLAG_NONE indicates that the atom being created should be placed in
 * the session-local atom table rather than the global atom table.
 */
#define ATOM_FLAG_NONE 0x0
/**
 * ATOM_FLAG_GLOBAL indicates that the atom being created should be placed in
 * the global atom table rather than the session-local table.
 * \remarks This flag is only valid starting with Windows 8 and later.
 */
#define ATOM_FLAG_GLOBAL 0x2

// rev
/**
 * The NtAddAtomEx routine adds a Unicode string to the system atom table with
 * additional creation flags.
 *
 * \param AtomName A pointer to a Unicode string containing the atom name.
 * \param Length The length, in bytes, of the string pointed to by AtomName.
 * \param Atom An optional pointer that receives the resulting atom identifier.
 * \param Flags A set of flags that control atom creation behavior.
 * \return NTSTATUS Successful or errant status.
 * \remarks ATOM_FLAG_GLOBAL may be used to create a global atom.
 * Only ATOM_FLAG_GLOBAL and ATOM_FLAG_NONE are currently supported.
 * Any other flag value results in STATUS_INVALID_PARAMETER.
 * \see https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-addatomw
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtAddAtomEx(
    _In_reads_bytes_opt_(Length) PCWSTR AtomName,
    _In_ ULONG Length,
    _Out_opt_ PRTL_ATOM Atom,
    _In_ ULONG Flags);

#endif

/**
 * The NtFindAtom routine retrieves the atom identifier associated with a
 * Unicode string in the system atom table.
 *
 * \param AtomName A pointer to a Unicode string containing the atom name.
 * \param Length The length, in bytes, of the string pointed to by AtomName.
 * \param Atom An optional pointer that receives the atom identifier if found.
 * \return NTSTATUS Successful or errant status.
 * \see https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-findatomw
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtFindAtom(
    _In_reads_bytes_opt_(Length) PCWSTR AtomName,
    _In_ ULONG Length,
    _Out_opt_ PRTL_ATOM Atom);

/**
 * The NtDeleteAtom routine decrements the reference count of an atom and
 * removes it from the system atom table when the count reaches zero.
 *
 * \param Atom The atom identifier to delete.
 * \return NTSTATUS Successful or errant status.
 * \remarks If the atom is still referenced elsewhere, it is not removed until
 * its reference count reaches zero.
 * \see https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-deleteatom
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtDeleteAtom(
    _In_ RTL_ATOM Atom);

/**
 * The ATOM_INFORMATION_CLASS enumeration specifies the type of information
 * returned when querying atom table data.
 */
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

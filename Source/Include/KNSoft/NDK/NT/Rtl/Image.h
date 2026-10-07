#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

/**
 * The RtlImageNtHeader routine returns a pointer to the IMAGE_NT_HEADERS of a mapped image.
 *
 * \param BaseOfImage The base address of the mapped image.
 * \return A pointer to the image NT headers, or NULL if the image is invalid.
 */
NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    _In_ PVOID BaseOfImage
);

/**
 * Flag to disable range checking in RtlImageNtHeaderEx.
 */
#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK 0x00000001

/**
 * The RtlImageNtHeaderEx routine returns a pointer to the IMAGE_NT_HEADERS of a mapped image, with validation options.
 *
 * \param Flags Flags controlling validation (for example, RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK).
 * \param BaseOfImage The base address of the mapped image.
 * \param Size The size, in bytes, of the mapped image.
 * \param OutHeaders Receives a pointer to the image NT headers.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlImageNtHeaderEx(
    _In_ ULONG Flags,
    _In_ PVOID BaseOfImage,
    _In_ ULONG64 Size,
    _Out_ PIMAGE_NT_HEADERS *OutHeaders
);

/**
 * The RtlAddressInSectionTable routine returns the address corresponding to a relative virtual address (RVA) using the
 * image section table.
 *
 * \param NtHeaders The NT headers of the image.
 * \param BaseOfImage The base address of the mapped image.
 * \param VirtualAddress The relative virtual address to translate.
 * \return A pointer to the data at the RVA, or NULL if the RVA is not within any section.
 */
NTSYSAPI
PVOID
NTAPI
RtlAddressInSectionTable(
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _In_ PVOID BaseOfImage,
    _In_ ULONG VirtualAddress
);

/**
 * The RtlSectionTableFromVirtualAddress routine returns the section header that contains the specified relative virtual
 * address (RVA).
 *
 * \param NtHeaders The NT headers of the image.
 * \param BaseOfImage The base address of the mapped image.
 * \param VirtualAddress The relative virtual address to locate.
 * \return A pointer to the containing section header, or NULL if none contains the RVA.
 */
NTSYSAPI
PIMAGE_SECTION_HEADER
NTAPI
RtlSectionTableFromVirtualAddress(
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _In_ PVOID BaseOfImage,
    _In_ ULONG VirtualAddress
);

/**
 * The RtlImageDirectoryEntryToData routine returns a pointer to the data of the specified image data directory.
 *
 * \param BaseOfImage The base address of the image.
 * \param MappedAsImage TRUE if the image is mapped as an image; FALSE if mapped as a flat file.
 * \param DirectoryEntry The data directory entry index (IMAGE_DIRECTORY_ENTRY_*).
 * \param Size Receives the size, in bytes, of the directory data.
 * \return A pointer to the directory data, or NULL if the directory is absent.
 */
NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
    _In_ PVOID BaseOfImage,
    _In_ BOOLEAN MappedAsImage,
    _In_ USHORT DirectoryEntry,
    _Out_ PULONG Size
);

/**
 * The RtlImageRvaToSection routine returns the section header that contains the specified relative virtual address
 * (RVA).
 *
 * \param NtHeaders The NT headers of the image.
 * \param BaseOfImage The base address of the mapped image.
 * \param Rva The relative virtual address to locate.
 * \return A pointer to the containing section header, or NULL if none contains the RVA.
 */
NTSYSAPI
PIMAGE_SECTION_HEADER
NTAPI
RtlImageRvaToSection(
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _In_ PVOID BaseOfImage,
    _In_ ULONG Rva
);

/**
 * The RtlImageRvaToVa routine translates a relative virtual address (RVA) to a virtual address within a mapped image.
 *
 * \param NtHeaders The NT headers of the image.
 * \param BaseOfImage The base address of the mapped image.
 * \param Rva The relative virtual address to translate.
 * \param LastRvaSection An optional pointer to a cached section header used and updated across calls.
 * \return A pointer to the data at the RVA, or NULL if the RVA is not within any section.
 */
NTSYSAPI
PVOID
NTAPI
RtlImageRvaToVa(
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _In_ PVOID BaseOfImage,
    _In_ ULONG Rva,
    _Out_opt_ PIMAGE_SECTION_HEADER *LastRvaSection
);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)

// rev
/**
 * The RtlFindExportedRoutineByName routine locates an exported routine within a mapped image by its export name.
 *
 * \param BaseOfImage The base address of the mapped image to search.
 * \param RoutineName The name of the exported routine to find.
 * \return A pointer to the exported routine, or NULL if the export was not found.
 */
NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID BaseOfImage,
    _In_z_ PCSTR RoutineName
);

// rev
/**
 * The RtlGuardCheckLongJumpTarget routine determines whether the specified address is a valid Control Flow Guard
 * long-jump target.
 *
 * \param PcValue The target instruction address to validate.
 * \param IsFastFail Specifies whether a failed validation should fast-fail.
 * \param IsLongJumpTarget Receives TRUE if the address is a valid long-jump target.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGuardCheckLongJumpTarget(
    _In_ PVOID PcValue,
    _In_ BOOL IsFastFail,
    _Out_ PBOOL IsLongJumpTarget
);

#endif

#if (NTDDI_VERSION >= NTDDI_WIN11_ZN)
/**
 * The RtlValidateUserCallTarget routine validates whether an address is a valid Control Flow Guard indirect call
 * target.
 *
 * \param Address The target address to validate.
 * \param Flags Receives flags describing the validation result.
 */
NTSYSAPI
VOID
NTAPI
RtlValidateUserCallTarget(
    _In_ PVOID Address,
    _Out_ PULONG Flags
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN11_ZN)
// rev
/**
 * Native machine architecture identifiers for the running platform.
 */
#define IMAGE_FILE_NATIVE_MACHINE_I386  0x1
#define IMAGE_FILE_NATIVE_MACHINE_AMD64 0x2
#define IMAGE_FILE_NATIVE_MACHINE_ARMNT 0x4
#define IMAGE_FILE_NATIVE_MACHINE_ARM64 0x8
#define IMAGE_FILE_NATIVE_MACHINE_ARM64EC 0x10

#if !defined(NTDDI_WIN11_BR)
typedef struct _IMAGE_FILE_MACHINES
{
    union
    {
        ULONG Value;
        struct
        {
            ULONG MachineX86 : 1;
            ULONG MachineAmd64 : 1;
            ULONG MachineArm : 1;
            ULONG MachineArm64 : 1;
            ULONG MachineArm64EC : 1;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} IMAGE_FILE_MACHINES;
#endif

/* winnt.h gates the function declaration separately from IMAGE_FILE_MACHINES. */
#if !defined(NTDDI_WIN11_BR) || (NTDDI_VERSION < NTDDI_WIN11_BR)
// rev
NTSYSAPI
NTSTATUS
NTAPI
RtlGetImageFileMachines(
    _In_ PCWSTR FileName,
    _Out_ IMAGE_FILE_MACHINES* MachineTypeFlags
    );
#endif
#endif

EXTERN_C_END

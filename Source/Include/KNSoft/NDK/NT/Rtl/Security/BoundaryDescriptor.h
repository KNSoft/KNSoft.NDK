#pragma once

#include "../../MinDef.h"
#include "../../Ob/Misc.h"

EXTERN_C_START

/* phnt */

/**
 * Flags for boundary descriptors.
 */
#define BOUNDARY_DESCRIPTOR_FLAG_NONE 0x0
#define BOUNDARY_DESCRIPTOR_ADD_APPCONTAINER_SID 0x0001

/**
 * The RtlCreateBoundaryDescriptor routine creates a boundary descriptor used to define an isolation boundary for a
 * private object namespace.
 *
 * \param Name A pointer to the Unicode string that names the boundary.
 * \param Flags Flags that control the creation of the boundary descriptor.
 * \return POBJECT_BOUNDARY_DESCRIPTOR A pointer to the created boundary descriptor, or `NULL` on failure.
 */
_Ret_maybenull_
_Success_(return != NULL)
NTSYSAPI
POBJECT_BOUNDARY_DESCRIPTOR
NTAPI
RtlCreateBoundaryDescriptor(
    _In_ PUNICODE_STRING Name,
    _In_ ULONG Flags);

/**
 * The RtlDeleteBoundaryDescriptor routine deletes a boundary descriptor and frees its resources.
 *
 * \param BoundaryDescriptor A pointer to the boundary descriptor to delete. The pointer is invalid after this call.
 */
NTSYSAPI
VOID
NTAPI
RtlDeleteBoundaryDescriptor(
    _In_ _Post_invalid_ POBJECT_BOUNDARY_DESCRIPTOR BoundaryDescriptor);

/**
 * The RtlAddSIDToBoundaryDescriptor routine adds a required security identifier (SID) to a boundary descriptor.
 *
 * \param BoundaryDescriptor A pointer to a variable that references the boundary descriptor to modify.
 * \param RequiredSid A pointer to the SID to add to the boundary.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddSIDToBoundaryDescriptor(
    _Inout_ POBJECT_BOUNDARY_DESCRIPTOR *BoundaryDescriptor,
    _In_ PCSID RequiredSid);

/**
 * The RtlAddIntegrityLabelToBoundaryDescriptor routine adds a mandatory integrity label to a boundary descriptor.
 *
 * \param BoundaryDescriptor A pointer to a variable that references the boundary descriptor to modify.
 * \param IntegrityLabel A pointer to the SID that specifies the integrity label to add.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddIntegrityLabelToBoundaryDescriptor(
    _Inout_ POBJECT_BOUNDARY_DESCRIPTOR *BoundaryDescriptor,
    _In_ PCSID IntegrityLabel);

EXTERN_C_END

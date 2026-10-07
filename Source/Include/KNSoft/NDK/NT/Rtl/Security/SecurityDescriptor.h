#pragma once

#include "../../MinDef.h"

EXTERN_C_START

/* ntifs.h & wdm.h */

/**
 * The RtlCreateSecurityDescriptor routine initializes a new absolute-format security descriptor.
 * On return, the security descriptor is initialized with no system ACL, no discretionary ACL, no owner, no primary group, and all control flags set to zero.
 * 
 * @param SecurityDescriptor Pointer to the buffer for the \ref SECURITY_DESCRIPTOR to be initialized.
 * @param Revision Specifies the revision level to assign to the security descriptor. Set this parameter to SECURITY_DESCRIPTOR_REVISION.
 * @return NTSTATUS Successful or errant status.
 * @see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcreatesecuritydescriptor
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateSecurityDescriptor(
    _Out_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG Revision);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateSecurityDescriptorRelative(
    _Out_ PISECURITY_DESCRIPTOR_RELATIVE SecurityDescriptor,
    _In_ ULONG Revision);

/**
 * The RtlValidSecurityDescriptor routine checks a given security descriptor's validity.
 * 
 * @param SecurityDescriptor Pointer to the \ref SECURITY_DESCRIPTOR to be checked.
 * @return Returns TRUE if the security descriptor is valid, or FALSE otherwise.
 * @remarks The routine checks the validity of an absolute-format security descriptor. To check the validity of a self-relative security descriptor, use the \ref RtlValidRelativeSecurityDescriptor routine instead.
 * @see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlvalidsecuritydescriptor
 */
_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlValidSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor);

/**
 * The RtlLengthSecurityDescriptor routine returns the size of a given security descriptor.
 * 
 * @param SecurityDescriptor A pointer to a \ref SECURITY_DESCRIPTOR structure whose length the function retrieves.
 * @return Returns the length, in bytes, of the SECURITY_DESCRIPTOR structure.
 * @see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtllengthsecuritydescriptor
 */
NTSYSAPI
ULONG
NTAPI
RtlLengthSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor);

/**
 * The RtlValidRelativeSecurityDescriptor routine checks the validity of a self-relative security descriptor.
 *
 * @param SecurityDescriptorInput A pointer to the buffer that contains the security descriptor in self-relative format.
 * The buffer must begin with a SECURITY_DESCRIPTOR structure, which is followed by the rest of the security descriptor data.
 * @param SecurityDescriptorLength The size of the SecurityDescriptorInput structure.
 * @param RequiredInformation A SECURITY_INFORMATION value that specifies the information that is required to be contained in the security descriptor.
 * @return RtlValidRelativeSecurityDescriptor returns TRUE if the security descriptor is valid and includes the information that the RequiredInformation parameter specifies. Otherwise, this routine returns FALSE.
 * @see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlvalidrelativesecuritydescriptor
 */
_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlValidRelativeSecurityDescriptor(
    _In_reads_bytes_(SecurityDescriptorLength) PSECURITY_DESCRIPTOR SecurityDescriptorInput,
    _In_ ULONG SecurityDescriptorLength,
    _In_ SECURITY_INFORMATION RequiredInformation);

/**
 * The RtlGetDaclSecurityDescriptor routine retrieves the discretionary access control list (DACL) of a security
 * descriptor.
 *
 * \param SecurityDescriptor A pointer to the security descriptor to query.
 * \param DaclPresent A pointer to a variable that receives `TRUE` if the security descriptor contains a DACL.
 * \param Dacl A pointer to a variable that receives a pointer to the DACL, or `NULL` if none is present.
 * \param DaclDefaulted A pointer to a variable that receives `TRUE` if the DACL was obtained by a default mechanism.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetdaclsecuritydescriptor
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetDaclSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PBOOLEAN DaclPresent,
    _Outptr_result_maybenull_ PACL *Dacl,
    _Pre_ _Writable_elements_(1)
    _When_(!(*DaclPresent), _Post_invalid_)
    _When_((*DaclPresent), _Post_valid_)
    PBOOLEAN DaclDefaulted);

/**
 * The RtlSetDaclSecurityDescriptor routine sets the discretionary access control list (DACL) of an absolute-format
 * security descriptor.
 *
 * \param SecurityDescriptor A pointer to the security descriptor to modify.
 * \param DaclPresent If `TRUE`, the security descriptor is marked as containing a DACL.
 * \param Dacl An optional pointer to the DACL to assign to the security descriptor.
 * \param DaclDefaulted If `TRUE`, the DACL was obtained by a default mechanism.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetdaclsecuritydescriptor
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetDaclSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN DaclPresent,
    _In_opt_ PACL Dacl,
    _In_ BOOLEAN DaclDefaulted);

/**
 * The RtlGetOwnerSecurityDescriptor routine returns the owner information for a given security descriptor.
 *
 * @param SecurityDescriptor Pointer to the SECURITY_DESCRIPTOR structure.
 * @param Owner Pointer to an address to receive a pointer to the owner security identifier (SID). If the security descriptor does not currently contain an owner SID, Owner receives NULL.
 * @param OwnerDefaulted Pointer to a Boolean variable that receives TRUE if the owner information is derived from a default mechanism, FALSE otherwise. Valid only if Owner receives a non-NULL value.
 * @return NTSTATUS Successful or errant status.
 * @see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetownersecuritydescriptor
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetOwnerSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Outptr_result_maybenull_ PSID *Owner,
    _When_(*Owner == NULL, _Post_invalid_)
    _When_(*Owner != NULL, _Post_valid_)
    _Pre_ _Notnull_ _Pre_ _Writable_elements_(1) PBOOLEAN OwnerDefaulted);

/**
 * The RtlSetOwnerSecurityDescriptor routine sets the owner information of an absolute-format security descriptor. It replaces any owner information that is already present in the security descriptor.
 *
 * @param SecurityDescriptor Pointer to the SECURITY_DESCRIPTOR structure whose owner is to be set. RtlSetOwnerSecurityDescriptor replaces any existing owner with the new owner.
 * @param Owner Pointer to a security identifier (SID) structure for the security descriptor's new primary owner.
 * @li \c This pointer, not the SID structure itself, is copied into the security descriptor.
 * @li \c If this parameter is NULL, RtlSetOwnerSecurityDescriptor clears the security descriptor's owner information. This marks the security descriptor as having no owner.
 * @param OwnerDefaulted Set to TRUE if the owner information is derived from a default mechanism.
 * @li \c If this value is TRUE, it is default information. RtlSetOwnerSecurityDescriptor sets the SE_OWNER_DEFAULTED flag in the security descriptor's SECURITY_DESCRIPTOR_CONTROL field.
 * @li \c If this parameter is FALSE, the SE_OWNER_DEFAULTED flag is cleared.
 * @return NTSTATUS Successful or errant status.
 * @see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetownersecuritydescriptor
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetOwnerSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID Owner,
    _In_ BOOLEAN OwnerDefaulted);

/**
 * The RtlGetGroupSecurityDescriptor routine returns the primary group information for a given security descriptor.
 *
 * @param SecurityDescriptor Pointer to the security descriptor whose primary group information is to be returned.
 * @param Group Pointer to a variable that receives a pointer to the security identifier (SID) for the primary group.
 * @param GroupDefaulted Pointer to a Boolean variable that receives the value of the SE_GROUP_DEFAULTED flag.
 * @return NTSTATUS Successful or errant status.
 * @see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetgroupsecuritydescriptor
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetGroupSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Outptr_result_maybenull_ PSID *Group,
    _Pre_ _Notnull_ _Pre_ _Writable_elements_(1)
    _When_(*Group == NULL, _Post_invalid_)
    _When_(*Group != NULL, _Post_valid_)
    PBOOLEAN GroupDefaulted);

/**
 * The RtlSetGroupSecurityDescriptor routine sets the primary group information of an absolute-format security descriptor. It replaces any primary group information that is already present in the security descriptor.
 *
 * @param SecurityDescriptor Pointer to the SECURITY_DESCRIPTOR structure whose primary group is to be set. RtlSetGroupSecurityDescriptor replaces any existing primary group with the new primary group.
 * @param Group Pointer to a security identifier (SID) structure for the security descriptor's new primary owner.
 * @li \c This pointer, not the SID structure itself, is copied into the security descriptor.
 * @li \c If Group is NULL, RtlSetGroupSecurityDescriptor clears the security descriptor's primary group information. This marks the security descriptor as having no primary group.
 * @param GroupDefaulted Set this Boolean variable to TRUE if the primary group information is derived from a default mechanism.
 * @li \c If this parameter is TRUE, RtlSetGroupSecurityDescriptor sets the SE_GROUP_DEFAULTED flag in the security descriptor's SECURITY_DESCRIPTOR_CONTROL field.
 * @li \c If this parameter is FALSE, RtlSetGroupSecurityDescriptor clears the SE_GROUP_DEFAULTED flag.
 * @return NTSTATUS Successful or errant status.
 * @see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetgroupsecuritydescriptor
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetGroupSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID Group,
    _In_ BOOLEAN GroupDefaulted);

/**
 * The RtlAbsoluteToSelfRelativeSD routine converts an absolute-format security descriptor into a self-relative security
 * descriptor.
 *
 * \param AbsoluteSecurityDescriptor A pointer to the absolute-format security descriptor to convert.
 * \param SelfRelativeSecurityDescriptor A pointer to a caller-allocated buffer that receives the self-relative security
 * descriptor.
 * \param BufferLength A pointer to a variable that on input specifies the buffer size and on output receives the
 * required length, in bytes.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlabsolutetoselfrelativesd
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAbsoluteToSelfRelativeSD(
    _In_ PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    _Inout_ PULONG BufferLength);

/**
 * The RtlSelfRelativeToAbsoluteSD routine converts a self-relative security descriptor into an absolute-format security
 * descriptor and its associated components.
 *
 * \param SelfRelativeSecurityDescriptor A pointer to the self-relative security descriptor to convert.
 * \param AbsoluteSecurityDescriptor A pointer to a buffer that receives the absolute-format security descriptor.
 * \param AbsoluteSecurityDescriptorSize A pointer to a variable specifying and receiving the size, in bytes, of the
 * absolute security descriptor.
 * \param Dacl A pointer to a buffer that receives the discretionary access control list (DACL).
 * \param DaclSize A pointer to a variable specifying and receiving the size, in bytes, of the DACL.
 * \param Sacl A pointer to a buffer that receives the system access control list (SACL).
 * \param SaclSize A pointer to a variable specifying and receiving the size, in bytes, of the SACL.
 * \param Owner A pointer to a buffer that receives the owner SID.
 * \param OwnerSize A pointer to a variable specifying and receiving the size, in bytes, of the owner SID.
 * \param PrimaryGroup A pointer to a buffer that receives the primary group SID.
 * \param PrimaryGroupSize A pointer to a variable specifying and receiving the size, in bytes, of the primary group
 * SID.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlselfrelativetoabsolutesd
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSelfRelativeToAbsoluteSD(
    _In_ PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    _Out_writes_bytes_to_opt_(*AbsoluteSecurityDescriptorSize, *AbsoluteSecurityDescriptorSize) PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    _Inout_ PULONG AbsoluteSecurityDescriptorSize,
    _Out_writes_bytes_to_opt_(*DaclSize, *DaclSize) PACL Dacl,
    _Inout_ PULONG DaclSize,
    _Out_writes_bytes_to_opt_(*SaclSize, *SaclSize) PACL Sacl,
    _Inout_ PULONG SaclSize,
    _Out_writes_bytes_to_opt_(*OwnerSize, *OwnerSize) PSID Owner,
    _Inout_ PULONG OwnerSize,
    _Out_writes_bytes_to_opt_(*PrimaryGroupSize, *PrimaryGroupSize) PSID PrimaryGroup,
    _Inout_ PULONG PrimaryGroupSize);

/* phnt */

/**
 * The RtlSelfRelativeToAbsoluteSD2 routine converts a self-relative security descriptor into an absolute-format
 * security descriptor in place.
 *
 * \param SelfRelativeSecurityDescriptor A pointer to the self-relative security descriptor to convert in place.
 * \param BufferSize A pointer to a variable that on input specifies the buffer size and on output receives the size, in
 * bytes, of the resulting descriptor.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSelfRelativeToAbsoluteSD2(
    _Inout_ PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    _Inout_ PULONG BufferSize);

/**
 * The RtlMakeSelfRelativeSD routine creates a self-relative security descriptor from an absolute-format security
 * descriptor.
 *
 * \param AbsoluteSecurityDescriptor A pointer to the absolute-format security descriptor to convert.
 * \param SelfRelativeSecurityDescriptor A pointer to a caller-allocated buffer that receives the self-relative security
 * descriptor.
 * \param BufferLength A pointer to a variable that on input specifies the buffer size and on output receives the
 * required length, in bytes.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlmakeselfrelativesd
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlMakeSelfRelativeSD(
    _In_ PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    _Out_writes_bytes_(*BufferLength) PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    _Inout_ PULONG BufferLength);

/**
 * The RtlGetControlSecurityDescriptor routine retrieves the control information and revision of a security descriptor.
 *
 * \param SecurityDescriptor A pointer to the security descriptor to query.
 * \param Control A pointer to a variable that receives the SECURITY_DESCRIPTOR_CONTROL flags.
 * \param Revision A pointer to a variable that receives the revision of the security descriptor.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetcontrolsecuritydescriptor
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetControlSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PSECURITY_DESCRIPTOR_CONTROL Control,
    _Out_ PULONG Revision);

/**
 * The RtlSetControlSecurityDescriptor routine sets selected control bits of a security descriptor.
 *
 * \param SecurityDescriptor A pointer to the security descriptor to modify.
 * \param ControlBitsOfInterest A mask identifying the control bits to modify.
 * \param ControlBitsToSet The values to assign to the control bits identified by ControlBitsOfInterest.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetcontrolsecuritydescriptor
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetControlSecurityDescriptor(
     _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
     _In_ SECURITY_DESCRIPTOR_CONTROL ControlBitsOfInterest,
     _In_ SECURITY_DESCRIPTOR_CONTROL ControlBitsToSet);

/**
 * The RtlSetAttributesSecurityDescriptor routine sets the control attributes of a security descriptor and returns its
 * revision.
 *
 * \param SecurityDescriptor A pointer to the security descriptor to modify.
 * \param Control The SECURITY_DESCRIPTOR_CONTROL attributes to set.
 * \param Revision A pointer to a variable that receives the revision of the security descriptor.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetattributessecuritydescriptor
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetAttributesSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ SECURITY_DESCRIPTOR_CONTROL Control,
    _Out_ PULONG Revision);

/**
 * The RtlGetSecurityDescriptorRMControl routine retrieves the resource manager control byte from a security descriptor.
 *
 * \param SecurityDescriptor A pointer to the security descriptor to query.
 * \param RMControl A pointer to a variable that receives the resource manager control byte.
 * \return Returns `TRUE` if the security descriptor contains a resource manager control byte, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlGetSecurityDescriptorRMControl(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PUCHAR RMControl);

/**
 * The RtlSetSecurityDescriptorRMControl routine sets or clears the resource manager control byte of a security
 * descriptor.
 *
 * \param SecurityDescriptor A pointer to the security descriptor to modify.
 * \param RMControl An optional pointer to the resource manager control byte to set. If `NULL`, the resource manager
 * control is cleared.
 */
NTSYSAPI
VOID
NTAPI
RtlSetSecurityDescriptorRMControl(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PUCHAR RMControl);

/**
 * The RtlGetSaclSecurityDescriptor routine retrieves the system access control list (SACL) of a security descriptor.
 *
 * \param SecurityDescriptor A pointer to the security descriptor to query.
 * \param SaclPresent A pointer to a variable that receives `TRUE` if the security descriptor contains a SACL.
 * \param Sacl A pointer to a variable that receives a pointer to the SACL, or `NULL` if none is present.
 * \param SaclDefaulted A pointer to a variable that receives `TRUE` if the SACL was obtained by a default mechanism.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetsaclsecuritydescriptor
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetSaclSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PBOOLEAN SaclPresent,
    _Out_ PACL *Sacl,
    _Out_ PBOOLEAN SaclDefaulted);

/**
 * The RtlSetSaclSecurityDescriptor routine sets the system access control list (SACL) of an absolute-format security
 * descriptor.
 *
 * \param SecurityDescriptor A pointer to the security descriptor to modify.
 * \param SaclPresent If `TRUE`, the security descriptor is marked as containing a SACL.
 * \param Sacl An optional pointer to the SACL to assign to the security descriptor.
 * \param SaclDefaulted If `TRUE`, the SACL was obtained by a default mechanism.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetsaclsecuritydescriptor
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetSaclSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN SaclPresent,
    _In_opt_ PACL Sacl,
    _In_ BOOLEAN SaclDefaulted);

/**
 * The RtlNewSecurityObject routine allocates and initializes a self-relative security descriptor for a new object,
 * combining the parent and creator descriptors.
 *
 * \param ParentDescriptor An optional pointer to the security descriptor of the parent object.
 * \param CreatorDescriptor An optional pointer to the security descriptor supplied by the creator.
 * \param NewDescriptor A pointer to a variable that receives the newly allocated security descriptor.
 * \param IsDirectoryObject If `TRUE`, the new object is a container that can contain other objects.
 * \param Token An optional handle to the token representing the client that is creating the object.
 * \param GenericMapping A pointer to the GENERIC_MAPPING for the object type.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlNewSecurityObject(
    _In_opt_ PSECURITY_DESCRIPTOR ParentDescriptor,
    _In_opt_ PSECURITY_DESCRIPTOR CreatorDescriptor,
    _Out_ PSECURITY_DESCRIPTOR *NewDescriptor,
    _In_ BOOLEAN IsDirectoryObject,
    _In_opt_ HANDLE Token,
    _In_ PGENERIC_MAPPING GenericMapping);

/**
 * The RtlNewSecurityObjectEx routine allocates and initializes a self-relative security descriptor for a new object,
 * with support for object types and auto-inheritance.
 *
 * \param ParentDescriptor An optional pointer to the security descriptor of the parent object.
 * \param CreatorDescriptor An optional pointer to the security descriptor supplied by the creator.
 * \param NewDescriptor A pointer to a variable that receives the newly allocated security descriptor.
 * \param ObjectType An optional pointer to the GUID that identifies the object type.
 * \param IsDirectoryObject If `TRUE`, the new object is a container that can contain other objects.
 * \param AutoInheritFlags A combination of SEF_ flags controlling automatic inheritance.
 * \param Token An optional handle to the token representing the client that is creating the object.
 * \param GenericMapping A pointer to the GENERIC_MAPPING for the object type.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlNewSecurityObjectEx(
    _In_opt_ PSECURITY_DESCRIPTOR ParentDescriptor,
    _In_opt_ PSECURITY_DESCRIPTOR CreatorDescriptor,
    _Out_ PSECURITY_DESCRIPTOR *NewDescriptor,
    _In_opt_ GUID *ObjectType,
    _In_ BOOLEAN IsDirectoryObject,
    _In_ ULONG AutoInheritFlags, // SEF_*
    _In_opt_ HANDLE Token,
    _In_ PGENERIC_MAPPING GenericMapping);

/**
 * The RtlNewSecurityObjectWithMultipleInheritance routine allocates and initializes a self-relative security descriptor
 * for a new object, supporting inheritance from multiple object types.
 *
 * \param ParentDescriptor An optional pointer to the security descriptor of the parent object.
 * \param CreatorDescriptor An optional pointer to the security descriptor supplied by the creator.
 * \param NewDescriptor A pointer to a variable that receives the newly allocated security descriptor.
 * \param ObjectType An optional pointer to an array of GUID pointers that identify the object types.
 * \param GuidCount The number of object type GUIDs in the ObjectType array.
 * \param IsDirectoryObject If `TRUE`, the new object is a container that can contain other objects.
 * \param AutoInheritFlags A combination of SEF_ flags controlling automatic inheritance.
 * \param Token An optional handle to the token representing the client that is creating the object.
 * \param GenericMapping A pointer to the GENERIC_MAPPING for the object type.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlNewSecurityObjectWithMultipleInheritance(
    _In_opt_ PSECURITY_DESCRIPTOR ParentDescriptor,
    _In_opt_ PSECURITY_DESCRIPTOR CreatorDescriptor,
    _Out_ PSECURITY_DESCRIPTOR *NewDescriptor,
    _In_opt_ GUID **ObjectType,
    _In_ ULONG GuidCount,
    _In_ BOOLEAN IsDirectoryObject,
    _In_ ULONG AutoInheritFlags, // SEF_*
    _In_opt_ HANDLE Token,
    _In_ PGENERIC_MAPPING GenericMapping);

/**
 * The RtlDeleteSecurityObject routine frees a security descriptor previously created by one of the RtlNewSecurityObject
 * routines.
 *
 * \param ObjectDescriptor A pointer to a variable that references the security descriptor to delete.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteSecurityObject(
    _Inout_ PSECURITY_DESCRIPTOR *ObjectDescriptor);

/**
 * The RtlQuerySecurityObject routine retrieves selected security information from a self-relative security descriptor.
 *
 * \param ObjectDescriptor A pointer to the security descriptor to query.
 * \param SecurityInformation A SECURITY_INFORMATION value specifying which components to retrieve.
 * \param ResultantDescriptor An optional pointer to a buffer that receives the resulting security descriptor.
 * \param DescriptorLength The length, in bytes, of the ResultantDescriptor buffer.
 * \param ReturnLength A pointer to a variable that receives the required or written length, in bytes.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQuerySecurityObject(
     _In_ PSECURITY_DESCRIPTOR ObjectDescriptor,
     _In_ SECURITY_INFORMATION SecurityInformation,
     _Out_opt_ PSECURITY_DESCRIPTOR ResultantDescriptor,
     _In_ ULONG DescriptorLength,
     _Out_ PULONG ReturnLength);

/**
 * The RtlSetSecurityObject routine applies a modification to an object's security descriptor.
 *
 * \param SecurityInformation A SECURITY_INFORMATION value specifying which components to modify.
 * \param ModificationDescriptor A pointer to the security descriptor that supplies the new information.
 * \param ObjectsSecurityDescriptor A pointer to a variable that references the object's security descriptor, updated on
 * success.
 * \param GenericMapping A pointer to the GENERIC_MAPPING for the object type.
 * \param TokenHandle An optional handle to the token representing the client making the modification.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetSecurityObject(
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR ModificationDescriptor,
    _Inout_ PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
    _In_ PGENERIC_MAPPING GenericMapping,
    _In_opt_ HANDLE TokenHandle);

/**
 * The RtlSetSecurityObjectEx routine applies a modification to an object's security descriptor, with control over
 * auto-inheritance.
 *
 * \param SecurityInformation A SECURITY_INFORMATION value specifying which components to modify.
 * \param ModificationDescriptor A pointer to the security descriptor that supplies the new information.
 * \param ObjectsSecurityDescriptor A pointer to a variable that references the object's security descriptor, updated on
 * success.
 * \param AutoInheritFlags A combination of SEF_ flags controlling automatic inheritance.
 * \param GenericMapping A pointer to the GENERIC_MAPPING for the object type.
 * \param TokenHandle An optional handle to the token representing the client making the modification.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetSecurityObjectEx(
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR ModificationDescriptor,
    _Inout_ PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
    _In_ ULONG AutoInheritFlags, // SEF_*
    _In_ PGENERIC_MAPPING GenericMapping,
    _In_opt_ HANDLE TokenHandle);

/**
 * The RtlConvertToAutoInheritSecurityObject routine converts a security descriptor so that it uses automatic
 * inheritance.
 *
 * \param ParentDescriptor An optional pointer to the security descriptor of the parent object.
 * \param CurrentSecurityDescriptor A pointer to the security descriptor to convert.
 * \param NewSecurityDescriptor A pointer to a variable that receives the converted security descriptor.
 * \param ObjectType An optional pointer to the GUID that identifies the object type.
 * \param IsDirectoryObject If `TRUE`, the object is a container that can contain other objects.
 * \param GenericMapping A pointer to the GENERIC_MAPPING for the object type.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlConvertToAutoInheritSecurityObject(
    _In_opt_ PSECURITY_DESCRIPTOR ParentDescriptor,
    _In_ PSECURITY_DESCRIPTOR CurrentSecurityDescriptor,
    _Out_ PSECURITY_DESCRIPTOR *NewSecurityDescriptor,
    _In_opt_ GUID *ObjectType,
    _In_ BOOLEAN IsDirectoryObject,
    _In_ PGENERIC_MAPPING GenericMapping);

/**
 * The RtlNewInstanceSecurityObject routine creates a new security descriptor for an object instance, reusing prior
 * state when the parent and creator descriptors are unchanged.
 *
 * \param ParentDescriptorChanged If `TRUE`, the parent descriptor has changed since the last call.
 * \param CreatorDescriptorChanged If `TRUE`, the creator descriptor has changed since the last call.
 * \param OldClientTokenModifiedId A pointer to the LUID recording the client token's previous modification identifier.
 * \param NewClientTokenModifiedId A pointer to a variable that receives the client token's current modification
 * identifier.
 * \param ParentDescriptor An optional pointer to the security descriptor of the parent object.
 * \param CreatorDescriptor An optional pointer to the security descriptor supplied by the creator.
 * \param NewDescriptor A pointer to a variable that receives the newly allocated security descriptor.
 * \param IsDirectoryObject If `TRUE`, the new object is a container that can contain other objects.
 * \param TokenHandle A handle to the token representing the client that is creating the object.
 * \param GenericMapping A pointer to the GENERIC_MAPPING for the object type.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlNewInstanceSecurityObject(
    _In_ BOOLEAN ParentDescriptorChanged,
    _In_ BOOLEAN CreatorDescriptorChanged,
    _In_ PLUID OldClientTokenModifiedId,
    _Out_ PLUID NewClientTokenModifiedId,
    _In_opt_ PSECURITY_DESCRIPTOR ParentDescriptor,
    _In_opt_ PSECURITY_DESCRIPTOR CreatorDescriptor,
    _Out_ PSECURITY_DESCRIPTOR *NewDescriptor,
    _In_ BOOLEAN IsDirectoryObject,
    _In_ HANDLE TokenHandle,
    _In_ PGENERIC_MAPPING GenericMapping);

/**
 * The RtlCopySecurityDescriptor routine creates a copy of a security descriptor.
 *
 * \param InputSecurityDescriptor A pointer to the security descriptor to copy.
 * \param OutputSecurityDescriptor A pointer to a variable that receives the newly allocated copy.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCopySecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR InputSecurityDescriptor,
    _Out_ PSECURITY_DESCRIPTOR *OutputSecurityDescriptor);

/**
 * Describes an access control entry used to build an access control list template.
 */
typedef struct _RTL_ACE_DATA
{
    UCHAR AceType;
    UCHAR InheritFlags;
    UCHAR AceFlags;
    ACCESS_MASK AccessMask;
    PSID* Sid;
} RTL_ACE_DATA, *PRTL_ACE_DATA;

/**
 * The RtlCreateUserSecurityObject routine creates a security descriptor for an object from an array of ACE data, owner,
 * and group.
 *
 * \param AceData A pointer to an array of RTL_ACE_DATA entries describing the ACEs to place in the DACL.
 * \param AceCount The number of entries in the AceData array.
 * \param OwnerSid A pointer to the SID to assign as the object owner.
 * \param GroupSid A pointer to the SID to assign as the object primary group.
 * \param IsDirectoryObject If `TRUE`, the new object is a container that can contain other objects.
 * \param GenericMapping A pointer to the GENERIC_MAPPING for the object type.
 * \param NewSecurityDescriptor A pointer to a variable that receives the newly allocated security descriptor.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserSecurityObject(
    _In_ PRTL_ACE_DATA AceData,
    _In_ ULONG AceCount,
    _In_ PSID OwnerSid,
    _In_ PSID GroupSid,
    _In_ BOOLEAN IsDirectoryObject,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_ PSECURITY_DESCRIPTOR* NewSecurityDescriptor);

/**
 * The RtlCreateAndSetSD routine creates a self-relative security descriptor from an array of ACE data, owner, and
 * group.
 *
 * \param AceData A pointer to an array of RTL_ACE_DATA entries describing the ACEs to place in the DACL.
 * \param AceCount The number of entries in the AceData array.
 * \param OwnerSid An optional pointer to the SID to assign as the object owner.
 * \param GroupSid An optional pointer to the SID to assign as the object primary group.
 * \param NewSecurityDescriptor A pointer to a variable that receives the newly allocated security descriptor.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateAndSetSD(
    _In_ PRTL_ACE_DATA AceData,
    _In_ ULONG AceCount,
    _In_opt_ PSID OwnerSid,
    _In_opt_ PSID GroupSid,
    _Out_ PSECURITY_DESCRIPTOR* NewSecurityDescriptor);

EXTERN_C_END

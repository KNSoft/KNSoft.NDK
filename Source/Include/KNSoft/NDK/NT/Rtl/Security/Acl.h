#pragma once

#include "../../MinDef.h"

EXTERN_C_START

/* ntifs.h */

/**
 * The RtlCreateAcl routine creates and initializes an access control list (ACL).
 *
 * \param Acl A pointer to a caller-allocated buffer that receives the initialized ACL.
 * \param AclLength The length, in bytes, of the buffer pointed to by Acl.
 * \param AclRevision The revision level of the ACL to create.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateacl
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateAcl(
    _Out_writes_bytes_(AclLength) PACL Acl,
    _In_ ULONG AclLength,
    _In_ ULONG AclRevision);

#if (NTDDI_VERSION >= NTDDI_WIN11_GA)
/**
 * The RtlGetAcesBufferSize routine returns the total size, in bytes, of the access control entries (ACEs) contained in
 * an access control list (ACL).
 *
 * \param Acl A pointer to the ACL to examine.
 * \param AcesBufferSize A pointer to a variable that receives the size, in bytes, of the ACEs.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetAcesBufferSize(
    _In_ PACL Acl,
    _Out_ PULONG AcesBufferSize);
#endif

/**
 * The RtlAddAce routine adds one or more ACEs to an access control list (ACL).
 *
 * \param Acl The ACL to modify.
 * \param AceRevision The revision of the ACL.
 * \param StartingAceIndex The zero-based index at which to insert the ACEs.
 * \param AceList A buffer containing the ACEs to add.
 * \param AceListLength The size, in bytes, of AceList.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG StartingAceIndex,
    _In_reads_bytes_(AceListLength) PVOID AceList,
    _In_ ULONG AceListLength);

/**
 * The RtlDeleteAce routine deletes an access control entry (ACE) at a specified index from an access control list
 * (ACL).
 *
 * \param Acl A pointer to the ACL from which to delete the ACE.
 * \param AceIndex The zero-based index of the ACE to delete.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldeleteace
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceIndex);

/**
 * The RtlGetAce routine retrieves a pointer to an ACE at the specified index in an access control list (ACL).
 *
 * \param Acl The ACL to query.
 * \param AceIndex The zero-based index of the ACE to retrieve.
 * \param Ace Receives a pointer to the ACE.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetAce(
    _In_ PACL Acl,
    _In_ ULONG AceIndex,
    _Outptr_ PVOID* Ace);

/**
 * The RtlAddAccessAllowedAce routine adds an access-allowed access control entry (ACE) to an access control list (ACL).
 *
 * \param Acl A pointer to the ACL to modify.
 * \param AceRevision The revision level of the ACE to add.
 * \param AccessMask The access mask granted by the ACE.
 * \param Sid A pointer to the SID to which access is granted.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdaccessallowedace
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessAllowedAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid);

/**
 * The RtlAddAccessAllowedAceEx routine adds an access-allowed access control entry (ACE), including inheritance flags,
 * to an access control list (ACL).
 *
 * \param Acl A pointer to the ACL to modify.
 * \param AceRevision The revision level of the ACE to add.
 * \param AceFlags The inheritance and audit flags for the ACE.
 * \param AccessMask The access mask granted by the ACE.
 * \param Sid A pointer to the SID to which access is granted.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdaccessallowedaceex
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessAllowedAceEx(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid);

/* phnt */

/**
 * The RtlDefaultNpAcl routine creates the default discretionary access control list (DACL) used for named pipes.
 *
 * \param Acl A pointer to a variable that receives the allocated default named-pipe ACL.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDefaultNpAcl(
    _Out_ PACL *Acl);

/**
 * The RtlValidAcl routine validates an access control list (ACL) by verifying its structure and contents.
 *
 * \param Acl A pointer to the ACL to validate.
 * \return Returns `TRUE` if the ACL is structurally valid, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlValidAcl(
    _In_ PACL Acl);

/**
 * The RtlQueryInformationAcl routine retrieves information about an access control list (ACL).
 *
 * \param Acl The ACL to query.
 * \param AclInformation A buffer that receives the requested information.
 * \param AclInformationLength The size, in bytes, of the buffer.
 * \param AclInformationClass The class of information to retrieve.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryInformationAcl(
    _In_ PACL Acl,
    _Out_writes_bytes_(AclInformationLength) PVOID AclInformation,
    _In_ ULONG AclInformationLength,
    _In_ ACL_INFORMATION_CLASS AclInformationClass);

/**
 * The RtlSetInformationAcl routine sets information on an access control list (ACL).
 *
 * \param Acl The ACL to modify.
 * \param AclInformation A buffer containing the information to set.
 * \param AclInformationLength The size, in bytes, of the buffer.
 * \param AclInformationClass The class of information to set.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetInformationAcl(
    _Inout_ PACL Acl,
    _In_reads_bytes_(AclInformationLength) PVOID AclInformation,
    _In_ ULONG AclInformationLength,
    _In_ ACL_INFORMATION_CLASS AclInformationClass);

/**
 * The RtlFirstFreeAce routine locates the first unused position in an access control list (ACL).
 *
 * \param Acl The ACL to examine.
 * \param FirstFree Receives a pointer to the first free position within the ACL.
 * \return TRUE if the ACL is well-formed; otherwise, FALSE.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlFirstFreeAce(
    _In_ PACL Acl,
    _Out_ PVOID *FirstFree);

/**
 * The RtlFindAceByType routine finds the first ACE of the specified type in an access control list (ACL).
 *
 * \param Acl The ACL to search.
 * \param AceType The ACE type to find.
 * \param Index An optional pointer that receives the index of the matching ACE.
 * \return A pointer to the matching ACE, or NULL if none was found.
 */
NTSYSAPI
PVOID
NTAPI
RtlFindAceByType(
    _In_ PACL Acl,
    _In_ UCHAR AceType,
    _Out_opt_ PULONG Index);

/**
 * The RtlOwnerAcesPresent routine determines whether an access control list (ACL) contains any access control entries
 * (ACEs) that carry the owner flag.
 *
 * \param pAcl A pointer to the ACL to examine.
 * \return Returns `TRUE` if the ACL contains owner ACEs, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlOwnerAcesPresent(
    _In_ PACL pAcl);

/**
 * The RtlAddAccessDeniedAce routine adds an access-denied access control entry (ACE) to an access control list (ACL).
 *
 * \param Acl A pointer to the ACL to modify.
 * \param AceRevision The revision level of the ACE to add.
 * \param AccessMask The access mask denied by the ACE.
 * \param Sid A pointer to the SID to which access is denied.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdaccessdeniedace
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessDeniedAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid);

/**
 * The RtlAddAccessDeniedAceEx routine adds an access-denied access control entry (ACE), including inheritance flags, to
 * an access control list (ACL).
 *
 * \param Acl A pointer to the ACL to modify.
 * \param AceRevision The revision level of the ACE to add.
 * \param AceFlags The inheritance and audit flags for the ACE.
 * \param AccessMask The access mask denied by the ACE.
 * \param Sid A pointer to the SID to which access is denied.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdaccessdeniedaceex
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessDeniedAceEx(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid);

/**
 * The RtlAddAuditAccessAce routine adds a system-audit access control entry (ACE) to an access control list (ACL).
 *
 * \param Acl A pointer to the ACL to modify.
 * \param AceRevision The revision level of the ACE to add.
 * \param AccessMask The access mask that triggers auditing.
 * \param Sid A pointer to the SID for which access is audited.
 * \param AuditSuccess If `TRUE`, successful access attempts are audited.
 * \param AuditFailure If `TRUE`, failed access attempts are audited.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdauditaccessace
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAuditAccessAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid,
    _In_ BOOLEAN AuditSuccess,
    _In_ BOOLEAN AuditFailure);

/**
 * The RtlAddAuditAccessAceEx routine adds a system-audit access control entry (ACE), including inheritance flags, to an
 * access control list (ACL).
 *
 * \param Acl A pointer to the ACL to modify.
 * \param AceRevision The revision level of the ACE to add.
 * \param AceFlags The inheritance and audit flags for the ACE.
 * \param AccessMask The access mask that triggers auditing.
 * \param Sid A pointer to the SID for which access is audited.
 * \param AuditSuccess If `TRUE`, successful access attempts are audited.
 * \param AuditFailure If `TRUE`, failed access attempts are audited.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdauditaccessaceex
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAuditAccessAceEx(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid,
    _In_ BOOLEAN AuditSuccess,
    _In_ BOOLEAN AuditFailure);

/**
 * The RtlAddAccessAllowedObjectAce routine adds an object-specific access-allowed access control entry (ACE) to an
 * access control list (ACL).
 *
 * \param Acl A pointer to the ACL to modify.
 * \param AceRevision The revision level of the ACE to add.
 * \param AceFlags The inheritance and audit flags for the ACE.
 * \param AccessMask The access mask granted by the ACE.
 * \param ObjectTypeGuid An optional pointer to the GUID of the object type protected by the ACE.
 * \param InheritedObjectTypeGuid An optional pointer to the GUID of the object type that inherits the ACE.
 * \param Sid A pointer to the SID to which access is granted.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdaccessallowedobjectace
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessAllowedObjectAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_opt_ PCGUID ObjectTypeGuid,
    _In_opt_ PCGUID InheritedObjectTypeGuid,
    _In_ PSID Sid);

/**
 * The RtlAddAccessDeniedObjectAce routine adds an object-specific access-denied access control entry (ACE) to an access
 * control list (ACL).
 *
 * \param Acl A pointer to the ACL to modify.
 * \param AceRevision The revision level of the ACE to add.
 * \param AceFlags The inheritance and audit flags for the ACE.
 * \param AccessMask The access mask denied by the ACE.
 * \param ObjectTypeGuid An optional pointer to the GUID of the object type protected by the ACE.
 * \param InheritedObjectTypeGuid An optional pointer to the GUID of the object type that inherits the ACE.
 * \param Sid A pointer to the SID to which access is denied.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdaccessdeniedobjectace
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessDeniedObjectAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_opt_ PCGUID ObjectTypeGuid,
    _In_opt_ PCGUID InheritedObjectTypeGuid,
    _In_ PSID Sid);

/**
 * The RtlAddAuditAccessObjectAce routine adds an object-specific system-audit access control entry (ACE) to an access
 * control list (ACL).
 *
 * \param Acl A pointer to the ACL to modify.
 * \param AceRevision The revision level of the ACE to add.
 * \param AceFlags The inheritance and audit flags for the ACE.
 * \param AccessMask The access mask that triggers auditing.
 * \param ObjectTypeGuid An optional pointer to the GUID of the object type protected by the ACE.
 * \param InheritedObjectTypeGuid An optional pointer to the GUID of the object type that inherits the ACE.
 * \param Sid A pointer to the SID for which access is audited.
 * \param AuditSuccess If `TRUE`, successful access attempts are audited.
 * \param AuditFailure If `TRUE`, failed access attempts are audited.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdauditaccessobjectace
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAuditAccessObjectAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_opt_ PCGUID ObjectTypeGuid,
    _In_opt_ PCGUID InheritedObjectTypeGuid,
    _In_ PSID Sid,
    _In_ BOOLEAN AuditSuccess,
    _In_ BOOLEAN AuditFailure);

/**
 * Compound ACE type value indicating impersonation.
 */
#define COMPOUND_ACE_IMPERSONATION 1

/**
 * Represents a compound access-allowed access control entry (ACE).
 */
typedef struct _COMPOUND_ACCESS_ALLOWED_ACE
{
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    USHORT CompoundAceType; // COMPOUND_ACE_*
    USHORT Reserved;
    ULONG SidStart; // Server SID
    // Client SID follows
} COMPOUND_ACCESS_ALLOWED_ACE, *PCOMPOUND_ACCESS_ALLOWED_ACE;

/**
 * The RtlAddCompoundAce routine adds a compound access control entry (ACE) that associates a server SID with a client
 * SID to an access control list (ACL).
 *
 * \param Acl A pointer to the ACL to modify.
 * \param AceRevision The revision level of the ACE to add.
 * \param AceType The compound ACE type.
 * \param AccessMask The access mask granted by the ACE.
 * \param ServerSid A pointer to the server SID.
 * \param ClientSid A pointer to the client SID.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddCompoundAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ UCHAR AceType, // COMPOUND_ACE_*
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID ServerSid,
    _In_ PSID ClientSid);

/**
 * The RtlAddMandatoryAce routine adds a mandatory integrity label access control entry (ACE) to an access control list
 * (ACL).
 *
 * \param Acl A pointer to the ACL to modify.
 * \param AceRevision The revision level of the ACE to add.
 * \param AceFlags The inheritance and audit flags for the ACE.
 * \param Sid A pointer to the SID that specifies the mandatory integrity level.
 * \param AceType The mandatory ACE type.
 * \param AccessMask The mandatory policy access mask enforced by the ACE.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddMandatoryAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ PSID Sid,
    _In_ UCHAR AceType,
    _In_ ACCESS_MASK AccessMask);

#if (NTDDI_VERSION >= NTDDI_WIN8)

/**
 * The RtlAddResourceAttributeAce routine adds a resource attribute access control entry (ACE) to an access control list
 * (ACL).
 *
 * \param Acl A pointer to the ACL to modify.
 * \param AceRevision The revision level of the ACE to add.
 * \param AceFlags The inheritance and audit flags for the ACE.
 * \param AccessMask The access mask for the ACE.
 * \param Sid A pointer to the SID associated with the ACE.
 * \param AttributeInfo A pointer to the CLAIM_SECURITY_ATTRIBUTES_INFORMATION that describes the resource attribute.
 * \param ReturnLength A pointer to a variable that receives the size, in bytes, of the added ACE.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdresourceattributeace
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddResourceAttributeAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ULONG AccessMask,
    _In_ PSID Sid,
    _In_ PCLAIM_SECURITY_ATTRIBUTES_INFORMATION AttributeInfo,
    _Out_ PULONG ReturnLength);

/**
 * The RtlAddScopedPolicyIDAce routine adds a scoped policy identifier access control entry (ACE) to an access control
 * list (ACL).
 *
 * \param Acl A pointer to the ACL to modify.
 * \param AceRevision The revision level of the ACE to add.
 * \param AceFlags The inheritance and audit flags for the ACE.
 * \param AccessMask The access mask for the ACE.
 * \param Sid A pointer to the SID that identifies the central access policy.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddScopedPolicyIDAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ULONG AccessMask,
    _In_ PSID Sid);

/**
 * The RtlAddProcessTrustLabelAce routine adds a process trust label access control entry (ACE) to an access control
 * list (ACL).
 *
 * \param Acl A pointer to the ACL to modify.
 * \param AceRevision The revision level of the ACE to add.
 * \param AceFlags The inheritance and audit flags for the ACE.
 * \param ProcessTrustLabelSid A pointer to the SID that specifies the process trust label.
 * \param AceType The process trust label ACE type.
 * \param AccessMask The access mask enforced by the ACE.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddProcessTrustLabelAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ PSID ProcessTrustLabelSid,
    _In_ UCHAR AceType, // SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE
    _In_ ACCESS_MASK AccessMask);

// rev
/**
 * The RtlAddAccessFilterAce routine adds an access-filter ACE to the specified access control list.
 *
 * \param Acl The ACL to modify.
 * \param AceRevision The revision of the ACL.
 * \param AceFlags The ACE flags (for example, TRUST_PROTECTED_FILTER_ACE_FLAG).
 * \param AccessFilterSid The SID identifying the access filter.
 * \param AceType The system filtering ACE type (SYSTEM_FILTERING_ACE_TYPE).
 * \param AccessMask The access mask for the ACE.
 * \param Buffer A buffer describing the SYSTEM_ACCESS_FILTER_ACE payload.
 * \param BufferLength The length, in bytes, of Buffer.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessFilterAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags, // TRUST_PROTECTED_FILTER_ACE_FLAG
    _In_ PSID AccessFilterSid,
    _In_ UCHAR AceType, // SYSTEM_FILTERING_ACE_TYPE
    _In_ ACCESS_MASK AccessMask,
    _In_ PVOID Buffer, // SYSTEM_ACCESS_FILTER_ACE
    _In_ USHORT BufferLength);

#endif

EXTERN_C_END

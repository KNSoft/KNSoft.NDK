#pragma once

#include "../../MinDef.h"

EXTERN_C_START

/* phnt */

#if (NTDDI_VERSION >= NTDDI_WIN8)

/**
 * The RtlIsUntrustedObject routine determines whether the specified object originates from an untrusted
 * (lower-integrity) source.
 *
 * \param Handle An optional handle to the object to inspect.
 * \param Object An optional pointer to the object to inspect.
 * \param IsUntrustedObject Receives TRUE if the object is untrusted.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIsUntrustedObject(
    _In_opt_ HANDLE Handle,
    _In_opt_ PVOID Object,
    _Out_ PBOOLEAN IsUntrustedObject);

/**
 * The RtlQueryValidationRunlevel routine returns the validation run level associated with an optional component name.
 *
 * \param ComponentName An optional pointer to the Unicode string that names the component to query.
 * \return ULONG The validation run level for the specified component.
 */
NTSYSAPI
ULONG
NTAPI
RtlQueryValidationRunlevel(
    _In_opt_ PUNICODE_STRING ComponentName);

/**
 * The RtlNewSecurityGrantedAccess routine determines the access granted to a client for a desired access mask, taking
 * privileges into account.
 *
 * \param DesiredAccess The access mask requested by the client.
 * \param NewPrivileges A pointer to a PRIVILEGE_SET that receives the privileges used to grant access.
 * \param Length A pointer to a variable that on input specifies and on output receives the size, in bytes, of
 * NewPrivileges.
 * \param TokenHandle An optional handle to the client token.
 * \param GenericMapping A pointer to the GENERIC_MAPPING for the object type.
 * \param RemainingDesiredAccess A pointer to a variable that receives the access still requiring a discretionary check.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlNewSecurityGrantedAccess(
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PPRIVILEGE_SET NewPrivileges,
    _Inout_ PULONG Length,
    _In_opt_ HANDLE TokenHandle,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_ PACCESS_MASK RemainingDesiredAccess);

#endif

// RtlpConvertRelativeToAbsoluteSecurityAttribute


// RtlpMergeSecurityAttributeInformation
/**
 * The RtlpMergeSecurityAttributeInformation routine merges the resource-attribute ACEs from two system access control
 * lists (SACLs) into a newly allocated ACL.
 *
 * \param SourceSacl An optional source ACL containing SYSTEM_RESOURCE_ATTRIBUTE_ACE entries.
 * \param AdditionalSacl An optional additional ACL whose attribute ACEs are merged with the source.
 * \param MergedSacl Receives a newly allocated ACL containing the merged attribute ACEs.
 * \param MergeMode Controls how overlapping attribute ACEs from the two ACLs are combined.
 * \return NTSTATUS Successful or errant status.
 * \remarks Prototype reconstructed from disassembly; the routine walks ACL structures (not raw security descriptors).
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpMergeSecurityAttributeInformation(
    _In_opt_ PACL SourceSacl,
    _In_opt_ PACL AdditionalSacl,
    _Outptr_ PACL *MergedSacl,
    _In_ CHAR MergeMode
    );

// RtlpConvertAbsoluteToRelativeSecurityAttribute
//NTSYSAPI
//PRUNTIME_FUNCTION
//NTAPI
//RtlLookupFunctionTable(
//    _In_ ULONGLONG ControlPc,
//    _Out_ ULONGLONG *ImageBase,
//    _Out_ ULONG *Length,
//    _In_ ULONGLONG HistoryTable
//    );

// rev
/**
 * The RtlpConvertAbsoluteToRelativeSecurityAttribute routine converts a security attribute from absolute to
 * self-relative form.
 *
 * \param AbsoluteSa The absolute-form security attribute information.
 * \param RelativeSa A buffer that receives the self-relative security attribute information.
 * \param RelativeSaLength On input specifies the buffer size; on output receives the required or written length, in
 * bytes.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpConvertAbsoluteToRelativeSecurityAttribute(
    _In_ PVOID AbsoluteSa,
    _Out_ PVOID RelativeSa,
    _Inout_ ULONG *RelativeSaLength
    );

// RtlMapSecurityErrorToNtStatus
/**
 * The RtlMapSecurityErrorToNtStatus routine maps an SSPI security status code to the corresponding NTSTATUS value.
 *
 * \param SecurityStatus The security status code to map.
 * \return NTSTATUS The NTSTATUS value that corresponds to the security status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlMapSecurityErrorToNtStatus(
    _In_ LONG SecurityStatus
    );


EXTERN_C_END

#pragma once

#include "../../MinDef.h"

EXTERN_C_START

/* ntifs.h */

/**
 * The RtlValidSid routine validates a security identifier (SID) by verifying that its revision level and subauthority
 * count are within valid ranges.
 *
 * \param Sid A pointer to the SID to validate.
 * \return Returns `TRUE` if the SID is structurally valid, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlvalidsid
 */
_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlValidSid(
    _In_ PSID Sid);

/**
 * The RtlEqualSid routine determines whether two security identifiers (SIDs) are equal.
 *
 * \param Sid1 A pointer to the first SID to compare.
 * \param Sid2 A pointer to the second SID to compare.
 * \return Returns `TRUE` if the two SIDs are equal, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlequalsid
 */
_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlEqualSid(
    _In_ PSID Sid1,
    _In_ PSID Sid2);

/**
 * The RtlEqualPrefixSid routine determines whether two security identifiers (SIDs) share the same prefix, ignoring the
 * final subauthority (relative identifier).
 *
 * \param Sid1 A pointer to the first SID to compare.
 * \param Sid2 A pointer to the second SID to compare.
 * \return Returns `TRUE` if the SID prefixes are equal, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlequalprefixsid
 */
_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlEqualPrefixSid(
    _In_ PSID Sid1,
    _In_ PSID Sid2);

/**
 * The RtlLengthRequiredSid routine returns the length, in bytes, required to store a security identifier (SID) with the
 * specified number of subauthorities.
 *
 * \param SubAuthorityCount The number of subauthorities the SID will contain.
 * \return ULONG The number of bytes required to hold the SID.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtllengthrequiredsid
 */
NTSYSAPI
ULONG
NTAPI
RtlLengthRequiredSid(
    _In_ ULONG SubAuthorityCount);

/**
 * The RtlFreeSid routine frees a SID previously allocated with RtlAllocateAndInitializeSid.
 *
 * \param Sid The SID to free.
 * \return NULL.
 */
NTSYSAPI
PVOID
NTAPI
RtlFreeSid(
    _In_ _Post_invalid_ PSID Sid);

/**
 * The RtlAllocateAndInitializeSid routine allocates and initializes a security identifier (SID) with up to eight
 * subauthorities.
 *
 * \param IdentifierAuthority A pointer to the SID_IDENTIFIER_AUTHORITY for the new SID.
 * \param SubAuthorityCount The number of subauthorities to place in the SID.
 * \param SubAuthority0 The first subauthority value.
 * \param SubAuthority1 The second subauthority value.
 * \param SubAuthority2 The third subauthority value.
 * \param SubAuthority3 The fourth subauthority value.
 * \param SubAuthority4 The fifth subauthority value.
 * \param SubAuthority5 The sixth subauthority value.
 * \param SubAuthority6 The seventh subauthority value.
 * \param SubAuthority7 The eighth subauthority value.
 * \param Sid A pointer to a variable that receives the allocated SID.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlallocateandinitializesid
 */
_Must_inspect_result_
NTSYSAPI
NTSTATUS
NTAPI
RtlAllocateAndInitializeSid(
    _In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    _In_ UCHAR SubAuthorityCount,
    _In_ ULONG SubAuthority0,
    _In_ ULONG SubAuthority1,
    _In_ ULONG SubAuthority2,
    _In_ ULONG SubAuthority3,
    _In_ ULONG SubAuthority4,
    _In_ ULONG SubAuthority5,
    _In_ ULONG SubAuthority6,
    _In_ ULONG SubAuthority7,
    _Outptr_ PSID *Sid);

#if (NTDDI_VERSION >= NTDDI_WIN8)
/**
 * The RtlAllocateAndInitializeSidEx routine allocates and initializes a security identifier (SID) from an array of
 * subauthorities.
 *
 * \param IdentifierAuthority A pointer to the SID_IDENTIFIER_AUTHORITY for the new SID.
 * \param SubAuthorityCount The number of subauthorities to place in the SID.
 * \param SubAuthorities A pointer to an array of subauthority values.
 * \param Sid A pointer to a variable that receives the allocated SID.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlallocateandinitializesidex
 */
_Must_inspect_result_
NTSYSAPI
NTSTATUS
NTAPI
RtlAllocateAndInitializeSidEx(
    _In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    _In_ UCHAR SubAuthorityCount,
    _In_reads_(SubAuthorityCount) PULONG SubAuthorities,
    _Outptr_ PSID *Sid);
#endif // NTDDI_VERSION >= NTDDI_WIN8

/**
 * The RtlInitializeSid routine initializes a caller-allocated security identifier (SID) structure.
 *
 * \param Sid A pointer to the SID buffer to initialize.
 * \param IdentifierAuthority A pointer to the SID_IDENTIFIER_AUTHORITY for the SID.
 * \param SubAuthorityCount The number of subauthorities the SID will contain.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitializesid
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeSid(
    _Out_ PSID Sid,
    _In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    _In_ UCHAR SubAuthorityCount);

#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
/**
 * The RtlInitializeSidEx routine initializes a caller-allocated security identifier (SID) using a variable number of
 * subauthority arguments.
 *
 * \param Sid A pointer to the SID buffer to initialize.
 * \param IdentifierAuthority A pointer to the SID_IDENTIFIER_AUTHORITY for the SID.
 * \param SubAuthorityCount The number of subauthority arguments that follow.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitializesidex
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeSidEx(
    _Out_writes_bytes_(SECURITY_SID_SIZE(SubAuthorityCount)) PSID Sid,
    _In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    _In_ UCHAR SubAuthorityCount,
    ...);
#endif

/**
 * The RtlIdentifierAuthoritySid routine returns a pointer to the identifier authority of a security identifier (SID).
 *
 * \param Sid A pointer to the SID to query.
 * \return PSID_IDENTIFIER_AUTHORITY A pointer to the SID_IDENTIFIER_AUTHORITY within the SID.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlidentifierauthoritysid
 */
NTSYSAPI
PSID_IDENTIFIER_AUTHORITY
NTAPI
RtlIdentifierAuthoritySid(
    _In_ PSID Sid);

/**
 * The RtlSubAuthoritySid routine returns a pointer to a specified subauthority of a security identifier (SID).
 *
 * \param Sid A pointer to the SID to query.
 * \param SubAuthority The zero-based index of the subauthority to retrieve.
 * \return PULONG A pointer to the requested subauthority value within the SID.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsubauthoritysid
 */
NTSYSAPI
PULONG
NTAPI
RtlSubAuthoritySid(
    _In_ PSID Sid,
    _In_ ULONG SubAuthority);

/**
 * The RtlSubAuthorityCountSid routine returns a pointer to the subauthority count field of a security identifier (SID).
 *
 * \param Sid A pointer to the SID to query.
 * \return PUCHAR A pointer to the subauthority count field within the SID.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsubauthoritycountsid
 */
NTSYSAPI
PUCHAR
NTAPI
RtlSubAuthorityCountSid(
    _In_ PSID Sid);

/**
 * The RtlLengthSid routine returns the length, in bytes, of a security identifier (SID).
 *
 * \param Sid A pointer to the SID to measure.
 * \return ULONG The length of the SID, in bytes.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtllengthsid
 */
NTSYSAPI
_Post_satisfies_(return >= 8 && return <= SECURITY_MAX_SID_SIZE)
ULONG
NTAPI
RtlLengthSid(
    _In_ PSID Sid);

/**
 * The RtlCopySid routine copies a security identifier (SID) into a caller-supplied buffer.
 *
 * \param DestinationSidLength The length, in bytes, of the destination buffer.
 * \param DestinationSid A pointer to the buffer that receives the copied SID.
 * \param SourceSid A pointer to the SID to copy.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopysid
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCopySid(
    _In_ ULONG DestinationSidLength,
    _Out_writes_bytes_(DestinationSidLength) PSID DestinationSid,
    _In_ PSID SourceSid);

/**
 * The RtlCreateServiceSid routine creates a service security identifier (SID) derived from a service name.
 *
 * \param ServiceName A pointer to the Unicode string that specifies the service name.
 * \param ServiceSid A pointer to a caller-allocated buffer that receives the service SID.
 * \param ServiceSidLength A pointer to a variable that on input specifies the buffer size and on output receives the
 * required or written length, in bytes.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateservicesid
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateServiceSid(
    _In_ PUNICODE_STRING ServiceName,
    _Out_writes_bytes_opt_(*ServiceSidLength) PSID ServiceSid,
    _Inout_ PULONG ServiceSidLength);

NTSYSAPI
NTSTATUS
NTAPI
RtlConvertSidToUnicodeString(
    _When_(AllocateDestinationString, _Out_) _When_(!AllocateDestinationString, _In_) PUNICODE_STRING UnicodeString,
    _In_ PSID Sid,
    _In_ BOOLEAN AllocateDestinationString);

/**
 * The RtlReplaceSidInSd routine replaces every occurrence of a security identifier (SID) in a security descriptor with
 * a new SID.
 *
 * \param SecurityDescriptor A pointer to the security descriptor to modify.
 * \param OldSid A pointer to the SID to be replaced.
 * \param NewSid A pointer to the replacement SID.
 * \param NumChanges A pointer to a variable that receives the number of replacements performed.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlreplacesidinsd
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlReplaceSidInSd(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ PSID OldSid,
    _In_ PSID NewSid,
    _Out_ ULONG * NumChanges);

/**
 * The RtlCreateVirtualAccountSid routine creates a virtual account security identifier (SID) from a name and base
 * subauthority.
 *
 * \param Name A pointer to the Unicode string that specifies the virtual account name.
 * \param BaseSubAuthority The base subauthority value that identifies the virtual account domain.
 * \param Sid A pointer to a caller-allocated buffer that receives the virtual account SID.
 * \param SidLength A pointer to a variable that on input specifies the buffer size and on output receives the required
 * or written length, in bytes.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateVirtualAccountSid(
    _In_ PCUNICODE_STRING Name,
    _In_ ULONG BaseSubAuthority,
    _Out_writes_bytes_(*SidLength) PSID Sid,
    _Inout_ PULONG SidLength);

/* phnt */

/**
 * The RtlCopySidAndAttributesArray routine copies an array of SID_AND_ATTRIBUTES entries, placing the copied SIDs into
 * a separate SID area.
 *
 * \param Count The number of SID_AND_ATTRIBUTES entries to copy.
 * \param Src A pointer to the source array of SID_AND_ATTRIBUTES entries.
 * \param SidAreaSize The size, in bytes, of the buffer that receives the copied SIDs.
 * \param Dest A pointer to the destination array of SID_AND_ATTRIBUTES entries.
 * \param SidArea A pointer to the buffer that receives the copied SIDs.
 * \param RemainingSidArea A pointer to a variable that receives a pointer to the unused portion of the SID area.
 * \param RemainingSidAreaSize A pointer to a variable that receives the size, in bytes, of the unused portion of the
 * SID area.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCopySidAndAttributesArray(
    _In_ ULONG Count,
    _In_ PSID_AND_ATTRIBUTES Src,
    _In_ ULONG SidAreaSize,
    _In_ PSID_AND_ATTRIBUTES Dest,
    _In_ PSID SidArea,
    _Out_ PSID * RemainingSidArea,
    _Out_ PULONG RemainingSidAreaSize);

/**
 * The RtlSidDominates routine determines whether one integrity-level security identifier (SID) dominates another.
 *
 * \param Sid1 A pointer to the first SID.
 * \param Sid2 A pointer to the second SID.
 * \param Dominates A pointer to a variable that receives `TRUE` if Sid1 dominates Sid2, otherwise `FALSE`.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSidDominates(
    _In_ PSID Sid1,
    _In_ PSID Sid2,
    _Out_ PBOOLEAN Dominates);

#if (NTDDI_VERSION >= NTDDI_WINBLUE)

/**
 * The RtlSidDominatesForTrust routine determines whether a security identifier (SID) dominates a process trust level
 * SID.
 *
 * \param Sid1 A pointer to the first SID.
 * \param Sid2 A pointer to the second SID.
 * \param DominatesTrust A pointer to a variable that receives `TRUE` if Sid1 dominates the trust SID, otherwise
 * `FALSE`.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSidDominatesForTrust(
    _In_ PSID Sid1,
    _In_ PSID Sid2,
    _Out_ PBOOLEAN DominatesTrust // TokenProcessTrustLevel
);

#endif

/**
 * The RtlSidEqualLevel routine determines whether two integrity-level security identifiers (SIDs) represent the same
 * level.
 *
 * \param Sid1 A pointer to the first SID.
 * \param Sid2 A pointer to the second SID.
 * \param EqualLevel A pointer to a variable that receives `TRUE` if the SIDs are at the same level, otherwise `FALSE`.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSidEqualLevel(
    _In_ PSID Sid1,
    _In_ PSID Sid2,
    _Out_ PBOOLEAN EqualLevel);

/**
 * The RtlSidIsHigherLevel routine determines whether one integrity-level security identifier (SID) represents a higher
 * level than another.
 *
 * \param Sid1 A pointer to the first SID.
 * \param Sid2 A pointer to the second SID.
 * \param HigherLevel A pointer to a variable that receives `TRUE` if Sid1 is at a higher level than Sid2, otherwise
 * `FALSE`.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSidIsHigherLevel(
    _In_ PSID Sid1,
    _In_ PSID Sid2,
    _Out_ PBOOLEAN HigherLevel);

/**
 * Maximum length of a Unicode string held in a stack buffer.
 */
#define MAX_UNICODE_STACK_BUFFER_LENGTH 256

/**
 * The RtlLengthSidAsUnicodeString routine returns the length, in bytes, of the Unicode string representation of a
 * security identifier (SID).
 *
 * \param Sid A pointer to the SID to measure.
 * \param StringLength A pointer to a variable that receives the required string length, in bytes.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlLengthSidAsUnicodeString(
    _In_ PSID Sid,
    _Out_ PULONG StringLength);

/**
 * The RtlSidHashInitialize routine initializes a SID_AND_ATTRIBUTES_HASH structure for fast lookup of an array of SIDs.
 *
 * \param SidAttr A pointer to the array of SID_AND_ATTRIBUTES entries to hash.
 * \param SidCount The number of entries in the SidAttr array.
 * \param SidAttrHash A pointer to the SID_AND_ATTRIBUTES_HASH structure to initialize.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSidHashInitialize(
    _In_reads_(SidCount) PSID_AND_ATTRIBUTES SidAttr,
    _In_ ULONG SidCount,
    _Out_ PSID_AND_ATTRIBUTES_HASH SidAttrHash);

/**
 * The RtlSidHashLookup routine looks up a security identifier (SID) in a previously initialized SID hash.
 *
 * \param SidAttrHash A pointer to the SID_AND_ATTRIBUTES_HASH to search.
 * \param Sid A pointer to the SID to find.
 * \return PSID_AND_ATTRIBUTES A pointer to the matching SID_AND_ATTRIBUTES entry, or `NULL` if not found.
 */
NTSYSAPI
PSID_AND_ATTRIBUTES
NTAPI
RtlSidHashLookup(
    _In_ PSID_AND_ATTRIBUTES_HASH SidAttrHash,
    _In_ PSID Sid);

/**
 * The RtlIsElevatedRid routine determines whether a SID_AND_ATTRIBUTES entry represents the elevated relative
 * identifier (RID).
 *
 * \param SidAttr A pointer to the SID_AND_ATTRIBUTES entry to test.
 * \return Returns `TRUE` if the entry represents an elevated RID, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsElevatedRid(
    _In_ PSID_AND_ATTRIBUTES SidAttr);

#if (NTDDI_VERSION >= NTDDI_WIN10)
/**
 * The RtlDeriveCapabilitySidsFromName routine derives the capability group SID and capability SID that correspond to a
 * capability name.
 *
 * \param UnicodeString A pointer to the Unicode string that specifies the capability name.
 * \param CapabilityGroupSid A pointer to a caller-allocated buffer that receives the capability group SID.
 * \param CapabilitySid A pointer to a caller-allocated buffer that receives the capability SID.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDeriveCapabilitySidsFromName(
    _Inout_ PUNICODE_STRING UnicodeString,
    _Out_ PSID CapabilityGroupSid,
    _Out_ PSID CapabilitySid);
#endif

EXTERN_C_END

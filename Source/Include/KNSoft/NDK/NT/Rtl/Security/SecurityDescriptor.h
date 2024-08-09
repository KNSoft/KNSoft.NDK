#pragma once

#include "../../MinDef.h"

EXTERN_C_START

/* ntifs.h & wdm.h */

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

_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlValidSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor);

NTSYSAPI
ULONG
NTAPI
RtlLengthSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor);

_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlValidRelativeSecurityDescriptor(
    _In_reads_bytes_(SecurityDescriptorLength) PSECURITY_DESCRIPTOR SecurityDescriptorInput,
    _In_ ULONG SecurityDescriptorLength,
    _In_ SECURITY_INFORMATION RequiredInformation);

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

NTSYSAPI
NTSTATUS
NTAPI
RtlSetDaclSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN DaclPresent,
    _In_opt_ PACL Dacl,
    _In_ BOOLEAN DaclDefaulted);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetOwnerSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Outptr_result_maybenull_ PSID *Owner,
    _When_(*Owner == NULL, _Post_invalid_)
    _When_(*Owner != NULL, _Post_valid_)
    _Pre_ _Notnull_ _Pre_ _Writable_elements_(1) PBOOLEAN OwnerDefaulted);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetOwnerSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID Owner,
    _In_ BOOLEAN OwnerDefaulted);

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

NTSYSAPI
NTSTATUS
NTAPI
RtlSetGroupSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID Group,
    _In_ BOOLEAN GroupDefaulted);

NTSYSAPI
NTSTATUS
NTAPI
RtlAbsoluteToSelfRelativeSD(
    _In_ PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    _Inout_ PULONG BufferLength);

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

NTSYSAPI
NTSTATUS
NTAPI
RtlSelfRelativeToAbsoluteSD2(
    _Inout_ PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    _Inout_ PULONG BufferSize);

NTSYSAPI
NTSTATUS
NTAPI
RtlMakeSelfRelativeSD(
    _In_ PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    _Out_writes_bytes_(*BufferLength) PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    _Inout_ PULONG BufferLength);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetControlSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PSECURITY_DESCRIPTOR_CONTROL Control,
    _Out_ PULONG Revision);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetControlSecurityDescriptor(
     _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
     _In_ SECURITY_DESCRIPTOR_CONTROL ControlBitsOfInterest,
     _In_ SECURITY_DESCRIPTOR_CONTROL ControlBitsToSet);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetAttributesSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ SECURITY_DESCRIPTOR_CONTROL Control,
    _Out_ PULONG Revision);

NTSYSAPI
BOOLEAN
NTAPI
RtlGetSecurityDescriptorRMControl(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PUCHAR RMControl);

NTSYSAPI
VOID
NTAPI
RtlSetSecurityDescriptorRMControl(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PUCHAR RMControl);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetSaclSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PBOOLEAN SaclPresent,
    _Out_ PACL *Sacl,
    _Out_ PBOOLEAN SaclDefaulted);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetSaclSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN SaclPresent,
    _In_opt_ PACL Sacl,
    _In_ BOOLEAN SaclDefaulted);

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

NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteSecurityObject(
    _Inout_ PSECURITY_DESCRIPTOR *ObjectDescriptor);

NTSYSAPI
NTSTATUS
NTAPI
RtlQuerySecurityObject(
     _In_ PSECURITY_DESCRIPTOR ObjectDescriptor,
     _In_ SECURITY_INFORMATION SecurityInformation,
     _Out_opt_ PSECURITY_DESCRIPTOR ResultantDescriptor,
     _In_ ULONG DescriptorLength,
     _Out_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetSecurityObject(
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR ModificationDescriptor,
    _Inout_ PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
    _In_ PGENERIC_MAPPING GenericMapping,
    _In_opt_ HANDLE TokenHandle);

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

NTSYSAPI
NTSTATUS
NTAPI
RtlCopySecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR InputSecurityDescriptor,
    _Out_ PSECURITY_DESCRIPTOR *OutputSecurityDescriptor);

typedef struct _RTL_ACE_DATA
{
    UCHAR AceType;
    UCHAR InheritFlags;
    UCHAR AceFlags;
    ACCESS_MASK AccessMask;
    PSID* Sid;
} RTL_ACE_DATA, *PRTL_ACE_DATA;

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

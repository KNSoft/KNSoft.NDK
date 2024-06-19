#pragma once

#include "../../NT/MinDef.h"

EXTERN_C_START

//
// BOOLEAN
// RtlEqualLuid(
//      PLUID L1,
//      PLUID L2
//      );

#define RtlEqualLuid(L1, L2) (((L1)->LowPart == (L2)->LowPart) && \
                              ((L1)->HighPart  == (L2)->HighPart))

//
// BOOLEAN
// RtlIsZeroLuid(
//      PLUID L1
//      );
//
#define RtlIsZeroLuid(L1) ((BOOLEAN) (((L1)->LowPart | (L1)->HighPart) == 0))

FORCEINLINE
LUID
NTAPI_INLINE
RtlConvertLongToLuid(_In_ LONG Long)
{
    LUID TempLuid;
    LARGE_INTEGER TempLi;

    TempLi.QuadPart = Long;
    TempLuid.LowPart = TempLi.u.LowPart;
    TempLuid.HighPart = TempLi.u.HighPart;
    return(TempLuid);
}

FORCEINLINE
LUID
NTAPI_INLINE
RtlConvertUlongToLuid(_In_ ULONG Ulong)
{
    LUID TempLuid;

    TempLuid.LowPart = Ulong;
    TempLuid.HighPart = 0;
    return(TempLuid);
}

#ifndef _KNSOFT_NDK_NT_INLINE
_Post_satisfies_(return >= 8 && return <= SECURITY_MAX_SID_SIZE)
ULONG
NTSYSAPI
NTAPI
RtlLengthSid(
    _In_ PSID Sid);
#endif

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateSecurityDescriptor(
    _Out_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG Revision);

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
RtlSetGroupSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID Group,
    _In_ BOOLEAN GroupDefaulted);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateAcl(
    _Out_writes_bytes_(AclLength) PACL Acl,
    _In_ ULONG AclLength,
    _In_ ULONG AclRevision);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessAllowedAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetDaclSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN DaclPresent,
    _In_opt_ PACL Dacl,
    _In_ BOOLEAN DaclDefaulted);

EXTERN_C_END

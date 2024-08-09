#pragma once

#include "../../MinDef.h"

EXTERN_C_START

/* ntddk.h */

_IRQL_requires_max_(APC_LEVEL)
NTSYSAPI
VOID
NTAPI
RtlMapGenericMask(
    _Inout_ PACCESS_MASK AccessMask,
    _In_ const GENERIC_MAPPING* GenericMapping);

/* phnt */

NTSYSAPI
BOOLEAN
NTAPI
RtlAreAllAccessesGranted(
    _In_ ACCESS_MASK GrantedAccess,
    _In_ ACCESS_MASK DesiredAccess);

NTSYSAPI
BOOLEAN
NTAPI
RtlAreAnyAccessesGranted(
    _In_ ACCESS_MASK GrantedAccess,
    _In_ ACCESS_MASK DesiredAccess);

EXTERN_C_END

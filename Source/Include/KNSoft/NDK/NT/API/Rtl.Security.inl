#pragma once

#include "../../NT/MinDef.h"

_Post_satisfies_(return >= 8 && return <= SECURITY_MAX_SID_SIZE)
ULONG
FORCEINLINE
NTAPI_INLINE
RtlLengthSid(
    _In_ PSID Sid)
{
    return UFIELD_OFFSET(SID, SubAuthority[Sid->SubAuthorityCount]);
}

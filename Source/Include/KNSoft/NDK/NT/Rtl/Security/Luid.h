#pragma once

#include "../../MinDef.h"

EXTERN_C_START

/* wdm.h */

#define RtlEqualLuid(L1, L2) (((L1)->LowPart == (L2)->LowPart) && ((L1)->HighPart  == (L2)->HighPart))
/**
 * The RtlIsZeroLuid routine determines whether a LUID is zero.
 *
 * \param L1 A pointer to the LUID to test.
 * \return Returns `TRUE` if the LUID is zero, otherwise `FALSE`.
 */
#define RtlIsZeroLuid(L1) ((BOOLEAN) (((L1)->LowPart | (L1)->HighPart) == 0))

/* ntddk.h */

/**
 * The RtlConvertLongToLuid routine converts a signed 32-bit value to a LUID.
 *
 * \param Long The signed 32-bit value to convert.
 * \return LUID The LUID whose low part is the specified value and whose high part is zero.
 */
FORCEINLINE
LUID
NTAPI_INLINE
RtlConvertLongToLuid(
    _In_ LONG Long)
{
    LUID TempLuid;
    LARGE_INTEGER TempLi;

    TempLi.QuadPart = Long;
    TempLuid.LowPart = TempLi.u.LowPart;
    TempLuid.HighPart = TempLi.u.HighPart;
    return(TempLuid);
}

/**
 * The RtlConvertUlongToLuid routine converts an unsigned 32-bit value to a LUID.
 *
 * \param Ulong The unsigned 32-bit value to convert.
 * \return LUID The LUID whose low part is the specified value and whose high part is zero.
 */
FORCEINLINE
LUID
NTAPI_INLINE
RtlConvertUlongToLuid(
    _In_ ULONG Ulong)
{
    LUID TempLuid;

    TempLuid.LowPart = Ulong;
    TempLuid.HighPart = 0;
    return(TempLuid);
}

/**
 * The RtlConvertLuidToLonglong routine converts a LUID to a signed 64-bit value.
 *
 * \param Luid The LUID to convert.
 * \return LONGLONG The 64-bit signed value formed from the LUID.
 */
FORCEINLINE
LONGLONG
NTAPI_INLINE
RtlConvertLuidToLonglong(
    _In_ LUID Luid)
{
    LONGLONG TempLl;

    TempLl = Luid.LowPart;
    TempLl += ((LONGLONG)(Luid.HighPart) << 32);

    return(TempLl);
}

/* ntifs.h */

/**
 * The RtlCopyLuid routine copies a locally unique identifier (LUID) from a source to a destination.
 *
 * \param DestinationLuid A pointer to a variable that receives the copied LUID.
 * \param SourceLuid A pointer to the LUID to copy.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopyluid
 */
NTSYSAPI
VOID
NTAPI
RtlCopyLuid(
    _Out_ PLUID DestinationLuid,
    _In_ PLUID SourceLuid);

/* phnt */

/**
 * The RtlCopyLuidAndAttributesArray routine copies an array of LUID_AND_ATTRIBUTES structures from a source to a
 * destination.
 *
 * \param Count The number of elements in the array.
 * \param Src A pointer to the source array of LUID_AND_ATTRIBUTES structures.
 * \param Dest A pointer to the destination array that receives the copied structures.
 */
NTSYSAPI
VOID
NTAPI
RtlCopyLuidAndAttributesArray(
    _In_ ULONG Count,
    _In_ PLUID_AND_ATTRIBUTES Src,
    _In_ PLUID_AND_ATTRIBUTES Dest);

EXTERN_C_END

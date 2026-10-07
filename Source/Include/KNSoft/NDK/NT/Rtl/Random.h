#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* 
 * By KNSoft.NDK.
 * Note: According to Microsoft Learning, return value of RtlRandom/RtlRandomEx in the range [0..MAXLONG-1].
 * But SAL in Windows SDK is [0..MAXLONG].
 */

_Ret_range_(0, MAXLONG)
NTSYSAPI
ULONG
NTAPI
RtlUniform(
    _Inout_ PULONG Seed);

/**
 * The RtlRandom routine generates a pseudo-random number from the specified seed.
 *
 * \param Seed A pointer to the seed value, which is updated on each call.
 * \return ULONG The generated pseudo-random number.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlrandom
 */
_Ret_range_(0, MAXLONG - 1)
NTSYSAPI
ULONG
NTAPI
RtlRandom(
    _Inout_ PULONG Seed);

/**
 * The RtlRandomEx routine generates a pseudo-random number from the specified seed using an improved algorithm.
 *
 * \param Seed A pointer to the seed value, which is updated on each call.
 * \return ULONG The generated pseudo-random number.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlrandomex
 */
_Ret_range_(0, MAXLONG - 1)
NTSYSAPI
ULONG
NTAPI
RtlRandomEx(
    _Inout_ PULONG Seed);

EXTERN_C_END

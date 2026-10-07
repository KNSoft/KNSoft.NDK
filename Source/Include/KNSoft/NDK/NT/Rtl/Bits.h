#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* wdm.h */

_Check_return_ unsigned short __cdecl _byteswap_ushort(_In_ unsigned short);
_Check_return_ unsigned long  __cdecl _byteswap_ulong (_In_ unsigned long);
_Check_return_ unsigned __int64 __cdecl _byteswap_uint64(_In_ unsigned __int64);

#pragma intrinsic(_byteswap_ushort)
#pragma intrinsic(_byteswap_ulong)
#pragma intrinsic(_byteswap_uint64)

#define RtlUshortByteSwap(_x)    _byteswap_ushort((USHORT)(_x))
#define RtlUlongByteSwap(_x)     _byteswap_ulong((_x))
/**
 * The RtlUlonglongByteSwap routine reverses the byte order of a 64-bit unsigned integer.
 *
 * \return ULONGLONG The byte-swapped 64-bit value.
 */
#define RtlUlonglongByteSwap(_x) _byteswap_uint64((_x))

/**
 * Atomically sets the specified bits of a ULONG and returns the previous value.
 */
#define RtlInterlockedSetBits(Flags, Flag) \
    InterlockedOr((PLONG)(Flags), Flag)

/**
 * Atomically ANDs the specified bits into a ULONG and returns the previous value.
 */
#define RtlInterlockedAndBits(Flags, Flag) \
    InterlockedAnd((PLONG)(Flags), Flag)

/**
 * Atomically clears the specified bits of a ULONG and returns the previous value.
 */
#define RtlInterlockedClearBits(Flags, Flag) \
    RtlInterlockedAndBits(Flags, ~(Flag))

/**
 * Atomically XORs the specified bits of a ULONG and returns the previous value.
 */
#define RtlInterlockedXorBits(Flags, Flag) \
    InterlockedXor(Flags, Flag)

/**
 * Atomically sets the specified bits of a ULONG, discarding the previous value.
 */
#define RtlInterlockedSetBitsDiscardReturn(Flags, Flag) \
    (VOID) RtlInterlockedSetBits(Flags, Flag)

/**
 * Atomically ANDs the specified bits into a ULONG, discarding the previous value.
 */
#define RtlInterlockedAndBitsDiscardReturn(Flags, Flag) \
    (VOID) RtlInterlockedAndBits(Flags, Flag)

/**
 * Atomically clears the specified bits of a ULONG, discarding the previous value.
 */
#define RtlInterlockedClearBitsDiscardReturn(Flags, Flag) \
    RtlInterlockedAndBitsDiscardReturn(Flags, ~(Flag))


// RtlUdiv128
/**
 * The RtlUdiv128 routine divides an unsigned 128-bit value by an unsigned 64-bit divisor.
 *
 * \param DividendHigh The high 64 bits of the 128-bit dividend.
 * \param DividendLow The low 64 bits of the 128-bit dividend.
 * \param Divisor The 64-bit divisor.
 * \param Remainder An optional pointer to a variable that receives the remainder.
 * \return ULONGLONG The 64-bit quotient of the division.
 */
NTSYSAPI
ULONGLONG
NTAPI
RtlUdiv128(
    _In_ ULONGLONG DividendHigh,
    _In_ ULONGLONG DividendLow,
    _In_ ULONGLONG Divisor,
    _Out_opt_ PLONGLONG Remainder
    );
EXTERN_C_END

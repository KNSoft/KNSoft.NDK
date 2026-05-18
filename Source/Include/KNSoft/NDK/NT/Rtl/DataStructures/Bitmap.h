#pragma once

#include "../../MinDef.h"

EXTERN_C_START

#pragma region Bitmap

//
//  BitMap routines.  The following structure, routines, and macros are
//  for manipulating bitmaps.  The user is responsible for allocating a bitmap
//  structure (which is really a header) and a buffer (which must be longword
//  aligned and multiple longwords in size).
//

typedef struct _RTL_BITMAP
{
    ULONG SizeOfBitMap; // Number of bits in bit map
    PULONG Buffer;      // Pointer to the bit map itself
} RTL_BITMAP;
typedef RTL_BITMAP *PRTL_BITMAP;

/**
 * The RtlInitializeBitMap routine initializes the header of a bitmap variable.
 *
 * \param BitMapHeader Pointer to an empty RTL_BITMAP structure.
 * \param BitMapBuffer Pointer to caller-allocated memory for the bitmap itself. The base address of this buffer must be ULONG-aligned. The size of the allocated buffer must be an integer multiple of sizeof(ULONG) bytes.
 * \param SizeOfBitMap Specifies the number of bits in the bitmap. This value can be any number of bits that will fit in the buffer allocated for the bitmap.
 * emarks RtlInitializeBitMap must be called before any other RtlXxx routine that operates on a bitmap variable. The caller is responsible for synchronizing access to the bitmap variable.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitializebitmap
 */
NTSYSAPI
VOID
NTAPI
RtlInitializeBitMap(
    _Out_ PRTL_BITMAP BitMapHeader,
    _In_opt_ __drv_aliasesMem PULONG BitMapBuffer,
    _In_opt_ ULONG SizeOfBitMap);

/**
 * The RtlClearBit routine sets the specified bit in a bitmap to zero.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param BitNumber Specifies the zero-based index of the bit within the bitmap. The routine sets this bit to zero.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearbit
 */
NTSYSAPI
VOID
NTAPI
RtlClearBit(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG BitNumber);

/**
 * The RtlSetBit routine sets the specified bit in a bitmap to one.
 *
 * \param BitMapHeader Pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param BitNumber Specifies the zero-based index of the bit within the bitmap. The routine sets this bit to one.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetbit
 */
NTSYSAPI
VOID
NTAPI
RtlSetBit(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG BitNumber);

/**
 * The RtlTestBit routine returns the value of a bit in a bitmap.
 *
 * \param BitMapHeader Pointer to the RTL_BITMAP structure that describes the bitmap.
 * \param BitNumber Specifies the zero-based index of the bit within the bitmap.
 * eturn The value of the requested bit.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltestbit
 */
_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlTestBit(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG BitNumber);

/**
 * The RtlClearAllBits routine sets all bits in a given bitmap variable to zero.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearallbits
 */

NTSYSAPI
VOID
NTAPI
RtlClearAllBits(
    _In_ PRTL_BITMAP BitMapHeader);

/**
 * The RtlSetAllBits routine sets all bits in a given bitmap variable to one.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetallbits
 */

NTSYSAPI
VOID
NTAPI
RtlSetAllBits(
    _In_ PRTL_BITMAP BitMapHeader);

/**
 * The RtlFindClearBits routine searches for a range of clear bits of a requested size within a bitmap.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param NumberToFind Specifies how many contiguous clear bits will satisfy this request.
 * \param HintIndex Specifies a zero-based bit position from which to start looking for a clear bit range of the given size.
 * \return RtlFindClearBits either returns the zero-based starting bit index for a clear bit range of at least the requested size, or it returns 0xFFFFFFFF if it cannot find such a range within the given bitmap.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindclearbits
 */

_Success_(return != -1)
_Ret_range_(<=, BitMapHeader->SizeOfBitMap - NumberToFind)
_Must_inspect_result_
NTSYSAPI
ULONG
NTAPI
RtlFindClearBits(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG NumberToFind,
    _In_ ULONG HintIndex);

/**
 * The RtlFindSetBits routine searches for a range of set bits of a requested size within a bitmap.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param NumberToFind Specifies how many contiguous set bits will satisfy this request.
 * \param HintIndex Specifies a zero-based bit position around which to start looking for a set bit range of the given size.
 * \return RtlFindSetBits either returns the zero-based starting bit index for a set bit range of the requested size, or it returns 0xFFFFFFFF if it cannot find such a range within the given bitmap variable.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindsetbits
 */

_Success_(return != -1)
_Ret_range_(<=, BitMapHeader->SizeOfBitMap - NumberToFind)
_Must_inspect_result_
NTSYSAPI
ULONG
NTAPI
RtlFindSetBits(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG NumberToFind,
    _In_ ULONG HintIndex);

/**
 * The RtlFindClearBitsAndSet routine searches for a range of clear bits of a requested size within a bitmap and sets all bits in the range when it has been located.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param NumberToFind Specifies how many contiguous clear bits will satisfy this request.
 * \param HintIndex Specifies a zero-based bit position from which to start looking for a clear bit range of the given size.
 * \return RtlFindClearBitsAndSet either returns the zero-based starting bit index for a clear bit range of the requested size that it set, or it returns 0xFFFFFFFF if it cannot find such a range within the given bitmap variable.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindclearbitsandset
 */

_Success_(return != -1)
_Ret_range_(<=, BitMapHeader->SizeOfBitMap - NumberToFind)
NTSYSAPI
ULONG
NTAPI
RtlFindClearBitsAndSet(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG NumberToFind,
    _In_ ULONG HintIndex);

/**
 * The RtlFindSetBitsAndClear routine searches for a range of set bits of a requested size within a bitmap and clears all bits in the range when it has been located.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param NumberToFind Specifies how many contiguous set bits will satisfy this request.
 * \param HintIndex Specifies a zero-based bit position around which to start looking for a set bit range of the given size.
 * \return RtlFindSetBitsAndClear either returns the zero-based starting bit index for a set bit range of the requested size that it cleared, or it returns 0xFFFFFFFF if it cannot find such a range within the given bitmap variable.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindsetbitsandclear
 */

_Success_(return != -1)
_Ret_range_(<=, BitMapHeader->SizeOfBitMap - NumberToFind)
NTSYSAPI
ULONG
NTAPI
RtlFindSetBitsAndClear(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG NumberToFind,
    _In_ ULONG HintIndex);

/**
 * The RtlClearBits routine sets all bits in the specified range of bits in the bitmap to zero.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param StartingIndex The index of the first bit in the bit range that is to be cleared. If the bitmap contains N bits, the bits are numbered from 0 to N-1.
 * \param NumberToClear Specifies how many bits to clear. If the bitmap contains N bits, this parameter can be a value in the range 1 to (N - StartingIndex).
 * \remarks If the NumberToClear parameter is zero, RtlClearBits simply returns control without clearing any bits. The sum (StartingIndex + NumberToClear) must not exceed the SizeOfBitMap parameter value specified in the RtlInitializeBitMap call that initialized the bitmap.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearbits
 */

NTSYSAPI
VOID
NTAPI
RtlClearBits(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(0, BitMapHeader->SizeOfBitMap - NumberToClear) ULONG StartingIndex,
    _In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToClear);

/**
 * The RtlSetBits routine sets all bits in a given range of a given bitmap variable.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param StartingIndex Specifies the start of the bit range to be set. This is a zero-based value indicating the position of the first bit in the range.
 * \param NumberToSet Specifies how many bits to set.
 * \remarks RtlSetBits simply returns control if the input NumberToSet is zero. StartingIndex plus NumberToSet must be less than or equal to BitMapHeader->SizeOfBitMap.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetbits
 */

NTSYSAPI
VOID
NTAPI
RtlSetBits(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(0, BitMapHeader->SizeOfBitMap - NumberToSet) ULONG StartingIndex,
    _In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToSet
);

//
//  The following routine locates a set of contiguous regions of clear
//  bits within the bitmap.  The caller specifies whether to return the
//  longest runs or just the first found lcoated.  The following structure is
//  used to denote a contiguous run of bits.  The two routines return an array
//  of this structure, one for each run located.
//

typedef struct _RTL_BITMAP_RUN
{
    ULONG StartingIndex;
    ULONG NumberOfBits;
} RTL_BITMAP_RUN, *PRTL_BITMAP_RUN;

/**
 * The RtlFindClearRuns routine finds the specified number of runs of clear bits within a given bitmap.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param RunArray Pointer to the first element in a caller-allocated array for the bit position and length of each clear run found in the given bitmap variable.
 * \param SizeOfRunArray Specifies the maximum number of clear runs to satisfy this request.
 * \param LocateLongestRuns If TRUE, specifies that the routine is to search the entire bitmap for the longest clear runs it can find. Otherwise, the routine stops searching when it has found the number of clear runs specified by SizeOfRunArray.
 * \return RtlFindClearRuns returns the number of clear runs found.
 * \remarks If LocateLongestRuns is TRUE, the clear runs indicated at RunArray are sorted from longest to shortest. A clear run can consist of a single bit.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindclearruns
 */

NTSYSAPI
ULONG
NTAPI
RtlFindClearRuns(
    _In_ PRTL_BITMAP BitMapHeader,
    _Out_writes_to_(SizeOfRunArray, return) PRTL_BITMAP_RUN RunArray,
    _In_range_(>, 0) ULONG SizeOfRunArray,
    _In_ BOOLEAN LocateLongestRuns);

/**
 * The RtlFindLongestRunClear routine searches for the largest contiguous range of clear bits within a given bitmap.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param StartingIndex Pointer to a variable in which the starting index of the longest clear run in the bitmap is returned. This is a zero-based value indicating the bit position of the first clear bit in the returned range.
 * \return RtlFindLongestRunClear returns either the number of bits in the run beginning at StartingIndex, or zero if it cannot find a run of clear bits within the bitmap.
 * \remarks A returned run can have a single clear bit.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindlongestrunclear
 */
NTSYSAPI
ULONG
NTAPI
RtlFindLongestRunClear(
    _In_ PRTL_BITMAP BitMapHeader,
    _Out_ PULONG StartingIndex);

/**
 * The RtlFindFirstRunClear routine searches for the initial contiguous range of clear bits within a given bitmap.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param StartingIndex Pointer to a variable in which the starting index of the first clear run in the bitmap is returned. This is a zero-based value indicating the bit position of the first clear bit in the returned range.
 * \return RtlFindFirstRunClear returns either the number of bits in the run beginning at StartingIndex, or zero if it cannot find a run of clear bits within the bitmap.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindfirstrunclear
 */
NTSYSAPI
ULONG
NTAPI
RtlFindFirstRunClear(
    _In_ PRTL_BITMAP BitMapHeader,
    _Out_ PULONG StartingIndex);

/**
 * The RtlCheckBit routine determines whether a particular bit in a given bitmap variable is clear or set.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param BitPosition Specifies which bit to check. This is a zero-based value indicating the position of the bit to be tested.
 * \return RtlCheckBit returns zero if the given bit is clear, or one if the given bit is set.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcheckbit
 */

#if defined(_M_AMD64)

_Must_inspect_result_
FORCEINLINE
BOOLEAN
RtlCheckBit(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG BitPosition)
{
    return BitTest64((LONG64 const *)BitMapHeader->Buffer, (LONG64)BitPosition);
}

#else

#define RtlCheckBit(BMH,BP) (((((PLONG)(BMH)->Buffer)[(BP) / 32]) >> ((BP) % 32)) & 0x1)

#endif

/**
 * The RtlNumberOfClearBits routine returns a count of the clear bits in a given bitmap variable.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \return RtlNumberOfClearBits returns the number of bits that are currently clear.
 * \remarks Callers of RtlNumberOfClearBits must be running at IRQL <= APC_LEVEL if the memory that contains the bitmap variable is pageable or the memory at BitMapHeader is pageable. Otherwise, RtlNumberOfClearBits can be called at any IRQL.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofclearbits
 */

#if (NTDDI_VERSION >= NTDDI_WIN8)

NTSYSAPI
ULONG
NTAPI
RtlNumberOfClearBitsInRange(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG StartingIndex,
    _In_ ULONG Length);

NTSYSAPI
ULONG
NTAPI
RtlNumberOfSetBitsInRange(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG StartingIndex,
    _In_ ULONG Length);

#endif

NTSYSAPI
ULONG
NTAPI
RtlNumberOfClearBits(
    _In_ PRTL_BITMAP BitMapHeader);

/**
 * The RtlNumberOfSetBits routine returns a count of the set bits in a given bitmap variable.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \return RtlNumberOfSetBits returns a count of the bits that are currently set.
 * \remarks Callers of RtlNumberOfSetBits must be running at IRQL <= APC_LEVEL if the memory that contains the bitmap variable is pageable or the memory at BitMapHeader is pageable. Otherwise, RtlNumberOfSetBits can be called at any IRQL.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofsetbits
 */

NTSYSAPI
ULONG
NTAPI
RtlNumberOfSetBits(
    _In_ PRTL_BITMAP BitMapHeader);

/**
 * The RtlAreBitsClear routine determines whether a given range of bits within a bitmap variable is clear.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param StartingIndex Specifies the start of the bit range to be examined. This is a zero-based value indicating the position of the first bit in the range.
 * \param Length Specifies how many bits to check.
 * \return RtlAreBitsClear returns TRUE if Length contiguous bits starting at StartingIndex are clear (that is, all the bits from StartingIndex to (StartingIndex + Length) -1). It returns FALSE if any bit in the given range is set, if the given range is not a proper subset of the bitmap, or if Length is zero.
 * \remarks Callers of RtlAreBitsClear must be running at IRQL <= APC_LEVEL if the memory that contains the bitmap variable is pageable or the memory at BitMapHeader is pageable. Otherwise, RtlAreBitsClear can be called at any IRQL.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlarebitsclear
 */

_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlAreBitsClear(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG StartingIndex,
    _In_ ULONG Length);

/**
 * The RtlAreBitsSet routine determines whether a given range of bits within a bitmap variable is set.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param StartingIndex Specifies the start of the bit range to be tested. This is a zero-based value indicating the position of the first bit in the range.
 * \param Length Specifies how many bits to test.
 * \return RtlAreBitsSet returns TRUE if Length consecutive bits beginning at StartingIndex are set (that is, all the bits from StartingIndex to (StartingIndex + Length)). It returns FALSE if any bit in the given range is clear, if the given range is not a proper subset of the bitmap, or if the given Length is zero.
 * \remarks Callers of RtlAreBitsSet must be running at IRQL <= APC_LEVEL if the memory that contains the bitmap variable is pageable or the memory at BitMapHeader is pageable. Otherwise, RtlAreBitsSet can be called at any IRQL.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlarebitsset
 */

_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlAreBitsSet(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG StartingIndex,
    _In_ ULONG Length);

/**
 * The RtlFindNextForwardRunClear routine searches a given bitmap variable for the next clear run of bits, starting from the specified index position.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param FromIndex Specifies a zero-based bit position at which to start looking for a clear run of bits.
 * \param StartingRunIndex Pointer to a variable in which the starting index of the clear run found in the bitmap is returned. This is a zero-based value indicating the bit position of the first clear bit in the run. Its value is meaningless if RtlFindNextForwardRunClear cannot find a run of clear bits.
 * \return RtlFindNextForwardRunClear returns either the number of bits in the run beginning at StartingRunIndex, or zero if it cannot find a run of clear bits following FromIndex in the bitmap.
 * \remarks Callers of RtlFindNextForwardRunClear must be running at IRQL <= APC_LEVEL if the memory that contains the bitmap variable is pageable or the memory at BitMapHeader is pageable. Otherwise, RtlFindNextForwardRunClear can be called at any IRQL.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindnextforwardrunclear
 */
NTSYSAPI
ULONG
NTAPI
RtlFindNextForwardRunClear(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG FromIndex,
    _Out_ PULONG StartingRunIndex);

/**
 * The RtlFindLastBackwardRunClear routine searches a given bitmap for the preceding clear run of bits, starting from the specified index position.
 *
 * \param BitMapHeader A pointer to the RTL_BITMAP structure that describes the bitmap. This structure must have been initialized by the RtlInitializeBitMap routine.
 * \param FromIndex Specifies a zero-based bit position at which to start looking for a clear run of bits.
 * \param StartingRunIndex Pointer to a variable in which the starting index of the clear run found in the bitmap is returned. This is a zero-based value indicating the bit position of the first clear bit in the run preceding the given FromIndex. Its value is meaningless if RtlFindLastBackwardRunClear cannot find a run of clear bits.
 * \return RtlFindLastBackwardRunClear returns the number of bits in the run beginning at StartingRunIndex, or zero if it cannot find a run of clear bits preceding FromIndex in the bitmap.
 * \remarks Callers of RtlFindLastBackwardRunClear must be running at IRQL <= APC_LEVEL if the memory that contains the bitmap variable is pageable or the memory at BitMapHeader is pageable. Otherwise, RtlFindLastBackwardRunClear can be called at any IRQL.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindlastbackwardrunclear
 */
NTSYSAPI
ULONG
NTAPI
RtlFindLastBackwardRunClear(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG FromIndex,
    _Out_ PULONG StartingRunIndex);

//
//  The following two procedures return to the caller a value indicating
//  the position within a ULONGLONG of the most or least significant non-zero
//  bit.  A value of zero results in a return value of -1.
//

/**
 * The RtlFindLeastSignificantBit routine returns the zero-based position of the least significant nonzero bit in its parameter.
 *
 * \param Set The 64-bit value to be searched for its least significant nonzero bit.
 * \return The zero-based bit position of the least significant nonzero bit, or -1 if every bit is zero.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindleastsignificantbit
 */

_Success_(return != -1)
_Must_inspect_result_
NTSYSAPI
CCHAR
NTAPI
RtlFindLeastSignificantBit(
    _In_ ULONGLONG Set);

/**
 * The RtlFindMostSignificantBit routine returns the zero-based position of the most significant nonzero bit in its parameter.
 *
 * \param Set The 64-bit value to be searched for its most significant nonzero bit.
 * \return The zero-based bit position of the most significant nonzero bit, or -1 if every bit is zero.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindmostsignificantbit
 */

_Success_(return != -1)
_Must_inspect_result_
NTSYSAPI
CCHAR
NTAPI
RtlFindMostSignificantBit(
    _In_ ULONGLONG Set);

//
// The following procedure finds the number of set bits within a ULONG_PTR
// value.
//

NTSYSAPI
ULONG
NTAPI
RtlNumberOfSetBitsUlongPtr(
    _In_ ULONG_PTR Target);

#if (NTDDI_VERSION >= NTDDI_WIN8)

NTSYSAPI
VOID
NTAPI
RtlCopyBitMap(
    _In_ PRTL_BITMAP Source,
    _In_ PRTL_BITMAP Destination,
    _In_range_(0, Destination->SizeOfBitMap - 1) ULONG TargetBit);

NTSYSAPI
VOID
NTAPI
RtlExtractBitMap(
    _In_ PRTL_BITMAP Source,
    _In_ PRTL_BITMAP Destination,
    _In_range_(0, Source->SizeOfBitMap - 1) ULONG TargetBit,
    _In_range_(0, Source->SizeOfBitMap) ULONG NumberOfBits);

#endif

#pragma endregion wdm.h

#pragma region Bitmap64

#if (NTDDI_VERSION >= NTDDI_WIN10)

typedef struct _RTL_BITMAP_EX
{
    ULONG64 SizeOfBitMap;
    PULONG64 Buffer;
} RTL_BITMAP_EX, *PRTL_BITMAP_EX;

NTSYSAPI
VOID
NTAPI
RtlInitializeBitMapEx(
    _Out_ PRTL_BITMAP_EX BitMapHeader,
    _In_ PULONG64 BitMapBuffer,
    _In_ ULONG64 SizeOfBitMap);

_Check_return_
NTSYSAPI
BOOLEAN
NTAPI
RtlTestBitEx(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG64 BitNumber);

NTSYSAPI
VOID
NTAPI
RtlClearAllBitsEx(
    _In_ PRTL_BITMAP_EX BitMapHeader);

NTSYSAPI
VOID
NTAPI
RtlClearBitEx(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG64 BitNumber);

NTSYSAPI
VOID
NTAPI
RtlSetBitEx(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG64 BitNumber);

NTSYSAPI
VOID
NTAPI
RtlSetBitsEx(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_ ULONGLONG StartingIndex,
    _In_ ULONGLONG NumberToSet);

NTSYSAPI
VOID
NTAPI
RtlSetAllBitsEx(
    _In_ PRTL_BITMAP_EX BitMapHeader);

NTSYSAPI
ULONG64
NTAPI
RtlFindSetBitsEx(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_ ULONG64 NumberToFind,
    _In_ ULONG64 HintIndex);

NTSYSAPI
ULONG64
NTAPI
RtlFindSetBitsAndClearEx(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_ ULONG64 NumberToFind,
    _In_ ULONG64 HintIndex);

NTSYSAPI
ULONGLONG
NTAPI
RtlNumberOfClearBitsEx(
    _In_ PRTL_BITMAP_EX BitMapHeader);

NTSYSAPI
ULONGLONG
NTAPI
RtlFindClearBitsAndSetEx(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_ ULONGLONG NumberToFind,
    _In_ ULONGLONG HintIndex);

NTSYSAPI
ULONGLONG
NTAPI
RtlFindClearBitsEx(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_ ULONGLONG NumberToFind,
    _In_ ULONGLONG HintIndex);

NTSYSAPI
VOID
NTAPI
RtlClearBitsEx(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_ ULONGLONG StartingIndex,
    _In_ ULONGLONG NumberToClear);

NTSYSAPI
ULONGLONG
NTAPI
RtlNumberOfSetBitsEx(
    _In_ PRTL_BITMAP_EX BitMapHeader);

#endif

#pragma endregion phnt

#pragma region RTL_BITMAP[64/32]

typedef struct _RTL_BITMAP64
{
    ULONG SizeOfBitMap;
    ULONG* POINTER_64 Buffer;
} RTL_BITMAP64, *PRTL_BITMAP64;

typedef struct _RTL_BITMAP32
{
    ULONG SizeOfBitMap;
    ULONG* POINTER_32 Buffer;
} RTL_BITMAP32, *PRTL_BITMAP32;

#pragma endregion KNSoft.NDK

EXTERN_C_END

﻿#pragma once

#include "../MinDef.h"

/* ntddk.h */
#define MM_LOWEST_USER_ADDRESS ((PVOID)(LONG_PTR)0x10000)

/* wdm.h */
#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12L

#define ROUND_TO_PAGES(Size)  (((ULONG_PTR)(Size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define BYTES_TO_PAGES(Size)  (((Size) >> PAGE_SHIFT) + (((Size) & (PAGE_SIZE - 1)) != 0))
#define BYTE_OFFSET(Va) ((ULONG)((LONG_PTR)(Va) & (PAGE_SIZE - 1)))
#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
#define ADDRESS_AND_SIZE_TO_SPAN_PAGES(Va,Size) ((BYTE_OFFSET (Va) + ((SIZE_T) (Size)) + (PAGE_SIZE - 1)) >> PAGE_SHIFT)

/* WDK/KNSoft.NDK */
#define MM_SHARED_USER_DATA_VA 0x7FFE0000

#define MM_ALLOCATION_GRANULARITY 0x10000

#if defined(_WIN64)
#define MM_HIGHEST_USER_ADDRESS ((PVOID)0x000007FFFFFEFFFFULL)
#else
#define MM_HIGHEST_USER_ADDRESS ((PVOID)0x7FFEFFFFUL)
#endif

#pragma region ASLR

/* 
 * ASLR initialization constants, see:
 * "Image randomization." Microsoft Windows Internals
 * ntoskrnl.exe!MiInitializeRelocations
 */

#if defined(_WIN64)

/* [0x00007FF7FFFF0000 ... 0x00007FFFFFFF0000), 32G */
#define MI_ASLR_BITMAP_SIZE 0x10000
#define MI_ASLR_LOWEST_SYSTEM_RANGE_ADDRESS ((PVOID)0x00007FF7FFFF0000ULL)
#define MI_ASLR_HIGHEST_SYSTEM_RANGE_ADDRESS ((PVOID)0x00007FFFFFFEFFFFULL)

#else

/* [0x50000000 ... 0x78000000), 640M */
#define MI_ASLR_BITMAP_SIZE 0x500
#define MI_ASLR_LOWEST_SYSTEM_RANGE_ADDRESS ((PVOID)0x50000000UL)
#define MI_ASLR_HIGHEST_SYSTEM_RANGE_ADDRESS ((PVOID)0x77FFFFFFUL)

#endif

C_ASSERT((ULONG_PTR)MI_ASLR_HIGHEST_SYSTEM_RANGE_ADDRESS - (ULONG_PTR)MI_ASLR_LOWEST_SYSTEM_RANGE_ADDRESS + 1 == (ULONG_PTR)MI_ASLR_BITMAP_SIZE * 8UL * (ULONG_PTR)MM_ALLOCATION_GRANULARITY);

#pragma endregion

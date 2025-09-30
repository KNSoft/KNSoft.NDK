/*
 * KNSoft.NDK RandGen.inl package, licensed under the MIT license.
 * Copyright (c) KNSoft.org (https://github.com/KNSoft). All rights reserved.
 *
 * Provide native implementation of random numbers generating.
 *
 * Rand_[SW/HW](16/32/64/SizeT/Buffer):
 *   SW/HW: Generate by software or hardware, if not specified, try hardware before software.
 *   16/32/64/SizeT: 16-bit, 32-bit, 64-bit, or SIZE_T random number.
 *   Buffer: Fill buffer with random numbers.
 */

#pragma once

#include "../NDK.h"

/*
 * Generate software random numbers by calling RtlRandomEx [0..MAXLONG-1], use the low 31 bits only
 */

static ULONG g_ulRandSeed = 0;

__forceinline
unsigned int
Rand_SW32(void)
{
    return ((RtlRandomEx(&g_ulRandSeed) & 0xFFFF) << 16) | (RtlRandomEx(&g_ulRandSeed) & 0xFFFF);
}

__forceinline
unsigned __int64
NTAPI
Rand_SW64(VOID)
{
    ULONGLONG p;

    p = (RtlRandomEx(&g_ulRandSeed) & 0xFFFFFFULL) << 40;
    p |= (RtlRandomEx(&g_ulRandSeed) & 0xFFFFFFULL) << 16;
    p |= RtlRandomEx(&g_ulRandSeed) & 0xFFFFULL;
    return p;
}

__forceinline
unsigned short
Rand_SW16(void)
{
    return (unsigned short)RtlRandomEx(&g_ulRandSeed);
}

/* Generate hardware random numbers by calling _rdrandxx_step. ARM is not supported yet, fallback to software */

#if (defined(_M_X64) && !defined(_M_ARM64EC)) || defined(_M_IX86)

__forceinline
LOGICAL
Rand_HW32(
    _Out_ unsigned int* Random)
{
    unsigned int i, p;

    for (i = 0; i < 1000000; i++)
    {
        if (_rdrand32_step(&p) != 0)
        {
            *Random = p;
            return TRUE;
        }
    }

    return FALSE;
}

__forceinline
LOGICAL
Rand_HW64(
    _Out_ unsigned __int64* Random)
{
    unsigned int i;
    unsigned __int64 p;

    for (i = 0; i < 1000000; i++)
    {
        if (
#if defined(_M_X64)
            _rdrand64_step(&p) != 0
#else
            _rdrand32_step((unsigned int*)&p) != 0 && _rdrand32_step((unsigned int*)Add2Ptr(&p, sizeof(unsigned int))) != 0
#endif
            )
        {
            *Random = p;
            return TRUE;
        }
    }

    return FALSE;
}

__forceinline
LOGICAL
Rand_HW16(
    _Out_ unsigned short* Random)
{
    unsigned int i;
    unsigned short p;

    for (i = 0; i < 1000000; i++)
    {
        if (_rdrand16_step(&p) != 0)
        {
            *Random = p;
            return TRUE;
        }
    }

    return FALSE;
}

#else

__forceinline
LOGICAL
Rand_HW32(
    _Out_ unsigned int* Random)
{
    *Random = Rand_SW32();
    return TRUE;
}

__forceinline
LOGICAL
Rand_HW64(
    _Out_ unsigned __int64* Random)
{
    *Random = Rand_SW64();
    return TRUE;
}

__forceinline
LOGICAL
Rand_HW16(
    _Out_ unsigned short* Random)
{
    *Random = Rand_SW16();
    return TRUE;
}

#endif

__forceinline
SIZE_T
Rand_SWSizeT(VOID)
{
    return
#if defined(_WIN64)
        Rand_SW64();
#else
        Rand_SW32();
#endif
}

__forceinline
LOGICAL
Rand_HWSizeT(
    _Out_ SIZE_T* Random)
{
    return
#if defined(_WIN64)
        Rand_HW64(Random);
#else
        Rand_HW32(Random);
#endif
}

__forceinline
unsigned __int64
Rand_64(VOID)
{
    unsigned __int64 p;
    return Rand_HW64(&p) ? p : Rand_SW64();
}

__forceinline
unsigned int
Rand_32(VOID)
{
    unsigned int p;
    return Rand_HW32(&p) ? p : Rand_SW32();
}

__forceinline
unsigned short
Rand_16(VOID)
{
    unsigned short p;
    return Rand_HW16(&p) ? p : Rand_SW16();
}

__forceinline
SIZE_T
Rand_SizeT(VOID)
{
    SIZE_T p;
    return Rand_HWSizeT(&p) ? p : Rand_SWSizeT();
}

__inline
void
Rand_SWBuffer(
    _Out_writes_bytes_(RandomBufferLength) void* RandomBuffer,
    _In_ unsigned int RandomBufferLength)
{
    unsigned char* pEnd = (unsigned char*)Add2Ptr(RandomBuffer, RandomBufferLength);
    unsigned char* p = (unsigned char*)RandomBuffer;
    unsigned char* q;
    unsigned __int64 s;

    while (p <= pEnd - sizeof(unsigned __int64))
    {
        *(unsigned __int64*)p = Rand_SW64();
        p += sizeof(unsigned __int64);
    }
    if (p != pEnd)
    {
        s = Rand_SW64();
        q = (unsigned char*)&s;
        do
        {
            *p++ = *q++;
        } while (p < pEnd);
    }
}

__inline
LOGICAL
Rand_HWBuffer(
    _Out_writes_bytes_(RandomBufferLength) void* RandomBuffer,
    _In_ unsigned int RandomBufferLength)
{
    unsigned char* pEnd = (unsigned char*)Add2Ptr(RandomBuffer, RandomBufferLength);
    unsigned char* p = (unsigned char*)RandomBuffer;
    unsigned char* q;
    SIZE_T s;

    while (p <= pEnd - sizeof(SIZE_T))
    {
        if (!Rand_HWSizeT((SIZE_T*)p))
        {
            return FALSE;
        }
        p += sizeof(SIZE_T);
    }
    if (p != pEnd)
    {
        if (!Rand_HWSizeT(&s))
        {
            return FALSE;
        }
        q = (unsigned char*)&s;
        do
        {
            *p++ = *q++;
        } while (p < pEnd);
    }

    return TRUE;
}

__inline
void
Rand_Buffer(
    _Out_writes_bytes_(RandomBufferLength) void* RandomBuffer,
    _In_ unsigned int RandomBufferLength)
{
    if (!Rand_HWBuffer(RandomBuffer, RandomBufferLength))
    {
        Rand_SWBuffer(RandomBuffer, RandomBufferLength);
    }
}

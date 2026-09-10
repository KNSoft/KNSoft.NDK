#pragma once

#include "../../NT/MinDef.h"

#ifdef __hstring_h__
#error Include KNSoft.NDK before hstring.h or WinRT headers.
#endif

#define HSTRING__ MS_HSTRING__
#define HSTRING MS_HSTRING
#define HSTRING_HEADER MS_HSTRING_HEADER
#include <hstring.h>
#undef HSTRING_HEADER
#undef HSTRING
#undef HSTRING__

EXTERN_C_START

// private (combase symbols)
_Enum_is_bitflag_
typedef enum _WINDOWS_RUNTIME_HSTRING_FLAGS
{
    WRHF_NONE = 0x0,
    WRHF_STRING_REFERENCE = 0x1,
    WRHF_VALID_UNICODE_FORMAT_INFO = 0x2,
    WRHF_WELL_FORMED_UNICODE = 0x4,
    WRHF_HAS_EMBEDDED_NULLS = 0x8,
    WRHF_EMBEDDED_NULLS_COMPUTED = 0x10,
    WRHF_RESERVED_FOR_PREALLOCATED_STRING_BUFFER = 0x80000000
} WINDOWS_RUNTIME_HSTRING_FLAGS, *PWINDOWS_RUNTIME_HSTRING_FLAGS;
DEFINE_ENUM_FLAG_OPERATORS(WINDOWS_RUNTIME_HSTRING_FLAGS);

typedef struct HSTRING_HEADER
{
    union
    {
        struct
        {
            WINDOWS_RUNTIME_HSTRING_FLAGS Flags;
            ULONG Length;
            ULONG Padding[2];
            PCWSTR Buffer;
        };
        union
        {
            PVOID Reserved1;
#if defined(_WIN64)
            CHAR Reserved2[24];
#else
            CHAR Reserved2[20];
#endif
        } Reserved;
    };
} HSTRING_HEADER, *PHSTRING_HEADER;

// private (STRING_OPAQUE). A reference occupies only the common HSTRING_HEADER prefix.
typedef struct HSTRING__
{
    HSTRING_HEADER Header;

    // Present only when (Header.Flags & WRHF_STRING_REFERENCE) == 0.
    _Interlocked_operand_ LONG volatile RefCount;
    // Present under the same condition; Header.Length + 1 WCHARs, including the terminator.
    _Field_size_(Header.Length + 1) WCHAR Data[ANYSIZE_ARRAY];
} HSTRING__, *HSTRING;

// Exact Flags value for an unpromoted HSTRING_BUFFER, not a flag combination.
#define HSTRING_BUFFER_SIGNATURE 0xF8B1A8BEUL

_STATIC_ASSERT(sizeof(HSTRING) == sizeof(MS_HSTRING));
_STATIC_ASSERT(__alignof(HSTRING) == __alignof(MS_HSTRING));

EXTERN_C_END

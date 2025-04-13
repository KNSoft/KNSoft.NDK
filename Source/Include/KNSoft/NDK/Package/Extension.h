/* KNSoft.NDK extension package, native addendum */

#pragma once

#ifdef _KNSOFT_NDK_NO_EXTENSION
#pragma message("KNSoft.NDK: Extension.h is included but _KNSOFT_NDK_NO_EXTENSION is defineded.")
#endif

#include "../NT/MinDef.h"

// Gets equality of two value after masked
#define IS_EQUAL_MASKED(val1, val2, mask) (!(((val1) ^ (val2)) & (mask)))
// Sets or removes a flag from a combination value
#define COMBINE_FLAGS(val, uflag, bEnable) ((bEnable) ? ((val) | (uflag)) : ((val) & ~(uflag)))
// Test combined flags
#define TEST_FLAGS(val, flags) (((val) & (flags)) == (flags))

#pragma region Size in bytes

#define BYTE_BIT 8UL
#define KB_TO_BYTES(x) ((x) * 1024UL)
#define MB_TO_KB(x) ((x) * 1024UL)
#define MB_TO_BYTES(x) (KB_TO_BYTES(MB_TO_KB(x)))
#define GB_TO_MB(x) ((x) * 1024UL)
#define GB_TO_BYTES(x) (MB_TO_BYTES(GB_TO_MB(x)))
#define TB_TO_GB(x) ((x) * 1024UL)
#define TB_TO_BYTES(x) (GB_TO_BYTES(TB_TO_GB(x)))

#if defined(_WIN64)
#define SIZE_OF_POINTER 8
#else
#define SIZE_OF_POINTER 4
#endif

#pragma endregion

#pragma region Limitations

#define MAX_CLASSNAME_CCH       256
#define MAX_CIDENTIFIERNAME_CCH 247
#define MAX_ATOM_CCH            255
#define MAX_REG_KEYNAME_CCH     255
#define MAX_REG_VALUENAME_CCH   16383
#define POINTER_CCH             (sizeof(PVOID) * 2 + 1)
#define HEX_RGB_CCH             8 // #RRGGBB

#pragma endregion

#pragma region Alignments

#define CODE_ALIGNMENT 0x10
#define STRING_ALIGNMENT 0x4

#pragma endregion

#pragma region String

#define _STR_CCH_LEN(quote) (ARRAYSIZE(quote) - 1)

#define ASCII_CASE_MASK 0b100000
#define UNICODE_EOL ((DWORD)0x000A000D)
#define ANSI_EOL ((WORD)0x0A0D)

#pragma endregion

#pragma region Any-size array

#define ANYSIZE_STRUCT_SIZE(structure, field, size) UFIELD_OFFSET(structure, field[size])

#define DEFINE_ANYSIZE_STRUCT(varName, baseType, arrayType, arraySize) struct {\
    baseType BaseType;\
    arrayType Array[(arraySize) - 1];\
} varName

#pragma endregion

#pragma region MSVC and WinSDK

#if _WIN64
#define IS_WIN64 TRUE
#else
#define IS_WIN64 FALSE
#endif

/* Patch C_ASSERT to avoid confusion amount static_assert, _Static_assert, _STATIC_ASSERT and C_ASSERT */

#undef C_ASSERT
#define C_ASSERT(expr) static_assert((expr), #expr)

#define __A2U8(quote) u8##quote
#define _A2U8(quote) __A2U8(quote)

#define __A2W(quote) L##quote
#define _A2W(quote) __A2W(quote)

#if _WIN64
#define MSVC_VARDNAME(x) x
#define MSVC_INCLUDE_VAR(x) __pragma(comment(linker, "/include:"#x))
#else
#define MSVC_VARDNAME(x) _##x
#define MSVC_INCLUDE_VAR(x) __pragma(comment(linker, "/include:_"#x))
#endif

/*
 * Initializer support
 * See also:
 *   https://devblogs.microsoft.com/cppblog/new-compiler-warnings-for-dynamic-initialization/
 *   https://learn.microsoft.com/en-us/cpp/c-runtime-library/crt-initialization
 * 
 * ** FIXME: Not support C++ yet **
 */

#ifndef __cplusplus

// Section 'section-name' is reserved for C++ dynamic initialization.
#pragma warning(error: 5247 5248)

typedef int(__cdecl* _PIFV)(void);

#pragma section(".CRT$XINDK", long, read)

#define MSVC_INITIALIZER(x)\
int __cdecl x(void);\
__declspec(allocate(".CRT$XINDK")) _PIFV _KNSoft_NDK_Initializer_User_##x = &x;\
MSVC_INCLUDE_VAR(_KNSoft_NDK_Initializer_User_##x)\
int __cdecl x(void)

#endif

#pragma endregion

#pragma region MSBuild

#define MSB_LIB_PATH(LibName) (MSB_PLATFORMTARGET"/"MSB_CONFIGURATION"/"##LibName)

/* Other MSB_* are defined in Directory.Build.props */

#pragma endregion

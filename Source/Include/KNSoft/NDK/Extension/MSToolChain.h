#pragma once

#ifdef _KNSOFT_NDK_NO_EXTENSION_MSTOOLCHAIN
#pragma message("KNSoft.NDK: MSToolChain.h is included but _KNSOFT_NDK_NO_EXTENSION_MSTOOLCHAIN is defined.")
#endif

#include "../NT/MinDef.h"

#pragma region Disable Microsoft extension warnings

// Nonstandard extension used: zero-sized array in struct/union
#pragma warning(disable: 4200)

#pragma endregion

#pragma region MSVC and WinSDK

EXTERN_C_START

extern IMAGE_DOS_HEADER __ImageBase;

EXTERN_C_END

#if _WIN64
#define IS_WIN64 TRUE
#else
#define IS_WIN64 FALSE
#endif

/* Patch _STATIC_ASSERT to avoid confusion amount static_assert, _Static_assert and C_ASSERT */

#undef _STATIC_ASSERT
#define _STATIC_ASSERT(expr) static_assert((expr), #expr)

#define __A2U8(quote) u8##quote
#define _A2U8(quote) __A2U8(quote)

#define __A2W(quote) L##quote
#define _A2W(quote) __A2W(quote)

#define DECLSPEC_EXPORT __declspec(dllexport)
typedef unsigned __int64 QWORD, near* PQWORD, far* LPQWORD;

// Makes a DWORD value by LOWORD and HIWORD
#define MAKEDWORD(l, h) ((DWORD)(((WORD)(((DWORD_PTR)(l)) & 0xffff)) | ((DWORD)((WORD)(((DWORD_PTR)(h)) & 0xffff))) << 16))
#define MAKEQWORD(l, h) ((QWORD)(((DWORD)(((DWORD_PTR)(l)) & 0xffffffff)) | ((QWORD)((DWORD)(((DWORD_PTR)(h)) & 0xffffffff))) << 32))

#if defined(_DEBUG) && !defined(DBG)
#define DBG 1
#endif

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
 */

// Section 'section-name' is reserved for C++ dynamic initialization.
#pragma warning(error: 5247 5248)

typedef int(__cdecl* _PIFV)(void);

#pragma section(".CRT$XINDK", long, read)

#define MSVC_INITIALIZER(x)\
int __cdecl x(void);\
__declspec(allocate(".CRT$XINDK")) _PIFV _KNSoft_NDK_Initializer_User_##x = &x;\
MSVC_INCLUDE_VAR(_KNSoft_NDK_Initializer_User_##x)\
int __cdecl x(void)

#pragma endregion

#pragma region MSBuild

#if defined(_M_IX86)
#define MSB_PLATFORMTARGET "x86"
#elif defined(_M_X64)
#define MSB_PLATFORMTARGET "x64"
#elif defined(_M_ARM64)
#define MSB_PLATFORMTARGET "ARM64"
#endif

#if defined(_DEBUG)
#define MSB_CONFIGURATION "Debug"
#else
#define MSB_CONFIGURATION "Release"
#endif

#define MSB_LIB_PATH(LibName) (MSB_PLATFORMTARGET"/"MSB_CONFIGURATION"/"##LibName)

/* MSB_CONFIGURATIONTYPE_[EXE/DLL/LIB/UTILITY] is defined in Directory.Build.props */

#pragma endregion

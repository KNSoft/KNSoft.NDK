/*
 * KNSoft.NDK.UnitTest
 *
 * Lite weight unit test framework
 *
 * Basic usage:
 *
 * // Define a test entry
 * TEST_DECL(Xxx)
 * {
 *     TEST_OK(1 == 1);
 *     TEST_SKIP("Skip reason");
 * }
 *
 * // Use UnitTest_Main to use default unit test program template
 * int wmain(
 *     _In_ int argc,
 *     _In_reads_(argc) _Pre_z_ wchar_t** argv)
 * {
 *     return UnitTest_Main(argc, argv);
 * }
 *
 */

#pragma once

#include "../NT/MinDef.h"

EXTERN_C_START

typedef struct _UNITTEST_RESULT
{
    ULONG Pass;
    ULONG Fail;
    ULONG Skip;
    ULONGLONG Elapsed; // in μs (us, microsecond)
} UNITTEST_RESULT, *PUNITTEST_RESULT;

typedef VOID NTAPI FN_UNITTEST_PROC(UNITTEST_RESULT*);

typedef struct _UNITTEST_ENTRY
{
    FN_UNITTEST_PROC* Proc;
    UNICODE_STRING Name;
} UNITTEST_ENTRY, *PUNITTEST_ENTRY;
typedef const UNITTEST_ENTRY *PCUNITTEST_ENTRY;

typedef BOOL CALLBACK FN_UNITTEST_ENUM_PROC(_In_ PCUNITTEST_ENTRY Entry, _In_opt_ PVOID Context);

BOOL NTAPI UnitTest_EnumEntries(
    _In_ __callback FN_UNITTEST_ENUM_PROC* Callback,
    _In_opt_ PVOID Context);

_Ret_maybenull_
_Must_inspect_result_
PCUNITTEST_ENTRY NTAPI UnitTest_FindEntry(
    _In_z_ PCWSTR Name);

VOID NTAPI UnitTest_RunEntry(
    _In_ PCUNITTEST_ENTRY Entry,
    _Out_ PUNITTEST_RESULT Result);

ULONG NTAPI UnitTest_RunAll(
    _Out_ PUNITTEST_RESULT Result);

_Success_(return != FALSE)
BOOL NTAPI UnitTest_Run(
    _In_z_ PCWSTR Name,
    _Out_ PUNITTEST_RESULT Result);

_Success_(return == 0)
INT NTAPI UnitTest_Main(
    _In_ int argc,
    _In_reads_(argc) _Pre_z_ wchar_t** argv);

/* Print string to stdout */
VOID NTAPI UnitTest_PrintEx(
    _In_reads_bytes_(TextSize) PCCH Text,
    _In_ ULONG TextSize);

#define UnitTest_Print(Text) UnitTest_PrintEx(Text, sizeof(Text))

/* Format string and print to stdout */
VOID __cdecl UnitTest_PrintF(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...);

/* Format string and output to both of stdout and debugger */
VOID __cdecl UnitTest_FormatMessage(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...);

#pragma section(".NDK$UTB", long, read)

#define TEST_PARAMETER_RESULT _KNSoft_NDK_UnitTest_Result

/*
 * Define a test entry (function)
 * 
 * FIXME: _KNSoft_NDK_UnitTest_Entry_Ptr_##Name may be optimized out,
 * add "_KNSoft_NDK_UnitTest_Entry_Ptr_Ptr_##Name = &_KNSoft_NDK_UnitTest_Entry_Ptr_##Name;"
 * is a hack fix but seems works.
 */
#define TEST_DECL(Name)\
VOID NTAPI Name(UNITTEST_RESULT*);\
static UNITTEST_ENTRY const _KNSoft_NDK_UnitTest_Entry_##Name = { Name, RTL_CONSTANT_STRING(L###Name) };\
static __declspec(allocate(".NDK$UTB")) PCUNITTEST_ENTRY _KNSoft_NDK_UnitTest_Entry_Ptr_##Name = &_KNSoft_NDK_UnitTest_Entry_##Name;\
static volatile PCUNITTEST_ENTRY* _KNSoft_NDK_UnitTest_Entry_Ptr_Ptr_##Name = &_KNSoft_NDK_UnitTest_Entry_Ptr_##Name;\
VOID NTAPI Name(UNITTEST_RESULT* TEST_PARAMETER_RESULT)

/* Increase count of test result, parameter can be Pass/Fail/Skip */
#define TEST_RESULT(r) (TEST_PARAMETER_RESULT->r++)

/* Pass if Expr is True, or fail and print assertion otherwise */
#define TEST_OK(Expr) (Expr ? TEST_RESULT(Pass) : (TEST_RESULT(Fail), UnitTest_FormatMessage("%hs (Line %d) Assertion failed: %hs\n", __FILE__, __LINE__, #Expr)))

/* Skip and print message */
#define TEST_SKIP(Format, ...) (TEST_RESULT(Skip), UnitTest_FormatMessage("%hs (Line %d) Skipped: " Format "\n", __FILE__, __LINE__, ##__VA_ARGS__))

/* Fail and print message */
#define TEST_FAIL(Format, ...) (TEST_RESULT(Fail), UnitTest_FormatMessage("%hs (Line %d) Failed: " Format "\n", __FILE__, __LINE__, ##__VA_ARGS__))

EXTERN_C_END

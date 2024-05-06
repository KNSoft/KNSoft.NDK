/*
 * Test for the StrSafe.h
 */

#include "Test.h"

#include <KNSoft/NDK/Extension/StrSafe.h>

#define TEST_STRING1 "KNSoft.NDK StrSafe.h Test String"
#define TEST_STRING1_PART1 "KNSoft.NDK StrSafe.h Test"

TEST_DECL(StrSafeFunc)
{
    char szTempA[_countof(TEST_STRING1)];
    wchar_t szTempW[_countof(TEST_STRING1)];

    TEST_OK(StrSafe_CchPrintfA(NULL, 0, "%hs", TEST_STRING1) == _STR_CCH_LEN(TEST_STRING1));
    TEST_OK(StrSafe_CchPrintfA(szTempA, ARRAYSIZE(szTempA), "%hs", TEST_STRING1) == _STR_CCH_LEN(TEST_STRING1));
    TEST_OK(strcmp(szTempA, TEST_STRING1) == 0);
    TEST_OK(StrSafe_CchPrintfW(NULL, 0, L"%ls", _A2W(TEST_STRING1)) == _STR_CCH_LEN(TEST_STRING1));
    TEST_OK(StrSafe_CchPrintfW(szTempW, ARRAYSIZE(szTempW), L"%ls", _A2W(TEST_STRING1)) == _STR_CCH_LEN(TEST_STRING1));
    TEST_OK(wcscmp(szTempW, _A2W(TEST_STRING1)) == 0);

    TEST_OK(StrSafe_CchPrintfA(szTempA, ARRAYSIZE(szTempA), "%hs", TEST_STRING1_PART1) == _STR_CCH_LEN(TEST_STRING1_PART1));
    TEST_OK(strcmp(szTempA, TEST_STRING1_PART1) == 0);
    TEST_OK(StrSafe_CchPrintfA(szTempA, ARRAYSIZE(szTempA), "%hs$", TEST_STRING1) == _STR_CCH_LEN(TEST_STRING1) + 1);
    TEST_OK(strcmp(szTempA, TEST_STRING1) == 0);
    TEST_OK(StrSafe_CchPrintfW(szTempW, ARRAYSIZE(szTempW), L"%ls", _A2W(TEST_STRING1_PART1)) == _STR_CCH_LEN(TEST_STRING1_PART1));
    TEST_OK(wcscmp(szTempW, _A2W(TEST_STRING1_PART1)) == 0);
    TEST_OK(StrSafe_CchPrintfW(szTempW, ARRAYSIZE(szTempW), L"%ls$", _A2W(TEST_STRING1)) == _STR_CCH_LEN(TEST_STRING1) + 1);
    TEST_OK(wcscmp(szTempW, _A2W(TEST_STRING1)) == 0);
}

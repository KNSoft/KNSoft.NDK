#define _NO_CRT_STDIO_INLINE

#include <KNSoft/NDK/NDK.h>
#include <KNSoft/NDK/UnitTest/UnitTest.h>
#include <KNSoft/NDK/WinDef/API/Ntdll.Hash.h>

#pragma comment(lib, "legacy_stdio_definitions.lib")

#pragma comment(lib, MSB_CONFIGURATION "/KNSoft.NDK.UnitTest.lib")
#pragma comment(lib, "KNSoft.NDK.Ntdll.Hash.lib")
#pragma comment(lib, "KNSoft.NDK.WinAPI.lib")

TEST_DECL(Result)
{
    TEST_PASS();
    TEST_PASS();
    TEST_PASS();
    TEST_SKIP();
    TEST_SKIP();
    TEST_FAIL();
}

int wmain()
{
    BOOL bRet;
    UNITTEST_RESULT Result;

    bRet = UnitTest_Run(L"Result", &Result);
    if (!bRet)
    {
        UnitTest_PrintF("UnitTest_Run returns FALSE!\n");
        return 1;
    }
    if (Result.Pass != 3 || Result.Skip != 2 || Result.Fail != 1)
    {
        UnitTest_PrintF("UnitTest result incorrect!\n");
        return 1;
    }

    return 0;
}

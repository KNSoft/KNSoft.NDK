/*
 * Test for the MSVC Specification
 */

#include "../UnitTest.h"

static volatile LONG g_lInit = 0;

static
MSVC_POST_INITIALIZER(Init1)
{
    InterlockedAdd(&g_lInit, 234);
    return 0;
}

static
MSVC_POST_INITIALIZER(Init2)
{
    InterlockedAdd(&g_lInit, 432);
    return 0;
}

TEST_FUNC(MSVC)
{
    TEST_OK(g_lInit == 666);
}

C_ASSERT(TRUE);

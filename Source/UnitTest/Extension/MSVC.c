/*
 * Test for the MSVC Specification
 */

#include "../UnitTest.h"

static volatile LONG g_lInit = 0;

static
MSVC_POST_CPP_USER_INITIALIZER(Init1)
{
    InterlockedAdd(&g_lInit, 234);
}

static
MSVC_POST_CPP_USER_INITIALIZER(Init2)
{
    InterlockedAdd(&g_lInit, 432);
}

TEST_FUNC(MSVC)
{
    TEST_OK(g_lInit == 666);
}

_STATIC_ASSERT(TRUE);

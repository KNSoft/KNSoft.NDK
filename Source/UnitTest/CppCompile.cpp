/*
 * Compile in C++
 */

#include "UnitTest.h"

#include <winrt/base.h>
#include <wrl/wrappers/corewrappers.h>

_STATIC_ASSERT((!std::is_same_v<HSTRING, MS_HSTRING>));
_STATIC_ASSERT((std::is_same_v<decltype(&WindowsCreateString),
                             HRESULT(STDAPICALLTYPE*)(PCNZWCH, UINT32, HSTRING*)>));

TEST_FUNC(HStringCpp)
{
    winrt::hstring WinrtString(L"a\0b", 3);
    HSTRING String = static_cast<HSTRING>(winrt::get_abi(WinrtString));
    TEST_OK(String->Header.Length == 3 && String->RefCount == 1 && String->Header.Buffer == String->Data);
    TEST_OK((String->Header.Flags & WRHF_STRING_REFERENCE) == 0);

    HSTRING Copy;
    TEST_OK(_Inline_WindowsDuplicateString(String, &Copy) == S_OK);
    TEST_OK(Copy == String && String->RefCount == 2);
    TEST_OK(_Inline_WindowsDeleteString(Copy) == S_OK);
    TEST_OK(String->RefCount == 1);

    Microsoft::WRL::Wrappers::HStringReference Reference(L"reference");
    String = Reference.Get();
    TEST_OK(String->Header.Length == 9 && (String->Header.Flags & WRHF_STRING_REFERENCE) != 0);
    TEST_OK(_Inline_WindowsDuplicateString(String, &Copy) == S_OK);
    TEST_OK(Copy != String && Copy->RefCount == 1 && (Copy->Header.Flags & WRHF_STRING_REFERENCE) == 0);
    winrt::hstring Adopted;
    winrt::attach_abi(Adopted, Copy);
    TEST_OK(Adopted == L"reference");

    Microsoft::WRL::Wrappers::HString WrlString;
    TEST_OK(WrlString.Set(L"wrl") == S_OK);
    String = WrlString.Get();
    TEST_OK(String->Header.Length == 3 && String->RefCount == 1 && String->Header.Buffer == String->Data);
    TEST_OK(_Inline_WindowsCreateString(L"inline", 6, &Copy) == S_OK);
    WrlString.Attach(Copy);
    TEST_OK(WrlString.Get() == Copy && WrlString.Get()->Header.Length == 6);
}

#include "../UnitTest.h"

#include <winrt/base.h>
#include <wrl/wrappers/corewrappers.h>

_STATIC_ASSERT((!std::is_same_v<HSTRING, MS_HSTRING>));
_STATIC_ASSERT((std::is_same_v<decltype(&WindowsCreateString),
                             HRESULT(STDAPICALLTYPE*)(PCNZWCH, UINT32, HSTRING*)>));
_STATIC_ASSERT((std::is_same_v<decltype(&_Inline_WindowsCreateString),
                             decltype(&WindowsCreateString)>));
_STATIC_ASSERT((std::is_same_v<decltype(&_Inline_WindowsCreateStringReference),
                             decltype(&WindowsCreateStringReference)>));
_STATIC_ASSERT((std::is_same_v<decltype(&_Inline_WindowsDeleteString),
                             decltype(&WindowsDeleteString)>));
_STATIC_ASSERT((std::is_same_v<decltype(&_Inline_WindowsDuplicateString),
                             decltype(&WindowsDuplicateString)>));
_STATIC_ASSERT((std::is_same_v<decltype(&_Inline_WindowsGetStringLen),
                             decltype(&WindowsGetStringLen)>));
_STATIC_ASSERT((std::is_same_v<decltype(&_Inline_WindowsGetStringRawBuffer),
                             decltype(&WindowsGetStringRawBuffer)>));
_STATIC_ASSERT((std::is_same_v<decltype(&_Inline_WindowsIsStringEmpty),
                             decltype(&WindowsIsStringEmpty)>));
_STATIC_ASSERT((std::is_same_v<decltype(&_Inline_WindowsStringHasEmbeddedNull),
                             decltype(&WindowsStringHasEmbeddedNull)>));
_STATIC_ASSERT((std::is_same_v<decltype(&_Inline_WindowsCompareStringOrdinal),
                             decltype(&WindowsCompareStringOrdinal)>));
_STATIC_ASSERT((std::is_same_v<decltype(&_Inline_WindowsSubstring),
                             decltype(&WindowsSubstring)>));
_STATIC_ASSERT((std::is_same_v<decltype(&_Inline_WindowsSubstringWithSpecifiedLength),
                             decltype(&WindowsSubstringWithSpecifiedLength)>));
_STATIC_ASSERT((std::is_same_v<decltype(&_Inline_WindowsPreallocateStringBuffer),
                             decltype(&WindowsPreallocateStringBuffer)>));
_STATIC_ASSERT((std::is_same_v<decltype(&_Inline_WindowsPromoteStringBuffer),
                             decltype(&WindowsPromoteStringBuffer)>));
_STATIC_ASSERT((std::is_same_v<decltype(&_Inline_WindowsDeleteStringBuffer),
                             decltype(&WindowsDeleteStringBuffer)>));

EXTERN_C
BOOL
HStringCppTestWinrt(VOID)
{
    winrt::hstring WinrtString(L"a\0b", 3);
    HSTRING String = static_cast<HSTRING>(winrt::get_abi(WinrtString));
    if (String == NULL || String->Header.Length != 3 || String->RefCount != 1 ||
        String->Header.Buffer != String->Data || (String->Header.Flags & WRHF_STRING_REFERENCE) != 0)
    {
        return FALSE;
    }

    HSTRING Copy;
    if (_Inline_WindowsDuplicateString(String, &Copy) != S_OK)
    {
        return FALSE;
    }
    BOOL Result = Copy == String && String->RefCount == 2;
    if (_Inline_WindowsDeleteString(Copy) != S_OK)
    {
        return FALSE;
    }
    return Result && String->RefCount == 1;
}

EXTERN_C
BOOL
HStringCppTestReference(VOID)
{
    Microsoft::WRL::Wrappers::HStringReference Reference(L"reference");
    HSTRING String = Reference.Get();
    if (String == NULL || String->Header.Length != 9 || (String->Header.Flags & WRHF_STRING_REFERENCE) == 0)
    {
        return FALSE;
    }

    HSTRING Copy;
    if (_Inline_WindowsDuplicateString(String, &Copy) != S_OK)
    {
        return FALSE;
    }
    winrt::hstring Adopted;
    winrt::attach_abi(Adopted, Copy);
    return Copy != NULL && Copy != String && Copy->RefCount == 1 &&
           (Copy->Header.Flags & WRHF_STRING_REFERENCE) == 0 && Adopted == L"reference";
}

EXTERN_C
BOOL
HStringCppTestWrl(VOID)
{
    Microsoft::WRL::Wrappers::HString WrlString;
    if (WrlString.Set(L"wrl") != S_OK)
    {
        return FALSE;
    }
    HSTRING String = WrlString.Get();
    if (String == NULL || String->Header.Length != 3 || String->RefCount != 1 ||
        String->Header.Buffer != String->Data)
    {
        return FALSE;
    }

    HSTRING Copy;
    if (_Inline_WindowsCreateString(L"inline", 6, &Copy) != S_OK)
    {
        return FALSE;
    }
    WrlString.Attach(Copy);
    return Copy != NULL && WrlString.Get() == Copy && Copy->Header.Length == 6;
}

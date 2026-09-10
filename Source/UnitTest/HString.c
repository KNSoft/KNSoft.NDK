#include "UnitTest.h"

#include <winstring.h>

#pragma comment(lib, "runtimeobject.lib")

static
VOID
CheckString(
    PUNITTEST_RESULT TEST_PARAMETER_RESULT,
    _In_opt_ HSTRING String,
    _In_reads_opt_(Length) PCWSTR Text,
    _In_ ULONG Length)
{
    UINT32 SystemLength = MAXUINT32;
    ULONG InlineLength = MAXULONG;
    PCWSTR SystemBuffer = WindowsGetStringRawBuffer(String, &SystemLength);
    PCWSTR InlineBuffer = _Inline_WindowsGetStringRawBuffer(String, &InlineLength);

    TEST_OK(SystemLength == Length && InlineLength == Length);
    TEST_OK(WindowsGetStringLen(String) == Length);
    TEST_OK(_Inline_WindowsGetStringLen(String) == Length);
    TEST_OK(WindowsIsStringEmpty(String) == (Length == 0));
    TEST_OK(_Inline_WindowsIsStringEmpty(String) == (Length == 0));
    TEST_OK(SystemBuffer != NULL && InlineBuffer != NULL);
    TEST_OK(SystemBuffer[Length] == UNICODE_NULL && InlineBuffer[Length] == UNICODE_NULL);
    TEST_OK(WindowsGetStringRawBuffer(String, NULL) == SystemBuffer);
    TEST_OK(_Inline_WindowsGetStringRawBuffer(String, NULL) == InlineBuffer);
    if (Length != 0)
    {
        TEST_OK(SystemBuffer == InlineBuffer);
        TEST_OK(RtlEqualMemory(SystemBuffer, Text, (SIZE_T)Length * sizeof(WCHAR)));
    }
}

static
VOID
CheckPair(
    PUNITTEST_RESULT TEST_PARAMETER_RESULT,
    _In_opt_ HSTRING SystemString,
    _In_opt_ HSTRING InlineString)
{
    UINT32 Length;
    PCWSTR Buffer = WindowsGetStringRawBuffer(SystemString, &Length);

    TEST_OK((SystemString == NULL) == (InlineString == NULL));
    CheckString(TEST_PARAMETER_RESULT, InlineString, Buffer, Length);
}

static
VOID
TestValues(
    PUNITTEST_RESULT TEST_PARAMETER_RESULT)
{
    static const struct
    {
        PCWSTR Text;
        ULONG Length;
    } Cases[] = {
        { NULL, 0 },
        { L"", 0 },
        { L"a", 1 },
        { L"\0", 1 },
        { L"\0a", 2 },
        { L"a\0b", 3 },
        { L"ab\0", 3 },
        { L"\x4E2D\x6587\xD83D\xDE00", 4 },
        { L"\xD800x\xDC00", 3 }
    };
    struct
    {
        HSTRING_HEADER Header;
        BYTE Guard[16];
    } Headers[2];
    HSTRING Strings[2];
    HSTRING Copies[2];
    HRESULT Hr[2];
    BOOL Embedded[2];
    ULONG Index;
    ULONG Reference;
    ULONG Origin;
    ULONG Copy;

    for (Index = 0; Index < ARRAYSIZE(Cases); Index++)
    {
        for (Reference = 0; Reference < 2; Reference++)
        {
            RtlFillMemory(Headers, sizeof(Headers), 0xA5);
            if (Reference)
            {
                Hr[0] = WindowsCreateStringReference(Cases[Index].Text, Cases[Index].Length,
                                                     &Headers[0].Header, &Strings[0]);
                Hr[1] = _Inline_WindowsCreateStringReference(Cases[Index].Text, Cases[Index].Length,
                                                             &Headers[1].Header, &Strings[1]);
                // Padding is unspecified; the x86 system implementation copies uninitialized padding.
                if (Cases[Index].Length == 0)
                {
                    TEST_OK(RtlEqualMemory(&Headers[0], &Headers[1], sizeof(Headers[0])));
                }
                for (Origin = 0; Origin < sizeof(Headers[0].Guard); Origin++)
                {
                    TEST_OK(Headers[0].Guard[Origin] == 0xA5 && Headers[1].Guard[Origin] == 0xA5);
                }
            } else
            {
                Hr[0] = WindowsCreateString(Cases[Index].Text, Cases[Index].Length, &Strings[0]);
                Hr[1] = _Inline_WindowsCreateString(Cases[Index].Text, Cases[Index].Length, &Strings[1]);
            }
            TEST_OK(Hr[0] == S_OK && Hr[1] == Hr[0]);
            if (FAILED(Hr[0]) || FAILED(Hr[1]))
            {
                WindowsDeleteString(Strings[0]);
                _Inline_WindowsDeleteString(Strings[1]);
                continue;
            }
            for (Origin = 0; Origin < 2; Origin++)
            {
                CheckString(TEST_PARAMETER_RESULT, Strings[Origin], Cases[Index].Text, Cases[Index].Length);
                if (Strings[Origin] != NULL)
                {
                    PHSTRING_HEADER p = (PHSTRING_HEADER)Strings[Origin];
                    TEST_OK(p->Flags == (Reference ? WRHF_STRING_REFERENCE : WRHF_NONE));
                    TEST_OK(p->Length == Cases[Index].Length);
                    if (Reference)
                    {
                        TEST_OK(Strings[Origin] == (HSTRING)&Headers[Origin].Header);
                        TEST_OK(p->Buffer == Cases[Index].Text);
                    } else
                    {
                        TEST_OK(p->Buffer == ((HSTRING)p)->Data);
                        TEST_OK(((HSTRING)p)->RefCount == 1);
                    }
                }
            }
            for (Copy = 0; Copy < 2; Copy++)
            {
                Hr[0] = WindowsStringHasEmbeddedNull(Strings[0], &Embedded[0]);
                Hr[1] = _Inline_WindowsStringHasEmbeddedNull(Strings[1], &Embedded[1]);
                TEST_OK(Hr[0] == S_OK && Hr[1] == Hr[0] && Embedded[0] == Embedded[1]);
                if (Strings[0] != NULL && Strings[1] != NULL)
                {
                    TEST_OK(((PHSTRING_HEADER)Strings[0])->Flags ==
                            ((PHSTRING_HEADER)Strings[1])->Flags);
                }
            }
            for (Origin = 0; Origin < 2; Origin++)
            {
                Hr[0] = WindowsDuplicateString(Strings[Origin], &Copies[0]);
                Hr[1] = _Inline_WindowsDuplicateString(Strings[Origin], &Copies[1]);
                TEST_OK(Hr[0] == S_OK && Hr[1] == Hr[0]);
                for (Copy = 0; Copy < 2; Copy++)
                {
                    CheckString(TEST_PARAMETER_RESULT, Copies[Copy], Cases[Index].Text, Cases[Index].Length);
                    TEST_OK(Reference && Strings[Origin] != NULL ? Copies[Copy] != Strings[Origin] :
                                                                 Copies[Copy] == Strings[Origin]);
                }
                if (!Reference && Strings[Origin] != NULL)
                {
                    TEST_OK(((HSTRING)Strings[Origin])->RefCount == 3);
                }
                TEST_OK(_Inline_WindowsDeleteString(Copies[0]) == S_OK);
                TEST_OK(WindowsDeleteString(Copies[1]) == S_OK);
                if (!Reference && Strings[Origin] != NULL)
                {
                    TEST_OK(((HSTRING)Strings[Origin])->RefCount == 1);
                }
            }
            TEST_OK(_Inline_WindowsDeleteString(Strings[0]) == S_OK);
            TEST_OK(WindowsDeleteString(Strings[1]) == S_OK);
        }
    }
}

static
VOID
TestBuffers(
    PUNITTEST_RESULT TEST_PARAMETER_RESULT)
{
    static const ULONG Lengths[] = { 0, 1, 3, 257 };
    WCHAR Text[258];
    PWSTR Buffers[2];
    HSTRING_BUFFER Handles[2];
    HSTRING Strings[2];
    HRESULT Hr[2];
    ULONG Index;
    ULONG Mode;
    ULONG Origin;
    ULONG Length;
    ULONG Character;

    for (Index = 0; Index < ARRAYSIZE(Lengths); Index++)
    {
        Length = Lengths[Index];
        for (Character = 0; Character < Length; Character++)
        {
            Text[Character] = Character % 3 == 0 ? UNICODE_NULL : (WCHAR)(L'a' + Character % 26);
        }
        Text[Length] = UNICODE_NULL;
        for (Mode = 0; Mode < 3; Mode++)
        {
            Hr[0] = WindowsPreallocateStringBuffer(Length, &Buffers[0], &Handles[0]);
            Hr[1] = _Inline_WindowsPreallocateStringBuffer(Length, &Buffers[1], &Handles[1]);
            TEST_OK(Hr[0] == S_OK && Hr[1] == Hr[0]);
            if (FAILED(Hr[0]) || FAILED(Hr[1]))
            {
                WindowsDeleteStringBuffer(Handles[0]);
                _Inline_WindowsDeleteStringBuffer(Handles[1]);
                continue;
            }
            for (Origin = 0; Origin < 2; Origin++)
            {
                HSTRING p = (HSTRING)Handles[Origin];
                TEST_OK(p != NULL && Buffers[Origin] != NULL);
                TEST_OK((ULONG)p->Header.Flags == HSTRING_BUFFER_SIGNATURE);
                TEST_OK(p->Header.Length == Length && p->RefCount == 1);
                TEST_OK(p->Header.Buffer == Buffers[Origin] && p->Data == Buffers[Origin]);
                TEST_OK(Buffers[Origin][Length] == UNICODE_NULL);
                RtlCopyMemory(Buffers[Origin], Text, (SIZE_T)Length * sizeof(WCHAR));
            }
            if (Mode == 2)
            {
                TEST_OK(_Inline_WindowsDeleteStringBuffer(Handles[0]) == S_OK);
                TEST_OK(WindowsDeleteStringBuffer(Handles[1]) == S_OK);
                continue;
            }
            Buffers[0][Length] = Buffers[1][Length] = L'!';
            Strings[0] = Strings[1] = (HSTRING)(ULONG_PTR)1;
            Hr[0] = WindowsPromoteStringBuffer(Handles[0], &Strings[0]);
            Hr[1] = _Inline_WindowsPromoteStringBuffer(Handles[1], &Strings[1]);
            TEST_OK(Hr[0] == E_INVALIDARG && Hr[1] == Hr[0]);
            TEST_OK(Strings[0] == NULL && Strings[1] == NULL);
            Buffers[0][Length] = Buffers[1][Length] = UNICODE_NULL;
            for (Origin = 0; Origin < 2; Origin++)
            {
                Hr[Origin] = Origin == Mode ? WindowsPromoteStringBuffer(Handles[Origin], &Strings[Origin]) :
                                             _Inline_WindowsPromoteStringBuffer(Handles[Origin], &Strings[Origin]);
                TEST_OK(Hr[Origin] == S_OK);
                CheckString(TEST_PARAMETER_RESULT, Strings[Origin], Text, Length);
                if (Length != 0)
                {
                    TEST_OK(Strings[Origin] == (HSTRING)Handles[Origin]);
                    TEST_OK(((PHSTRING_HEADER)Strings[Origin])->Flags == WRHF_NONE);
                } else
                {
                    TEST_OK(Strings[Origin] == NULL);
                }
            }
            TEST_OK(_Inline_WindowsDeleteString(Strings[0]) == S_OK);
            TEST_OK(WindowsDeleteString(Strings[1]) == S_OK);
        }
    }
}

static
VOID
TestErrors(
    PUNITTEST_RESULT TEST_PARAMETER_RESULT)
{
    static const ULONG OverflowLengths[] = {
        MAXULONG, MAXULONG / 2, (MAXULONG - sizeof(HSTRING__)) / sizeof(WCHAR) + 1
    };
    HSTRING Strings[2];
    HSTRING_HEADER Headers[2];
    PWSTR Buffers[2];
    HSTRING_BUFFER Handles[2];
    HRESULT Hr[2];
    WCHAR Unterminated[] = { L'a', L'b', L'c' };
    ULONG Index;

    TEST_OK(WindowsCreateString(NULL, 0, NULL) == _Inline_WindowsCreateString(NULL, 0, NULL));
    TEST_OK(WindowsDuplicateString(NULL, NULL) == _Inline_WindowsDuplicateString(NULL, NULL));
    TEST_OK(WindowsStringHasEmbeddedNull(NULL, NULL) == _Inline_WindowsStringHasEmbeddedNull(NULL, NULL));
    TEST_OK(WindowsCompareStringOrdinal(NULL, NULL, NULL) ==
            _Inline_WindowsCompareStringOrdinal(NULL, NULL, NULL));
    TEST_OK(WindowsPromoteStringBuffer(NULL, NULL) == _Inline_WindowsPromoteStringBuffer(NULL, NULL));
    TEST_OK(WindowsDeleteString(NULL) == _Inline_WindowsDeleteString(NULL));
    TEST_OK(WindowsDeleteStringBuffer(NULL) == _Inline_WindowsDeleteStringBuffer(NULL));

    Strings[0] = Strings[1] = (HSTRING)(ULONG_PTR)1;
    TEST_OK(WindowsCreateString(NULL, 1, &Strings[0]) == _Inline_WindowsCreateString(NULL, 1, &Strings[1]));
    TEST_OK(Strings[0] == NULL && Strings[1] == NULL);
    TEST_OK(WindowsCreateString(Unterminated, 2, &Strings[0]) ==
            _Inline_WindowsCreateString(Unterminated, 2, &Strings[1]));
    CheckPair(TEST_PARAMETER_RESULT, Strings[0], Strings[1]);
    WindowsDeleteString(Strings[0]);
    _Inline_WindowsDeleteString(Strings[1]);

    for (Index = 0; Index < 5; Index++)
    {
        PCWSTR Text = Index == 0 ? NULL : Unterminated;
        ULONG Length = Index == 0 ? 1 : (Index == 1 ? MAXULONG : (Index == 2 ? 2 : 0));
        Strings[0] = Strings[1] = (HSTRING)(ULONG_PTR)1;
        RtlFillMemory(Headers, sizeof(Headers), 0xA5);
        Hr[0] = WindowsCreateStringReference(Text, Length, Index == 4 ? NULL : &Headers[0], &Strings[0]);
        Hr[1] = _Inline_WindowsCreateStringReference(Text, Length, Index == 4 ? NULL : &Headers[1], &Strings[1]);
        TEST_OK(FAILED(Hr[0]) && Hr[0] == Hr[1]);
        TEST_OK(Strings[0] == Strings[1]);
        TEST_OK(RtlEqualMemory(&Headers[0], &Headers[1], sizeof(Headers[0])));
    }
    TEST_OK(WindowsCreateStringReference(NULL, 0, &Headers[0], NULL) ==
            _Inline_WindowsCreateStringReference(NULL, 0, &Headers[1], NULL));

    Buffers[0] = Buffers[1] = (PWSTR)(ULONG_PTR)1;
    Handles[0] = Handles[1] = (HSTRING_BUFFER)(ULONG_PTR)1;
    TEST_OK(WindowsPreallocateStringBuffer(0, &Buffers[0], NULL) ==
            _Inline_WindowsPreallocateStringBuffer(0, &Buffers[1], NULL));
    TEST_OK(Buffers[0] == Buffers[1] && Buffers[0] == (PWSTR)(ULONG_PTR)1);
    TEST_OK(WindowsPreallocateStringBuffer(0, NULL, &Handles[0]) ==
            _Inline_WindowsPreallocateStringBuffer(0, NULL, &Handles[1]));
    TEST_OK(Handles[0] == Handles[1] && Handles[0] == (HSTRING_BUFFER)(ULONG_PTR)1);
    for (Index = 0; Index < ARRAYSIZE(OverflowLengths); Index++)
    {
        Strings[0] = Strings[1] = (HSTRING)(ULONG_PTR)1;
        Hr[0] = WindowsCreateString(L"", OverflowLengths[Index], &Strings[0]);
        Hr[1] = _Inline_WindowsCreateString(L"", OverflowLengths[Index], &Strings[1]);
        TEST_OK(Hr[0] == MEM_E_INVALID_SIZE && Hr[1] == Hr[0]);
        TEST_OK(Strings[0] == NULL && Strings[1] == NULL);
        Buffers[0] = Buffers[1] = (PWSTR)(ULONG_PTR)1;
        Handles[0] = Handles[1] = (HSTRING_BUFFER)(ULONG_PTR)1;
        Hr[0] = WindowsPreallocateStringBuffer(OverflowLengths[Index], &Buffers[0], &Handles[0]);
        Hr[1] = _Inline_WindowsPreallocateStringBuffer(OverflowLengths[Index], &Buffers[1], &Handles[1]);
        TEST_OK(Hr[0] == MEM_E_INVALID_SIZE && Hr[1] == Hr[0]);
        TEST_OK(Buffers[0] == NULL && Buffers[1] == NULL && Handles[0] == NULL && Handles[1] == NULL);
    }
    Strings[0] = Strings[1] = (HSTRING)(ULONG_PTR)1;
    TEST_OK(WindowsPromoteStringBuffer(NULL, &Strings[0]) ==
            _Inline_WindowsPromoteStringBuffer(NULL, &Strings[1]));
    TEST_OK(Strings[0] == NULL && Strings[1] == NULL);
}

static
VOID
TestSubstringAndCompare(
    PUNITTEST_RESULT TEST_PARAMETER_RESULT)
{
    static const PCWSTR Text[] = { L"", L"a", L"A", L"a\0b", L"a\0c", L"\xD800\xDC00", L"\xE000" };
    static const ULONG Lengths[] = { 0, 1, 1, 3, 3, 2, 1 };
    HSTRING Strings[ARRAYSIZE(Text)];
    HSTRING Substrings[2];
    HRESULT Hr[2];
    INT32 Comparison[2];
    ULONG Index;
    ULONG Other;
    ULONG Start;
    ULONG Length;

    for (Index = 0; Index < ARRAYSIZE(Text); Index++)
    {
        Hr[0] = WindowsCreateString(Text[Index], Lengths[Index], &Strings[Index]);
        TEST_OK(Hr[0] == S_OK);
    }
    for (Index = 0; Index < ARRAYSIZE(Text); Index++)
    {
        for (Other = 0; Other < ARRAYSIZE(Text); Other++)
        {
            Hr[0] = WindowsCompareStringOrdinal(Strings[Index], Strings[Other], &Comparison[0]);
            Hr[1] = _Inline_WindowsCompareStringOrdinal(Strings[Index], Strings[Other], &Comparison[1]);
            TEST_OK(Hr[0] == S_OK && Hr[1] == Hr[0] && Comparison[0] == Comparison[1]);
        }
        TEST_OK(WindowsSubstring(Strings[Index], 0, NULL) == _Inline_WindowsSubstring(Strings[Index], 0, NULL));
        TEST_OK(WindowsSubstringWithSpecifiedLength(Strings[Index], 0, 0, NULL) ==
                _Inline_WindowsSubstringWithSpecifiedLength(Strings[Index], 0, 0, NULL));
        for (Start = 0; Start <= Lengths[Index] + 1; Start++)
        {
            Substrings[0] = Substrings[1] = (HSTRING)(ULONG_PTR)1;
            Hr[0] = WindowsSubstring(Strings[Index], Start, &Substrings[0]);
            Hr[1] = _Inline_WindowsSubstring(Strings[Index], Start, &Substrings[1]);
            TEST_OK(Hr[0] == Hr[1]);
            CheckPair(TEST_PARAMETER_RESULT, Substrings[0], Substrings[1]);
            WindowsDeleteString(Substrings[0]);
            _Inline_WindowsDeleteString(Substrings[1]);
            for (Length = 0; Length <= Lengths[Index] + 2; Length++)
            {
                ULONG Count = Length == Lengths[Index] + 2 ? MAXULONG : Length;
                Substrings[0] = Substrings[1] = (HSTRING)(ULONG_PTR)1;
                Hr[0] = WindowsSubstringWithSpecifiedLength(Strings[Index], Start, Count, &Substrings[0]);
                Hr[1] = _Inline_WindowsSubstringWithSpecifiedLength(Strings[Index], Start, Count, &Substrings[1]);
                TEST_OK(Hr[0] == Hr[1]);
                CheckPair(TEST_PARAMETER_RESULT, Substrings[0], Substrings[1]);
                WindowsDeleteString(Substrings[0]);
                _Inline_WindowsDeleteString(Substrings[1]);
            }
        }
    }
    for (Index = 0; Index < ARRAYSIZE(Text); Index++)
    {
        WindowsDeleteString(Strings[Index]);
    }
}

static
VOID
TestLifetimeAndBounds(
    PUNITTEST_RESULT TEST_PARAMETER_RESULT)
{
    WCHAR Text[] = L"a\0b";
    HSTRING_HEADER Header;
    HSTRING String;
    HSTRING Copies[2];
    HRESULT Hr;
    ULONG Mode;
    PVOID Pages;
    PWSTR Boundary;

    for (Mode = 0; Mode < 4; Mode++)
    {
        Text[0] = L'a';
        if (Mode < 2)
        {
            Hr = Mode == 0 ? WindowsCreateString(Text, 3, &String) : _Inline_WindowsCreateString(Text, 3, &String);
        } else
        {
            Hr = Mode == 2 ? WindowsCreateStringReference(Text, 3, &Header, &String) :
                             _Inline_WindowsCreateStringReference(Text, 3, &Header, &String);
        }
        TEST_OK(Hr == S_OK);
        if (FAILED(Hr))
        {
            continue;
        }
        TEST_OK(WindowsDuplicateString(String, &Copies[0]) == S_OK);
        TEST_OK(_Inline_WindowsDuplicateString(String, &Copies[1]) == S_OK);
        TEST_OK(_Inline_WindowsDeleteString(String) == S_OK);
        Text[0] = L'z';
        CheckString(TEST_PARAMETER_RESULT, Copies[0], L"a\0b", 3);
        CheckString(TEST_PARAMETER_RESULT, Copies[1], L"a\0b", 3);
        TEST_OK(WindowsDeleteString(Copies[0]) == S_OK);
        CheckString(TEST_PARAMETER_RESULT, Copies[1], L"a\0b", 3);
        TEST_OK(_Inline_WindowsDeleteString(Copies[1]) == S_OK);
    }

    // The source ends exactly at an inaccessible page: CreateString must not read a terminator.
    Pages = VirtualAlloc(NULL, PAGE_SIZE * 2, MEM_RESERVE, PAGE_NOACCESS);
    TEST_OK(Pages != NULL);
    if (Pages == NULL)
    {
        return;
    }
    if (VirtualAlloc(Pages, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE) != NULL)
    {
        Boundary = (PWSTR)((PBYTE)Pages + PAGE_SIZE) - 1;
        *Boundary = L'x';
        TEST_OK(WindowsCreateString(Boundary, 1, &Copies[0]) == S_OK);
        TEST_OK(_Inline_WindowsCreateString(Boundary, 1, &Copies[1]) == S_OK);
        CheckPair(TEST_PARAMETER_RESULT, Copies[0], Copies[1]);
        TEST_OK(_Inline_WindowsDeleteString(Copies[0]) == S_OK);
        TEST_OK(WindowsDeleteString(Copies[1]) == S_OK);

        // A fast-pass handle has no accessible reference count after its header.
        HSTRING_HEADER* BoundaryHeader = (HSTRING_HEADER*)((PBYTE)Pages + PAGE_SIZE) - 1;
        TEST_OK(_Inline_WindowsCreateStringReference(L"x", 1, BoundaryHeader, &String) == S_OK);
        CheckString(TEST_PARAMETER_RESULT, String, L"x", 1);
        TEST_OK(WindowsDuplicateString(String, &Copies[0]) == S_OK);
        TEST_OK(_Inline_WindowsDuplicateString(String, &Copies[1]) == S_OK);
        TEST_OK(WindowsDeleteString(String) == S_OK);
        TEST_OK(_Inline_WindowsDeleteString(String) == S_OK);
        TEST_OK(_Inline_WindowsDeleteString(Copies[0]) == S_OK);
        TEST_OK(WindowsDeleteString(Copies[1]) == S_OK);
    } else
    {
        TEST_FAIL("Cannot commit the HSTRING boundary test page\n");
    }
    TEST_OK(VirtualFree(Pages, 0, MEM_RELEASE));
}

static
VOID
TestInvalidBuffer(
    PUNITTEST_RESULT TEST_PARAMETER_RESULT)
{
    HSTRING_HEADER Header;
    HSTRING String;
    HSTRING Output;
    HRESULT Hr[2];
    volatile DWORD Codes[2] = { 0, 0 };
    volatile DWORD Flags[2] = { 0, 0 };
    ULONG Index;

    TEST_OK(WindowsCreateStringReference(L"a", 1, &Header, &String) == S_OK);
    for (Index = 0; Index < 2; Index++)
    {
        Output = (HSTRING)(ULONG_PTR)1;
        Hr[Index] = Index == 0 ? WindowsPromoteStringBuffer((HSTRING_BUFFER)String, &Output) :
                                _Inline_WindowsPromoteStringBuffer((HSTRING_BUFFER)String, &Output);
        TEST_OK(Output == NULL);
        __try
        {
            if (Index == 0)
            {
                WindowsDeleteStringBuffer((HSTRING_BUFFER)String);
            } else
            {
                _Inline_WindowsDeleteStringBuffer((HSTRING_BUFFER)String);
            }
        }
        __except ((Flags[Index] = GetExceptionInformation()->ExceptionRecord->ExceptionFlags),
                  (Codes[Index] = GetExceptionCode()) == STATUS_INVALID_PARAMETER ?
                  EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
        {
            NOTHING;
        }
    }
    TEST_OK(Hr[0] == E_INVALIDARG && Hr[1] == Hr[0]);
    TEST_OK(Codes[0] == STATUS_INVALID_PARAMETER && Codes[1] == Codes[0]);
    TEST_OK((Flags[0] & EXCEPTION_NONCONTINUABLE) != 0 && Flags[1] == Flags[0]);
}

TEST_FUNC(HString)
{
    TestValues(TEST_PARAMETER_RESULT);
    TestBuffers(TEST_PARAMETER_RESULT);
    TestErrors(TEST_PARAMETER_RESULT);
    TestSubstringAndCompare(TEST_PARAMETER_RESULT);
    TestLifetimeAndBounds(TEST_PARAMETER_RESULT);
    TestInvalidBuffer(TEST_PARAMETER_RESULT);
}

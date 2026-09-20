#include "../UnitTest.h"

TEST_FUNC(NlsNative)
{
    USHORT Table[256 + 256 + 4096];
    PVOID SectionBase;
    SIZE_T SectionSize;
    const USHORT* UpperCaseTable;
    const USHORT* LowerCaseTable;
    NTSTATUS Status;
    ULONG i;
    ULONG Group;
    ULONG Middle;
    ULONG Low;
    WCHAR Character;
    WCHAR Mapped;

    /* Synthetic tables exercise every index level and 16-bit delta wraparound independently of system data. */
    for (i = 0; i < 256; i++)
    {
        Table[i] = (USHORT)(256 + ((i ^ (i >> 4)) & 0xF) * 16);
    }
    for (Group = 0; Group < 16; Group++)
    {
        for (Middle = 0; Middle < 16; Middle++)
        {
            Table[256 + Group * 16 + Middle] = (USHORT)(512 + Group * 256 + Middle * 16);
            for (Low = 0; Low < 16; Low++)
            {
                Table[512 + Group * 256 + Middle * 16 + Low] =
                    (USHORT)(0x8001 + (Group * 256 + Middle * 16 + Low) * 17);
            }
        }
    }
    for (i = 0; i <= MAXUSHORT; i++)
    {
        Character = (WCHAR)i;
        Group = ((i >> 8) ^ (i >> 12)) & 0xF;
        Mapped = (WCHAR)(i + 0x8001 + (Group * 256 + (i & 0xFF)) * 17);
        TEST_OK(_Inline_NLS_UPCASE(NULL, Character) ==
                (Character >= L'a' && Character <= L'z' ? Character - 32 : Character));
        TEST_OK(_Inline_NLS_DOWNCASE(NULL, Character) ==
                (Character >= L'A' && Character <= L'Z' ? Character + 32 : Character));
        TEST_OK(_Inline_NLS_UPCASE(Table, Character) ==
                (Character >= 0xC0 ? Mapped :
                 Character >= L'a' && Character <= L'z' ? Character - 32 : Character));
        TEST_OK(_Inline_NLS_DOWNCASE(Table, Character) ==
                (Character >= 0xC0 ? Mapped :
                 Character >= L'A' && Character <= L'Z' ? Character + 32 : Character));
    }

    /* Acquire system tables only for differential testing of the stateless helpers. */
    Status = NtGetNlsSectionPtr(14, 0, NULL, &SectionBase, &SectionSize);
    TEST_OK(NT_SUCCESS(Status));
    if (!NT_SUCCESS(Status))
    {
        return;
    }
    UpperCaseTable = (const USHORT*)SectionBase + 2;
    LowerCaseTable = UpperCaseTable + ((const USHORT*)SectionBase)[1];
    for (i = 0; i <= MAXUSHORT; i++)
    {
        TEST_OK(_Inline_NLS_UPCASE(UpperCaseTable, (WCHAR)i) == RtlUpcaseUnicodeChar((WCHAR)i));
        TEST_OK(_Inline_NLS_DOWNCASE(LowerCaseTable, (WCHAR)i) == RtlDowncaseUnicodeChar((WCHAR)i));
    }
    TEST_OK(NT_SUCCESS(NtUnmapViewOfSection(NtCurrentProcess(), SectionBase)));
}

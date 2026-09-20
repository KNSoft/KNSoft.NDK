#include "../UnitTest.h"

TEST_FUNC(RtlString)
{
    static const BOOLEAN CaseModes[] = { FALSE, TRUE, 0xFF };
    static const USHORT Lengths[] = { 0, 1, 2, 3, 4, 5, 31, 32, 33, 255, 256, 257, 65534, 65535 };
    static WCHAR Buffer1[32768];
    static WCHAR Buffer2[32768];
    STRING String1 = { 1, 1, (PCHAR)Buffer1 };
    STRING String2 = { 1, 1, (PCHAR)Buffer2 };
    UNICODE_STRING Unicode1 = { sizeof(WCHAR), sizeof(WCHAR), Buffer1 };
    UNICODE_STRING Unicode2 = { sizeof(WCHAR), sizeof(WCHAR), Buffer2 };
    ULONG i;
    ULONG j;
    ULONG Mode;
    SIZE_T Last;

    for (i = 0; i <= MAXUCHAR; i++)
    {
        TEST_OK(_Inline_RtlUpperChar((CHAR)i) == RtlUpperChar((CHAR)i));
        String1.Buffer[0] = (CHAR)i;
        for (j = 0; j <= MAXUCHAR; j++)
        {
            String2.Buffer[0] = (CHAR)j;
            for (Mode = 0; Mode < ARRAYSIZE(CaseModes); Mode++)
            {
                TEST_OK(_Inline_RtlEqualString(&String1, &String2, CaseModes[Mode]) ==
                        RtlEqualString(&String1, &String2, CaseModes[Mode]));
            }
        }
    }

    /* Include surrogates, noncharacters and the 0xC0 NLS lookup boundary. */
    for (i = 0; i <= MAXUSHORT; i++)
    {
        Buffer1[0] = (WCHAR)i;
        for (j = 0; j < 4; j++)
        {
            Buffer2[0] = j == 0 ? (WCHAR)i :
                         j == 1 ? RtlUpcaseUnicodeChar((WCHAR)i) :
                         j == 2 ? RtlDowncaseUnicodeChar((WCHAR)i) : (WCHAR)(i + 1);
            for (Mode = 0; Mode < ARRAYSIZE(CaseModes); Mode++)
            {
                TEST_OK(_Inline_RtlEqualUnicodeString(&Unicode1, &Unicode2, CaseModes[Mode]) ==
                        RtlEqualUnicodeString(&Unicode1, &Unicode2, CaseModes[Mode]));
            }
        }
    }

    for (i = 0; i < ARRAYSIZE(Lengths); i++)
    {
        String1.Length = String2.Length = Lengths[i];
        Unicode1.Length = Unicode2.Length = Lengths[i];
        /* MaximumLength is ignored by both native comparisons. */
        String1.MaximumLength = String2.MaximumLength = 0;
        Unicode1.MaximumLength = Unicode2.MaximumLength = 0;
        RtlFillMemory(Buffer1, sizeof(Buffer1), 'a');
        RtlFillMemory(Buffer2, sizeof(Buffer2), 'A');
        for (j = 0; j < 3; j++)
        {
            if (j == 1)
            {
                RtlCopyMemory(Buffer2, Buffer1, sizeof(Buffer1));
                Buffer1[0] = Buffer2[0] = 0;
            }
            else if (j == 2 && Lengths[i] != 0)
            {
                String2.Buffer[Lengths[i] - 1] ^= 1;
            }
            for (Mode = 0; Mode < ARRAYSIZE(CaseModes); Mode++)
            {
                TEST_OK(_Inline_RtlEqualString(&String1, &String2, CaseModes[Mode]) ==
                        RtlEqualString(&String1, &String2, CaseModes[Mode]));
            }
        }
        for (j = 0; j < ARRAYSIZE(Buffer1); j++)
        {
            Buffer1[j] = L'a';
            Buffer2[j] = L'A';
        }
        for (j = 0; j < 3; j++)
        {
            if (j == 1)
            {
                RtlCopyMemory(Buffer2, Buffer1, sizeof(Buffer1));
                Buffer1[0] = Buffer2[0] = 0;
            }
            else if (j == 2 && Lengths[i] != 0)
            {
                /* Odd lengths still compare the whole final WCHAR in the insensitive path. */
                Last = (Lengths[i] - 1) / sizeof(WCHAR);
                Buffer1[Last] = 0x0141;
                Buffer2[Last] = 0x0241;
            }
            for (Mode = 0; Mode < ARRAYSIZE(CaseModes); Mode++)
            {
                TEST_OK(_Inline_RtlEqualUnicodeString(&Unicode1, &Unicode2, CaseModes[Mode]) ==
                        RtlEqualUnicodeString(&Unicode1, &Unicode2, CaseModes[Mode]));
            }
        }
    }

    String1.Buffer = String2.Buffer = NULL;
    Unicode1.Buffer = Unicode2.Buffer = NULL;
    String1.Length = Unicode1.Length = 0;
    for (i = 0; i < 2; i++)
    {
        String2.Length = Unicode2.Length = (USHORT)(i * 2);
        for (Mode = 0; Mode < ARRAYSIZE(CaseModes); Mode++)
        {
            TEST_OK(_Inline_RtlEqualString(&String1, &String2, CaseModes[Mode]) ==
                    RtlEqualString(&String1, &String2, CaseModes[Mode]));
            TEST_OK(_Inline_RtlEqualUnicodeString(&Unicode1, &Unicode2, CaseModes[Mode]) ==
                    RtlEqualUnicodeString(&Unicode1, &Unicode2, CaseModes[Mode]));
        }
    }
}

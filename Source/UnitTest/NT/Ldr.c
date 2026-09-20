#include "../UnitTest.h"

TEST_FUNC(LdrRelocation)
{
    static const ULONG Machines[] = {
        IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
        IMAGE_FILE_MACHINE_ARM, IMAGE_FILE_MACHINE_THUMB, IMAGE_FILE_MACHINE_ARMNT,
        IMAGE_FILE_MACHINE_IA64, IMAGE_FILE_MACHINE_R4000, 0, 0x10000 | IMAGE_FILE_MACHINE_ARMNT
    };
    static const LONGLONG Deltas[] = {
        0, 1, -1, 0x7FFF, 0x8000, -0x8000, 0x12345678, -0x12345678,
        0x7FFFFFFF, 0x80000000LL, 0x100000001LL, -0x100000001LL,
        0x7FFFFFFFFFFFFFFFLL, (-0x7FFFFFFFFFFFFFFFLL - 1)
    };
    static const USHORT Offsets[] = { 0, 1, 2, 3, 0xFFE, 0xFFF };
    static const USHORT Companions[] = { 0, 0x7FFF, 0x8000, 0xA123, 0xFFFF };
    DECLSPEC_ALIGN(8) BYTE Original[0x1010], Native[0x1010], Inlined[0x1010];
    USHORT Entries[4];
    PIMAGE_BASE_RELOCATION NativeResult, InlineResult;
    typeof(LdrProcessRelocationBlockEx)* NativeEx;
    ULONG i, j, k, l, Count, Type;
    LONG_PTR Diff;

    NativeEx = (typeof(NativeEx))GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrProcessRelocationBlockEx");
    if (NativeEx == NULL)
    {
        TEST_SKIP("LdrProcessRelocationBlockEx is unavailable");
        return;
    }
    for (i = 0; i < sizeof(Original); i++)
    {
        Original[i] = (BYTE)(i * 37 + (i >> 2));
    }
    for (i = 0; i < ARRAYSIZE(Machines); i++)
    {
        for (Type = 0; Type < 16; Type++)
        {
            for (j = 0; j < ARRAYSIZE(Deltas); j++)
            {
                Diff = (LONG_PTR)Deltas[j];
                for (k = 0; k < ARRAYSIZE(Offsets); k++)
                {
                    for (Count = 1; Count <= 3; Count += 2)
                    {
                        Entries[0] = (USHORT)((Type << 12) | Offsets[k]);
                        Entries[1] = Companions[(j + k) % ARRAYSIZE(Companions)];
                        Entries[2] = 0x3020;
                        Entries[3] = 0;
                        RtlCopyMemory(Native, Original, sizeof(Native));
                        RtlCopyMemory(Inlined, Original, sizeof(Inlined));
                        NativeResult = NativeEx(Machines[i], (ULONG_PTR)Native, Count, Entries, Diff);
                        InlineResult = _Inline_LdrProcessRelocationBlockEx(Machines[i], (ULONG_PTR)Inlined,
                                                                         Count, Entries, Diff);
                        TEST_OK(NativeResult == InlineResult && RtlEqualMemory(Native, Inlined, sizeof(Native)));

                        RtlCopyMemory(Inlined, Original, sizeof(Inlined));
                        InlineResult = _Inline_LdrProcessRelocationBlockLongLong((USHORT)Machines[i],
                            (ULONG_PTR)Inlined, Count, Entries, (LONGLONG)Diff);
                        TEST_OK(NativeResult == InlineResult && RtlEqualMemory(Native, Inlined, sizeof(Native)));

                        if (Machines[i] == MACHINE_TYPE)
                        {
                            RtlCopyMemory(Native, Original, sizeof(Native));
                            RtlCopyMemory(Inlined, Original, sizeof(Inlined));
                            NativeResult = LdrProcessRelocationBlock((ULONG_PTR)Native, Count, Entries, Diff);
                            InlineResult = _Inline_LdrProcessRelocationBlock((ULONG_PTR)Inlined, Count, Entries, Diff);
                            TEST_OK(NativeResult == InlineResult && RtlEqualMemory(Native, Inlined, sizeof(Native)));
                        }
                    }
                }
            }
        }
    }

    /* HIGHADJ consumes its physically present companion even when only one entry is counted. */
    Entries[0] = 0x4000;
    Entries[1] = 0x8000;
    RtlZeroMemory(Inlined, sizeof(Inlined));
    TEST_OK(_Inline_LdrProcessRelocationBlockLongLong(IMAGE_FILE_MACHINE_I386, (ULONG_PTR)Inlined,
                                                     1, Entries, 0) == (PIMAGE_BASE_RELOCATION)(Entries + 2));
    TEST_OK(*(USHORT*)Inlined == 1);

    /* Unsupported entries leave preceding writes intact and return NULL. */
    Entries[0] = 0x3000;
    Entries[1] = 0x6000;
    RtlZeroMemory(Inlined, sizeof(Inlined));
    TEST_OK(_Inline_LdrProcessRelocationBlockLongLong(IMAGE_FILE_MACHINE_I386, (ULONG_PTR)Inlined,
                                                     2, Entries, 7) == NULL);
    TEST_OK(*(ULONG*)Inlined == 7);

    /* The LongLong entry point retains all 64 delta bits, including in x86 builds. */
    Entries[0] = 0xA001;
    for (j = 0; j < ARRAYSIZE(Deltas); j++)
    {
        RtlZeroMemory(Inlined, sizeof(Inlined));
        *(ULONGLONG UNALIGNED*)(Inlined + 1) = 0xFEDCBA9876543210ULL;
        TEST_OK(_Inline_LdrProcessRelocationBlockLongLong(IMAGE_FILE_MACHINE_AMD64, (ULONG_PTR)Inlined,
                                                         1, Entries, Deltas[j]) ==
                (PIMAGE_BASE_RELOCATION)(Entries + 1));
        TEST_OK(*(ULONGLONG UNALIGNED*)(Inlined + 1) == 0xFEDCBA9876543210ULL + (ULONGLONG)Deltas[j]);
    }

    /* Zero entries and a wrapped unsigned end address return NextOffset without reading it. */
    TEST_OK(NativeEx(0, 0, 0, Entries, 0) == (PIMAGE_BASE_RELOCATION)Entries);
    TEST_OK(_Inline_LdrProcessRelocationBlockEx(0, 0, 0, Entries, 0) == (PIMAGE_BASE_RELOCATION)Entries);
    {
        PUSHORT Wrapped = (PUSHORT)(MAXULONG_PTR - 1);
        TEST_OK(NativeEx(0, 0, 1, Wrapped, 0) == (PIMAGE_BASE_RELOCATION)Wrapped);
        TEST_OK(_Inline_LdrProcessRelocationBlockEx(0, 0, 1, Wrapped, 0) == (PIMAGE_BASE_RELOCATION)Wrapped);
    }

    /* The private helpers report WORDs consumed; they do not validate instruction opcodes. */
    for (Type = 0; Type < 16; Type++)
    {
        for (l = 0; l < 3; l++)
        {
            ULONG Consumed;
            Entries[0] = (USHORT)((Type << 12) | 3);
            Entries[1] = 0xFFFF;
            RtlCopyMemory(Inlined, Original, sizeof(Inlined));
            if (l == 0)
            {
                Consumed = _Inline_LdrpGenericProcessRelocation(Entries, (ULONG_PTR)Inlined, -1);
                TEST_OK(Consumed == (Type == 4 ? 2 : (Type <= 3 || Type == 10 ? 1 : 0)));
            } else if (l == 1)
            {
                Consumed = _Inline_LdrpArmProcessRelocation(Entries, (ULONG_PTR)Inlined, -1);
                TEST_OK(Consumed == (Type == 5 ? 1 : 0));
            } else
            {
                Consumed = _Inline_LdrpThumbProcessRelocation(Entries, (ULONG_PTR)Inlined, -1);
                TEST_OK(Consumed == (Type == 5 || Type == 7 ? 1 : 0));
            }
            if (Consumed == 0)
            {
                TEST_OK(RtlEqualMemory(Original, Inlined, sizeof(Original)));
            }
        }
    }
}

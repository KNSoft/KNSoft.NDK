#include "../UnitTest.h"

#define RTL_MEMORY_TEST_ALIGNMENT (sizeof(ULONG64))
#define RTL_MEMORY_TEST_LENGTH (RTL_MEMORY_TEST_ALIGNMENT * 2)

TEST_FUNC(RtlMemory)
{
    UCHAR Buffer[RTL_MEMORY_TEST_ALIGNMENT + RTL_MEMORY_TEST_LENGTH + 1];
    SIZE_T Index;
    SIZE_T Length;
    SIZE_T Offset;

    TEST_OK(_Inline_RtlIsZeroMemory(Buffer, 0));

    for (Offset = 0; Offset < RTL_MEMORY_TEST_ALIGNMENT; Offset++)
    {
        for (Length = 0; Length <= RTL_MEMORY_TEST_LENGTH; Length++)
        {
            RtlFillMemory(Buffer, sizeof(Buffer), 0xA5);
            RtlZeroMemory(Buffer + Offset, Length);
            TEST_OK(_Inline_RtlIsZeroMemory(Buffer + Offset, Length));
            TEST_OK(_Inline_RtlIsZeroMemory(Buffer + Offset, Length) ==
                    RtlIsZeroMemory(Buffer + Offset, Length));

            for (Index = 0; Index < Length; Index++)
            {
                Buffer[Offset + Index] = 1;
                TEST_OK(!_Inline_RtlIsZeroMemory(Buffer + Offset, Length));
                TEST_OK(_Inline_RtlIsZeroMemory(Buffer + Offset, Length) ==
                        RtlIsZeroMemory(Buffer + Offset, Length));
                Buffer[Offset + Index] = 0;
            }
        }
    }
}

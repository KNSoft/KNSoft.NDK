#include "../Include/KNSoft/NDK/UnitTest/UnitTest.h"

#include "../Include/KNSoft/NDK/Extension/StrSafe.h"
#include "../Include/KNSoft/NDK/WinDef/API/Ntdll.h"
#include "../Include/KNSoft/NDK/NT/Extension.h"

#include <dpfilter.h>

#pragma region Entries

#pragma section(".NDK$UTA", long, read) // First
#pragma section(".NDK$UTZ", long, read) // Last

__declspec(allocate(".NDK$UTA")) static PUNITTEST_ENTRY g_EntryList_First = NULL;
__declspec(allocate(".NDK$UTZ")) static PUNITTEST_ENTRY g_EntryList_Last = NULL;
static PUNITTEST_ENTRY* g_pEntryBegin = (&g_EntryList_First) + 1;
static PUNITTEST_ENTRY* g_pEntryEnd = (&g_EntryList_Last);

#pragma comment(linker, "/merge:.NDK=.rdata")

#pragma endregion

#pragma region Prints

static VOID UnitTest_PrintTitle()
{
    UnitTest_Print("====================================================================================================\n"
                   "KNSoft.NDK.UnitTest\n\n"
                   "    Lite-weight Unit Test Framework from KNSoft.NDK (https://github.com/KNSoft/KNSoft.NDK)\n"
                   "====================================================================================================\n\n");
}

static VOID UnitTest_PrintUsage()
{
    UnitTest_Print("Usage: Test_Program [-Run | -List] [TestName]\n\n"
                   "e.g.,\n\n"
                   "    Test_Program -List\n"
                   "        List all tests.\n\n"
                   "    Test_Program -Run\n"
                   "        Run all tests.\n\n"
                   "    Test_Program -Run TestName\n"
                   "        Run the test that named TestName.\n\n"
                   "Exit with the count of failed tests, or 0 if no test failed.\n\n");
}

static VOID UnitTest_PrintList()
{
    PUNITTEST_ENTRY* Entry;

    UnitTest_Print("Test list:\n");

    for (Entry = g_pEntryBegin; Entry != g_pEntryEnd; Entry++)
    {
        if (*Entry != NULL)
        {
            UnitTest_PrintF("    %wZ\n", &(*Entry)->Name);
        }
    }

    UnitTest_Print("\n");
}

#pragma endregion

#pragma region Entry API

BOOL NTAPI UnitTest_EnumEntries(
    _In_ __callback FN_UNITTEST_ENUM_PROC* Callback,
    _In_opt_ PVOID Context)
{
    PUNITTEST_ENTRY* Entry;
    BOOL Ret;

    for (Entry = g_pEntryBegin; Entry != g_pEntryEnd; Entry++)
    {
        if (*Entry != NULL)
        {
            Ret = Callback(*Entry, Context);
            if (!Ret)
            {
                return Ret;
            }
        }
    }

    return TRUE;
}

_Ret_maybenull_
_Must_inspect_result_
PUNITTEST_ENTRY NTAPI UnitTest_FindEntry(
    _In_z_ PCWSTR Name)
{
    PUNITTEST_ENTRY* Entry;
    UNICODE_STRING NameString;

    RtlInitUnicodeString(&NameString, Name);

    for (Entry = g_pEntryBegin; Entry != g_pEntryEnd; Entry++)
    {
        if (*Entry != NULL && RtlEqualUnicodeString(&(*Entry)->Name, &NameString, FALSE))
        {
            return *Entry;
        }
    }

    return NULL;
}

#pragma endregion

#pragma region Execute API

VOID NTAPI UnitTest_RunEntry(
    _In_ PUNITTEST_ENTRY Entry,
    _Out_ PUNITTEST_RESULT Result)
{
    UnitTest_FormatMessage(">>>> Running unit test: %wZ\n", &Entry->Name);
    RtlZeroMemory(Result, sizeof(*Result));
    Entry->Proc(Result);
    UnitTest_FormatMessage("<<<< Result: %lu tests executed (%lu passed, %lu failed, %lu skipped)\n\n",
                           Result->Pass + Result->Fail + Result->Skip,
                           Result->Pass,
                           Result->Fail,
                           Result->Skip);
}

ULONG NTAPI UnitTest_RunAll(
    _Out_ PUNITTEST_RESULT Result)
{
    ULONG Ret = 0;
    PUNITTEST_ENTRY* Entry;
    UNITTEST_RESULT EntryResult;

    RtlZeroMemory(Result, sizeof(*Result));

    for (Entry = g_pEntryBegin; Entry != g_pEntryEnd; Entry++)
    {
        if (*Entry != NULL)
        {
            UnitTest_RunEntry(*Entry, &EntryResult);
            Result->Pass += EntryResult.Pass;
            Result->Fail += EntryResult.Fail;
            Result->Skip += EntryResult.Skip;
            Ret++;
        }
    }

    UnitTest_FormatMessage("Totally %lu test entries run, %lu tests executed (%lu passed, %lu failed, %lu skipped)\n",
                           Ret,
                           Result->Pass + Result->Fail + Result->Skip,
                           Result->Pass,
                           Result->Fail,
                           Result->Skip);

    return Ret;
}

_Success_(return != FALSE)
BOOL NTAPI UnitTest_Run(
    _In_z_ PCWSTR Name,
    _Out_ PUNITTEST_RESULT Result)
{
    PUNITTEST_ENTRY Entry = UnitTest_FindEntry(Name);

    if (Entry == NULL)
    {
        return FALSE;
    }

    UnitTest_RunEntry(Entry, Result);
    return TRUE;
}

_Success_(return == 0)
INT NTAPI UnitTest_Main(
    _In_ int argc,
    _In_reads_(argc) _Pre_z_ wchar_t** argv)
{
    UNITTEST_RESULT Result;
    PUNITTEST_ENTRY Entry;

    UnitTest_PrintTitle();
    if (argc > 1)
    {
        if (_wcsicmp(argv[1], L"-List") == 0)
        {
            UnitTest_PrintList();
            return 0;
        } else if (_wcsicmp(argv[1], L"-Run") == 0)
        {
            if (argc == 2)
            {
                UnitTest_RunAll(&Result);
                goto _Exit;
            } else if (argc == 3)
            {
                Entry = UnitTest_FindEntry(argv[2]);
                if (Entry == NULL)
                {
                    UnitTest_PrintF("Test \"%ls\" not found.\n\n", argv[2]);
                    UnitTest_PrintList();
                    return (INT)STATUS_NOT_FOUND;
                }
                UnitTest_RunEntry(Entry, &Result);
                goto _Exit;
            }
        }
    }
    UnitTest_Print("Invalid parameter.\n\n");
    UnitTest_PrintUsage();
    return (INT)STATUS_INVALID_PARAMETER;

_Exit:
    return Result.Fail;
}

#pragma endregion

#pragma region Utils

VOID NTAPI UnitTest_PrintEx(
    _In_reads_bytes_(TextSize) PCCH Text,
    _In_ ULONG TextSize)
{
    HANDLE StdOutHandle;
    IO_STATUS_BLOCK IoStatusBlock;

    StdOutHandle = NtCurrentPeb()->ProcessParameters->StandardOutput;
    if (StdOutHandle != NULL)
    {
        NtWriteFile(StdOutHandle, NULL, NULL, NULL, &IoStatusBlock, (PVOID)Text, TextSize, NULL, NULL);
    }
}

static VOID __cdecl UnitTest_PrintFV(
    _In_z_ _Printf_format_string_ PCSTR Format,
    _In_ va_list ArgList)
{

    CHAR sz[512 + 1];
    ULONG u, uNew;
    HANDLE hStdOut;
    PSTR psz;
    IO_STATUS_BLOCK IoStatusBlock;

    /* Write standard output if exists */
    hStdOut = NtCurrentPeb()->ProcessParameters->StandardOutput;
    if (hStdOut == NULL)
    {
        return;
    }

    /* Format string */
    u = StrSafe_CchVPrintfA(sz, ARRAYSIZE(sz), Format, ArgList);
    if (u == 0)
    {
        return;
    }

    /* Allocate buffer if sz too small */
    if (u >= ARRAYSIZE(sz))
    {
        psz = RtlAllocateHeap(NtGetProcessHeap(), 0, u + 1);
        if (psz != NULL)
        {
            uNew = StrSafe_CchVPrintfA(psz, u + 1, Format, ArgList);
            if (uNew > 0 && uNew < u)
            {
                u = uNew;
                goto _Print_Stdout;
            }
            RtlFreeHeap(NtGetProcessHeap(), 0, psz);
        }

        /* New allocated buffer unavailable, fallback to sz (truncated) */
        u = ARRAYSIZE(sz) - 1;
    }

    psz = sz;

_Print_Stdout:
    NtWriteFile(hStdOut, NULL, NULL, NULL, &IoStatusBlock, psz, u, NULL, NULL);
    if (psz != sz)
    {
        RtlFreeHeap(NtGetProcessHeap(), 0, psz);
    }
}

VOID __cdecl UnitTest_PrintF(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...)
{
    va_list ArgList;

    va_start(ArgList, Format);
    UnitTest_PrintFV(Format, ArgList);
}

VOID __cdecl UnitTest_FormatMessage(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...)
{
    va_list ArgList;

    va_start(ArgList, Format);
    vDbgPrintEx(MAXULONG, DPFLTR_ERROR_LEVEL, Format, ArgList);
    UnitTest_PrintFV(Format, ArgList);
}

#pragma endregion

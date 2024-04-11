#include "../Include/KNSoft/NDK/UnitTest/UnitTest.h"

#include "../Include/KNSoft/NDK/WinDef/API/StrSafe.h"
#include "../Include/KNSoft/NDK/WinDef/API/Ntdll.h"
#include "../Include/KNSoft/NDK/NT/Extension.h"

#include <dpfilter.h>

#pragma region Entries

#pragma section(".NUT$ELA", long, read) // First
#pragma section(".NUT$ELZ", long, read) // Last

__declspec(allocate(".NUT$ELA")) static PUNITTEST_ENTRY g_EntryList_First = NULL;
__declspec(allocate(".NUT$ELZ")) static PUNITTEST_ENTRY g_EntryList_Last = NULL;
static PUNITTEST_ENTRY* g_pEntryBegin = (&g_EntryList_First) + 1;
static PUNITTEST_ENTRY* g_pEntryEnd = (&g_EntryList_Last);

#pragma comment(linker, "/merge:.NUT=.rdata")

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

#pragma region Execuate

ULONG NTAPI UnitTest_RunAll(
    _Out_ PUNITTEST_RESULT Result)
{
    ULONG Ret = 0;
    PUNITTEST_ENTRY* Entry;

    RtlZeroMemory(Result, sizeof(*Result));

    for (Entry = g_pEntryBegin; Entry != g_pEntryEnd; Entry++)
    {
        if (*Entry != NULL)
        {
            (*Entry)->Proc(Result);
            Ret++;
        }
    }

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

    RtlZeroMemory(Result, sizeof(*Result));
    Entry->Proc(Result);
    return TRUE;
}

_Success_(return > 0)
ULONG NTAPI UnitTest_Main(
    _In_ int argc,
    _In_reads_(argc) _Pre_z_ wchar_t** argv,
    _Out_ PUNITTEST_RESULT Result)
{
    ULONG RunCount;
    int i;
    UNICODE_STRING NameString;
    PUNITTEST_ENTRY* Entry;

    if (argc == 1)
    {
        RunCount = UnitTest_RunAll(Result);
    } else if (argc > 1)
    {
        RtlZeroMemory(Result, sizeof(*Result));
        RunCount = 0;

        for (i = 1; i < argc; i++)
        {
            RtlInitUnicodeString(&NameString, argv[i]);

            for (Entry = g_pEntryBegin; Entry != g_pEntryEnd; Entry++)
            {
                if (RtlEqualUnicodeString(&(*Entry)->Name, &NameString, FALSE))
                {
                    (*Entry)->Proc(Result);
                    RunCount++;
                    break;
                }
            }
        }
    } else
    {
        RunCount = 0;
    }

    return RunCount;
}

#pragma endregion

#pragma region Utils

VOID __cdecl UnitTest_PrintF(
    _In_z_ _Printf_format_string_ PCSTR Format, ...)
{
    CHAR sz[512 + 1];
    va_list argList;
    ULONG u, uNew;
    HANDLE hStdOut;
    PSTR psz;
    IO_STATUS_BLOCK IoStatusBlock;

    va_start(argList, Format);

    /* Write DbgPrint */
    vDbgPrintEx(MAXULONG, DPFLTR_ERROR_LEVEL, Format, argList);

    /* Write standard output if exists */
    hStdOut = NtCurrentPeb()->ProcessParameters->StandardOutput;
    if (hStdOut == NULL)
    {
        return;
    }

    /* Format string */
    u = StrSafe_CchVPrintfA(sz, ARRAYSIZE(sz), Format, argList);
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
            uNew = StrSafe_CchVPrintfA(psz, u + 1, Format, argList);
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

#pragma endregion

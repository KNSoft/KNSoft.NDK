#pragma once

#include "../MinDef.h"
#include "../Rtl/Process/Process.h"
#include "../Rtl/Process/EnvironmentBlock.h"

#pragma region TEB Fast Access

#if defined(_M_X64)

#ifdef FIELD_TYPE
#define ReadTeb(m) ((FIELD_TYPE(TEB, m))(\
    FIELD_SIZE(TEB, m) == sizeof(ULONGLONG) ? __readgsqword(UFIELD_OFFSET(TEB, m)) : (\
        FIELD_SIZE(TEB, m) == sizeof(ULONG) ? __readgsdword(UFIELD_OFFSET(TEB, m)) : (\
            FIELD_SIZE(TEB, m) == sizeof(USHORT) ? __readgsword(UFIELD_OFFSET(TEB, m)) : (\
                FIELD_SIZE(TEB, m) == sizeof(UCHAR) ? __readgsbyte(UFIELD_OFFSET(TEB, m)) :\
                    (__fastfail(FAST_FAIL_INVALID_ARG), 0)\
            )\
        )\
    )\
))
#else
#define ReadTeb(m) (\
    FIELD_SIZE(TEB, m) == sizeof(ULONGLONG) ? __readgsqword(UFIELD_OFFSET(TEB, m)) : (\
        FIELD_SIZE(TEB, m) == sizeof(ULONG) ? __readgsdword(UFIELD_OFFSET(TEB, m)) : (\
            FIELD_SIZE(TEB, m) == sizeof(USHORT) ? __readgsword(UFIELD_OFFSET(TEB, m)) : (\
                FIELD_SIZE(TEB, m) == sizeof(UCHAR) ? __readgsbyte(UFIELD_OFFSET(TEB, m)) :\
                    (__fastfail(FAST_FAIL_INVALID_ARG), 0)\
            )\
        )\
    )\
)
#endif

#define WriteTeb(m, val) (\
    FIELD_SIZE(TEB, m) == sizeof(ULONGLONG) ? __writegsqword(UFIELD_OFFSET(TEB, m), (ULONGLONG)(val)) : (\
        FIELD_SIZE(TEB, m) == sizeof(ULONG) ? __writegsdword(UFIELD_OFFSET(TEB, m), (ULONG)(val)) : (\
            FIELD_SIZE(TEB, m) == sizeof(USHORT) ? __writegsword(UFIELD_OFFSET(TEB, m), (USHORT)(val)) : (\
                FIELD_SIZE(TEB, m) == sizeof(UCHAR) ? __writegsbyte(UFIELD_OFFSET(TEB, m), (UCHAR)(val)) :\
                    __fastfail(FAST_FAIL_INVALID_ARG)\
            )\
        )\
    )\
)

#elif defined(_M_IX86)

#ifdef FIELD_TYPE
#define ReadTeb(m) ((FIELD_TYPE(TEB, m))(\
    FIELD_SIZE(TEB, m) == sizeof(ULONG) ? __readfsdword(UFIELD_OFFSET(TEB, m)) : (\
        FIELD_SIZE(TEB, m) == sizeof(USHORT) ? __readfsword(UFIELD_OFFSET(TEB, m)) : (\
            FIELD_SIZE(TEB, m) == sizeof(UCHAR) ? __readfsbyte(UFIELD_OFFSET(TEB, m)) :\
                (__fastfail(FAST_FAIL_INVALID_ARG), 0)\
        )\
    )\
))
#else
#define ReadTeb(m) (\
    FIELD_SIZE(TEB, m) == sizeof(ULONG) ? __readfsdword(UFIELD_OFFSET(TEB, m)) : (\
        FIELD_SIZE(TEB, m) == sizeof(USHORT) ? __readfsword(UFIELD_OFFSET(TEB, m)) : (\
            FIELD_SIZE(TEB, m) == sizeof(UCHAR) ? __readfsbyte(UFIELD_OFFSET(TEB, m)) :\
                (__fastfail(FAST_FAIL_INVALID_ARG), 0)\
        )\
    )\
)
#endif

#define WriteTeb(m, val) (\
    FIELD_SIZE(TEB, m) == sizeof(ULONG) ? __writefsdword(UFIELD_OFFSET(TEB, m), (ULONG)(val)) : (\
        FIELD_SIZE(TEB, m) == sizeof(USHORT) ? __writefsword(UFIELD_OFFSET(TEB, m), (USHORT)(val)) : (\
            FIELD_SIZE(TEB, m) == sizeof(UCHAR) ? __writefsbyte(UFIELD_OFFSET(TEB, m), (UCHAR)(val)) :\
                __fastfail(FAST_FAIL_INVALID_ARG)\
        )\
    )\
)

#else

#define ReadTeb(m) (NtCurrentTeb()->m)
#define WriteTeb(m, val) (NtCurrentTeb()->m = (val))

#endif

#pragma endregion

#pragma region Error codes

/* Gets or sets the last error */

_Ret_range_(>, 0)
FORCEINLINE
ULONG
NtGetLastError(VOID)
{
    ULONG Error;

    Error = (ULONG)ReadTeb(LastErrorValue);
    _Analysis_assume_(Error > 0);
    return Error;
}

FORCEINLINE
VOID
NtSetLastError(
    _In_ ULONG Error)
{
    WriteTeb(LastErrorValue, Error);
}

/* Gets or sets the last status */

_Ret_range_(<, 0)
FORCEINLINE
NTSTATUS
NtGetLastStatus(VOID)
{
    NTSTATUS Status;

    Status = (NTSTATUS)ReadTeb(LastStatusValue);
    _Analysis_assume_(Status < 0);
    return Status;
}

FORCEINLINE
VOID
NtSetLastStatus(
    _In_ NTSTATUS Status)
{
    WriteTeb(LastStatusValue, Status);
}

/*
 * Error code conversion (NOT translation) Win32 Error/NTSTATUS/HRESULT 
 * HRESULT_FROM_WIN32 / NTSTATUS_FROM_WIN32 / HRESULT_FROM_NT
 */

#pragma endregion

#pragma region Pseudo Handles

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess() NtCurrentProcess()
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define ZwCurrentThread() NtCurrentThread()
#define NtCurrentSession() ((HANDLE)(LONG_PTR)-3)
#define ZwCurrentSession() NtCurrentSession()
#define NtCurrentProcessToken() ((HANDLE)(LONG_PTR)-4) // NtOpenProcessToken(NtCurrentProcess())
#define ZwCurrentProcessToken() NtCurrentProcessToken()
#define NtCurrentThreadToken() ((HANDLE)(LONG_PTR)-5) // NtOpenThreadToken(NtCurrentThread())
#define ZwCurrentThreadToken() NtCurrentThreadToken()
#define NtCurrentThreadEffectiveToken() ((HANDLE)(LONG_PTR)-6) // NtOpenThreadToken(NtCurrentThread()) + NtOpenProcessToken(NtCurrentProcess())
#define ZwCurrentThreadEffectiveToken() NtCurrentThreadEffectiveToken()

#define NtCurrentSilo() ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentSilo() NtCurrentSilo()

#pragma endregion

#pragma region Current runtime information

#define NtCurrentPeb() ((PPEB)ReadTeb(ProcessEnvironmentBlock))
#define NtCurrentProcessId() ((ULONG)(ULONG_PTR)ReadTeb(ClientId.UniqueProcess))
#define NtCurrentThreadId() ((ULONG)(ULONG_PTR)ReadTeb(ClientId.UniqueThread))
#define NtCurrentLogonId() (NtCurrentPeb()->LogonId)
#define NtGetProcessHeap() (NtCurrentPeb()->ProcessHeap)
#define NtGetNtdllBase() (CONTAINING_RECORD(NtCurrentPeb()->Ldr->InInitializationOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks)->DllBase)

#pragma endregion

#if defined(_M_IX86)
#define CONTEXT_PC Eip
#elif defined(_M_X64)
#define CONTEXT_PC Rip
#elif defined(_M_ARM64)
#define CONTEXT_PC Pc
#endif

typedef
_Function_class_(RUNDLL32_ENTRY_FN)
VOID
CALLBACK
RUNDLL32_ENTRY_FN(
    _In_ HWND hWnd,
    _In_ HINSTANCE hInst,
    _In_ LPSTR lpszCmdLine,
    _In_ int nCmdShow);

#define CPU_CACHE_LINE_SIZE 64

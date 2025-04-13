#pragma once

#include "../MinDef.h"
#include "../Rtl/Process/Process.h"
#include "../Rtl/Process/EnvironmentBlock.h"

#pragma region TEB Fast Access (Without Pointer Reference)

#if !defined(_WIN64)

__forceinline
unsigned __int64
NtReadCurrentTebUlonglong(
    unsigned int Offset)
{
    ULARGE_INTEGER li;

    li.LowPart = NtReadCurrentTebUlong(Offset);
    li.HighPart = NtReadCurrentTebUlong(Offset + sizeof(ULONG));
    return li.QuadPart;
}

#endif

#ifdef FIELD_TYPE
#define NtReadTeb(m) ((FIELD_TYPE(TEB, m))(\
    FIELD_SIZE(TEB, m) == sizeof(ULONGLONG) ? NtReadCurrentTebUlonglong(UFIELD_OFFSET(TEB, m)) : (\
        FIELD_SIZE(TEB, m) == sizeof(ULONG) ? NtReadCurrentTebUlong(UFIELD_OFFSET(TEB, m)) : (\
            FIELD_SIZE(TEB, m) == sizeof(USHORT) ? NtReadCurrentTebUshort(UFIELD_OFFSET(TEB, m)) : (\
                FIELD_SIZE(TEB, m) == sizeof(UCHAR) ? NtReadCurrentTebByte(UFIELD_OFFSET(TEB, m)) :\
                    ((ULONGLONG)(NtCurrentTeb()->m))\
            )\
        )\
    )\
))
#else
#define NtReadTeb(m) (\
    FIELD_SIZE(TEB, m) == sizeof(ULONGLONG) ? NtReadCurrentTebUlonglong(UFIELD_OFFSET(TEB, m)) : (\
        FIELD_SIZE(TEB, m) == sizeof(ULONG) ? NtReadCurrentTebUlong(UFIELD_OFFSET(TEB, m)) : (\
            FIELD_SIZE(TEB, m) == sizeof(USHORT) ? NtReadCurrentTebUshort(UFIELD_OFFSET(TEB, m)) : (\
                FIELD_SIZE(TEB, m) == sizeof(UCHAR) ? NtReadCurrentTebByte(UFIELD_OFFSET(TEB, m)) :\
                    ((ULONGLONG)(NtCurrentTeb()->m))\
            )\
        )\
    )\
)
#endif

#if defined(_M_X64)

#define NtWriteTeb(m, val) (\
    FIELD_SIZE(TEB, m) == sizeof(ULONGLONG) ? __writegsqword(UFIELD_OFFSET(TEB, m), (ULONGLONG)(val)) : (\
        FIELD_SIZE(TEB, m) == sizeof(ULONG) ? __writegsdword(UFIELD_OFFSET(TEB, m), (ULONG)(val)) : (\
            FIELD_SIZE(TEB, m) == sizeof(USHORT) ? __writegsword(UFIELD_OFFSET(TEB, m), (USHORT)(val)) : (\
                FIELD_SIZE(TEB, m) == sizeof(UCHAR) ? __writegsbyte(UFIELD_OFFSET(TEB, m), (UCHAR)(val)) :\
                    ((void)(NtCurrentTeb()->m = (val)))\
            )\
        )\
    )\
)

#elif defined(_M_IX86)

#define NtWriteTeb(m, val) (\
    FIELD_SIZE(TEB, m) == sizeof(ULONG) ? __writefsdword(UFIELD_OFFSET(TEB, m), (ULONG)(val)) : (\
        FIELD_SIZE(TEB, m) == sizeof(USHORT) ? __writefsword(UFIELD_OFFSET(TEB, m), (USHORT)(val)) : (\
            FIELD_SIZE(TEB, m) == sizeof(UCHAR) ? __writefsbyte(UFIELD_OFFSET(TEB, m), (UCHAR)(val)) :\
                ((void)(NtCurrentTeb()->m = (val)))\
        )\
    )\
)

#elif defined(_M_ARM64) || defined(_M_ARM64EC)

#define NtWriteTeb(m, val) (\
    FIELD_SIZE(TEB, m) == sizeof(ULONGLONG) ? __writex18qword(UFIELD_OFFSET(TEB, m), (ULONGLONG)(val)) : (\
        FIELD_SIZE(TEB, m) == sizeof(ULONG) ? __writex18dword(UFIELD_OFFSET(TEB, m), (ULONG)(val)) : (\
            FIELD_SIZE(TEB, m) == sizeof(USHORT) ? __writex18word(UFIELD_OFFSET(TEB, m), (USHORT)(val)) : (\
                FIELD_SIZE(TEB, m) == sizeof(UCHAR) ? __writex18byte(UFIELD_OFFSET(TEB, m), (UCHAR)(val)) :\
                    ((void)(NtCurrentTeb()->m = (val)))\
            )\
        )\
    )\
)

#else

#define NtWriteTeb(m, val) (NtCurrentTeb()->m = (val))

#endif

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

#define NtCurrentPeb() ((PPEB)NtReadTeb(ProcessEnvironmentBlock))
#define NtCurrentProcessId() ((ULONG)(ULONG_PTR)NtReadTeb(ClientId.UniqueProcess))
#define NtCurrentThreadId() ((ULONG)(ULONG_PTR)NtReadTeb(ClientId.UniqueThread))
#define NtCurrentLogonId() (NtCurrentPeb()->LogonId)
#define NtGetProcessHeap() (NtCurrentPeb()->ProcessHeap)
#define NtGetNtdllBase() (CONTAINING_RECORD(NtCurrentPeb()->Ldr->InInitializationOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks)->DllBase)
#define NtGetImageNtHeader() ((PIMAGE_NT_HEADERS)Add2Ptr(&__ImageBase, __ImageBase.e_lfanew))

#pragma endregion

#pragma region Machine

#define CPU_CACHE_LINE_SIZE 64

#if defined(_M_IX86)

#define CONTEXT_PC Eip
#define MACHINE_TYPE IMAGE_FILE_MACHINE_I386

#elif defined(_M_X64)

#define CONTEXT_PC Rip
#define MACHINE_TYPE IMAGE_FILE_MACHINE_AMD64

#elif defined(_M_ARM64)

#define CONTEXT_PC Pc
#define MACHINE_TYPE IMAGE_FILE_MACHINE_ARM64

#endif

#pragma endregion

typedef
_Function_class_(RUNDLL32_ENTRY_FN)
VOID
CALLBACK
RUNDLL32_ENTRY_FN(
    _In_ HWND hWnd,
    _In_ HINSTANCE hInst,
    _In_ LPSTR lpszCmdLine,
    _In_ int nCmdShow);

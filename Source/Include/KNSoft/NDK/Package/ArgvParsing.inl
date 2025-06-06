#ifdef TChar

#include "../NDK.h"

#define _ARGPARSE_PARSE_FUNCNAME(x) Arg_ParseCmdline_##x
#define ARGPARSE_PARSE_FUNCNAME(x) _ARGPARSE_PARSE_FUNCNAME(x)
#define ARGPARSE_PARSE_FUNC(x) static __inline VOID _ARGPARSE_PARSE_FUNCNAME(x)

ARGPARSE_PARSE_FUNC(TChar)(
    _In_ _Null_terminated_ CONST TChar* Cmdline,
    _Outptr_opt_result_z_ TChar** ArgV,
    _Out_opt_ TChar* ArgPtr,
    _Out_ PULONG ArgC,
    _Out_ PULONG CharC)
{
    CONST TChar* p;
    TChar c;
    BOOL IsQuoted, DoCopy;
    ULONG SlashCount;

    *CharC = 0;
    *ArgC = 1;

    p = Cmdline;
    if (ArgV)
    {
        *ArgV++ = ArgPtr;
    }

    IsQuoted = FALSE;
    do
    {
        if (*p == '"')
        {
            IsQuoted = !IsQuoted;
            c = *p++;
            continue;
        }

        ++*CharC;
        if (ArgPtr)
        {
            *ArgPtr++ = *p;
        }

        c = *p++;
    } while (c != '\0' && (IsQuoted || (c != ' ' && c != '\t')));

    if (c == '\0')
    {
        p--;
    } else
    {
        if (ArgPtr)
        {
            *(ArgPtr - 1) = '\0';
        }
    }

    IsQuoted = FALSE;

    while (TRUE)
    {
        if (*p)
        {
            while (*p == ' ' || *p == '\t')
            {
                ++p;
            }
        }
        if (*p == '\0')
        {
            break;
        }
        if (ArgV)
        {
            *ArgV++ = ArgPtr;
        }
        ++ * ArgC;

        for (;;)
        {
            DoCopy = TRUE;
            SlashCount = 0;

            while (*p == '\\')
            {
                ++p;
                ++SlashCount;
            }

            if (*p == '"')
            {
                if (SlashCount % 2 == 0)
                {
                    if (IsQuoted && p[1] == '"')
                    {
                        p++;
                    } else
                    {
                        DoCopy = FALSE;
                        IsQuoted = !IsQuoted;
                    }
                }

                SlashCount /= 2;
            }

            while (SlashCount--)
            {
                if (ArgPtr)
                {
                    *ArgPtr++ = '\\';
                }
                ++*CharC;
            }

            if (*p == '\0' || (!IsQuoted && (*p == ' ' || *p == '\t')))
            {
                break;
            }

            if (DoCopy)
            {
                if (ArgPtr)
                {
                    *ArgPtr++ = *p;
                }

                ++*CharC;
            }

            ++p;
        }

        if (ArgPtr)
        {
            *ArgPtr++ = '\0';
        }

        ++*CharC;
    }

    if (ArgV)
    {
        *ArgV++ = NULL;
    }

    ++*ArgC;
}

#define _ARGPARSE_ALLOC_FUNCNAME(x) Arg_AllocArgV_##x
#define ARGPARSE_ALLOC_FUNCNAME(x) _ARGPARSE_ALLOC_FUNCNAME(x)
#define ARGPARSE_ALLOC_FUNC(x) static __inline NTSTATUS _ARGPARSE_ALLOC_FUNCNAME(x)

ARGPARSE_ALLOC_FUNC(TChar)(
    _In_z_ CONST TChar* Cmdline,
    _Out_ PULONG ArgC,
    _Out_ TChar*** ArgV)
{
    ULONG ArgCount, CchCmdline, ArgPtrSize;
    PVOID Buffer;

    ARGPARSE_PARSE_FUNCNAME(TChar)(Cmdline, NULL, NULL, &ArgCount, &CchCmdline);
    ArgPtrSize = ArgCount * sizeof(PVOID);

    Buffer = RtlAllocateHeap(RtlProcessHeap(), 0, ArgPtrSize + CchCmdline * sizeof(TChar));
    if (Buffer == NULL)
    {
        return STATUS_NO_MEMORY;
    }
    ARGPARSE_PARSE_FUNCNAME(TChar)(Cmdline,
                                   (TChar**)Buffer,
                                   (TChar*)(Add2Ptr(Buffer, ArgPtrSize)),
                                   &ArgCount,
                                   &CchCmdline);

    *ArgC = ArgCount - 1;
    *ArgV = (TChar**)Buffer;
    return STATUS_SUCCESS;
}

#endif

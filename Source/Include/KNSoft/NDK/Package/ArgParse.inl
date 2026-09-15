/*
 * KNSoft.NDK ArgParse.inl package, licensed under the MIT license.
 * Copyright (c) KNSoft.org (https://github.com/KNSoft). All rights reserved.
 *
 * Provide native implementation of command-line parsing.
 * See also `_Inline_CommandLineToArgv(A/W)` in "..\Win32\Shell32.inl" for usage.
 * 
 * Source base on Microsoft UCRT:
 * 
 * Microsoft.Windows.SDK.CRTSource (https://www.nuget.org/packages/Microsoft.Windows.SDK.CRTSource)
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT license.
 */

#ifdef TChar

#include "../NDK.h"

#include <mbctype.h>

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
        if (sizeof(TChar) == sizeof(CHAR) && _ismbblead((UCHAR)c) && *p != '\0')
        {
            ++*CharC;
            if (ArgPtr)
            {
                *ArgPtr++ = *p;
            }
            ++p;
        }
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
        ++*ArgC;

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

                if (sizeof(TChar) == sizeof(CHAR) && _ismbblead((UCHAR)*p) && p[1] != '\0')
                {
                    ++p;
                    ++*CharC;
                    if (ArgPtr)
                    {
                        *ArgPtr++ = *p;
                    }
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

#define _ARGPARSE_BUILD_FUNCNAME(x) Arg_BuildCmdline_##x
#define ARGPARSE_BUILD_FUNCNAME(x) _ARGPARSE_BUILD_FUNCNAME(x)
#define ARGPARSE_BUILD_FUNC(x) static __inline NTSTATUS _ARGPARSE_BUILD_FUNCNAME(x)

/* ArgV[0] is the program name and must not contain double quotes; later arguments follow UCRT escaping rules. */
ARGPARSE_BUILD_FUNC(TChar)(
    _In_ ULONG ArgC,
    _In_reads_(ArgC) _At_buffer_(ArgV, _Iter_, ArgC, _In_z_) CONST TChar* CONST* ArgV,
    _Out_opt_ TChar* Cmdline,
    _Out_ PSIZE_T CharC)
{
    CONST SIZE_T MaxCharCount = MAXSIZE_T / sizeof(TChar);
    CONST TChar* p;
    SIZE_T CharCount = 0, SlashCount;
    ULONG Index;

    for (Index = 0; Index < ArgC; Index++)
    {
        if (CharCount > MaxCharCount - 3)
        {
            return STATUS_INTEGER_OVERFLOW;
        }
        CharCount += 3;
        if (Cmdline)
        {
            *Cmdline++ = '"';
        }
        SlashCount = 0;
        for (p = ArgV[Index]; *p != '\0'; p++)
        {
            if (Index != 0 && *p == '\\')
            {
                SlashCount++;
                continue;
            }
            if (Index != 0 && *p == '"')
            {
                if (SlashCount > (MaxCharCount - 1) / 2)
                {
                    return STATUS_INTEGER_OVERFLOW;
                }
                SlashCount = SlashCount * 2 + 1;
            }
            if (SlashCount >= MaxCharCount - CharCount)
            {
                return STATUS_INTEGER_OVERFLOW;
            }
            CharCount += SlashCount + 1;
            if (Cmdline)
            {
                while (SlashCount != 0)
                {
                    *Cmdline++ = '\\';
                    SlashCount--;
                }
                *Cmdline++ = *p;
            }
            if (sizeof(TChar) == sizeof(CHAR) && _ismbblead((UCHAR)*p) && p[1] != '\0')
            {
                if (CharCount == MaxCharCount)
                {
                    return STATUS_INTEGER_OVERFLOW;
                }
                CharCount++;
                p++;
                if (Cmdline)
                {
                    *Cmdline++ = *p;
                }
            }
            SlashCount = 0;
        }
        // Escape trailing backslashes before the closing quote, except in the program name.
        if (SlashCount > (MaxCharCount - CharCount) / 2)
        {
            return STATUS_INTEGER_OVERFLOW;
        }
        SlashCount *= 2;
        CharCount += SlashCount;
        if (Cmdline)
        {
            while (SlashCount != 0)
            {
                *Cmdline++ = '\\';
                SlashCount--;
            }
            *Cmdline++ = '"';
            *Cmdline++ = Index + 1 < ArgC ? ' ' : '\0';
        }
    }
    if (ArgC == 0)
    {
        if (Cmdline)
        {
            *Cmdline = '\0';
        }
        CharCount = 1;
    }
    *CharC = CharCount;
    return STATUS_SUCCESS;
}

#define _ARGPARSE_ALLOC_CMDLINE_FUNCNAME(x) Arg_AllocCmdline_##x
#define ARGPARSE_ALLOC_CMDLINE_FUNCNAME(x) _ARGPARSE_ALLOC_CMDLINE_FUNCNAME(x)
#define ARGPARSE_ALLOC_CMDLINE_FUNC(x) static __inline NTSTATUS _ARGPARSE_ALLOC_CMDLINE_FUNCNAME(x)

ARGPARSE_ALLOC_CMDLINE_FUNC(TChar)(
    _In_ ULONG ArgC,
    _In_reads_(ArgC) _At_buffer_(ArgV, _Iter_, ArgC, _In_z_) CONST TChar* CONST* ArgV,
    _Out_ TChar** Cmdline)
{
    SIZE_T CharCount;
    TChar* Buffer;
    NTSTATUS Status;

    Status = ARGPARSE_BUILD_FUNCNAME(TChar)(ArgC, ArgV, NULL, &CharCount);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }
    Buffer = (TChar*)RtlAllocateHeap(RtlProcessHeap(), 0, CharCount * sizeof(TChar));
    if (Buffer == NULL)
    {
        return STATUS_NO_MEMORY;
    }
    ARGPARSE_BUILD_FUNCNAME(TChar)(ArgC, ArgV, Buffer, &CharCount);
    *Cmdline = Buffer;
    return STATUS_SUCCESS;
}

#define ARGPARSE_FREE_FUNC(ArgV) RtlFreeHeap(RtlProcessHeap(), 0, ArgV);

#endif

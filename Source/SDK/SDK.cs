using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using KNSoft.C4Lib.CodeHelper;

namespace KNSoft.NDK.SDK;

public class SyscallResolver
{
    public class Syscall : Cpp.Function
    {
        public List<String[]> Conditions = [];
    }

    public enum SyscallType
    {
        Nt = 0,
        NtUser = 1,
        Zw = 2
    };

    /* Have no Zw version exported in ntdll.dll */
    static public readonly String[] UserModeImplSyscalls = ["NtGetTickCount"];

    static public List<Syscall> GetSyscallsFromFile(String FilePath)
    {
        String[] Content = File.ReadAllLines(FilePath);
        List<Syscall> Functions = [];
        List<List<String>> Conditions = [];

        for (Int32 i = 0; i < Content.Length; i++)
        {
            String Line = Content[i].Trim();
            if (Line.StartsWith("#if"))
            {
                Conditions.Add([]);
            } else if (Line.StartsWith("#endif"))
            {
                Conditions.RemoveAt(Conditions.Count - 1);
                continue;
            }
            if (Line.StartsWith("#if") || Line.StartsWith("#elif") || Line.StartsWith("#else"))
            {
                Conditions[^1].Add(Line);
                while (Line.EndsWith('\\'))
                {
                    Line = Content[++i];
                    Conditions[^1].Add(Line);
                }
                continue;
            }
            if (Line != "NTSYSCALLAPI")
            {
                continue;
            }
            Int32 iStart;
            for (iStart = i - 1; iStart >= 0; iStart--)
            {
                if (Cpp.CodeResolver.IsFunctionDeclarationStart(Content[iStart]))
                {
                    break;
                }
            }
            if (iStart < 0)
            {
                continue;
            }
            do
            {
                if (Cpp.CodeResolver.IsFunctionDeclarationEnd(Content[i]))
                {
                    break;
                }
            } while (++i < Content.Length);
            if (i < Content.Length)
            {
                foreach (Cpp.Function Function in Cpp.CodeResolver.GetFunctionsFromContent(Content[(iStart + 1)..(i + 1)]))
                {
                    Functions.Add(new Syscall
                    {
                        Name = Function.Name,
                        Prefixes = Function.Prefixes,
                        Parameters = Function.Parameters,
                        Content = Function.Content,
                        Conditions = [.. Conditions.Select(x => x.ToArray())]
                    });
                }
            }
        }

        return Functions;
    }

    static public List<Syscall> GetSyscalls(String NtDir /* KNSoft.NDK\Source\Include\KNSoft\NDK\NT */, SyscallType Type)
    {
        if (Type == SyscallType.Nt)
        {
            List<Syscall> Syscalls = [];

            String[] Headers = Directory.GetFiles(NtDir, @"*.h", SearchOption.AllDirectories);
            foreach (String Header in Headers)
            {
                if (Header.StartsWith(NtDir + @"\Rtl\") ||
                    Header.StartsWith(NtDir + @"\Extension\") ||
                    Header == NtDir + @"\Win32K\Win32KApi.h" ||
                    Header == NtDir + @"\ZwApi.h")
                {
                    continue;
                }
                Syscalls.AddRange(GetSyscallsFromFile(Header));
            }

            return Syscalls;
        } else if (Type == SyscallType.NtUser)
        {
            return GetSyscallsFromFile(NtDir + @"\Win32K\Win32KApi.h");
        } else if (Type == SyscallType.Zw)
        {
            return GetSyscallsFromFile(NtDir + @"\ZwApi.h");
        }

        return [];
    }
}

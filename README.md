# KNSoft.NDK

![NuGet Downloads](https://img.shields.io/nuget/dt/KNSoft.NDK) ![GitHub Release](https://img.shields.io/github/v/release/KNSoft/KNSoft.NDK) ![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/KNSoft/KNSoft.NDK/msbuild.yml) ![PR Welcome](https://img.shields.io/badge/PR-welcome-0688CB.svg) ![GitHub License](https://img.shields.io/github/license/KNSoft/KNSoft.NDK)

KNSoft.NDK provides native C/C++ definitions and import libraries for Windows NT and some specifications.

## Feature

- Windows NT
  - Undocumented type definitions, i.e. `PEB`, `TEB`, `LDR_*`, ...
  - Undocumented API declarations, i.e. `Nt/Zw*`, `Ldr*`, ...
  - Definitions in public sources but not in Windows SDK, i.e. `winsta.h`, `KUSER_SHARED_DATA`, ...
  - Import library for Windows DLL exports, i.e. `KERNEL32.dll!CreateProcessInternalW`, `ntdll.dll!LdrRegisterDllNotification`, ...
  - Addendum to Windows SDK
  - Extension macros and definitions, i.e. `NtCurrentPeb()`, `PEB(64/32)`, `TEB(64/32)`, ...
- Specifications
  - SMBIOS
  - CPUID
  - MSVC
- Kits
  - Unit Test Framework

## Usage

![NuGet Downloads](https://img.shields.io/nuget/dt/KNSoft.NDK) ![GitHub Release](https://img.shields.io/github/v/release/KNSoft/KNSoft.NDK)

### TL;DR

Include [NDK.h](./Source/Include/KNSoft/NDK/NDK.h) instead of `Windows.h` will do.
```C
#include <KNSoft/NDK/NDK.h>
```

NuGet package [KNSoft.NDK](https://www.nuget.org/packages/KNSoft.NDK) includes all the headers and compiled libraries.

### Details

Reference following header and library on demand:

- Ntdll Hash API (`(A_SHA/MD4/MD5)(Init/Update/Final)`)
  - [Ntdll.Hash.h](./Source/Include/KNSoft/NDK/WinDef/API/Ntdll.Hash.h)
  - KNSoft.NDK.Ntdll.Hash.lib (Generated from [KNSoft.NDK.Ntdll.Hash.xml](./Source/KNSoft.NDK/WinAPI/KNSoft.NDK.Ntdll.Hash.xml))
- Windows API import library addendum
  - KNSoft.NDK.WinAPI.lib (Generated from [KNSoft.NDK.WinAPI.xml](./Source/KNSoft.NDK/WinAPI/KNSoft.NDK.WinAPI.xml))
- Unit Test Framework
  - [UnitTest.h](./Source/Include/KNSoft/NDK/UnitTest/UnitTest.h)
  - KNSoft.NDK.UnitTest.lib (Generated from [KNSoft.NDK.UnitTest](./Source/KNSoft.NDK.UnitTest/))

To include specified feature, include corresponding header (i.e. [SMBIOS.h](./Source/Include/KNSoft/NDK/Extension/SMBIOS.h) for SMBIOS Specification) instead of the whole [NDK.h](./Source/Include/KNSoft/NDK/NDK.h) is better. To exclude specified feature included by default, define following macros:

| Macro | Exclude feature |
| ---- | ---- |
| _KNSOFT_NDK_NO_EXTENSION | Addendum or extension macros and definitions |
| _KNSOFT_NDK_NO_EXTENSION_CPUID | CPUID Specification |
| _KNSOFT_NDK_NO_EXTENSION_MSTOOLCHAIN | Microsoft Tool chain Specification |
| _KNSOFT_NDK_NO_EXTENSION_SMBIOS | SMBIOS Specification |

## Compatibility

![PR Welcome](https://img.shields.io/badge/PR-welcome-0688CB.svg) ![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/KNSoft/KNSoft.NDK/msbuild.yml)

KNSoft.NDK always keep up with trends:
- Keep up the latest Windows NT and specifications
- Build with the latest Visual Studio (MSVC) and SDK, targets to x86, x64 and ARM64 platforms

**In alpha stage, do not use on production environment.**

## License

![GitHub License](https://img.shields.io/github/license/KNSoft/KNSoft.NDK)

KNSoft.NDK is licensed under the [MPL-2.0 license](./LICENSE).

The content from the following public sources were used:
- Microsoft WDK/DDK/SDK
- Microsoft Public Symbolic Data
- Microsoft Learning
- Microsoft Windows Protocols

KNSoft.NDK also uses [KNSoft/Precomp4C](https://github.com/KNSoft/Precomp4C) to generate DLL import libraries.

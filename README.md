# KNSoft.NDK

[![NuGet Downloads](https://img.shields.io/nuget/dt/KNSoft.NDK)](https://www.nuget.org/packages/KNSoft.NDK) [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/KNSoft/KNSoft.NDK/msbuild.yml)](https://github.com/KNSoft/KNSoft.NDK/actions/workflows/msbuild.yml) ![PR Welcome](https://img.shields.io/badge/PR-welcome-0688CB.svg) [![GitHub License](https://img.shields.io/github/license/KNSoft/KNSoft.NDK)](./LICENSE)

KNSoft.NDK provides native C/C++ definitions and import libraries for Windows NT and some specifications development.

## Feature

- Windows NT
  - Undocumented type definitions, e.g. `PEB`, `TEB`, `LDR_*`, ...
  - Undocumented API declarations, e.g. `Nt/Zw*`, `Ldr*`, ...
  - Definitions in public sources but not in Windows SDK, e.g. `winsta.h`, `KUSER_SHARED_DATA`, ...
  - Import library for Windows DLL exports, e.g. `KERNEL32.dll!CreateProcessInternalW`, `ntdll.dll!LdrRegisterDllNotification`, ...
  - Addendum to Windows SDK
  - Extension macros and definitions, e.g. `NtCurrentPeb()`, `PEB(64/32)`, `TEB(64/32)`, ...
- Specifications
  - SMBIOS
  - CPUID
  - MSVC
- Kits
  - Unit Test Framework
  - StrSafe.h (different from `strsafe.h` in Windows SDK)

## Usage

[![NuGet Downloads](https://img.shields.io/nuget/dt/KNSoft.NDK)](https://www.nuget.org/packages/KNSoft.NDK)

### TL;DR

Include [NDK.h](./Source/Include/KNSoft/NDK/NDK.h) instead of (or **BEFORE**) `Windows.h` will do.
```C
#include <KNSoft/NDK/NDK.h>
```

NuGet package [KNSoft.NDK](https://www.nuget.org/packages/KNSoft.NDK) includes all the headers and compiled libraries.

### Details

The following features are not enabled by default, reference corresponding headers and libraries on demand:

- Specifications
  - CPUID: [CPUID.h](./Source/Include/KNSoft/NDK/Extension/CPUID.h)
  - SMBIOS: [SMBIOS.h](./Source/Include/KNSoft/NDK/Extension/SMBIOS.h)
- Ntdll Hash API (`(A_SHA/MD4/MD5)(Init/Update/Final)`)
  - [Ntdll.Hash.h](./Source/Include/KNSoft/NDK/WinDef/API/Ntdll.Hash.h)
  - KNSoft.NDK.Ntdll.Hash.lib (Generated from [KNSoft.NDK.Ntdll.Hash.xml](./Source/KNSoft.NDK/WinAPI/KNSoft.NDK.Ntdll.Hash.xml))
- Windows API import library addendum
  - KNSoft.NDK.WinAPI.lib (Generated from [KNSoft.NDK.WinAPI.xml](./Source/KNSoft.NDK/WinAPI/KNSoft.NDK.WinAPI.xml))
- Unit Test Framework
  - [UnitTest.h](./Source/Include/KNSoft/NDK/UnitTest/UnitTest.h)
  - KNSoft.NDK.UnitTest.lib (Generated from [KNSoft.NDK.UnitTest](./Source/KNSoft.NDK.UnitTest/))
- Safe string functions (different from `strsafe.h` in Windows SDK)
  - [StrSafe.h](./Source/Include/KNSoft/NDK/Extension/StrSafe.h)

The following features are enabled by default, can be excluded by defining corresponding macro:

| Macro | Exclude feature |
| ---- | ---- |
| _KNSOFT_NDK_NO_EXTENSION | Addendum or extension macros and definitions |
| _KNSOFT_NDK_NO_EXTENSION_MSTOOLCHAIN | Microsoft Tool Chain Specification |
| _KNSOFT_NDK_NO_INLINE | Use inline implementation instead of function call |

## Compatibility

![PR Welcome](https://img.shields.io/badge/PR-welcome-0688CB.svg) [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/KNSoft/KNSoft.NDK/msbuild.yml)](https://github.com/KNSoft/KNSoft.NDK/actions/workflows/msbuild.yml)

KNSoft.NDK always keep up with trends:
- Keep up the latest Windows NT and specifications
- Build with the latest Visual Studio (MSVC) and SDK, targets to x86, x64 and ARM64 platforms

> [!CAUTION]
> In alpha stage, do not use on production environment.

## License

[![GitHub License](https://img.shields.io/github/license/KNSoft/KNSoft.NDK)](./LICENSE)

KNSoft.NDK is licensed under the [MPL-2.0 license](./LICENSE).

The content from the following public sources were used:
- Microsoft WDK/DDK/SDK
- Microsoft Public Symbolic Data
- Microsoft Learning
- Microsoft Windows Protocols

And public projects:
- [NDK (From ReactOS)](https://github.com/reactos/reactos/tree/master/sdk/include/ndk) - MIT
- [winsiderss/phnt](https://github.com/winsiderss/phnt) - CC-BY-4.0

KNSoft.NDK also uses [KNSoft/Precomp4C](https://github.com/KNSoft/Precomp4C) to generate DLL import libraries.

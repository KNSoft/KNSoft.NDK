# AGENTS.md

## Scope
- Applies to the entire repository.
- Goal: deliver safe, minimal, testable changes to `KNSoft.NDK`.
- Priority: keep compatibility with `systeminformer/phnt` semantics while improving structure and alignment with Windows SDK/WDK.

## Quick Start (Read First)
- `README.md`
- `Source/.editorconfig`
- `Source/KNSoft.NDK.sln`
- `Source/Include/KNSoft/NDK/NDK.h`
- `Source/Include/KNSoft/NDK/NT/NT.h`
- `Source/Include/KNSoft/NDK/Win32/API/Ntdll.h`
- `Source/KNSoft.NDK/WinAPI/KNSoft.NDK.WinAPI.xml`
- `Source/KNSoft.NDK/WinAPI/KNSoft.NDK.Ntdll.Hash.xml`
- `Source/KNSoft.NDK/WinAPI/KNSoft.NDK.Ntdll.CRT.xml`
- `Source/UnitTest/Main.c`
- `.github/workflows/Build_Publish.yml`

## Hard Rules
- CRITICAL: Follow `Source/.editorconfig` strictly (encoding, CRLF, formatting, line length).
- CRITICAL: Preserve original file encoding and line endings when editing existing files.
- Keep diffs minimal; do not refactor unrelated code.
- Do not edit generated/build artifacts: `Source/OutDir/`, `Source/**/IntDir/`, `Source/SDK/bin/`, `Source/SDK/obj/`.
- `Source/SDK/3rdParty/C4Lib/` is a submodule dependency; do not modify it unless explicitly requested.
- Maintain API/ABI compatibility for existing declarations:
  - avoid changing struct/union layout, packing, field order, and calling conventions unless required.
  - avoid breaking existing macro names and include contracts.
- For declaration sync work (phnt/SDK/WDK/public symbols), keep source intent and naming consistent; avoid speculative rewrites.
- For `phnt` sync work, sync relevant upstream comments/docblocks together with declarations when they clarify semantics or versioning.
- For `phnt` sync work, translate upstream `PHNT_` version-control guards/macros to this repo's `NTDDI_VERSION`-based gating style.
- Add concise technical comments only when necessary.

## Build and Validate
- Build (single target example):
  - `msbuild .\Source\KNSoft.NDK.sln /restore /m /p:Configuration=Debug /p:Platform=x64 /p:RestorePackagesConfig=true`
- Build (all main platforms):
  - `msbuild .\Source\KNSoft.NDK.sln /restore /m /p:Configuration=Release /p:Platform=x64 /p:RestorePackagesConfig=true`
  - `msbuild .\Source\KNSoft.NDK.sln /restore /m /p:Configuration=Release /p:Platform=x86 /p:RestorePackagesConfig=true`
  - `msbuild .\Source\KNSoft.NDK.sln /restore /m /p:Configuration=Release /p:Platform=ARM64 /p:RestorePackagesConfig=true`
  - `msbuild .\Source\KNSoft.NDK.sln /restore /m /p:Configuration=Release /p:Platform=ARM64EC /p:RestorePackagesConfig=true`
- Run tests:
  - `.\Source\OutDir\x64\Debug\UnitTest.exe -Run`
  - `.\Source\OutDir\x86\Debug\UnitTest.exe -Run`
  - `.\Source\OutDir\ARM64\Debug\UnitTest.exe -Run` (when available)

## Change Routing
- NT native declarations (`Nt/Zw`, kernel/user native types): `Source/Include/KNSoft/NDK/NT/**`
- Win32 API addendum declarations: `Source/Include/KNSoft/NDK/Win32/**`
- Public aggregate entry points/macros: `Source/Include/KNSoft/NDK/NDK.h`, `NDK.Ext.h`, `NDK.inl`
- Import-library generation definitions: `Source/KNSoft.NDK/WinAPI/*.xml`
- MIDL-related virtual desktop interfaces:
  - source: `Source/Include/KNSoft/NDK/Win32/API/ShObjIdl/VirtualDesktop/VirtualDesktop.idl`
  - generated headers in repo: `VirtualDesktop.idl_h.h`, `VirtualDesktop.idl_i.h`
- Package-level helpers (`UnitTest`, `StrSafe`, `ArgParse`, `RandGen`): `Source/Include/KNSoft/NDK/Package/**`
- Validation coverage: `Source/UnitTest/**`
- Build/packaging: `Source/KNSoft.NDK.nuspec`, `Source/KNSoft.NDK.targets`, `Source/Directory.Build*.props`
- SDK tooling/automation: `Source/SDK/**`

## Before Finishing
- Confirm touched headers compile in both C and C++ paths (see `Source/UnitTest/CppCompile.cpp`).
- Recheck cross-arch impact (`x86`, `x64`, `ARM64`, `ARM64EC`), especially pointer-size-dependent definitions.
- For import library changes, ensure corresponding XML edits are intentional and consistent with expected exports.
- If tests/build were not run, state that explicitly in the final report.

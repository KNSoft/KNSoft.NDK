# AGENTS.md

This repository supplements low-level definitions not provided by the Windows SDK. It is primarily adapted from [phnt](https://github.com/winsiderss/systeminformer/tree/master/phnt), with additional extension definitions, import libraries, and native function libraries.

## Workflow

### phnt Sync

This workflow synchronizes declaration changes from `phnt` into this repository.

The goal is not to mirror `phnt` mechanically. This repository exists to provide definitions that the Windows SDK does not provide, and to expose selected kernel-mode definitions for user-mode use when appropriate. Keep that goal in view while synchronizing, and preserve support for x86, x64, ARM64, and ARM64EC.

#### Rule

- Upstream is the [phnt](https://github.com/winsiderss/systeminformer/tree/master/phnt) directory. Ignore upstream changes outside `phnt`.
- Except for the exclusions below, synchronize upstream declaration changes, together with relevant comments or docblocks that clarify their semantics or versioning. Ignore phnt-local project/build files such as `phnt/meson.build`.
- A commit in this repository with a message like `[SYNC] Sync phnt` and a URL to the upstream commit indicates that this repository is synchronized through that upstream commit.
- Windows SDK headers are located in the highest version-numbered directory under `%ProgramFiles(x86)%\Windows Kits\10\Include`; `um` contains headers available in user mode, `km` contains headers available in kernel mode, and `shared` contains headers available in both.
  - If a definition is already available from `um` or `shared`, do not synchronize it.
  - If a definition is available only from `km`, use the Windows SDK definition as the source of truth and synchronize that user-mode-accessible form instead.
- `phnt` provides its own `phnt_ntdef.h`, while this repository's `MinDef.h` includes the Windows SDK `windef.h` and `ntdef.h` and resolves conflicts between them. Do not assume changes in `phnt_ntdef.h` map directly to `MinDef.h`; evaluate them against the Windows SDK-based model used here before synchronizing.
- `ZwApi.h` is auto-generated, so changes to system calls whose names begin with `Zw` do not need to be synchronized.
- Translate upstream `PHNT_` version-control guards/macros to this repo's `NTDDI_VERSION`-based gating style.

#### How to sync

- Use the upstream commit URL in the latest local `[SYNC] Sync phnt` commit as the current sync base. For the next sync, review in-scope changes under `phnt` from that upstream commit, exclusive, through the target upstream commit, inclusive.
- Identify what changed, usually macros, structs, function declarations, typedefs, or nearby explanatory comments.
- For each definition, first decide whether it belongs in this repository under the goal above and the SDK rules above.
- Use each definition's name, purpose, and nearby symbol names in context to locate the best matching file and position in this repository. `phnt` often keeps definitions in large files, while this repository splits them into smaller files, so synchronize by declaration meaning rather than by upstream file layout. For example, `ntrtl.h` changes may land across `NT/Rtl/**`, and `ntimage.h` changes may belong in either `NT/Image.h` or `NT/Rtl/Image.h`.
- When synchronization adds, removes, or renames a public header, or adds a public Win32 declaration in this repository, also update the related repository wiring as needed, such as aggregate includes, Visual Studio project entries, or import-library XML definitions.
- Do not synchronize anything you are uncertain about; collect those items in `Sync.Todo.md`.
- After synchronization is complete, ensure that the `UnitTest` project builds successfully, with cross-platform impact considered for x86, x64, ARM64, and ARM64EC.
- Record the completed synchronization with a `[SYNC] Sync phnt` commit whose body includes the target upstream commit URL.

# AGENTS.md

This repository supplements low-level definitions not provided by the Windows SDK. It is primarily adapted from [phnt](https://github.com/winsiderss/systeminformer/tree/master/phnt), with additional extension definitions, import libraries, and native function libraries.

## Workflow

### phnt Sync

This workflow synchronizes declaration changes from `phnt` into this repository.

The goal is not to mirror `phnt` mechanically. This repository exists to provide definitions that the Windows SDK does not provide, and to expose selected kernel-mode definitions for user-mode use when appropriate. Keep that goal in view while synchronizing, and preserve support for x86, x64, ARM64, and ARM64EC.

#### Rule

- Upstream is the [phnt](https://github.com/winsiderss/systeminformer/tree/master/phnt) directory. Ignore upstream changes outside `phnt`.
- Except for the exclusions below, synchronize upstream declaration changes, together with relevant comments or docblocks that clarify their semantics or versioning. Ignore phnt-local project/build files such as `phnt/meson.build`.
- If an upstream commit only modifies an existing `phnt` declaration that this repository has never carried, do not add that declaration merely because it changed upstream. Synchronize it only when the declaration itself is newly introduced upstream, or when it is already present in this repository and remains in scope here.
- If a definition is not provided by the Windows SDK and this repository already carries the same definition as `phnt`, continue following later upstream changes to that definition. If this repository already differs from `phnt`, determine why before changing it rather than assuming the upstream form should replace the local one.
- A commit in this repository with a message like `[SYNC] Sync phnt` and a URL to the upstream commit indicates that this repository is synchronized through that upstream commit.
- Windows SDK headers are located in the highest version-numbered directory under `%ProgramFiles(x86)%\Windows Kits\10\Include`; `um` contains headers available in user mode, `km` contains headers available in kernel mode, and `shared` contains headers available in both.
  - If a definition is already available from `um` or `shared`, do not synchronize it.
  - If a definition is available only from `km`, normally use the Windows SDK definition as the source of truth and synchronize that user-mode-accessible form instead.
  - If `phnt` keeps the same underlying definition but exposes strictly richer structure or naming than the `km` header, prefer the richer `phnt` form when it is still compatible with the SDK definition and useful to this repository. For example, a `km` `LONGLONG FileReference` field may be synchronized as phnt's compatible union that also exposes `MftRecordIndex` and `SequenceNumber`.
- Apply the Windows SDK rule above before considering any upstream source-specific handling. In particular, `phnt` provides its own `phnt_ntdef.h`, while this repository's `MinDef.h` includes the Windows SDK `windef.h` and `ntdef.h` and resolves conflicts between them. Do not assume changes in `phnt_ntdef.h` map directly to `MinDef.h`; only consider them after confirming that the corresponding definition is not already provided by the Windows SDK.
- `win32k`-related native declarations are in scope when they satisfy the repository goal above; do not exclude them merely because they are graphics/window-manager related.
- When synchronization introduces a new upstream header, do not mirror its include graph mechanically. Apply the Windows SDK rule first, keep SDK-provided definitions as the source of truth, and introduce only the declarations and minimal dependencies actually needed in this repository.
- If upstream adds or changes inline implementations for APIs whose standard Windows SDK form is an exported function declaration, keep the SDK-style declaration in the corresponding `.h` file. When the inline implementation is useful and this repository has a matching `.inl` file, adapt the implementation there instead, following the existing `_Inline_` naming/style used by this repository. Preserve relevant upstream comments in the `.h` declaration file.
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

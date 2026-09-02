# Component-Based Servicing analysis

## Scope

This document describes the private CBS ABI exposed by `CbsCore.dll`, `CbsApi.dll`, `CbsProvider.dll`, and
`wcp.dll`. The analysis used the x86 and x64 binaries from Windows build 26100.9156. It is not a compatibility
contract for other Windows builds.

Only x86 and x64 were compared. ARM64 and ARM64EC are outside this analysis.

Confidence terms used below:

- **Confirmed**: x86 and x64 control flow, call sites, parameter widths, and observable constants agree.
- **High confidence**: symbols, logs, data flow, and cross-module callers agree, but only one implementation owns
  the behavior.
- **Unknown**: only the ABI slot, parameter count, or parameter width is known. The header intentionally preserves
  an `Unknown` name.

The headers expose confirmed and high-confidence ABI facts. Build-specific behavior and unresolved semantics stay
in this document.

## Architecture

| Module | Role |
| --- | --- |
| `CbsApi.dll` | COM proxy/stub. It marshals CBS interfaces and does not implement the servicing engine. |
| `CbsCore.dll` | CBS object model, session and package planning, lifecycle processing, public COM wrappers, and most policy checks. |
| `CbsProvider.dll` | DISM-facing adapter. It translates DISM feature/package requests into CBS session, update, and package calls. |
| `wcp.dll` | CSI/WCP component-store and manifest transaction engine used by CBS. |

The practical call chain is:

```text
DISM/provider client
    -> CbsProvider.dll
    -> CbsCore.dll public COM wrappers
    -> CBS planning/execution objects
    -> WCP/CSI store and transformer APIs
```

`CbsCore.dll` also loads WDS, KTM, DPX, DrUpdate, CfgMgr32, System Restore, TurboStack, and TurboContainer support.
Initialization unwinds already-created managers and loaded modules if a later step fails.

## ABI, allocation, and caller context

- CBS COM interfaces use the ordinary `IUnknown` prefix and native pointer-size layout. The C structs containing
  only `lpVtbl` match MIDL-generated C interface layout.
- Enum and `BOOL` values occupy 32 bits on both examined architectures.
- Public strings and enumerator elements are copied with the task allocator supplied to `CbsCoreInitialize`.
  Callers must release returned allocations through the matching allocator contract.
- Interface enumerators retain elements with `AddRef`. String and structure enumerators deep-copy their elements.
- Mutation paths commonly capture the caller's impersonation token and verify administrative membership. A caller
  running inside an administrative process can still fail when the active impersonation token is not administrative.
- Session and package objects use internal critical sections. This protects object state; it does not make arbitrary
  concurrent mutations valid.
- Only one active offline session is registered at a time.
- Private CBS ABI is build-specific. A matching parameter width does not prove a stable semantic contract.

## CbsCore lifecycle exports

### `CbsCoreInitialize`

Confirmed parameter order:

1. task `IMalloc`;
2. `LockProcess`, returning an HRESULT-compatible 32-bit value and receiving a 32-bit options value;
3. `UnlockProcess`;
4. instance-created notification;
5. instance-destroyed notification;
6. optional immediate-shutdown notification;
7. required shutdown-processing notification;
8. class-factory output.

The examined core calls `LockProcess(0)`. Its return value is propagated by the CSI-store lock helper, so declaring
the callback as `BOOL` loses error semantics. The unlock and notification callbacks are parameterless.

Initialization installs the allocator and callbacks, creates the execution engine and managers, initializes WCP,
and returns the CBS class factory. The factory rejects aggregation with `CLASS_E_NOAGGREGATION`. Direct creation
accepts `IID_IUnknown` or `IID_ICbsSession`; later session revisions are obtained through `QueryInterface`.

### `CbsCoreFinalize`

Finalization tears down the execution engine, capability/session managers, WCP state, events, modules, allocator,
and callbacks. Cleanup continues after an intermediate failure. The returned HRESULT is the retained engine
finalization result.

### Startup processing

`CbsCoreStartupProcessing(SafeMode)` calls `CbsCoreStartupProcessingEx` with:

- normal startup: `CBS_CORE_STARTUP_OPTION_UNKNOWN1` (`0x1`);
- safe-mode startup: `CBS_CORE_STARTUP_OPTION_UNKNOWN1 | CBS_CORE_STARTUP_OPTION_SAFE_MODE` (`0x5`).

Confirmed `CbsCoreStartupProcessingEx` bits:

| Bit | Meaning |
| --- | --- |
| `0x1` | Always supplied by the simple wrapper; its independent semantic meaning remains unknown. |
| `0x2` | Requests recovery processing. |
| `0x4` | Selects CBS safe-mode processing. Internally this maps to core mode 8, whose own text form is `SafeMode`. |

`CbsCoreEnsureNoStartupProcessing(SafeMode)` reads `PostponeOnlineActions`. In safe mode it records safe-mode
handling. Outside safe mode, unless the property equals 1, it schedules a component-store consistency check. A
property-read failure is treated as value 0, and the export returns success after applying that behavior.

### Shutdown processing

`CbsCorePrepareShutdownProcessing(Service, Options)`:

- reads `PreshutdownTimeout`, defaulting to 1,800,000 milliseconds;
- reads `BlockTimeIncrement`, defaulting to 900 seconds, and converts it to milliseconds;
- calls `ITrustedInstallerService::RequestAdditionalTime` with the preshutdown timeout;
- creates a manual-reset event and a progress thread;
- is idempotent when preparation already exists.

The `Options` parameter is present in the ABI but unused in the examined build.

`CbsCoreFinalizeShutdownProcessing` signals the event, waits for the progress thread, and releases the shutdown
state.

`CbsCoreShutdownProcessing(Service, SafeMode)` evaluates deferred work, active servicing, sleep prevention,
reboot-in-progress state, outstanding sessions, smart-pended transactions, advanced installers, primitive
operation queues, drivers, rollback, and required reboot state. The second parameter is a safe-mode selector, not
a wait flag.

### Idle servicing

`CbsCoreServiceIdleProcessing(Enable, Completed)` has two modes:

- `Enable != FALSE`: run idle maintenance repeatedly until stopped. It waits for no active session, identifies the
  client as `CbsTask`, and performs maintenance operation 0.
- `Enable == FALSE`: perform a one-shot scavenge. The client is `CbsAuto` for automatic scavenging and `Manual`
  otherwise; maintenance type 3 or 4 is selected accordingly.

The output reports completion, not a snapshot of whether the engine is idle.

`CbsCoreStopIdleProcessing` signals the stop event and pauses the idle loop.

`CbsCoreIsExecutionEngineIdle` is only a snapshot. It returns true when four internal activity counters/flags are
all zero; it does not reserve the engine or prevent a new operation.

### Session-creation notification

`CbsCreateSessionNotifyInitialize` reads the blocking policy. The default total block time is 10,800 seconds and
the default increment is 900 seconds. `CbsCreateSessionNotifyFinalize` frees the cached progress text and state.

`CbsCreateSessionNotify` returns a notification and an optional allocator-owned progress message:

| Value | Meaning |
| --- | --- |
| `1` | Startup is complete, or the timeout elapsed without recovery; allow logon. |
| `2` | Startup remains active; keep waiting without text. |
| `3` | Startup remains active; keep waiting and display the returned text. |
| `4` | Startup timed out and restart recovery is required. |

`ITrustedInstallerService::GetLastSleepTickCount` supplies the most recent sleep tick count. CBS excludes sleep time
from the blocking timeout calculation.

### Other exports

| Export | Behavior and boundary |
| --- | --- |
| `CbsCoreGetActiveOfflineSession` | Returns the registered offline session; returns `E_UNEXPECTED` when the session manager is unavailable. |
| `CbsCoreLoadComponentStore` | Locks CSI and lazily loads `HKLM\COMPONENTS` from `System32\Config\COMPONENTS`; sharing failures are retried. |
| `CbsCoreNotifyAllowingUserLogin` | Reports and removes the reboot CV records used around user-logon blocking. |
| `CbsCoreSetCustomLogging` | Stores a caller-owned `void (ULONG, PCSTR)` callback. The caller must keep it valid until replacement or finalization. |
| `CreateCbsRegBackupHelper` | Allocates the registry-backup COM helper. |
| `SetRebootInProgressFlag` | Creates the CBS `RebootInProgress` key idempotently. |
| `SetTestMode` | Sets the process-global CBS test-mode flag. |

## `CbsCoreSetState`

`Value` is intentionally `ULONG_PTR`: its interpretation depends on `State`.

| State | `Value` interpretation and behavior |
| --- | --- |
| 0 | Parameterless require-reboot callback. |
| 1 | Parameterless revoke-shutdown-processing callback. |
| 2 | Unsupported in the examined build; returns `E_INVALIDARG`. |
| 3 | Parameterless callback returning `BOOL` for reboot-required state. |
| 4 | Parameterless callback returning `HRESULT` for anticipated shutdown processing. |
| 5 | Parameterless register-Winlogon-notification callback. |
| 6 | Unregister-Winlogon-notification callback receiving one 32-bit value. |
| 7 | Finalizes the execution engine and capability manager; `Value` is ignored. |
| 8 | Clears the global offline flag and returns CBS to online mode; `Value` is ignored. |
| 9 | Parameterless all-pended-operations-canceled callback. |
| 10 | Timeout used while waiting for outstanding sessions. The wrapper returns `S_OK` after the wait path. |

The callback typedefs in `CbsCore.h` cover the distinct return types. Callers must not treat every state value as a
function pointer with the same prototype.

## Identity

`ICbsIdentity` owns the canonical five-part CBS identity:

```text
name~publicKeyToken~processorArchitecture~language~version
```

Behavior:

- `Clear` resets the identity.
- `IsNull` reports whether no identity is loaded.
- `IsEqual` compares through the private identity representation.
- `LoadFromAttributes` validates the name, a 16-hex-digit public-key token, architecture, normalized language, and
  a four-part version whose components do not exceed 65535.
- `LoadFromStringId` parses the canonical form, including moniker forms beginning with `@`.
- `SaveAsStringId` allocates the canonical string with the task allocator.

Token and architecture text are normalized to lowercase. Language normalization follows CBS/WCP rules rather than
performing a byte-for-byte copy.

## Sessions

### Interface revisions

| Interface | Added capability |
| --- | --- |
| `ICbsSession` | Initialize/finalize, create/open/enumerate packages, and create identities. |
| `ICbsSession7` | Status, resume, session ID, properties, `FinalizeEx`, and an unimplemented phase-break slot. |
| `ICbsSession8` | Session-level sources and UI-handler registration. |
| `ICbsSession9` | Windows Update packages, capabilities, external transformers, observation, activities, and enhanced options. |
| `ICbsSession10` | Configurable properties and explicit operations. |

### Initialization and finalization

`Initialize` forwards to `InitializeEx` without an external directory. `InitializeEx` validates paths, option
combinations, compression settings, and object state. It registers an offline session when offline paths are
provided and initializes online OneSettings state otherwise. A special lazy DISM path exists, but it does not
remove the one-active-offline-session restriction.

`Finalize` forwards to `FinalizeEx(0)`. `FinalizeEx` requires a `CBS_REQUIRED_ACTION` output and rejects a read-only
observer session. `CBS_SESSION_FINALIZE_OPTION_CANCEL_PENDING` requests cancellation of pending work only when every
queued operation is cancellable. Finalization plans tasks, persists required store operations, invokes
shutdown-related callbacks, and returns the required reboot action.

### Package construction

- `CreatePackage` accepts the package types declared in `CBS_PACKAGE_TYPE`. Expanded package paths are normalized;
  XML-string and manifest forms follow separate construction paths.
- `OpenPackage` resolves an existing package by identity, with an optional package path.
- `EnumeratePackages` accepts only the mask `0xFF0` in the examined build.
- `CreateWindowsUpdatePackage` stores the optional Windows Update application ID and attaches the update GUID plus
  revision number to the package. The remaining package-path, sandbox, decryption-data, and encryption arguments
  feed the ordinary internal package creator.
- `CreateCbsIdentity` returns an empty allocator-backed identity object.

### Status, resume, and observation

`GetStatus` returns phase, last successful session state, completion, and servicing HRESULT as independent outputs.
`GetSessionId` returns an allocator-owned ID. `Resume` attaches an optional UI handler and continues a persisted
session.

`RegisterCbsUIHandler` retains the handler and replays a cached `ICbsUIHandler8` stage when one exists.
`SetEnhancedOptions` stores the enhanced planning options used by later session work; the servicing-processor bit
mappings documented below are the confirmed external inputs to this method. `CreateExternalTransformerExecutor`
obtains the CSI store interface and returns the session-bound transformer wrapper described later.

`ObserveSessions` is read-only and accepts only:

- `0x10`: enumerate active in-memory sessions;
- `0x20`: load persisted pending sessions from `Sessions.xml`.

An optional listener is retained or replaces the previous listener. Registration immediately reports the session
as `CbsSessionStateQueued`. Subsequent transitions call
`ICbsSessionObserverListener::OnSessionStateChanged(ICbsSession9*, CBS_SESSION_STATE)`.

Observer sessions expose status and query methods. Mutation methods return `E_NOTIMPL`.

### Session properties

`GetProperty` returns strings. Numeric values are formatted as decimal text.

| Values | Behavior |
| --- | --- |
| 1-7 | Reboot, error, serviceability, compression, report, corruption, and repair state. |
| 8-11 | Four 64-bit component-store size measures. |
| 12 | Last-scavenge timestamp. |
| 13 | Superseded-package count. |
| 14 | Cleanup recommendation. |
| 15 | Session-completion timestamp. |
| 16-17 | Two package minimum-size totals. For eligible queued package tasks they sum distinct internal size fields. Their precise public distinction remains unknown. |
| 18 | Rejected by the examined build. It is intentionally absent from the header enum. |
| 19 | Features to retry. |
| 20 | FOD retry state. |
| 21 | LCU reoffer state. |
| 22 | Repair-needed state. |
| 23-25 | Shutdown, reboot, and post-reboot durations. |
| 26 | Accepted, but the exact semantic meaning remains unknown. |
| 27 | LCU pending state. |
| 28 | Deep-reoffer state. |
| 29 | `UpdateAgent.dll` path. |
| 30 | Sorted `FodMetadata\metadata\*.XML` paths; feature-gated. |
| 31 | Sorted component-database XML paths for installed packages; feature-gated. |
| 32 | Repair MFL path. |
| 33 | Repair MFL generation completion state. |

### Configurable properties

`SetProperty` accepts values 1 through 19 and requires an administrative caller.

- Properties 1, 2, and 5 normalize path text; property 6 stores its path form without that normalization.
- Property 1 is the local UUP repository.
- Property 10 is the active container transaction ID.
- Properties 11, 12, and 13 split semicolon-delimited values and enqueue distinct internal state collections. Their
  public semantic labels remain unknown.
- Properties 14 through 19 are retained by the current implementation, but their consumers and public meanings are
  not established.

No names are assigned to values whose storage alone does not prove meaning.

### Explicit operations

`PerformOperation(Options, Operation)` permits the following values:

| Value | Behavior |
| --- | --- |
| 0 | No operation. |
| 1 | Export repository. |
| 2 | Update image. |
| 3 | Prepare servicing. |
| 4 | Late acquisition. |
| 5-7 | Accepted and persisted, but no execution branch exists in the examined build. |
| 8 | Initialize the CSI store immediately. |
| 9 | Create `ReservesRebootPending`, configure TrustedInstaller for automatic start, and persist the operation. |
| 10 | Offline finalize installation; feature-gated. |
| 11 | Offline rollback installation; feature-gated. |
| 12 | Generate the repair file list. |
| 13 | Perform repair using external content. |

Only one pending explicit operation may be stored on a session. Attempting to overwrite it returns an invalid-
argument failure.

### Capabilities and activities

`EnumerateCapabilities` accepts the low ten source-filter bits. Bit `0x40` selects language-pack capability handling.

`GetActivities` returns:

- type 1: package task;
- type 2: update/feature task;
- type 3: capability task.

The identity and install-state fields are mapped from the queued task. Two extra strings are populated for some
capability tasks, but their exact contract is not established and remains `Unknown1`/`Unknown2`.

## Packages

### Properties

Most package properties are stored metadata or are localized through the session. Four previously unnamed values
have direct, confirmed implementations:

| Value | Behavior |
| --- | --- |
| 49 | Calls `IsMumServicingLCUPackage` and returns `"1"` or `"0"`. |
| 50 | Returns `"1"` when the current internal state is at least Installed (112), otherwise `"0"`. |
| 54 | Calls `IsLanguageSatellitePackage`. |
| 55 | Calls `IsArchSatellitePackage`. |

Values 36, 37, 40, and 48 remain unnamed because the examined conversion and access paths do not establish a
stable public meaning.

`GetIdentity` returns the package identity with `AddRef`; it does not serialize or copy the identity string.

### Sources and updates

- `AddSource` stores a package source. Adding an existing source returns the positive CBS status `0x000F0802`.
- `RemoveSource` removes and persists the source list.
- `EnumerateSources` returns deep-copied strings.
- `EnumerateUpdates` rejects read-only package wrappers, resolves parent-package relationships, and reports missing
  or duplicate update declarations as CBS errors. Applicability and selectability are bitmask filters; zero selects
  all values.
- `GetUpdate` resolves one named update from the package.

### Applicability and change initiation

`EvaluateApplicability` produces the applicable target state and current state. `InitiateChanges` validates the
caller, session state, target state, package lifecycle, and option mask before queuing work.

Confirmed public masks:

- package changes: `0x001DC17F`;
- capability changes: `0x0001007F`.

Package target states accepted by the examined build are `-16`, `0`, `2`, `4`, `5`, `7`, and `8`. Administrative
membership is required. `CBS_PACKAGE_CHANGE_OPTION_TREAT_PACKAGE_AS_PSFX` (`0x8000`) is accepted only for offline
servicing.

Confirmed internal option behavior:

- `0x200` selects partial staging. The action-list partial-stage path combines it with `0x80000`.
- `0x80000` participates in baseline handling, but its independent public meaning is not proven.
- `0x100` participates in rebase/baseline installation, but its independent meaning is not proven.
- `0x100000` identifies non-baseline FOD or language-pack installation.
- session `NoPend` processing clears package option `0x4`.

The remaining bits intentionally retain `UNKNOWN` names.

### Why the provider passes `5`

The DISM feature path supplies package option `1`. `CbsProvider.dll` then enters its internal package-state helper,
which ORs option `4` before calling `ICbsPackage::InitiateChanges`. The resulting value is exactly:

```c
CBS_PACKAGE_CHANGE_OPTION_UNKNOWN1 | CBS_PACKAGE_CHANGE_OPTION_UNKNOWN4
```

x86 and x64 both perform this sequence. Feature enable first queues the update for Install Requested (`6`) and then
queues the package for Installed (`7`). Disable uses package target Default (`-16`). The presence of bits `1` and
`4` is confirmed; their independent semantic labels are not. Defining a single named flag for decimal `5` would
hide the actual composition and overstate what is known.

### Resources and status

`ResourcesToCheck` accepts:

| Value | Result |
| --- | --- |
| 1 | Enumerates files in use. |
| 2 | Enumerates services that must stop. |
| 3 | Identified internally as `CbsResourceTypeProcess`, but returns `E_NOTIMPL`. |
| other | Returns an unexpected/invalid CBS failure. |

Manifest-only and dead package objects reject the query. `Status` returns the current progress state and the last
servicing error separately.

## Updates

`ICbsUpdate` behavior:

- `GetProperty` supports values 1 through 7. Values 4 and 6 are real stored fields, but the internal property-name
  conversion rejects them; they remain unknown. No value 8 is exposed.
- localized display text is obtained under the captured caller context and copied with the task allocator.
- `GetPackage` returns the owning package.
- `GetParentUpdate` enumerates parent update/set relationships. The parent-set string is optional.
- `GetCapability` returns applicability and selectability.
- `GetDeclaredSet` returns `E_NOTIMPL` in the examined build.
- `GetInstallState` returns current, intended, and requested states. A type-5 deployment without an intended state
  maps the intended state to Resolved.
- `SetInstallState` accepts only option bit `0x1` and maps Cancel (`-18`), Default (`-16`), Uninstall Requested (`5`),
  and Install Requested (`6`) into the internal planning state. It requires an administrative caller.

## Capabilities

Capabilities reuse the package-shaped interface but only part of that surface is implemented.

- `GetCapability` returns namespace, language, architecture, major version, and minor version.
- `GetDependencies` returns capability-interface dependencies.
- `GetSources` returns the capability source filter.
- `GetDownloadSize`, `GetInstallSize`, and `GetInstallState` are implemented. Install size accounts for reserved
  content and can include a doubled reserve contribution.
- Package-style sources, status, and resource queries return `E_NOTIMPL` in the examined build.
- Change initiation uses the capability mask `0x0001007F`, the same target-state restrictions, and the same
  administrative check as package changes.
- `ICbsCapability2::EnumerateFeaturePackages` returns `E_NOTIMPL`; no feature-package implementation is created.
  Consequently, the ABI-only `ICbsFeaturePackage::GetProperty` slot has no reachable producer to establish its
  property enum or behavior.

`GetOwnerInformation(Options, IsSelfOwned, OwnerCount, OwnerCapabilities)` ignores `Options` in the examined build.
It resolves packages depending on the capability, verifies that each external owner package declares a capability,
deduplicates owner capability identities case-insensitively, and returns them as a semicolon-delimited string.

- No internal package or an absent capability returns an empty string, `FALSE`, and count 0.
- A present internal package makes `IsSelfOwned` true.
- `OwnerCount` is the number of unique external owner capability identities plus one for the internal package.
- The returned list contains external owner capability identities only; the internal package is represented by the
  boolean/count, not repeated in the string.

## Custom information

`ICbsCustomInformation` represents the custom XML subtree attached to CBS metadata.

- `GetProperty` accepts option bits 0 and 1. Raw XML is available only at the root; namespace/name lookup is used
  for ordinary properties.
- `SetProperty` returns `E_NOTIMPL`.
- `GetSelfInformation` returns the element namespace and name.
- `EnumerateCustomProperties`, `EnumerateChildElements`, and `GetChildElement` expose copied metadata.
- A missing element/property maps to `HRESULT_FROM_WIN32(ERROR_NOT_FOUND)`.

Some private implementations assume non-null output pointers because the public wrapper performs validation first.

## UI handler protocol

The final output of `Initiate`, `Error`, `ResolveSource`, `Progress`, and `ProgressEx` is not a Boolean cancel flag.
It is a 32-bit response value:

| Value | Meaning |
| --- | --- |
| 1 | Continue. |
| 2 | Cancel; CBS maps this to its user-cancel error. |
| 3 | Abort; CBS maps this to a client-abort path. |
| 4-5 | Accepted as continue/no-op by the examined progress path; exact public names remain unknown. |
| `0x1000` | Normal priority. |
| `0x1001` | User-present priority. |
| `0x1002` | User-away priority. |

`Progress` rate-limits callbacks, caps ordinary progress, and recognizes internal sentinel counts `-1`, `-2`, and
`-3`. `EnteringStage` is available only through `ICbsUIHandler8`; the current stage is cached and replayed to a newly
registered handler. Download-stage failure has a dedicated error path.

`Terminate` retries a failing client callback once after one second. CBS does not retry indefinitely.

## Servicing processor

`ICbsServicingProcessor` is the action-list entry point used by higher-level servicing code.

### `Process`

Confirmed signature:

```text
Process(
    Options,
    ActionListPath,
    SandboxPath,
    ClientId,
    WindowsDirectory,
    UIHandler,
    RequiredAction,
    SessionId)
```

`ActionListPath`, `SandboxPath`, `ClientId`, `RequiredAction`, and `SessionId` are required.
`WindowsDirectory` and `UIHandler` are optional. A boot drive is derived from the Windows directory when supplied.

The method captures the caller token, requires an administrator, initializes a CBS session, registers the UI
handler, applies priority/enhanced options, returns the session ID, processes the action list, and finalizes the
session. Option `0x1000` can delegate to an up-level servicing stack.

Accepted option mask: `0x773F`.

| Bit | Confirmed behavior |
| --- | --- |
| `0x1`, `0x2`, `0x4`, `0x8`, `0x10` | Accepted and consumed by session/finalization paths, but independent public names are not fully established. |
| `0x20` | Copies the action list to the session store as `ActionList.xml` and schedules Late Acquisition. |
| `0x100` | User-present UI priority. |
| `0x200` | User-away UI priority. |
| `0x400` | Stage only. |
| `0x1000` | Hydrate only. |
| `0x2000` | Disable the parallel hydrator. |
| `0x4000` | SSU only; processing stops after the SSU pass. |

Stage-only and hydrate-only are mutually exclusive. Hydrate-only is also rejected with `0x2000`.

Additional confirmed data flow:

- bit `0x8` maps to enhanced session option `0x100000`;
- bit `0x10` maps to finalize option `0x200` and requests UI termination on validation failure;
- bit `0x2` contributes session option `0x02000000`;
- bit `0x4` contributes session option `0x100`.

Those mappings are recorded without assigning unsupported semantic names to the source bits.

### `QuerySessionStatus`

The input is a session ID and the output is the servicing status HRESULT. The method loads a persisted session with
the `LoadPersisted` option and calls `GetStatus`. If the session object is missing, a feature-gated path recovers a
completed status from `Sessions.xml`.

The method's own HRESULT reports whether the query succeeded. The output `Status` reports servicing success or
failure. When the stored status is success but the session is incomplete, the output is
`HRESULT_FROM_WIN32(ERROR_INSTALL_SUSPEND)`.

### `WritePackageFileList`

Confirmed signature:

```text
WritePackageFileList(
    Options,
    ActionListPath,
    SandboxPath,
    ClientId,
    WindowsDirectory,
    PackagePath,
    FileListPath)
```

All strings except `WindowsDirectory` are required. The method captures and duplicates the caller token, requires an
administrator, creates a separate session, applies UI priority, normalizes paths, and calls the action-list missing-
file-list generator.

Accepted option mask: `0x0BC0`.

| Bit | Confirmed behavior |
| --- | --- |
| `0x40` | Multiple packages. |
| `0x80` | Accepted; exact meaning remains unknown. |
| `0x100` | User-present UI priority. |
| `0x200` | User-away UI priority. |
| `0x800` | Baseline MFL only; generates the baseline package file list from the container. |

`0x40` and `0x800` are mutually exclusive.

## Registry backup helper

The corrected method parameters are image roots, not arbitrary source/destination paths:

- `Backup(RootDirectory, WindowsDirectory)`;
- `Restore(RootDirectory, WindowsDirectory)`;
- `Delete(WindowsDirectory)`;
- `BackupExists(WindowsDirectory, Exists)`.

The helper enables the required registry privileges and covers:

- root-relative hive: `Users\Default\ntuser.dat`;
- Windows hives: `COMPONENTS`, `DEFAULT`, `DRIVERS`, `SAM`, `SECURITY`, `SOFTWARE`, `SYSTEM`, and `schema.dat`.

Backup writes to `CbsTemp\{GUID}`, flushes the hives, and atomically moves the completed directory to
`CbsTemp\RegBackup`. Restore, delete, and existence checks operate on that fixed image-relative backup location.

## External transformer and WCP

`ICSIExternalTransformerExecutor` is a CBS wrapper around the WCP external transformer. CBS locks the CSI store for
each forwarded operation and retains the session/execution objects needed by the wrapper.

Confirmed parameter meanings:

- `Initialize(Options, Version, WindowsDirectory, PseudoWindowsDirectory, Unknown5)`;
- `Install(ManifestPath, TransformId)`;
- `Uninstall(ManifestPath, TransformId)`;
- `Commit(UserSid, Unknown2, Unknown3, Unknown4)`.

The transform ID name is confirmed by WCP's own trace path. `Commit` validates a supplied SID. The remaining commit
strings participate in optional registry/profile mapping, but their individual roles are not sufficiently isolated
to publish names.

CBS offline servicing builds:

```text
WinSxS\TEMP\TransformerRollbackData\PseudoWindows
```

It initializes WCP with options `0xA` or `0xE`, version 0, the Windows directory, the pseudo-Windows directory, and a
null final argument. Manifests are queued from `WinSxS\manifests\<key>.manifest`, then committed.

Confirmed WCP initialization bits:

| Bit | Internal behavior |
| --- | --- |
| `0x2` | Offline creation/commit mode. |
| `0x4` | Open an existing offline store and enable pseudo-Windows handling. |
| `0x8` | Use the second path as the pseudo-Windows target and load the offline hive. |
| `0x20` | Skip the registry-setup branch. |
| `0x40` | Bind the preloaded `\Registry\Machine\$OFFLINE_RW$COMPONENTS` hive. |

WCP transformer phases are uninitialized (0), initialized (1), queued (2), and committed (3). `Install` queues
action 1 and `Uninstall` queues action 2. x86 and x64 agree on the argument order and state transitions.

## Enumerators

CBS enumerators implement ordinary COM semantics:

- `Next` returns up to the requested count and reports the fetched count;
- `Skip`, `Reset`, and `Clone` preserve the current logical collection;
- interface arrays retain COM references;
- strings and `CBS_ACTIVITY`/`CBS_CUSTOM_PROPERTY` values are deep-copied with the configured allocator.

`IEnumCbsFeaturePackage` has only `Next`, `Skip`, and `Reset`. It has no `Clone` slot. Its producer is currently
unimplemented.

## Known unimplemented and opaque surfaces

Confirmed `E_NOTIMPL` methods in the examined build:

- `ICbsUpdate::GetDeclaredSet`;
- `ICbsCapability2::EnumerateFeaturePackages`;
- `ICbsCustomInformation::SetProperty`;
- `ICbsSession7::AddPhaseBreak`;
- package-shaped source/status/resource operations on capabilities;
- process resource enumeration.

`ICbsWorker`, `ICbsWorker2`, `IWimFileFetcherSandbox`, and `IFodHelperComObject` are implemented outside the examined
CBS core or have no reachable implementation in these binaries. Their vtable slot order and parameter ABI are
retained, but semantic names are not published.

`ITrustedInstallerService` is likewise implemented by the service host. Two methods are nevertheless confirmed by
their CbsCore callers on both architectures:

- slot 9 after the named CBS method sequence: `RequestAdditionalTime(ULONG TimeoutMilliseconds)`;
- slot 14: `GetLastSleepTickCount(PULONGLONG TickCount)`.

All other service slots remain `Unknown`.

## Error and state boundaries

- Null required outputs generally return `E_POINTER`; invalid enums/options generally return `E_INVALIDARG` or a
  CBS-specific invalid-state error.
- `E_NOTIMPL` is meaningful here: it identifies an ABI slot that exists but has no current implementation.
- Read-only observer wrappers reject mutation even when the underlying object could otherwise perform it.
- Public wrappers perform argument and caller checks before invoking private objects; private helper assumptions
  must not be copied into external callers.
- A nonnegative CBS status is not necessarily plain `S_OK`; for example, duplicate package sources return
  `0x000F0802`.
- `QuerySessionStatus` has two HRESULT channels: the method result and the servicing status output.
- Rebound/feature gates can make a structurally valid operation unavailable on the current system.

## Cross-architecture verification

The following ABI-sensitive areas were explicitly compared between x86 and x64:

| Area | Result |
| --- | --- |
| Package change option `1 | 4` | Same provider-to-core composition and target-state flow. |
| `CreateWindowsUpdatePackage` | Same application-ID, update-GUID, revision, package, and decryption argument order. |
| `ICbsServicingProcessor` | Same vtable order, parameter order, option masks, and required-pointer checks. |
| `ITrustedInstallerService` calls | Same timeout input and 64-bit sleep-tick output slots. |
| UI responses | Same 32-bit values and cancel/abort branches. |
| External transformer | Same method order, string arguments, action values, and phase transitions. |
| Registry backup helper | Same image-root interpretation and fixed hive list. |

Pointer-sized temporaries differ as expected. No x86-only stack parameter or x64-only hidden semantic parameter was
found in the published declarations.

## Intentionally unresolved details

The following items are left unknown because available evidence does not isolate their independent meaning:

- package change bits `0x1`, `0x2`, `0x4`, `0x8`, `0x10`, `0x20`, `0x40`, `0x100`, `0x4000`, `0x10000`,
  `0x40000`, and `0x80000`;
- startup option bit `0x1`;
- session operation values 5 through 7;
- session properties 16, 17, and 26;
- most configurable session-property labels;
- UI response values 4 and 5;
- servicing-processor option `0x80` and the independent meaning of low bits whose downstream mapping is known;
- the final transformer initialization string and three optional commit strings;
- opaque worker, FOD helper, WIM sandbox, and unnamed TrustedInstaller service slots.

These are valid ABI reservations, not invitations to assign descriptive names from a single call site.

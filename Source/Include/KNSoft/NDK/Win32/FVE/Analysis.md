# FVE API analysis

## Scope and evidence

The declarations in `FveApi.h` model the private `fveapi.dll` ABI. They were checked against the following binaries:

| Binary | Architecture | File version | SHA-256 |
| --- | --- | --- | --- |
| `fveapi.dll` | x64 | 10.0.26100.8737 | `10eeb74698e158ad2ced4fd404eb993d8bd2347170086c1fd9b9ce0095bf1eb9` |
| `fveapi.dll` | x86 | 10.0.26100.8972 | `3bd8b37972d9fd6bed1febebf4e5ded7015046b7df6202eceeab45f28292eec4` |
| `fveapi.dll` | x64 | 10.0.26100.9278 | `3324ed8a6c49aea7dbbe9eebf09e7a5f96d7c6a407d00052accf4024a1c4cca0` |
| `fveapi.dll` | x86 | 10.0.26100.9278 | `31de0a83d49a4d03fa720caefa5bf30543c3ca50e27434e24be05e024f54eb0e` |
| `fveapibase.dll` | x64 | 10.0.26100.9168 | `25c5d107b6565629dcc76ccdf87a3598a24ac5d75f0937191a1a7f67e51e99f4` |
| `fveapibase.dll` | x86 | 10.0.26100.8972 | `6b960aad89c0ad39d3a2f68f6b8f57ca7449bdcf90c60ddd9460364aae4d4779` |
| `Win32_EncryptableVolume.dll` | x64 | 10.0.26100.8972 | `b09de814b53464f361bfa2574380c7003aa717383c690f9a846acef3aab4698a` |
| `bdesvc.dll` | x64 | 10.0.26100.8875 | `4044fafe6cd98acc7d5d9a4b29138a76f5d1b66742f31fc71f7751d87df580ca` |
| `manage-bde.exe` | x64 | 10.0.26100.8875 | `4fd53453b8f5b099d9ef204b00e48be778033ca2a2b167e73f63c7c6fd605051` |

The earlier review checked all 162 x86 `fveapi.dll` exports against their `ret` stack cleanup. Every maximum observed argument count matches `FveApi.h`. x64 implementations and first-party callers were then used to recover pointer direction, structure contracts, constants, ownership, and operation sequences. `fveapibase.dll` independently confirms its 63-export subset. Unknown fields and flags remain unnamed.

## Handles and volume enumeration

`FveFindFirstVolume` creates an enumeration handle. `FveFindNextVolume` advances it and returns `HRESULT_FROM_WIN32(ERROR_NO_MORE_FILES)` at the end. Close the enumeration handle with `FveCloseHandle`.

Initialize `FVE_FIND_DATA_V1` with `FveFindVersion = FVE_FIND_VERSION_1` and `DevType = FVE_DEVICE_UNKNOWN` to enumerate supported volume classes. `bdesvc.dll` uses this exact contract.

`FveGetVolumeNameW` supports a size query with a zero character count and a null buffer. Its returned count includes the terminator. The resulting identity is a canonical `\\?\Volume{GUID}\` path.

`FveOpenVolumeW` is equivalent to `FveOpenVolumeExW` with name flags zero, `FVE_INTERFACE_UNKNOWN`, and handle flags zero. A read-only open first requests `GENERIC_READ`; on `ERROR_ACCESS_DENIED`, the implementation retries with desired access zero. Consequently, status queries can work without elevation while state-changing operations still require the access enforced by the underlying interface.

Close a volume with `FveCloseVolume`. It delegates to `FveCloseHandle` and normalizes `S_FALSE` to `S_OK`.

## Status

Before calling `FveGetStatus`, zero `FVE_STATUS_V9`, set `StructureSize` to 128, and set `StructureVersion` to `FVE_STATUS_VERSION_9`. The implementation accepts only the exact size for each version: V1 32, V2 32, V3 40, V4 64, V5 88, V6 104, V7 112, V8 120, and V9 128 bytes.

`Flags` has the following confirmed semantics:

| Mask | Meaning |
| --- | --- |
| `0x00000001` | FVE metadata is initialized |
| `0x00000004` | Fully decrypted |
| `0x00000008` | Fully encrypted |
| `0x00000010` | Decryption in progress |
| `0x00000020` | Encryption in progress |
| `0x000000C0` | Conversion pause-state mask |
| `0x00000100` | Non-TPM secure-key protector present |
| `0x00000200` | TPM secure-key protector present |
| `0x00000400` | Clear-key protector present; normal key protection is disabled |
| `0x00000800` | Volume is locked |
| `0x00001000` | Protection state is active |
| `0x00004000` | Operating-system volume |
| `0x00020000` | External-key protector present |
| `0x00040000` | Recovery-password protector present |
| `0x00080000` | TPM-and-PIN protector present |
| `0x00100000` | TPM-and-startup-key protector present |
| `0x00200000` | Passphrase protector present |
| `0x00400000` | Removable data volume |
| `0x00800000` | Certificate protector present |
| `0x01000000` | Used-space-only encryption |
| `0x10000000` | Preserved as initialization flag `0x100`; exact meaning unknown |

The first-party WMI provider derives its public values as follows:

- Conversion status: fully decrypted = 0, fully encrypted = 1, encrypting = 2, decrypting = 3, encryption paused = 4, and decryption paused = 5.
- Lock status: `(Flags >> 11) & 1`.
- Protection status: unknown when locked; otherwise on only when `0x1000` is set, `0x400` is clear, and `0x8` is set.
- Volume type: operating system when `0x4000` is set, removable when `0x400000` is set, otherwise fixed data.
- Encryption percentage: `ConvertedPercent`.
- Encryption flags: public bit zero is set when native flag `0x01000000` is present.

## Encryption methods

`FveGetFveMethod`, `FveGetFveMethodEDrv`, `FveGetFveMethodEx`, and `FveSetFveMethod` use the combined legacy values represented by `FVE_LEGACY_METHOD`. Only `FveSetFveMethodEx` splits the algorithm family (`FVE_METHOD`) from key strength (`FVE_METHOD_STRENGTH`). The combined mapping is:

| Value | Method |
| --- | --- |
| 0 | None |
| 1 | AES-128 with diffuser |
| 2 | AES-256 with diffuser |
| 3 | AES-128 |
| 4 | AES-256 |
| 5 | Hardware encryption |
| 6 | XTS-AES-128 |
| 7 | XTS-AES-256 |

`FVE_CONVERSION_FLAG_DATA_ONLY` requests used-space-only encryption. Native conversion flags `0x2` and `0x4` select mutually exclusive wipe operations, and `0x10` and `0x20` are mutually exclusive modifiers; their exact meanings are not exposed because the examined callers do not establish them. The WMI provider's public flag `0x8` is consumed by that provider and must not be forwarded to `FveConversionEncryptEx`.

When initializing inactive metadata, the WMI provider maps status bit `0x10000000` to initialization flag `0x100`. Both values remain named as unknown because the examined binaries establish the mapping but not its meaning.

## Authentication information

`FVE_AUTH_INFORMATION` is 56 bytes on x64 and 48 bytes on x86. `FVE_AUTH_ELEMENT` is 584 bytes on x64 and 580 bytes on x86. An element may use a smaller `StructureSize` appropriate to its active payload: recovery password 32, PIN 48, TPM 36, external key 48, public key 40, and passphrase 578 bytes.

The confirmed `FVE_AUTH_ELEMENT_TYPE` values are recovery password 1, PIN 2, TPM 3, external key 4, public-key input 5, public-key-info output 7, passphrase 8, clear key 9, DPAPI-NG 10, and predicted TPM information 12. Value 6 retains the inherited private-key label without independently verified payload semantics; value 11 remains unnamed. `GetAuthMethodInformation` builds type 7 with the `FVE_AUTH_INFO_PUBLIC_KEY` payload; type 5 is the different input payload `FVE_AUTH_PUBLIC_KEY`. DPAPI-NG descriptor construction builds type 10, and the query path can also construct that element. `FveAddPredictiveTpmProtector` supplies type 12 with an `FVE_TPM_STATE` pointer to `AddAuthMethodInformation`.

First-party recovery-password creation leaves `ElementFlags` at zero. Recovery-password unlock and clear-key creation for disabling protectors set bit `FVE_AUTH_ELEMENT_FLAG_UNKNOWN1`; its independent meaning is not established.

The protector portion of `AuthFlags` is mapped by `FveFlagsToProtectorType`:

| Flags | Protector |
| --- | --- |
| `0x00010000` | Clear key |
| `0x00020000` | TPM |
| `0x00040000` | External key |
| `0x00080000` | Recovery password |
| `0x00120000` | TPM and PIN |
| `0x00060000` | TPM and startup key |
| `0x00160000` | TPM, PIN, and startup key |
| `0x00200000` | Certificate |
| `0x00800000` | Passphrase |
| `0x00220000` | TPM and certificate |
| `0x01000000` | DPAPI-NG |

Low `AuthFlags` bits 1, 2, and 4 are query selectors. Their precise independent semantics are not established, so the header exposes them as `UNKNOWN1`, `UNKNOWN2`, and `UNKNOWN4`. The WMI provider uses value 1 for metadata queries and value 3 only after enabling thread-local key export for operations that inspect sensitive key material. `FveSetAllowKeyExport` returns `S_FALSE` when the requested state is already set.

`FveGetAuthMethodGuids` supports a count query with a null array and zero capacity. It returns `S_FALSE` with the required count; a second call with exactly that many GUIDs returns `S_OK`. An inactive volume returns `FVE_E_NOT_ACTIVATED`.

For `FveGetAuthMethodInformation`, initialize a template with structure size, version, query flags, and identifier. The first call supplies the template-sized buffer and obtains the required size. Allocate that size, copy the template into it, and call again. Embedded pointers refer to the caller-owned result buffer. Because the result can contain key material, securely zero the entire buffer before freeing it.

`FveAuthElementFromRecoveryPasswordW`, `FveAuthElementFromPinW`, and `FveAuthElementFromPassPhraseW` initialize their corresponding element payloads. Authentication information passed to `FveAddAuthMethodInformation` or `FveUnlockVolume` is consumed synchronously and remains caller-owned.

## Transactions and control workflows

Metadata mutation is transactional. Add, delete, description, method, and related setters stage changes. `FveCommitChanges` persists them. `FveDiscardChanges` discards staged changes and reloads volume metadata. `FveRevertVolume` removes FVE metadata after decryption.

The first-party WMI provider uses these sequences:

- Add recovery password: initialize inactive metadata when necessary; build one recovery-password element; add it; commit; revert initialization on failure.
- Unlock with recovery password: parse the password into one element and call `FveUnlockVolume`; securely erase the element afterward.
- Disable protectors: add a clear-key element with the requested disable count, then commit.
- Enable protectors: locate the clear-key authentication method, delete it, then commit.
- Delete protector: prevent deletion of the auto-unlock protector, preserve at least one usable protector on an encrypted volume, delete the selected GUID, then commit.
- Encrypt: initialize metadata if needed, stage the selected method, commit, then call `FveConversionEncryptEx`.
- Decrypt: call `FveConversionDecrypt`; once fully decrypted, call `FveRevertVolume`.
- Pause and resume: the WMI provider uses `FveConversionStop` and `FveConversionResume` respectively.
- Lock and unlock: call `FveLockVolume` and `FveUnlockVolume` directly.

`FveCommitChangesEx` validates scenarios 0 through 8 and 10 in the earlier binaries. The 10.0.26100.9278 x64 and x86 implementations also accept 14, 15, and 16. Scenario-specific internal behavior remains undocumented; use `FveCommitChanges` unless a verified scenario is required.

## Fixed behavior in the examined build

- `FveClearUserFlags`, `FveGetUserFlags`, and `FveSetUserFlags` return `E_NOTIMPL`.
- `FveIsHybridVolume`, `FveIsHybridVolumeW`, `FveNeedsDiscoveryVolumeUpdate`, and `FveServiceDiscoveryVolume` return `HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)`.
- `FveSetFipsAllowDisabled` is a no-op returning `S_OK`.
- `FveCommitChanges`, `FveConversionDecrypt`, `FveConversionEncryptPendingReboot`, and `FveConversionStop` call their extended forms with zero flags or the default scenario.
- `FveEnableRawAccess` calls `FveEnableRawAccessEx` with its third argument false.

These observations describe the inspected Windows build and must not be treated as a compatibility guarantee for future builds.

## 10.0.26100.9278 verification

The x64 and x86 IDB input hashes match the live PE hashes listed above. Both disassembly and decompilation were used; decompiler argument types and inferred structure names were not treated as independent ABI evidence.

`FveGetFveMethodEx` delegates to `GetFveMethodEDrv` and returns a combined legacy method. Its eDrive buffer is optional, as is the same buffer in `FveGetFveMethodEDrv`. When supplied, the buffer has room for 256 WCHARs. The flags pointer is also optional. A successful path can OR bit zero into the caller's flags without initializing them; callers must initialize this value. The independent meaning of that bit remains unassigned. The x64 flags write is at `0x18000E032`; the corresponding x86 write is at `0x10034502`.

`TpmApiCallbackTpmCall` reads the callback's result length before the indirect call and restores that capacity before each retry. The callback receives a command buffer of `cbCmd` bytes, a result buffer whose capacity is the incoming `*pcbResult`, and an input/output result-length pointer. The x64 capacity read/write is at `0x18003B04D`/`0x18003B0AC`; x86 uses `0x100E78C7`/`0x100E7929`. `FveSetupTpmCallback` accepts version 0, 1, or 2; version zero asks `Tbsi_GetDeviceInfo` for the version.

Authentication-element construction independently establishes public-key-info type 7 at `0x1800227CB`/`0x10036935`, DPAPI-NG type 10 at `0x180075E88`/`0x100CBB81`, and predicted TPM information type 12 at `0x18005D883`/`0x10055AB0`. Clear-key type 9 remains the value accepted by `AddAuthMethodInformation`; neither the DPAPI-NG nor predicted-TPM element should be assigned the shifted upstream values 11 or 13. Element flag bits are consumed differently by individual payload paths. Their global semantics are not inferred from a single size check or diagnostic string. Bit 0x1 participates in payload-size and complete-key-data handling on different paths. On the public-key path, bit 0x20 is associated with NBP/network-unlock information; a diagnostic string alone does not establish a universal predictive-PCR7 meaning. Existing phnt flag labels are retained, while these observations limit their independently verified semantics. Value 11 remains without a safely recovered element interpretation.

The header retains phnt's inherited private-key label for authentication-element value 6 as `FveAuthElementTypePrivateKey`. This review did not independently establish that payload's meaning; lack of recovered semantics does not disprove the existing upstream name. The observed clear-key 9, DPAPI-NG 10 and predicted-TPM 12 corrections remain unchanged.

`FvePcrMonPredictionsUpdated` is a named, non-forwarded export in both examined PEs and takes one nonnull context pointer; x86 ends in `ret 4`. The three names `FveCheckBootFileW`, `FveEraseDriveExW`, and `FvepCanPinExceptionPolicyBeApplied` are absent from these export tables. The latter exists as an internal function reached by the public `FveCanPinExceptionPolicyBeApplied` thunk. Its x86 implementation receives its parameter in ECX and uses a plain return under LTCG optimization; that internal call shape does not establish a separate public WINAPI export ABI. This establishes the current-build export surface only; it does not rule out additional exports in a later Windows build.

`FveGetIdentificationFieldW` reports characters, including the null terminator, rather than bytes. The internal implementation adds one to `FveDatumUnicodeGetLength` at `0x180074F61`/`0x100B9F9E` and uses `StringCchCopyExW` with the supplied character capacity. A null buffer is permitted with capacity zero.

The protector-GUID outputs of `FveValidateExistingPinW` and `FveValidateExistingPassphraseW` are optional and are written only when the PIN or passphrase matches. A nonmatching successful comparison writes `FALSE` to the validation result without initializing the GUID. The GUID null checks are at `0x1800A04C5`/`0x100D37CA` and `0x1800A02B4`/`0x100D3579` respectively.

`FveAddAuthMethodInformation` accepts a null output GUID. Its implementation checks the pointer before copying the newly added protector identifier at `0x18009B62A`/`0x1007E9D5`. The authentication information remains required input.

The 9278 follow-up collected both architectures for the 81 declarations that differ textually from the synchronized phnt header, along with the new query/control implementations and authentication-element constructors. The maximum x86 return-stack cleanup matches the local argument count for all 81 declarations; plain returns in SEH funclets are not treated as additional public signatures. This establishes the stack shape, not every parameter's purpose. Opaque contexts, unused fields, and unverified flag meanings remain unassigned.

### Query and control layouts

The following sizes and offsets for the 23 synchronized query/control types agree with the x64 and x86 disassembly. Compile checks also establish that the declarations produce the expected layout on x86, x64, ARM64, and ARM64EC; no ARM64 or ARM64EC DLL implementation was examined. Unless noted otherwise, the request prefix is a USHORT version followed by a USHORT size. A size query supplies a correctly sized request, a null output pointer, and an output size initially zero.

| Operation | Input bytes x64 / x86 | Output bytes | Contract established in 9278 |
| --- | --- | --- | --- |
| Query 5, WCOS security | 12 / 12 | 64 | Supports a size query; completion timeout is DWORD at 4, optional version-2 flags are bytes at 8 and 9. |
| Query 6, boot integrity | No input required | 40 | Supports a size query; ULONGLONG flags are at 8, six HRESULTs at 16 through 36. |
| Query 8, TPM protector version | 24 / 12 | 4 | Supports a size query; handle and GUID pointer are at 8/16 on x64 and 4/8 on x86. |
| Query 9, Secure Boot binding | 32 / 16 | 1 | Supports a size query; the legacy-binding selector is one byte at 16 / 8. |
| Query 10, Secure Boot evaluation | 8 / 8 | 16 | Supports a size query; input selector at 4 and response enum/BOOL/BOOL at 4/8/12 are DWORDs. |
| Query 11, binding count | 24 / 12 | 2 | Supports a size query; the result is a USHORT. |
| Query 12, binding census | 32 / 16 | Variable | Null output returns size zero; no reliable required-size query is established. |
| Query 13, default PCR profile | 16 / 8 | 24 | Supports a size query; GUID at 4 and profile DWORD at 20. |
| Query 14, prediction mapping | 16 / 8 | 132 | Requires a real output buffer of at least 132 bytes; WCHAR[64] starts at 4. |
| Query 15, WinRE policy | 12 / 12 | 4 | Supports a size query; DWORD size at 0, byte logging selector at 4, DWORD WIM type at 8. |
| Control 1, external-key protection | 1056 / 1056 | 536 | Supports a size query before the state-changing implementation. |
| Control 3, default PCR profile | 40 / 28 | None | Handle at 8 / 4, GUID at 16 / 8, profile DWORD at 32 / 24. |
| Control 4, TPM-core provisioning | 40 / 20 | None | Path pointer, DWORD flags, API-surface pointer, and PCR DWORD pointer match native alignment. |
| Control 5, prediction mapping | 144 / 136 | None | Handle at 8 / 4; WCHAR[64] starts at 16 / 8. |

The external-key request has DWORD flags at 4, a legacy-method DWORD at 8, USHORT key flags at 12, and two WCHAR[260] arrays at 14 and 534. Its response has DWORD flags/method/method-flags at 4/8/12 and WCHAR[260] at 16. The query-14 response initializes version 1 and size 132; query 5 and query 6 initialize the size field but leave version zero, while query 13 leaves both prefix fields zero. Callers must not require every successful response to echo a requested version or size.

The WinRE disposition values 0/1/2 are independently observed as allowed, disabled by policy, and undetermined. WIM type 1 bypasses the WinRE-policy check, but the names of WIM type 0 and 2 are retained from phnt rather than independently recovered. Secure Boot evaluation writes 0 initially, 1 on the explicit disabled-policy path, 2 while evaluating UEFI configuration, and 3 on the usable path. TPM protector version 1 identifies the legacy blob path and 2 the extended blob path. Reserved bytes and the independent meanings of unobserved field combinations have not been inferred.

The query-15 and control-6-through-9 dispatch cases are feature gated. Control 6 is PCR-monitor boot, 7 and 8 are shutdown/hibernate scenarios 3 and 2 respectively, and 9 requests boot-time PCR-unseal information. These global operations are distinct from volume-only metadata queries.

## 10.0.28000.2804 static verification

The follow-up inspected the DLLs copied from the disposable VM, with these identities:

| Binary directory | Architecture | File version | SHA-256 |
| --- | --- | --- | --- |
| `System32/fveapi.dll` | x64 | 10.0.28000.2804 | `f09ff7e84d7f1a67356edc9418023983e039e17e0b4ef9234460c97d2602680f` |
| `SysWOW64/fveapi.dll` | x86 | 10.0.28000.2804 | `847f3719cc60a61283f9e074441e7cbbb6f57a4b3ab508c8a8ed8f6326f495b6` |

Both fresh IDB input hashes match the copied PE hashes. The guest OS reports 10.0.28000.2956; that OS version must not be substituted for the DLL file version. The original 26100.9278 IDBs remain separate.

This review covers the nine public exports `FveOpenVolumeW`, `FveCloseVolume`, `FveInitVolume`, `FveAddAuthMethodInformation`, `FveGetAuthMethodInformation`, `FveDiscardChanges`, `FveGetFveMethodEx`, `FveQuery`, and `FveControl`, together with their relevant native call paths. It collected 57 x64 and 58 x86 functions, 115 in total. All conclusions below combine disassembly and decompilation; inferred decompiler prototypes are not treated as original PDB declarations. The 18 frontend cases are eight query cases and one control case on each architecture. These are static findings; they do not establish runtime completion or successful creation of a protector on the test fixture.

### Volume and authentication paths

`FveOpenVolumeW` still passes the caller's `NeedWriteAccess` BOOL to `FveOpenVolumeExW`. Read-only access requests `GENERIC_READ`, with a zero-access retry on access-denied; write access requests `GENERIC_READ | GENERIC_WRITE`. The canonicalizer copies the path and removes its trailing backslash before opening the device. Consequently, a `\\?\Volume{GUID}\` path returned by volume enumeration can be passed directly. The trailing-backslash zero stores are at `0x18001B1EA` and `0x1004B209`.

`FveInitVolume` takes an optional input `PCWSTR` discovery-volume type as its second parameter. The implementation checks for NULL before comparing the supported discovery strings; the wrapper supplies its own internal provisioning-scenario GUID. Initialization can persist metadata and write the volume boot region. `FveDiscardChanges` zeroes and frees the current working datasets and key cache, then reopens the volume to reload disk state. It does not undo persisted initialization. `FveCloseVolume` retains the handle-release path and normalizes `S_FALSE` to `S_OK`.

The full authentication-information and element sizes remain 56/48 and 584/580 bytes on x64/x86 respectively. The clear-key element is still type 9. Its flag-1 path requires at least 24 bytes, reads a BYTE count at payload offset 16 and a DWORD context at offset 20, and permits count zero without the OS-volume-specific restriction. A zero-initialized full element with version 1, type 9, element flag 1 and count zero, in version-1 authentication information with `AuthFlags = 0x10000`, matches the inspected input contract. The independent global meaning of element flag 1 remains unknown.

Unlike 26100.9278, the 28000.2804 public `FveAddAuthMethodInformation` wrapper requires a nonnull output GUID on both architectures. NULL authentication information or a NULL GUID is rejected before handle acquisition. With valid information and a NULL GUID, WPP may read the information's flags before rejecting it; this is not a valid metadata operation. The common successful creation path writes the GUID from the new VMK datum at `0x1800A3CF0` and `0x10083DAB` through `0x10083DAE`. `S_OK` establishes this ordinary output path. The existing-clear-key early exit returns `S_FALSE` without writing the GUID, at `0x1800A2536` and `0x10082929` through `0x1008292C`. A successful HRESULT test alone therefore does not establish a new identifier or a newly created clear-key protector. The common write tests a nonnegative result, so this review does not claim that every other positive status necessarily leaves the GUID untouched.

For `FveGetAuthMethodInformation`, low query bit 1 selects the supplied GUID; bit 2 selects key-material export and is left clear for metadata-only queries. The identifier is at offset 40 on x64 and 32 on x86. Buffer capacities and required sizes use native `SIZE_T`. Returned embedded pointers reference the caller's result buffer and must be checked against its extent before following them. A metadata-only result may legitimately have `ElementsCount = 0`; that does not prove a failed query or a missing authentication method. The buffer remains subject to secure zeroing before release.

`FveGetFveMethodEx` still accepts a NULL eDrive buffer and an optional flags pointer. The public wrapper obtains the combined legacy method, then conditionally ORs bit zero into the caller's flags on the successful nonzero-method/state-bit path. It does not initialize or clear the flags. Preserved seed bits on a failed call do not establish the successful output contract.

### Restricted query and control size paths

For the following cases, a NULL output pointer and an output size initialized to zero bypass the substantive implementation. The query request sizes and required output sizes agree with 26100.9278; Control 1 differs.

| Operation | Input bytes x64 / x86 | Required output bytes | Static result for the restricted size path |
| --- | --- | --- | --- |
| Query 5 | 12 / 12 | 64 | `S_OK`; skips WCOS implementation. |
| Query 6 | 0 / 0 | 40 | `S_OK`; skips boot-integrity implementation. |
| Query 8 | 24 / 12 | 4 | `S_OK`; does not follow the handle or GUID pointer. |
| Query 9 | 32 / 16 | 1 | `S_OK`; skips binding inspection. |
| Query 10 | 8 / 8 | 16 | `S_OK`; skips Secure Boot evaluation. |
| Query 11 | 24 / 12 | 2 | `S_OK`; skips binding enumeration. |
| Query 13 | 16 / 8 | 24 | `S_OK`; skips handle acquisition and PCR-profile lookup. |
| Query 15 | 12 / 12 | 4 | Feature enabled: `S_OK`; feature disabled: `0x80070001`, with the initial size unchanged. |
| Control 1 | 1112 / 1108 | 604 | `S_OK`; skips external-key protection implementation. |

The ordinary request prefix is a USHORT version and USHORT size; the restricted checks use requests initialized with version 1 and their actual size. Query 15 instead requires a DWORD size at offset zero. Its size branch consumes only fixed scalar request fields before returning, keeps the real-operation marker clear and skips object allocation, OS-volume/BCD/policy reads and the WinRE-policy event. A feature-disabled result is a limited observation, not a positive required-size result. Query 13's final release of the NULL local object is a no-op.

These conclusions apply to NULL output with zero capacity. Several frontends enter their real implementation for a nonnull output before testing whether its capacity is sufficient; this review does not extend the restriction to nonnull zero-capacity buffers. WPP and feature bookkeeping may still run on a size-only call.

Control 1's x64 NULL-output branch at `0x1800AC4D8` jumps to the required-size store at `0x1800AC51A`, bypassing the implementation call at `0x1800AC4E2`. The x86 equivalents are `0x1008788E`, `0x100878DE` and `0x1008789C`. The real implementation can change key-export state, mutate volume metadata and create files. A size-only result establishes none of those operations or their full input contract.

The existing `FVE_CTL_PROTECT_WITH_EK_REQUEST` and `FVE_CTL_PROTECT_WITH_EK_RESPONSE` declarations describe the verified 26100.9278 layouts, 1056-byte request and 536-byte response. The 28000.2804 native consumers require 1112/1108 input bytes and report 604 output bytes. Consumed offsets establish additional categories including a handle/path union, provisioning-scenario GUID and external-key data, but the fresh PDB type catalogs do not provide complete named members. Unconsumed bytes, original member names and all flag semantics remain unresolved. No complete new typed layout or DDI introduction boundary is asserted; the old typed layouts must not be used as the full 28000.2804 buffers. The restricted frontend size checks also do not establish a new structure-version value or the first Windows version with this change.

The following 28000.2804 consumer offsets were retained from the synchronization review. They describe observed accesses, not a complete public structure:

| Buffer | Offset | Observed access |
| --- | --- | --- |
| Request | 0 / 2 | USHORT version / size |
| Request | 4 | ULONG flags |
| Request | 8 | LONG value |
| Request | 12 | USHORT value |
| Request | 16 | WCHAR[260] path or native HANDLE; flag 0x200 selects the handle path |
| Request | 536 | WCHAR[260] path |
| Request | 1056 | GUID |
| Request | 1072 | USHORT length |
| Request | 1074 | 32-byte data on the flag-0x80 path |
| Response | 16 | WCHAR[260] |
| Response | 536 / 552 | GUIDs |
| Response | 568 | USHORT length |
| Response | 570 | 32-byte data |

Request bytes 14–15 and 1106 through the end, and response bytes 602–603, were not confirmed as consumed. Their presence does not establish named reserved members, complete flag semantics or a DDI boundary.


### Export-surface limits

Both new PEs contain 167 named exports, compared with 163 in both 26100.9278 PEs. The additional names are `FveInitVolumeEx2`, `FveInitializeDeviceEncryption3`, `FveOpenVolumeById`, and `FveUnlockVolumeWithExternalKey`. Their existence is recorded here without recovering declarations or exercising them.

`FveCheckBootFileW`, `FveEraseDriveExW`, and `FvepCanPinExceptionPolicyBeApplied` are absent from both architectures' export tables in both 26100.9278 and 28000.2804. The examined phnt source does not establish a verified version boundary, and no supporting SDK declaration or tested export ABI establishes these three imports. Their synchronized public declarations and import entries are therefore withheld. The internal `FvepCanPinExceptionPolicyBeApplied` implementation and the distinct public `FveCanPinExceptionPolicyBeApplied` export must not be conflated. The available evidence establishes these sampled export surfaces; it does not establish absence from every past or future Windows build.

### Isolated VM runtime coverage

On 2026-10-08, run `NDK-PrivateAPI-20261008-230930-9657ddc1648c46e9b57f97498fa162eb` completed the four FVE cases against the identified 10.0.28000.2804 DLLs. All four elevated administrator processes ran in noninteractive Session 0 and exited zero without a recorded exception, refusal or timeout. The raw JSONL counts distinguish API calls from identity and output-observation records:

| Case | JSONL rows | Private FVE API calls |
| --- | --- | --- |
| Read-only x64 | 16 | 13 |
| Read-only x86 | 16 | 13 |
| Clear-key x64 | 20 | 16 |
| Clear-key x86 | 20 | 16 |
| Total | 72 | 58 |

The 58 calls comprise 32 `FveQuery`, four `FveControl`, four `FveOpenVolumeW`, eight `FveGetFveMethodEx`, four `FveCloseVolume`, two `FveInitVolume`, two `FveAddAuthMethodInformation` and two `FveDiscardChanges` calls. DLL loading and symbol lookup are excluded. Of the nine statically reviewed exports, eight were called; `FveGetAuthMethodInformation` was resolved but never called.

On both architectures, Query 5/6/8/9/10/11/13 returned `S_OK` and required 64/40/4/1/16/2/24 bytes respectively. Control type 1 returned `S_OK` with 1112-byte x64 or 1108-byte x86 input and required 604 output bytes. Every query/control call supplied NULL output and zero initial capacity. Query 15 returned `0x80070001` with size still zero in all four cases, exercising only the feature-disabled path. These observations support the restricted frontend contracts; they do not exercise substantive query implementations, external-key protection or the complete new Control 1 structures.

Both read-only and write-access opens accepted the enumerated volume GUID paths with trailing backslashes, and all closes returned `S_OK`. Each `FveGetFveMethodEx` call succeeded with a NULL eDrive buffer: the initial call reported legacy method 6 and flags zero, and the seeded call retained exactly `0xA5000000`. The flags bit-zero-setting path remains unexercised. Both initialization calls used the optional discovery type as NULL and returned `S_OK`; the later discard calls also returned `S_OK`. Discard does not undo persisted initialization; the fixture rollback was performed through the exact VM checkpoint.

Both clear-key cases supplied full version-1 authentication information and a type-9 element, with `AuthFlags = 0x10000`, element flag 1 and payload count zero. Both additions took the existing-clear-key `S_FALSE` branch. The required GUID output remained entirely at its `0xC3` seed, and its 16-byte leading and trailing canaries were intact. The probe correctly skipped the GUID-filtered GetAuth calls. Thus this run establishes neither new-clear-key creation nor the `S_OK` GUID-writing path. No authentication result buffer was returned: its required length, embedded pointers, returned element types and `ElementsCount` remain outside runtime coverage. The measured canaries apply to the GUID storage only.

The manifest matches all four DLL roles against the prior reviewed collection and matches their hashes again after the calls. An attach/detach/reattach observation identifies the unique owned disk; both architecture-specific NTFS volumes belong to that disk. Final exact-checkpoint rollback records `Cleanup.Verified = true`, VM state `Off`, and removal of the owned checkpoint and VHD. The original two disk roots, two pre-existing checkpoints and adapter configuration match the baseline. The combined FVE/WinSta evaluator reports 213 checks passed, zero failed and status `Limited`; that count is not an API-call count. Query 15's enabled size path, successful protector creation/GetAuth output, full query/control implementations, and native ARM64/ARM64EC behavior remain untested.

## phnt synchronization decisions and upstream status

These records were consolidated from the repository-root `note.md` on 2026-10-09. Future FVE evidence, unresolved ABI details and synchronization decisions are maintained in this document.

The initial conflict was introduced by [phnt commit c9fa7ccd](https://github.com/winsiderss/systeminformer/commit/c9fa7ccd3640c24352e33ad418ea1a1cb1b6a668): `FVE_AUTH_ELEMENT_TYPE` in `phnt/include/ntfve.h` (original lines 852-853) assigned TPM-PIN to 9 and clear key to 10. On 2026-10-08, the user confirmed retaining the locally verified clear-key value 9 and withholding conflicting unverified labels. The later constructors and consumer paths also establish DPAPI-NG 10 and predicted TPM information 12, as recorded above. This does not establish replacement values for the displaced TPM-PIN or network-server labels. The inherited private-key label at value 6 remains preserved without claiming new proof of its payload semantics.

The public `FveAddAuthMethodInformation` contract uses a required GUID output to accommodate both inspected versions: 26100.9278 permits NULL, whereas 28000.2804 rejects it. Normal `S_OK` creation and the existing-clear-key `S_FALSE` branch have different output behavior. The separate optional, matched-only GUID outputs of PIN/passphrase validation remain as described above.

The three upstream declarations absent from all four sampled export tables remain withheld from NDK public declarations and ordinary imports. Their original declarations are preserved in the local verification artifacts. The introduction commit supplied no verified build boundary, and SDK 10.0.28000.0 provided no additional public contract supporting these imports. Sample absence and an internal LTCG implementation are insufficient to recover a portable exported signature. The four newly observed 28000.2804 names likewise remain recorded without guessed prototypes.

[Upstream draft PR #3100](https://github.com/winsiderss/systeminformer/pull/3100) contains the completed FVE declaration work. As checked on 2026-10-09, it is open, remains a draft and has not merged; its signed head is `d06df7e287eb6ef356ce97de844b459cb64ba9ba`. It retains all 156 preexisting upstream declarations, including the three unsampled declarations, and adds ten reviewed downstream exports. This preserves the upstream inventory while NDK continues to withhold imports that were not safely established for its sampled inputs. The previous note stating that no FVE PR would be opened described an earlier task phase and is superseded by this publication.

### Shared validation-run provenance and recovery

The completed run identified above covered eight processes across FVE and WinSta. The callers were WuaCuaAdmin with high integrity and enabled Administrators membership in noninteractive Session 0. WinSta's console Session 1 was a target argument, not the caller's interactive session. FVE's two architecture-specific 1 GiB NTFS volumes were on the same dedicated VHD. The four reviewed FVE/WinSta DLL roles retained their hashes before calls, after the WinSta phase and at the end; the evaluator's 213 successful checks and `Limited` status are evidence-check counts, not API-call counts or complete API coverage. The separately recorded LogicalProcessorIdling issue remained unchanged and outside the private-API probe scope.

Guest `UniqueId` is a VPD83 identifier and cannot be compared directly with a VHD GUID. Disk association used the exact host path/GUID/size/slot together with controlled attach, disappearance of the full guest identifier after detach, and return of the same identifier after reattach. The original two disk identities were preserved at all three stages. Verified rollback left the VM Off, removed the owned checkpoint/VHD, and preserved the original two disk roots, two checkpoints, adapter configuration and five preexisting VHDX files.

Earlier attempt records remain immutable: four startup/readiness failures, one storage-CIM failure and one disk-association failure before formatting. The first five attempts created no VHD; the sixth created an unformatted owned RAW VHD. Two initially failed cleanup operations have separate exact-recovery evidence; their failure manifests were not rewritten as successful runs. The guest-reset initiator and internal cause were not inferred. Those failed attempts are excluded from the completed run's 58 FVE API calls and do not establish additional API coverage.

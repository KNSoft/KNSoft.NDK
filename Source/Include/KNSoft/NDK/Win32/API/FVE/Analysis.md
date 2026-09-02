# FVE API analysis

## Scope and evidence

The declarations in `FveApi.h` model the private `fveapi.dll` ABI. They were checked against the following Windows 11 26H1 binaries:

| Binary | Architecture | File version | SHA-256 |
| --- | --- | --- | --- |
| `fveapi.dll` | x64 | 10.0.26100.8737 | `10eeb74698e158ad2ced4fd404eb993d8bd2347170086c1fd9b9ce0095bf1eb9` |
| `fveapi.dll` | x86 | 10.0.26100.8972 | `3bd8b37972d9fd6bed1febebf4e5ded7015046b7df6202eceeab45f28292eec4` |
| `fveapibase.dll` | x64 | 10.0.26100.9168 | `25c5d107b6565629dcc76ccdf87a3598a24ac5d75f0937191a1a7f67e51e99f4` |
| `fveapibase.dll` | x86 | 10.0.26100.8972 | `6b960aad89c0ad39d3a2f68f6b8f57ca7449bdcf90c60ddd9460364aae4d4779` |
| `Win32_EncryptableVolume.dll` | x64 | 10.0.26100.8972 | `b09de814b53464f361bfa2574380c7003aa717383c690f9a846acef3aab4698a` |
| `bdesvc.dll` | x64 | 10.0.26100.8875 | `4044fafe6cd98acc7d5d9a4b29138a76f5d1b66742f31fc71f7751d87df580ca` |
| `manage-bde.exe` | x64 | 10.0.26100.8875 | `4fd53453b8f5b099d9ef204b00e48be778033ca2a2b167e73f63c7c6fd605051` |

All 162 x86 `fveapi.dll` exports were checked against their `ret` stack cleanup. Every maximum observed argument count matches `FveApi.h`. x64 implementations and first-party callers were then used to recover pointer direction, structure contracts, constants, ownership, and operation sequences. `fveapibase.dll` independently confirms its 63-export subset. Unknown fields and flags remain unnamed.

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

`FveGetFveMethod` and `FveSetFveMethod` use the combined legacy method values represented by `FVE_LEGACY_METHOD`. `FveGetFveMethodEx` and `FveSetFveMethodEx` split the algorithm family (`FVE_METHOD`) from key strength (`FVE_METHOD_STRENGTH`). The combined mapping is:

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

The confirmed `FVE_AUTH_ELEMENT_TYPE` values are recovery password 1, PIN 2, TPM 3, external key 4, public key 5, passphrase 8, and clear key 9. Values 6 and 7 remain unnamed.

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

`FveCommitChangesEx` validates scenarios 0 through 8 and 10 in the examined implementation. Scenario-specific internal behavior remains undocumented; use `FveCommitChanges` unless a verified scenario is required.

## Fixed behavior in the examined build

- `FveClearUserFlags`, `FveGetUserFlags`, and `FveSetUserFlags` return `E_NOTIMPL`.
- `FveIsHybridVolume`, `FveIsHybridVolumeW`, `FveNeedsDiscoveryVolumeUpdate`, and `FveServiceDiscoveryVolume` return `HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)`.
- `FveSetFipsAllowDisabled` is a no-op returning `S_OK`.
- `FveCommitChanges`, `FveConversionDecrypt`, `FveConversionEncryptPendingReboot`, and `FveConversionStop` call their extended forms with zero flags or the default scenario.
- `FveEnableRawAccess` calls `FveEnableRawAccessEx` with its third argument false.

These observations describe the inspected Windows build and must not be treated as a compatibility guarantee for future builds.

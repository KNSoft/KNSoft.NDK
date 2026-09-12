# WinSta API analysis

## Scope

`winsta.dll` exposes private Terminal Services client APIs. The implementations described here are:

| Architecture | File version | SHA-256 |
| --- | --- | --- |
| x64 | `10.0.26100.6899` | `6fb63648dee54c11b91d5778aba7b2325aed9419559e877b64fd7117c27d2bcf` |
| x86 | `10.0.26100.8972` | `ffa6abb538d243266d376c7a0b460bb0634dc6be6b3101db89e6612b588e7996` |

These are the original input identities stored in the IDA databases. Private behavior can differ between Windows
versions. ARM64 and ARM64EC implementations are outside this analysis.

## Client architecture

The exports select between local session helpers, LSM/RCM RPC interfaces, and legacy Terminal Services RPC.
`CPublicBinding` owns RPC bindings and session contexts. Some operations translate RPC structures into native
caller buffers; others pass opaque data through. Native and wire layouts are therefore not interchangeable.

`NULL` selects the local server where the API accepts a server handle. `WINSTATION_CURRENT_SESSION` (`-1`)
is an API-specific selector, not a universal valid session ID. `WinStationQueryInformationW` resolves it from
the process session for a local server and rejects it for a remote server. `WinStationConnectAndLockDesktop`
requires a null server handle and an explicit session ID other than `-1`.

`WinStationGetAllUserSessions` constructs a local binding and does not use its `ServerHandle` parameter.

`WinStationServerPing` accepts a licensing RPC context returned by `ServerLicensingOpenW`. With `NULL`,
it obtains the local licensing context through `LcRpcBindLocal`. This is a different handle domain from
the binding objects returned by `WinStationOpenServer*`; the ping RPC uses `FC_BIND_CONTEXT`.

## Status and boolean widths

Traditional `BOOLEAN` results use `AL`. The upper bits of `EAX`/`RAX` can retain unrelated values, including
on failure. Test the declared byte result. Notification functions returning `BOOL` produce a full `EAX` result.

| Return contract | Functions |
| --- | --- |
| `BOOL` | Window notification registration, unregistration and release functions; event notification registration and unregistration |
| Win32 error code in `ULONG`, with `0` for success | `WinStationConsumeCacheSession`, `WinStationIsBoundToCacheTerminal`, `WinStationIsSessionPermitted`, `WinStationSystemShutdownStarted`, `WinStationSystemShutdownWait`, `WinStationRedirectErrorMessage`, `WinStationGetUserCredentials`, `WinStationFreeUserCredentials` |
| `HRESULT` | `WinStationSetRenderHint`, `WinStationCreateChildSessionTransport`, `WinStationRedirectLogonBeginPainting`, `WinStationRedirectLogonStatus`, `WinStationRedirectLogonMessage`, `WinStationRedirectLogonError`, `WinStationGetUserProfile` |

Return width and output width are independent. `WinStationActiveSessionExists` returns `BOOLEAN` status and
accepts a four-byte `PBOOL` output. `WinStationIsChildSessionsEnabled`, `WinStationIsCurrentSessionRemoteable`,
`WinStationIsSessionRemoteable`, and `WinStationShadowAccessCheck` use one-byte `PBOOLEAN` outputs.

`GetLastError` is not a uniform secondary status channel. Local release paths can preserve it;
`WinStationIsSessionPermitted` returns a Win32 error directly. Logon-redirection exports can return `S_OK`
without writing their RPC outputs when the current process is not in a remote session.

## Information queries

`WinStationQueryCurrentSessionInformation` takes an information class, output buffer, byte capacity, and required
`PULONG ReturnLength`. It rejects a null buffer or return-length pointer. With both pointers valid, it clears
`ReturnLength` before dispatching.

| Class | Native buffer | Minimum byte capacity |
| --- | --- | --- |
| `WinStationConfiguration` (`1`) | `WINSTATIONCONFIG` | `2664` |
| `WinStationClient` (`6`) | `WINSTATIONCLIENT` | `2296` |
| `WinStationInformation` (`8`) | `WINSTATIONINFORMATION` | `1216` |
| `WinStationType` (`39`) | `ULONG` | `4` |

Other classes are rejected with `ERROR_INVALID_PARAMETER`. Configuration and client fallback paths can clear
the entire supplied capacity and report that capacity. Some RPC paths can report a required byte count larger
than the copied output. `ReturnLength` is not always the number of initialized bytes.

`WinStationQueryInformationW` additionally handles explicit session queries. Notable native layouts are:

- `WinStationPdParams`: a `568`-byte `PDPARAMS` buffer; the current helper returns a zero-filled template.
- `WinStationPd`: `PDCONFIG2` followed by `PDPARAMS`, totaling `736` bytes; the template writes `SdClass == 2`.
- `WinStationUserToken`: a `WINSTATIONUSERTOKEN`, with the returned handle at offset `16` on x64 or `8` on x86.
- `WinStationRemoteAddress`: a `32`-byte `WINSTATIONREMOTEADDRESS`.
- `WinStationInformationEx`: level `1`, data at offset `8`, and returned size `1224`. The helper writes level `1`
  even when the incoming level is `2`. No producer of `WINSTATIONINFORMATIONEX_LEVEL2` was found in these paths.

Class `41` (`WinStationValidationInfo`) is unsupported in these implementations. Class `42` (`WinStationActivityId`) has
a feature-dependent path. Several historical classes return `ERROR_INVALID_FUNCTION`.

## Native buffers and legacy RPC

The legacy `RpcWinStationQueryInformation` / `RpcWinStationSetInformation` contracts include wire descriptors
that the native query helpers omit. For configuration, the native result is `WINSTATIONCONFIG`; legacy RPC
uses `WINSTACONFIGWIRE` followed by `USERCONFIG`. Legacy protocol-driver parameters use `PDPARAMSWIRE` followed
by `PDPARAMS`. Legacy client and extended-information results have a `VARDATA_WIRE` prefix.
See [MS-TSTS query](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/1bba9ff2-71d3-49a3-bb26-2e5f6fcab3ee)
and [set](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/2a5ee131-a1dd-44c7-9880-98df708061ea).

In the analyzed implementations, `WinStationSetInformationW` only reaches RPC for a local server, session ID
`-1`, and `WinStationNtSecurity` (`13`). That path calls `RpcPopSecurityDialog`. All paths return `FALSE`.
Other classes, including `WinStationConfiguration` and `WinStationPdParams`, set `ERROR_INVALID_FUNCTION`
without reading the input buffer.

The legacy RPC protocol nevertheless defines setters for configuration and protocol-driver parameters.
Its contract does not establish that the current DLL export forwards those operations, or that a particular
current server accepts direct legacy RPC calls. The version where native setting was removed is unknown.

## Configuration and client records

`WINSTATIONCONFIG` consists of `WCHAR Comment[61]`, `USERCONFIG User`, and `CHAR OEMId[4]`. It occupies `2664`
bytes on both architectures; `User.Password` starts at offset `210`.
[Protocol definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/379fe706-cf87-417e-b1f2-e8536013132d).

`WINSTATIONCLIENT` occupies `2296` bytes. Its password starts at offset `124`. The first DWORD contains the
client flags, including `fRestrictedLogon` immediately after `fUsingSavedCreds`.
[Protocol definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/673d8ac0-f557-48cb-98a6-49925160d729).

`WinStationGetDeviceId` forwards a direct output buffer to `RpcQuerySessionData`, using data class `4` and
twice the supplied `ULONG` capacity as its byte capacity. The two-byte unit does not establish that the
payload is a UTF-16 string; its encoding and contents remain protocol-specific.

`WinStationSetAutologonPassword` marshals both parameters as null-terminated wide strings.

## Session and process enumeration

`SESSIONIDW` has a `76`-byte stride and `State` at offset `72`. `SESSIONIDA` has a `44`-byte stride and `State`
at offset `40`. Both contain space for a 32-character station name plus its terminator.

`WinStationGetAllSessionsEx` accepts level `1`. `EXECENVDATAEX` occupies `64` bytes on x64 and `36` on x86;
its level-1 payload holds three 32-bit values and five allocated string pointers. Free the array with
`WinStationFreeEXECENVDATAEX`, supplying its entry count.

`WinStationGetAllUserSessions` validates the SID, converts it to a string SID, and obtains session records by
RPC. The native output uses a `20`-byte stride: a leading version DWORD set to `1`, followed by four copied
DWORDs. The client does not establish the meaning of every copied field. In particular, the inherited
`TS_USER_SESSION.State` / `SESSIONTYPE` association is not independently confirmed by this copy loop.

`WinStationGetSessionIds` requires a nonnull array and nonzero input capacity through `Count`. It clears the
array and count before RPC. A partial result can be copied on `ERROR_MORE_DATA` while the function returns
`FALSE`. `SESSION_FILTER` occupies four bytes in the native ABI and uses `FC_ENUM16` on the wire.
The protocol defines `SF_SERVICES_SESSION_POPUP == 0`.
[Filter definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/35269584-7c5e-4410-8195-1aa49559274e).

`WinStationGetAllProcesses` returns level-`0` `TS_ALL_PROCESSES_INFO` entries. The outer stride is `24` bytes on
x64 and `12` on x86; each points to a `TS_SYS_PROCESS_INFORMATION` of `184` or `136` bytes and a separate SID.
The process record is converted from native system information. `CycleTime` is copied, spare fields are cleared,
and `UniqueProcessKey` remains zero. `ImageName.Length` includes the terminator added by this conversion.
The NT4 compatibility constants `64` and `136` are legacy record sizes, not native x64 system-information sizes.

`WinStationGetProcessSid` writes directly into caller-provided SID storage. `SidSize` supplies its byte capacity
and receives the result/required size. `ProcessStartTime` is an eight-byte `FILETIME` passed by value, including
on x86; it must not be replaced with a pointer.

## Counters and status records

`WinStationGetTermSrvCountersValue` accepts an input/output array of `Count` `TS_COUNTER` entries. Initialize
each `CounterHead.CounterID` before the call. `CounterHead.Result` is one byte at offset `4`; `Value` is at
offset `8`, and `StartTime` at `16`. The array stride is `24` bytes on both architectures.

`PROTOCOLCOUNTERS`, `CACHE_STATISTICS`, and `PROTOCOLSTATUS` occupy `460`, `84`, and `1012` bytes respectively.
`WINSTATIONINFORMATION` and `WINSTATIONINFORMATIONEX_LEVEL1` each occupy `1216` bytes.

## Virtual IP

`WinStationQuerySessionVirtualIP` accepts an address family and produces `WINSTATIONREMOTEADDRESS`, which
occupies `32` bytes. The family returned by RPC must match the requested family.

| Field | Offset | Size |
| --- | --- | --- |
| Address family | `0` | `2` |
| Port | `4` | `2` |
| IPv4 address / IPv6 flow information | `8` | `4` |
| IPv4 trailing bytes | `12` | `8` |
| IPv6 address | `12` | `16` |
| IPv6 scope ID | `28` | `4` |

The gaps at offsets `2` and `6` are alignment padding. These paths establish no caller-side zero requirement
for padding. The IPv4 path does not initialize the whole 32-byte extent; read only the active variant.

## Virtual channels

`WinStationVirtualOpen` reads exactly eight bytes from `Name`, then writes a terminator at byte `7` of its
local copy. The caller must provide eight readable bytes, even for a shorter name. Only the first seven
bytes can reach channel creation. `WinStationVirtualOpenEx` checks a nonnull, nonempty string and forwards
the name and flags to the channel helper.

## Connection properties

`WinStationGetConnectionProperty` and `WinStationGetCurrentSessionConnectionProperty` return an allocated
`TS_PROPERTY_VALUE` through a pointer-to-pointer. The discriminant is a `USHORT` at offset `0`.

| Type | Union member |
| --- | --- |
| `1` | 32-bit scalar |
| `2` | Counted wide-string descriptor |
| `3` | Byte length and byte-buffer pointer |
| `4` | Inline `GUID` |

The union starts at offset `8` on x64 and `4` on x86. Nested string/binary pointers are at `16` or `8`.
The whole object occupies `24` or `20` bytes. Alignment gaps are padding. String terminator accounting
should not be inferred from the binary variant's length convention.

`WinStationFreePropertyValue` frees the nested allocation for types `2` and `3`, then the outer object.
It rejects a null object with `ERROR_INVALID_DATA`.

The monitor-configuration and correlation GUID constants are inherited values. Neither appears in the
analyzed client images; these clients forward caller-provided property GUIDs. Their payload contracts are not established by these client paths.

## Notifications

Window registration uses `WNOTIFY_THIS_SESSION == 0` or `WNOTIFY_ALL_SESSIONS == 1`. The `Ex` variants additionally
accept an RPC notification mask. The simple registration wrappers supply `0xFFFFFFFF` for that mask.

Event registration duplicates the caller's event handle and returns an opaque registration object. Release
the object with `WinStationUnRegisterNotificationEvent`; it is not a kernel handle. A null registration is
invalid and is dereferenced by the release path.

The event-registration mask is translated before RPC; it is not the `WEVENT_*` mask accepted by
`WinStationWaitSystemEvent`. Both architectures perform this mapping:

| Input bit | RPC mask | Notification |
| --- | --- | --- |
| `0x001` | `0x100` | Console connect |
| `0x002` | `0x200` | Console disconnect |
| `0x004` | `0x002` | Connect |
| `0x008` | `0x004` | Disconnect |
| `0x010` | `0x008` | Logon |
| `0x020` | `0x010` | Logoff |
| `0x100` | `0x060` | Shadow start or stop |

Other input bits do not contribute to this mapping. RPC notification meanings are defined in
[MS-TSTS `tsdef.h`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/c00907ea-a492-415b-bc19-fbcb36934710).

## Current-session, child-session and rendering APIs

`WinStationGetCurrentSessionCapabilities` clears its required four-byte output before checking the service
or level. It accepts level `1`.
Other levels fail. `WinStationGetCurrentSessionTerminalName` clears the first character and copies through
`StringCchCopyW` with a capacity of `32` WCHARs, including the terminator.

`WinStationEnableChildSessions` takes a byte boolean; `WinStationIsChildSessionsEnabled` writes one.
Child/parent session IDs are DWORDs. `WinStationCreateChildSessionTransport` writes a wide string into a
caller buffer; the NDR capacity range is `1` through `256` characters.

`WinStationSetRenderHint` returns `HRESULT`. A local/nonremote session returns `S_OK` without changing the hint.
The remote helper requires a valid hint-ID pointer and window. It reads the existing 64-bit ID and writes
a generated ID when the input is zero. Hint types `1` and `2` allow a null data pointer; a nonnull payload
for those types must have length `16`. The helper accepts only types below `3`.

## Certificates, credentials and logon data

`TS_USER_CERTIFICATES` contains a DWORD count, DWORD byte length, and pointer, totaling `16` bytes on x64 or
`12` on x86. `WinStationFreeUserCertificates` frees the buffer and object and accepts null.

`TS_USER_CREDENTIALS` contains three DWORDs followed by an aligned pointer, totaling `24` or `16` bytes.
The first DWORD is initialized to zero; the second is copied from RPC metadata. The third is the payload's
byte length. Some payloads undergo password/PIN decryption before ownership is transferred to the caller.
The payload can represent different authentication formats and remains `PVOID`.
`WinStationFreeUserCredentials` clears the indicated payload bytes, frees both allocations, and returns
`ERROR_INVALID_PARAMETER` for null.

`WinStationGetInitialApplication` returns two allocated wide strings and two one-byte outputs. Their individual
meanings remain unknown. `WinStationGetUserProfile` takes a pointer-sized handle value and returns three
allocated wide strings. The required handle subtype and access rights remain unknown.

Logon-redirection calls use the wide-string and DWORD slots declared in the header. Unnamed DWORDs and strings
retain `Unknown` names. `WinStationSystemShutdownWait` accepts a millisecond timeout and an optional DWORD output;
the meaning of that output remains unknown.

## Ownership and unresolved legacy data

Close server-binding objects with `WinStationCloseServer`. Use `WinStationFreeMemory` for flat buffers and
the individually allocated strings identified in the header. Both accept null. Use the matching structured
release function for process arrays, extended session arrays, properties, certificates and credentials.
Freeing only an outer allocation can leak its children. Virtual-channel handles have a separate lifetime contract.

Legacy transport, trace, cache, video and device structures are often only copied or rejected by these clients.
Their historical field meanings remain protocol-derived. No current producing path independently establishes
all members of `WINSTATIONEXECSRVSYSTEMPIPE`, `WINSTATIONINFORMATIONEX_LEVEL2`, or every `SESSIONTYPE` value.
These limits do not invalidate the inherited declarations, but they prevent assigning new semantics from
client-side copies alone.

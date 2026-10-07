# WinSta API analysis

## Scope

`winsta.dll` exposes private Terminal Services client APIs. The original analysis used these implementations:

| Architecture | File version | SHA-256 |
| --- | --- | --- |
| x64 | `10.0.26100.6899` | `6fb63648dee54c11b91d5778aba7b2325aed9419559e877b64fd7117c27d2bcf` |
| x86 | `10.0.26100.8972` | `ffa6abb538d243266d376c7a0b460bb0634dc6be6b3101db89e6612b588e7996` |

These are the original input identities stored in the IDA databases. Private behavior can differ between Windows
versions. Additional verification on 10.0.26100.9278 and scoped revalidation on 10.0.28000.2804 are described
below. ARM64 and ARM64EC implementations are outside this analysis.

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
| Win32 error code in `ULONG`, with `0` for success | `WinStationConsumeCacheSession`, `WinStationIsBoundToCacheTerminal`, `WinStationIsSessionPermitted`, `WinStationSystemShutdownStarted`, `WinStationSystemShutdownWait`, `WinStationRedirectErrorMessage`, `WinStationGetUserCredentials`, `WinStationFreeUserCredentials`, `WinStationNegotiateSession`, `WinStationReportUIResult` |
| `ULONG` translated RPC status, with an early local-binding-failure exception | `ServerLicensingSetPolicy`; a null-context binding failure returns `0` and sets `RPC_S_INVALID_BINDING` without executing the operation |
| `HRESULT` | `WinStationSetRenderHint`, `WinStationCreateChildSessionTransport`, `WinStationRedirectLogonBeginPainting`, `WinStationRedirectLogonStatus`, `WinStationRedirectLogonMessage`, `WinStationRedirectLogonError`, `WinStationGetUserProfile`, `WinStationGetRedirectAuthInfo` |
| `NTSTATUS`, with `NT_SUCCESS` to test the result | `_WinStationShadowTarget`, `_WinStationShadowTarget2` |

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
DWORDs. The current fields are `SessionId`, `State`, `SessionType`, and `ChildSessionId`, at offsets 4, 8, 12,
and 16. Their names and enum semantics are inherited from phnt; the copy loop does not independently establish
the meaning of every field.

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

`WinStationGetInitialApplication` returns two allocated wide strings and two one-byte outputs. The header retains
phnt's `CommandLine`, `WorkingDirectory`, `ApplicationAllowed` and `Maximize` names; their individual purposes
were not independently recovered. `WinStationGetUserProfile` takes a pointer-sized unsigned scalar represented by
`HANDLE` and returns three allocated wide strings. Its `SessionId`, `UserName`, `Domain` and `ProfilePath` names
follow phnt; the required input subtype and access rights remain unknown.

Logon-redirection calls use the wide-string and DWORD slots declared in the header. Existing phnt parameter names
are retained where the inspected client does not contradict their roles. `WinStationSystemShutdownWait` accepts
a millisecond timeout and an optional DWORD output named `Result`; its purpose was not independently recovered.

The current header also retains phnt's capability enum and `PBOOL` result, the CHAR element category of the direct
device-ID buffer, and inherited policy, negotiation, notification-clock and UI-result interpretations. These names
and interpretations are not new reverse-engineering findings. Width, direction or client forwarding alone does not
invalidate an existing semantic name. The verified ABI corrections remain: native-sized inputs, one-byte outputs,
required output slots, fixed 257-WCHAR extents and corrected return types. The 23 unresolved legacy prototypes
remain excluded from NDK; no upstream-only declaration was added by this naming correction.

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

## Verification on 10.0.26100.9278

The current x64 and WOW64 images both have file/product version `10.0.26100.9278`. The IDA input SHA-256 values
were read from each database and matched to the live PE files before assigning that version to the analysis.

| Architecture | SHA-256 |
| --- | --- |
| x64 | `94365e3090001ce4003d000424d07bf5ce3d28b9311372ab864e106117ec0072` |
| x86 | `23b43d57835a6f06dc0feff7599fd3b210ba851b410aae8a666e1ac7b50ed6fd` |

This pass collected complete disassembly for all 157 declarations in the initial merged-header snapshot, and
successful decompilation for all 157 x64 exports. Five x86 exports could not be decompiled; their complete
assembly and x64 counterparts remain available. Forty-nine direct `NdrClientCall3` paths were inspected in the
x64 client, with x86 NDR and assembly cross-checks for the corrected interfaces. Collection, argument-byte counts,
and wire descriptions do not establish all parameter semantics. The coverage manifest distinguishes newly
verified contracts, limited stub behavior, and declarations whose remaining semantics are inherited from phnt
or the existing analysis. ARM64 and ARM64EC runtime implementations were not examined.

`ServerLicensingSetAadInfo` is excluded pending ABI verification because its full native argument types remain unresolved.
The inherited declaration supplies two x86 arguments, but the current export returns `E_NOTIMPL` with
`ret 0x10` and does not read the argument area. The 16-byte cleanup is established; the original argument
count, categories, native widths, and meanings are not. No replacement historical prototype is inferred from
the non-reading stub.

## Notifications and profile outputs

The two event-registration exports return a full 32-bit `BOOL`. They duplicate the caller's kernel event handle,
allocate a wait-registration object, and write that object pointer through a pointer-sized output slot. The
returned object is opaque and must be released through `WinStationUnRegisterNotificationEvent`; it is not a
kernel handle. Unregistration also returns a full `BOOL` and dereferences the supplied object without a null check.
The previously documented mask translation is present in both current images.

`WinStationGetInitialApplication` returns two allocated wide-string pointers and two one-byte output values.
Both x64 and x86 NDR descriptions use `FC_CHAR` for those final output slots. The `ApplicationAllowed` and `Maximize`
names follow phnt; their individual purposes were not independently recovered. They must not be widened to `PULONG`
or `PBOOL`.

`WinStationGetUserProfile` takes a pointer-sized unsigned scalar, represented by `HANDLE` in this header. The
handle subtype and access rights remain unknown. It clears three required pointer-sized output slots before RPC
and returns the RPC HRESULT, or an HRESULT formed from a binding error. Its allocated strings use the normal
LocalAlloc/LocalFree ownership convention. Required output-slot pointers and nullable returned pointers are
different contracts: the NDR string referents are unique pointers, and the client does not validate that every
successful result contains a nonnull string.

## Licensing and request contexts

`ServerLicensingGetPolicy` requires a DWORD output pointer as its second argument. It returns a byte boolean.
The DWORD's meaning has not been independently established.

`ServerLicensingSetPolicy` takes an input DWORD and a required DWORD output pointer. After RPC it returns the
service's status translated through `RtlNtStatusToDosError`, normally zero for RPC success. With a null context,
failed local binding creation also returns zero and sets last error to `RPC_S_INVALID_BINDING` (1702), without
sending the policy RPC or writing the output. Zero alone therefore does not prove success. The final output
is not an input policy value. `ServerLicensingFreePolicyInformation` accepts a null outer
pointer or a null object. It also ignores objects whose `Version` is not 1. For version 1, it frees nonnull
`Name` and `Value` allocations and the containing object with `LocalFree`, without clearing the caller's pointer.

`WinStationNegotiateSession` uses an input/output RPC context slot as its first argument and a pointer-sized
unsigned scalar as its second argument. They are not an ordinary server-binding handle and a DWORD session ID.
The returned DWORD array has four-byte elements; its scalar field names remain inherited. The exact context
creation/release sequence and the scalar's meaning are not established by this client path.

`WinStationReportUIResult` takes an input RPC context, followed by two DWORDs. It returns a Win32 error code,
with zero for success. The first argument is not a DWORD session ID. The exact request-context subtype and
lifetime should not be inferred merely from the related negotiation/report RPC methods.

## Certificates and credentials

The native certificate wrapper receives RPC method 10 on RCMPublic interface
`bde95fdf-eee0-45de-9e12-e5a61cd0d4fe`, then copies the returned count, byte length, and data pointer into a native
object. The official `RpcGetUserCertificates` contract identifies `pcCerts` as the certificate count, `ppbCerts`
as the data, and `pcbCerts` as the byte length. The first native DWORD is therefore `Count`, not `Type`.
The native object occupies 16 bytes on x64 and 12 on x86; the pointer is at offset 8 on both architectures.
No particular certificate-blob encoding is inferred from the client copy.
See [MS-TSTS RCMPublic IDL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/7b70d367-5d92-4783-8bb7-ce1820ca8069)
and [RpcGetUserCertificates](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/aa5f03ee-8284-48f0-a3e0-3c4661336541).

`CRED_PROV_CREDENTIAL` and `TS_USER_CREDENTIALS` have compatible native layouts: three DWORDs followed by an
aligned pointer, occupying 24 bytes on x64 and 16 on x86. The first DWORD is initialized to zero, the next two
are copied from RPC metadata, and the third is the payload byte length. The free helper reads that length,
clears the payload, and frees both allocations. The client confirms this layout and ownership, but not every
inherited field name, including `AuthenticationPackage`, for all credential formats. These inherited names are distinct from the offsets and stores independently established above.

`WinStationGetRedirectAuthInfo` has six output parameters. Its first parameter receives a 16-byte GUID; it is
not an input GUID pointer. Its return follows HRESULT semantics. Its byte arrays and string use unique NDR
referents; their format-specific meanings remain inherited unless separately supported.

## Window messages, enumeration, and fixed arrays

`WinStationBroadcastSystemMessage` receives the message ID in its seventh argument, followed by native-width
`WPARAM` and `LPARAM` values. Its third argument supplies the target session ID. A zero second DWORD selects
that target, while a nonzero value omits that filter. The fourth and fifth DWORDs are passed to RPC without
establishing their meanings. The recipients pointer accepts null. The response value is read and updated:
for messages 26 and 27 the wrapper permits a null response pointer, but the direct worker for messages 536 and
537 can dereference it without a null check. A required input/output pointer is the conservative general SAL
contract. The message-specific payload is marshalled from `lParam`, not from a separate `MessageData` argument.
The worker normalizes its result to zero or one; it does not return an untruncated RPC status code.

`WinStationSendWindowMessage` constructs a local binding and ignores its native server-handle argument. Its
fourth argument is a pointer-sized unsigned value of unverified meaning. The sixth and seventh are native-width
`WPARAM` and `LPARAM`, and the eighth is a required DWORD output pointer, not an input timeout. For selected
messages, a pointer payload in `lParam` is read and copied before RPC. Its shape is message-specific.

`WinStationEnumerateContainerSessions` takes an allocated-output pointer and DWORD count output. There is no
native server-handle argument. It constructs a local binding; the client does not establish every returned
record's field semantics.

The get/set last-Winlogon-notification RPC methods marshal a fixed 257-WCHAR subscriber-name array on both
architectures. The setter therefore requires 257 readable WCHARs even if a terminator occurs earlier.
The fixed-array descriptor alone does not establish a terminator guarantee for the getter. MAX_PATH is not
the marshalled extent.

`WinStationSendMessageA` requires terminated ANSI title/message strings: the conversion path computes
`strlen + 1`, independently of the accompanying length arguments. Connection-property getter success does
not guarantee a nonnull returned property object; the output slots remain required, with nullable results.

## Structure interpretation limits

The user-session converter produces 20-byte native records, sets `Version` to 1, and copies four DWORDs from
16-byte RPC records. The current header names those DWORDs `SessionId`, `State`, `SessionType`, and
`ChildSessionId` at offsets 4, 8, 12, and 16. The names and enum meanings are inherited; the copy loop does not
independently interpret them. The copy loop alone does not establish the enum associations or the meaning of every copied field.

The all-session fallback constructs 344-byte records and initializes a verified subset from `SESSIONIDW`.
The extended enumerator constructs 1112-byte records. Copy sizes, offsets, and initialized portions support
layout constraints; copied opaque data does not independently establish every new field name or semantic.
Failure-only or initializer stubs cannot recover unused historical parameter types. Their observed failure
code, output widths, and stack cleanup may be recorded, while the remaining inherited contract stays explicit.

## Previously excluded export verification

The following additional client observations were made on winsta.dll 10.0.26100.9278. The x64 input SHA-256
is 94365e3090001ce4003d000424d07bf5ce3d28b9311372ab864e106117ec0072; the WOW64 x86 input SHA-256 is
23b43d57835a6f06dc0feff7599fd3b210ba851b410aae8a666e1ac7b50ed6fd. These identities apply to this section
only; earlier observations retain their original binary scope. ARM64 and ARM64EC were not reverse analyzed.

ServerLicensingOpenW takes one native-sized input that must be zero. A nonzero value is rejected before
RPC binding with RPC_S_SERVER_UNAVAILABLE. These implementations never read pointee data, so the original
semantic type is unknown. The zero-only input is exposed as a reserved ULONG_PTR Unknown. The result is an
opaque native licensing RPC context or NULL. The RPC operation's output is FC_BIND_CONTEXT; it is distinct
from the binding-object domain returned by WinStationOpenServer*. The RPC's own byte result controls whether
the context is returned, while its separate status output is 32 bits.

_WinStationWaitForConnectEx takes GUID by value. WOW64 copies the caller's 16-byte stack argument into a
local value and returns with ret 0x10. The x64 ABI passes the 16-byte aggregate indirectly. Both RPC type
tables describe the GUID layout: a DWORD, two WORDs, and eight bytes. The client forwards its GUID address
as an input argument to RpcConnectTerminalEx and provides no caller GUID writeback. The RPC returns a
32-bit HRESULT; the native export reports success or failure in the one-byte BOOLEAN result.

WinStationQueryAllowConcurrentConnections has no parameters. Its x86 import is decorated @0 and the
export returns without an argument cleanup immediate. Both current implementations are deprecated stubs
that set ERROR_INVALID_FUNCTION and return FALSE in AL. There is no output-buffer parameter.

The other 22 previously excluded declarations remain unresolved. Together with `ServerLicensingSetAadInfo`,
23 current exports are withheld from this header. Twenty-one are stubs whose positive
x86 stack cleanup agrees with the SDK import library but does not establish argument count, scalar
widths, pointer types, or direction. ServerLicensingLoadPolicy and ServerLicensingUnloadPolicy share one
stub setting ERROR_CALL_NOT_IMPLEMENTED; the other stubs set ERROR_INVALID_FUNCTION. No code callers in
these two client images establish the missing argument types. Filling the cleanup with invented
ULONG_PTR Unknown slots would hide the uncertainty and is not supported by this evidence.

WinStationFreeUserSessionInfo is implemented, but its full ABI remains unproved. It passes a nonnull first
pointer to LocalFree once and returns TRUE without checking LocalFree's result; NULL gives
ERROR_INVALID_PARAMETER and FALSE. It reads no fields from the allocation. WOW64 requires eight argument
bytes but neither architecture reads the second parameter. Its scalar/pointer category and x64 width are
not established, nor is a historical entry-count contract. It remains excluded until independent
functioning implementation or caller evidence establishes that second parameter.

For these BOOLEAN results, only AL is an output contract; the upper EAX/RAX bits can retain unrelated
values. Constant-failure stubs do not prove their historical output contracts or restore the semantics
of removed operations.

### Unresolved ABI inventory (10.0.26100.9278)

This per-export inventory retains the evidence for all 23 excluded declarations. The input
identities are those stated at the start of this section. VAs use image bases 0x180000000
(x64) and 0x10000000 (WOW64). Cleanup sizes and observed results describe these images only;
they do not recover unused argument categories or establish safe replacement prototypes.

| Export | x64 VA | WOW64 VA | x86 cleanup bytes | Observed result | Evidence boundary |
| --- | --- | --- | ---: | --- | --- |
| `ServerGetInternetConnectorStatus` | `0x18002de10` | `0x10039e10` | 12 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `ServerLicensingLoadPolicy` | `0x18002da40` | `0x10039b20` | 8 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `ServerLicensingSetAadInfo` | `0x18002dc00` | `0x10039c60` | 16 | EAX: `E_NOTIMPL` | non-reading stub; inherited two-argument @8 declaration conflicts with ret 0x10 and the @16 symbol; argument count/categories/native widths remain unknown |
| `ServerLicensingUnloadPolicy` | `0x18002da40` | `0x10039b20` | 8 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `ServerQueryInetConnectorInformationA` | `0x18002de50` | `0x10039e40` | 16 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `ServerQueryInetConnectorInformationW` | `0x18002de90` | `0x10039e70` | 16 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `ServerSetInternetConnectorStatus` | `0x18002ded0` | `0x10039ea0` | 12 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `WinStationActivateLicense` | `0x18002df10` | `0x10039ed0` | 16 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `WinStationConnectA` | `0x18002e010` | `0x10039f90` | 20 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `WinStationEnumerate_IndexedA` | `0x18002e110` | `0x1003a050` | 20 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `WinStationEnumerate_IndexedW` | `0x18002e150` | `0x1003a080` | 20 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `WinStationFreeUserSessionInfo` | `0x180013610` | `0x10034ae0` | 8 | BOOLEAN/AL | first pointer passed to LocalFree; second slot never read; its x64 width/category remains unknown |
| `WinStationGenerateLicense` | `0x18002e190` | `0x1003a0b0` | 16 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `WinStationGetLanAdapterNameA` | `0x18002e1d0` | `0x1003a0e0` | 24 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `WinStationGetLanAdapterNameW` | `0x18002e210` | `0x1003a110` | 24 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `WinStationInstallLicense` | `0x18002e290` | `0x1003a170` | 12 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `WinStationNameFromLogonIdA` | `0x18002e2d0` | `0x1003a1a0` | 12 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `WinStationQueryLogonCredentialsW` | `0x18002e410` | `0x1003a280` | 4 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `WinStationRemoveLicense` | `0x18002e490` | `0x1003a2e0` | 12 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `_NWLogonQueryAdmin` | `0x18002e5d0` | `0x1003a3d0` | 12 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `_NWLogonSetAdmin` | `0x18002e610` | `0x1003a400` | 12 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `_WinStationNotifyLogon` | `0x18002e850` | `0x1003a590` | 32 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |
| `_WinStationOpenSessionDirectory` | `0x18002e8d0` | `0x1003a5f0` | 8 | BOOLEAN/AL | deprecated stub; no argument reads or code callers in either IDB; argument categories/directions unknown |

`ServerLicensingSetAadInfo` is absent from both 10.0.28000.2804 export tables. That absence does not
resolve the older ABI or establish an exact removal build. Its former local two-argument
declaration and @8 import were withdrawn; no guessed replacement was introduced.

The 23 upstream prototypes remain unchanged in
[PR #3070](https://github.com/winsiderss/systeminformer/pull/3070). Verified repairs, binary
checkpoints and test limits are summarized in its
[follow-up comment](https://github.com/winsiderss/systeminformer/pull/3070#issuecomment-6063796614).

## Scoped revalidation on 10.0.28000.2804

The following static pass used copied x64 and WOW64 `winsta.dll` files from an isolated guest collection.
Both files have file/product version `10.0.28000.2804`. Each new IDA input path, architecture and SHA-256
was matched to the copied PE and its collection manifest before assigning this version to the evidence.
The DLL version is independent of the guest OS revision.

| Architecture | SHA-256 |
| --- | --- |
| x64 | `256b19f4cda7f479fcb90c907334ebb04db5751ce3be9baa327c54672033d496` |
| x86 | `1e09860f856aedc6f6373b005bd31be8ebd2f37de606f5f31de8fc434c4df405` |

Both PE export tables contain 180 named exports. Compared with the 184 exports in 10.0.26100.9278,
exactly four names are absent and none are added: `ServerLicensingGetAadInfo`, `ServerLicensingSetAadInfo`,
`WinStationCreateAgentSessionTransport`, and `WinStationGetSpecialSessionFlags`. The previously established
contracts for the other three remain evidence for older inputs. This observation does not establish an
exact removal build or a maximum `NTDDI_VERSION` boundary. `ServerLicensingSetAadInfo` remains unresolved;
its absence here supplies no newer argument-type or stack-cleanup evidence. An internal or PDB name would
not establish a public export contract.

This pass collected complete function/chunk disassembly, CFGs and successful decompilation for 11 native
exports on each architecture: both event-registration methods, event unregistration, initial application,
user profile, licensing open/get-policy/set-policy/free-policy, the concurrent-connection query, and
`WinStationFreeMemory`. Seven supporting implementations were also inspected: two internal notification
registration helpers and five WOW64 RPC wrappers. The complete NDR procedure descriptors for
`WinStationGetInitialApplication`, `WinStationGetUserProfile`, `ServerLicensingGetPolicy`, and
`ServerLicensingSetPolicy` match the older 10.0.26100.9278 descriptors on both architectures, for eight
comparisons. Their relevant output-pointer/type chains were checked separately. This is scoped contract
revalidation, not semantic verification of every parameter or all 180 exports.

Event registration still duplicates a valid caller event, writes an opaque registration object on success,
and returns a full 32-bit zero/one value. Unregistration reads the supplied object without a null check;
only a nonnull object returned by successful registration is a valid release input. Initial application
still returns a byte Boolean and receives two allocated unique wide-string outputs plus two `FC_CHAR`
outputs. The latter establishes one-byte width, not Boolean meaning. User profile still marshals a
native-width unsigned scalar and three nullable unique wide-string outputs, and returns `HRESULT`.
Its null input is forwarded to RPC without a special client-side rejection; no fixed HRESULT or server
outcome is established for that input.

Licensing open still rejects every nonzero native-width input before RPC with
`RPC_S_SERVER_UNAVAILABLE`, including a high-word-only nonzero value on x64. GetPolicy's second argument
and SetPolicy's third argument remain DWORD output slots. The local-binding helper was additionally
cross-checked on both old and new architectures: failed context creation sets `RPC_S_INVALID_BINDING`
(1702). The policy wrappers return zero immediately, without issuing their operation RPC or writing the
output. After binding succeeds, a null output gives FALSE/last error 87 for GetPolicy and direct result
87 for SetPolicy; SetPolicy does not set last error to 87 on that validation path. The early binding
failure is a limitation, not successful policy execution. These paths support the bounded return
contract described above and do not establish the service-defined DWORD meanings.

FreePolicyInformation still ignores null outer/inner pointers and objects whose `Version` is not 1.
For version 1 it accepts null `Name`/`Value`, frees any nonnull nested allocations and the object with
`LocalFree`, and leaves the caller's pointer unchanged. A zero-initialized version-0 object tests only the
no-op branch. The concurrent-connection query still takes no arguments, sets `ERROR_INVALID_FUNCTION`,
and returns FALSE in `AL`; `WinStationFreeMemory` accepts null and otherwise calls `LocalFree` before
returning TRUE in `AL`.

No ABI change was found in these 11 declarations. This static pass did not execute the private APIs,
verify service-side parameter meanings, or establish runtime success. The earlier 157-declaration
coverage and its inherited/stub limitations remain separate; ARM64 and ARM64EC runtime implementations
were not examined.

## Runtime coverage status

The read-only collection successfully copied the four x64/WOW64 `winsta.dll`/`fveapi.dll` files with
file/product version `10.0.28000.2804`; those files supplied the static IDA inputs. Earlier startup/readiness
attempts stopped before private API calls. Hyper-V-Worker event 18514 identifies a guest OS reset, whose
internal cause and initiating process remain unknown. One failed automatic cleanup manifest and its
separate successful exact-checkpoint recovery record remain preserved independently.

The later run `NDK-PrivateAPI-20261008-230930-9657ddc1648c46e9b57f97498fa162eb` completed all eight child
cases with exit code zero, without timeout or token refusal. Four WinSta cases ran before VHD creation:
x64 and WOW64 against explicit target Session 0, then the same architectures against the observed active
console target Session 1. All four actual callers remained elevated, high-integrity administrators in
noninteractive Session 0; the console target was an API argument, not an interactive caller context.
Native stdout PIDs, pointer sizes and token observations matched the suspended-child launcher records.

The WinSta probes made 42 direct export invocations: 11 in each x64 case and 10 in each WOW64 case.
Internal helper/RPC calls and observation-only rows are not included in that count. Explicit registration
returned full `BOOL` value 1 for both target sessions on both architectures; each entered the nonnull
registration-object branch and was immediately unregistered with full `BOOL` value 1. Thus four successful
registration/unregistration pairs were observed, with the measured registration-slot canaries intact.
Notification delivery itself was not tested. Current-session registration returned 0 with last error 87
for all four Session 0 callers; its successful output path remains untested in this caller context.

InitialApplication returned 0 with last error 2250 in all four cases. Its two one-byte values changed from
`0xC3` to zero while each preceding byte and four following bytes retained `0xC3`; both string-output slots were NULL.
This observes failure-path byte writes and intact adjacent canaries, not successful string outputs or the
meaning of either byte. UserProfile(NULL) returned `0x80070005` in all four cases. Its success string outputs
were not exercised, and its logged `guards: true` is a fixed probe field, not an independent canary check.
No `WinStationFreeMemory` branch was entered.

The remaining observed paths were consistent across targets and architectures:

- The no-argument concurrent-connection query returned FALSE and set last error 1.
- LicensingOpenW returned NULL with last error 1722 for four nonzero inputs and the two x64 high-word-only inputs.
- GetPolicy(NULL, NULL) returned FALSE with last error 87 four times. SetPolicy(NULL, 0, NULL) returned 87
  four times and preserved the seeded last-error value `0x12345678`. These reached the null-output validation
  paths, without issuing policy RPCs. The separate early-binding-failure `0`/1702 path was not observed here.
- Four version-1 FreePolicy calls, each using an outer `LocalAlloc(LPTR)` object with NULL `Name` and `Value`,
  left the caller's pointer unchanged. That observation does not independently verify heap deallocation or
  freeing nonnull members, and its reported value 1 is the pointer comparison, not a native VOID return.

All four reviewed DLL identities matched before the calls, after the WinSta phase and at the end of the
complete run. The overall evaluator recorded 213/213 checks passing with status `Limited`, preserving the
unexercised success-path limits above. Automatic cleanup verified Off, removed the exact owned checkpoint
and VHD, and retained the original two disk roots, two pre-existing checkpoints and network configuration.
These selected client observations do not establish every parameter meaning or historical implementation.

The NDK solution passed eight build configurations and four native UnitTest runs. The PR changes also
passed x86/x64/ARM64/ARM64EC header, call-shape and layout compilation checks. Those compilation and
basic-library results remain distinct from the scoped x64/WOW64 private-API observations above; ARM64 and
ARM64EC runtime implementations were not exercised.

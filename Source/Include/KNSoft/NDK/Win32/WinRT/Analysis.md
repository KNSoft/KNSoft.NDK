# HSTRING analysis

## Scope

[HString.h](HString.h) defines the private `HSTRING` layout; [HString.inl](HString.inl) implements its string APIs.
The 2026-09-12 IDA review covered all 14 exports, `CHSTRINGUtil::CreateString`, and `STRING_OPAQUE::Release`.

| Binary | Architecture | File version | SHA-256 |
| --- | --- | --- | --- |
| `combase.dll` | x64 | 10.0.26100.8875 | `065096969039d1cefa7a15222b3951bf3b5950440c9b8e2de25b75a6a4b4a51c` |

The IDB hash matched the tested system binary. x86 was compared at runtime; ARM64 and ARM64EC were compile-checked.
Private layout and behavior may differ across Windows builds.

## Layout

The SDK exposes `HSTRING` as an opaque handle and `HSTRING_HEADER` as opaque storage.

| Field | x64 offset | x86 offset | Meaning |
| --- | --- | --- | --- |
| `Header.Flags` | `0x00` | `0x00` | Representation and cached properties |
| `Header.Length` | `0x04` | `0x04` | UTF-16 code units, excluding the terminator |
| `Header.Padding` | `0x08` | `0x08` | Eight padding bytes; no semantic use observed |
| `Header.Buffer` | `0x10` | `0x10` | Character buffer pointer |
| `RefCount` | `0x18` | `0x14` | Signed 32-bit reference count; owning strings only |
| `Data` | `0x1C` | `0x18` | Inline character storage; owning strings only |

`HSTRING_HEADER` occupies 24 bytes on x64 and 20 on x86. `HSTRING__`, including its first `WCHAR` and alignment
padding, occupies 32 and 28 bytes. Fast-pass references contain only the header, without `RefCount` or `Data`.

`Header.Padding` is padding, with no required value. The reviewed functions do not read it.
`WindowsCreateStringReference` zeroes it on x64; observed x86 contents are unspecified. The x64 write is an
implementation detail, not a requirement that callers clear these bytes.

The SDK declarations are imported under `MS_` names; assertions check handle and header size and alignment.
Include NDK before SDK `HSTRING` or WinRT headers to keep function declarations consistent.

Strings are immutable, counted UTF-16 and may contain embedded nulls or unpaired surrogates. A trailing null lies
outside `Header.Length`. `WindowsCreateString` copies the specified length without reading a source terminator.
Creation APIs return `NULL` for empty strings, but `WindowsGetStringLen` and `WindowsIsStringEmpty` read
`Header.Length` for non-`NULL` handles. A non-`NULL` handle with zero length is also empty.

## Flags

| Value | Name | Meaning |
| --- | --- | --- |
| `0x00000000` | `WRHF_NONE` | Owning string with no cached properties |
| `0x00000001` | `WRHF_STRING_REFERENCE` | Caller-owned header and buffer |
| `0x00000002` | `WRHF_VALID_UNICODE_FORMAT_INFO` | Unicode-format cache flag |
| `0x00000004` | `WRHF_WELL_FORMED_UNICODE` | Unicode-format cache flag |
| `0x00000008` | `WRHF_HAS_EMBEDDED_NULLS` | Cached embedded-null result |
| `0x00000010` | `WRHF_EMBEDDED_NULLS_COMPUTED` | Embedded-null result is cached |
| `0x80000000` | `WRHF_RESERVED_FOR_PREALLOCATED_STRING_BUFFER` | Name from private symbols |

The reviewed functions preserve the Unicode-format flags; their validation algorithm was not examined.
An unpromoted buffer uses the exact `Flags` value `HSTRING_BUFFER_SIGNATURE` (`0xF8B1A8BE`). Promotion and deletion
compare the whole value, not just `WRHF_RESERVED_FOR_PREALLOCATED_STRING_BUFFER`.

## Creation

`WindowsCreateString` rejects a `NULL` output pointer with `E_INVALIDARG`, otherwise clears the output first.
A `NULL` source with nonzero length returns `E_POINTER`; zero length succeeds with a `NULL` handle.

The x64 process-heap allocation size is `32 + 2 * length`. Multiplication and addition are checked for 32-bit
unsigned overflow (`MEM_E_INVALID_SIZE`); allocation failure returns `E_OUTOFMEMORY`.
The allocation is written to the output before copying. A source access violation leaves that output set,
with an incomplete header; such an allocation requires raw heap cleanup.

`CHSTRINGUtil::CreateString` accepts a `NULL` source with nonzero length: it allocates, skips copying, and sets the
header and terminator, leaving the content uninitialized. Fast-pass duplication and substring creation use this
path. `_Inline_HStringCreate` preserves it; calling the public `WindowsCreateString` would add an `E_POINTER` check.

## References and ownership

`WindowsCreateStringReference` borrows the caller's header and buffer. Validation and initialization are:

- Reject `NULL` output or header with `E_INVALIDARG`; clear the output only when both pointers are valid.
- Reject `MAXULONG` length with `E_INVALIDARG` before reading the source.
- Return `E_POINTER` for a `NULL` source with nonzero length.
- For a non-`NULL` source, check `sourceString[length]` even when length is zero; a missing terminator returns
  `E_STRING_NOT_NULL_TERMINATED`.
- Return `NULL` for zero length, leaving the header untouched. Otherwise set `Flags`, `Length`, and `Buffer`.

Keep the borrowed header and buffer alive and unchanged while using the reference. Deleting a reference does
nothing. `WindowsDuplicateString` copies fast-pass input into an owning string; for owning input it increments
the reference count and returns the same handle. Retain the returned handle.

`WindowsDeleteString` returns `S_OK` for `NULL` and fast-pass handles. For owning strings it atomically subtracts
one, checks the old signed count and wrapped new signed count, then frees when applicable. The inline preserves
these branches and signed wraparound, but omits Windows' negative-count diagnostic.

## Preallocated buffers

`WindowsPreallocateStringBuffer` requires both output pointers; otherwise it returns `E_POINTER` without clearing
either output. It clears valid outputs, checks the allocation size, allocates, and sets the header, terminator,
and signature. This build allocates even for zero length. Success writes `bufferHandle` before `charBuffer`,
which is observable with overlapping outputs.

Callers may write `length` code units before promotion, excluding the supplied terminator. A zero-length buffer
has no writable content; other implementations may use shared storage for it.

`WindowsPromoteStringBuffer` rejects a `NULL` output with `E_POINTER`, otherwise clears it. A `NULL` buffer succeeds
as empty. It checks the full signature, then the terminator; either failure returns `E_INVALIDARG`.
For nonempty buffers it clears `Flags` and transfers the handle; for empty buffers it frees the allocation.

`WindowsDeleteStringBuffer` accepts `NULL`. An invalid signature raises `STATUS_INVALID_PARAMETER` with
`EXCEPTION_NONCONTINUABLE`; a valid buffer is released through `WindowsDeleteString`.

## Reading and comparison

`WindowsGetStringRawBuffer` returns `Header.Buffer` without validation and optionally copies `Header.Length`.
For `NULL` input it returns an empty-string buffer and zero length.

`WindowsStringHasEmbeddedNull` requires an output pointer (`E_INVALIDARG`) and writes `FALSE` before reading the
input. `NULL` or zero-length input succeeds immediately. For nonempty input, `WRHF_EMBEDDED_NULLS_COMPUTED` avoids
rescanning. Otherwise it scans `Length` code units, preserves existing flags, sets `WRHF_EMBEDDED_NULLS_COMPUTED`
and, if needed, `WRHF_HAS_EMBEDDED_NULLS`. The flag update is an ordinary store, not an interlocked operation.

`WindowsCompareStringOrdinal` validates the result pointer first. Identical handles compare equal; if one is
`NULL`, the other's length determines emptiness. Otherwise it calls `CompareStringOrdinal` with explicit lengths
and case sensitivity enabled. `CSTR_LESS_THAN` maps to `-1`, `CSTR_GREATER_THAN` to `1`, and every other result to `0`.
Even a failed call returns `S_OK` with result `0`; `LastError` is not converted to an `HRESULT`.

## Substrings

Both substring APIs validate and clear `newString` before reading the input header, and skip `Header.Buffer`
for empty input. `WindowsSubstring` returns `E_BOUNDS` when `startIndex` exceeds the source length; an empty input
or `startIndex` equal to the source length succeeds with `NULL`.

`WindowsSubstringWithSpecifiedLength` checks, in order:

1. `startIndex` beyond the source length: `E_BOUNDS`.
2. Unsigned overflow of `startIndex + length`: `HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW)`.
3. End beyond the source length: `E_BOUNDS`.
4. Empty input or zero requested length: `S_OK` with `NULL` output.

Nonempty results use `_Inline_HStringCreate`. A compiler barrier after output clearing and `volatile` header
reads preserve access order under optimization, including the input read for zero-length requests.

## Verification and limits

Known differences from Windows:

- Error reporting through `RoOriginateErrorW`, `SendReport`, and ETW is omitted.
- Negative-count telemetry through `MicrosoftTelemetryAssertTriggeredNoArgs` and
  `MicrosoftTelemetryAssertTriggeredUM` is omitted.
- Empty-string addresses, exception addresses, and call stacks differ.

System-versus-inline validation on 2026-09-12:

| Configuration | Solution build | `HString` checks passed | `HStringCpp` checks passed |
| --- | --- | --- | --- |
| Debug x64 | Passed | 4486 | 14 |
| Release x64 | Passed | 4486 | 14 |
| Debug x86 | Passed | 4477 | 14 |
| Release x86 | Passed | 4477 | 14 |
| Debug ARM64 | Passed | Not run | Not run |
| Debug ARM64EC | Passed | Not run | Not run |

Coverage includes counted strings, embedded nulls, ownership, reference counts, preallocation, promotion,
substring bounds and overflow, comparison failures, and C++/WinRT and WRL interoperability. Nine additional x64
checks compare the observed padding initialization.

`PAGE_NOACCESS` probes verify output validation and clearing before input faults, skipped `Buffer` reads for empty
headers, and allocation publication before copy faults. Other probes cover overlapping outputs and internal
creation with a `NULL` buffer. Malformed-input probes establish observed access order, not supported API usage.

Allocation failure was not injected. Invalid reference-count boundaries were checked statically. Malformed
handles, concurrent interleavings, and other Windows builds were not exhaustively tested.

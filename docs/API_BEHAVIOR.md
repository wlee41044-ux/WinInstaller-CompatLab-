# v0.2 API behavior and evidence

This is a public, independently authored host subset. No Windows binary is executed by these tests. `data/api_contracts.json` is the function-level contract; `data/lab_manifest.json` remains the backward-compatible DLL/name list. Listing a name is not verification. `TESTED` applies only to the declared host arguments and limitations. Most Win32 functions remain `PARTIAL` because flags, objects or ABI arguments are missing.

## File changes

Keep the existing `FileApi` interface/target and strict C/D sandbox mapping. Creation/opening with read access is allowed for CREATE_NEW/OPEN_ALWAYS. CREATE_ALWAYS and TRUNCATE_EXISTING require write access in this subset. Existing OPEN_ALWAYS preserves contents. CREATE_ALWAYS truncates only after the initial inode share/permission checks. `Result::error` still controls success; a new defaulted `last_error` carries successful CREATE_ALWAYS/OPEN_ALWAYS diagnostics: 183 for an existing file and 0 for a new one. Do not turn a successful handle into failure because this diagnostic is 183. Recompile C++ consumers after this header change.

Invalid CRT access combination `_O_WRONLY|_O_RDWR` now fails with 87 before truncation. Read-only attributes map to the host owner-write bit; write opens and destination replacement reject them. Negative resulting seek returns 131; the pointer remains unchanged. FlushFileBuffers now requires GENERIC_WRITE, returning 5 for read-only/metadata handles. C-to-D moves without copy support return 17 even when the two virtual drives share one host filesystem. Unsupported move flags still return 50.

A Linux x86-64 page-fault regression probe also verifies that size-only Registry queries write the output size without first reading its potentially indeterminate previous value. It is supplementary host instrumentation; the core remains portable C++17.

Existing protections remain: descriptor-relative traversal with O_NOFOLLOW, symlink rejection, device/ADS/UNC/NT/path-escape rejection, conservative trailing dot/space rejection and ASCII-insensitive lookup. Exact Korean and supplementary UTF-16 names roundtrip. Dots, repeated separators and Unicode-wide case folding are not normalized. Hard links, concurrent external namespace mutation and hostile changes to sandbox ancestors are outside the isolation contract: the adapter must exclusively control a trusted sandbox root and its namespace. This is not a sandbox against another host process with write access to that namespace.

Known inherited differences: share rules are per FileApi, not globally between processes; zero-access metadata opens conservatively follow ordinary sharing checks rather than the Windows attribute-access exemption; FILE_SHARE_DELETE currently allows immediate POSIX unlink instead of NT delete-pending; case-only/directory rename is not implemented; a directory destination uses the existing conflict error 32. The CRT errno helper returns host errno constants; adapters must translate platform-dependent constants to guest MSVC values. No full Windows path, ACL, attribute or object-manager behavior is claimed.

## Registry contract

`RegistryApi` has no filesystem access. Each instance owns its keys, values and live handles; the only global state allocates unique opaque handle IDs. No key/value state crosses contexts. Destruction releases all state, including unclosed handles. `liveHandleCount()` provides lifecycle verification. Use one instance per guest process. This deliberately does not implement Windows' cross-process shared registry or persistence.

- HKCU is writable. HKLM defaults to read-only; missing keys return 2, not invented OS defaults. `RegistryOptions{true}` explicitly enables writes only to that instance's virtual HKLM. No real host settings are touched.
- Open does not create. Create recursively creates missing path components, reports 1 for new or 2 for existing, and opens existing keys without overwriting values. The hive access policy models a fixed security policy; child creation/open checks that policy rather than the parent handle's access mask, matching the documented distinction from set/query access checks.
- Query needs KEY_QUERY_VALUE; set needs KEY_SET_VALUE. KEY_READ/WRITE/ALL_ACCESS and their subsets are accepted. Unsupported WOW64 flags/options fail with 50. ACL modification, notification and enumeration APIs are not implemented merely because their access bits can be requested.
- Empty value name denotes the unnamed value; a key has no default value unless set. Null optional value names must be decoded to the empty string by the adapter. Open of an empty predefined hive returns that hive; open/create of an existing nonroot returns a new handle. Closing allocated handles invalidates them, while closing the two predefined roots succeeds without destroying them. Normalize 64-bit sign-extended HKEY constants in the adapter.
- Names are UTF-16, ASCII-insensitive with exact matching for other code units; full Windows Unicode case folding is not implemented. NUL/malformed UTF-16, empty path components, components over 255 UTF-16 units and value names over 16383 units are rejected with 87. More than 32 path components per call or 512 total levels is outside the subset (50).
- REG_SZ/REG_EXPAND_SZ/REG_DWORD/REG_QWORD/REG_BINARY store exactly the supplied bytes. Correct Windows W strings use UTF-16LE, including a two-byte null terminator in cbData; DWORD/QWORD use little-endian 4/8-byte payloads. Like a raw registry value store, the module does not repair malformed payload lengths, expand environment variables or synthesize terminators. An unterminated stored string remains unterminated when queried. REG_MULTI_SZ and other types return 50.
- Query with null data returns the required **byte** size and optional type. A small buffer returns 234 and required byte size; this implementation leaves data untouched (Windows leaves its contents undefined). A nonnull data buffer without size returns 87. Missing values return 2; do not rely on output sizes on failure. Null data with zero size is valid for set; nonzero size with null data returns 87 before changing the original value. Set deep-copies input bytes.
- `REG_OPTION_NON_VOLATILE` means lifetime of this virtual hive only; no disk persistence is provided. VOLATILE, link and backup options are rejected. No delete/enum functions or 32/64 views in v0.2. Public std::string/container allocations can throw; the ABI adapter must catch host allocation exceptions and return ERROR_NOT_ENOUGH_MEMORY without unwinding into guest code. Set's data-copy allocation failure already maps to error 8.

## Authoritative references

Semantics were checked against Microsoft documentation, not an actual Windows execution oracle. These pages define the contract; host tests cover the stated subset only.

- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [SetFilePointer / negative seek](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfilepointer)
- [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
- [MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw)
- [_open / _wopen](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/open-wopen)
- [RegOpenKeyExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw)
- [RegCreateKeyExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw)
- [RegQueryValueExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw)
- [RegSetValueExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexw)
- [RegCloseKey](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey)
- [Registry access rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)

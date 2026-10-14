# Private integration contract — v0.2

Private Windows x64 Runtime → Win32 API Adapter → Public Compatibility Module → Isolated Host Resources.

No private repository was accessed, checked out or modified to develop this batch. Public modules do not read x64 registers, dereference guest pointers or depend on Android Activity. Preserve MIT and pin a reviewed commit.

## Linkable interfaces

CMake targets: existing `winclab_file_api` and independent `winclab_registry_api`. Headers: `winclab/file_api.h`, `winclab/registry_api.h`; C++17. Registry reuses SDK-free Error/Result types from the file header but requires no FileApi instance/library or POSIX resource. File target requires Linux/Android POSIX. Build and run public host tests before consuming a version.

```cpp
winclab::FileApi files(trusted_isolated_virtual_drive_root);
winclab::RegistryApi registry;  // writable HKCU; read-only virtual HKLM
// Explicit installer policy, only when desired:
// winclab::RegistryApi registry(winclab::RegistryOptions{true});
```

Create a fresh resource context for each process. Give file contexts separate roots when isolation is required. Reusing a root across FileApi instances does not create cross-process share checking. Registry objects never share key/value state. Handle numbers are tokens inside the owning context, never native pointers. Keep guest handle tables and resource-type tags in the private adapter so a guest cannot confuse file/registry/CRT handles.

## ABI adapter responsibilities

1. Decode Windows x64 ABI registers/stack and Windows-width integers privately. Validate all guest input/output ranges before any public operation, including optional output pointers. Copy/limit null-terminated UTF-16 names into owned host strings. Canonicalize the two predefined HKEY values, including sign extension. Use little-endian bytes, not host `wchar_t` or host-endian integer addresses.
2. Select only the implemented parameter subset. Check RegCreateKeyEx Reserved=0; class must be absent/ignored by documented policy; reject unimplemented security attributes rather than silently granting them. RegSetValueEx Reserved must be 0 and RegQueryValueEx reserved pointer NULL. Unsupported options/views/types must return explicit errors; do not dispatch them as ordinary calls.
3. CreateFile returns INVALID_HANDLE_VALUE on error and a valid guest handle on success. Set guest LastError from `error` on failure. On successful CREATE_ALWAYS/OPEN_ALWAYS, use `last_error` (0 or 183), **not** `error`; other successful functions generally do not prescribe resetting LastError. Results are C++ wrappers, not ABI structures. Recompile after v0.2 adds the defaulted success diagnostic field.
4. Map other file methods to BOOL/byte-count outputs and INVALID_FILE_ATTRIBUTES/GetFileSizeEx/SetFilePointerEx conventions. CRT calls return -1 on failure and use per-thread guest errno, translating host numeric differences (e.g. ENOTEMPTY). `_get_osfhandle` borrows; `_close` owns lifetime. Public closeHandle deliberately rejects borrowed CRT handles. Preserve existing private read-only operations and use module-specific feature flags/regression comparisons.
5. Registry methods map `Error` directly to Windows LSTATUS; do **not** substitute BOOL or GetLastError. Open/create write guest output handles only on success. Copy optional disposition separately. Query preserves two-call size negotiation in bytes, writes required size on 234 and never writes beyond validated output capacity. Decode null value names as empty strings; null RegOpenKeyEx subkey as empty; RegCreateKeyEx NULL subkey is invalid. Use the returned type; do not assume all values are strings or null-terminated.
6. Catch allocation exceptions on all ABI boundaries and return guest error 8. Keep output memory valid during the call. Synchronize process teardown so no operation uses destroyed contexts; registry/FileApi locking is not a lifetime manager.
7. Host filesystem access is restricted to a caller-designated trusted root. The runtime must exclusively control that namespace, forbid externally introduced links/hardlinks, and avoid hostile concurrent mutation of ancestors or directories. Modules reject guest path traversal/symlinks but cannot isolate against another host writer with the same permissions.

## Risk and staged private checks

| Area | Integration risk | Required validation |
|---|---|---|
| Create/open/CRT | byte counts, modes, LastError/errno and borrowed handle ownership | Existing read-only regressions, binary roundtrip, rejected truncate preserves original |
| Delete/rename | per-instance sharing, POSIX unlink differs from NT pending-delete, no cross-drive copy | Synthetic original/staged files, open-handle lifetime, no-clobber replacement; keep risky cases disabled |
| Registry | HKEY normalization, LSTATUS, pointer optionality and byte-size negotiation | Five API bridge tests, exact UTF-16LE/DWORD/QWORD, canaries, missing keys and HKLM denial |
| Context lifecycle | state contamination, dangling handles, no persistence | Two distinct contexts, stale/foreign handles, process exit cleanup and clean relaunch |
| Host namespace | external mutation not covered by per-instance mutex | Exclusive app-owned sandbox, symlink escape probes, preserve originals |

Do not implement disk persistence by pointing RegistryApi at host system configuration. Design a separate versioned storage layer if future evidence requires it. Default v0.2 settings last only until that virtual process context is destroyed.

Actual APK and EXE checks remain future private work: invoke the reached API through the real adapter; verify guest register/stack conventions, LastError/errno/LSTATUS, valid output memory, first usable GUI frame, original file preservation, process exit and user-device relaunch. No emulator, APK or device verification occurred here.

Integration evidence fields: `app_class, exe_arch, API actually reached, first missing API, stop_reason, host side_effects, exit_condition, GUI_first_frame, user_device_validation`. Use UNKNOWN for missing evidence; static import presence is not a reached API.

# Private integration contract

This open module accepts decoded Windows path values (UTF-16) and validated host buffers. It does not accept emulated register values or pointers.

The **private** Android EXE Installer must:
1. Pin a verified version/commit of this library; retain its MIT license.
2. Instantiate one `winclab::FileApi` per new Windows guest process with the private runtime's existing isolated virtual-drive root.
3. Decode x64 Windows ABI calls (registers, stack slots, UTF-16 guest strings, memory ranges) **inside the private runtime**, then delegate only the supported file operation.
4. Map `winclab::Result` to exact Win32 ABI return conventions and per-thread `GetLastError` / CRT `errno`. The `Result` wrapper is not itself a Windows ABI structure.
5. Keep existing working read-only operations, prepared cache, Warm Runtime and Shared Warm Environment behavior unchanged; use focused feature flags or regression comparisons.
6. Validate create/write/truncate/delete/rename and failure paths against synthetic files **first**, then separately against authorized real applications with original files preserved.

Priority integration candidates: CRT `_wopen` binary write/create modes and `DeleteFileW`, followed by `MoveFileExW`. These were selected because actual app diagnostics exposed file-operation gaps, **not** because this public code has already fixed them in the private interpreter.

## Safety and scope

The lab blocks `.. `, symlinks, alternative data streams, UNC/NT paths and unsupported modes by design. Only `C:\\...` and `D:\\...` are mapped inside its own sandbox. Windows-style case matching is currently ASCII-only; do not claim Unicode-complete behavior.

Sharing rules are enforced within one `FileApi` object, not between unrelated OS processes. Unsupported features should produce explicit errors rather than simulated success. The private runtime must prevent arbitrary host paths from reaching this library. Do not publish runtime code, user EXE paths, games or diagnostics here.

Integration report: `app_class, exe_arch, import/API reached, first missing API, stop_reason, host side-effects, exit condition, GUI first frame, user-device validation`. Mark missing evidence as UNKNOWN.

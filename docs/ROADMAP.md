# Compatibility-first roadmap

This lab prioritizes APIs which unlock **more different applications**, not CPU speed.

**v0.1 — independent host module:** Win32 file creation/read/write/seek/delete/rename, CRT binary file descriptors, secure virtual-drive paths, synthetic C++ tests and PE import comparison.

**Next batch — integrate privately:** Compare the current private runtime's import handlers with v0.1; implement tested adapters for `_wopen` write/create and `DeleteFileW`. Demonstrate unchanged read-only behavior and validate actual EXE output only after private CI and user Android testing.

**Next standalone module candidate:** Registry data-model subset (`RegOpenKeyExW`, `RegQueryValueExW`, `RegSetValueExW`, `RegCloseKey`) with hive isolation and deterministic Windows error mapping.

**Later:** Processes, synchronization, COM dialogs, GUI resources and graphics APIs based on repeated failures across legally obtained test programs.

Do not fake compatibility by returning unconditional success for unsupported APIs. Prefer distinct reproductions with regression tests, matching Windows-visible behavior and isolated state. Do not change the private x64 emulator in public CI.

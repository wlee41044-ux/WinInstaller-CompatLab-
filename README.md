# WinInstaller CompatLab

**Open-source Windows compatibility modules** for [Android EXE Installer](https://github.com/wlee41044-ux/Android-exe-Installer). This repository is an independently authored, MIT-licensed laboratory for improving the variety of Windows programs that can run; it is **not** a performance optimization or the private x64 runtime.

## v0.1: File APIs and PE imports

- `winclab::FileApi` (C++17/Linux/Android POSIX): sandboxed subsets of `CreateFileW`, `ReadFile`, `WriteFile`, `SetFilePointerEx`, `GetFileSizeEx`, `FlushFileBuffers`, `CloseHandle`, `DeleteFileW`, `MoveFileExW`, `CreateDirectoryW`, `RemoveDirectoryW`, `GetFileAttributesW`.
- CRT binary file descriptors: `_wopen`, `_read`, `_write`, `_get_osfhandle`, `_close`. Unsupported mode/flags fail explicitly.
- Process-scoped handles, Windows-style sharing checks within one `FileApi`, drive-root isolation (`C:\\`, `D:\\`), UTF-16 conversion and path traversal/symlink defense.
- `tools/pe_imports.py`: standard-library PE32/PE32+ static import scanner to compare several EXEs and prioritize missing Win32 symbols. **Does not execute Windows binaries.**

## Test locally

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Public CI runs the same tests in `.github/workflows/compatibility.yml`, without private checkout or credentials.

## Compare EXE dependencies

```bash
python3 tools/pe_imports.py --manifest data/lab_manifest.json example-one.exe example-two.exe
```

The manifest describes only **this lab's implementation subset**; it is not a statement that the private Android runtime supports those imports. Regular static imports only; delay-loaded and dynamically resolved APIs are not fully enumerated. Do not commit proprietary EXEs, games or their extracted text to this public repository.

## Integration and limitations

See [private integration checklist](docs/INTEGRATION.md) and [compatibility roadmap](docs/ROADMAP.md). Real Windows x64 ABI bridging, guest pointers, `GetLastError`, per-thread CRT errno, Windows application launch, Android APK integration and device verification remain **private and not yet completed**. Windows object-manager features, process-wide sharing, overlapped I/O, ACLs, registry, COM, GUI, DirectX and extensive Windows path semantics are beyond v0.1.

**Passing the public host tests does not establish that any particular Windows EXE runs.** Preserve the original game files when testing write/delete operations. The private repository and its original engine/history are not included.

License: MIT (only this new standalone module).

# WinInstaller CompatLab v0.3

Independently authored, MIT-licensed Windows API compatibility subsets for future use by Android EXE Installer. This public lab contains no private runtime/Android source and performs no Windows EXE execution.

- Existing `FileApi`: isolated C/D virtual drives, Win32 file/CRT binary subsets, share checks and UTF-16 paths. v0.2 corrects read-mode create/open, invalid CRT mode, read-only replacement, negative seek, virtual cross-drive move and successful creation diagnostics.
- v0.3 adds `RegDeleteValueW`, `RegEnumKeyExW`, `RegEnumValueW` **host-side subsets**, including deterministic immediate-child enumeration, snapshot values, access enforcement and isolation. The private x64 ABI adapter and Windows buffer negotiation are not implemented here.\n- New `RegistryApi`: RegOpenKeyExW, RegCreateKeyExW, RegQueryValueExW, RegSetValueExW and RegCloseKey. Context-local HKCU/HKLM, five value types, byte-size negotiation, error/rights checks and handle lifetime. Memory only; HKLM read-only by default.
- Four independent **synthetic host** profiles: basic utility, installer-like, registry-dependent and CRT file app. These do not establish real Windows app compatibility.
- Offline PE32/PE32+ static comparisons: missing import frequency, per-input status counts, delay/dynamic-loading limitations. No executable is uploaded or run.

## Build and test (Linux; no Windows SDK)

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Sanitizers: configure a separate directory with `-DWINCLAB_SANITIZERS=ON`. Public CI uses standard Ubuntu runners: GCC tests plus Clang ASan/UBSan tests, with Python once. No private token, checkout, proprietary EXE or APK build.

## Compare local dependencies

```sh
python3 tools/pe_imports.py --manifest data/api_contracts.json first.exe second.exe
```

`data/lab_manifest.json` retains legacy DLL/name lists. Its legacy `supported` output means unverified declarations; use the v2 contract for TESTED/PARTIAL/EXPERIMENTAL/UNSUPPORTED buckets. TESTED applies only to a declared host subset; runtime calls and dynamic targets remain unknown. No paths or binary contents appear in the result. Only x86/PE32 and x64/PE32+ images are accepted.

The new [offline `.wicmod` source-kit format](docs/MODULE_BUNDLE.md) provides integrity/host-contract checks for staged sources. It **cannot automatically install into an existing APK**.\n\nSee [API behavior and Microsoft references](docs/API_BEHAVIOR.md), [private adapter contract](docs/INTEGRATION.md), [app-family analysis and roadmap](docs/ROADMAP.md) and [validation record](docs/VALIDATION.md). No actual app count, private integration, Windows execution or Android device success is claimed.

MIT license is preserved. Never commit private engine/history, Android internals, tokens, user diagnostics, games or commercial executables.

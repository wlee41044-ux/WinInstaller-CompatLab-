# CompatLab v0.3 — offline module source-kit and future two-download installation

The `.wicmod` format in this public repository is **SOURCE-KIT ONLY**. It is not an APK patch, a dynamic-code Android plugin, or an automatically executable package. v0.3 packages independently authored, MIT-licensed file and Registry API C++ sources, hashes, module IDs, a pinned format version, and host API contract.

## Build and validate without private source

```sh
python3 tools/module_bundle.py build --out dist/WinInstaller-CompatLab-0.3.0.wicmod
sha256sum dist/WinInstaller-CompatLab-0.3.0.wicmod
python3 tools/module_bundle.py verify dist/WinInstaller-CompatLab-0.3.0.wicmod
python3 -m unittest tests/test_module_bundle.py -v
```

For local integration prototype, an authorized host environment (not existing APK) supplies a contract such as:

```json
{"consumer":"wininstaller","host_api":1,"allow_source_kits":true,"allowed_modules":["winclab-file","winclab-registry"]}
```

Stage verified sources in an isolated folder, **never overwriting the Android app or executing code**:

```sh
python3 tools/module_bundle.py stage dist/WinInstaller-CompatLab-0.3.0.wicmod \
  --trust-sha256 <SHA256 obtained from an independently trusted channel> \
  --host-contract ./trusted-host-contract.json --destination ./staging
```

**Important:** A SHA-256 embedded within a downloaded archive is not an authenticity guarantee. The expected archive digest must come from an independent trusted source. The staging tool merely checks files and preconditions; it does not activate a native module.

## User's proposed two-download flow (future private integration)

1. User installs the **signed Win Installer APK** normally.
2. User downloads a separately signed and compatible `.wicmod` package.
3. Android share/open-with, or an in-app file picker, passes the module to a **private APK module receiver**. Android may not silently scan Downloads for arbitrary files.
4. Receiver verifies trusted signer, hashes, schema, app version, ABI (arm64-v8a), permissions and declared API capabilities.
5. Receiver stages with rollback under app-private storage, loads only supported/approved modules and reports status. Use a stable C ABI and isolate guest/host handles and memory.
6. Reject incompatible modules without modifying app files. Preserve previous version, show clear user consent, and allow disabling/removing the module.

**Until that private APK receiver exists, downloading the APK and this source kit will NOT auto-merge or automatically improve EXE compatibility.** A native arm64 runtime module would require private loader integration, Android NDK builds, an explicit stable ABI and an authenticated distribution policy. Avoid rewriting/re-signing the APK in a Public CI and avoid untrusted dynamic code from the web.

This public repository does not request secrets or the private runtime. Keep native module activation separated from data-only compatibility profiles; respect target Android distribution policy.

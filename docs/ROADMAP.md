# Compatibility-first roadmap

v0.1 established the independent file core and static import comparison. v0.2 adds five Registry APIs, focused file corrections, status-aware PE comparisons and four composite host profiles. Exact supported subsets and open limitations are in API_BEHAVIOR.md and data/api_contracts.json. No actual supported app count is established.

## Repeated needs by app family (analysis directions, not support guarantees)

| Family | Repeated needs | Public v0.2 coverage / gap |
|---|---|---|
| Win32 utility | files, paths, registry settings | File subset + five Registry calls; path queries, enum and shell absent |
| Installer | directories, staged files, registry | Synthetic files/settings profile; MSI, rollback transactions, elevation and services absent |
| Python/PyInstaller | CRT, files, process and loader | Binary CRT subset; process creation, DLL loader and runtime initialization absent |
| GUI utility | settings, resources, windows | Registry settings subset; resources/message loop/windowing absent |
| Unity | files, process, graphics initialization | File/settings foundations only; runtime, graphics and process support absent |
| .NET | runtime, registry, system APIs | Registry subset only; CLR/.NET hosting, COM and system APIs absent |

## Next priorities

1. Run local authorized multi-EXE static comparisons with `--manifest data/api_contracts.json`. Rank missing imports by **number of distinct inputs**, not repeated entries. Runtime traces from a future private adapter must distinguish APIs reached from static dependency candidates. No commercial input is uploaded or committed.
2. Privately bridge the five Registry calls and the corrected file modes behind flags; verify byte counts, HKEY IDs, error returns and state cleanup. No private integration in this batch.
3. Prioritize Registry enumeration/deletion or process/synchronization APIs when repeated input comparisons **and reached-call evidence** show a blocker. There is no real application corpus in this release, so a measured frequency ranking of actual apps is not yet available.
4. Fix NT delete-pending/cross-process share coordination and broader path semantics before claiming Windows-complete file behavior. Persistence/full Unicode folding require separate designs and evidence.
5. COM dialogs, GUI resources and graphics are independent later modules, selected by actual blockers. No CPU optimization, JIT, Box64/Wine port, DirectX reimplementation or Android build here.

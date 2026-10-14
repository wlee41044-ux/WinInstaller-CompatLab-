# WinInstaller CompatLab

Public, independent Windows API compatibility research and regression tests for the private Android EXE Installer.

The goal is to improve **compatibility across different Windows apps**, not launch speed.

## Scope
- Win32 / CRT file API compatibility experiments
- PE32 and PE32+ static import analysis
- Standalone C++ and Python tests on GitHub-hosted runners
- A documented, versioned interface for later private-runtime integration

No private interpreter, Android APK sources, Windows app/game binaries or private test evidence belongs here.

This repository starts with the MIT-licensed standalone compatibility module. Passing its public tests **does not** prove a specific Windows program runs in Android EXE Installer. Real x64 integration and device validation happen in the private project.

*Initial import in progress.*
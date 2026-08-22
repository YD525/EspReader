# EspReader

## 🧩 Third-Party Frameworks

This project uses the following key open-source libraries/frameworks:

- [miniz](https://github.com/richgel999/miniz) – Compress and decompress content.  

Other dependencies (such as various helper libraries) are also used.  
Please refer to their respective LICENSE files for more information.

---

EspReader is designed to replace the Lexicon AI Translator EspReader.cs class.

> ⚠️ Note: This library is still under active development.

This library was partially inspired by the logic of [SSE-Auto-Translator](https://github.com/Cutleast/SSE-Auto-Translator) and is used here with the explicit permission of its author.

## Building from source

EspReader requires Visual Studio 2022 with the Desktop development with C++ workload.

Restore the pinned miniz sources and build the x64 Release configuration:

```powershell
.\scripts\Restore-Miniz.ps1
.\scripts\Invoke-NativeBuild.ps1 -Configuration Release -Platform x64
.\scripts\Run-Tests.ps1 -Configuration Release -Platform x64
```

The resulting library is written to `x64\Release\EspReader.dll`.

The parser suite runs non-interactively through the Visual Studio C++ test runner. Its synthetic ESP/ESM
fixtures and their license status are documented in `EspReader.Tests/Fixtures/README.md`.
The pull-request, native-analysis, warning, diagnostic-artifact, and sanitizer policy is documented in `docs/ci.md`.

## Public C ABI

`EspReader/EspReaderApi.h` is the canonical C and C++ contract. It defines fixed-width values, explicit cdecl and
stdcall entry points, the dialogue structure packing, UTF-8 and UTF-16 string rules, byte-oriented buffer capacities,
and ownership for handles and returned allocations. Existing exports remain available, while `C_GetAbiVersion`,
`C_GetLastStatus`, and `C_GetLastErrorUtf8` provide additive version negotiation and a thread-local error contract.

Consumers must release handles with `C_DestroyInstance`, search arrays with `FreeSearchResults`, and dialogue link
arrays with `C_FreeDialContext`. Borrowed record, subrecord, and string pointers must not be freed by the caller.

## Releases

Push a version tag matching `v*` to build the x64 library and create a GitHub Release. Each release contains
`EspReader.dll`, `EspReaderApi.h`, and a SHA-256 checksum for each file.


## Contributors:

YD525 (https://github.com/YD525).

Cutleast (https://github.com/cutleast).

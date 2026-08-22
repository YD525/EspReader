# Native CI policy

Pull requests must pass a Release x64 build, the parser regression suite, and MSVC native code analysis. The project
uses warning level 4 and treats compiler and linker warnings as errors. The build wrapper also rejects warning output
so analyzer diagnostics cannot silently pass when a tool returns exit code zero.

The first-party warning baseline is zero. The pinned miniz 3.1.2 source currently produces MSVC v143 compiler warning
C4127 and analyzer diagnostics C28182 and C6386. Those three diagnostics are suppressed only on `miniz.c`; all other
compiler and analyzer warnings remain enabled. Updating miniz requires reviewing and either removing or revising this
scoped baseline.

The build and test wrappers can write sanitized diagnostics below `.ci-artifacts`. Repository, runner, temporary, tool
cache, and user-profile roots are replaced before CI uploads failure artifacts. The artifacts are retained for seven
days and must not contain secrets or developer paths.

The weekly and manually dispatchable sanitizer job rebuilds Release x64 with AddressSanitizer and runs the same parser
suite. Tag releases call the same build and test wrappers as pull requests before publishing the DLL, canonical C ABI
header, and their checksums.

Run the regular gates from a Visual Studio developer shell:

```powershell
.\scripts\Restore-Miniz.ps1
.\scripts\Invoke-NativeBuild.ps1 -Configuration Release -Platform x64
.\scripts\Run-Tests.ps1 -Configuration Release -Platform x64
.\scripts\Invoke-NativeBuild.ps1 -Configuration Release -Platform x64 -Analyze
```

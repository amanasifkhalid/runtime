# Build

## Quick Start

Here is one example of a daily workflow for a developer working mainly on the libraries, in this case using Windows:

```cmd
:: From root:
git clean -xdf
git pull upstream main & git push origin main
:: Build Debug libraries on top of Release runtime:
build.cmd clr+libs -rc Release
:: Performing the above is usually only needed once in a day, or when you pull down significant new changes.

:: If you use Visual Studio, you might open System.Collections.Concurrent.slnx here.
build.cmd -vs System.Collections.Concurrent

:: Switch to working on a given library (System.Collections.Concurrent in this case)
cd src\libraries\System.Collections.Concurrent

:: Change to test directory
cd tests

:: Then inner loop build / test
:: (If using Visual Studio, you might run tests inside it instead)
pushd ..\src & dotnet build & popd & dotnet build /t:test
```

Instructions for Unix-like operating systems are essentially the same:

```bash
#!/usr/bin/env bash

# From root:
git clean -xdf
git pull upstream main; git push origin main
# Build Debug libraries on top of Release runtime:
./build.sh clr+libs -rc Release
# Performing the above is usually only needed once in a day, or when you pull down significant new changes.

# Switch to working on a given library (System.Collections.Concurrent in this case)
cd src/libraries/System.Collections.Concurrent

# Change to test directory
cd tests

# Then inner loop build / test:
pushd ../src; dotnet build; popd; dotnet build /t:test
```

The steps above may be all you need to know to make a change. Want more details about what this means? Read on.

## Building everything

This document explains how to work on libraries. In order to work on library projects or run library tests it is necessary to have built the runtime to give the libraries something to run on. You should normally build CoreCLR runtime in release configuration and libraries in debug configuration. If you haven't already done so, please read [this document](../../README.md#Configurations) to understand configurations.

These example commands will build a release CoreCLR (and CoreLib), debug libraries, and debug installer:

For Linux:
```bash
./build.sh -rc Release
```

For Windows:
```cmd
./build.cmd -rc Release
```

Detailed information about building and testing runtimes and the libraries is in the documents linked below.

### More details if you need them

The above commands will give you libraries in "debug" configuration (the default) using a runtime in "release" configuration which hopefully you built earlier.

The libraries build has two logical components, the native build which produces the "shims" (which provide a stable interface between the OS and managed code) and the managed build which produces the MSIL code and NuGet packages that make up Libraries. The commands above will build both.

The build settings (BuildTargetFramework, TargetOS, Configuration, Architecture) are generally defaulted based on where you are building (i.e. which OS or which architecture) but we have a few shortcuts for the individual properties that can be passed to the build scripts:

- `-framework|-f` identifies the target framework for the build. Possible values include `net10.0` (currently the latest .NET version) or `net481` (the latest .NET Framework version). (msbuild property `BuildTargetFramework`)
- `-os` identifies the OS for the build. It defaults to the OS you are running on but possible values include `windows`, `unix`, `linux`, or `osx`. (msbuild property `TargetOS`)
- `-configuration|-c Debug|Release` controls the optimization level the compilers use for the build. It defaults to `Debug`. (msbuild property `Configuration`)
- `-arch` identifies the architecture for the build. It defaults to `x64` but possible values include `x64`, `x86`, `arm`, or `arm64`. (msbuild property `TargetArchitecture`)

For more details on the build settings see [project-guidelines](../../../coding-guidelines/project-guidelines.md#build-pivots).

If you invoke the `build` script without any actions, the default action chain `-restore -build` is executed.

By default the `build` script only builds the product libraries and none of the tests. If you want to include tests, you want to add the subset `libs.tests`. If you want to run the tests you want to use the `-test` action instead of the `-build`, e.g. `build.cmd/sh libs.tests -test`. To specify just the libraries, use `libs`.

**Examples**
- Building in release mode for platform x64 (restore and build are implicit here as no actions are passed in)
```bash
./build.sh libs -c Release -arch x64
```

- Building the src assemblies and build and run tests (running all tests takes a considerable amount of time!)
```bash
./build.sh libs -test
```

- Clean the entire artifacts folder
```bash
./build.sh -clean
```

For Windows, replace `./build.sh` with `build.cmd`.

### Building the native components with native sanitizers

The libraries native components can be built with native sanitizers like AddressSanitizer to help catch memory safety issues. To build the project with native sanitizers, add the `-fsanitize` argument to the build script like the following:

```bash
build.sh -s libs -fsanitize address
```

When building the repo with any native sanitizers, you should build all native components in the repo with the same set of sanitizers.

### How to build native components only

The libraries build contains some native code. This includes shims over libc, openssl, gssapi, and zlib. The build system uses CMake to generate Makefiles using clang. The build also uses git for generating some version information.

**Examples**

- Building in debug mode for platform x64
```bash
./src/native/libs/build-native.sh debug x64
```

- Building and updating the binplace (for e.g. the testhost), which is needed when iterating on native components
```bash
dotnet.sh build src/native/libs/build-native.proj
```

- The following example shows how you would do an arm cross-compile build
```bash
./src/native/libs/build-native.sh debug arm cross verbose
```

For Windows, replace `build-native.sh` with `build-native.cmd`.

## Building individual libraries

Similar to building the entire repo with `build.cmd` or `build.sh` in the root you can build projects based on our directory structure by passing in the directory. We also support shortcuts for libraries so you can omit the root `src` folder from the path. When given a directory we will build all projects that we find recursively under that directory. Some examples may help here.

**Examples**

- Build all projects for a given library (e.g.: System.Collections) including running the tests

```bash
 ./build.sh -projects src/libraries/*/System.Collections.slnx
```

- Build just the tests for a library project
```bash
 ./build.sh -projects src/libraries/System.Collections/tests/*.csproj
```

- All the options listed above like framework and configuration are also supported (note they must be after the directory)
```bash
 ./build.sh -projects src/libraries/*/System.Collections.slnx -f net472 -c Release
```

As `dotnet build` works on both Unix and Windows and calls the restore target implicitly, we will use it throughout this guide.

Under the `src` directory is a set of directories, each of which represents a particular assembly in Libraries. See Library Project Guidelines section under [project-guidelines](../../../coding-guidelines/project-guidelines.md) for more details about the structure.

For example the `src\libraries\System.Diagnostics.DiagnosticSource` directory holds the source code for the System.Diagnostics.DiagnosticSource.dll assembly.

You can build the DLL for System.Diagnostics.DiagnosticSource.dll by going to the `src\libraries\System.Diagnostics.DiagnosticsSource\src` directory and typing `dotnet build`. The DLL ends up in `artifacts\bin\System.Diagnostics.DiagnosticSource` as well as `artifacts\bin\runtime\[$(BuildTargetFramework)-$(TargetOS)-$(Configuration)-$(TargetArchitecture)]`.

You can build the tests for System.Diagnostics.DiagnosticSource.dll by going to
`src\libraries\System.Diagnostics.DiagnosticSource\tests` and typing `dotnet build`.

Some libraries might also have a `ref` and/or a `pkg` directory and you can build them in a similar way by typing `dotnet build` in that directory.

For libraries that have multiple target frameworks the target frameworks will be listed in the `<TargetFrameworks>` property group. When building the csproj for a BuildTargetFramework the most compatible target framework in the list will be chosen and set for the build. For more information about `TargetFrameworks` see [project-guidelines](../../../coding-guidelines/project-guidelines.md).

**Examples**

- Build project for Linux
```bash
dotnet build System.Net.NetworkInformation.csproj /p:TargetOS=linux
```

- Build Release version of library
```bash
dotnet build -c Release System.Net.NetworkInformation.csproj
```

### Iterating on System.Private.CoreLib changes
When changing `System.Private.CoreLib` after a full build, in order to test against those changes, you will need an updated `System.Private.CoreLib` in the testhost. In order to achieve that, you can build the `libs.pretest` subset which does testhost setup including copying over `System.Private.CoreLib`.

After doing a build of the runtime:

```cmd
build.cmd clr -rc Release
```

You can iterate on `System.Private.CoreLib` by running:

```cmd
build.cmd clr.corelib+clr.nativecorelib+libs.pretest -rc Release
```

When this `System.Private.CoreLib` will be built in Release mode, then it will be crossgen'd and we will update the testhost to the latest version of corelib.

You can use the same workflow for mono runtime by using `mono.corelib+libs.pretest` subsets.

### Building for Mono
By default the libraries will attempt to build using the CoreCLR version of `System.Private.CoreLib.dll`. In order to build against the Mono version you need to use the `/p:RuntimeFlavor=Mono` argument.

```cmd
.\build.cmd libs /p:RuntimeFlavor=Mono
```

### Building all for other OSes

By default, building from the root will only build the libraries for the OS you are running on. One can
build for another OS by specifying `./build.sh libs -os [value]`.

Note that you cannot generally build native components for another OS but you can for managed components so if you need to do that you can do it at the individual project level or build all via passing `/p:BuildNative=false`.

### Building in Release or Debug

By default, building from the root or within a project will build the libraries in Debug mode.
One can build in Debug or Release mode from the root by doing `./build.sh libs -c Release` or `./build.sh libs`.

### Building other Architectures

One can build 32- or 64-bit binaries or for any architecture by specifying in the root `./build.sh libs -arch [value]` or in a project `/p:TargetArchitecture=[value]` after the `dotnet build` command.

## Working in Visual Studio

If you are working on Windows, and use Visual Studio, you can open individual libraries projects into it. From within Visual Studio you can then build, debug, and run tests.

## Debugging

Starting with Visual Studio 2022 version 17.5, Visual Studio will validate that the debugging libraries that shipped with the .NET Runtime are correctly signed before loading them. See https://aka.ms/vs/unsigned-dotnet-debugger-lib for more information.

## Running tests

For more details about running tests inside Visual Studio, [go here](../../testing/visualstudio.md).

For more about running tests, read the [running tests](../../testing/libraries/testing.md) document.

## Build packages
To build a library's package, simply invoke `dotnet pack` on the src project after you successfully built the .NETCoreApp vertical from root:

```cmd
build libs
dotnet.cmd pack src\libraries\System.Text.Json\src\
```

Same as for `dotnet build` or `dotnet publish`, you can specify the desired configuration via the `-c` flag:

```cmd
dotnet.cmd pack src\libraries\System.Text.Json\src\ -c Release
```

## APICompat

If changes to the library include any API incompatibilities, calling `dotnet build` or `dotnet pack` may result in API compatibility errors.

In rare cases where these are expected (e.g. updating APIs previously shipped only in preview or as experimental), the errors may be suppressed. This can be done by following the directions in the error to invoke `dotnet build` (if the project isn't packable) or `dotnet pack` (if the project is packable) with an additional `/p:ApiCompatGenerateSuppressionFile=true` argument.

See https://learn.microsoft.com/dotnet/fundamentals/apicompat/overview for more details.

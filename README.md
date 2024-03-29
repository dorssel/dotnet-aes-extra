<!--
SPDX-FileCopyrightText: 2022 Frans van Dorsselaer

SPDX-License-Identifier: MIT
-->

# dotnet-aes-extra

[![Build](https://github.com/dorssel/dotnet-aes-extra/workflows/Build/badge.svg?branch=master)](https://github.com/dorssel/dotnet-aes-extra/actions?query=workflow%3ABuild+branch%3Amaster)
[![CodeQL](https://github.com/dorssel/dotnet-aes-extra/workflows/CodeQL/badge.svg?branch=master)](https://github.com/dorssel/dotnet-aes-extra/actions?query=workflow%3ACodeQL+branch%3Amaster)
[![MegaLinter](https://github.com/dorssel/dotnet-aes-extra/workflows/MegaLinter/badge.svg?branch=master)](https://github.com/dorssel/dotnet-aes-extra/actions?query=workflow%3AMegaLinter+branch%3Amaster)
[![codecov](https://codecov.io/gh/dorssel/dotnet-aes-extra/branch/master/graph/badge.svg?token=zsbTiXoisQ)](https://codecov.io/gh/dorssel/dotnet-aes-extra)
[![REUSE status](https://api.reuse.software/badge/github.com/dorssel/dotnet-aes-extra)](https://api.reuse.software/info/github.com/dorssel/dotnet-aes-extra)
[![NuGet](https://img.shields.io/nuget/v/Dorssel.Security.Cryptography.AesExtra?logo=nuget)](https://www.nuget.org/packages/Dorssel.Security.Cryptography.AesExtra)

.NET Standard 2.0 implementation of the following AES modes that are not included in .NET 6.0 / .NET Framework:

- AES-CTR, as defined by [NIST SP 800-38A](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
- AES-CMAC, as defined by [NIST SP 800-38B](https://csrc.nist.gov/publications/detail/sp/800-38b/final)
- SIV-AES, as defined by [RFC 5297](https://datatracker.ietf.org/doc/html/rfc5297) \
  (Note: this is often refered to as AES-SIV, but the original RFC specification uses the name SIV-AES)

The implementation is for AnyCPU, and works on all platforms.

# Usage

The released binary NuGet packages and the .NET assemblies contained therein:

- use [Strong Naming](https://docs.microsoft.com/en-us/dotnet/standard/library-guidance/strong-naming),
- include [SourceLink](https://docs.microsoft.com/en-us/dotnet/standard/library-guidance/sourcelink),
- include [IntelliSense](https://docs.microsoft.com/en-us/visualstudio/ide/using-intellisense) compatible documentation, and
- are signed and timestamped with Authenticode.

All public classes are in the `Dorssel.Security.Cryptography` namespace.

- `AesCtr` is modeled after .NET's `Aes`. So, instead of `Aes.Create()`, use `AesCtr.Create()`.
- `AesCmac` is modeled after .NET's `HMACSHA256`. So, instead of `new HMACSHA256(key)`, use `new AesCmac(key)`.
- `AesSiv` is modeled after .NET's `AesGcm`. So, instead of `new AesGcm(key)`, use `new AesSiv(key)`.

<!--
SPDX-FileCopyrightText: 2022 Frans van Dorsselaer

SPDX-License-Identifier: MIT
-->

# dotnet-aes-extra

[![Build](https://github.com/dorssel/dotnet-aes-extra/actions/workflows/dotnet.yml/badge.svg?branch=master)](https://github.com/dorssel/dotnet-aes-extra/actions/workflows/dotnet.yml?query=branch%3Amaster)
[![CodeQL](https://github.com/dorssel/dotnet-aes-extra/actions/workflows/codeql.yml/badge.svg?branch=master)](https://github.com/dorssel/dotnet-aes-extra/actions/workflows/codeql.yml?query=branch%3Amaster)
[![Lint](https://github.com/dorssel/dotnet-aes-extra/actions/workflows/lint.yml/badge.svg?branch=master)](https://github.com/dorssel/dotnet-aes-extra/actions/workflows/lint.yml?query=branch%3Amaster)
[![Codecov](https://codecov.io/gh/dorssel/dotnet-aes-extra/branch/master/graph/badge.svg?token=zsbTiXoisQ)](https://codecov.io/gh/dorssel/dotnet-aes-extra)
[![REUSE](https://api.reuse.software/badge/github.com/dorssel/dotnet-aes-extra)](https://api.reuse.software/info/github.com/dorssel/dotnet-aes-extra)
[![NuGet](https://img.shields.io/nuget/v/Dorssel.Security.Cryptography.AesExtra?logo=nuget)](https://www.nuget.org/packages/Dorssel.Security.Cryptography.AesExtra)

.NET Standard 2.0 implementation of the following AES modes that are not included in .NET:

- **AES-CTR** \
  Defined by [NIST SP 800-38A](https://csrc.nist.gov/publications/detail/sp/800-38a/final).
- **AES-CMAC** \
  Defined by [NIST SP 800-38B](https://csrc.nist.gov/publications/detail/sp/800-38b/final)
  and [RFC 4493](https://datatracker.ietf.org/doc/html/rfc4493).
- **SIV-AES** \
  Defined by [RFC 5297](https://datatracker.ietf.org/doc/html/rfc5297). \
  This is often referred to as AES-SIV.
- **AES-CMAC-PRF-128** \
  Defined by [RFC 4615](https://datatracker.ietf.org/doc/html/rfc4615). \
  Registered by IANA as PRF_AES128_CMAC.
- **PBKDF2-AES-CMAC-PRF-128** \
  Defined by [RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018) in combination with
  [RFC 4615](https://datatracker.ietf.org/doc/html/rfc4615).

The implementation is for AnyCPU, and works on all platforms.

# Usage

The released [NuGet package](https://www.nuget.org/packages/Dorssel.Security.Cryptography.AesExtra)
and the .NET assemblies contained therein have the following properties:

- [Strong Naming](https://learn.microsoft.com/en-us/dotnet/standard/library-guidance/strong-naming)
- [SourceLink](https://learn.microsoft.com/en-us/dotnet/standard/library-guidance/sourcelink)
- [IntelliSense](https://learn.microsoft.com/en-us/visualstudio/ide/using-intellisense)
- [Authenticode](https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures#a-brief-introduction-to-authenticode)

All public classes are in the `Dorssel.Security.Cryptography` namespace.

- `AesCtr` is modeled after .NET's `Aes`. \
  Use `AesCtr.Create()` instead of `Aes.Create()`.

- `AesCmac` is modeled after .NET's `HMACSHA256` \
  Use `new AesCmac(key)` instead of `new HMACSHA256(key)`.

- `AesSiv` is modeled after .NET's `AesGcm`. \
  Use `new AesSiv(key)` instead of `new AesGcm(key)`.

- For AES-CMAC-PRF-128, `AesCmacPrf128` is modeled after .NET's `HKDF`. \
  Use `AesCmacPrf128.DeriveKey()` instead of `HKDF.DeriveKey()`.

- For PBKDF2-AES-CMAC-PRF-128, `AesCmacPrf128` is modeled after .NET's `Rfc2898DeriveBytes`. \
  Use `AesCmacPrf128.Pbkdf2()` instead of `Rfc2898DeriveBytes.Pbkdf2()`.

For further information, see the [API documentation](https://dorssel.github.io/dotnet-aes-extra/).

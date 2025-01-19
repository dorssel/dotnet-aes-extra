<!--
SPDX-FileCopyrightText: 2025 Frans van Dorsselaer

SPDX-License-Identifier: MIT
-->

# dotnet-aes-extra

The library leverages the AES implementation of .NET; it does not contain the AES primitive itself.
Instead, it adds modes of AES that are not in available in .NET / .NET Core / .NET Framework.

The library exposes its objects modeled after default .NET classes, so its usage is straightforward.

The @"Dorssel.Security.Cryptography?text=API" includes both the classic `byte[]` as well as the modern `Span<byte>` overloads.

There are two builds of the library included in th package, one for .NET Standard 2.0 and one for .NET 8 (or higher).
The public @"Dorssel.Security.Cryptography?text=API" is the same for both, but internally the builds slightly differ:

- The .NET Standard build depends on `Microsoft.Bcl.AsyncInterfaces` and `Microsoft.Bcl.Memory` for `ValueTask` and `Span` support.

- The .NET 8 build uses `CryptographicOperations` for `ZeroMemory` and `FixedTimeEquals`,
  whereas the .NET Standard build uses an internal implementation backported from the original .NET 8 code.

- The .NET 8 build supports trimming.

## Example

[!code-csharp[](../Example/Program.cs)]

// SPDX-FileCopyrightText: .NET Foundation
// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

#if NETSTANDARD2_0

using System.Runtime.CompilerServices;

namespace Dorssel.Security.Cryptography;

/// <summary>
/// This is a backport of .NET 9.
/// <para/>
/// See:
/// <see href="https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/CryptographicOperations.cs"/>
/// </summary>
static class CryptographicOperations
{
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        // NoOptimization because we want this method to be exactly as non-short-circuiting
        // as written.
        //
        // NoInlining because the NoOptimization would get lost if the method got inlined.

        if (left.Length != right.Length)
        {
            return false;
        }

        var length = left.Length;
        var accum = 0;

        for (var i = 0; i < length; i++)
        {
            accum |= left[i] - right[i];
        }

        return accum == 0;
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void ZeroMemory(Span<byte> buffer)
    {
        // NoOptimize to prevent the optimizer from deciding this call is unnecessary
        // NoInlining to prevent the inliner from forgetting that the method was no-optimize
        for (var i = 0; i < buffer.Length; i++)
        {
            buffer[i] = 0;
        }
    }
}

#endif

// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.CompilerServices;

namespace Dorssel.Security.Cryptography;

static class ExtensionMethods
{
    const int BLOCKSIZE = 16;  // bytes

    // See: NIST SP 800-38B, Section 4.2
    //
    // In place: X = (X << 1)
    // Returns final carry.
    static bool LeftShiftOne_InPlace(this Span<byte> X)
    {
        var carry = false;
        for (var i = X.Length - 1; i >= 0; --i)
        {
            var nextCarry = (X[i] & 0x80) != 0;
            _ = unchecked(X[i] <<= 1);
            if (carry)
            {
                X[i] |= 1;
            }
            carry = nextCarry;
        }
        return carry;
    }

    // See: NIST SP 800-38B, Section 6.1
    // See: RFC 5297, Section 2.1
    //
    // In place: S = dbl(S)
#pragma warning disable IDE1006 // Naming Styles
    public static void dbl_InPlace(this Span<byte> S)
#pragma warning restore IDE1006 // Naming Styles
    {
        // See: NIST SP 800-38B, Section 5.3
        // See: RFC 5297, Section 2.3
        const int Rb = 0b10000111;

        // See: NIST SP 800-38B, Section 6.1, Step 2/3
        if (S.LeftShiftOne_InPlace())
        {
            S[BLOCKSIZE - 1] ^= Rb;
        }
    }

    // See: NIST SP 800-38B, Section 4.2.2
    //
    // In place: X = (X xor Y)
#pragma warning disable IDE1006 // Naming Styles
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void xor_InPlace(this Span<byte> X, ReadOnlySpan<byte> Y)
#pragma warning restore IDE1006 // Naming Styles
    {
        for (var i = 0; i < X.Length; ++i)
        {
            X[i] ^= Y[i];
        }
    }

    public static void BigEndianIncrement(this Span<byte> counter)
    {
        // Increment counter
        for (var i = counter.Length - 1; i >= 0; --i)
        {
            if (unchecked(++counter[i]) != 0)
            {
                break;
            }
        }
    }
}

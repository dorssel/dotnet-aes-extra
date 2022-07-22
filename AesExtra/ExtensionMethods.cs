// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

static class ExtensionMethods
{
    const int BLOCKSIZE = AesCtr.FixedBlockSize;

    // See: NIST SP 800-38B, Section 4.2
    //
    // In place: X = (X << 1)
    // Returns final carry.
    static bool LeftShiftOne_InPlace(this byte[] X)
    {
        var carry = false;
        for (var i = X.Length - 1; i >= 0; --i)
        {
            var nextCarry = (X[i] & 0x80) != 0;
            X[i] <<= 1;
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
    public static void dbl_InPlace(this byte[] S)
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
    public static void xor_InPlace(this byte[] X_Base, int X_Offset, byte[] Y_Base, int Y_Offset, int count)
    {
        for (var i = 0; i < count; ++i)
        {
            X_Base[X_Offset + i] ^= Y_Base[Y_Offset + i];
        }
    }
}

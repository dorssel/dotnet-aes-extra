﻿// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;

namespace Dorssel.Security.Cryptography;

public static partial class AesCmacPrf128
{
    const int BLOCKSIZE = 16;  // bytes
    readonly static byte[] BlockOfZeros = new byte[BLOCKSIZE];

    static AesCmac UncheckedCreateKeyedPrf(byte[] key)
    {
        // Implementation of RFC 4615 (Section 3).

        var prf = new AesCmac();
        // Step 1.
        if (key.Length == BLOCKSIZE)
        {
            // Step 1a.
            prf.Key = key;
        }
        else
        {
            // Step 1b.
            using var blockSizedKey = new SecureByteArray(BLOCKSIZE);
            prf.Key = BlockOfZeros;
            prf.UncheckedHashCore(key);
            prf.UncheckedHashFinal(blockSizedKey);
            prf.Initialize();
            prf.Key = blockSizedKey;
        }
        return prf;
    }

    static AesCmac UncheckedCreateKeyedPrf(ReadOnlySpan<byte> key)
    {
        // Implementation of RFC 4615 (Section 3).

        var prf = new AesCmac();
        // Step 1.
        if (key.Length == BLOCKSIZE)
        {
            // Step 1a.
            using var blockSizedKey = new SecureByteArray(key);
            prf.Key = blockSizedKey;
        }
        else
        {
            // Step 1b.
            using var blockSizedKey = new SecureByteArray(BLOCKSIZE);
            prf.Key = BlockOfZeros;
            prf.UncheckedHashCore(key);
            prf.UncheckedHashFinal(blockSizedKey);
            prf.Initialize();
            prf.Key = blockSizedKey;
        }
        return prf;
    }

    public static partial byte[] DeriveKey(byte[] inputKey, byte[] message)
    {
        if (inputKey is null)
        {
            throw new ArgumentNullException(nameof(inputKey));
        }
        if (message is null)
        {
            throw new ArgumentNullException(nameof(inputKey));
        }

        // Implementation of RFC 4615 (Section 3).

        // Step 1 + 1a + 1b.
        using var cmac = UncheckedCreateKeyedPrf(inputKey);
        // Step 2.
        var destination = new byte[BLOCKSIZE];
        cmac.UncheckedHashCore(message);
        cmac.UncheckedHashFinal(destination);
        return destination;
    }

    public static partial void DeriveKey(ReadOnlySpan<byte> inputKey, ReadOnlySpan<byte> message, Span<byte> destination)
    {
        if (destination.Length != BLOCKSIZE)
        {
            throw new ArgumentException("Destination is not exactly 16-bytes long.");
        }

        // Implementation of RFC 4615 (Section 3).

        // Step 1 + 1a + 1b.
        using var cmac = UncheckedCreateKeyedPrf(inputKey);
        // Step 2.
        cmac.UncheckedHashCore(message);
        cmac.UncheckedHashFinal(destination);
    }

    static void UncheckedPbkdf2(AesCmac cmac, ReadOnlySpan<byte> salt, Span<byte> destination, int iterations)
    {
        // Implementation of RFC 8018 (Section 5.2) + RFC 4615 (Section 3).

        // i
        Span<byte> INT_i = [0, 0, 0, 1];

        Span<byte> U = stackalloc byte[BLOCKSIZE];
        Span<byte> F = stackalloc byte[BLOCKSIZE];

        // i from 1 to l
        while (destination.Length > 0)
        {
            // j = 1
            // U_1 = PRF (P, S || INT (i))
            cmac.Initialize();
            cmac.UncheckedHashCore(salt);
            cmac.UncheckedHashCore(INT_i);
            cmac.UncheckedHashFinal(U);
            // F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
            U.CopyTo(F);
            // j from 2 to c
            for (var j = 2; j <= iterations; j++)
            {
                // U = PRF (P, U_{j-1})
                cmac.Initialize();
                cmac.UncheckedHashCore(U);
                cmac.UncheckedHashFinal(U);
                // F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
                F.xor_InPlace(U);
            }
            if (destination.Length < BLOCKSIZE)
            {
                break;
            }
            // DK = T_1 || T_2 ||  ...  || T_l<0..r-1>
            // where T_i = F (P, S, c, i)
            F.CopyTo(destination);
            destination = destination[BLOCKSIZE..];
            INT_i.BigEndianIncrement();
        }
        // T_l<0..r-1>, if r != 0, where T_l = F (P, S, c, l)
        F[..destination.Length].CopyTo(destination);

        CryptographicOperations.ZeroMemory(U);
        CryptographicOperations.ZeroMemory(F);
    }

    public static partial byte[] Pbkdf2(byte[] password, byte[] salt, int iterations, int outputLength)
    {
        if (password == null)
        {
            throw new ArgumentNullException(nameof(password));
        }
        if (salt == null)
        {
            throw new ArgumentNullException(nameof(password));
        }
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }
        if (outputLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength));
        }

        if (outputLength == 0)
        {
            return [];
        }

        var destination = new byte[outputLength];
        using var cmac = UncheckedCreateKeyedPrf(password);
        UncheckedPbkdf2(cmac, salt, destination, iterations);
        return destination;
    }

    public static partial byte[] Pbkdf2(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations, int outputLength)
    {
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }
        if (outputLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength));
        }

        if (outputLength == 0)
        {
            return [];
        }

        var destination = new byte[outputLength];
        using var cmac = UncheckedCreateKeyedPrf(password);
        UncheckedPbkdf2(cmac, salt, destination, iterations);
        return destination;
    }

    public static partial void Pbkdf2(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> destination, int iterations)
    {
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }

        if (destination.Length == 0)
        {
            return;
        }

        using var cmac = UncheckedCreateKeyedPrf(password);
        UncheckedPbkdf2(cmac, salt, destination, iterations);
    }

    static SecureByteArray PasswordAsBytes(string password)
    {
        var encoding = new UTF8Encoding(false, true);
        var byteCount = encoding.GetByteCount(password);
        var secureByteArray = new SecureByteArray(byteCount);
        _ = encoding.GetBytes(password, 0, password.Length, secureByteArray, 0);
        return secureByteArray;
    }

    static SecureByteArray PasswordAsBytes(ReadOnlySpan<char> password)
    {
        var encoding = new UTF8Encoding(false, true);
        var passwordAsChars = password.ToArray();
        try
        {
            var byteCount = encoding.GetByteCount(passwordAsChars);
            var secureByteArray = new SecureByteArray(byteCount);
            _ = encoding.GetBytes(passwordAsChars, 0, password.Length, secureByteArray, 0);
            return secureByteArray;
        }
        finally
        {
            for (var i = 0; i < passwordAsChars.Length; i++)
            {
                passwordAsChars[i] = '\0';
            }
        }
    }

    public static partial byte[] Pbkdf2(string password, byte[] salt, int iterations, int outputLength)
    {
        if (password == null)
        {
            throw new ArgumentNullException(nameof(password));
        }
        using var passwordAsBytes = PasswordAsBytes(password);
        if (salt == null)
        {
            throw new ArgumentNullException(nameof(password));
        }
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }
        if (outputLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength));
        }

        if (outputLength == 0)
        {
            return [];
        }

        var destination = new byte[outputLength];
        using var cmac = UncheckedCreateKeyedPrf(passwordAsBytes);
        UncheckedPbkdf2(cmac, salt, destination, iterations);
        return destination;
    }

    public static partial byte[] Pbkdf2(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, int iterations, int outputLength)
    {
        using var passwordAsBytes = PasswordAsBytes(password);
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }
        if (outputLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength));
        }

        if (outputLength == 0)
        {
            return [];
        }

        var destination = new byte[outputLength];
        using var cmac = UncheckedCreateKeyedPrf(passwordAsBytes);
        UncheckedPbkdf2(cmac, salt, destination, iterations);
        return destination;
    }

    public static partial void Pbkdf2(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, Span<byte> destination, int iterations)
    {
        using var passwordAsBytes = PasswordAsBytes(password);
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }

        if (destination.Length == 0)
        {
            return;
        }

        using var cmac = UncheckedCreateKeyedPrf(passwordAsBytes);
        UncheckedPbkdf2(cmac, salt, destination, iterations);
    }
}

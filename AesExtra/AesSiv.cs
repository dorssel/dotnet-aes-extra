// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

public sealed class AesSiv
    : IDisposable
{
    public AesSiv(byte[] key)
    {
        _ = key ?? throw new ArgumentNullException(nameof(key));

        Cmac.Key = key.Take(key.Length / 2).ToArray();
        Ctr.Key = key.Skip(key.Length / 2).ToArray();
    }

    const int BLOCKSIZE = 16; // bytes

    static readonly byte[] zero = new byte[BLOCKSIZE];

    readonly Aes Ctr = AesCtr.Create();
    readonly KeyedHashAlgorithm Cmac = new AesCmac();

    #region IDisposable
    bool IsDisposed;

    public void Dispose()
    {
        if (!IsDisposed)
        {
            Ctr.Dispose();
            Cmac.Dispose();
            IsDisposed = true;
        }
    }
    #endregion

    public static int BlockSize { get => 128; }

    static readonly ReadOnlyCollection<KeySizes> _LegalKeySizes = new(new KeySizes[] { new(256, 512, 128) });
    public static ReadOnlyCollection<KeySizes> LegalKeySizes { get => _LegalKeySizes; }

    public static bool ValidKeySize(int bitLength)
    {
        return bitLength switch
        {
            256 or 384 or 512 => true,
            _ => false
        };
    }

    byte[] S2V(byte[][] associatedData, byte[] plaintext)
    {
        var D = Cmac.ComputeHash(zero);
        foreach (var S in associatedData)
        {
            D.dbl_InPlace();
            D.xor_InPlace(0, Cmac.ComputeHash(S), 0, BLOCKSIZE);
        }
        if (plaintext.Length >= BLOCKSIZE)
        {
            // D takes the role of the "end" in "xorend"
            D.xor_InPlace(0, plaintext, plaintext.Length - BLOCKSIZE, BLOCKSIZE);
            // Using Transform instead of Compute prevents cloning plaintext.
            Cmac.TransformBlock(plaintext, 0, plaintext.Length - BLOCKSIZE, null, 0);
            Cmac.TransformBlock(D, 0, BLOCKSIZE, null, 0);
            Cmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return Cmac.Hash;
        }
        else
        {
            D.dbl_InPlace();
            // This implements pad() as well.
            D.xor_InPlace(0, plaintext, 0, plaintext.Length);
            D[plaintext.Length] ^= 0x80;
            return Cmac.ComputeHash(D);
        }
    }

    // RFC 5297, Section 2.6 and 2.7
    //
    // Q = V bitand (1^64 || 0^1 || 1^31 || 0^1 || 1^31)
    static byte[] InitializationVectorToInitialCounter(byte[] V)
    {
        var Q = new byte[BLOCKSIZE];
        V.CopyTo(Q, 0);
        Q[8] &= 0x7f;
        Q[12] &= 0x7f;
        return Q;
    }

    public void Encrypt(byte[] plaintext, byte[] ciphertext, params byte[][] associatedData)
    {
        // Input validation

        _ = plaintext ?? throw new ArgumentNullException(nameof(plaintext));
        _ = ciphertext ?? throw new ArgumentNullException(nameof(plaintext));
        _ = associatedData ?? throw new ArgumentNullException(nameof(plaintext));
        foreach (var ad in associatedData)
        {
            _ = ad ?? throw new ArgumentException("Associated data items must not be null.", nameof(associatedData));
        }

        if (ciphertext.Length != BLOCKSIZE + plaintext.Length)
        {
            throw new ArgumentException($"Ciphertext must be larger than plaintext by exactly BlockSize ({BLOCKSIZE} bytes).", nameof(ciphertext));
        }

        // RFC 5297, Section 2.6

        var V = S2V(associatedData, plaintext);
        if (plaintext.Length > 0)
        {
            Ctr.IV = InitializationVectorToInitialCounter(V);
            using var encryptor = Ctr.CreateEncryptor();
            var fullBlocksByteCount = plaintext.Length / BLOCKSIZE * BLOCKSIZE;
            var ciphertextOffset = BLOCKSIZE;
            if (fullBlocksByteCount > 0)
            {
                ciphertextOffset += encryptor.TransformBlock(plaintext, 0, fullBlocksByteCount, ciphertext, ciphertextOffset);
            }
            if (plaintext.Length > fullBlocksByteCount)
            {
                encryptor.TransformFinalBlock(plaintext, fullBlocksByteCount, plaintext.Length - fullBlocksByteCount).CopyTo(ciphertext, ciphertextOffset);
            }
        }
        V.CopyTo(ciphertext, 0);
    }

    public void Decrypt(byte[] ciphertext, byte[] plaintext, params byte[][] associatedData)
    {
        // Input validation

        _ = ciphertext ?? throw new ArgumentNullException(nameof(ciphertext));
        _ = plaintext ?? throw new ArgumentNullException(nameof(plaintext));
        _ = associatedData ?? throw new ArgumentNullException(nameof(associatedData));
        foreach (var ad in associatedData)
        {
            _ = ad ?? throw new ArgumentException("Associated data items must not be null.", nameof(associatedData));
        }

        if (ciphertext.Length < BLOCKSIZE)
        {
            throw new ArgumentException("Ciphertext too short.", nameof(ciphertext));
        }

        if (plaintext.Length != ciphertext.Length - BLOCKSIZE)
        {
            throw new ArgumentException($"Plaintext must be shorter than ciphertext by exactly BlockSize ({BLOCKSIZE} bytes).", nameof(plaintext));
        }

        // RFC 5297, Section 2.7

        var V = ciphertext.Take(BLOCKSIZE).ToArray();
        if (plaintext.Length > 0)
        {
            Ctr.IV = InitializationVectorToInitialCounter(V);
            using var decryptor = Ctr.CreateDecryptor();
            var fullBlocksByteCount = plaintext.Length / BLOCKSIZE * BLOCKSIZE;
            var plaintextOffset = 0;
            if (fullBlocksByteCount > 0)
            {
                plaintextOffset += decryptor.TransformBlock(ciphertext, BLOCKSIZE, fullBlocksByteCount, plaintext, plaintextOffset);
            }
            if (plaintext.Length > fullBlocksByteCount)
            {
                decryptor.TransformFinalBlock(ciphertext, BLOCKSIZE + fullBlocksByteCount, plaintext.Length - fullBlocksByteCount).CopyTo(plaintext, plaintextOffset);
            }
        }
        var T = S2V(associatedData, plaintext);
        if (!Enumerable.SequenceEqual(T, V))
        {
            for (var i = 0; i < plaintext.Length; ++i)
            {
                plaintext[i] = 0;
            }
            throw new CryptographicException("Authentication failed.");
        }
    }
}

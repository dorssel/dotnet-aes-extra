// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System;
using System.Linq;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

/// <summary>
/// Represents an Advanced Encryption Standard (AES) key to be used with the Synthetic Initialization Vector (SIV) mode of operation.
/// </summary>
public sealed class AesSiv
    : IDisposable
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AesSiv"/> class with a provided key.
    /// </summary>
    /// <param name="key">The secret key to use for this instance.</param>
    /// <exception cref="ArgumentNullException" />
    public AesSiv(byte[] key)
    {
        _ = key ?? throw new ArgumentNullException(nameof(key));

        Cmac.Key = key.Take(key.Length / 2).ToArray();
        Ctr.Key = key.Skip(key.Length / 2).ToArray();
    }

    const int BLOCKSIZE = 16; // bytes
    // See: RFC 5297, Section 7
    const int MaximumAssociatedDataCount = 126;

    static readonly byte[] zero = new byte[BLOCKSIZE];

    readonly Aes Ctr = AesCtr.Create();
    readonly KeyedHashAlgorithm Cmac = new AesCmac();

    #region IDisposable
    bool IsDisposed;

    /// <inheritdoc cref="IDisposable.Dispose()" />
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

    /// <summary>
    /// Encrypts the plaintext into the ciphertext destination buffer, prepending the synthetic IV.
    /// </summary>
    /// <param name="plaintext">The content to encrypt.</param>
    /// <param name="ciphertext">The byte array to receive the encrypted contents, prepended with the synthetic IV.</param>
    /// <param name="associatedData">Extra data associated with this message, which must also be provided during decryption.</param>
    /// <exception cref="ArgumentNullException" />
    /// <exception cref="ArgumentException" />
    public void Encrypt(byte[] plaintext, byte[] ciphertext, params byte[][] associatedData)
    {
        // Input validation

        _ = plaintext ?? throw new ArgumentNullException(nameof(plaintext));
        _ = ciphertext ?? throw new ArgumentNullException(nameof(plaintext));
        _ = associatedData ?? throw new ArgumentNullException(nameof(plaintext));
        if (associatedData.Length > MaximumAssociatedDataCount)
        {
            throw new ArgumentException("Too many associated data items.");
        }
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

    /// <summary>
    /// Decrypts the ciphertext into the provided destination buffer if the data can be validated.
    /// </summary>
    /// <param name="ciphertext">The encrypted content to decrypt, including the prepended IV.</param>
    /// <param name="plaintext">The byte array to receive the decrypted contents.</param>
    /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
    /// <exception cref="ArgumentNullException" />
    /// <exception cref="ArgumentException" />
    /// <exception cref="CryptographicException" />
    public void Decrypt(byte[] ciphertext, byte[] plaintext, params byte[][] associatedData)
    {
        // Input validation

        _ = ciphertext ?? throw new ArgumentNullException(nameof(ciphertext));
        _ = plaintext ?? throw new ArgumentNullException(nameof(plaintext));
        _ = associatedData ?? throw new ArgumentNullException(nameof(associatedData));
        if (associatedData.Length > MaximumAssociatedDataCount)
        {
            throw new ArgumentException("Too many associated data items.");
        }
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
        if (!CryptographicOperations.FixedTimeEquals(T, V))
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException("Authentication failed.");
        }
    }
}

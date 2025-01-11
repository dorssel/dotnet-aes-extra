// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

/// <summary>
/// Computes a Cipher-based Message Authentication Code (CMAC) by using the symmetric key AES block cipher.
/// </summary>
public sealed class AesCmac
    : KeyedHashAlgorithm
{
    const int BLOCKSIZE = 16; // bytes
    const int BitsPerByte = 8;

    /// <inheritdoc cref="KeyedHashAlgorithm.Create()" path="/summary" />
    /// <returns>A new <see cref="AesCmac" /> instance.</returns>
    public static new AesCmac Create()
    {
        return new AesCmac();
    }

    /// <inheritdoc cref="KeyedHashAlgorithm.Create(string)" />
    [Obsolete("Cryptographic factory methods accepting an algorithm name are obsolete. Use the parameterless Create factory method on the algorithm type instead.")]
#if !NETSTANDARD2_0
    [RequiresUnreferencedCode("The default algorithm implementations might be removed, use strong type references like 'RSA.Create()' instead.")]
#endif
    public static new KeyedHashAlgorithm? Create(string algorithmName)
    {
        return algorithmName == nameof(AesCmac) ? Create() : KeyedHashAlgorithm.Create(algorithmName);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AesCmac" /> class with a randomly generated key.
    /// </summary>
    /// <param name="keySize">The size, in bits, of the randomly generated key.</param>
    public AesCmac(int keySize = 256)
    {
        AesEcb = Aes.Create();
        AesEcb.Mode = CipherMode.ECB;  // DevSkim: ignore DS187371
        AesEcb.BlockSize = BLOCKSIZE * BitsPerByte;
        AesEcb.KeySize = keySize;
        HashSizeValue = BLOCKSIZE * 8;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AesCmac" /> class with the specified key data.
    /// </summary>
    /// <param name="key">The secret key for AES-CMAC algorithm.</param>
    public AesCmac(byte[] key)
        : this()
    {
        Key = key;
    }

    #region IDisposable
    /// <inheritdoc cref="KeyedHashAlgorithm.Dispose(bool)" />
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            CryptographicOperations.ZeroMemory(KeyValue);
            CryptographicOperations.ZeroMemory(K1Value);
            CryptographicOperations.ZeroMemory(K2Value);
            CryptographicOperations.ZeroMemory(C);
            CryptographicOperations.ZeroMemory(Partial);
            AesEcb.Dispose();
            CryptoTransformValue?.Dispose();
            CryptoTransformValue = null;
            K1Value = null;
            K2Value = null;
            PartialLength = 0;
            State = 0;
        }
        base.Dispose(disposing);
    }
    #endregion

    /// <inheritdoc />
    public override byte[] Key
    {
        get => AesEcb.Key;
        set
        {
            if (State != 0)
            {
                throw new InvalidOperationException("Key cannot be changed during a computation.");
            }
            AesEcb.Key = value;
            CryptographicOperations.ZeroMemory(K1Value);
            CryptographicOperations.ZeroMemory(K2Value);
            CryptoTransformValue?.Dispose();
            CryptoTransformValue = null;
            K1Value = null;
            K2Value = null;
        }
    }

    readonly Aes AesEcb;
    ICryptoTransform? CryptoTransformValue;

    ICryptoTransform CryptoTransform
    {
        get
        {
            CryptoTransformValue ??= AesEcb.CreateEncryptor();
            return CryptoTransformValue;
        }
    }

    // See: NIST SP 800-38B, Section 6.2, Step 5
    readonly byte[] C = new byte[BLOCKSIZE];

    byte[]? K1Value;
    byte[]? K2Value;

    // See: NIST SP 800-38B, Section 6.1
    byte[] K1 {
        get
        {
            if (K1Value is null)
            {
                // Step 1: K1Value has the role of L
                K1Value = new byte[BLOCKSIZE];
                CIPH_K_InPlace(K1Value);
                // Step 2: K1Value has the role of K1
                K1Value.dbl_InPlace();
            }
            // Step 4: return K1
            return K1Value;
        }
    }

    // See: NIST SP 800-38B, Section 6.1
    byte[] K2
    {
        get
        {
            if (K2Value is null)
            {
                // Step 3: K2Value has the role of K1
                K2Value = (byte[])K1.Clone();
                K2Value.dbl_InPlace();
            }
            // Step 4: return K2
            return K2Value;
        }
    }

    // See: NIST SP 800-38B, Section 4.2.2
    //
    // In-place: X = CIPH_K(X)
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    void CIPH_K_InPlace(byte[] X)
    {
        _ = CryptoTransform.TransformBlock(X, 0, BLOCKSIZE, X, 0);
    }

    /// <inheritdoc cref="HashAlgorithm.Initialize" />
    public override void Initialize()
    {
        // See: NIST SP 800-38B, Section 6.2, Step 5
        C.AsSpan().Clear();
        PartialLength = 0;
        State = 0;
    }

    readonly byte[] Partial = new byte[BLOCKSIZE];
    int PartialLength;

    // See: NIST SP 800-38B, Section 6.2, Step 6
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    void AddBlock(ReadOnlySpan<byte> block)
    {
        C.xor_InPlace(block);
        CIPH_K_InPlace(C);
    }

    /// <inheritdoc />
    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
        HashCore(array.AsSpan(ibStart, cbSize));
    }

    /// <inheritdoc/>
#if !NETSTANDARD2_0
    protected override
#endif
    void HashCore(ReadOnlySpan<byte> source)
    {
        State = 1;

        if (source.Length == 0)
        {
            return;
        }

        // If we have a non-empty && non-full Partial block already -> append to that first.
        if (PartialLength is > 0 and < BLOCKSIZE)
        {
            var count = Math.Min(source.Length, BLOCKSIZE - PartialLength);
            source[..count].CopyTo(Partial.AsSpan(PartialLength));
            PartialLength += count;
            if (count == source.Length)
            {
                // No more data supplied, we're done. Even if we filled up Partial completely,
                // because we don't know if it will be the final block.
                return;
            }
            source = source[count..];
        }

        // We get here only if Partial is either empty or full (i.e. we are block-aligned) && there is more to "hash".
        if (PartialLength == BLOCKSIZE)
        {
            // Since there is more to hash, this is not the final block.
            // See: NIST SP 800-38B, Section 6.2, Steps 3 and 6
            AddBlock(Partial);
            PartialLength = 0;
        }

        // We get here only if Partial is empty && there is more to "hash".
        // Add complete, non-final blocks. Never add the last block given in this call since we don't know if that will be the final block.
        for (int i = 0, nonFinalBlockCount = (source.Length - 1) / BLOCKSIZE; i < nonFinalBlockCount; i++)
        {
            // See: NIST SP 800-38B, Section 6.2, Steps 3 and 6
            AddBlock(source[..BLOCKSIZE]);
            source = source[BLOCKSIZE..];
        }

        // Save what we have left (we always have some, by construction).
        source.CopyTo(Partial);
        PartialLength = source.Length;
    }

    /// <inheritdoc cref="HashAlgorithm.HashFinal" />
    protected override byte[] HashFinal()
    {
        var result = new byte[BLOCKSIZE];
        _ = TryHashFinal(result, out _);
        return result;
    }

    /// <inheritdoc/>
#if !NETSTANDARD2_0
    protected override
#endif
    bool TryHashFinal(Span<byte> destination, out int bytesWritten)
    {
        // See: NIST SP 800-38B, Section 6.2, Step 4
        // Partial now has the role of Mn*
        if (PartialLength == BLOCKSIZE)
        {
            // See: NIST SP 800-38B, Section 6.2, Step 1: K1
            Partial.xor_InPlace(K1);
            // Partial now has the role of Mn
        }
        else
        {
            // Add padding
            Partial[PartialLength] = 0x80;
            Partial.AsSpan(PartialLength + 1).Clear();
            // See: NIST SP 800-38B, Section 6.2, Step 1: K2
            Partial.xor_InPlace(K2);
            // Partial now has the role of Mn
        }
        // See: NIST SP 800-38B, Section 6.2, Step 6
        AddBlock(Partial);

        C.CopyTo(destination);

        Initialize();

        bytesWritten = BLOCKSIZE;
        return true;
    }
}

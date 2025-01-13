// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
// SPDX-FileCopyrightText: .NET Foundation
//
// SPDX-License-Identifier: MIT

using System.Buffers;
using System.Diagnostics;
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
                K1Value.AsSpan().dbl_InPlace();
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
                K2Value.AsSpan().dbl_InPlace();
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
        C.AsSpan().xor_InPlace(block);
        CIPH_K_InPlace(C);
    }

    /// <inheritdoc />
    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
        UncheckedHashCore(array.AsSpan(ibStart, cbSize));
    }

    /// <inheritdoc/>
#if !NETSTANDARD2_0
    protected override
#endif
    void HashCore(ReadOnlySpan<byte> source)
    {
        UncheckedHashCore(source);
    }

    internal void UncheckedHashCore(ReadOnlySpan<byte> source)
    {
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
        var destination = new byte[BLOCKSIZE];
        UncheckedHashFinal(destination);
        return destination;
    }

    /// <inheritdoc/>
#if !NETSTANDARD2_0
    protected override
#endif
    bool TryHashFinal(Span<byte> destination, out int bytesWritten)
    {
        UncheckedHashFinal(destination);
        bytesWritten = BLOCKSIZE;
        return true;
    }

    internal void UncheckedHashFinal(Span<byte> destination)
    {
        // See: NIST SP 800-38B, Section 6.2, Step 4
        // Partial now has the role of Mn*
        if (PartialLength == BLOCKSIZE)
        {
            // See: NIST SP 800-38B, Section 6.2, Step 1: K1
            Partial.AsSpan().xor_InPlace(K1);
            // Partial now has the role of Mn
        }
        else
        {
            // Add padding
            Partial[PartialLength] = 0x80;
            Partial.AsSpan(PartialLength + 1).Clear();
            // See: NIST SP 800-38B, Section 6.2, Step 1: K2
            Partial.AsSpan().xor_InPlace(K2);
            // Partial now has the role of Mn
        }
        // See: NIST SP 800-38B, Section 6.2, Step 6
        AddBlock(Partial);

        C.CopyTo(destination);
    }

    #region Modern_KeyedHashAlgorithm
    // Helper with a byte[] as key, which is required since we need to pass it as such.
    static void OneShot(byte[] key, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        using var cmac = new AesCmac(key);
        cmac.UncheckedHashCore(source);
        cmac.UncheckedHashFinal(destination);
    }

    // Helper with a byte[] as key, which is required since we need to pass it as such.
    // see https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/LiteHashProvider.cs
    static void OneShot(byte[] key, Stream source, Span<byte> destination)
    {
        Debug.Assert(destination.Length >= BLOCKSIZE);

        using var cmac = new AesCmac(key);
        var maxRead = 0;
        int read;
        var rented = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            while ((read = source.Read(rented, 0, 4096)) > 0)
            {
                maxRead = Math.Max(maxRead, read);
                cmac.UncheckedHashCore(rented.AsSpan(0, read));
            }
            cmac.UncheckedHashFinal(destination);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rented.AsSpan(0, maxRead));
            ArrayPool<byte>.Shared.Return(rented, false);
        }
    }

    // Helper with a byte[] as key, which is required since we need to pass it as such.
    // see https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/LiteHashProvider.cs
    static async ValueTask OneShotAsync(byte[] key, Stream source, Memory<byte> destination, CancellationToken cancellationToken)
    {
        Debug.Assert(destination.Length >= BLOCKSIZE);

        using var cmac = new AesCmac(key);
        var maxRead = 0;
        int read;
        var rented = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            while ((read = await source.ReadAsync(rented, 0, 4096, cancellationToken).ConfigureAwait(false)) > 0)
            {
                maxRead = Math.Max(maxRead, read);
                cmac.UncheckedHashCore(rented.AsSpan(0, read));
            }
            cmac.UncheckedHashFinal(destination.Span);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rented.AsSpan(0, maxRead));
            ArrayPool<byte>.Shared.Return(rented, false);
        }
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="key">TODO</param>
    /// <param name="source">TODO</param>
    /// <param name="destination">TODO</param>
    /// <param name="bytesWritten">TODO</param>
    /// <returns>TODO</returns>
    public static bool TryHashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten)
    {
        if (destination.Length < BLOCKSIZE)
        {
            bytesWritten = 0;
            return false;
        }

        using var keyCopy = new SecureByteArray(key);
        OneShot(keyCopy, source, destination);
        bytesWritten = BLOCKSIZE;
        return true;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="key">TODO</param>
    /// <param name="source">TODO</param>
    /// <returns>TODO</returns>
    public static byte[] HashData(byte[] key, byte[] source)
    {
        var destination = new byte[BLOCKSIZE];
        OneShot(key, source, destination);
        return destination;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="key">TODO</param>
    /// <param name="source">TODO</param>
    /// <returns>TODO</returns>
    public static byte[] HashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source)
    {
        using var keyCopy = new SecureByteArray(key);
        var destination = new byte[BLOCKSIZE];
        OneShot(keyCopy, source, destination);
        return destination;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="key">TODO</param>
    /// <param name="source">TODO</param>
    /// <param name="destination">TODO</param>
    /// <returns>TODO</returns>
    public static int HashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (destination.Length < BLOCKSIZE)
        {
            throw new ArgumentException("Destination is too short.", nameof(destination));
        }

        using var keyCopy = new SecureByteArray(key);
        OneShot(keyCopy, source, destination);
        return BLOCKSIZE;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="key">TODO</param>
    /// <param name="source">TODO</param>
    /// <returns>TODO</returns>
    public static byte[] HashData(byte[] key, Stream source)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        var destination = new byte[BLOCKSIZE];
        OneShot(key, source, destination);
        return destination;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="key">TODO</param>
    /// <param name="source">TODO</param>
    /// <returns>TODO</returns>
    public static byte[] HashData(ReadOnlySpan<byte> key, Stream source)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        using var keyCopy = new SecureByteArray(key);
        var destination = new byte[BLOCKSIZE];
        OneShot(keyCopy, source, destination);
        return destination;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="key">TODO</param>
    /// <param name="source">TODO</param>
    /// <param name="destination">TODO</param>
    /// <returns>TODO</returns>
    public static int HashData(ReadOnlySpan<byte> key, Stream source, Span<byte> destination)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }
        if (destination.Length < BLOCKSIZE)
        {
            throw new ArgumentException("Destination is too short.", nameof(destination));
        }

        using var keyCopy = new SecureByteArray(key);
        OneShot(keyCopy, source, destination);
        return BLOCKSIZE;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="key">TODO</param>
    /// <param name="source">TODO</param>
    /// <param name="cancellationToken">TODO</param>
    /// <returns>TODO</returns>
    /// <exception cref="ArgumentNullException">TODO</exception>
    public static async ValueTask<byte[]> HashDataAsync(byte[] key, Stream source, CancellationToken cancellationToken = default)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        var destination = new byte[BLOCKSIZE];
        await OneShotAsync(key, source, destination, cancellationToken).ConfigureAwait(false);
        return destination;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="key">TODO</param>
    /// <param name="source">TODO</param>
    /// <param name="cancellationToken">TODO</param>
    /// <returns>TODO</returns>
    public static async ValueTask<byte[]> HashDataAsync(ReadOnlyMemory<byte> key, Stream source, CancellationToken cancellationToken = default)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        using var keyCopy = new SecureByteArray(key);
        var destination = new byte[BLOCKSIZE];
        await OneShotAsync(keyCopy, source, destination, cancellationToken).ConfigureAwait(false);
        return destination;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="key">TODO</param>
    /// <param name="source">TODO</param>
    /// <param name="destination">TODO</param>
    /// <param name="cancellationToken">TODO</param>
    /// <returns>TODO</returns>
    public static async ValueTask<int> HashDataAsync(ReadOnlyMemory<byte> key, Stream source, Memory<byte> destination,
        CancellationToken cancellationToken = default)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }
        if (destination.Length < BLOCKSIZE)
        {
            throw new ArgumentException("Destination is too short.", nameof(destination));
        }

        using var keyCopy = new SecureByteArray(key);
        await OneShotAsync(keyCopy, source, destination, cancellationToken).ConfigureAwait(false);
        return BLOCKSIZE;
    }
#endregion
}

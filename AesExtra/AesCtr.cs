// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

/// <summary>
/// Provides an implementation of the Advanced Encryption Standard (AES) symmetric algorithm in CTR mode.
/// </summary>
/// <seealso href="https://csrc.nist.gov/publications/detail/sp/800-38a/final"/>
public sealed class AesCtr
    : Aes
{
    const int BLOCKSIZE = 16;  // bytes
    const int BitsPerByte = 8;
    const CipherMode FixedModeValue = CipherMode.CTS;  // DevSkim: ignore DS187371
    const PaddingMode FixedPaddingValue = PaddingMode.None;
    const int FixedFeedbackSizeValue = BLOCKSIZE * BitsPerByte;

    /// <inheritdoc cref="Aes.Create()" />
    public static new AesCtr Create()
    {
        return new AesCtr();
    }

    /// <inheritdoc cref="Aes.Create(string)" />
    [Obsolete("Cryptographic factory methods accepting an algorithm name are obsolete. Use the parameterless Create factory method on the algorithm type instead.")]
#if !NETSTANDARD2_0
    [RequiresUnreferencedCode("The default algorithm implementations might be removed, use strong type references like 'RSA.Create()' instead.")]
#endif
    public static new Aes? Create(string algorithmName)
    {
        return algorithmName == nameof(AesCtr) ? Create() : Aes.Create(algorithmName);
    }

    AesCtr()
    {
        KeySizeValue = 256;
        ModeValue = FixedModeValue;
        PaddingValue = FixedPaddingValue;
        FeedbackSizeValue = FixedFeedbackSizeValue;
        BlockSizeValue = BLOCKSIZE * BitsPerByte;
        LegalBlockSizesValue = [new(128, 128, 0)];
        LegalKeySizesValue = [new(128, 256, 64)];
    }

    #region IDisposable
    /// <inheritdoc cref="SymmetricAlgorithm.Dispose(bool)" />
    protected override void Dispose(bool disposing)
    {
        CryptographicOperations.ZeroMemory(KeyValue);
        KeyValue = null;
        CryptographicOperations.ZeroMemory(IVValue);
        IVValue = null;
        base.Dispose(disposing);
    }
    #endregion

    /// <inheritdoc cref="AesManaged.Mode" />
    /// <remarks><see cref="AesCtr"/> always pretends to use <see cref="CipherMode.CTS" />.</remarks>
    public override CipherMode Mode
    {
        get => FixedModeValue;
        set
        {
            if (value != FixedModeValue)
            {
                throw new CryptographicException("Specified cipher mode is not valid for this algorithm.");
            }
        }
    }

    /// <inheritdoc cref="SymmetricAlgorithm.Padding" />
    /// <remarks><see cref="AesCtr"/> always uses <see cref="PaddingMode.None" />.</remarks>
    public override PaddingMode Padding
    {
        get => FixedPaddingValue;
        set
        {
            if (value != FixedPaddingValue)
            {
                throw new CryptographicException("Specified padding mode is not valid for this algorithm.");
            }
        }
    }

    /// <inheritdoc cref="SymmetricAlgorithm.FeedbackSize" />
    /// <remarks><see cref="AesCtr"/> always uses 128 bits.</remarks>
    public override int FeedbackSize
    {
        get => FixedFeedbackSizeValue;
        set
        {
            if (value != FixedFeedbackSizeValue)
            {
                throw new CryptographicException("Specified feedback size is not valid for this algorithm.");
            }
        }
    }

    // CTR.Encrypt === CTR.Decrypt; the transform is entirely symmetric.
    static AesCtrTransform CreateTransform(byte[] rgbKey, byte[]? rgbIV)
    {
        return rgbIV is not null ? new(rgbKey, rgbIV)
            : throw new CryptographicException("The cipher mode specified requires that an initialization vector(IV) be used.");
    }

    /// <inheritdoc cref="AesManaged.CreateDecryptor(byte[], byte[])" />
    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        return CreateTransform(rgbKey, rgbIV);
    }

    /// <inheritdoc cref="AesManaged.CreateEncryptor(byte[], byte[])" />
    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        return CreateTransform(rgbKey, rgbIV);
    }

    /// <inheritdoc cref="AesManaged.GenerateIV" />
    public override void GenerateIV()
    {
        CryptographicOperations.ZeroMemory(IVValue);
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        IVValue = new byte[BLOCKSIZE];
        randomNumberGenerator.GetBytes(IVValue);
    }

    /// <inheritdoc cref="AesManaged.GenerateKey" />
    public override void GenerateKey()
    {
        CryptographicOperations.ZeroMemory(KeyValue);
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        KeyValue = new byte[KeySize / BitsPerByte];
        randomNumberGenerator.GetBytes(KeyValue);
    }

    #region Modern_SymmetricAlgorithm
    /// <exception cref="ArgumentNullException"><paramref name="input"/> is <see langword="null"/>.</exception>
    static void ThrowIfInvalidInput(byte[] input)
    {
        if (input is null)
        {
            throw new ArgumentNullException(nameof(input));
        }
    }

    /// <exception cref="ArgumentNullException"><paramref name="iv"/> is <see langword="null"/>.</exception>
    /// <inheritdoc cref="ThrowIfInvalidIV(ReadOnlySpan{byte})"/>
    static void ThrowIfInvalidIV(byte[] iv)
    {
        if (iv is null)
        {
            throw new ArgumentNullException(nameof(iv));
        }
        ThrowIfInvalidIV(iv.AsSpan());
    }

    /// <exception cref="ArgumentException">
    /// <paramref name="iv"/> is the incorrect length.
    /// Callers are expected to pass an initialization vector that is exactly <see cref="SymmetricAlgorithm.BlockSize"/> in length,
    /// converted to bytes (`BlockSize / 8`).
    /// </exception>
    static void ThrowIfInvalidIV(ReadOnlySpan<byte> iv)
    {
        if (iv.Length != BLOCKSIZE)
        {
            throw new ArgumentException("Specified initial counter (IV) does not match the block size for this algorithm.", nameof(iv));
        }
    }

    /// <exception cref="ArgumentException">The buffer in <paramref name="destination"/> is too small to hold the transformed data.</exception>
    static void ThrowIfInvalidDestination(Span<byte> destination, int requiredLength)
    {
        if (destination.Length < requiredLength)
        {
            throw new ArgumentException("Destination is too short.", nameof(destination));
        }
    }

    /// <summary>
    /// Transforms data using CTR mode.
    /// </summary>
    /// <param name="input">The data to transform.</param>
    /// <param name="iv">The initialization vector (initial counter).</param>
    /// <returns>The transformed data.</returns>
    /// <inheritdoc cref="ThrowIfInvalidInput(byte[])"/>
    /// <inheritdoc cref="ThrowIfInvalidIV(byte[])"/>
    public byte[] TransformCtr(byte[] input, byte[] iv)
    {
        ThrowIfInvalidInput(input);
        ThrowIfInvalidIV(iv);

        var output = new byte[input.Length];
        using var transform = new AesCtrTransform(Key, iv);
        transform.UncheckedTransform(input, output);
        return output;
    }

    /// <summary>
    /// Transforms data using CTR mode.
    /// </summary>
    /// <param name="input">The data to transform.</param>
    /// <param name="iv">The initialization vector (initial counter).</param>
    /// <returns>The transformed data.</returns>
    /// <inheritdoc cref="ThrowIfInvalidIV(ReadOnlySpan{byte})"/>
    public byte[] TransformCtr(ReadOnlySpan<byte> input, ReadOnlySpan<byte> iv)
    {
        ThrowIfInvalidIV(iv);

        var output = new byte[input.Length];
        using var transform = new AesCtrTransform(Key, iv);
        transform.UncheckedTransform(input, output);
        return output;
    }

    /// <summary>
    /// Transforms data into the specified buffer, using CTR mode.
    /// </summary>
    /// <param name="input">The data to transform.</param>
    /// <param name="iv">The initialization vector (initial counter).</param>
    /// <param name="destination">The buffer to receive the transformed data.</param>
    /// <returns>The total number of bytes written to <paramref name="destination"/>.</returns>
    /// <inheritdoc cref="ThrowIfInvalidIV(ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfInvalidDestination(Span{byte}, int)"/>
    public int TransformCtr(ReadOnlySpan<byte> input, ReadOnlySpan<byte> iv, Span<byte> destination)
    {
        ThrowIfInvalidIV(iv);
        ThrowIfInvalidDestination(destination, input.Length);

        using var transform = new AesCtrTransform(Key, iv);
        transform.UncheckedTransform(input, destination);
        return input.Length;
    }

    /// <summary>
    /// Attempts to transform data into the specified buffer, using CTR mode.
    /// </summary>
    /// <param name="input">The data to transform.</param>
    /// <param name="iv">The initialization vector (initial counter).</param>
    /// <param name="destination">The buffer to receive the transformed data.</param>
    /// <param name="bytesWritten">When this method returns, contains the total number of bytes written to <paramref name="destination"/>.</param>
    /// <returns>
    /// <see langword="true"/> if <paramref name="destination"/> was large enough to receive the transformed data; otherwise, <see langword="false"/>.
    /// </returns>
    /// <inheritdoc cref="ThrowIfInvalidIV(ReadOnlySpan{byte})"/>
    public bool TryTransformCtr(ReadOnlySpan<byte> input, ReadOnlySpan<byte> iv, Span<byte> destination, out int bytesWritten)
    {
        ThrowIfInvalidIV(iv);

        if (destination.Length < input.Length)
        {
            bytesWritten = 0;
            return false;
        }

        using var transform = new AesCtrTransform(Key, iv);
        transform.UncheckedTransform(input, destination);
        bytesWritten = input.Length;
        return true;
    }
    #endregion
}

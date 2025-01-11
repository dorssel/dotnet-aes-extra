// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

/// <summary>
/// Provides an implementation of the Advanced Encryption Standard (AES) symmetric algorithm in CTR mode.
/// </summary>
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
    bool TryTransformCtr(ReadOnlySpan<byte> input, ReadOnlySpan<byte> iv, Span<byte> destination, out int bytesWritten)
    {
        if (destination.Length < input.Length)
        {
            bytesWritten = 0;
            return false;
        }
        using var transform = new AesCtrTransform(Key, iv);
        var inputSlice = input;
        var destinationSlice = destination;
        while (inputSlice.Length >= BLOCKSIZE)
        {
            // full blocks
            transform.TransformBlock(inputSlice, destinationSlice);
            inputSlice = inputSlice[BLOCKSIZE..];
            destinationSlice = destinationSlice[BLOCKSIZE..];
        }
        if (!inputSlice.IsEmpty)
        {
            // final partial block (if any)
            Span<byte> block = stackalloc byte[BLOCKSIZE];
            inputSlice.CopyTo(block);
            transform.TransformBlock(block, block);
            block[0..inputSlice.Length].CopyTo(destinationSlice);
            CryptographicOperations.ZeroMemory(block);
        }
        bytesWritten = input.Length;
        return true;
    }

    byte[] TransformCtr(ReadOnlySpan<byte> input, ReadOnlySpan<byte> iv)
    {
        var output = new byte[input.Length];
        _ = TryTransformCtr(input, iv, output, out _);
        return output;
    }

    int TransformCtr(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv, Span<byte> destination)
    {
        return TryTransformCtr(plaintext, iv, destination, out var bytesWritten) ? bytesWritten
            : throw new ArgumentException("Destination is too short.", nameof(destination));
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="plaintext">TODO</param>
    /// <param name="iv">TODO</param>
    /// <returns>TODO</returns>
    public byte[] EncryptCtr(byte[] plaintext, byte[] iv)
    {
        return TransformCtr(plaintext, iv);
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="plaintext">TODO</param>
    /// <param name="iv">TODO</param>
    /// <returns>TODO</returns>
    public byte[] EncryptCtr(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv)
    {
        return TransformCtr(plaintext, iv);
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="plaintext">TODO</param>
    /// <param name="iv">TODO</param>
    /// <param name="destination">TODO</param>
    /// <returns>TODO</returns>
    public int EncryptCtr(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv, Span<byte> destination)
    {
        return TransformCtr(plaintext, iv, destination);
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="plaintext">TODO</param>
    /// <param name="iv">TODO</param>
    /// <param name="destination">TODO</param>
    /// <param name="bytesWritten">TODO</param>
    /// <returns>TODO</returns>
    public bool TryEncryptCtr(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv, Span<byte> destination, out int bytesWritten)
    {
        return TryTransformCtr(plaintext, iv, destination, out bytesWritten);
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="ciphertext">TODO</param>
    /// <param name="iv">TODO</param>
    /// <returns>TODO</returns>
    public byte[] DecryptCtr(byte[] ciphertext, byte[] iv)
    {
        return TransformCtr(ciphertext, iv);
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="ciphertext">TODO</param>
    /// <param name="iv">TODO</param>
    /// <returns>TODO</returns>
    public byte[] DecryptCtr(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> iv)
    {
        return TransformCtr(ciphertext, iv);
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="ciphertext">TODO</param>
    /// <param name="iv">TODO</param>
    /// <param name="destination">TODO</param>
    /// <returns>TODO</returns>
    public int DecryptCtr(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> iv, Span<byte> destination)
    {
        return TransformCtr(ciphertext, iv, destination);
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="ciphertext">TODO</param>
    /// <param name="iv">TODO</param>
    /// <param name="destination">TODO</param>
    /// <param name="bytesWritten">TODO</param>
    /// <returns>TODO</returns>
    public bool TryDecryptCtr(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> iv, Span<byte> destination, out int bytesWritten)
    {
        return TryTransformCtr(ciphertext, iv, destination, out bytesWritten);
    }
    #endregion
}

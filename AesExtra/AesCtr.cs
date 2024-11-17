// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

/// <summary>
/// Provides an implementation of the Advanced Encryption Standard (AES) symmetric algorithm in CTR mode.
/// </summary>
public sealed class AesCtr
    : Aes
{
    internal const int FixedBlockSize = 16; // bytes
    const CipherMode FixedCipherMode = CipherMode.ECB; // DevSkim: ignore DS187371
    const PaddingMode FixedPaddingMode = PaddingMode.None;
    const int FixedFeedbackSize = FixedBlockSize * 8; // bits

    /// <inheritdoc cref="Aes.Create()" />
    public static new Aes Create()
    {
        return new AesCtr();
    }

    /// <inheritdoc cref="Aes.Create(string)" />
    public static new Aes? Create(string algorithmName)
    {
        return algorithmName != null ? algorithmName == nameof(AesCtr) ? Create() : null
            : throw new ArgumentNullException(nameof(algorithmName));
    }

    AesCtr()
    {
        Mode = FixedCipherMode;
        Padding = FixedPaddingMode;
        FeedbackSize = FixedFeedbackSize;
    }

    /// <summary>
    /// The aggregated underlying AES-ECB implementation.
    /// </summary>
    readonly Aes AesEcb = Aes.Create();

    #region IDisposable
    bool IsDisposed;

    /// <inheritdoc cref="SymmetricAlgorithm.Dispose(bool)" />
    protected override void Dispose(bool disposing)
    {
        if (!IsDisposed)
        {
            if (disposing)
            {
                AesEcb.Dispose();
            }
            IsDisposed = true;
        }
        base.Dispose(disposing);
    }
    #endregion

    /// <inheritdoc cref="AesManaged.Mode" />
    /// <remarks><see cref="AesCtr"/> always uses <see cref="CipherMode.ECB" />.</remarks>
    public override CipherMode Mode
    {
        get => AesEcb.Mode;
        set
        {
            if (value != FixedCipherMode)
            {
                throw new CryptographicException("Specified cipher mode is not valid for this algorithm.");
            }
            // Just in case there are side-effects of setting to the current value.
            AesEcb.Mode = value;
        }
    }

    /// <inheritdoc cref="SymmetricAlgorithm.Padding" />
    /// <remarks><see cref="AesCtr"/> always uses <see cref="PaddingMode.None" />.</remarks>
    public override PaddingMode Padding
    {
        get => AesEcb.Padding;
        set
        {
            if (value != FixedPaddingMode)
            {
                throw new CryptographicException("Specified padding mode is not valid for this algorithm.");
            }
            // Just in case there are side-effects of setting to the current value.
            AesEcb.Padding = value;
        }
    }

    /// <inheritdoc cref="SymmetricAlgorithm.FeedbackSize" />
    /// <remarks><see cref="AesCtr"/> always uses 128 bits.</remarks>
    public override int FeedbackSize
    {
        get => AesEcb.FeedbackSize;
        set
        {
            if (value != FixedFeedbackSize)
            {
                throw new CryptographicException("Specified feedback size is not valid for this algorithm.");
            }
            AesEcb.FeedbackSize = value;
        }
    }

    /// <inheritdoc cref="SymmetricAlgorithm.IV" />
    public override byte[] IV { get => AesEcb.IV; set => AesEcb.IV = value; }

    /// <inheritdoc cref="SymmetricAlgorithm.Key" />
    public override byte[] Key { get => AesEcb.Key; set => AesEcb.Key = value; }

    /// <inheritdoc cref="SymmetricAlgorithm.BlockSize" />
    public override int BlockSize { get => AesEcb.BlockSize; set => AesEcb.BlockSize = value; }

    /// <inheritdoc cref="SymmetricAlgorithm.KeySize" />
    public override int KeySize { get => AesEcb.KeySize; set => AesEcb.KeySize = value; }

    /// <inheritdoc cref="SymmetricAlgorithm.LegalBlockSizes" />
    public override KeySizes[] LegalBlockSizes => AesEcb.LegalBlockSizes;

    /// <inheritdoc cref="SymmetricAlgorithm.LegalKeySizes" />
    public override KeySizes[] LegalKeySizes => base.LegalKeySizes;

    AesCtrTransform CreateTransform(byte[] rgbKey, byte[]? rgbIV)
    {
        // ECB.Encrypt === ECB.Decrypt; the transform is entirely symmetric.
        // ECB does not use an IV; the IV we received is actually the initial counter for AES-CTR.
        return new(rgbIV ?? new byte[FixedBlockSize], AesEcb.CreateEncryptor(rgbKey, new byte[FixedBlockSize]));
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
        AesEcb.GenerateIV();
    }

    /// <inheritdoc cref="AesManaged.GenerateKey" />
    public override void GenerateKey()
    {
        AesEcb.GenerateKey();
    }
}

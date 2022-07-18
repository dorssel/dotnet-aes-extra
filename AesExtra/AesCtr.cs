using System;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

public sealed class AesCtr
    : Aes
{
    internal const int FixedBlockSize = 16; // bytes
    const CipherMode FixedCipherMode = CipherMode.ECB;
    const PaddingMode FixedPaddingMode = PaddingMode.None;
    const int FixedFeedbackSize = FixedBlockSize * 8; // bits

    public static new Aes Create() => new AesCtr();

    public static new Aes? Create(string algorithmName)
    {
        if (algorithmName == null)
        {
            throw new ArgumentNullException(nameof(algorithmName));
        }
        return algorithmName == nameof(AesCtr) ? Create() : null;
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

    public override int FeedbackSize
    {
        get => AesEcb.FeedbackSize;
        set
        {
            if (value != FixedFeedbackSize)
            {
                throw new CryptographicException("Specified feedback size is not valid for this algorithm.");
            }
            AesEcb.FeedbackSize= value;
        }
    }

    public override byte[] IV { get => AesEcb.IV; set => AesEcb.IV = value; }
    public override byte[] Key { get => AesEcb.Key; set => AesEcb.Key = value; }
    public override int BlockSize { get => AesEcb.BlockSize; set => AesEcb.BlockSize = value; }
    public override int KeySize { get => AesEcb.KeySize; set => AesEcb.KeySize = value; }
    public override KeySizes[] LegalBlockSizes => AesEcb.LegalBlockSizes;
    public override KeySizes[] LegalKeySizes => base.LegalKeySizes;

    ICryptoTransform CreateTransform(byte[] rgbKey, byte[]? rgbIV)
    {
        // ECB.Encrypt === ECB.Decrypt; the transform is entirely symmetric.
        // ECB does not use an IV; the IV we received is actually the initial counter for AES-CTR.
        return new AesCtrTransform(rgbIV ?? new byte[FixedBlockSize], AesEcb.CreateEncryptor(rgbKey, new byte[FixedBlockSize]));
    }

    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV) => CreateTransform(rgbKey, rgbIV);

    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV) => CreateTransform(rgbKey, rgbIV);

    public override void GenerateIV()
    {
        AesEcb.GenerateIV();
    }

    public override void GenerateKey()
    {
        AesEcb.GenerateKey();
    }
}

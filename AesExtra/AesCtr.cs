using System;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

public sealed class AesCtr
    : Aes
{
    const int BLOCKSIZE = 16; // bytes
    const CipherMode FixedCipherMode = CipherMode.ECB;
    const PaddingMode FixedPaddingMode = PaddingMode.None;
    const int FixedFeedbackSize = BLOCKSIZE * 8; // bits

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

    #region IDisposable
    bool IsDisposed;

    protected override void Dispose(bool disposing)
    {
        if (!IsDisposed)
        {
            if (disposing)
            {
            }
            IsDisposed = true;
        }
        base.Dispose(disposing);
    }
    #endregion

    void ThrowIfDisposed()
    {
        if (IsDisposed)
        {
            throw new ObjectDisposedException(nameof(AesCtr));
        }
    }

    public override CipherMode Mode
    { 
        get => base.Mode;
        set
        {
            if (value != FixedCipherMode)
            {
                throw new CryptographicException("Specified cipher mode is not valid for this algorithm.");
            }
            base.Mode = value;
        }
    }

    public override PaddingMode Padding
    {
        get => base.Padding;
        set
        {
            if (value != FixedPaddingMode)
            {
                throw new CryptographicException("Specified padding mode is not valid for this algorithm.");
            }
            base.Padding = value;
        }
    }

    public override int FeedbackSize
    {
        get => base.FeedbackSize;
        set
        {
            if (value != FixedFeedbackSize)
            {
                throw new CryptographicException("Specified feedback size is not valid for this algorithm.");
            }
            base.FeedbackSize= value;
        }
    }

    ICryptoTransform CreateTransform(byte[] rgbKey, byte[]? rgbIV)
    {
        ThrowIfDisposed();

        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        // ECB.Encrypt === ECB.Decrypt; the transform is entirely symmetric.
        // ECB does not use an IV; the IV we received is actually the initial counter for AES-CTR.
        return new AesCtrTransform(rgbIV ?? new byte[BLOCKSIZE], aes.CreateEncryptor(rgbKey, new byte[BLOCKSIZE]));
    }

    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV) => CreateTransform(rgbKey, rgbIV);

    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV) => CreateTransform(rgbKey, rgbIV);

    public override void GenerateIV()
    {
        ThrowIfDisposed();
        IVValue = new byte[BLOCKSIZE];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(IVValue);
    }

    public override void GenerateKey()
    {
        ThrowIfDisposed();
        KeyValue = new byte[KeySizeValue / 8];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(KeyValue);
    }
}

using System;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

public class AesCtr
    : Aes
{
    const int BLOCKSIZE = 16; // bytes

    public static new Aes Create() => new AesCtr();

    public static new Aes? Create(string algorithmName)
    {
        if (algorithmName == null)
        {
            throw new ArgumentNullException(nameof(algorithmName));
        }
        return algorithmName == nameof(AesCtr) ? Create() : null;
    }

    protected AesCtr()
    {
        ModeValue = CipherMode.ECB;
        PaddingValue = PaddingMode.None;
        FeedbackSizeValue = BLOCKSIZE * 8; // bits
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
        get => CipherMode.ECB;
        set
        {
            if (value != CipherMode.ECB)
            {
                throw new CryptographicException("Specified cipher mode is not valid for this algorithm.");
            }
        }
    }

    public override PaddingMode Padding
    {
        get => PaddingMode.None;
        set
        {
            if (value != PaddingMode.None)
            {
                throw new CryptographicException("Specified padding mode is not valid for this algorithm.");
            }
        }
    }

    public override int FeedbackSize
    {
        get => BLOCKSIZE * 8; // bits
        set
        {
            if (value != BLOCKSIZE)
            {
                throw new CryptographicException("Specified feedback size is not valid for this algorithm.");
            }
        }
    }

    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        ThrowIfDisposed();
        return new AesCtrTransform(rgbKey, rgbIV);
    }

    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        ThrowIfDisposed();
        return new AesCtrTransform(rgbKey, rgbIV);
    }

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

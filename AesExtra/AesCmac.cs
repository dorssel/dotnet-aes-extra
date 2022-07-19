using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

public class AesCmac
    : KeyedHashAlgorithm
{
    const int BLOCKSIZE = 16; // bytes

    public static new KeyedHashAlgorithm Create() => new AesCmac();

    public static new KeyedHashAlgorithm? Create(string algorithmName)
    {
        if (algorithmName == null)
        {
            throw new ArgumentNullException(nameof(algorithmName));
        }
        return algorithmName == nameof(AesCmac) ? Create() : null;
    }

    public AesCmac()
    {
        AesEcb = Aes.Create();
        AesEcb.Mode = CipherMode.ECB;
        AesEcb.Padding = PaddingMode.None;
    }

    public override byte[] Key
    { 
        get => AesEcb.Key;
        set
        {
            ThrowIfProcessing();
            AesEcb.Key = value;
        }
    }

    public AesCmac(byte[] key)
        : this()
    {
        Key = key;
    }

    #region IDisposable
    bool IsDisposed;
    protected override void Dispose(bool disposing)
    {
        if (!IsDisposed)
        {
            if (disposing)
            {
                CryptoTransform?.Dispose();
                AesEcb.Dispose();
            }
            IsDisposed = true;
        }
        base.Dispose(disposing);
    }
    #endregion

    bool HasProcessedFinal;

    void ThrowIfDisposed()
    {
        if (IsDisposed)
        {
            throw new ObjectDisposedException(nameof(AesCtr));
        }
    }

    void ThrowIfProcessing()
    {
        if (CryptoTransform is not null)
        {
            throw new InvalidOperationException("Cannot change settings while processing.");
        }
    }

    void ThrowIfHasProcessedFinal()
    {
        if (HasProcessedFinal)
        {
            throw new InvalidOperationException("HashFinal has already been called");
        }
    }

    byte[] K1 = new byte[BLOCKSIZE];
    byte[] K2 = new byte[BLOCKSIZE];
    // See: NIST SP 800-38B, Section 6.2, Step 5
    byte[] C = new byte[BLOCKSIZE];
    readonly Aes AesEcb;
    ICryptoTransform? CryptoTransform;

    // See: NIST SP 800-38B, Section 5.3
    const int Rb = 0b10000111;

    // See: NIST SP 800-38B, Section 4.2
    static byte[] LeftShiftOne(byte[] X)
    {
        var result = new byte[X.Length];
        var carry = false;
        for (var i = X.Length - 1; i >= 0; --i)
        {
            result[i] = (byte)(X[i] << 1);
            if (carry)
            {
                result[i] |= 1;
            }
            carry = (X[i] & 0x80) != 0;
        }
        return result;
    }

    // See: NIST SP 800-38B, Section 4.2.2
    byte[] CIPH_K(byte[] X)
    {
        Debug.Assert(CryptoTransform is not null);

        var result = new byte[BLOCKSIZE];
        CryptoTransform!.TransformBlock(X, 0, BLOCKSIZE, result, 0);
        return result;
    }

    // See: NIST SP 800-38B, Section 6.1
    (byte[] K1, byte[] K2) SUBK()
    {
        // Step 1
        var L = CIPH_K(new byte[BLOCKSIZE]);
        // Step 2
        var K1 = LeftShiftOne(L);
        if ((L[0] & 0x80) != 0)
        {
            K1[15] ^= Rb;
        }
        // Step 3
        var K2 = LeftShiftOne(K1);
        if ((K1[0] & 0x80) != 0)
        {
            K2[15] ^= Rb;
        }
        // Step 4
        return (K1, K2);
    }

    public override void Initialize()
    {
        ThrowIfDisposed();
        HasProcessedFinal = false;

        // See: NIST SP 800-38B, Section 6.2, Step 5
        for (var i = 0; i < C.Length; ++i)
        {
            C[i] = 0;
        }
    }

    void EnsureProcessing()
    {
        if (CryptoTransform is null)
        {
            CryptoTransform = AesEcb.CreateEncryptor(Key, new byte[BLOCKSIZE]);

            // See: NIST SP 800-38B, Section 6.2, Step 1
            (K1, K2) = SUBK();
        }
    }

    readonly byte[] Partial = new byte[BLOCKSIZE];
    int PartialLength;

    // See: NIST SP 800-38B, Section 4.2.2
    static byte[] Xor(byte[] X, byte[] Y)
    {
        Debug.Assert(X.Length == Y.Length);

        var result = new byte[X.Length];
        for (var i = 0; i < X.Length; ++i)
        {
            result[i] = (byte)(X[i] ^ Y[i]);
        }
        return result;
    }

    // See: NIST SP 800-38B, Section 6.2, Step 6
    void AddBlock(byte[] block)
    {
        C = CIPH_K(Xor(C, block));
    }

    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
        ThrowIfDisposed();
        ThrowIfHasProcessedFinal();

        EnsureProcessing();

        switch (cbSize)
        {
            case < 0:
                throw new ArgumentOutOfRangeException(nameof(cbSize));
            case 0:
                // Nothing to do. We're not even going to check the other arguments.
                return;
            default:
                break;
        }
        if (array is null)
        {
            throw new ArgumentNullException(nameof(array));
        }
        if (ibStart < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(cbSize));
        }

        // If we have a non-empty && non-full Partial block already -> append to that first.
        if ((0 < PartialLength) && (PartialLength < BLOCKSIZE))
        {
            // We've got a non-empty && non-full Partial block already -> append to that first.
            var count = Math.Min(cbSize, BLOCKSIZE - PartialLength);
            Array.Copy(array, ibStart, Partial, PartialLength, count);
            PartialLength += count;
            if (count == cbSize)
            {
                // No more data supplied, we're done. Even if we filled up Partial completely,
                // because we don't know if it will be the final block.
                return;
            }
            ibStart += count;
            cbSize -= count;
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
        for (int i = 0, nonFinalBlockCount = (cbSize - 1) / BLOCKSIZE; i < nonFinalBlockCount; i++)
        {
            // See: NIST SP 800-38B, Section 6.2, Steps 3 and 6
            Array.Copy(array, ibStart, Partial, 0, BLOCKSIZE);
            AddBlock(Partial);
            ibStart += BLOCKSIZE;
            cbSize -= BLOCKSIZE;
        }

        // Save what we have left (we always have some, by construction).
        Array.Copy(array, ibStart, Partial, 0, cbSize);
        PartialLength = cbSize;
    }

    protected override byte[] HashFinal()
    {
        ThrowIfDisposed();
        ThrowIfHasProcessedFinal();

        EnsureProcessing();

        byte[] Mn;
        if (PartialLength == BLOCKSIZE)
        {
            Mn = Xor(K1, Partial);
        }
        else
        {
            // Add padding
            Partial[PartialLength] = 0x80;
            for (var i = PartialLength + 1; i < BLOCKSIZE; ++i)
            {
                Partial[i] = 0x00;
            }
            Mn = Xor(K2, Partial);
        }
        // See: NIST SP 800-38B, Section 6.2, Steps 4 and 6
        AddBlock(Mn);

        HasProcessedFinal = true;
        return C;
    }
}

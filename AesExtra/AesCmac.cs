﻿using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

public sealed class AesCmac
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
        CryptoTransform = AesEcb.CreateEncryptor();
        HashSizeValue = BLOCKSIZE * 8;
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
                CryptoTransform.Dispose();
                AesEcb.Dispose();
            }
            IsDisposed = true;
        }
        base.Dispose(disposing);
    }
    #endregion

    public override byte[] Key
    {
        get => AesEcb.Key;
        set
        {
            CryptoTransform.Dispose();
            AesEcb.Key = value;
            CryptoTransform = AesEcb.CreateEncryptor();
        }
    }

    readonly Aes AesEcb;
    ICryptoTransform CryptoTransform;

    // See: NIST SP 800-38B, Section 6.2, Step 5
    readonly byte[] C = new byte[BLOCKSIZE];

    // See: NIST SP 800-38B, Section 4.2
    //
    // In place: X = (X << 1)
    // Returns final carry.
    static bool LeftShiftOne_InPlace(byte[] X)
    {
        var carry = false;
        for (var i = X.Length - 1; i >= 0; --i)
        {
            var nextCarry = (X[i] & 0x80) != 0;
            X[i] <<= 1;
            if (carry)
            {
                X[i] |= 1;
            }
            carry = nextCarry;
        }
        return carry;
    }

    // See: NIST SP 800-38B, Section 4.2.2
    //
    // In-place: X = CIPH_K(X)
    void CIPH_K_InPlace(byte[] X_Base, int X_Offset = 0)
    {
        CryptoTransform.TransformBlock(X_Base, X_Offset, BLOCKSIZE, X_Base, X_Offset);
    }

    // See: NIST SP 800-38B, Section 6.1
    //
    // Returns: first ? K1 : K2
    byte[] SUBK(bool first)
    {
        // See: NIST SP 800-38B, Section 5.3
        const int Rb = 0b10000111;

        var X = new byte[BLOCKSIZE];
        // Step 1: X has the role of L
        CIPH_K_InPlace(X);
        // Step 2: X has the role of K1
        if (LeftShiftOne_InPlace(X))
        {
            X[BLOCKSIZE - 1] ^= Rb;
        }
        if (first)
        {
            // Step 4: return K1
            return X;
        }
        // Step 3: X has the role of K1
        if (LeftShiftOne_InPlace(X))
        {
            X[BLOCKSIZE - 1] ^= Rb;
        }
        // Step 4: return K2
        return X;
    }

    public override void Initialize()
    {
        // See: NIST SP 800-38B, Section 6.2, Step 5
        for (var i = 0; i < C.Length; ++i)
        {
            C[i] = 0;
        }

        PartialLength = 0;
    }

    readonly byte[] Partial = new byte[BLOCKSIZE];
    int PartialLength;

    // See: NIST SP 800-38B, Section 4.2.2
    //
    // In place: X = (X xor Y)
    static void Xor_InPlace(byte[] X, byte[] Y_Base, int Y_Offset = 0)
    {
        for (var i = 0; i < X.Length; ++i)
        {
            X[i] ^= Y_Base[Y_Offset + i];
        }
    }

    // See: NIST SP 800-38B, Section 6.2, Step 6
    void AddBlock(byte[] blockBase, int blockOffset = 0)
    {
        Xor_InPlace(C, blockBase, blockOffset);
        CIPH_K_InPlace(C);
    }

    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
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
            AddBlock(array, ibStart);
            ibStart += BLOCKSIZE;
            cbSize -= BLOCKSIZE;
        }

        // Save what we have left (we always have some, by construction).
        Array.Copy(array, ibStart, Partial, 0, cbSize);
        PartialLength = cbSize;
    }

    protected override byte[] HashFinal()
    {
        // Partial now has the role of Mn*
        if (PartialLength == BLOCKSIZE)
        {
            // See: NIST SP 800-38B, Section 6.2, Step 1: K1
            var K1 = SUBK(true);
            Xor_InPlace(Partial, K1);
            // Partial now has the role of Mn
        }
        else
        {
            // Add padding
            Partial[PartialLength] = 0x80;
            for (var i = PartialLength + 1; i < BLOCKSIZE; ++i)
            {
                Partial[i] = 0x00;
            }
            // See: NIST SP 800-38B, Section 6.2, Step 1: K2
            var K2 = SUBK(false);
            Xor_InPlace(Partial, K2);
            // Partial now has the role of Mn
        }
        // See: NIST SP 800-38B, Section 6.2, Steps 4 and 6
        AddBlock(Partial);
        PartialLength = 0;

        // NOTE: KeyedHashAlgoritm exposes the returned array reference as the
        // Hash property, so we must *not* return C itself as it may be reused.
        return (byte[])C.Clone();
    }
}

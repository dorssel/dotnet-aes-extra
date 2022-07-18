﻿using System;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

sealed class AesCtrTransform
    : ICryptoTransform
{
    const int BLOCKSIZE = 16; // bytes

    readonly ICryptoTransform AesEcbTransform;
    readonly byte[] Counter;

    internal AesCtrTransform(byte[] rgbKey, byte[]? rgbIV)
    {
        using var aes = Aes.Create();
        aes.Key = rgbKey;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        AesEcbTransform = aes.CreateEncryptor();

        Counter = rgbIV ?? new byte[BLOCKSIZE];
    }

    bool IsDisposed;

    #region IDisposable
    void IDisposable.Dispose()
    {
        if (!IsDisposed)
        {
            AesEcbTransform.Dispose();
            IsDisposed = true;
        }
    }
    #endregion

    void ThrowIfDisposed()
    {
        if (IsDisposed)
        {
            throw new ObjectDisposedException(nameof(AesCtrTransform));
        }
    }

    bool HasProcessedFinal;

    void ThrowIfProcessedFinal()
    {
        if (HasProcessedFinal)
        {
            throw new InvalidOperationException("TransformFinalBlock has already been called");
        }
    }

    void IncrementCounter()
    {
        for (var i = Counter.Length - 1; i >= 0; --i)
        {
            if (++Counter[i] != 0)
            {
                break;
            }
        }
    }

    // See: NIST SP 800-38A, Section 4.2.2
    void CIPH_K(byte[] X, byte[] output)
    {
        if (AesEcbTransform.TransformBlock(X, 0, BLOCKSIZE, output, 0) != BLOCKSIZE)
        {
            throw new CryptographicException("Unexpected failure in the underlying AES implementation.");
        }
    }

    readonly byte[] XorBlock = new byte[BLOCKSIZE];

    void TransformBlock(byte[] inputBlockBase, int inputBlockOffset, byte[] outputBlockBase, int outputBlockOffset)
    {
        CIPH_K(Counter, XorBlock);
        for (var i = 0; i < BLOCKSIZE; ++i)
        {
            outputBlockBase[outputBlockOffset + i] = (byte)(inputBlockBase[inputBlockOffset + i] ^ XorBlock[i]);
        }
        IncrementCounter();
    }

    #region ICryptoTransform
    bool ICryptoTransform.CanReuseTransform => false;

    bool ICryptoTransform.CanTransformMultipleBlocks => true;

    int ICryptoTransform.InputBlockSize => BLOCKSIZE;

    int ICryptoTransform.OutputBlockSize => BLOCKSIZE;

    int ICryptoTransform.TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        // State validation.
        ThrowIfDisposed();
        ThrowIfProcessedFinal();

        // Input validaton.
        // NOTE: All other validation is implicitly done by AsSpan().
        if (inputCount % BLOCKSIZE != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(inputCount));
        }

        for (var i = 0; i < inputCount / BLOCKSIZE; ++i)
        {
            TransformBlock(inputBuffer, inputOffset + i * BLOCKSIZE, outputBuffer, outputOffset + i * BLOCKSIZE);
        }
        return inputCount;
    }

    byte[] ICryptoTransform.TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        // State validation.
        ThrowIfDisposed();
        ThrowIfProcessedFinal();

        // Fast path.
        if (inputCount == 0)
        {
            HasProcessedFinal = true;
            return Array.Empty<byte>();
        }

        // Input validation.
        if (inputCount > BLOCKSIZE)
        {
            throw new ArgumentOutOfRangeException(nameof(inputCount));
        }

        var inputBlock = new byte[BLOCKSIZE];
        Array.Copy(inputBuffer, inputOffset, inputBlock, 0, inputCount);
        var outputBlock = new byte[BLOCKSIZE];
        TransformBlock(inputBlock, 0, outputBlock, 0);
        HasProcessedFinal = true;
        Array.Resize(ref outputBlock, inputCount);
        return outputBlock;
    }
    #endregion
}

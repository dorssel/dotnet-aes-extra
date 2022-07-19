// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

sealed class AesCtrTransform
    : ICryptoTransform
{
    const int BLOCKSIZE = AesCtr.FixedBlockSize; // bytes

    readonly ICryptoTransform AesEcbTransform;
    readonly byte[] Counter;

    static void ThrowUnexpectedAesFailure()
    {
        throw new CryptographicException("Unexpected failure in the underlying AES implementation.");
    }

    internal AesCtrTransform(byte[] initialCounter, ICryptoTransform aesEcbTransform)
    {
        AesEcbTransform = aesEcbTransform;
        if ((AesEcbTransform.InputBlockSize != BLOCKSIZE) || (AesEcbTransform.OutputBlockSize != BLOCKSIZE))
        {
            ThrowUnexpectedAesFailure();
        }

        if (initialCounter.Length != BLOCKSIZE)
        {
            throw new ArgumentException("Specified initial counter (IV) does not match the block size for this algorithm.", nameof(initialCounter));
        }
        Counter = initialCounter;
    }

    #region IDisposable
    bool IsDisposed;

    public void Dispose()
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
            ThrowUnexpectedAesFailure();
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
        // NOTE: All other validation is implicitly done by the array access itself.
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

        var block = new byte[BLOCKSIZE];
        Array.Copy(inputBuffer, inputOffset, block, 0, inputCount);
        TransformBlock(block, 0, block, 0);
        HasProcessedFinal = true;
        Array.Resize(ref block, inputCount);
        return block;
    }
    #endregion
}

// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

sealed class AesCtrTransform
    : ICryptoTransform
{
    const int BLOCKSIZE = 16;  // bytes
    const int BitsPerByte = 8;

    readonly ICryptoTransform AesEcbTransform;
    readonly byte[] Counter;

    // The key must be passed to CreateEncryptor(), which only accepts a byte[], which it will make a copy of.
    internal AesCtrTransform(byte[] key, ReadOnlySpan<byte> initialCounter)
    {
        if (initialCounter.Length != BLOCKSIZE)
        {
            throw new ArgumentException("Specified initial counter (IV) does not match the block size for this algorithm.", nameof(initialCounter));
        }

        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;  // DevSkim: ignore DS187371
        aes.BlockSize = BLOCKSIZE * BitsPerByte;
        AesEcbTransform = aes.CreateEncryptor(key, null);
        Counter = initialCounter.ToArray();
    }

    void Purge()
    {
        CryptographicOperations.ZeroMemory(XorBlock);
        CryptographicOperations.ZeroMemory(Counter);
    }

    #region IDisposable
    bool IsDisposed;

    public void Dispose()
    {
        if (!IsDisposed)
        {
            AesEcbTransform.Dispose();
            Purge();
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

    readonly byte[] XorBlock = new byte[BLOCKSIZE];

    internal void TransformBlock(ReadOnlySpan<byte> inputBlock, Span<byte> destination)
    {
        // CIPH_K(X)
        // See: NIST SP 800-38A, Section 4.2.2
        _ = AesEcbTransform.TransformBlock(Counter, 0, BLOCKSIZE, XorBlock, 0);

        for (var i = 0; i < BLOCKSIZE; ++i)
        {
            destination[i] = (byte)(inputBlock[i] ^ XorBlock[i]);
        }

        // Increment counter
        for (var i = Counter.Length - 1; i >= 0; --i)
        {
            if (unchecked(++Counter[i]) != 0)
            {
                break;
            }
        }
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

        // Input validation.
        // NOTE: All other validation is implicitly done by the array access itself.
        if (inputCount % BLOCKSIZE != 0)
        {
            throw new ArgumentException("Input must be a multiple of the block size.", nameof(inputCount));
        }

        for (var i = 0; i < inputCount / BLOCKSIZE; ++i)
        {
            TransformBlock(inputBuffer.AsSpan(inputOffset + (i * BLOCKSIZE), BLOCKSIZE), outputBuffer.AsSpan(outputOffset + (i * BLOCKSIZE)));
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
            return [];
        }

        // Input validation.
        if (inputCount > BLOCKSIZE)
        {
            throw new ArgumentOutOfRangeException(nameof(inputCount));
        }

        var block = new byte[BLOCKSIZE];
        Array.Copy(inputBuffer, inputOffset, block, 0, inputCount);
        TransformBlock(block, block);
        Array.Resize(ref block, inputCount);
        HasProcessedFinal = true;

        Purge();

        return block;
    }
    #endregion
}

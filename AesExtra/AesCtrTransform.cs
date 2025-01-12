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

    // RFC 5297, Section 2.6 and 2.7
    //
    // Q = V bitand (1^64 || 0^1 || 1^31 || 0^1 || 1^31)
    internal void ResetSivCounter(ReadOnlySpan<byte> V)
    {
        V.CopyTo(Counter);
        Counter[8] &= 0x7f;
        Counter[12] &= 0x7f;
    }

    #region IDisposable
    bool IsDisposed;

    public void Dispose()
    {
        if (!IsDisposed)
        {
            AesEcbTransform.Dispose();
            CryptographicOperations.ZeroMemory(XorBlock);
            CryptographicOperations.ZeroMemory(Counter);
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

    void UncheckedTransformSingleBlock(ReadOnlySpan<byte> inputBlock, Span<byte> destination)
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

    internal void UncheckedTransform(ReadOnlySpan<byte> input, Span<byte> destination)
    {
        var inputSlice = input;
        var destinationSlice = destination;
        while (inputSlice.Length >= BLOCKSIZE)
        {
            // full blocks
            UncheckedTransformSingleBlock(inputSlice, destinationSlice);
            inputSlice = inputSlice[BLOCKSIZE..];
            destinationSlice = destinationSlice[BLOCKSIZE..];
        }
        if (!inputSlice.IsEmpty)
        {
            // final partial block (if any)
            Span<byte> block = stackalloc byte[BLOCKSIZE];
            inputSlice.CopyTo(block);
            UncheckedTransformSingleBlock(block, block);
            block[0..inputSlice.Length].CopyTo(destinationSlice);
            CryptographicOperations.ZeroMemory(block);
        }
    }

    #region ICryptoTransform
    bool ICryptoTransform.CanReuseTransform => false;

    bool ICryptoTransform.CanTransformMultipleBlocks => true;

    int ICryptoTransform.InputBlockSize => BLOCKSIZE;

    int ICryptoTransform.OutputBlockSize => BLOCKSIZE;

    int ICryptoTransform.TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        // Input validation
        if (inputBuffer is null)
        {
            throw new ArgumentNullException(nameof(inputBuffer));
        }
        if (inputOffset < 0 || inputOffset > inputBuffer.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(inputOffset));
        }
        if (inputCount < 0 || inputCount > (inputBuffer.Length - inputOffset))
        {
            throw new ArgumentOutOfRangeException(nameof(inputCount));
        }
        if (inputCount % BLOCKSIZE != 0)
        {
            throw new ArgumentException("TransformBlock may only process bytes in block sized increments.", nameof(inputCount));
        }
        if (outputBuffer is null)
        {
            throw new ArgumentNullException(nameof(outputBuffer));
        }
        if (outputOffset < 0 || outputOffset > outputBuffer.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(outputOffset));
        }
        if (outputBuffer.Length - outputOffset < inputCount)
        {
            throw new ArgumentException("Output buffer is too small.", nameof(outputBuffer));
        }

        // State validation.
        ThrowIfDisposed();
        ThrowIfProcessedFinal();

        UncheckedTransform(inputBuffer.AsSpan(inputOffset, inputCount), outputBuffer.AsSpan(outputOffset));
        return inputCount;
    }

    byte[] ICryptoTransform.TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        // Input validation
        if (inputBuffer is null)
        {
            throw new ArgumentNullException(nameof(inputBuffer));
        }
        if (inputOffset < 0 || inputOffset > inputBuffer.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(inputOffset));
        }
        if (inputCount < 0 || inputCount > (inputBuffer.Length - inputOffset))
        {
            throw new ArgumentOutOfRangeException(nameof(inputCount));
        }

        // State validation.
        ThrowIfDisposed();
        ThrowIfProcessedFinal();

        // Fast path.
        if (inputCount == 0)
        {
            HasProcessedFinal = true;
            return [];
        }

        var output = new byte[inputCount];
        UncheckedTransform(inputBuffer.AsSpan(inputOffset, inputCount), output);
        HasProcessedFinal = true;
        return output;
    }
    #endregion
}

// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
// SPDX-FileCopyrightText: .NET Foundation
//
// SPDX-License-Identifier: MIT

using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

/// <summary>
/// Computes a Cipher-based Message Authentication Code (CMAC) by using the symmetric key AES block cipher.
/// </summary>
/// <seealso href="https://csrc.nist.gov/publications/detail/sp/800-38b/final"/>
/// <seealso href="https://www.rfc-editor.org/rfc/rfc4493.html"/>
public sealed class AesCmac
    : KeyedHashAlgorithm
{
    const int BLOCKSIZE = 16; // bytes
    const int BitsPerByte = 8;

    #region CryptoConfig
    static readonly object RegistrationLock = new();
    static bool TriedRegisterOnce;

    /// <summary>
    /// Registers the <see cref="AesCmac"/> class with <see cref="CryptoConfig"/>, such that it can be created by name.
    /// </summary>
    /// <seealso cref="CryptoConfig.CreateFromName(string)"/>
    /// <remarks>
    /// <see cref="CryptoConfig"/> is not supported in browsers.
    /// </remarks>
#if !NETSTANDARD2_0
    [UnsupportedOSPlatform("browser")]
#endif
    public static void RegisterWithCryptoConfig()
    {
        lock (RegistrationLock)
        {
            if (!TriedRegisterOnce)
            {
                TriedRegisterOnce = true;
                CryptoConfig.AddAlgorithm(typeof(AesCmac), nameof(AesCmac), typeof(AesCmac).FullName!);
            }
        }
    }

    /// <inheritdoc cref="KeyedHashAlgorithm.Create()" path="/summary" />
    /// <returns>A new <see cref="AesCmac" /> instance.</returns>
    [Obsolete("Use one of the constructors instead.")]
    public static new AesCmac Create()
    {
        return new AesCmac();
    }

    /// <inheritdoc cref="KeyedHashAlgorithm.Create(string)" />
    [Obsolete("Cryptographic factory methods accepting an algorithm name are obsolete. Use the parameterless Create factory method on the algorithm type instead.")]
#if !NETSTANDARD2_0
    [RequiresUnreferencedCode("The default algorithm implementations might be removed, use strong type references like 'RSA.Create()' instead.")]
#endif
    public static new AesCmac? Create(string algorithmName)
    {
        if (algorithmName is null)
        {
            throw new ArgumentNullException(nameof(algorithmName));
        }
        // Our class is sealed, so there definitely is no other implementation.
        return algorithmName == nameof(AesCmac) || algorithmName == typeof(AesCmac).FullName! ? new AesCmac() : null;
    }
    #endregion

    /// <exception cref="CryptographicException"><paramref name="keySize"/> is other than 128, 192, or 256 bits.</exception>
    static void ThrowIfInvalidKeySize(int keySize)
    {
        if (keySize is not (128 or 192 or 256))
        {
            throw new CryptographicException("Specified key size is valid for this algorithm.");
        }
    }

    /// <exception cref="CryptographicException">The <paramref name="key"/> length is other than 16, 24, or 32 bytes (128, 192, or 256 bits).</exception>
    static void ThrowIfInvalidKey(ReadOnlySpan<byte> key)
    {
        if (key.Length is not (16 or 24 or 32))
        {
            throw new CryptographicException("Specified key is not a valid size for this algorithm.");
        }
    }

    /// <exception cref="ArgumentNullException"><paramref name="key"/> is <see langword="null"/>.</exception>
    /// <inheritdoc cref="ThrowIfInvalidKey(ReadOnlySpan{byte})"/>
    static void ThrowIfInvalidKey(byte[] key)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }
        ThrowIfInvalidKey(key.AsSpan());
    }

    void InitializeFixedValues()
    {
        HashSizeValue = BLOCKSIZE * 8;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AesCmac" /> class with a randomly generated 256-bit key.
    /// </summary>
    public AesCmac()
        : this(256)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AesCmac" /> class with a randomly generated key.
    /// </summary>
    /// <param name="keySize">The size, in bits, of the randomly generated key.</param>
    /// <inheritdoc cref="ThrowIfInvalidKeySize(int)"/>
    public AesCmac(int keySize)
    {
        ThrowIfInvalidKeySize(keySize);

        InitializeFixedValues();

        KeyValue = new byte[keySize / BitsPerByte];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(KeyValue);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AesCmac" /> class with the specified key data.
    /// </summary>
    /// <param name="key">The secret key for AES-CMAC algorithm.</param>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is <see langword="null"/>.</exception>
    /// <inheritdoc cref="AesCmac(ReadOnlySpan{byte})" path="/exception"/>
    public AesCmac(byte[] key)
        : this(new ReadOnlySpan<byte>(key ?? throw new ArgumentNullException(nameof(key))))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AesCmac" /> class with the specified key data.
    /// </summary>
    /// <param name="key">The secret key for AES-CMAC algorithm.</param>
    /// <inheritdoc cref="ThrowIfInvalidKey(ReadOnlySpan{byte})"/>
    public AesCmac(ReadOnlySpan<byte> key)
    {
        ThrowIfInvalidKey(key);

        InitializeFixedValues();

        KeyValue = key.ToArray();
    }

    #region IDisposable
    bool IsDisposed;

    /// <inheritdoc cref="KeyedHashAlgorithm.Dispose(bool)" />
    protected override void Dispose(bool disposing)
    {
        if (IsDisposed)
        {
            return;
        }

        if (disposing)
        {
            AesEcbTransformValue?.Dispose();
        }

        CryptographicOperations.ZeroMemory(KeyValue);
        CryptographicOperations.ZeroMemory(K1Value);
        CryptographicOperations.ZeroMemory(K2Value);
        CryptographicOperations.ZeroMemory(C);
        CryptographicOperations.ZeroMemory(Partial);
        K1Value = null;
        K2Value = null;
        PartialLength = 0;
        State = 0;
        AesEcbTransformValue = null;
        IsDisposed = true;

        base.Dispose(disposing);
    }
    #endregion

    /// <exception cref="ObjectDisposedException">The <see cref="AesCmac"/> instance has been disposed.</exception>
    void ThrowIfDisposed()
    {
        if (IsDisposed)
        {
            throw new ObjectDisposedException(nameof(AesCmac));
        }
    }

    /// <inheritdoc />
    /// <inheritdoc cref="ThrowIfInvalidKey(byte[])"/>
    /// <inheritdoc cref="ThrowIfDisposed"/>
    /// <exception cref="InvalidOperationException">An attempt was made to change the <see cref="Key"/> during a computation.</exception>
    public override byte[] Key
    {
        get
        {
            ThrowIfDisposed();

            return (byte[])KeyValue.Clone();
        }
        set
        {
            // Input validation

            ThrowIfInvalidKey(value);

            // State validation

            ThrowIfDisposed();

            if (State != 0)
            {
                throw new InvalidOperationException("Key cannot be changed during a computation.");
            }

            // Side effects

            CryptographicOperations.ZeroMemory(KeyValue);
            CryptographicOperations.ZeroMemory(K1Value);
            CryptographicOperations.ZeroMemory(K2Value);
            AesEcbTransformValue?.Dispose();
            AesEcbTransformValue = null;
            K1Value = null;
            K2Value = null;

            KeyValue = (byte[])value.Clone();
        }
    }

    ICryptoTransform? AesEcbTransformValue;

    ICryptoTransform AesEcbTransform
    {
        get
        {
            if (AesEcbTransformValue is null)
            {
                using var aes = Aes.Create();
                aes.Mode = CipherMode.ECB;  // DevSkim: ignore DS187371
                aes.BlockSize = BLOCKSIZE * BitsPerByte;
                AesEcbTransformValue = aes.CreateEncryptor(KeyValue, null);
            }
            return AesEcbTransformValue;
        }
    }

    // See: NIST SP 800-38B, Section 6.2, Step 5
    readonly byte[] C = new byte[BLOCKSIZE];

    byte[]? K1Value;
    byte[]? K2Value;

    // See: NIST SP 800-38B, Section 6.1
    byte[] K1 {
        get
        {
            if (K1Value is null)
            {
                // Step 1: K1Value has the role of L
                K1Value = new byte[BLOCKSIZE];
                CIPH_K_InPlace(K1Value);
                // Step 2: K1Value has the role of K1
                K1Value.AsSpan().dbl_InPlace();
            }
            // Step 4: return K1
            return K1Value;
        }
    }

    // See: NIST SP 800-38B, Section 6.1
    byte[] K2
    {
        get
        {
            if (K2Value is null)
            {
                // Step 3: K2Value has the role of K1
                K2Value = (byte[])K1.Clone();
                K2Value.AsSpan().dbl_InPlace();
            }
            // Step 4: return K2
            return K2Value;
        }
    }

    // See: NIST SP 800-38B, Section 4.2.2
    //
    // In-place: X = CIPH_K(X)
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    void CIPH_K_InPlace(byte[] X)
    {
        _ = AesEcbTransform.TransformBlock(X, 0, BLOCKSIZE, X, 0);
    }

    /// <inheritdoc cref="HashAlgorithm.Initialize" />
    /// <inheritdoc cref="ThrowIfDisposed"/>
    public override void Initialize()
    {
        ThrowIfDisposed();

        // See: NIST SP 800-38B, Section 6.2, Step 5
        C.AsSpan().Clear();
        PartialLength = 0;
        State = 0;
    }

    readonly byte[] Partial = new byte[BLOCKSIZE];
    int PartialLength;

    // See: NIST SP 800-38B, Section 6.2, Step 6
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    void AddBlock(ReadOnlySpan<byte> block)
    {
        C.AsSpan().xor_InPlace(block);
        CIPH_K_InPlace(C);
    }

    /// <inheritdoc />
    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
        // This is only called by HashAlgorithm, which is known to behave well.
        // We skip input validation for performance reasons; there is no unsafe code.

        UncheckedHashCore(array.AsSpan(ibStart, cbSize));
    }

    /// <inheritdoc/>
#if !NETSTANDARD2_0
    protected override
#endif
    void HashCore(ReadOnlySpan<byte> source)
    {
        // This is only called by HashAlgorithm, which is known to behave well.
        // We skip input validation for performance reasons; there is no unsafe code.

        UncheckedHashCore(source);
    }

    internal void UncheckedHashCore(ReadOnlySpan<byte> source)
    {
        if (source.Length == 0)
        {
            return;
        }

        // If we have a non-empty && non-full Partial block already -> append to that first.
        if (PartialLength is > 0 and < BLOCKSIZE)
        {
            var count = Math.Min(source.Length, BLOCKSIZE - PartialLength);
            source[..count].CopyTo(Partial.AsSpan(PartialLength));
            PartialLength += count;
            if (count == source.Length)
            {
                // No more data supplied, we're done. Even if we filled up Partial completely,
                // because we don't know if it will be the final block.
                return;
            }
            source = source[count..];
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
        for (int i = 0, nonFinalBlockCount = (source.Length - 1) / BLOCKSIZE; i < nonFinalBlockCount; i++)
        {
            // See: NIST SP 800-38B, Section 6.2, Steps 3 and 6
            AddBlock(source[..BLOCKSIZE]);
            source = source[BLOCKSIZE..];
        }

        // Save what we have left (we always have some, by construction).
        source.CopyTo(Partial);
        PartialLength = source.Length;
    }

    /// <inheritdoc cref="HashAlgorithm.HashFinal" />
    protected override byte[] HashFinal()
    {
        var destination = new byte[BLOCKSIZE];
        UncheckedHashFinal(destination);
        return destination;
    }

    /// <inheritdoc/>
#if !NETSTANDARD2_0
    protected override
#endif
    bool TryHashFinal(Span<byte> destination, out int bytesWritten)
    {
        // This is only called by HashAlgorithm, which promises to never call us with a destination that is too short.
        // We skip input validation for performance reasons; there is no unsafe code.

        UncheckedHashFinal(destination);
        bytesWritten = BLOCKSIZE;
        return true;
    }

    internal void UncheckedHashFinal(Span<byte> destination)
    {
        // See: NIST SP 800-38B, Section 6.2, Step 4
        // Partial now has the role of Mn*
        if (PartialLength == BLOCKSIZE)
        {
            // See: NIST SP 800-38B, Section 6.2, Step 1: K1
            Partial.AsSpan().xor_InPlace(K1);
            // Partial now has the role of Mn
        }
        else
        {
            // Add padding
            Partial[PartialLength] = 0x80;
            Partial.AsSpan(PartialLength + 1).Clear();
            // See: NIST SP 800-38B, Section 6.2, Step 1: K2
            Partial.AsSpan().xor_InPlace(K2);
            // Partial now has the role of Mn
        }
        // See: NIST SP 800-38B, Section 6.2, Step 6
        AddBlock(Partial);

        C.CopyTo(destination);
    }

    #region Modern_KeyedHashAlgorithm
    // Helper with a byte[] as key, which is required since we need to pass it as such.
    static void UncheckedOneShot(byte[] key, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        using var cmac = new AesCmac(key);
        cmac.UncheckedHashCore(source);
        cmac.UncheckedHashFinal(destination);
    }

    // Helper with a byte[] as key, which is required since we need to pass it as such.
    // see https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/LiteHashProvider.cs
    static void UncheckedOneShot(byte[] key, Stream source, Span<byte> destination)
    {
        using var cmac = new AesCmac(key);
        var maxRead = 0;
        int read;
        var rented = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            while ((read = source.Read(rented, 0, 4096)) > 0)
            {
                maxRead = Math.Max(maxRead, read);
                cmac.UncheckedHashCore(rented.AsSpan(0, read));
            }
            cmac.UncheckedHashFinal(destination);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rented.AsSpan(0, maxRead));
            ArrayPool<byte>.Shared.Return(rented, false);
        }
    }

    // Helper with a byte[] as key, which is required since we need to pass it as such.
    // see https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/LiteHashProvider.cs
    static async ValueTask UncheckedOneShotAsync(byte[] key, Stream source, Memory<byte> destination, CancellationToken cancellationToken)
    {
        using var cmac = new AesCmac(key);
        var maxRead = 0;
        int read;
        var rented = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            while ((read = await source.ReadAsync(rented, 0, 4096, cancellationToken).ConfigureAwait(false)) > 0)
            {
                maxRead = Math.Max(maxRead, read);
                cmac.UncheckedHashCore(rented.AsSpan(0, read));
            }
            cmac.UncheckedHashFinal(destination.Span);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rented.AsSpan(0, maxRead));
            ArrayPool<byte>.Shared.Return(rented, false);
        }
    }

    /// <exception cref="ArgumentNullException"><paramref name="source"/> is <see langword="null"/>.</exception>
    static void ThrowIfInvalidSource(byte[] source)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }
    }

    /// <exception cref="ArgumentNullException"><paramref name="source"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="source"/> does not support reading.</exception>
    static void ThrowIfInvalidSource(Stream source)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }
        if (!source.CanRead)
        {
            throw new ArgumentException("Source does not support reading.", nameof(source));
        }
    }

    /// <exception cref="ArgumentException">
    /// The buffer in <paramref name="destination"/> is too small to hold the calculated CMAC.
    /// The AES-CMAC algorithm always produces a 128-bit CMAC, or 16 bytes.
    /// </exception>
    static void ThrowIfInvalidDestination(Span<byte> destination)
    {
        if (destination.Length < BLOCKSIZE)
        {
            throw new ArgumentException("Destination is too short.", nameof(destination));
        }
    }

    /// <summary>
    /// Attempts to compute the CMAC of data using the AES-CMAC algorithm.
    /// </summary>
    /// <param name="key">The CMAC key.</param>
    /// <param name="source">The data to CMAC.</param>
    /// <param name="destination">The buffer to receive the CMAC value.</param>
    /// <param name="bytesWritten">When this method returns, the total number of bytes written into <paramref name="destination"/>.</param>
    /// <returns>
    /// <see langword="true"/> if <paramref name="destination"/> was large enough to receive the calculated CMAC; otherwise, <see langword="false"/>.
    /// </returns>
    /// <inheritdoc cref="ThrowIfInvalidKey(ReadOnlySpan{byte})"/>
    public static bool TryHashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten)
    {
        ThrowIfInvalidKey(key);

        if (destination.Length < BLOCKSIZE)
        {
            bytesWritten = 0;
            return false;
        }

        using var keyCopy = new SecureByteArray(key);
        UncheckedOneShot(keyCopy, source, destination);
        bytesWritten = BLOCKSIZE;
        return true;
    }

    /// <summary>
    /// Computes the CMAC of data using the AES-CMAC algorithm.
    /// </summary>
    /// <param name="key">The CMAC key.</param>
    /// <param name="source">The data to CMAC.</param>
    /// <returns>The CMAC of the data.</returns>
    /// <inheritdoc cref="ThrowIfInvalidKey(byte[])"/>
    /// <inheritdoc cref="ThrowIfInvalidSource(byte[])"/>
    public static byte[] HashData(byte[] key, byte[] source)
    {
        ThrowIfInvalidKey(key);
        ThrowIfInvalidSource(source);

        var destination = new byte[BLOCKSIZE];
        UncheckedOneShot(key, source, destination);
        return destination;
    }

    /// <summary>
    /// Computes the CMAC of data using the AES-CMAC algorithm.
    /// </summary>
    /// <param name="key">The CMAC key.</param>
    /// <param name="source">The data to CMAC.</param>
    /// <returns>The CMAC of the data.</returns>
    /// <inheritdoc cref="ThrowIfInvalidKey(ReadOnlySpan{byte})"/>
    public static byte[] HashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source)
    {
        ThrowIfInvalidKey(key);

        using var keyCopy = new SecureByteArray(key);
        var destination = new byte[BLOCKSIZE];
        UncheckedOneShot(keyCopy, source, destination);
        return destination;
    }

    /// <summary>
    /// Computes the CMAC of data using the AES-CMAC algorithm.
    /// </summary>
    /// <param name="key">The CMAC key.</param>
    /// <param name="source">The data to CMAC.</param>
    /// <param name="destination">The buffer to receive the CMAC value.</param>
    /// <returns>The total number of bytes written to <paramref name="destination"/>.</returns>
    /// <inheritdoc cref="ThrowIfInvalidKey(ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfInvalidDestination(Span{byte})"/>
    public static int HashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        ThrowIfInvalidKey(key);
        ThrowIfInvalidDestination(destination);

        using var keyCopy = new SecureByteArray(key);
        UncheckedOneShot(keyCopy, source, destination);
        return BLOCKSIZE;
    }

    /// <summary>
    /// Computes the CMAC of a stream using the AES-CMAC algorithm.
    /// </summary>
    /// <param name="key">The CMAC key.</param>
    /// <param name="source">The stream to CMAC.</param>
    /// <returns>The CMAC of the data.</returns>
    /// <inheritdoc cref="ThrowIfInvalidKey(byte[])"/>
    /// <inheritdoc cref="ThrowIfInvalidSource(Stream)"/>
    public static byte[] HashData(byte[] key, Stream source)
    {
        ThrowIfInvalidKey(key);
        ThrowIfInvalidSource(source);

        var destination = new byte[BLOCKSIZE];
        UncheckedOneShot(key, source, destination);
        return destination;
    }

    /// <summary>
    /// Computes the CMAC of a stream using the AES-CMAC algorithm.
    /// </summary>
    /// <param name="key">The CMAC key.</param>
    /// <param name="source">The stream to CMAC.</param>
    /// <returns>The CMAC of the data.</returns>
    /// <inheritdoc cref="ThrowIfInvalidKey(ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfInvalidSource(Stream)"/>
    public static byte[] HashData(ReadOnlySpan<byte> key, Stream source)
    {
        ThrowIfInvalidKey(key);
        ThrowIfInvalidSource(source);

        using var keyCopy = new SecureByteArray(key);
        var destination = new byte[BLOCKSIZE];
        UncheckedOneShot(keyCopy, source, destination);
        return destination;
    }

    /// <summary>
    /// Computes the CMAC of a stream using the AES-CMAC algorithm.
    /// </summary>
    /// <param name="key">The CMAC key.</param>
    /// <param name="source">The stream to CMAC.</param>
    /// <param name="destination">The buffer to receive the CMAC value.</param>
    /// <returns>The total number of bytes written to <paramref name="destination"/>.</returns>
    /// <inheritdoc cref="ThrowIfInvalidKey(ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfInvalidSource(Stream)"/>
    /// <inheritdoc cref="ThrowIfInvalidDestination(Span{byte})"/>
    public static int HashData(ReadOnlySpan<byte> key, Stream source, Span<byte> destination)
    {
        ThrowIfInvalidKey(key);
        ThrowIfInvalidSource(source);
        ThrowIfInvalidDestination(destination);

        using var keyCopy = new SecureByteArray(key);
        UncheckedOneShot(keyCopy, source, destination);
        return BLOCKSIZE;
    }

    /// <summary>
    /// Asynchronously computes the CMAC of a stream using the AES-CMAC algorithm.
    /// </summary>
    /// <param name="key">The CMAC key.</param>
    /// <param name="source">The stream to CMAC.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <see cref="CancellationToken.None"/>.</param>
    /// <returns>The HMAC of the data.</returns>
    /// <inheritdoc cref="ThrowIfInvalidKey(byte[])"/>
    /// <inheritdoc cref="ThrowIfInvalidSource(Stream)"/>
    /// <exception cref="OperationCanceledException">The cancellation token was canceled. This exception is stored into the returned task.</exception>
    /// <remarks>
    /// This method stores in the task it returns all non-usage exceptions that the method's synchronous counterpart can throw.
    /// If an exception is stored into the returned task, that exception will be thrown when the task is awaited.
    /// Usage exceptions, such as <see cref="ArgumentException"/>, are still thrown synchronously.
    /// For the stored exceptions, see the exceptions thrown by <see cref="HashData(byte[], Stream)"/>.
    /// </remarks>
    public static async ValueTask<byte[]> HashDataAsync(byte[] key, Stream source, CancellationToken cancellationToken = default)
    {
        ThrowIfInvalidKey(key);
        ThrowIfInvalidSource(source);

        var destination = new byte[BLOCKSIZE];
        await UncheckedOneShotAsync(key, source, destination, cancellationToken).ConfigureAwait(false);
        return destination;
    }

    /// <summary>
    /// Asynchronously computes the CMAC of a stream using the AES-CMAC algorithm.
    /// </summary>
    /// <param name="key">The CMAC key.</param>
    /// <param name="source">The stream to CMAC.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <see cref="CancellationToken.None"/>.</param>
    /// <returns>The HMAC of the data.</returns>
    /// <inheritdoc cref="ThrowIfInvalidKey(ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfInvalidSource(Stream)"/>
    /// <exception cref="OperationCanceledException">The cancellation token was canceled. This exception is stored into the returned task.</exception>
    /// <remarks>
    /// This method stores in the task it returns all non-usage exceptions that the method's synchronous counterpart can throw.
    /// If an exception is stored into the returned task, that exception will be thrown when the task is awaited.
    /// Usage exceptions, such as <see cref="ArgumentException"/>, are still thrown synchronously.
    /// For the stored exceptions, see the exceptions thrown by <see cref="HashData(ReadOnlySpan{byte}, Stream)"/>.
    /// </remarks>
    public static async ValueTask<byte[]> HashDataAsync(ReadOnlyMemory<byte> key, Stream source, CancellationToken cancellationToken = default)
    {
        ThrowIfInvalidKey(key.Span);
        ThrowIfInvalidSource(source);

        using var keyCopy = new SecureByteArray(key);
        var destination = new byte[BLOCKSIZE];
        await UncheckedOneShotAsync(keyCopy, source, destination, cancellationToken).ConfigureAwait(false);
        return destination;
    }

    /// <summary>
    /// Asynchronously computes the CMAC of a stream using the AES-CMAC algorithm.
    /// </summary>
    /// <param name="key">The CMAC key.</param>
    /// <param name="source">The stream to CMAC.</param>
    /// <param name="destination">The buffer to receive the CMAC value.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <see cref="CancellationToken.None"/>.</param>
    /// <returns>The total number of bytes written to <paramref name="destination"/>.</returns>
    /// <inheritdoc cref="ThrowIfInvalidKey(ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfInvalidSource(Stream)"/>
    /// <inheritdoc cref="ThrowIfInvalidDestination(Span{byte})"/>
    /// <exception cref="OperationCanceledException">The cancellation token was canceled. This exception is stored into the returned task.</exception>
    /// <remarks>
    /// This method stores in the task it returns all non-usage exceptions that the method's synchronous counterpart can throw.
    /// If an exception is stored into the returned task, that exception will be thrown when the task is awaited.
    /// Usage exceptions, such as <see cref="ArgumentException"/>, are still thrown synchronously.
    /// For the stored exceptions, see the exceptions thrown by <see cref="HashData(ReadOnlySpan{byte}, ReadOnlySpan{byte}, Span{byte})"/>.
    /// </remarks>
    public static async ValueTask<int> HashDataAsync(ReadOnlyMemory<byte> key, Stream source, Memory<byte> destination,
        CancellationToken cancellationToken = default)
    {
        ThrowIfInvalidKey(key.Span);
        ThrowIfInvalidSource(source);
        ThrowIfInvalidDestination(destination.Span);

        using var keyCopy = new SecureByteArray(key);
        await UncheckedOneShotAsync(keyCopy, source, destination, cancellationToken).ConfigureAwait(false);
        return BLOCKSIZE;
    }
#endregion
}

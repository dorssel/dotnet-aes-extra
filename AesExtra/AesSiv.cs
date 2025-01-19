// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

/// <summary>
/// Represents an Advanced Encryption Standard (AES) key to be used with the Synthetic Initialization Vector (SIV) mode of operation.
/// </summary>
/// <seealso href="https://www.rfc-editor.org/rfc/rfc5297.html"/>
public sealed class AesSiv
    : IDisposable
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AesSiv"/> class with a provided key.
    /// </summary>
    /// <param name="key">The secret key to use for this instance.</param>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is <see langword="null"/>.</exception>
    public AesSiv(byte[] key)
        : this(new ReadOnlySpan<byte>(key ?? throw new ArgumentNullException(nameof(key))))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AesSiv"/> class with a provided key.
    /// </summary>
    /// <param name="key">The secret key to use for this instance.</param>
    public AesSiv(ReadOnlySpan<byte> key)
    {
        if (key.Length is not (32 or 48 or 64))
        {
            throw new CryptographicException("Specified key is not a valid size for this algorithm.");
        }

        using var cmacKey = new SecureByteArray(key[..(key.Length / 2)]);
        using var ctrKey = new SecureByteArray(key[(key.Length / 2)..]);
        Cmac = new(cmacKey);
        Ctr = new(ctrKey, new byte[BLOCKSIZE]);
    }

    const int BLOCKSIZE = 16; // bytes
    // See: RFC 5297, Section 7
    const int MaximumAssociatedDataCount = 126;

    readonly AesCmac Cmac;
    readonly AesCtrTransform Ctr;

    #region IDisposable
    bool IsDisposed;

    /// <inheritdoc cref="IDisposable.Dispose()" />
    public void Dispose()
    {
        if (!IsDisposed)
        {
            Cmac.Dispose();
            Ctr.Dispose();
            CryptographicOperations.ZeroMemory(InitialD);
            InitialD = null;
            IsDisposed = true;
        }
    }
    #endregion

    /// <exception cref="ObjectDisposedException">The <see cref="AesSiv"/> instance has been disposed.</exception>
    void ThrowIfDisposed()
    {
        if (IsDisposed)
        {
            throw new ObjectDisposedException(nameof(AesCtrTransform));
        }
    }

    byte[]? InitialD;

    // See: RFC 5297, Section 2.4
    void S2V_Init(Span<byte> V)
    {
        // V starts out with the role of D
        if (InitialD is null)
        {
            // we cache this value
            InitialD = new byte[BLOCKSIZE];
            Cmac.Initialize();
            Cmac.UncheckedHashCore(InitialD);
            Cmac.UncheckedHashFinal(InitialD);
        }
        InitialD.CopyTo(V);
    }

    // See: RFC 5297, Section 2.4
    void S2V_AddAssociatedDataItem(ReadOnlySpan<byte> associatedDataItem, Span<byte> V)
    {
        // associatedDataItem === Si
        // V still has the role of D
        V.dbl_InPlace();
        Span<byte> mac = stackalloc byte[BLOCKSIZE];
        Cmac.Initialize();
        Cmac.UncheckedHashCore(associatedDataItem);
        Cmac.UncheckedHashFinal(mac);
        V.xor_InPlace(mac);
    }

    // See: RFC 5297, Section 2.4
    void S2V_Final(ReadOnlySpan<byte> plaintext, Span<byte> V)
    {
        // plaintext === Sn
        // V still has the role of D
        Cmac.Initialize();
        if (plaintext.Length >= BLOCKSIZE)
        {
            // V takes the role of the "end" in "xorend"
            V.xor_InPlace(plaintext[(plaintext.Length - BLOCKSIZE)..]);
            Cmac.UncheckedHashCore(plaintext[0..(plaintext.Length - BLOCKSIZE)]);
        }
        else
        {
            V.dbl_InPlace();
            // This implements pad() as well.
            V[..plaintext.Length].xor_InPlace(plaintext);
            V[plaintext.Length] ^= 0x80;
        }
        Cmac.UncheckedHashCore(V);
        Cmac.UncheckedHashFinal(V);
        // V is now final
    }

    /// <exception cref="ArgumentNullException"><paramref name="plaintext"/> is <see langword="null"/>.</exception>
    static void ThrowIfInvalidPlaintext(byte[] plaintext)
    {
        if (plaintext is null)
        {
            throw new ArgumentNullException(nameof(plaintext));
        }
    }

    /// <exception cref="ArgumentException"><paramref name="plaintext"/> is not exactly one block smaller than <paramref name="ciphertext"/>.</exception>
    static void ThrowIfInvalidPlaintext(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        if (plaintext.Length != ciphertext.Length - BLOCKSIZE)
        {
            throw new ArgumentException("Plaintext must be exactly one block smaller than ciphertext.", nameof(plaintext));
        }
    }

    /// <exception cref="ArgumentNullException"><paramref name="ciphertext"/> is <see langword="null"/>.</exception>
    /// <inheritdoc cref="ThrowIfInvalidCiphertext(ReadOnlySpan{byte})"/>
    static void ThrowIfInvalidCiphertext(byte[] ciphertext)
    {
        if (ciphertext is null)
        {
            throw new ArgumentNullException(nameof(ciphertext));
        }
        ThrowIfInvalidCiphertext(ciphertext.AsSpan());
    }

    /// <exception cref="ArgumentException"><paramref name="ciphertext"/> is too short.</exception>
    static void ThrowIfInvalidCiphertext(ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length < BLOCKSIZE)
        {
            throw new ArgumentException("Ciphertext is too short.", nameof(ciphertext));
        }
    }

    /// <exception cref="ArgumentException"><paramref name="ciphertext"/> is not exactly one block larger than <paramref name="plaintext"/>.</exception>
    static void ThrowIfInvalidCiphertext(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext)
    {
        if (ciphertext.Length < BLOCKSIZE || (ciphertext.Length - BLOCKSIZE) != plaintext.Length)
        {
            throw new ArgumentException("Ciphertext must be exactly one block larger than plaintext.", nameof(ciphertext));
        }
    }

    /// <exception cref="ArgumentNullException"><paramref name="associatedData"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="associatedData"/> has too many items.
    ///
    /// -or-
    ///
    /// <paramref name="associatedData"/> contains an item that is <see langword="null"/>.
    /// </exception>
    static void ThrowIfInvalidAssociatedData(byte[][] associatedData)
    {
        if (associatedData is null)
        {
            throw new ArgumentNullException(nameof(associatedData));
        }
        if (associatedData.Length > MaximumAssociatedDataCount)
        {
            throw new ArgumentException("Too many associated data items.", nameof(associatedData));
        }
        foreach (var associatedDataItem in associatedData)
        {
            if (associatedDataItem is null)
            {
                throw new ArgumentException("Associated data items must not be null.", nameof(associatedData));
            }
        }
    }

    /// <exception cref="ArgumentException"><paramref name="associatedData"/> has too many items.</exception>
    static void ThrowIfInvalidAssociatedData(ReadOnlySpan<ReadOnlyMemory<byte>> associatedData)
    {
        if (associatedData.Length > MaximumAssociatedDataCount)
        {
            throw new ArgumentException("Too many associated data items.", nameof(associatedData));
        }
    }

    /// <summary>
    /// Encrypts the plaintext into the ciphertext destination buffer, prepending the synthetic IV.
    /// </summary>
    /// <param name="plaintext">The content to encrypt.</param>
    /// <param name="ciphertext">The byte array to receive the encrypted contents, prepended with the synthetic IV.</param>
    /// <param name="associatedData">Extra data associated with this message, which must also be provided during decryption.</param>
    /// <inheritdoc cref="ThrowIfInvalidPlaintext(byte[])"/>
    /// <inheritdoc cref="ThrowIfInvalidCiphertext(byte[])"/>
    /// <inheritdoc cref="ThrowIfInvalidCiphertext(Span{byte}, ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfInvalidAssociatedData(byte[][])"/>
    /// <inheritdoc cref="ThrowIfDisposed"/>
    public void Encrypt(byte[] plaintext, byte[] ciphertext, params byte[][] associatedData)
    {
        // Input validation

        ThrowIfInvalidPlaintext(plaintext);
        ThrowIfInvalidCiphertext(ciphertext);
        ThrowIfInvalidCiphertext(ciphertext, plaintext);
        ThrowIfInvalidAssociatedData(associatedData);

        // State validation

        ThrowIfDisposed();

        // RFC 5297, Section 2.6

        var V = ciphertext.AsSpan(0, BLOCKSIZE);
        S2V_Init(V);
        foreach (var associatedDataItem in associatedData)
        {
            S2V_AddAssociatedDataItem(associatedDataItem, V);
        }
        S2V_Final(plaintext, V);
        if (plaintext.Length > 0)
        {
            Ctr.ResetSivCounter(V);
            Ctr.UncheckedTransform(plaintext, ciphertext.AsSpan(BLOCKSIZE));
        }
    }

    /// <summary>
    /// Encrypts the plaintext into the ciphertext destination buffer, prepending the synthetic IV.
    /// </summary>
    /// <remarks>
    /// This method adds exactly one associated data item, possibly of zero length, which differs from adding no associated data items at all.
    /// </remarks>
    /// <param name="plaintext">The content to encrypt.</param>
    /// <param name="ciphertext">The byte array to receive the encrypted contents, prepended with the synthetic IV.</param>
    /// <param name="associatedData">Extra data associated with this message, which must also be provided during decryption.</param>
    /// <inheritdoc cref="ThrowIfInvalidCiphertext(Span{byte}, ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfDisposed"/>
    public void Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, ReadOnlySpan<byte> associatedData)
    {
        // Input validation

        ThrowIfInvalidCiphertext(ciphertext, plaintext);

        // State validation

        ThrowIfDisposed();

        // RFC 5297, Section 2.6

        var V = ciphertext[..BLOCKSIZE];
        S2V_Init(V);
        S2V_AddAssociatedDataItem(associatedData, V);
        S2V_Final(plaintext, V);
        if (plaintext.Length > 0)
        {
            Ctr.ResetSivCounter(V);
            Ctr.UncheckedTransform(plaintext, ciphertext[BLOCKSIZE..]);
        }
    }

    /// <summary>
    /// Encrypts the plaintext into the ciphertext destination buffer, prepending the synthetic IV.
    /// </summary>
    /// <param name="plaintext">The content to encrypt.</param>
    /// <param name="ciphertext">The byte array to receive the encrypted contents, prepended with the synthetic IV.</param>
    /// <param name="associatedData">Extra data associated with this message, which must also be provided during decryption.</param>
    /// <inheritdoc cref="ThrowIfInvalidCiphertext(Span{byte}, ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfInvalidAssociatedData(ReadOnlySpan{ReadOnlyMemory{byte}})"/>
    /// <inheritdoc cref="ThrowIfDisposed"/>
    public void Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, params ReadOnlySpan<ReadOnlyMemory<byte>> associatedData)
    {
        // Input validation

        ThrowIfInvalidCiphertext(ciphertext, plaintext);
        ThrowIfInvalidAssociatedData(associatedData);

        // State validation

        ThrowIfDisposed();

        // RFC 5297, Section 2.6

        var V = ciphertext[..BLOCKSIZE];
        S2V_Init(V);
        foreach (var associatedDataItem in associatedData)
        {
            S2V_AddAssociatedDataItem(associatedDataItem.Span, V);
        }
        S2V_Final(plaintext, V);
        if (plaintext.Length > 0)
        {
            Ctr.ResetSivCounter(V);
            Ctr.UncheckedTransform(plaintext, ciphertext[BLOCKSIZE..]);
        }
    }

    /// <summary>
    /// Decrypts the ciphertext into the provided destination buffer if the data can be validated.
    /// </summary>
    /// <param name="ciphertext">The encrypted content to decrypt, including the prepended IV.</param>
    /// <param name="plaintext">The byte array to receive the decrypted contents.</param>
    /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
    /// <inheritdoc cref="ThrowIfInvalidCiphertext(byte[])"/>
    /// <inheritdoc cref="ThrowIfInvalidPlaintext(byte[])"/>
    /// <inheritdoc cref="ThrowIfInvalidPlaintext(Span{byte}, ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfInvalidAssociatedData(byte[][])"/>
    /// <inheritdoc cref="ThrowIfDisposed"/>
    /// <exception cref="CryptographicException">The tag value could not be verified.</exception>
    public void Decrypt(byte[] ciphertext, byte[] plaintext, params byte[][] associatedData)
    {
        // Input validation

        ThrowIfInvalidCiphertext(ciphertext);
        ThrowIfInvalidPlaintext(plaintext);
        ThrowIfInvalidPlaintext(plaintext, ciphertext);
        ThrowIfInvalidAssociatedData(associatedData);

        // State validation

        ThrowIfDisposed();

        // RFC 5297, Section 2.7

        var V = ciphertext.AsSpan(0, BLOCKSIZE);
        if (plaintext.Length > 0)
        {
            Ctr.ResetSivCounter(V);
            Ctr.UncheckedTransform(ciphertext.AsSpan(BLOCKSIZE), plaintext);
        }
        Span<byte> T = stackalloc byte[BLOCKSIZE];
        S2V_Init(T);
        foreach (var associatedDataItem in associatedData)
        {
            S2V_AddAssociatedDataItem(associatedDataItem, T);
        }
        S2V_Final(plaintext, T);
        if (!CryptographicOperations.FixedTimeEquals(T, V))
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException("Authentication failed.");
        }
    }

    /// <summary>
    /// Decrypts the ciphertext into the provided destination buffer if the data can be validated.
    /// </summary>
    /// <remarks>
    /// This method expects exactly one associated data item, possibly of zero length, which differs from expecting no associated data items at all.
    /// </remarks>
    /// <param name="ciphertext">The encrypted content to decrypt, including the prepended IV.</param>
    /// <param name="plaintext">The byte array to receive the decrypted contents.</param>
    /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
    /// <inheritdoc cref="ThrowIfInvalidCiphertext(ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfInvalidPlaintext(Span{byte}, ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfDisposed"/>
    /// <exception cref="CryptographicException">The tag value could not be verified.</exception>
    public void Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        // Input validation

        ThrowIfInvalidCiphertext(ciphertext);
        ThrowIfInvalidPlaintext(plaintext, ciphertext);

        // State validation

        ThrowIfDisposed();

        // RFC 5297, Section 2.7

        var V = ciphertext[..BLOCKSIZE];
        if (plaintext.Length > 0)
        {
            Ctr.ResetSivCounter(V);
            Ctr.UncheckedTransform(ciphertext[BLOCKSIZE..], plaintext);
        }
        Span<byte> T = stackalloc byte[BLOCKSIZE];
        S2V_Init(T);
        S2V_AddAssociatedDataItem(associatedData, T);
        S2V_Final(plaintext, T);
        if (!CryptographicOperations.FixedTimeEquals(T, V))
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException("Authentication failed.");
        }
    }

    /// <summary>
    /// Decrypts the ciphertext into the provided destination buffer if the data can be validated.
    /// </summary>
    /// <param name="ciphertext">The encrypted content to decrypt, including the prepended IV.</param>
    /// <param name="plaintext">The byte array to receive the decrypted contents.</param>
    /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
    /// <inheritdoc cref="ThrowIfInvalidCiphertext(ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfInvalidPlaintext(Span{byte}, ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfInvalidAssociatedData(ReadOnlySpan{ReadOnlyMemory{byte}})"/>
    /// <inheritdoc cref="ThrowIfDisposed"/>
    /// <exception cref="CryptographicException">The tag value could not be verified.</exception>
    public void Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, params ReadOnlySpan<ReadOnlyMemory<byte>> associatedData)
    {
        // Input validation

        ThrowIfInvalidCiphertext(ciphertext);
        ThrowIfInvalidPlaintext(plaintext, ciphertext);
        ThrowIfInvalidAssociatedData(associatedData);

        // State validation

        ThrowIfDisposed();

        // RFC 5297, Section 2.7

        var V = ciphertext[..BLOCKSIZE];
        if (plaintext.Length > 0)
        {
            Ctr.ResetSivCounter(V);
            Ctr.UncheckedTransform(ciphertext[BLOCKSIZE..], plaintext);
        }
        Span<byte> T = stackalloc byte[BLOCKSIZE];
        S2V_Init(T);
        foreach (var associatedDataItem in associatedData)
        {
            S2V_AddAssociatedDataItem(associatedDataItem.Span, T);
        }
        S2V_Final(plaintext, T);
        if (!CryptographicOperations.FixedTimeEquals(T, V))
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException("Authentication failed.");
        }
    }
}

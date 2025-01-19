// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

/// <summary>
/// Provides an implementation of the Advanced Encryption Standard (AES) symmetric algorithm in CTR mode.
/// </summary>
/// <seealso href="https://csrc.nist.gov/publications/detail/sp/800-38a/final"/>
public sealed class AesCtr
    : Aes
{
    const int BLOCKSIZE = 16;  // bytes
    const int BitsPerByte = 8;
    const CipherMode FixedModeValue = CipherMode.CTS;  // DevSkim: ignore DS187371
    const PaddingMode FixedPaddingValue = PaddingMode.None;
    const int FixedFeedbackSizeValue = BLOCKSIZE * BitsPerByte;

    #region CryptoConfig
    static readonly object RegistrationLock = new();
    static bool TriedRegisterOnce;

    /// <summary>
    /// Registers the <see cref="AesCtr"/> class with <see cref="CryptoConfig"/>, such that it can be created by name.
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
                CryptoConfig.AddAlgorithm(typeof(AesCtr), nameof(AesCtr), typeof(AesCtr).FullName!);
            }
        }
    }

    /// <inheritdoc cref="Aes.Create()" />
    [Obsolete("Use one of the constructors instead.")]
    public static new AesCtr Create()
    {
        return new AesCtr();
    }

    /// <inheritdoc cref="Aes.Create(string)" />
    [Obsolete("Cryptographic factory methods accepting an algorithm name are obsolete. Use the parameterless Create factory method on the algorithm type instead.")]
#if !NETSTANDARD2_0
    [RequiresUnreferencedCode("The default algorithm implementations might be removed, use strong type references like 'RSA.Create()' instead.")]
#endif
    public static new AesCtr? Create(string algorithmName)
    {
        if (algorithmName is null)
        {
            throw new ArgumentNullException(nameof(algorithmName));
        }
        // Our class is sealed, so there definitely is no other implementation.
        return algorithmName == nameof(AesCtr) || algorithmName == typeof(AesCtr).FullName! ? new AesCtr() : null;
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

    /// <exception cref="ArgumentNullException"><paramref name="iv"/> is <see langword="null"/>.</exception>
    /// <inheritdoc cref="ThrowIfInvalidIV(ReadOnlySpan{byte})"/>
    static void ThrowIfInvalidIV(byte[] iv)
    {
        if (iv is null)
        {
            throw new ArgumentNullException(nameof(iv));
        }
        ThrowIfInvalidIV(iv.AsSpan());
    }

    /// <exception cref="ArgumentException">
    /// <paramref name="iv"/> is the incorrect length.
    /// Callers are expected to pass an initialization vector that is exactly <see cref="SymmetricAlgorithm.BlockSize"/> in length,
    /// converted to bytes (`BlockSize / 8`).
    /// </exception>
    static void ThrowIfInvalidIV(ReadOnlySpan<byte> iv)
    {
        if (iv.Length != BLOCKSIZE)
        {
            throw new ArgumentException("Specified initial counter (IV) does not match the block size for this algorithm.", nameof(iv));
        }
    }

    void InitializeFixedValues()
    {
        ModeValue = FixedModeValue;
        PaddingValue = FixedPaddingValue;
        FeedbackSizeValue = FixedFeedbackSizeValue;
        BlockSizeValue = BLOCKSIZE * BitsPerByte;
        LegalBlockSizesValue = [new(128, 128, 0)];
        LegalKeySizesValue = [new(128, 256, 64)];
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AesCtr" /> class with a randomly generated 256-bit key and an initial counter of zero.
    /// </summary>
    public AesCtr()
        : this(256)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AesCtr" /> class with a randomly generated key and an initial counter of zero.
    /// </summary>
    /// <param name="keySize">The size, in bits, of the randomly generated key.</param>
    /// <inheritdoc cref="ThrowIfInvalidKeySize(int)"/>
    public AesCtr(int keySize)
    {
        ThrowIfInvalidKeySize(keySize);

        InitializeFixedValues();

        KeySizeValue = keySize;
        IVValue = new byte[BLOCKSIZE];
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AesCtr" /> class with the specified key data and a randomly generated initial counter.
    /// </summary>
    /// <param name="key">The secret key for the AES-CTR algorithm.</param>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is <see langword="null"/>.</exception>
    /// <inheritdoc cref="AesCtr(ReadOnlySpan{byte})" path="/exception"/>
    public AesCtr(byte[] key)
        : this(new ReadOnlySpan<byte>(key ?? throw new ArgumentNullException(nameof(key))))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AesCtr" /> class with the specified key data and a randomly generated initial counter.
    /// </summary>
    /// <param name="key">The secret key for the AES-CTR algorithm.</param>
    /// <inheritdoc cref="ThrowIfInvalidKey(ReadOnlySpan{byte})"/>
    public AesCtr(ReadOnlySpan<byte> key)
    {
        ThrowIfInvalidKey(key);

        InitializeFixedValues();

        KeyValue = key.ToArray();
        KeySizeValue = key.Length * BitsPerByte;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AesCtr" /> class with the specified key data and initial counter.
    /// </summary>
    /// <param name="key">The secret key for the AES-CTR algorithm.</param>
    /// <param name="iv">The initialization vector (initial counter).</param>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="iv"/> is <see langword="null"/>.</exception>
    /// <inheritdoc cref="AesCtr(ReadOnlySpan{byte}, ReadOnlySpan{byte})" path="/exception"/>
    public AesCtr(byte[] key, byte[] iv) :
        this(new ReadOnlySpan<byte>(key ?? throw new ArgumentNullException(nameof(key))),
            new ReadOnlySpan<byte>(iv ?? throw new ArgumentNullException(nameof(iv))))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AesCtr" /> class with the specified key data and initial counter.
    /// </summary>
    /// <param name="key">The secret key for the AES-CTR algorithm.</param>
    /// <param name="iv">The initialization vector (initial counter).</param>
    /// <inheritdoc cref="ThrowIfInvalidKey(ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfInvalidIV(ReadOnlySpan{byte})"/>
    public AesCtr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        ThrowIfInvalidKey(key);
        ThrowIfInvalidIV(iv);

        InitializeFixedValues();

        KeyValue = key.ToArray();
        KeySizeValue = key.Length * BitsPerByte;
        IVValue = iv.ToArray();
    }

    void PurgeKeyValue()
    {
        CryptographicOperations.ZeroMemory(KeyValue);
        KeyValue = null;
    }

    void PurgeIVValue()
    {
        CryptographicOperations.ZeroMemory(IVValue);
        IVValue = null;
    }

    #region IDisposable
    bool IsDisposed;

    /// <inheritdoc cref="SymmetricAlgorithm.Dispose(bool)" />
    protected override void Dispose(bool disposing)
    {
        if (IsDisposed)
        {
            return;
        }

        PurgeKeyValue();
        PurgeIVValue();
        IsDisposed = true;

        base.Dispose(disposing);
    }
    #endregion

    /// <exception cref="ObjectDisposedException">The <see cref="AesCtr"/> instance has been disposed.</exception>
    void ThrowIfDisposed()
    {
        if (IsDisposed)
        {
            throw new ObjectDisposedException(nameof(AesCtr));
        }
    }

    /// <inheritdoc path="/summary"/>
    /// <inheritdoc path="/returns"/>
    /// <remarks>
    /// Setting this property always resets the key to a new random value, even if the key size
    /// is set to current value.
    /// </remarks>
    /// <inheritdoc cref="ThrowIfInvalidKeySize"/>
    /// <inheritdoc cref="ThrowIfDisposed"/>
    public override int KeySize
    {
        get
        {
            ThrowIfDisposed();

            return KeySizeValue;
        }

        set
        {
            ThrowIfInvalidKeySize(value);

            ThrowIfDisposed();

            PurgeKeyValue();
            KeySizeValue = value;
        }
    }

    /// <inheritdoc path="/summary"/>
    /// <inheritdoc path="/returns"/>
    /// <inheritdoc cref="ThrowIfInvalidKey(byte[])"/>
    /// <inheritdoc cref="ThrowIfDisposed"/>
    public override byte[] Key
    {
        get
        {
            ThrowIfDisposed();

            UncheckedGenerateKeyValueIfNull();
            return (byte[])KeyValue!.Clone();
        }

        set
        {
            ThrowIfInvalidKey(value);

            ThrowIfDisposed();

            PurgeKeyValue();
            KeySizeValue = value.Length * 8;

            KeyValue = (byte[])value.Clone();
        }
    }

    /// <inheritdoc path="/summary"/>
    /// <inheritdoc path="/returns"/>
    /// <remarks>
    /// For AES-CTR, the initialization vector (IV) is the initial counter.
    /// </remarks>
    /// <inheritdoc cref="ThrowIfInvalidIV(byte[])"/>
    /// <inheritdoc cref="ThrowIfDisposed"/>
    public override byte[] IV
    {
        get
        {
            ThrowIfDisposed();

            UncheckedGenerateIVValueIfNull();
            return (byte[])IVValue!.Clone();
        }

        set
        {
            ThrowIfInvalidIV(value);

            ThrowIfDisposed();

            PurgeIVValue();

            IVValue = (byte[])value.Clone();
        }
    }

    /// <inheritdoc cref="AesManaged.Mode" />
    /// <remarks><see cref="AesCtr"/> always pretends to use <see cref="CipherMode.CTS" />.</remarks>
    public override CipherMode Mode
    {
        get => FixedModeValue;
        set
        {
            if (value != FixedModeValue)
            {
                throw new CryptographicException("Specified cipher mode is not valid for this algorithm.");
            }
        }
    }

    /// <inheritdoc cref="SymmetricAlgorithm.Padding" />
    /// <remarks><see cref="AesCtr"/> always uses <see cref="PaddingMode.None" />.</remarks>
    public override PaddingMode Padding
    {
        get => FixedPaddingValue;
        set
        {
            if (value != FixedPaddingValue)
            {
                throw new CryptographicException("Specified padding mode is not valid for this algorithm.");
            }
        }
    }

    /// <inheritdoc cref="SymmetricAlgorithm.FeedbackSize" />
    /// <remarks><see cref="AesCtr"/> always uses 128 bits.</remarks>
    public override int FeedbackSize
    {
        get => FixedFeedbackSizeValue;
        set
        {
            if (value != FixedFeedbackSizeValue)
            {
                throw new CryptographicException("Specified feedback size is not valid for this algorithm.");
            }
        }
    }

    /// <inheritdoc/>
    /// <inheritdoc cref="ThrowIfDisposed"/>
    public override ICryptoTransform CreateDecryptor()
    {
        ThrowIfDisposed();

        UncheckedGenerateKeyValueIfNull();
        UncheckedGenerateIVValueIfNull();
        return new AesCtrTransform(KeyValue!, IVValue!);
    }

    /// <summary>
    /// Creates a symmetric decryptor object with the specified key and initial counter (IV).
    /// </summary>
    /// <param name="rgbKey">The secret key to use for the symmetric algorithm.</param>
    /// <param name="rgbIV">The initialization vector (initial counter).</param>
    /// <returns>A symmetric decryptor object.</returns>
    /// <inheritdoc cref="ThrowIfDisposed"/>
    /// <inheritdoc cref="ThrowIfInvalidKey(byte[])"/>
    /// <exception cref="CryptographicException"><paramref name="rgbIV"/> is <see langword="null"/>.</exception>
    /// <inheritdoc cref="ThrowIfInvalidIV(ReadOnlySpan{byte})"/>
    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        ThrowIfDisposed();

        ThrowIfInvalidKey(rgbKey);
        ThrowIfInvalidIV(rgbIV ?? throw new CryptographicException("The cipher mode specified requires that an initialization vector (IV) be used."));

        return new AesCtrTransform(rgbKey, rgbIV);
    }

    /// <inheritdoc/>
    /// <inheritdoc cref="ThrowIfDisposed"/>
    public override ICryptoTransform CreateEncryptor()
    {
        ThrowIfDisposed();

        UncheckedGenerateKeyValueIfNull();
        UncheckedGenerateIVValueIfNull();
        return new AesCtrTransform(KeyValue!, IVValue!);
    }

    /// <summary>
    /// Creates a symmetric encryptor object with the specified key and initial counter (IV).
    /// </summary>
    /// <param name="rgbKey">The secret key to use for the symmetric algorithm.</param>
    /// <param name="rgbIV">The initialization vector (initial counter).</param>
    /// <returns>A symmetric encryptor object.</returns>
    /// <inheritdoc cref="ThrowIfDisposed"/>
    /// <inheritdoc cref="ThrowIfInvalidKey(byte[])"/>
    /// <exception cref="CryptographicException"><paramref name="rgbIV"/> is <see langword="null"/>.</exception>
    /// <inheritdoc cref="ThrowIfInvalidIV(ReadOnlySpan{byte})"/>
    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        ThrowIfDisposed();

        ThrowIfInvalidKey(rgbKey);
        ThrowIfInvalidIV(rgbIV ?? throw new CryptographicException("The cipher mode specified requires that an initialization vector (IV) be used."));

        return new AesCtrTransform(rgbKey, rgbIV);
    }

    void UncheckedGenerateIVValueIfNull()
    {
        if (IVValue is null)
        {
            IVValue = new byte[BLOCKSIZE];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(IVValue);
        }
    }

    /// <inheritdoc cref="AesManaged.GenerateIV" />
    /// <inheritdoc cref="ThrowIfDisposed"/>
    public override void GenerateIV()
    {
        ThrowIfDisposed();

        PurgeIVValue();
        UncheckedGenerateIVValueIfNull();
    }

    void UncheckedGenerateKeyValueIfNull()
    {
        if (KeyValue is null)
        {
            KeyValue = new byte[KeySizeValue / BitsPerByte];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(KeyValue);
        }
    }

    /// <inheritdoc cref="AesManaged.GenerateKey" />
    /// <inheritdoc cref="ThrowIfDisposed"/>
    public override void GenerateKey()
    {
        ThrowIfDisposed();

        PurgeKeyValue();
        UncheckedGenerateKeyValueIfNull();
    }

    #region Modern_SymmetricAlgorithm
    /// <exception cref="ArgumentNullException"><paramref name="input"/> is <see langword="null"/>.</exception>
    static void ThrowIfInvalidInput(byte[] input)
    {
        if (input is null)
        {
            throw new ArgumentNullException(nameof(input));
        }
    }

    /// <exception cref="ArgumentException">The buffer in <paramref name="destination"/> is too small to hold the transformed data.</exception>
    static void ThrowIfInvalidDestination(Span<byte> destination, int requiredLength)
    {
        if (destination.Length < requiredLength)
        {
            throw new ArgumentException("Destination is too short.", nameof(destination));
        }
    }

    /// <summary>
    /// Transforms data using CTR mode.
    /// </summary>
    /// <param name="input">The data to transform.</param>
    /// <param name="iv">The initialization vector (initial counter).</param>
    /// <returns>The transformed data.</returns>
    /// <inheritdoc cref="ThrowIfInvalidInput(byte[])"/>
    /// <inheritdoc cref="ThrowIfInvalidIV(byte[])"/>
    public byte[] TransformCtr(byte[] input, byte[] iv)
    {
        ThrowIfInvalidInput(input);
        ThrowIfInvalidIV(iv);

        ThrowIfDisposed();

        var output = new byte[input.Length];
        UncheckedGenerateKeyValueIfNull();
        using var transform = new AesCtrTransform(KeyValue!, iv);
        transform.UncheckedTransform(input, output);
        return output;
    }

    /// <summary>
    /// Transforms data using CTR mode.
    /// </summary>
    /// <param name="input">The data to transform.</param>
    /// <param name="iv">The initialization vector (initial counter).</param>
    /// <returns>The transformed data.</returns>
    /// <inheritdoc cref="ThrowIfInvalidIV(ReadOnlySpan{byte})"/>
    public byte[] TransformCtr(ReadOnlySpan<byte> input, ReadOnlySpan<byte> iv)
    {
        ThrowIfInvalidIV(iv);

        ThrowIfDisposed();

        var output = new byte[input.Length];
        UncheckedGenerateKeyValueIfNull();
        using var transform = new AesCtrTransform(KeyValue!, iv);
        transform.UncheckedTransform(input, output);
        return output;
    }

    /// <summary>
    /// Transforms data into the specified buffer, using CTR mode.
    /// </summary>
    /// <param name="input">The data to transform.</param>
    /// <param name="iv">The initialization vector (initial counter).</param>
    /// <param name="destination">The buffer to receive the transformed data.</param>
    /// <returns>The total number of bytes written to <paramref name="destination"/>.</returns>
    /// <inheritdoc cref="ThrowIfInvalidIV(ReadOnlySpan{byte})"/>
    /// <inheritdoc cref="ThrowIfInvalidDestination(Span{byte}, int)"/>
    public int TransformCtr(ReadOnlySpan<byte> input, ReadOnlySpan<byte> iv, Span<byte> destination)
    {
        ThrowIfInvalidIV(iv);
        ThrowIfInvalidDestination(destination, input.Length);

        ThrowIfDisposed();

        UncheckedGenerateKeyValueIfNull();
        using var transform = new AesCtrTransform(KeyValue!, iv);
        transform.UncheckedTransform(input, destination);
        return input.Length;
    }

    /// <summary>
    /// Attempts to transform data into the specified buffer, using CTR mode.
    /// </summary>
    /// <param name="input">The data to transform.</param>
    /// <param name="iv">The initialization vector (initial counter).</param>
    /// <param name="destination">The buffer to receive the transformed data.</param>
    /// <param name="bytesWritten">When this method returns, contains the total number of bytes written to <paramref name="destination"/>.</param>
    /// <returns>
    /// <see langword="true"/> if <paramref name="destination"/> was large enough to receive the transformed data; otherwise, <see langword="false"/>.
    /// </returns>
    /// <inheritdoc cref="ThrowIfInvalidIV(ReadOnlySpan{byte})"/>
    public bool TryTransformCtr(ReadOnlySpan<byte> input, ReadOnlySpan<byte> iv, Span<byte> destination, out int bytesWritten)
    {
        ThrowIfInvalidIV(iv);

        ThrowIfDisposed();

        if (destination.Length < input.Length)
        {
            bytesWritten = 0;
            return false;
        }

        UncheckedGenerateKeyValueIfNull();
        using var transform = new AesCtrTransform(KeyValue!, iv);
        transform.UncheckedTransform(input, destination);
        bytesWritten = input.Length;
        return true;
    }
    #endregion
}

// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Text;

namespace Dorssel.Security.Cryptography;

/// <summary>
/// RFC 4615 key derivation algorithm (AES-CMAC-PRF-128) and the associated RFC 8018 password-based key
/// derivation function (PBKDF2-AES-CMAC-PRF-128).
/// </summary>
/// <remarks>
/// AES-CMAC-PRF-128 is registered by IANA as PRF_AES128_CMAC.
/// </remarks>
/// <seealso href="https://www.rfc-editor.org/rfc/rfc4615.html"/>
/// <seealso href="https://www.rfc-editor.org/rfc/rfc8018.html"/>
/// <seealso href="https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml"/>
public static partial class AesCmacPrf128
{
    /// <summary>
    /// Performs the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="inputKey">The input keying material.</param>
    /// <param name="message">The message, i.e., the input data of the PRF.</param>
    /// <returns>128-bit (16 bytes) pseudo-random variable.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="inputKey"/> or <paramref name="message"/> is <see langword="null"/>.</exception>
    public static partial byte[] DeriveKey(byte[] inputKey, byte[] message);

    /// <summary>
    /// Performs the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="inputKey">The input keying material.</param>
    /// <param name="message">The message, i.e., the input data of the PRF.</param>
    /// <param name="destination">The output buffer that represents the 128-bit (16 bytes) pseudo-random variable.</param>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is not exactly 16 bytes long.</exception>
    public static partial void DeriveKey(ReadOnlySpan<byte> inputKey, ReadOnlySpan<byte> message, Span<byte> destination);

    /// <summary>
    /// Creates a PBKDF2 derived key from password bytes using the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="password">The password used to derive the key.</param>
    /// <param name="salt">The key salt used to derive the key.</param>
    /// <param name="iterations">The number of iterations for the operation.</param>
    /// <param name="outputLength">The size of key to derive.</param>
    /// <returns>A byte array of length <paramref name="outputLength"/> that is filled with pseudo-random key bytes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="password"/> or <paramref name="salt"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="outputLength"/> is not zero or a positive value.
    ///
    /// -or-
    ///
    /// <paramref name="iterations"/> is not a positive value.
    /// </exception>
    public static partial byte[] Pbkdf2(byte[] password, byte[] salt, int iterations, int outputLength);

    /// <summary>
    /// Creates a PBKDF2 derived key from password bytes using the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="password">The password used to derive the key.</param>
    /// <param name="salt">The key salt used to derive the key.</param>
    /// <param name="iterations">The number of iterations for the operation.</param>
    /// <param name="outputLength">The size of key to derive.</param>
    /// <returns>A byte array of length <paramref name="outputLength"/> that is filled with pseudo-random key bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="outputLength"/> is not zero or a positive value.
    ///
    /// -or-
    ///
    /// <paramref name="iterations"/> is not a positive value.
    /// </exception>
    public static partial byte[] Pbkdf2(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations, int outputLength);

    /// <summary>
    /// Fills a buffer with a PBKDF2 derived key using the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="password">The password used to derive the key.</param>
    /// <param name="salt">The key salt used to derive the key.</param>
    /// <param name="destination">The buffer to fill with a derived key.</param>
    /// <param name="iterations">The number of iterations for the operation.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is not a positive value.</exception>
    public static partial void Pbkdf2(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> destination, int iterations);

    /// <summary>
    /// Creates a PBKDF2 derived key from a password using the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="password">The password used to derive the key.</param>
    /// <param name="salt">The key salt used to derive the key.</param>
    /// <param name="iterations">The number of iterations for the operation.</param>
    /// <param name="outputLength">The size of key to derive.</param>
    /// <returns>A byte array of length <paramref name="outputLength"/> that is filled with pseudo-random key bytes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="password"/> or <paramref name="salt"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="outputLength"/> is not zero or a positive value.
    ///
    /// -or-
    ///
    /// <paramref name="iterations"/> is not a positive value.
    /// </exception>
    /// <exception cref="EncoderFallbackException"><paramref name="password"/> contains text that cannot be converted to UTF8.</exception>
    /// <remarks>
    /// The <paramref name="password"/> will be converted to bytes using the UTF8 encoding. For other encodings, convert
    /// the password string to bytes using the appropriate <see cref="Encoding"/> and use <see cref="Pbkdf2(byte[], byte[], int, int)"/>.
    /// </remarks>
    public static partial byte[] Pbkdf2(string password, byte[] salt, int iterations, int outputLength);

    /// <summary>
    /// Creates a PBKDF2 derived key from a password using the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="password">The password used to derive the key.</param>
    /// <param name="salt">The key salt used to derive the key.</param>
    /// <param name="iterations">The number of iterations for the operation.</param>
    /// <param name="outputLength">The size of key to derive.</param>
    /// <returns>A byte array of length <paramref name="outputLength"/> that is filled with pseudo-random key bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="outputLength"/> is not zero or a positive value.
    ///
    /// -or-
    ///
    /// <paramref name="iterations"/> is not a positive value.
    /// </exception>
    /// <exception cref="EncoderFallbackException"><paramref name="password"/> contains text that cannot be converted to UTF8.</exception>
    /// <remarks>
    /// The <paramref name="password"/> will be converted to bytes using the UTF8 encoding. For other encodings, convert
    /// the password string to bytes using the appropriate <see cref="Encoding"/> and use
    /// <see cref="Pbkdf2(ReadOnlySpan{byte}, ReadOnlySpan{byte}, int, int)"/>.
    /// </remarks>
    public static partial byte[] Pbkdf2(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, int iterations, int outputLength);

    /// <summary>
    /// Fills a buffer with a PBKDF2 derived key using the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="password">The password used to derive the key.</param>
    /// <param name="salt">The key salt used to derive the key.</param>
    /// <param name="destination">The buffer to fill with a derived key.</param>
    /// <param name="iterations">The number of iterations for the operation.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is not a positive value.</exception>
    /// <exception cref="EncoderFallbackException"><paramref name="password"/> contains text that cannot be converted to UTF8.</exception>
    /// <remarks>
    /// The <paramref name="password"/> will be converted to bytes using the UTF8 encoding. For other encodings, convert
    /// the password string to bytes using the appropriate <see cref="Encoding"/> and use
    /// <see cref="Pbkdf2(ReadOnlySpan{byte}, ReadOnlySpan{byte}, Span{byte}, int)"/>.
    /// </remarks>
    public static partial void Pbkdf2(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, Span<byte> destination, int iterations);
}

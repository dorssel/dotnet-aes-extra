// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
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
public static class AesCmacPrf128
{
    const int BLOCKSIZE = 16;  // bytes
    static readonly byte[] BlockOfZeros = new byte[BLOCKSIZE];

    static AesCmac UncheckedCreateKeyedPrf(byte[] key)
    {
        // Implementation of RFC 4615 (Section 3).

        var prf = new AesCmac();
        // Step 1.
        if (key.Length == BLOCKSIZE)
        {
            // Step 1a.
            prf.Key = key;
        }
        else
        {
            // Step 1b.
            using var blockSizedKey = new SecureByteArray(BLOCKSIZE);
            prf.Key = BlockOfZeros;
            prf.UncheckedHashCore(key);
            prf.UncheckedHashFinal(blockSizedKey);
            prf.Initialize();
            prf.Key = blockSizedKey;
        }
        return prf;
    }

    static AesCmac UncheckedCreateKeyedPrf(ReadOnlySpan<byte> key)
    {
        // Implementation of RFC 4615 (Section 3).

        var prf = new AesCmac();
        // Step 1.
        if (key.Length == BLOCKSIZE)
        {
            // Step 1a.
            using var blockSizedKey = new SecureByteArray(key);
            prf.Key = blockSizedKey;
        }
        else
        {
            // Step 1b.
            using var blockSizedKey = new SecureByteArray(BLOCKSIZE);
            prf.Key = BlockOfZeros;
            prf.UncheckedHashCore(key);
            prf.UncheckedHashFinal(blockSizedKey);
            prf.Initialize();
            prf.Key = blockSizedKey;
        }
        return prf;
    }

    /// <summary>
    /// Performs the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="inputKey">The input keying material.</param>
    /// <param name="message">The message, i.e., the input data of the PRF.</param>
    /// <returns>128-bit (16 bytes) pseudo-random variable.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="inputKey"/> or <paramref name="message"/> is <see langword="null"/>.</exception>
    public static byte[] DeriveKey(byte[] inputKey, byte[] message)
    {
        if (inputKey is null)
        {
            throw new ArgumentNullException(nameof(inputKey));
        }
        if (message is null)
        {
            throw new ArgumentNullException(nameof(inputKey));
        }

        // Implementation of RFC 4615 (Section 3).

        // Step 1 + 1a + 1b.
        using var cmac = UncheckedCreateKeyedPrf(inputKey);
        // Step 2.
        var destination = new byte[BLOCKSIZE];
        cmac.UncheckedHashCore(message);
        cmac.UncheckedHashFinal(destination);
        return destination;
    }

    /// <summary>
    /// Performs the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="inputKey">The input keying material.</param>
    /// <param name="message">The message, i.e., the input data of the PRF.</param>
    /// <param name="destination">The output buffer that represents the 128-bit (16 bytes) pseudo-random variable.</param>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is not exactly 16 bytes long.</exception>
    public static void DeriveKey(ReadOnlySpan<byte> inputKey, ReadOnlySpan<byte> message, Span<byte> destination)
    {
        if (destination.Length != BLOCKSIZE)
        {
            throw new ArgumentException("Destination is not exactly 16-bytes long.");
        }

        // Implementation of RFC 4615 (Section 3).

        // Step 1 + 1a + 1b.
        using var cmac = UncheckedCreateKeyedPrf(inputKey);
        // Step 2.
        cmac.UncheckedHashCore(message);
        cmac.UncheckedHashFinal(destination);
    }

    static void UncheckedPbkdf2(AesCmac cmac, ReadOnlySpan<byte> salt, Span<byte> destination, int iterations)
    {
        // Implementation of RFC 8018 (Section 5.2) + RFC 4615 (Section 3).

        // i
        Span<byte> INT_i = [0, 0, 0, 1];

        Span<byte> U = stackalloc byte[BLOCKSIZE];
        Span<byte> F = stackalloc byte[BLOCKSIZE];

        // i from 1 to l
        while (destination.Length > 0)
        {
            // j = 1
            // U_1 = PRF (P, S || INT (i))
            cmac.Initialize();
            cmac.UncheckedHashCore(salt);
            cmac.UncheckedHashCore(INT_i);
            cmac.UncheckedHashFinal(U);
            // F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
            U.CopyTo(F);
            // j from 2 to c
            for (var j = 2; j <= iterations; j++)
            {
                // U = PRF (P, U_{j-1})
                cmac.Initialize();
                cmac.UncheckedHashCore(U);
                cmac.UncheckedHashFinal(U);
                // F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
                F.xor_InPlace(U);
            }
            if (destination.Length < BLOCKSIZE)
            {
                break;
            }
            // DK = T_1 || T_2 ||  ...  || T_l<0..r-1>
            // where T_i = F (P, S, c, i)
            F.CopyTo(destination);
            destination = destination[BLOCKSIZE..];
            INT_i.BigEndianIncrement();
        }
        // T_l<0..r-1>, if r != 0, where T_l = F (P, S, c, l)
        F[..destination.Length].CopyTo(destination);

        CryptographicOperations.ZeroMemory(U);
        CryptographicOperations.ZeroMemory(F);
    }

    /// <summary>
    /// Creates a PBKDF2 derived key from password bytes using the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="password">The password used to derive the key.</param>
    /// <param name="salt">The key salt used to derive the key.</param>
    /// <param name="iterations">The number of iterations for the operation.</param>
    /// <param name="outputLength">The size of key to derive.</param>
    /// <returns>A byte array of length <paramref name="outputLength"/> that is filled with pseudo-random key bytes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="password"/> or <paramref name="salt"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="outputLength"/> is not zero or a positive value.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is not a positive value.</exception>
    public static byte[] Pbkdf2(byte[] password, byte[] salt, int iterations, int outputLength)
    {
        if (password == null)
        {
            throw new ArgumentNullException(nameof(password));
        }
        if (salt == null)
        {
            throw new ArgumentNullException(nameof(password));
        }
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }
        if (outputLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength));
        }

        if (outputLength == 0)
        {
            return [];
        }

        var destination = new byte[outputLength];
        using var cmac = UncheckedCreateKeyedPrf(password);
        UncheckedPbkdf2(cmac, salt, destination, iterations);
        return destination;
    }

    /// <summary>
    /// Creates a PBKDF2 derived key from password bytes using the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="password">The password used to derive the key.</param>
    /// <param name="salt">The key salt used to derive the key.</param>
    /// <param name="iterations">The number of iterations for the operation.</param>
    /// <param name="outputLength">The size of key to derive.</param>
    /// <returns>A byte array of length <paramref name="outputLength"/> that is filled with pseudo-random key bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="outputLength"/> is not zero or a positive value.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is not a positive value.</exception>
    public static byte[] Pbkdf2(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations, int outputLength)
    {
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }
        if (outputLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength));
        }

        if (outputLength == 0)
        {
            return [];
        }

        var destination = new byte[outputLength];
        using var cmac = UncheckedCreateKeyedPrf(password);
        UncheckedPbkdf2(cmac, salt, destination, iterations);
        return destination;
    }

    /// <summary>
    /// Fills a buffer with a PBKDF2 derived key using the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="password">The password used to derive the key.</param>
    /// <param name="salt">The key salt used to derive the key.</param>
    /// <param name="destination">The buffer to fill with a derived key.</param>
    /// <param name="iterations">The number of iterations for the operation.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is not a positive value.</exception>
    public static void Pbkdf2(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> destination, int iterations)
    {
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }

        if (destination.Length == 0)
        {
            return;
        }

        using var cmac = UncheckedCreateKeyedPrf(password);
        UncheckedPbkdf2(cmac, salt, destination, iterations);
    }

    static SecureByteArray PasswordAsBytes(string password)
    {
        var encoding = new UTF8Encoding(false, true);
        var byteCount = encoding.GetByteCount(password);
        var secureByteArray = new SecureByteArray(byteCount);
        _ = encoding.GetBytes(password, 0, password.Length, secureByteArray, 0);
        return secureByteArray;
    }

    static SecureByteArray PasswordAsBytes(ReadOnlySpan<char> password)
    {
        var encoding = new UTF8Encoding(false, true);
        var passwordAsChars = password.ToArray();
        try
        {
            var byteCount = encoding.GetByteCount(passwordAsChars);
            var secureByteArray = new SecureByteArray(byteCount);
            _ = encoding.GetBytes(passwordAsChars, 0, password.Length, secureByteArray, 0);
            return secureByteArray;
        }
        finally
        {
            for (var i = 0; i < passwordAsChars.Length; i++)
            {
                passwordAsChars[i] = '\0';
            }
        }
    }

    /// <summary>
    /// Creates a PBKDF2 derived key from a password using the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="password">The password used to derive the key.</param>
    /// <param name="salt">The key salt used to derive the key.</param>
    /// <param name="iterations">The number of iterations for the operation.</param>
    /// <param name="outputLength">The size of key to derive.</param>
    /// <returns>A byte array of length <paramref name="outputLength"/> that is filled with pseudo-random key bytes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="password"/> or <paramref name="salt"/> is <see langword="null"/>.</exception>
    /// <exception cref="EncoderFallbackException"><paramref name="password"/> contains text that cannot be converted to UTF8.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="outputLength"/> is not zero or a positive value.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is not a positive value.</exception>
    /// <remarks>
    /// The <paramref name="password"/> will be converted to bytes using the UTF8 encoding. For other encodings, convert
    /// the password string to bytes using the appropriate <see cref="Encoding"/> and use <see cref="Pbkdf2(byte[], byte[], int, int)"/>.
    /// </remarks>
    public static byte[] Pbkdf2(string password, byte[] salt, int iterations, int outputLength)
    {
        if (password == null)
        {
            throw new ArgumentNullException(nameof(password));
        }
        using var passwordAsBytes = PasswordAsBytes(password);
        if (salt == null)
        {
            throw new ArgumentNullException(nameof(password));
        }
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }
        if (outputLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength));
        }

        if (outputLength == 0)
        {
            return [];
        }

        var destination = new byte[outputLength];
        using var cmac = UncheckedCreateKeyedPrf(passwordAsBytes);
        UncheckedPbkdf2(cmac, salt, destination, iterations);
        return destination;
    }

    /// <summary>
    /// Creates a PBKDF2 derived key from a password using the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="password">The password used to derive the key.</param>
    /// <param name="salt">The key salt used to derive the key.</param>
    /// <param name="iterations">The number of iterations for the operation.</param>
    /// <param name="outputLength">The size of key to derive.</param>
    /// <returns>A byte array of length <paramref name="outputLength"/> that is filled with pseudo-random key bytes.</returns>
    /// <exception cref="EncoderFallbackException"><paramref name="password"/> contains text that cannot be converted to UTF8.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="outputLength"/> is not zero or a positive value.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is not a positive value.</exception>
    /// <remarks>
    /// The <paramref name="password"/> will be converted to bytes using the UTF8 encoding. For other encodings, convert
    /// the password string to bytes using the appropriate <see cref="Encoding"/> and use
    /// <see cref="Pbkdf2(ReadOnlySpan{byte}, ReadOnlySpan{byte}, int, int)"/>.
    /// </remarks>
    public static byte[] Pbkdf2(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, int iterations, int outputLength)
    {
        using var passwordAsBytes = PasswordAsBytes(password);
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }
        if (outputLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength));
        }

        if (outputLength == 0)
        {
            return [];
        }

        var destination = new byte[outputLength];
        using var cmac = UncheckedCreateKeyedPrf(passwordAsBytes);
        UncheckedPbkdf2(cmac, salt, destination, iterations);
        return destination;
    }

    /// <summary>
    /// Fills a buffer with a PBKDF2 derived key using the AES-CMAC-PRF-128 pseudo-random function.
    /// </summary>
    /// <param name="password">The password used to derive the key.</param>
    /// <param name="salt">The key salt used to derive the key.</param>
    /// <param name="destination">The buffer to fill with a derived key.</param>
    /// <param name="iterations">The number of iterations for the operation.</param>
    /// <exception cref="EncoderFallbackException"><paramref name="password"/> contains text that cannot be converted to UTF8.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is not a positive value.</exception>
    /// <remarks>
    /// The <paramref name="password"/> will be converted to bytes using the UTF8 encoding. For other encodings, convert
    /// the password string to bytes using the appropriate <see cref="Encoding"/> and use
    /// <see cref="Pbkdf2(ReadOnlySpan{byte}, ReadOnlySpan{byte}, Span{byte}, int)"/>.
    /// </remarks>
    public static void Pbkdf2(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, Span<byte> destination, int iterations)
    {
        using var passwordAsBytes = PasswordAsBytes(password);
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }

        if (destination.Length == 0)
        {
            return;
        }

        using var cmac = UncheckedCreateKeyedPrf(passwordAsBytes);
        UncheckedPbkdf2(cmac, salt, destination, iterations);
    }
}

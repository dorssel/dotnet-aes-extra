// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

/// <summary>
/// RFC 4615 key derivation algorithm (AES-CMAC-PRF-128) for the Internet Key Exchange Protocol (IKE).
/// </summary>
/// <remarks>
/// The IANA name is PRF_AES128_CMAC.
/// </remarks>
/// <seealso href="https://www.rfc-editor.org/rfc/rfc4615.html"/>
/// <seealso href="https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml"/>
public static class AesCmacPrf128
{
    const int BLOCKSIZE = 16;  // bytes

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="inputKey">TODO</param>
    /// <param name="message">TODO</param>
    /// <returns>TODO</returns>
    /// <exception cref="ArgumentNullException">TODO</exception>
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

        var destination = new byte[BLOCKSIZE];
        DeriveKey(inputKey, message, destination);
        return destination;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="inputKey">TODO</param>
    /// <param name="message">TODO</param>
    /// <param name="destination">TODO</param>
    /// <returns>TODO</returns>
    /// <exception cref="ArgumentException">TODO</exception>
    public static int DeriveKey(ReadOnlySpan<byte> inputKey, ReadOnlySpan<byte> message, Span<byte> destination)
    {
        if (destination.Length < BLOCKSIZE)
        {
            throw new ArgumentException("Destination is too short.");
        }

        if (inputKey.Length == BLOCKSIZE)
        {
            return AesCmac.HashData(inputKey, message, destination);
        }
        else
        {
            using var K = new SecureByteArray(BLOCKSIZE);
            _ = AesCmac.HashData(new byte[BLOCKSIZE], inputKey, K);
            return AesCmac.HashData(K, message, destination);
        }
    }
}

// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

sealed class SecureByteArray : IDisposable
{
    byte[] _Data = [];

    public SecureByteArray(int size)
    {
        _Data = new byte[size];
    }

    public SecureByteArray(ReadOnlySpan<byte> data)
    {
        _Data = data.ToArray();
    }

    public SecureByteArray(ReadOnlyMemory<byte> data)
    {
        _Data = data.ToArray();
    }

    public static implicit operator byte[](SecureByteArray source)
    {
        return source._Data;
    }

    public static implicit operator Span<byte>(SecureByteArray source)
    {
        return source._Data;
    }

    public static implicit operator ReadOnlySpan<byte>(SecureByteArray source)
    {
        return source._Data;
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_Data);
        _Data = [];
    }
}

// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class AesCmacPrf128_Tests
{
    const int BLOCKSIZE = 16;  // bytes

    static readonly byte[] TestKey = new byte[BLOCKSIZE];
    static readonly byte[] TestMessage = [1, 2, 3];

    [TestMethod]
    public void DeriveKey_Array_Array_KeyNull()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            AesCmacPrf128.DeriveKey(null!, TestMessage);
        });
    }

    [TestMethod]
    public void DeriveKey_Array_Array_MessageNull()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            AesCmacPrf128.DeriveKey(TestKey, null!);
        });
    }

    [TestMethod]
    public void DeriveKey_ReadOnlySpan_ReadOnlySpan_Span_Short()
    {
        var output = new byte[BLOCKSIZE - 1];
        Assert.ThrowsException<ArgumentException>(() =>
        {
            AesCmacPrf128.DeriveKey(TestKey, TestMessage, output);
        });
    }

    [TestMethod]
    public void Pbkdf2_Array_Array_PasswordNull()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            AesCmacPrf128.Pbkdf2((byte[])null!, Array.Empty<byte>(), 1, 1);
        });
    }

    [TestMethod]
    public void Pbkdf2_Array_Array_SaltNull()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            AesCmacPrf128.Pbkdf2(Array.Empty<byte>(), null!, 1, 1);
        });
    }

    [TestMethod]
    public void Pbkdf2_Array_Array_IterationsNegative()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
        {
            AesCmacPrf128.Pbkdf2(Array.Empty<byte>(), Array.Empty<byte>(), -1, 1);
        });
    }

    [TestMethod]
    public void Pbkdf2_Array_Array_OutputLengthNegative()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
        {
            AesCmacPrf128.Pbkdf2(Array.Empty<byte>(), Array.Empty<byte>(), 1, -1);
        });
    }

    [TestMethod]
    public void Pbkdf2_Array_Array_OutputLengthZero()
    {
        AesCmacPrf128.Pbkdf2(Array.Empty<byte>(), Array.Empty<byte>(), 1, 0);
    }

    [TestMethod]
    public void Pbkdf2_ReadOnlyBytes_ReadOnlySpan_IterationsNegative()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
        {
            AesCmacPrf128.Pbkdf2(new Span<byte>(), new Span<byte>(), -1, 1);
        });
    }

    [TestMethod]
    public void Pbkdf2_ReadOnlyBytes_ReadOnlySpan_OutputLengthNegative()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
        {
            AesCmacPrf128.Pbkdf2(new Span<byte>(), new Span<byte>(), 1, -1);
        });
    }

    [TestMethod]
    public void Pbkdf2_ReadOnlyBytes_ReadOnlySpan_OutputLengthZero()
    {
        AesCmacPrf128.Pbkdf2(new Span<byte>(), new Span<byte>(), 1, 0);
    }

    [TestMethod]
    public void Pbkdf2_ReadOnlyBytes_ReadOnlySpan_Span_IterationsNegative()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
        {
            AesCmacPrf128.Pbkdf2(new Span<byte>(), new Span<byte>(), new Span<byte>(), -1);
        });
    }

    [TestMethod]
    public void Pbkdf2_ReadOnlyBytes_ReadOnlySpan_Span_OutputLengthZero()
    {
        AesCmacPrf128.Pbkdf2(new Span<byte>(), new Span<byte>(), new Span<byte>(), 1);
    }

    [TestMethod]
    public void Pbkdf2_String_Array_PasswordNull()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            AesCmacPrf128.Pbkdf2((string)null!, Array.Empty<byte>(), 1, 1);
        });
    }

    [TestMethod]
    public void Pbkdf2_String_Array_SaltNull()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            AesCmacPrf128.Pbkdf2(string.Empty, null!, 1, 1);
        });
    }

    [TestMethod]
    public void Pbkdf2_String_Array_IterationsNegative()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
        {
            AesCmacPrf128.Pbkdf2(string.Empty, Array.Empty<byte>(), -1, 1);
        });
    }

    [TestMethod]
    public void Pbkdf2_String_Array_OutputLengthNegative()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
        {
            AesCmacPrf128.Pbkdf2(string.Empty, Array.Empty<byte>(), 1, -1);
        });
    }

    [TestMethod]
    public void Pbkdf2_String_Array_OutputLengthZero()
    {
        AesCmacPrf128.Pbkdf2(string.Empty, Array.Empty<byte>(), 1, 0);
    }

    [TestMethod]
    public void Pbkdf2_ReadOnlyChars_ReadOnlySpan_IterationsNegative()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
        {
            AesCmacPrf128.Pbkdf2(new Span<char>(), new Span<byte>(), -1, 1);
        });
    }

    [TestMethod]
    public void Pbkdf2_ReadOnlyChars_ReadOnlySpan_OutputLengthNegative()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
        {
            AesCmacPrf128.Pbkdf2(new Span<char>(), new Span<byte>(), 1, -1);
        });
    }

    [TestMethod]
    public void Pbkdf2_ReadOnlyChars_ReadOnlySpan_OutputLengthZero()
    {
        AesCmacPrf128.Pbkdf2(new Span<char>(), new Span<byte>(), 1, 0);
    }

    [TestMethod]
    public void Pbkdf2_ReadOnlyChars_ReadOnlySpan_Span_IterationsNegative()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
        {
            AesCmacPrf128.Pbkdf2(new Span<char>(), new Span<byte>(), new Span<byte>(), -1);
        });
    }

    [TestMethod]
    public void Pbkdf2_ReadOnlyChars_ReadOnlySpan_Span_OutputLengthZero()
    {
        AesCmacPrf128.Pbkdf2(new Span<char>(), new Span<byte>(), new Span<byte>(), 1);
    }
}

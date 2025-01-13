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

}

// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class AesCmac_Tests
{
    const int BLOCKSIZE = 16;  // bytes

    static readonly byte[] TestKey =
        [
            31, 32, 33, 34, 35, 36, 37, 38,
            41, 42, 43, 44, 45, 46, 47, 48,
            51, 52, 53, 54, 55, 56, 57, 58
        ];

    static readonly byte[] TestMessage = [1, 2, 3, 4, 5];

    static readonly byte[] TestTag = InitializeTestTag();

    static byte[] InitializeTestTag()
    {
        // This is "known good", in the sense that ComputeHash is tested with the SIV vectors.
        // This value is subsequently used to verify the one-shot functions.

        using var cmac = new AesCmac(TestKey);
        return cmac.ComputeHash(TestMessage);
    }

    [TestMethod]
    public void Create()
    {
        using var keyedHashAlgorithm = AesCmac.Create();
        Assert.IsNotNull(keyedHashAlgorithm);
    }

    [TestMethod]
    public void Create_Name()
    {
#pragma warning disable CS0618 // Type or member is obsolete
        using var keyedHashAlgorithm = AesCmac.Create("AesCmac");
#pragma warning restore CS0618 // Type or member is obsolete
        Assert.IsNotNull(keyedHashAlgorithm);
    }

    [TestMethod]
    public void Create_NullNameFails()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
#pragma warning disable CS0618 // Type or member is obsolete
            using var keyedHashAlgorithm = AesCmac.Create(null!);
#pragma warning restore CS0618 // Type or member is obsolete
        });
    }

    [TestMethod]
    public void Create_OtherNameReturnsNull()
    {
#pragma warning disable CS0618 // Type or member is obsolete
        using var keyedHashAlgorithm = AesCmac.Create("SomeOtherName");
#pragma warning restore CS0618 // Type or member is obsolete
        Assert.IsNull(keyedHashAlgorithm);
    }

    [TestMethod]
    public void Constructor_Default()
    {
        using var aesCmac = new AesCmac();
    }

    [TestMethod]
    [DataRow(128)]
    [DataRow(192)]
    [DataRow(256)]
    public void Constructor_WithKey(int keySize)
    {
        using var aesCmac = new AesCmac(new byte[keySize / 8]);
    }

    [TestMethod]
    public void Constructor_WithInvalidKeySize()
    {
        Assert.ThrowsException<CryptographicException>(() =>
        {
            using var aesCmac = new AesCmac(new byte[42]);
        });
    }

    [TestMethod]
    public void Constructor_WithNullKey()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            using var aesCmac = new AesCmac(null!);
        });
    }

    [TestMethod]
    public void Dispose()
    {
        var aesCmac = new AesCmac();
        aesCmac.Dispose();
    }

    [TestMethod]
    public void Dispose_Double()
    {
        var aesCmac = new AesCmac();
        aesCmac.Dispose();
        aesCmac.Dispose();
    }

    [TestMethod]
    public void Key_Change()
    {
        var keys = NistAesCmacSampleTestVector.All
            .Select(tv => tv.Key.ToArray())
            .DistinctBy(BitConverter.ToString);

        using var aesCmac = new AesCmac();
        foreach (var key in keys)
        {
            aesCmac.Key = key;
            CollectionAssert.AreEqual(key, aesCmac.Key);
        }
    }

    [TestMethod]
    public void Key_ChangeWhileBusy()
    {
        using var aesCmac = new AesCmac();
        aesCmac.TransformBlock(new byte[1], 0, 0, null, 0);

        Assert.ThrowsException<InvalidOperationException>(() =>
        {
            aesCmac.Key = new byte[aesCmac.Key.Length];
        });
    }

    [TestMethod]
    public void ComputeHash_Segmented()
    {
        var testVector = NistAesCmacSampleTestVector.All.First(tv => tv.PT.Length == 64);

        using var aesCmac = new AesCmac(testVector.Key.ToArray());

        var pos = 0;
        void Transfer(int count)
        {
            aesCmac.TransformBlock(testVector.PT.ToArray(), pos, count, null, 0);
            pos += count;
        }

        // less than 1 block
        Transfer(16 - 3);
        // append to, but don't complete the partial block
        Transfer(2);
        // complete the partial block precisely
        Transfer(1);
        // more than 1 block, but not an exact multiple
        Transfer((2 * 16) - 3);
        // topping off the partial block + again less than 1 block
        Transfer(16);
        // remainder
        Transfer(testVector.PT.Length - pos);

        aesCmac.TransformFinalBlock([], 0, 0);

        CollectionAssert.AreEqual(testVector.Tag.ToArray(), aesCmac.Hash);
    }

    [TestMethod]
    public void ComputeHash_Reuse()
    {
        using var aesCmac = new AesCmac();
        foreach (var testVector in NistAesCmacSampleTestVector.All)
        {
            aesCmac.Key = testVector.Key.ToArray();
            var tag = aesCmac.ComputeHash(testVector.PT.ToArray());
            CollectionAssert.AreEqual(testVector.Tag.ToArray(), tag);
        }
    }

    [TestMethod]
    public void TryHashData()
    {
        var destination = new byte[BLOCKSIZE];

        var success = AesCmac.TryHashData(TestKey.AsSpan(), TestMessage, destination, out var bytesWritten);

        Assert.IsTrue(success);
        Assert.AreEqual(BLOCKSIZE, bytesWritten);
        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public void TryHashData_short()
    {
        var destination = new byte[BLOCKSIZE - 1];

        var success = AesCmac.TryHashData(TestKey.AsSpan(), TestMessage, destination, out var bytesWritten);

        Assert.IsFalse(success);
        Assert.AreEqual(0, bytesWritten);
    }

    [TestMethod]
    public void HashData_Array_Array()
    {
        using var stream = new MemoryStream(TestMessage);

        var destination = AesCmac.HashData(TestKey, TestMessage);

        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_Span()
    {
        using var stream = new MemoryStream(TestMessage);

        var destination = AesCmac.HashData(TestKey.AsSpan(), TestMessage.AsSpan());

        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_ReadOnlySpan_Span()
    {
        using var stream = new MemoryStream(TestMessage);
        var destination = new byte[BLOCKSIZE];

        var bytesWritten = AesCmac.HashData(TestKey.AsSpan(), TestMessage.AsSpan(), destination);

        Assert.AreEqual(BLOCKSIZE, bytesWritten);
        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_ReadOnlySpan_Span_Short()
    {
        using var stream = new MemoryStream(TestMessage);
        var destination = new byte[BLOCKSIZE - 1];

        Assert.ThrowsException<ArgumentException>(() =>
        {
            AesCmac.HashData(TestKey.AsSpan(), TestMessage.AsSpan(), destination);
        });
    }

    [TestMethod]
    public void HashData_Array_Stream()
    {
        using var stream = new MemoryStream(TestMessage);

        var destination = AesCmac.HashData(TestKey, stream);

        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public void HashData_Array_Stream_Null()
    {
        var destination = new byte[BLOCKSIZE];

        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            AesCmac.HashData(TestKey, (Stream)null!);
        });
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_Stream()
    {
        using var stream = new MemoryStream(TestMessage);

        var destination = AesCmac.HashData(TestKey.AsSpan(), stream);

        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_Stream_Null()
    {
        var destination = new byte[BLOCKSIZE];

        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            AesCmac.HashData(TestKey.AsSpan(), (Stream)null!);
        });
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_Stream_Span()
    {
        using var stream = new MemoryStream(TestMessage);
        var destination = new byte[BLOCKSIZE];

        var bytesWritten = AesCmac.HashData(TestKey.AsSpan(), stream, destination);

        Assert.AreEqual(BLOCKSIZE, bytesWritten);
        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_Stream_Span_Null()
    {
        var destination = new byte[BLOCKSIZE];

        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            AesCmac.HashData(TestKey.AsSpan(), (Stream)null!, destination);
        });
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_Stream_Span_Short()
    {
        using var stream = new MemoryStream(TestMessage);
        var destination = new byte[BLOCKSIZE - 1];

        Assert.ThrowsException<ArgumentException>(() =>
        {
            AesCmac.HashData(TestKey.AsSpan(), stream, destination);
        });
    }

    [TestMethod]
    public async Task HashDataAsync_Array_Stream()
    {
        using var stream = new MemoryStream(TestMessage);

        var destination = await AesCmac.HashDataAsync(TestKey, stream);

        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public async Task HashDataAsync_Array_Stream_Null()
    {
        await Assert.ThrowsExceptionAsync<ArgumentNullException>(async () =>
        {
            await AesCmac.HashDataAsync(TestKey, null!);
        });
    }

    [TestMethod]
    public async Task HashDataAsync_ReadOnlyMemory_Stream()
    {
        using var stream = new MemoryStream(TestMessage);

        var destination = await AesCmac.HashDataAsync(TestKey.AsMemory(), stream);

        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public async Task HashDataAsync_ReadOnlyMemory_Stream_Null()
    {
        await Assert.ThrowsExceptionAsync<ArgumentNullException>(async () =>
        {
            await AesCmac.HashDataAsync(TestKey.AsMemory(), null!);
        });
    }

    [TestMethod]
    public async Task HashDataAsync_ReadOnlyMemory_Stream_Memory()
    {
        using var stream = new MemoryStream(TestMessage);
        var destination = new byte[BLOCKSIZE];

        var bytesWritten = await AesCmac.HashDataAsync(TestKey.AsMemory(), stream, destination.AsMemory());

        Assert.AreEqual(BLOCKSIZE, bytesWritten);
        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public async Task HashDataAsync_ReadOnlyMemory_Stream_Memory_Null()
    {
        var destination = new byte[BLOCKSIZE];

        await Assert.ThrowsExceptionAsync<ArgumentNullException>(async () =>
        {
            await AesCmac.HashDataAsync(TestKey.AsMemory(), null!, destination.AsMemory());
        });
    }

    [TestMethod]
    public async Task HashDataAsync_ReadOnlyMemory_Stream_Memory_Short()
    {
        using var stream = new MemoryStream(TestMessage);
        var destination = new byte[BLOCKSIZE - 1];

        await Assert.ThrowsExceptionAsync<ArgumentException>(async () =>
        {
            await AesCmac.HashDataAsync(TestKey.AsMemory(), stream, destination.AsMemory());
        });
    }
}

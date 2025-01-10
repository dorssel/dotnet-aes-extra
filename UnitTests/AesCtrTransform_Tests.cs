// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class AesCtrTransform_Tests
{
    const int BLOCKSIZE = 16;  // bytes

    static readonly byte[] TestKey =
        [
            31, 32, 33, 34, 35, 36, 37, 38,
            41, 42, 43, 44, 45, 46, 47, 48,
            51, 52, 53, 54, 55, 56, 57, 58
        ];

    static readonly byte[] TestInitialCounter =
        [
            61, 62, 63, 64, 65, 66, 67, 68,
            71, 72, 73, 74, 75, 76, 77, 78
        ];

    [TestMethod]
    public void Constructor()
    {
        using var transform = new AesCtrTransform(TestKey, TestInitialCounter);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(BLOCKSIZE / 8)]
    [DataRow(BLOCKSIZE / 2)]
    [DataRow(BLOCKSIZE - 1)]
    [DataRow(BLOCKSIZE + 1)]
    [DataRow(BLOCKSIZE * 2)]
    [DataRow(BLOCKSIZE * 8)]
    public void Constructor_InvalidIVSize(int ivSize)
    {
        Assert.ThrowsException<ArgumentException>(() =>
        {
            using var transform = new AesCtrTransform(TestKey, new byte[ivSize]);
        });
    }

    [TestMethod]
    public void Dispose()
    {
        var transform = new AesCtrTransform(TestKey, TestInitialCounter);
        transform.Dispose();
    }

    [TestMethod]
    public void Dispose_Double()
    {
        var transform = new AesCtrTransform(TestKey, TestInitialCounter);
        transform.Dispose();
        transform.Dispose();
    }


    [TestMethod]
    public void CanReuseTransform_Get()
    {
        using ICryptoTransform transform = new AesCtrTransform(TestKey, TestInitialCounter);
        Assert.IsFalse(transform.CanReuseTransform);
    }

    [TestMethod]
    public void CanTransformMultipleBlocks_Get()
    {
        using ICryptoTransform transform = new AesCtrTransform(TestKey, TestInitialCounter);
        Assert.IsTrue(transform.CanTransformMultipleBlocks);
    }

    [TestMethod]
    public void InputBlockSize_Get()
    {
        using ICryptoTransform transform = new AesCtrTransform(TestKey, TestInitialCounter);
        Assert.AreEqual(BLOCKSIZE, transform.InputBlockSize);
    }

    [TestMethod]
    public void OutputBlockSize_Get()
    {
        using ICryptoTransform transform = new AesCtrTransform(TestKey, TestInitialCounter);
        Assert.AreEqual(BLOCKSIZE, transform.InputBlockSize);
    }

    [TestMethod]
    [DataRow(0 * BLOCKSIZE)]
    [DataRow(1 * BLOCKSIZE)]
    [DataRow(2 * BLOCKSIZE)]
    [DataRow(10 * BLOCKSIZE)]
    public void TransformBlock_ValidSize(int size)
    {
        using ICryptoTransform transform = new AesCtrTransform(TestKey, TestInitialCounter);
        var result = transform.TransformBlock(new byte[size], 0, size, new byte[size], 0);
        Assert.AreEqual(size, result);
    }

    [TestMethod]
    [DataRow(1)]
    [DataRow(BLOCKSIZE - 1)]
    [DataRow(BLOCKSIZE + 1)]
    public void TransformBlock_InvalidSizeFails(int size)
    {
        Assert.ThrowsException<ArgumentException>(() =>
        {
            using ICryptoTransform transform = new AesCtrTransform(TestKey, TestInitialCounter);
            transform.TransformBlock(new byte[size], 0, size, new byte[size], 0);
        });
    }

    [TestMethod]
    public void TransformBlock_AfterFinalFails()
    {
        using ICryptoTransform transform = new AesCtrTransform(TestKey, TestInitialCounter);
        transform.TransformFinalBlock([], 0, 0);
        Assert.ThrowsException<InvalidOperationException>(() =>
        {
            transform.TransformBlock(new byte[BLOCKSIZE], 0, BLOCKSIZE, new byte[BLOCKSIZE], 0);
        });
    }

    [TestMethod]
    public void TransformBlock_AfterDisposeFails()
    {
        ICryptoTransform transform = new AesCtrTransform(TestKey, TestInitialCounter);
        transform.TransformBlock(new byte[BLOCKSIZE], 0, BLOCKSIZE, new byte[BLOCKSIZE], 0);
        transform.Dispose();
        Assert.ThrowsException<ObjectDisposedException>(() =>
        {
            transform.TransformBlock(new byte[BLOCKSIZE], 0, BLOCKSIZE, new byte[BLOCKSIZE], 0);
        });
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(BLOCKSIZE - 1)]
    [DataRow(BLOCKSIZE)]
    public void TransformFinalBlock_ValidSize(int size)
    {
        using ICryptoTransform transform = new AesCtrTransform(TestKey, TestInitialCounter);
        var result = transform.TransformFinalBlock(new byte[size], 0, size);
        Assert.AreEqual(size, result.Length);
    }

    [TestMethod]
    [DataRow(BLOCKSIZE + 1)]
    [DataRow(2 * BLOCKSIZE)]
    public void TransformFinalBlock_InvalidSizeFails(int size)
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
        {
            using ICryptoTransform transform = new AesCtrTransform(TestKey, TestInitialCounter);
            transform.TransformFinalBlock(new byte[size], 0, size);
        });
    }

    [TestMethod]
    public void TransformFinalBlock_AfterFinalFails()
    {
        using ICryptoTransform transform = new AesCtrTransform(TestKey, TestInitialCounter);
        transform.TransformFinalBlock([], 0, 0);
        Assert.ThrowsException<InvalidOperationException>(() =>
        {
            transform.TransformFinalBlock([], 0, 0);
        });
    }

    [TestMethod]
    public void TransformFinalBlock_AfterDisposeFails()
    {
        ICryptoTransform transform = new AesCtrTransform(TestKey, TestInitialCounter);
        transform.TransformBlock(new byte[BLOCKSIZE], 0, BLOCKSIZE, new byte[BLOCKSIZE], 0);
        transform.Dispose();
        Assert.ThrowsException<ObjectDisposedException>(() =>
        {
            transform.TransformFinalBlock([], 0, 0);
        });
    }
}

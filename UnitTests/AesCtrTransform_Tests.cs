// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class AesCtrTransform_Tests
{
    const int BLOCKSIZE = 16;  // bytes

    readonly byte[] TestKey = new byte[128 / 8];
    readonly byte[] InitialCounter = new byte[BLOCKSIZE];

    [TestMethod]
    public void Constructor()
    {
        using var transform = new AesCtrTransform(TestKey, InitialCounter);
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
        var transform = new AesCtrTransform(TestKey, InitialCounter);
        transform.Dispose();
    }

    [TestMethod]
    public void Dispose_Double()
    {
        var transform = new AesCtrTransform(TestKey, InitialCounter);
        transform.Dispose();
        transform.Dispose();
    }


    [TestMethod]
    public void CanReuseTransform_Get()
    {
        using ICryptoTransform transform = new AesCtrTransform(TestKey, InitialCounter);
        Assert.IsFalse(transform.CanReuseTransform);
    }

    [TestMethod]
    public void CanTransformMultipleBlocks_Get()
    {
        using ICryptoTransform transform = new AesCtrTransform(TestKey, InitialCounter);
        Assert.IsTrue(transform.CanTransformMultipleBlocks);
    }

    [TestMethod]
    public void InputBlockSize_Get()
    {
        using ICryptoTransform transform = new AesCtrTransform(TestKey, InitialCounter);
        Assert.AreEqual(BLOCKSIZE, transform.InputBlockSize);
    }

    [TestMethod]
    public void OutputBlockSize_Get()
    {
        using ICryptoTransform transform = new AesCtrTransform(TestKey, InitialCounter);
        Assert.AreEqual(BLOCKSIZE, transform.InputBlockSize);
    }

    [TestMethod]
    [DataRow(0 * BLOCKSIZE)]
    [DataRow(1 * BLOCKSIZE)]
    [DataRow(2 * BLOCKSIZE)]
    [DataRow(10 * BLOCKSIZE)]
    public void TransformBlock_ValidSize(int size)
    {
        using ICryptoTransform transform = new AesCtrTransform(TestKey, InitialCounter);
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
            using ICryptoTransform transform = new AesCtrTransform(TestKey, InitialCounter);
            transform.TransformBlock(new byte[size], 0, size, new byte[size], 0);
        });
    }

    [TestMethod]
    public void TransformBlock_AfterFinalFails()
    {
        using ICryptoTransform transform = new AesCtrTransform(TestKey, InitialCounter);
        transform.TransformFinalBlock([], 0, 0);
        Assert.ThrowsException<InvalidOperationException>(() =>
        {
            transform.TransformBlock(new byte[BLOCKSIZE], 0, BLOCKSIZE, new byte[BLOCKSIZE], 0);
        });
    }

    [TestMethod]
    public void TransformBlock_AfterDisposeFails()
    {
        ICryptoTransform transform = new AesCtrTransform(TestKey, InitialCounter);
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
        using ICryptoTransform transform = new AesCtrTransform(TestKey, InitialCounter);
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
            using ICryptoTransform transform = new AesCtrTransform(TestKey, InitialCounter);
            transform.TransformFinalBlock(new byte[size], 0, size);
        });
    }

    [TestMethod]
    public void TransformFinalBlock_AfterFinalFails()
    {
        using ICryptoTransform transform = new AesCtrTransform(TestKey, InitialCounter);
        transform.TransformFinalBlock([], 0, 0);
        Assert.ThrowsException<InvalidOperationException>(() =>
        {
            transform.TransformFinalBlock([], 0, 0);
        });
    }

    [TestMethod]
    public void TransformFinalBlock_AfterDisposeFails()
    {
        ICryptoTransform transform = new AesCtrTransform(TestKey, InitialCounter);
        transform.TransformBlock(new byte[BLOCKSIZE], 0, BLOCKSIZE, new byte[BLOCKSIZE], 0);
        transform.Dispose();
        Assert.ThrowsException<ObjectDisposedException>(() =>
        {
            transform.TransformFinalBlock([], 0, 0);
        });
    }
}

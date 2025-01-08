// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class AesCtrTransform_Tests
{
    const int BLOCKSIZE = AesCtr.FixedBlockSize; // bytes

    readonly ICryptoTransform AesEcbTransform;
    readonly byte[] InitialCounter = new byte[BLOCKSIZE];

    public AesCtrTransform_Tests()
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB; // DevSkim: ignore DS187371
        aes.Padding = PaddingMode.None;
        AesEcbTransform = aes.CreateEncryptor(new byte[128 / 8], new byte[BLOCKSIZE]);
    }

    [TestMethod]
    public void Constructor()
    {
        using var transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
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
        _ = Assert.ThrowsException<ArgumentException>(() =>
        {
            using var transform = new AesCtrTransform(new byte[ivSize], AesEcbTransform);
        });
    }

    [TestMethod]
    public void Constructor_TransformInvalidInputBlockSize()
    {
        var mockTransform = new Mock<ICryptoTransform>();
        _ = mockTransform.SetupGet(m => m.InputBlockSize).Returns(BLOCKSIZE + 1);
        _ = mockTransform.SetupGet(m => m.OutputBlockSize).Returns(BLOCKSIZE);

        _ = Assert.ThrowsException<CryptographicException>(() =>
        {
            using var transform = new AesCtrTransform(InitialCounter, mockTransform.Object);
        });
    }

    [TestMethod]
    public void Constructor_TransformInvalidOutputBlockSize()
    {
        var mockTransform = new Mock<ICryptoTransform>();
        _ = mockTransform.SetupGet(m => m.InputBlockSize).Returns(BLOCKSIZE);
        _ = mockTransform.SetupGet(m => m.OutputBlockSize).Returns(BLOCKSIZE + 1);

        _ = Assert.ThrowsException<CryptographicException>(() =>
        {
            using var transform = new AesCtrTransform(InitialCounter, mockTransform.Object);
        });
    }

    [TestMethod]
    public void Dispose()
    {
        var transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
        transform.Dispose();
    }

    [TestMethod]
    public void Dispose_Double()
    {
        var transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
        transform.Dispose();
        transform.Dispose();
    }


    [TestMethod]
    public void CanReuseTransform_Get()
    {
        using ICryptoTransform transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
        Assert.IsFalse(transform.CanReuseTransform);
    }

    [TestMethod]
    public void CanTransformMultipleBlocks_Get()
    {
        using ICryptoTransform transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
        Assert.IsTrue(transform.CanTransformMultipleBlocks);
    }

    [TestMethod]
    public void InputBlockSize_Get()
    {
        using ICryptoTransform transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
        Assert.AreEqual(BLOCKSIZE, transform.InputBlockSize);
    }

    [TestMethod]
    public void OutputBlockSize_Get()
    {
        using ICryptoTransform transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
        Assert.AreEqual(BLOCKSIZE, transform.InputBlockSize);
    }

    [TestMethod]
    [DataRow(0 * BLOCKSIZE)]
    [DataRow(1 * BLOCKSIZE)]
    [DataRow(2 * BLOCKSIZE)]
    [DataRow(10 * BLOCKSIZE)]
    public void TransformBlock_ValidSize(int size)
    {
        using ICryptoTransform transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
        var result = transform.TransformBlock(new byte[size], 0, size, new byte[size], 0);
        Assert.AreEqual(size, result);
    }

    [TestMethod]
    [DataRow(1)]
    [DataRow(BLOCKSIZE - 1)]
    [DataRow(BLOCKSIZE + 1)]
    public void TransformBlock_InvalidSizeFails(int size)
    {
        _ = Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
        {
            using ICryptoTransform transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
            _ = transform.TransformBlock(new byte[size], 0, size, new byte[size], 0);
        });
    }

    [TestMethod]
    public void TransformBlock_AfterFinalFails()
    {
        using ICryptoTransform transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
        _ = transform.TransformFinalBlock([], 0, 0);
        _ = Assert.ThrowsException<InvalidOperationException>(() =>
        {
            _ = transform.TransformBlock(new byte[BLOCKSIZE], 0, BLOCKSIZE, new byte[BLOCKSIZE], 0);
        });
    }

    [TestMethod]
    public void TransformBlock_AfterDisposeFails()
    {
        ICryptoTransform transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
        _ = transform.TransformBlock(new byte[BLOCKSIZE], 0, BLOCKSIZE, new byte[BLOCKSIZE], 0);
        transform.Dispose();
        _ = Assert.ThrowsException<ObjectDisposedException>(() =>
        {
            _ = transform.TransformBlock(new byte[BLOCKSIZE], 0, BLOCKSIZE, new byte[BLOCKSIZE], 0);
        });
    }

    [TestMethod]
    public void TransformBlock_TransformInvalidReturn()
    {
        var mockTransform = new Mock<ICryptoTransform>();
        _ = mockTransform.SetupGet(m => m.InputBlockSize).Returns(BLOCKSIZE);
        _ = mockTransform.SetupGet(m => m.OutputBlockSize).Returns(BLOCKSIZE);
        _ = mockTransform.SetupSequence(m => m.TransformBlock(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<byte[]>(), It.IsAny<int>()))
            .Returns(BLOCKSIZE)
            .Returns(BLOCKSIZE + 1);

        using ICryptoTransform transform = new AesCtrTransform(InitialCounter, mockTransform.Object);
        _ = transform.TransformBlock(new byte[BLOCKSIZE], 0, BLOCKSIZE, new byte[BLOCKSIZE], 0);
        _ = Assert.ThrowsException<CryptographicException>(() =>
        {
            _ = transform.TransformBlock(new byte[BLOCKSIZE], 0, BLOCKSIZE, new byte[BLOCKSIZE], 0);
        });
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(BLOCKSIZE - 1)]
    [DataRow(BLOCKSIZE)]
    public void TransformFinalBlock_ValidSize(int size)
    {
        using ICryptoTransform transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
        var result = transform.TransformFinalBlock(new byte[size], 0, size);
        Assert.AreEqual(size, result.Length);
    }

    [TestMethod]
    [DataRow(BLOCKSIZE + 1)]
    [DataRow(2 * BLOCKSIZE)]
    public void TransformFinalBlock_InvalidSizeFails(int size)
    {
        _ = Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
        {
            using ICryptoTransform transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
            _ = transform.TransformFinalBlock(new byte[size], 0, size);
        });
    }

    [TestMethod]
    public void TransformFinalBlock_AfterFinalFails()
    {
        using ICryptoTransform transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
        _ = transform.TransformFinalBlock([], 0, 0);
        _ = Assert.ThrowsException<InvalidOperationException>(() =>
        {
            _ = transform.TransformFinalBlock([], 0, 0);
        });
    }

    [TestMethod]
    public void TransformFinalBlock_AfterDisposeFails()
    {
        ICryptoTransform transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
        _ = transform.TransformBlock(new byte[BLOCKSIZE], 0, BLOCKSIZE, new byte[BLOCKSIZE], 0);
        transform.Dispose();
        _ = Assert.ThrowsException<ObjectDisposedException>(() =>
        {
            _ = transform.TransformFinalBlock([], 0, 0);
        });
    }

    [TestMethod]
    public void TransformFinalBlock_TransformInvalidReturn()
    {
        var mockTransform = new Mock<ICryptoTransform>();
        _ = mockTransform.SetupGet(m => m.InputBlockSize).Returns(BLOCKSIZE);
        _ = mockTransform.SetupGet(m => m.OutputBlockSize).Returns(BLOCKSIZE);
        _ = mockTransform.Setup(m => m.TransformFinalBlock(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>())).Returns(new byte[BLOCKSIZE + 1]);

        using ICryptoTransform transform = new AesCtrTransform(InitialCounter, mockTransform.Object);
        _ = Assert.ThrowsException<CryptographicException>(() =>
        {
            _ = transform.TransformFinalBlock(new byte[BLOCKSIZE], 0, BLOCKSIZE);
        });
    }
}

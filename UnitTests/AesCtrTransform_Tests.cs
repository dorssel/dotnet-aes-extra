namespace UnitTests;

[TestClass]
sealed class AesCtrTransform_Tests
{
    const int BLOCKSIZE = 16; // bytes

    readonly ICryptoTransform AesEcbTransform;
    readonly byte[] InitialCounter = new byte[BLOCKSIZE];

    public AesCtrTransform_Tests()
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        AesEcbTransform = aes.CreateEncryptor();
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
        Assert.ThrowsException<ArgumentException>(() =>
        {
            using var transform = new AesCtrTransform(new byte[ivSize], AesEcbTransform);
        });
    }

    [TestMethod]
    public void Constructor_TransformInvalidInputBlockSize()
    {
        Assert.ThrowsException<CryptographicException>(() =>
        {
            var mockTransform = new Mock<ICryptoTransform>();
            mockTransform.SetupGet(m => m.InputBlockSize).Returns(BLOCKSIZE + 1);
            mockTransform.SetupGet(m => m.OutputBlockSize).Returns(BLOCKSIZE);
            using var transform = new AesCtrTransform(InitialCounter, mockTransform.Object);
        });
    }

    [TestMethod]
    public void Constructor_TransformInvalidOutputBlockSize()
    {
        Assert.ThrowsException<CryptographicException>(() =>
        {
            var mockTransform = new Mock<ICryptoTransform>();
            mockTransform.SetupGet(m => m.InputBlockSize).Returns(BLOCKSIZE);
            mockTransform.SetupGet(m => m.OutputBlockSize).Returns(BLOCKSIZE + 1);
            using var transform = new AesCtrTransform(InitialCounter, mockTransform.Object);
        });
    }

    [TestMethod]
    public void CanReuseTransform_Get()
    {
        using ICryptoTransform transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
        Assert.AreEqual(false, transform.CanReuseTransform);
    }

    [TestMethod]
    public void CanTransformMultipleBlocks_Get()
    {
        using ICryptoTransform transform = new AesCtrTransform(InitialCounter, AesEcbTransform);
        Assert.AreEqual(true, transform.CanTransformMultipleBlocks);
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
}

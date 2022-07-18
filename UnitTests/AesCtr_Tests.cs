namespace UnitTests;

[TestClass]
sealed class AesCtr_Tests
{
    [TestMethod]
    public void Create()
    {
        using var aes = AesCtr.Create();
        Assert.IsNotNull(aes);
    }

    [TestMethod]
    public void Create_Name()
    {
        using var aes = AesCtr.Create("AesCtr");
        Assert.IsNotNull(aes);
    }

    [TestMethod]
    public void Create_NullNameFails()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            using var aes = AesCtr.Create(null!);
        });
    }

    [TestMethod]
    public void Create_OtherNameReturnsNull()
    {
        using var aes = AesCtr.Create("SomeOtherName");
        Assert.IsNull(aes);
    }

    [TestMethod]
    public void Dispose()
    {
        var aes = AesCtr.Create();
        aes.Dispose();
    }

    [TestMethod]
    public void Dispose_Double()
    {
        var aes = AesCtr.Create();
        aes.Dispose();
        aes.Dispose();
    }

    [TestMethod]
    public void Mode_SetUnchanged()
    {
        using var aes = AesCtr.Create();
        Assert.AreEqual(CipherMode.ECB, aes.Mode);
        aes.Mode = CipherMode.ECB;
        Assert.AreEqual(CipherMode.ECB, aes.Mode);
    }

    [TestMethod]
    public void Mode_CannotChange()
    {
        using var aes = AesCtr.Create();
        Assert.AreEqual(CipherMode.ECB, aes.Mode);
        Assert.ThrowsException<CryptographicException>(() =>
        {
            aes.Mode = CipherMode.CBC;
        });
        Assert.AreEqual(CipherMode.ECB, aes.Mode);
    }

    [TestMethod]
    public void Padding_SetUnchanged()
    {
        using var aes = AesCtr.Create();
        Assert.AreEqual(PaddingMode.None, aes.Padding);
        aes.Padding = PaddingMode.None;
        Assert.AreEqual(PaddingMode.None, aes.Padding);
    }

    [TestMethod]
    public void Padding_CannotChange()
    {
        using var aes = AesCtr.Create();
        var padding = aes.Padding;
        Assert.AreEqual(PaddingMode.None, padding);
        Assert.ThrowsException<CryptographicException>(() =>
        {
            aes.Padding = PaddingMode.PKCS7;
        });
        Assert.AreEqual(PaddingMode.None, padding);
    }

    [TestMethod]
    public void FeedbackSize_SetUnchanged()
    {
        using var aes = AesCtr.Create();
        Assert.AreEqual(aes.BlockSize, aes.FeedbackSize);
        aes.FeedbackSize = aes.BlockSize;
        Assert.AreEqual(aes.BlockSize, aes.FeedbackSize);
    }

    [TestMethod]
    public void FeedbackSize_CannotChange()
    {
        using var aes = AesCtr.Create();
        Assert.AreEqual(aes.BlockSize, aes.FeedbackSize);
        Assert.ThrowsException<CryptographicException>(() =>
        {
            aes.FeedbackSize = 8;
        });
        Assert.AreEqual(aes.BlockSize, aes.FeedbackSize);
    }

    [TestMethod]
    public void KeySize_AllValid()
    {
        using var aes = AesCtr.Create();
        foreach (var legalKeySize in aes.LegalKeySizes)
        {
            for (var keySize = legalKeySize.MinSize; keySize <= legalKeySize.MaxSize; keySize += Math.Max(legalKeySize.SkipSize, 1))
            {
                aes.KeySize = keySize;
                Assert.AreEqual(keySize, aes.KeySize);
                Assert.AreEqual(keySize, aes.Key.Length * 8);
            }
        }
    }

    [TestMethod]
    public void BlockSize_AllValid()
    {
        using var aes = AesCtr.Create();
        foreach (var legalBlockSize in aes.LegalBlockSizes)
        {
            for (var blockSize = legalBlockSize.MinSize; blockSize <= legalBlockSize.MaxSize; blockSize += Math.Max(legalBlockSize.SkipSize, 1))
            {
                aes.BlockSize = blockSize;
                Assert.AreEqual(blockSize, aes.BlockSize);
            }
        }
    }

    [TestMethod]
    [DataRow(128)]
    [DataRow(192)]
    [DataRow(256)]
    public void GenerateIV_HasCorrectLength(int keySize)
    {
        using var aes = AesCtr.Create();
        aes.KeySize = keySize;
        aes.GenerateIV();
        Assert.AreEqual(aes.BlockSize, aes.IV.Length * 8);
    }

    [TestMethod]
    [DataRow(128)]
    [DataRow(192)]
    [DataRow(256)]
    public void GenerateKey_HasCorrectLength(int keySize)
    {
        using var aes = AesCtr.Create();
        aes.KeySize = keySize;
        aes.GenerateKey();
        Assert.AreEqual(keySize, aes.Key.Length * 8);
    }

    [TestMethod]
    public void CreateEncryptor()
    {
        using var aes = AesCtr.Create();
        using var _ = aes.CreateEncryptor();
    }

    [TestMethod]
    public void CreateDecryptor()
    {
        using var aes = AesCtr.Create();
        using var _ = aes.CreateDecryptor();
    }
}

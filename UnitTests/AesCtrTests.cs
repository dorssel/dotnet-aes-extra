namespace UnitTests;

[TestClass]
public class AesCtrTests
{
    [TestMethod]
    public void Create()
    {
        using var aes = AesCtr.Create();
        Assert.IsNotNull(aes);
    }

    [TestMethod]
    public void CreateByName()
    {
        using var aes = AesCtr.Create("AesCtr");
        Assert.IsNotNull(aes);
    }

    [TestMethod]
    public void CreateByNullNameFails()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            using var aes = AesCtr.Create(null!);
        });
    }

    [TestMethod]
    public void CreateByOtherNameFails()
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
    public void DisposeTwice()
    {
        var aes = AesCtr.Create();
        aes.Dispose();
        aes.Dispose();
    }

    [TestMethod]
    public void ModeCannotChange()
    {
        using var aes = AesCtr.Create();
        var mode = aes.Mode;
        Assert.AreEqual(CipherMode.ECB, mode);
        Assert.ThrowsException<CryptographicException>(() =>
        {
            aes.Mode = CipherMode.CBC;
        });
        Assert.AreEqual(CipherMode.ECB, mode);
    }

    [TestMethod]
    public void PaddingCannotChange()
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
    public void FeedbackSizeCannotChange()
    {
        using var aes = AesCtr.Create();
        var feedbackSize = aes.FeedbackSize;
        Assert.AreEqual(aes.BlockSize, feedbackSize);
        Assert.ThrowsException<CryptographicException>(() =>
        {
            aes.FeedbackSize = 8;
        });
        Assert.AreEqual(aes.BlockSize, feedbackSize);
    }

    [TestMethod]
    [DataRow(128)]
    [DataRow(192)]
    [DataRow(256)]
    public void GenerateIVHasCorrectLength(int keySize)
    {
        using var aes = AesCtr.Create();
        aes.KeySize = keySize;
        aes.GenerateIV();
        Assert.AreEqual(aes.BlockSize, aes.IV.Length * 8);
    }

    [TestMethod]
    public void GenerateIVAfterDisposeFails()
    {
        var aes = AesCtr.Create();
        aes.Dispose();
        Assert.ThrowsException<ObjectDisposedException>(() =>
        {
            aes.GenerateIV();
        });
    }

    [TestMethod]
    [DataRow(128)]
    [DataRow(192)]
    [DataRow(256)]
    public void GenerateKeyHasCorrectLength(int keySize)
    {
        using var aes = AesCtr.Create();
        aes.KeySize = keySize;
        aes.GenerateKey();
        Assert.AreEqual(keySize, aes.Key.Length * 8);
    }

    [TestMethod]
    public void GenerateKeyAfterDisposeFails()
    {
        var aes = AesCtr.Create();
        aes.Dispose();
        Assert.ThrowsException<ObjectDisposedException>(() =>
        {
            aes.GenerateKey();
        });
    }

    [TestMethod]
    public void CreateEncryptor()
    {
        using var aes = AesCtr.Create();
        aes.CreateEncryptor();
    }

    [TestMethod]
    public void CreateEncryptorAfterDisposeFails()
    {
        var aes = AesCtr.Create();
        aes.Dispose();
        Assert.ThrowsException<ObjectDisposedException>(() =>
        {
            aes.CreateEncryptor();
        });
    }

    [TestMethod]
    public void CreateDecryptor()
    {
        using var aes = AesCtr.Create();
        aes.CreateDecryptor();
    }

    [TestMethod]
    public void CreateDecryptorAfterDisposeFails()
    {
        var aes = AesCtr.Create();
        aes.Dispose();
        Assert.ThrowsException<ObjectDisposedException>(() =>
        {
            aes.CreateDecryptor();
        });
    }
}

// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

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
        Assert.AreEqual(CipherMode.CTS, aes.Mode);  // DevSkim: ignore DS187371
        aes.Mode = CipherMode.CTS;  // DevSkim: ignore DS187371
        Assert.AreEqual(CipherMode.CTS, aes.Mode);  // DevSkim: ignore DS187371
    }

    [TestMethod]
    public void Mode_CannotChange()
    {
        using var aes = AesCtr.Create();
        Assert.AreEqual(CipherMode.CTS, aes.Mode);  // DevSkim: ignore DS187371
        Assert.ThrowsException<CryptographicException>(() =>
        {
            aes.Mode = CipherMode.CBC;
        });
        Assert.AreEqual(CipherMode.CTS, aes.Mode);  // DevSkim: ignore DS187371
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
    public void CreateEncryptor_WithKeyAndDefaultIV()
    {
        using var aes = AesCtr.Create();
        using var _ = aes.CreateEncryptor(new byte[16], null);
    }

    [TestMethod]
    public void CreateDecryptor()
    {
        using var aes = AesCtr.Create();
        using var _ = aes.CreateDecryptor();
    }

    [TestMethod]
    public void CreateDecryptor_WithKeyAndDefaultIV()
    {
        using var aes = AesCtr.Create();
        using var _ = aes.CreateDecryptor(new byte[16], null);
    }

    [TestMethod]
    public void EncryptCtr_WithDefaultIV()
    {
        using var aes = AesCtr.Create();
        aes.Key = new byte[128 / 8];

        var fromDefaultIV = aes.EncryptCtr([1, 2, 3]);

        aes.IV = new byte[16];

        var fromExplicitIV = aes.EncryptCtr([1, 2, 3]);

        CollectionAssert.AreEqual(fromExplicitIV, fromDefaultIV);
    }

    [TestMethod]
    public void EncryptCtr_DestinationShort()
    {
        using var aes = AesCtr.Create();
        Assert.ThrowsException<ArgumentException>(() =>
        {
            aes.EncryptCtr([3, 3, 3], new byte[2]);
        });
    }

    [TestMethod]
    public void DecryptCtr_DestinationShort()
    {
        using var aes = AesCtr.Create();
        Assert.ThrowsException<ArgumentException>(() =>
        {
            aes.DecryptCtr([3, 3, 3], new byte[2]);
        });
    }

    [TestMethod]
    public void TryEncryptCtr_DestinationShort()
    {
        using var aes = AesCtr.Create();
        Assert.IsFalse(aes.TryEncryptCtr([3, 3, 3], new byte[2], out var bytesWritten));
        Assert.AreEqual(0, bytesWritten);
    }

    [TestMethod]
    public void TryDecryptCtr_DestinationShort()
    {
        using var aes = AesCtr.Create();
        Assert.IsFalse(aes.TryEncryptCtr([3, 3, 3], new byte[2], out var bytesWritten));
        Assert.AreEqual(0, bytesWritten);
    }

    [TestMethod]
    public void TryEncryptCtr_PartialBlock()
    {
        using var aes = AesCtr.Create();
        Assert.IsTrue(aes.TryEncryptCtr([5, 5, 5, 5, 5], new byte[5], out var bytesWritten));
        Assert.AreEqual(5, bytesWritten);
    }

    [TestMethod]
    public void TryDecryptCtr_PartialBlock()
    {
        using var aes = AesCtr.Create();
        Assert.IsTrue(aes.TryDecryptCtr([5, 5, 5, 5, 5], new byte[5], out var bytesWritten));
        Assert.AreEqual(5, bytesWritten);
    }
}

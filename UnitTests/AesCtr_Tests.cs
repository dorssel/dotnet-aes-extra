// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class AesCtr_Tests
{
    const int BLOCKSIZE = 16;  // bytes

    static readonly byte[] TestKey =
        [
            31, 32, 33, 34, 35, 36, 37, 38,
            41, 42, 43, 44, 45, 46, 47, 48,
            51, 52, 53, 54, 55, 56, 57, 58
        ];

    static readonly byte[] TestIV =
        [
            61, 62, 63, 64, 65, 66, 67, 68,
            71, 72, 73, 74, 75, 76, 77, 78
        ];

    static readonly byte[] TestMessage = [1, 2, 3, 4, 5];

    static readonly byte[] TestInvalidIV = new byte[BLOCKSIZE - 1];

    [TestMethod]
    public void Create()
    {
        using var aes = AesCtr.Create();
        Assert.IsNotNull(aes);
    }

    [TestMethod]
    public void Create_Name()
    {
#pragma warning disable CS0618 // Type or member is obsolete
        using var aes = AesCtr.Create("AesCtr");
#pragma warning restore CS0618 // Type or member is obsolete
        Assert.IsNotNull(aes);
    }

    [TestMethod]
    public void Create_NullNameFails()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
#pragma warning disable CS0618 // Type or member is obsolete
            using var aes = AesCtr.Create(null!);
#pragma warning restore CS0618 // Type or member is obsolete
        });
    }

    [TestMethod]
    public void Create_OtherNameReturnsNull()
    {
#pragma warning disable CS0618 // Type or member is obsolete
        using var aes = AesCtr.Create("SomeOtherName");
#pragma warning restore CS0618 // Type or member is obsolete
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
    public void CreateEncryptor_Null()
    {
        using var aes = AesCtr.Create();
        Assert.ThrowsException<CryptographicException>(() =>
        {
            using var _ = aes.CreateEncryptor(TestKey, null);
        });
    }

    [TestMethod]
    public void CreateDecryptor()
    {
        using var aes = AesCtr.Create();
        using var _ = aes.CreateDecryptor();
    }

    [TestMethod]
    public void CreateDecryptor_Null()
    {
        using var aes = AesCtr.Create();
        Assert.ThrowsException<CryptographicException>(() =>
        {
            using var _ = aes.CreateDecryptor(TestKey, null);
        });
    }

    [TestMethod]
    public void TransformCtr_Array_Array()
    {
        using var aes = AesCtr.Create();

        aes.TransformCtr(TestMessage, TestIV);
    }

    [TestMethod]
    public void TransformCtr_Null_Array()
    {
        using var aes = AesCtr.Create();

        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            aes.TransformCtr(null!, TestIV);
        });
    }

    [TestMethod]
    public void TransformCtr_Array_Null()
    {
        using var aes = AesCtr.Create();

        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            aes.TransformCtr(TestMessage, null!);
        });
    }

    [TestMethod]
    public void TransformCtr_Array_Array_InvalidIV()
    {
        using var aes = AesCtr.Create();

        Assert.ThrowsException<ArgumentException>(() =>
        {
            aes.TransformCtr(TestMessage, TestInvalidIV);
        });
    }

    [TestMethod]
    public void TransformCtr_ReadOnlySpan_ReadOnlySpan()
    {
        using var aes = AesCtr.Create();

        aes.TransformCtr(TestMessage.AsSpan(), TestIV.AsSpan());
    }

    [TestMethod]
    public void TransformCtr_ReadOnlySpan_ReadOnlySpan_InvalidIV()
    {
        using var aes = AesCtr.Create();

        Assert.ThrowsException<ArgumentException>(() =>
        {
            aes.TransformCtr(TestMessage.AsSpan(), TestInvalidIV.AsSpan());
        });
    }

    [TestMethod]
    public void TransformCtr_ReadOnlySpan_ReadOnlySpan_Span()
    {
        using var aes = AesCtr.Create();
        var destination = new byte[TestMessage.Length];

        aes.TransformCtr(TestMessage.AsSpan(), TestIV.AsSpan(), destination);
    }

    [TestMethod]
    public void TransformCtr_ReadOnlySpan_ReadOnlySpan_Span_InvalidIV()
    {
        using var aes = AesCtr.Create();
        var destination = new byte[TestMessage.Length];

        Assert.ThrowsException<ArgumentException>(() =>
        {
            aes.TransformCtr(TestMessage, TestInvalidIV, destination);
        });
    }

    [TestMethod]
    public void TransformCtr_ReadOnlySpan_ReadOnlySpan_Span_Short()
    {
        using var aes = AesCtr.Create();
        var destination = new byte[TestMessage.Length - 1];

        Assert.ThrowsException<ArgumentException>(() =>
        {
            aes.TransformCtr(TestMessage, TestIV, destination);
        });
    }

    [TestMethod]
    public void TryTransformCtr()
    {
        using var aes = AesCtr.Create();
        var destination = new byte[TestMessage.Length];

        aes.TryTransformCtr(TestMessage.AsSpan(), TestIV.AsSpan(), destination, out _);
    }

    [TestMethod]
    public void TryTransformCtr_InvalidIV()
    {
        using var aes = AesCtr.Create();
        var destination = new byte[TestMessage.Length];

        Assert.ThrowsException<ArgumentException>(() =>
        {
            aes.TryTransformCtr(TestMessage.AsSpan(), TestInvalidIV, destination, out _);
        });
    }

    [TestMethod]
    public void TryTransformCtr_Short()
    {
        using var aes = AesCtr.Create();
        var destination = new byte[TestMessage.Length - 1];

        var success = aes.TryTransformCtr(TestMessage, TestIV, destination, out var bytesWritten);

        Assert.IsFalse(success);
        Assert.AreEqual(0, bytesWritten);
    }
}

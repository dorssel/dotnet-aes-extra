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

    static readonly byte[] TestIVInvalid = new byte[BLOCKSIZE - 1];

    static byte[] TestKeyNull => null!;

    static byte[] TestIVNull => null!;

    [TestMethod]
    public void RegisterWithCryptoConfig()
    {
        AesCtr.RegisterWithCryptoConfig();
        using var aes = (AesCtr?)CryptoConfig.CreateFromName("AesCtr");
        Assert.IsNotNull(aes);
    }

    [TestMethod]
    public void RegisterWithCryptoConfig_Twice()
    {
        AesCtr.RegisterWithCryptoConfig();
        AesCtr.RegisterWithCryptoConfig();
        using var aes = (AesCtr?)CryptoConfig.CreateFromName("Dorssel.Security.Cryptography.AesCtr");
        Assert.IsNotNull(aes);
    }

    [TestMethod]
    public void Create()
    {
#pragma warning disable CS0618 // Type or member is obsolete
        using var aesCtr = AesCtr.Create();
#pragma warning restore CS0618 // Type or member is obsolete
        Assert.IsNotNull(aesCtr);
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
    public void Create_FullName()
    {
#pragma warning disable CS0618 // Type or member is obsolete
        using var aes = AesCtr.Create("Dorssel.Security.Cryptography.AesCtr");
#pragma warning restore CS0618 // Type or member is obsolete
        Assert.IsNotNull(aes);
    }


    [TestMethod]
    public void Create_NullNameFails()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
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
    public void Constructor()
    {
        using var aes = new AesCtr();

        Assert.AreEqual(256, aes.KeySize);
        Assert.AreEqual(256 / 8, aes.Key.Length);
        CollectionAssert.AreNotEqual(new byte[aes.Key.Length], aes.Key);
        Assert.AreEqual(256, aes.KeySize);
    }

    [TestMethod]
    [DataRow(128)]
    [DataRow(192)]
    [DataRow(256)]
    public void Constructor_Int(int keySize)
    {
        using var aes = new AesCtr(keySize);

        Assert.AreEqual(keySize, aes.KeySize);
        Assert.AreEqual(keySize / 8, aes.Key.Length);
        CollectionAssert.AreNotEqual(new byte[aes.Key.Length], aes.Key);
        Assert.AreEqual(keySize, aes.KeySize);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(16)]
    [DataRow(24)]
    [DataRow(32)]
    public void Constructor_Int_Invalid(int keySize)
    {
        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            using var aes = new AesCtr(keySize);
        });
    }

    [TestMethod]
    [DataRow(128)]
    [DataRow(192)]
    [DataRow(256)]
    public void Constructor_Array(int keySize)
    {
        using var aes = new AesCtr(new byte[keySize / 8]);

        Assert.AreEqual(keySize, aes.KeySize);
        Assert.AreEqual(keySize / 8, aes.Key.Length);
        Assert.AreEqual(keySize, aes.KeySize);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(16)]
    [DataRow(24)]
    [DataRow(32)]
    public void Constructor_Array_Invalid(int keySize)
    {
        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            using var aes = new AesCtr(new byte[keySize / 8]);
        });
    }

    [TestMethod]
    public void Constructor_Array_Null()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            using var aes = new AesCtr(TestKeyNull);
        });
    }

    [TestMethod]
    [DataRow(128)]
    [DataRow(192)]
    [DataRow(256)]
    public void Constructor_ReadOnlySpan(int keySize)
    {
        using var aes = new AesCtr(new byte[keySize / 8].AsSpan());

        Assert.AreEqual(keySize, aes.KeySize);
        Assert.AreEqual(keySize / 8, aes.Key.Length);
        Assert.AreEqual(keySize, aes.KeySize);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(16)]
    [DataRow(24)]
    [DataRow(32)]
    public void Constructor_ReadOnlySpan_Invalid(int keySize)
    {
        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            using var aes = new AesCtr(new byte[keySize / 8].AsSpan());
        });
    }

    [TestMethod]
    [DataRow(128)]
    [DataRow(192)]
    [DataRow(256)]
    public void Constructor_Array_Array(int keySize)
    {
        using var aes = new AesCtr(new byte[keySize / 8], TestIV);

        Assert.AreEqual(keySize, aes.KeySize);
        Assert.AreEqual(keySize / 8, aes.Key.Length);
        Assert.AreEqual(keySize, aes.KeySize);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(16)]
    [DataRow(24)]
    [DataRow(32)]
    public void Constructor_Array_Array_KeyInvalid(int keySize)
    {
        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            using var aes = new AesCtr(new byte[keySize / 8], TestIV);
        });
    }

    [TestMethod]
    public void Constructor_Array_Array_KeyNull()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            using var aes = new AesCtr(TestKeyNull, TestIV);
        });
    }

    [TestMethod]
    public void Constructor_Array_Array_IVInvalid()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using var aes = new AesCtr(TestKey, TestIVInvalid);
        });
    }

    [TestMethod]
    public void Constructor_Array_Array_IVNull()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            using var aes = new AesCtr(TestKey, TestIVNull);
        });
    }

    [TestMethod]
    [DataRow(128)]
    [DataRow(192)]
    [DataRow(256)]
    public void Constructor_ReadOnlySpan_ReadOnlySpan(int keySize)
    {
        using var aes = new AesCtr(new byte[keySize / 8].AsSpan(), TestIV.AsSpan());

        Assert.AreEqual(keySize, aes.KeySize);
        Assert.AreEqual(keySize / 8, aes.Key.Length);
        Assert.AreEqual(keySize, aes.KeySize);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(16)]
    [DataRow(24)]
    [DataRow(32)]
    public void Constructor_ReadOnlySpan_ReadOnlySpan_KeyInvalid(int keySize)
    {
        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            using var aes = new AesCtr(new byte[keySize / 8].AsSpan(), TestIV.AsSpan());
        });
    }

    [TestMethod]
    public void Constructor_ReadOnlySpan_ReadOnlySpan_IVInvalid()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using var aes = new AesCtr(TestKey.AsSpan(), TestIVInvalid.AsSpan());
        });
    }

    [TestMethod]
    public void Dispose()
    {
        var aes = new AesCtr();
        aes.Dispose();
    }

    [TestMethod]
    public void Dispose_Double()
    {
        var aes = new AesCtr();
        aes.Dispose();
        aes.Dispose();
    }

    [TestMethod]
    public void Mode_SetUnchanged()
    {
        using var aes = new AesCtr();
        Assert.AreEqual(CipherMode.CTS, aes.Mode);  // DevSkim: ignore DS187371
        aes.Mode = CipherMode.CTS;  // DevSkim: ignore DS187371
        Assert.AreEqual(CipherMode.CTS, aes.Mode);  // DevSkim: ignore DS187371
    }

    [TestMethod]
    public void Mode_CannotChange()
    {
        using var aes = new AesCtr();
        Assert.AreEqual(CipherMode.CTS, aes.Mode);  // DevSkim: ignore DS187371
        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            aes.Mode = CipherMode.CBC;
        });
        Assert.AreEqual(CipherMode.CTS, aes.Mode);  // DevSkim: ignore DS187371
    }

    [TestMethod]
    public void Padding_SetUnchanged()
    {
        using var aes = new AesCtr();
        Assert.AreEqual(PaddingMode.None, aes.Padding);
        aes.Padding = PaddingMode.None;
        Assert.AreEqual(PaddingMode.None, aes.Padding);
    }

    [TestMethod]
    public void Padding_CannotChange()
    {
        using var aes = new AesCtr();
        var padding = aes.Padding;
        Assert.AreEqual(PaddingMode.None, padding);
        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            aes.Padding = PaddingMode.PKCS7;
        });
        Assert.AreEqual(PaddingMode.None, padding);
    }

    [TestMethod]
    public void FeedbackSize_SetUnchanged()
    {
        using var aes = new AesCtr();
        Assert.AreEqual(aes.BlockSize, aes.FeedbackSize);
        aes.FeedbackSize = aes.BlockSize;
        Assert.AreEqual(aes.BlockSize, aes.FeedbackSize);
    }

    [TestMethod]
    public void FeedbackSize_CannotChange()
    {
        using var aes = new AesCtr();
        Assert.AreEqual(aes.BlockSize, aes.FeedbackSize);
        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            aes.FeedbackSize = 8;
        });
        Assert.AreEqual(aes.BlockSize, aes.FeedbackSize);
    }

    [TestMethod]
    public void KeySize_AllValid()
    {
        using var aes = new AesCtr();
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
    public void Key_AllValid()
    {
        using var aes = new AesCtr();
        foreach (var legalKeySize in aes.LegalKeySizes)
        {
            for (var keySize = legalKeySize.MinSize; keySize <= legalKeySize.MaxSize; keySize += Math.Max(legalKeySize.SkipSize, 1))
            {
                aes.Key = new byte[keySize / 8];
                Assert.AreEqual(keySize, aes.KeySize);
                Assert.AreEqual(keySize, aes.Key.Length * 8);
            }
        }
    }

    [TestMethod]
    public void Key_Null()
    {
        using var aes = new AesCtr();

        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            aes.Key = TestKeyNull;
        });
    }

    [TestMethod]
    public void Key_AfterDispose()
    {
        using var aes = new AesCtr();
        aes.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() =>
        {
            aes.Key = TestKey;
        });
    }

    [TestMethod]
    public void IV()
    {
        using var aes = new AesCtr();

        aes.IV = TestIV;
        CollectionAssert.AreEqual(TestIV, aes.IV);
    }

    [TestMethod]
    public void IV_Null()
    {
        using var aes = new AesCtr();

        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            aes.IV = TestIVNull;
        });
    }

    [TestMethod]
    public void IV_AfterDispose()
    {
        using var aes = new AesCtr();
        aes.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() =>
        {
            aes.IV = TestIV;
        });
    }

    [TestMethod]
    public void BlockSize_AllValid()
    {
        using var aes = new AesCtr();
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
        using var aes = new AesCtr();
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
        using var aes = new AesCtr();
        aes.KeySize = keySize;
        aes.GenerateKey();
        Assert.AreEqual(keySize, aes.Key.Length * 8);
    }

    [TestMethod]
    public void CreateEncryptor()
    {
        using var aes = new AesCtr();
        using var _ = aes.CreateEncryptor();
    }

    [TestMethod]
    public void CreateEncryptor_Array_Array()
    {
        using var aes = new AesCtr();
        using var _ = aes.CreateEncryptor(TestKey, TestIV);
    }

    [TestMethod]
    public void CreateEncryptor_Array_Array_KeyNull()
    {
        using var aes = new AesCtr();
        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            using var _ = aes.CreateEncryptor(TestKeyNull, TestIV);
        });
    }

    [TestMethod]
    public void CreateEncryptor_Array_Array_IVNull()
    {
        using var aes = new AesCtr();
        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            using var _ = aes.CreateEncryptor(TestKey, TestIVNull);
        });
    }

    [TestMethod]
    public void CreateDecryptor()
    {
        using var aes = new AesCtr();
        using var _ = aes.CreateDecryptor();
    }

    [TestMethod]
    public void CreateDecryptor_Array_Array()
    {
        using var aes = new AesCtr();
        using var _ = aes.CreateDecryptor(TestKey, TestIV);
    }

    [TestMethod]
    public void CreateDecryptor_Array_Array_KeyNull()
    {
        using var aes = new AesCtr();
        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            using var _ = aes.CreateDecryptor(TestKeyNull, TestIV);
        });
    }

    [TestMethod]
    public void CreateDecryptor_Array_Array_IVNull()
    {
        using var aes = new AesCtr();
        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            using var _ = aes.CreateDecryptor(TestKey, TestIVNull);
        });
    }

    [TestMethod]
    public void TransformCtr_Array_Array()
    {
        using var aes = new AesCtr();

        aes.TransformCtr(TestMessage, TestIV);
    }

    [TestMethod]
    public void TransformCtr_Null_Array()
    {
        using var aes = new AesCtr();

        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            aes.TransformCtr(TestKeyNull, TestIV);
        });
    }

    [TestMethod]
    public void TransformCtr_Array_Null()
    {
        using var aes = new AesCtr();

        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            aes.TransformCtr(TestMessage, TestIVNull);
        });
    }

    [TestMethod]
    public void TransformCtr_Array_Array_InvalidIV()
    {
        using var aes = new AesCtr();

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aes.TransformCtr(TestMessage, TestIVInvalid);
        });
    }

    [TestMethod]
    public void TransformCtr_ReadOnlySpan_ReadOnlySpan()
    {
        using var aes = new AesCtr();

        aes.TransformCtr(TestMessage.AsSpan(), TestIV.AsSpan());
    }

    [TestMethod]
    public void TransformCtr_ReadOnlySpan_ReadOnlySpan_InvalidIV()
    {
        using var aes = new AesCtr();

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aes.TransformCtr(TestMessage.AsSpan(), TestIVInvalid.AsSpan());
        });
    }

    [TestMethod]
    public void TransformCtr_ReadOnlySpan_ReadOnlySpan_Span()
    {
        using var aes = new AesCtr();
        var destination = new byte[TestMessage.Length];

        aes.TransformCtr(TestMessage.AsSpan(), TestIV.AsSpan(), destination);
    }

    [TestMethod]
    public void TransformCtr_ReadOnlySpan_ReadOnlySpan_Span_InvalidIV()
    {
        using var aes = new AesCtr();
        var destination = new byte[TestMessage.Length];

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aes.TransformCtr(TestMessage, TestIVInvalid, destination);
        });
    }

    [TestMethod]
    public void TransformCtr_ReadOnlySpan_ReadOnlySpan_Span_Short()
    {
        using var aes = new AesCtr();
        var destination = new byte[TestMessage.Length - 1];

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aes.TransformCtr(TestMessage, TestIV, destination);
        });
    }

    [TestMethod]
    public void TryTransformCtr()
    {
        using var aes = new AesCtr();
        var destination = new byte[TestMessage.Length];

        aes.TryTransformCtr(TestMessage.AsSpan(), TestIV.AsSpan(), destination, out _);
    }

    [TestMethod]
    public void TryTransformCtr_InvalidIV()
    {
        using var aes = new AesCtr();
        var destination = new byte[TestMessage.Length];

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aes.TryTransformCtr(TestMessage.AsSpan(), TestIVInvalid, destination, out _);
        });
    }

    [TestMethod]
    public void TryTransformCtr_Short()
    {
        using var aes = new AesCtr();
        var destination = new byte[TestMessage.Length - 1];

        var success = aes.TryTransformCtr(TestMessage, TestIV, destination, out var bytesWritten);

        Assert.IsFalse(success);
        Assert.AreEqual(0, bytesWritten);
    }
}

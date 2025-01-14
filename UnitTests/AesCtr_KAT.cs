// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class AesCtr_KAT
{
    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void Encrypt_Write(NistAesCtrSampleTestVector testVector)
    {
        using var aes = new AesCtr(testVector.Key.Span, testVector.InitialCounter.Span);
        using var plaintextStream = new MemoryStream(testVector.Plaintext.ToArray());
        using var ciphertextStream = new MemoryStream();
        {
            using var encryptor = aes.CreateEncryptor();
            using var encryptorStream = new CryptoStream(ciphertextStream, encryptor, CryptoStreamMode.Write);
            plaintextStream.CopyTo(encryptorStream);
        }
        CollectionAssert.AreEqual(testVector.Ciphertext.ToArray(), ciphertextStream.ToArray());
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void Encrypt_Read(NistAesCtrSampleTestVector testVector)
    {
        using var aes = new AesCtr(testVector.Key.Span, testVector.InitialCounter.Span);
        using var plaintextStream = new MemoryStream(testVector.Plaintext.ToArray());
        using var ciphertextStream = new MemoryStream();
        {
            using var encryptor = aes.CreateEncryptor();
            using var encryptorStream = new CryptoStream(plaintextStream, encryptor, CryptoStreamMode.Read);
            encryptorStream.CopyTo(ciphertextStream);
        }
        CollectionAssert.AreEqual(testVector.Ciphertext.ToArray(), ciphertextStream.ToArray());
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void Decrypt_Write(NistAesCtrSampleTestVector testVector)
    {
        using var aes = new AesCtr(testVector.Key.Span, testVector.InitialCounter.Span);
        using var ciphertextStream = new MemoryStream(testVector.Ciphertext.ToArray());
        using var plaintextStream = new MemoryStream();
        {
            using var decryptor = aes.CreateDecryptor();
            using var decryptorStream = new CryptoStream(plaintextStream, decryptor, CryptoStreamMode.Write);
            ciphertextStream.CopyTo(decryptorStream);
        }
        CollectionAssert.AreEqual(testVector.Plaintext.ToArray(), plaintextStream.ToArray());
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void Decrypt_Read(NistAesCtrSampleTestVector testVector)
    {
        using var aes = new AesCtr(testVector.Key.Span, testVector.InitialCounter.Span);
        using var ciphertextStream = new MemoryStream(testVector.Ciphertext.ToArray());
        using var plaintextStream = new MemoryStream();
        {
            using var decryptor = aes.CreateDecryptor();
            using var decryptorStream = new CryptoStream(ciphertextStream, decryptor, CryptoStreamMode.Read);
            decryptorStream.CopyTo(plaintextStream);
        }
        CollectionAssert.AreEqual(testVector.Plaintext.ToArray(), plaintextStream.ToArray());
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void Encrypt_TransformCtr_Array_Array(NistAesCtrSampleTestVector testVector)
    {
        using var aes = new AesCtr(testVector.Key.Span);

        var destination = aes.TransformCtr(testVector.Plaintext.ToArray(), testVector.InitialCounter.ToArray());

        CollectionAssert.AreEqual(testVector.Ciphertext.ToArray(), destination);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void Encrypt_TransformCtr_ReadOnlySpan_ReadOnlySpan(NistAesCtrSampleTestVector testVector)
    {
        using var aes = new AesCtr(testVector.Key.Span);

        var destination = aes.TransformCtr(testVector.Plaintext.Span, testVector.InitialCounter.Span);

        CollectionAssert.AreEqual(testVector.Ciphertext.ToArray(), destination);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void Encrypt_TransformCtr_ReadOnlySpan_ReadOnlySpan_Span(NistAesCtrSampleTestVector testVector)
    {
        using var aes = new AesCtr(testVector.Key.Span);
        var destination = new byte[testVector.Ciphertext.Length];

        var count = aes.TransformCtr(testVector.Plaintext.Span, testVector.InitialCounter.Span, destination);

        Assert.AreEqual(testVector.Ciphertext.Length, count);
        CollectionAssert.AreEqual(testVector.Ciphertext.ToArray(), destination);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void Encrypt_TryTransformCtr(NistAesCtrSampleTestVector testVector)
    {
        using var aes = new AesCtr(testVector.Key.Span);
        var destination = new byte[testVector.Ciphertext.Length];

        var success = aes.TryTransformCtr(testVector.Plaintext.Span, testVector.InitialCounter.Span, destination, out var bytesWritten);

        Assert.IsTrue(success);
        Assert.AreEqual(testVector.Ciphertext.Length, bytesWritten);
        CollectionAssert.AreEqual(testVector.Ciphertext.ToArray(), destination);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void Decrypt_TransformCtr_Array_Array(NistAesCtrSampleTestVector testVector)
    {
        using var aes = new AesCtr(testVector.Key.Span);

        var destination = aes.TransformCtr(testVector.Ciphertext.ToArray(), testVector.InitialCounter.ToArray());

        CollectionAssert.AreEqual(testVector.Plaintext.ToArray(), destination);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void Decrypt_TransformCtr_ReadOnlySpan_ReadOnlySpan(NistAesCtrSampleTestVector testVector)
    {
        using var aes = new AesCtr(testVector.Key.Span);

        var destination = aes.TransformCtr(testVector.Ciphertext.Span, testVector.InitialCounter.Span);

        CollectionAssert.AreEqual(testVector.Plaintext.ToArray(), destination);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void Decrypt_TransformCtr_ReadOnlySpan_ReadOnlySpan_Span(NistAesCtrSampleTestVector testVector)
    {
        using var aes = new AesCtr(testVector.Key.Span);
        var destination = new byte[testVector.Plaintext.Length];

        var count = aes.TransformCtr(testVector.Ciphertext.Span, testVector.InitialCounter.Span, destination);

        Assert.AreEqual(testVector.Plaintext.Length, count);
        CollectionAssert.AreEqual(testVector.Plaintext.ToArray(), destination);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void Decrypt_TryTransformCtr(NistAesCtrSampleTestVector testVector)
    {
        using var aes = new AesCtr(testVector.Key.Span);
        var destination = new byte[testVector.Plaintext.Length];

        var success = aes.TryTransformCtr(testVector.Ciphertext.Span, testVector.InitialCounter.Span, destination, out var bytesWritten);

        Assert.IsTrue(success);
        Assert.AreEqual(testVector.Plaintext.Length, bytesWritten);
        CollectionAssert.AreEqual(testVector.Plaintext.ToArray(), destination);
    }
}

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
        using var aes = AesCtr.Create();
        aes.Key = testVector.Key.ToArray();
        aes.IV = testVector.InitialCounter.ToArray();
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
        using var aes = AesCtr.Create();
        aes.Key = testVector.Key.ToArray();
        aes.IV = testVector.InitialCounter.ToArray();
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
    public void EncryptCtr_Bytes(NistAesCtrSampleTestVector testVector)
    {
        using var aes = AesCtr.Create();
        aes.Key = testVector.Key.ToArray();
        aes.IV = testVector.InitialCounter.ToArray();
        var ciphertext = aes.EncryptCtr(testVector.Plaintext.ToArray());
        CollectionAssert.AreEqual(testVector.Ciphertext.ToArray(), ciphertext);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void EncryptCtr_Span(NistAesCtrSampleTestVector testVector)
    {
        using var aes = AesCtr.Create();
        aes.Key = testVector.Key.ToArray();
        aes.IV = testVector.InitialCounter.ToArray();
        var ciphertext = aes.EncryptCtr(testVector.Plaintext.Span);
        CollectionAssert.AreEqual(testVector.Ciphertext.ToArray(), ciphertext);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void EncryptCtr_Destination(NistAesCtrSampleTestVector testVector)
    {
        using var aes = AesCtr.Create();
        aes.Key = testVector.Key.ToArray();
        aes.IV = testVector.InitialCounter.ToArray();
        var ciphertext = new byte[testVector.Plaintext.Length];
        var count = aes.EncryptCtr(testVector.Plaintext.Span, ciphertext);
        CollectionAssert.AreEqual(testVector.Ciphertext.ToArray(), ciphertext.ToArray());
        Assert.AreEqual(testVector.Plaintext.Length, count);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void Decrypt_Write(NistAesCtrSampleTestVector testVector)
    {
        using var aes = AesCtr.Create();
        aes.Key = testVector.Key.ToArray();
        aes.IV = testVector.InitialCounter.ToArray();
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
        using var aes = AesCtr.Create();
        aes.Key = testVector.Key.ToArray();
        aes.IV = testVector.InitialCounter.ToArray();
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
    public void DecryptCtr_Bytes(NistAesCtrSampleTestVector testVector)
    {
        using var aes = AesCtr.Create();
        aes.Key = testVector.Key.ToArray();
        aes.IV = testVector.InitialCounter.ToArray();
        var plaintext = aes.DecryptCtr(testVector.Ciphertext.ToArray());
        CollectionAssert.AreEqual(testVector.Plaintext.ToArray(), plaintext);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void DecryptCtr_Span(NistAesCtrSampleTestVector testVector)
    {
        using var aes = AesCtr.Create();
        aes.Key = testVector.Key.ToArray();
        aes.IV = testVector.InitialCounter.ToArray();
        var plaintext = aes.DecryptCtr(testVector.Ciphertext.Span);
        CollectionAssert.AreEqual(testVector.Plaintext.ToArray(), plaintext);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource]
    public void DecryptCtr_Destination(NistAesCtrSampleTestVector testVector)
    {
        using var aes = AesCtr.Create();
        aes.Key = testVector.Key.ToArray();
        aes.IV = testVector.InitialCounter.ToArray();
        var plaintext = new byte[testVector.Ciphertext.Length];
        var count = aes.DecryptCtr(testVector.Ciphertext.Span, plaintext);
        CollectionAssert.AreEqual(testVector.Plaintext.ToArray(), plaintext.ToArray());
        Assert.AreEqual(testVector.Ciphertext.Length, count);
    }
}

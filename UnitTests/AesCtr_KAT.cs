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
        Assert.IsTrue(Enumerable.SequenceEqual(testVector.Ciphertext.ToArray(), ciphertextStream.ToArray()));
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
        Assert.IsTrue(Enumerable.SequenceEqual(testVector.Ciphertext.ToArray(), ciphertextStream.ToArray()));
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
        Assert.IsTrue(Enumerable.SequenceEqual(testVector.Plaintext.ToArray(), plaintextStream.ToArray()));
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
        Assert.IsTrue(Enumerable.SequenceEqual(testVector.Plaintext.ToArray(), plaintextStream.ToArray()));
    }
}
